//! The confined in-sandbox PID-1 (`sandlock-init`) control loop and its wire
//! protocol.
//!
//! [`run_init`] is the loop: it reads [`Req`] messages on [`CONTROL_FD`] and
//! fork-execs the workload (`RunMain`) and additional `exec`'d commands
//! (`RunExec`). Every child inherits this process's seccomp filter and Landlock
//! ruleset, so they share the one supervisor. When the main workload exits, the
//! container is done: the loop signals every registered child group and exits.
//!
//! # Per-child process groups (SECE-6 / F1.7)
//!
//! `spawn()` calls `setpgid(0,0)` in the child before exec, so every child is
//! the leader of its **own** process group (pgid == child pid). A guest
//! `killpg(getpgid(0), SIGKILL)` can therefore only reach that child's own
//! subtree — never init or a sibling (docs `sandbox-exec-security.md` §4.6:
//! before this change one command killed the whole container). Instance-level
//! operations (main-exit teardown, `Shutdown`, `Signal`) traverse the
//! registered child-group set: group-first `killpg` plus a per-child
//! `pidfd_send_signal` complement that fires **only when the child has left
//! its own group or session** (best-effort `getpgid` + `getsid` compare,
//! FUP-10 — the session compare closes the two-step setpgid→setsid blind
//! spot), so an in-group child gets exactly one delivery from the group
//! signal and an escapee (e.g. a child that `setsid()`s away) is still
//! reached by its pidfd while siblings are never touched. When a child is
//! reaped, its pgid is retained in a
//! `dead_groups` set so live descendants that stayed in the dead child's
//! group are still covered by later instance-level operations; the entry is
//! dropped once `killpg` reports ESRCH (the group is empty), so the set does
//! not grow without bound. There is deliberately **no** pid-addressed signal
//! verb on the wire: a compromised control-channel holder can request
//! instance-level delivery only, never a signal to an arbitrary pid (the
//! same-uid direct `kill(2)` between sandbox processes is a kernel boundary
//! sandlock does not mediate, §4.15).
//!
//! # Orphan reaping (SL-6)
//!
//! `run_init` starts by making itself a child subreaper
//! (`PR_SET_CHILD_SUBREAPER`) and every loop round drains
//! `waitpid(-1, WNOHANG)`, so **all** descendants that outlive their parent are
//! adopted by init and reaped here:
//!
//! - With a PID namespace (the shape this project targets later, per
//!   `docs/sandbox-exec-security.md` S8) init *is* namespace PID 1, so the
//!   kernel hands every orphan to init; without the reaper loop they would
//!   stay `<defunct>` forever inside the container.
//! - Without a PID namespace (the current OCI form), the kernel falls back to
//!   the nearest *subreaper* ancestor. Before this change init was not one, so
//!   double-fork orphans were reparented past init to the outer container
//!   PID 1 and could accumulate there; with `PR_SET_CHILD_SUBREAPER` init is
//!   that nearest ancestor and reaps them itself, never depending on the
//!   outer PID 1.
//!
//! Reaps are routed through a child table: children init spawned (main /
//! attach exec / detach exec) are answered per the protocol below, exactly
//! once per pid; adopted orphans that init did not spawn are reaped silently
//! and counted by a local reconciler counter — they are never reported,
//! because the supervisor's F1.2 announced-registry would count an unexpected
//! `Exited` as forged. Replies are single-writer (only the main loop calls
//! [`send`]), which keeps the supervisor's `Started` → `Exited` correlation
//! intact.
//!
//! # Wire protocol
//!
//! It runs **in-process** in the confined fork (see
//! `Sandbox::create_with_in_child_main`), not as a separately-exec'd binary:
//! the child is already a fork of the supervisor, so this code is mapped, and
//! nothing is exec'd for init itself, which sidesteps Landlock having to
//! authorize an execve of a path-less image.
//!
//! The wire itself is the explicitly framed envelope in [`proto`] (length
//! prefix + version + type, JSON payloads unchanged); every received
//! SCM_RIGHTS fd is owned by a RAII guard and closed on every exit path
//! (SL-5), see [`RecvFdGuard`].

pub mod proto;
pub mod fdpass;
mod fdrecv;
pub(crate) mod executor;

pub use proto::{Req, Resp, CONTROL_FD};
use proto::FrameKind;

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

/// Send one framed `Resp` reply on the control socket (single-writer: only
/// the main loop calls this). Best-effort: a dead peer or a failed write is
/// ignored — the reap/loop logic never depends on delivery.
fn send(fd: RawFd, resp: &Resp) {
    let payload = match serde_json::to_vec(resp) {
        Ok(p) => p,
        Err(_) => return,
    };
    let frame = match proto::encode_frame(proto::FrameKind::Resp, &payload, 0) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut off = 0usize;
    while off < frame.len() {
        let n = unsafe {
            libc::write(
                fd,
                frame.as_ptr().add(off) as *const libc::c_void,
                frame.len() - off,
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        off += n as usize;
    }
}

/// FUP-23: reserved child-side stdio slots.
///
/// An `exec`'s three stdio ends arrive over SCM_RIGHTS, so init holds them at
/// whatever numbers `recvmsg` picked (the lowest free ones — classically 5/6/7).
/// `spawn` used to `dup2` straight from those numbers *in the forked child*.
/// Measured on the E2B host shape (see `docs/fork-plan-followups.md` FUP-23):
/// between the fork and the child's very first instruction, one of those low
/// numbers could already refer to a different file description (an unrelated
/// pipe pair), so the workload ran with e.g. a read end in its stdout slot —
/// every write failed `EBADF`, CPython exited 120 and command output vanished
/// with no error anywhere. init's own table is provably intact before and after
/// the fork, so the replacement comes from outside this code path (anything
/// that installs a descriptor into a fresh child at a low fd number hits it).
///
/// Two independent defences, because the clobberer is outside core:
///
/// 1. relocate the three ends to a fixed reserved range *in init, before the
///    fork*, so the numbers the child dups from are not in the range a
///    low-number allocation would pick;
/// 2. verify in the child, before wiring anything, that every reserved slot
///    still refers to the same description (access mode + `st_dev`/`st_ino`)
///    that init relocated — and fail the exec loudly instead of running a
///    workload whose stdio was swapped under it.
const EXEC_STDIO_BASE: RawFd = 64;

/// Exit code for an exec whose stdio was swapped between the fork and the
/// child's wiring. Distinct from 125 (chdir/stdio setup failure), 126
/// (`setpgid` failure) and 127 (`execvp` failure).
const EXEC_STDIO_SWAPPED_EXIT: i32 = 124;

/// Identity of the open file description behind `fd`: the access mode plus the
/// `(st_dev, st_ino)` pair. Cheap, and enough to notice that a slot now points
/// somewhere else.
fn fd_identity(fd: RawFd) -> (u64, u64, i32) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return (u64::MAX, u64::MAX, 7);
    }
    (
        st.st_dev as u64,
        st.st_ino as u64,
        if flags < 0 { 7 } else { flags & libc::O_ACCMODE },
    )
}

/// What `spawn` needs in order to wire an exec's stdio: the numbers to dup2
/// from, the identity each of those numbers had when the plan was built, and
/// whether the plan relocated them (which decides what the parent and the child
/// have to close).
struct ExecStdioPlan {
    slots: [RawFd; 3],
    expect: [(u64, u64, i32); 3],
    relocated: bool,
}

/// True when `fd` is not currently open (a number the relocation may take over
/// without destroying somebody else's descriptor).
fn fd_is_free(fd: RawFd) -> bool {
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
    } else {
        false
    }
}

/// Move the received stdio ends out of the low allocation range.
///
/// Relocation is declined — silently, keeping the received numbers — when the
/// reserved triple is not entirely free or a `dup3` fails (e.g. a sandbox whose
/// `RLIMIT_NOFILE` sits below the range). Declining must never be worse than
/// the pre-FUP-23 behaviour, and destroying a descriptor init or a long-lived
/// sibling still holds would be far worse than the race this guards: `dup3`
/// replaces its target without complaining. The identity check in the child
/// stays active either way, so a swapped slot is still a loud failure.
fn plan_exec_stdio(fds: [RawFd; 3]) -> ExecStdioPlan {
    let expect = fds.map(fd_identity);
    let mut slots = fds;
    let mut made = 0usize;
    let reserved_free = (0..3).all(|i| {
        let target = EXEC_STDIO_BASE + i as RawFd;
        fds.iter().all(|&fd| fd != target) && fd_is_free(target)
    });
    if !reserved_free {
        return ExecStdioPlan {
            slots: fds,
            expect,
            relocated: false,
        };
    }
    for i in 0..3 {
        let target = EXEC_STDIO_BASE + i as RawFd;
        if fds[i] == target {
            continue;
        }
        let rc = unsafe { libc::dup3(fds[i], target, libc::O_CLOEXEC) };
        if rc < 0 {
            for j in 0..made {
                unsafe {
                    libc::close(slots[j]);
                }
            }
            return ExecStdioPlan {
                slots: fds,
                expect,
                relocated: false,
            };
        }
        slots[i] = rc;
        made = i + 1;
    }
    ExecStdioPlan {
        slots,
        expect,
        relocated: true,
    }
}

/// A reserved slot no longer holds the description init put there: report it
/// through the slots that still verify (the broken one is by definition
/// unusable) and abort the exec.
fn exec_stdio_swapped(slot: usize, plan: &ExecStdioPlan) -> ! {
    let msg = format!(
        "sandlock-init: exec stdio slot {slot} was replaced between the fork and \
         the workload start; refusing to run with swapped descriptors\n"
    );
    for (i, (&fd, &want)) in plan.slots.iter().zip(plan.expect.iter()).enumerate() {
        if i != slot && fd_identity(fd) == want {
            unsafe {
                libc::write(fd, msg.as_ptr() as *const libc::c_void, msg.len());
            }
        }
    }
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(EXEC_STDIO_SWAPPED_EXIT);
    }
}

/// Verify that every reserved slot still holds the description init relocated,
/// then wire them onto 0/1/2 and drop the scratch numbers.
///
/// `Err(slot)` means the slot was replaced between the fork and here: nothing is
/// wired, and the caller must abort the exec rather than run a workload with a
/// swapped descriptor (FUP-23 — that is exactly how command output used to
/// vanish with no error anywhere).
fn wire_exec_stdio(plan: &ExecStdioPlan, received: [RawFd; 3]) -> Result<(), usize> {
    for (i, (&fd, &want)) in plan.slots.iter().zip(plan.expect.iter()).enumerate() {
        if fd_identity(fd) != want {
            return Err(i);
        }
    }
    for (i, &fd) in plan.slots.iter().enumerate() {
        unsafe {
            libc::dup2(fd, i as i32);
        }
    }
    // Drop every scratch number: the reserved slots plus, when the plan
    // relocated, the received ends. A stray dup of the workload's own stdout
    // write end would keep the host-side reader from ever seeing EOF.
    let mut seen: [RawFd; 6] = [-1; 6];
    let mut n = 0usize;
    for &fd in plan.slots.iter().chain(received.iter()) {
        if fd > 2 && !seen[..n].contains(&fd) && n < seen.len() {
            seen[n] = fd;
            n += 1;
            unsafe {
                libc::close(fd);
            }
        }
    }
    Ok(())
}

/// fork+exec `argv` with optional cwd/env and optional stdio fds (0,1,2).
/// Returns the child pid, or -1 on fork failure.
fn spawn(
    argv: &[String],
    env: &[(String, String)],
    cwd: &Option<String>,
    clean_env: bool,
    stdio: Option<[RawFd; 3]>,
) -> i32 {
    // SL-4 belt: the control socket must never survive the workload's execvp.
    // fcntl is async-signal-safe and FD_CLOEXEC is per-fd-table state, so
    // setting it here — in init, before the fork — provably covers every exec
    // path through this spawner: fork copies the flag, init itself never
    // execs, and a later spawn re-arms it even if the fd table was rebuilt.
    // If CONTROL_FD is already closed (channel torn down) the fcntl fails with
    // EBADF and there is nothing to protect, so the error is deliberately
    // ignored.
    unsafe {
        libc::fcntl(CONTROL_FD, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    // FUP-23: relocate the received ends before the fork, so the child never
    // dups from a low number that an outside party can hand out in parallel.
    let plan = stdio.map(plan_exec_stdio);
    let pid = unsafe { libc::fork() };
    if pid != 0 {
        // The reserved copies were only ever meant for the child; init keeps
        // none of them, or every exec would leak three descriptors.
        if let Some(plan) = plan.as_ref() {
            if plan.relocated {
                for &fd in &plan.slots {
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
        }
        // Belt alongside the child's own setpgid(0,0): close the fork→setpgid
        // window so the pid is a valid pgid as soon as spawn returns. The
        // child may already have setpgid'd (then this fails EACCES/ESRCH,
        // which is fine — the outcome is the same pgid).
        unsafe {
            libc::setpgid(pid, pid);
        }
        return pid;
    }
    // child
    // FUP-14: init's SIGCHLD block must not leak into the workload (shells
    // and runtimes legitimately rely on SIGCHLD). Unblock before exec.
    unsafe {
        let mut unblock: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut unblock);
        libc::sigaddset(&mut unblock, libc::SIGCHLD);
        libc::sigprocmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());
    }
    // SECE-6 (F1.7): every child becomes its own process-group leader before
    // exec, so a killpg(getpgid(0), SIGKILL) inside one command can never
    // reach init or a sibling. Fail closed if the kernel refuses: continuing
    // in init's shared group would silently re-expose the whole-instance
    // killpg. (The parent's setpgid above may win the race; that is fine.)
    if unsafe { libc::setpgid(0, 0) } != 0 {
        unsafe {
            libc::_exit(126);
        }
    }
    if let (Some(plan), Some(received)) = (plan.as_ref(), stdio) {
        // FUP-23: a slot that no longer holds the description init relocated is
        // a slot somebody else took over — never run the workload on it.
        if let Err(slot) = wire_exec_stdio(plan, received) {
            exec_stdio_swapped(slot, plan);
        }
    }
    // Per-exec parameter application (F4.1): chdir first, then build the
    // environment. `clean_env` starts from an empty environ and applies
    // `env` as the child's complete environment; otherwise `env` entries are
    // additive overrides of init's inherited session environment. Both are
    // process-local mutations in the post-fork child, so one exec can never
    // leak its cwd/env into a sibling (they fork from init, which never
    // mutates its own cwd/env here).
    // F4.1 follow-up (reviewer minor): a failed chdir must be loud, not
    // silently ignored — running the workload in the wrong cwd is a real
    // semantic error. The error is written to the child's stderr (the stdio
    // fds were dup2'd above) and the child exits with a distinct setup-failure
    // code (125; 126 is setpgid failure, 127 exec failure) so `wait_child`
    // reports it instead of the workload silently running elsewhere.
    if let Some(c) = cwd {
        let chdir_errno = match CString::new(c.as_str()) {
            Ok(cs) => {
                if unsafe { libc::chdir(cs.as_ptr()) } == 0 {
                    None
                } else {
                    std::io::Error::last_os_error().raw_os_error()
                }
            }
            Err(_) => Some(libc::EINVAL),
        };
        if let Some(errno) = chdir_errno {
            child_fail(&format!(
                "sandlock-init: chdir to {c:?} failed (errno {errno})\n"
            ));
        }
    }
    if clean_env {
        let keys: Vec<_> = std::env::vars_os().map(|(k, _)| k).collect();
        for key in keys {
            std::env::remove_var(&key);
        }
    }
    for (k, v) in env {
        std::env::set_var(k, v);
    }
    let cargv: Vec<CString> = argv.iter().filter_map(|a| CString::new(a.as_str()).ok()).collect();
    let mut ptrs: Vec<*const libc::c_char> = cargv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // Under chroot the sandlock seccomp exec handler rewrites the pathname in
    // place (to /proc/self/fd/N for the injected binary fd). Pass a separate
    // PATH_MAX buffer as the `file` argument so that rewrite cannot clobber
    // argv[0], which busybox-style binaries use for applet detection. execvp
    // still does PATH lookup for bare command names against this buffer.
    if let Some(first) = cargv.first() {
        let orig = first.as_bytes_with_nul();
        let mut exec_path = vec![0u8; libc::PATH_MAX as usize];
        exec_path[..orig.len()].copy_from_slice(orig);
        unsafe {
            libc::execvp(exec_path.as_ptr() as *const libc::c_char, ptrs.as_ptr());
        }
        // FUP-26: `execvp` only returns on failure, and the reserved 127 alone
        // is not a diagnosis -- in a lane log it reads as "the command died
        // and said nothing". `ENOENT` stays silent on purpose (it is the
        // POSIX "not found" shape every execvp caller already handles, and the
        // e2b contract pins "127 with no output" for a missing binary); every
        // *other* errno is a failure the sandbox hid from the child and gets
        // the one line that names it -- 13 a DAC refusal, 40 a symlink loop,
        // 11/35 the *retryable* `EAGAIN` openat2(RESOLVE_IN_ROOT) reports for
        // a `..` it could not prove stayed inside the root.
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno != libc::ENOENT {
            exec_fail(&format!(
                "sandlock-init: exec {argv0:?} failed (errno {errno})\n",
                argv0 = cargv[0].to_string_lossy()
            ));
        }
    }
    unsafe { libc::_exit(127) };
}

/// Write a child-side setup error to fd 2 and `_exit(125)`. Runs in the
/// post-fork child; glibc's heap is fork-safe in this single-threaded loop.
fn child_fail(msg: &str) -> ! {
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(125);
    }
}

/// Write a child-side *exec* failure to fd 2 and `_exit(127)`.
///
/// 127 stays the reserved "the workload never started" code (125 is the
/// chdir/stdio setup failure, 126 a failed `setpgid`); the message is what
/// makes it diagnosable, exactly as [`child_fail`] does for 125.
fn exec_fail(msg: &str) -> ! {
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(127);
    }
}

/// Decode a `waitpid` status into `(code, signal)`.
fn decode_status(status: i32) -> (Option<i32>, Option<i32>) {
    if libc::WIFEXITED(status) {
        (Some(libc::WEXITSTATUS(status)), None)
    } else if libc::WIFSIGNALED(status) {
        (None, Some(libc::WTERMSIG(status)))
    } else {
        // waitpid without WUNTRACED/WCONTINUED only returns for exited or
        // signal-killed children, so this arm is defensive only.
        (None, None)
    }
}

/// Non-blocking reap of one exited child, if any. `waitpid(-1, WNOHANG)`
/// covers every adopted child, including orphans init did not spawn.
fn try_reap_one() -> Option<(i32, Option<i32>, Option<i32>)> {
    let mut status = 0i32;
    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    if pid <= 0 {
        // 0 = nothing exited yet; -1 = ECHILD (nothing left) or EINTR (the
        // next sweep retries). Never fabricate an exit from an error.
        return None;
    }
    let (code, signal) = decode_status(status);
    Some((pid, code, signal))
}

/// Kind of a child init spawned, deciding what (if anything) is reported when
/// the child is reaped.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChildKind {
    /// The OCI main workload. Its exit ends the container: report `Exited`,
    /// signal every registered child group, and `_exit` init.
    Main,
    /// An attached `exec`: report `Exited` to the supervisor waiter.
    ExecAttach,
    /// A detached `exec`: reap silently (supervisor never registers a waiter).
    ExecDetach,
}

/// Per-child metadata recorded by init at spawn time.
struct Child {
    kind: ChildKind,
    /// The child's pid (== its pgid unless it escaped the group).
    pid: i32,
    /// Process group id of this child. `spawn()` makes every child its own
    /// group leader before exec, so pgid == child pid.
    pgid: i32,
    /// pidfd for this child, opened parent-side right after fork; the
    /// escapee-resistant half of instance-level delivery (`pidfd_send_signal`
    /// still reaches the child if it leaves its group/session). Only used
    /// when the child has actually escaped its own group — an in-group child
    /// gets exactly one delivery from the group signal. -1 when `pidfd_open`
    /// is unavailable (kernels that old cannot run the sandlock feature set
    /// anyway; group-first delivery still applies).
    pidfd: i32,
}

/// Open a pidfd for `pid`, or -1 when the kernel refuses.
fn open_child_pidfd(pid: i32) -> i32 {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        -1
    } else {
        raw as i32
    }
}

/// Deliver `signum` to every registered child group and every retained dead
/// child group: the instance-level kill / teardown / supervisor-signal
/// primitive. Live children are delivered group-first (with the escape-only
/// pidfd complement); `dead_groups` holds the pgids of reaped children whose
/// group may still contain live descendants that never left it — a pgid is
/// dropped once `killpg` returns ESRCH (empty group), bounding the set. Only
/// init-spawned children (and their retained groups) are ever addressed;
/// adopted orphans and arbitrary pids never are.
fn signal_all_children(
    supervisor_session: i32,
    children: &HashMap<i32, Child>,
    dead_groups: &mut HashSet<i32>,
    signum: i32,
) {
    for child in children.values() {
        if child_escaped(child, supervisor_session) {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal as libc::c_long,
                    child.pidfd,
                    signum,
                    std::ptr::null::<libc::c_void>(),
                    0u32,
                );
            }
        }
    }
    let mut emptied = Vec::new();
    for pgid in unique_signal_pgids(children, dead_groups) {
        let r = unsafe { libc::killpg(pgid, signum) };
        if r != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            && dead_groups.contains(&pgid)
        {
            emptied.push(pgid);
        }
    }
    for pgid in emptied {
        dead_groups.remove(&pgid);
    }
}

/// FUP-10: a child has escaped group-first delivery when it no longer sits
/// in its recorded group **or** it created its own session. The session
/// compare closes the two-step blind spot: `setpgid` into another group
/// followed by `setsid` returns the child to pgid == its recorded pid, which
/// the old `getpgid`-only check could not distinguish from never escaping.
fn escaped_group(
    recorded_pgid: i32,
    current_pgid: i32,
    current_sid: i32,
    supervisor_sid: i32,
) -> bool {
    current_pgid != recorded_pgid || current_sid != supervisor_sid
}

fn child_escaped(child: &Child, supervisor_session: i32) -> bool {
    if child.pidfd < 0 {
        return false;
    }
    let pg = unsafe { libc::getpgid(child.pid) };
    let sid = unsafe { libc::getsid(child.pid) };
    escaped_group(child.pgid, pg, sid, supervisor_session)
}

/// FUP-10: every pgid (live children plus retained dead groups) is signaled
/// exactly once per instance-level delivery. Live children share a pgid only
/// in the setpgid-failure corner, and a dead group's pgid can be recycled by
/// a live child; dedupe before `killpg` so neither case double-delivers.
fn unique_signal_pgids(
    children: &HashMap<i32, Child>,
    dead_groups: &HashSet<i32>,
) -> Vec<i32> {
    let mut seen = HashSet::new();
    let mut pgids: Vec<i32> = children
        .values()
        .map(|c| c.pgid)
        .filter(|pgid| seen.insert(*pgid))
        .collect();
    for pgid in dead_groups.iter().copied() {
        if seen.insert(pgid) {
            pgids.push(pgid);
        }
    }
    pgids.sort_unstable();
    pgids
}

/// Fallback poll interval for the control channel (FUP-14): child exits now
/// wake the loop immediately via a SIGCHLD signalfd, so this timeout only
/// bounds how long an adopted orphan (no pidfd/signalfd wake) can sit as a
/// zombie when no control message is arriving. Kernels without signalfd fall
/// back to this poll-only behavior (100 ms class).
const REAP_POLL_MS: i32 = 100;

/// RAII guard for the SCM_RIGHTS fds received in one control read (SL-5).
///
/// `fdrecv::recv` transfers ownership of every received fd into this guard at
/// the recvmsg boundary, so **every** exit from the receive branch — EOF,
/// frame/parse errors, `RunMain`/`Shutdown`/`Signal` carrying unexpected fds,
/// `RunExec` with too few fds, a failed fork — closes them when the guard
/// drops. Nothing is `mem::forget`ten and nothing escapes the guard except
/// the fds a successful `RunExec` dup's into its child, which `spawn`
/// consumes inside the child before exec (tracked via `handed` so the parent
/// still closes its own copies on drop).
///
/// Drop also records the guard-closed fds in `leaks`: the exact set the
/// pre-F1.6 exits (parse error / EOF / `RunMain` / `Shutdown` / unexpected
/// fds) used to leave open. The counter is deliberately local and never
/// wire-exposed (the F1.5 `_reaped_unknown` precedent): the supervisor has no
/// read for it, so the observable guarantee is fd-table flatness asserted by
/// the root-mode leak tests, not a frame. The leading underscore marks the
/// counter as unread.
struct RecvFdGuard<'a> {
    fds: Vec<OwnedFd>,
    /// Fds a successful `RunExec` handed to its child (0 or 3).
    handed: usize,
    leaks: &'a mut u64,
}

impl Drop for RecvFdGuard<'_> {
    fn drop(&mut self) {
        *self.leaks += self.fds.len().saturating_sub(self.handed) as u64;
        // The OwnedFds in `fds` close here, after the counter update.
    }
}

/// Assign one frame its own slice of a read unit's descriptor list, by the
/// count the frame declared (F15). `None` means the read unit cannot satisfy
/// the declaration, and the caller fails the whole unit closed rather than
/// hand a frame somebody else's descriptor.
fn take_frame_fds(
    cursor: &mut usize,
    declared: u8,
    available: usize,
) -> Option<std::ops::Range<usize>> {
    let end = cursor.checked_add(declared as usize)?;
    if end > available {
        return None;
    }
    let range = *cursor..end;
    *cursor = end;
    Some(range)
}

/// Run the confined PID-1 control loop on [`CONTROL_FD`]. Returns when the
/// daemon closes the channel or sends `Shutdown`. When the main workload
/// exits, the loop reports its `Exited`, signals every registered child group
/// plus every retained dead child group (main's own group is retained when it
/// is reaped, so its forked descendants are still collapsed), and `_exit`s
/// the process from the reap sweep — the container ends with the workload.
///
/// This runs in the confined fork created by
/// `Sandbox::create_with_in_child_main`; it uses only `libc` + `serde_json`
/// (heap allocation only, which glibc makes fork-safe via its atfork handler)
/// and never touches the supervisor's async runtime.
pub fn run_init() {
    // SL-6: become a subreaper before any fork, so double-fork descendants
    // orphan to *this* process (the nearest subreaper ancestor) even when
    // there is no PID namespace; with a PID namespace init is PID 1 anyway.
    // Best-effort: kernels predating PR_SET_CHILD_SUBREAPER cannot run the
    // sandlock feature set either, so a failure is ignored here and any
    // orphan-reaping regression is caught by the reaper integration tests.
    unsafe {
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }
    // FUP-10: children inherit init's session; a child that creates its own
    // session (the two-step setpgid→setsid escape) is detected by comparing
    // its session against this one.
    let supervisor_session = unsafe { libc::getsid(0) };
    // FUP-14: block SIGCHLD and arm a signalfd so a child exit wakes the
    // control loop immediately instead of waiting out REAP_POLL_MS (the old
    // ~100 ms exec-round-trip floor). The block is process-local to init;
    // `spawn` unblocks SIGCHLD in every child before exec, so workloads keep
    // stock SIGCHLD semantics.
    let mut sigchld_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let sigfd = unsafe {
        libc::sigemptyset(&mut sigchld_mask);
        libc::sigaddset(&mut sigchld_mask, libc::SIGCHLD);
        libc::sigprocmask(libc::SIG_BLOCK, &sigchld_mask, std::ptr::null_mut());
        libc::signalfd(-1, &sigchld_mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC)
    };

    let ctl = CONTROL_FD;
    // Child table: pids init spawned, routed exactly-once on reap. A pid is
    // removed when it is reaped, so a recycled pid cannot double-report.
    let mut children: HashMap<i32, Child> = HashMap::new();
    // Retained pgids of reaped children: their group may still hold live
    // descendants that never left it (adopted orphans of a dead exec child,
    // forked workers of a dead main, ...). Instance-level operations keep
    // covering these groups; `signal_all_children` drops an entry once the
    // group is empty (killpg ESRCH), so the set is bounded.
    let mut dead_groups: HashSet<i32> = HashSet::new();
    // Reconciler count for adopted orphans init did not spawn: reaped silently
    // and counted locally. The count is intentionally never wire-exposed: the
    // supervisor's F1.2 announced registry treats an `Exited` frame for a pid
    // it never saw a `Started` for as forged, so reconciliation is observed as
    // defunct-absence in the reaper integration tests, not as a frame. The
    // leading underscore marks the counter as deliberately unread.
    let mut _reaped_unknown: u64 = 0;
    // SL-5 local leak counter (see [`RecvFdGuard`]): received fds the guard
    // had to close because no branch consumed them. Never wire-exposed; the
    // root-mode leak tests observe the fd table instead.
    let mut _init_recv_fd_leaks: u64 = 0;
    loop {
        // Reap every exited child (known or adopted) before (re)blocking on
        // the control channel. Replies are only ever sent from this loop, so
        // the supervisor sees a strictly ordered Started -> Exited stream.
        while let Some((pid, code, signal)) = try_reap_one() {
            match children.remove(&pid) {
                Some(child) => {
                    // The child is reaped; its pidfd has no further purpose.
                    if child.pidfd >= 0 {
                        unsafe {
                            libc::close(child.pidfd);
                        }
                    }
                    // Keep the group id alive for teardown coverage: live
                    // descendants that stayed in this child's group are
                    // adopted by init but must not escape later instance-level
                    // operations (regression vs the old whole-group killpg).
                    dead_groups.insert(child.pgid);
                    match child.kind {
                        ChildKind::Main => {
                            if code.is_some() || signal.is_some() {
                                send(ctl, &Resp::Exited { pid, code, signal });
                                // Collapse the main child's own group (now in
                                // dead_groups) and every remaining registered
                                // child group, so no descendant or exec'd
                                // sibling survives the container.
                                signal_all_children(supervisor_session, &children, &mut dead_groups, libc::SIGKILL);
                                // _exit rather than std::process::exit: this
                                // is a fork of the supervisor, so atexit
                                // handlers would run inherited (tokio/glibc)
                                // cleanup.
                                unsafe {
                                    libc::_exit(0);
                                }
                            }
                        }
                        ChildKind::ExecAttach => {
                            send(ctl, &Resp::Exited { pid, code, signal });
                        }
                        ChildKind::ExecDetach => {
                            // Detached execs are silent: the supervisor forgot
                            // the pid and would count a late frame as unknown.
                        }
                    }
                }
                None => {
                    // Adopted orphan (double-fork descendant): reap, count,
                    // and drop. Never reply: the supervisor never announced
                    // this pid, so an Exited frame would be treated as forged.
                    _reaped_unknown += 1;
                }
            }
        }

        // Wait for a control message or a child exit (SIGCHLD via the
        // signalfd). The REAP_POLL_MS timeout remains only as a fallback
        // sweep for kernels without signalfd and for adopted orphans whose
        // exit did not wake us; with the signalfd armed, an exec+exit round
        // wakes immediately instead of paying the old ~100 ms floor.
        let mut pfds = [
            libc::pollfd {
                fd: ctl,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: sigfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let pr = unsafe {
            libc::poll(
                pfds.as_mut_ptr(),
                pfds.len() as libc::nfds_t,
                REAP_POLL_MS,
            )
        };
        if pr < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break; // control fd unusable; treat like EOF below
        }
        if pr == 0 {
            continue; // timeout (or spurious wakeup): sweep again on top
        }
        if sigfd >= 0 && (pfds[1].revents & (libc::POLLIN | libc::POLLERR)) != 0 {
            // Drain the signalfd queue (level-triggered: an unread pending
            // SIGCHLD would otherwise keep the loop busy).
            let mut drain = [0u8; 256];
            loop {
                let n = unsafe {
                    libc::read(
                        sigfd,
                        drain.as_mut_ptr() as *mut libc::c_void,
                        drain.len(),
                    )
                };
                if n <= 0 {
                    break;
                }
            }
        }
        if (pfds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) == 0 {
            continue; // only the signalfd woke us; sweep reaps on the top
        }

        let (bytes, fds) = match fdrecv::recv(ctl, proto::MAX_FDS_PER_READ) {
            Ok(p) => p,
            Err(_) => break,
        };
        // SL-5: every fd received by this read is owned by the guard from
        // this line on and is closed on drop — no exit branch may leak one.
        let mut received = RecvFdGuard {
            fds,
            handed: 0,
            leaks: &mut _init_recv_fd_leaks,
        };
        if bytes.is_empty() {
            // Daemon closed the channel: leave the loop; the guard closes
            // (and counts) any fd a zero-byte read carried, defensively.
            break;
        }
        // Decode every complete frame in this read unit (several whole frames
        // may coalesce into one recvmsg). Replies are deferred until the guard
        // has dropped, so a reply can never be observed before its frame's
        // fds are closed.
        let mut replies: Vec<Resp> = Vec::new();
        let mut shutdown = false;
        let mut off = 0usize;
        // F15: descriptors arrive as one concatenated list per read unit;
        // each frame takes the front slice it *declared*. A declaration the
        // queue cannot satisfy rejects the whole unit — no frame inherits
        // another frame's descriptors.
        let mut fd_cursor = 0usize;
        let mut handed = 0usize;
        while off < bytes.len() {
            let frame = match proto::decode_frame(&bytes[off..]) {
                Ok(f) => f,
                Err(e) => {
                    replies.push(Resp::Err {
                        msg: format!("bad control frame: {e}"),
                    });
                    // A framing error means the following bytes may not start
                    // at a frame boundary: stop consuming this read unit
                    // rather than half-guessing. A serialized, well-formed
                    // supervisor never produces one; a hostile peer degrades
                    // only this unit — with no fd leak and no buffering.
                    break;
                }
            };
            let frame_fds = match take_frame_fds(
                &mut fd_cursor,
                frame.n_fds,
                received.fds.len(),
            ) {
                Some(range) => range,
                None => {
                    replies.push(Resp::Err {
                        msg: "control frame declares more descriptors than the read unit carries"
                            .into(),
                    });
                    break;
                }
            };
            off += frame.consumed;
            match frame.kind {
                FrameKind::Resp => {
                    // init only ever receives Req frames; a Resp-type frame is
                    // a protocol violation.
                    replies.push(Resp::Err {
                        msg: "init received a resp-type control frame".into(),
                    });
                    break;
                }
                FrameKind::Req => {
                    let req: Req = match serde_json::from_slice(frame.payload) {
                        Ok(r) => r,
                        Err(e) => {
                            replies.push(Resp::Err { msg: e.to_string() });
                            continue; // frame boundary known: try the next frame
                        }
                    };
                    match req {
                        Req::RunMain { argv, env, cwd } => {
                            if children.values().any(|c| c.kind == ChildKind::Main) {
                                // Only one OCI start is legitimate; a second
                                // RunMain would otherwise overwrite the table
                                // entry and orphan the first main's exit
                                // routing.
                                replies.push(Resp::Err { msg: "main already running".into() });
                                continue;
                            }
                            let pid = spawn(&argv, &env, &cwd, false, None);
                            if pid < 0 {
                                replies.push(Resp::Err { msg: "fork failed".into() });
                                continue;
                            }
                            children.insert(
                                pid,
                                Child {
                                    kind: ChildKind::Main,
                                    pid,
                                    // spawn() setpgid(0,0)'d the child: pgid
                                    // == child pid.
                                    pgid: pid,
                                    pidfd: open_child_pidfd(pid),
                                },
                            );
                            replies.push(Resp::Started { pid });
                        }
                        Req::RunExec {
                            argv,
                            env,
                            cwd,
                            detach,
                            clean_env,
                            extra_writable: _,
                            bind_ports: _,
                        } => {
                            let exec_fds = &received.fds[frame_fds];
                            if exec_fds.len() != 3 {
                                replies.push(Resp::Err { msg: "exec needs 3 fds".into() });
                                continue;
                            }
                            let stdio = [
                                exec_fds[0].as_raw_fd(),
                                exec_fds[1].as_raw_fd(),
                                exec_fds[2].as_raw_fd(),
                            ];
                            let pid = spawn(&argv, &env, &cwd, clean_env, Some(stdio));
                            if pid < 0 {
                                replies.push(Resp::Err { msg: "fork failed".into() });
                                continue;
                            }
                            // The fds were dup2'd into the child before exec;
                            // the guard still closes the parent's copies on
                            // drop but no longer counts them as guard-closed.
                            handed += 3;
                            children.insert(
                                pid,
                                Child {
                                    kind: if detach {
                                        ChildKind::ExecDetach
                                    } else {
                                        ChildKind::ExecAttach
                                    },
                                    pid,
                                    pgid: pid,
                                    pidfd: open_child_pidfd(pid),
                                },
                            );
                            replies.push(Resp::Started { pid });
                        }
                        Req::Shutdown => {
                            // Teardown: instance-level SIGKILL over the
                            // child-group set (live + retained dead groups),
                            // then exit the loop (the sandbox Drop reaps
                            // init). Unconditional since F3.2: an exec-only
                            // session (no RunMain) must still collapse every
                            // registered child on Shutdown; with an OCI-style
                            // main present the behavior is unchanged.
                            signal_all_children(supervisor_session, &children, &mut dead_groups, libc::SIGKILL);
                            shutdown = true;
                        }
                        Req::Signal { signum } => {
                            // Instance-level signal relayed by the supervisor:
                            // traverse the registered child-group set plus
                            // retained dead groups. No pid payload exists on
                            // this verb, so even a forged frame cannot address
                            // an arbitrary process (see the module docs,
                            // SECE-6 boundary).
                            signal_all_children(supervisor_session, &children, &mut dead_groups, signum);
                        }
                    }
                }
            }
        }
        // Count every exec whose stdio was handed to a child (dup'd into the
        // child before exec) as consumed; the guard's own copies still close
        // on drop but are not counted as guard-closed leaks.
        received.handed = handed;
        // Release the receive guard (closing every unhanded fd) before any
        // reply becomes observable, then answer in frame order.
        drop(received);
        for reply in replies {
            send(ctl, &reply);
        }
        if shutdown {
            break;
        }
    }

}

#[cfg(test)]
mod fd_assignment_tests {
    use super::take_frame_fds;

    /// F15: descriptors belong to the frame that *declared* them. A
    /// zero-descriptor frame ahead of an exec must not shift that exec's
    /// stdio onto the wrong pipe ends.
    #[test]
    fn a_zero_fd_frame_does_not_steal_the_next_frames_descriptors() {
        let mut cursor = 0usize;
        assert_eq!(take_frame_fds(&mut cursor, 0, 3), Some(0..0));
        assert_eq!(take_frame_fds(&mut cursor, 3, 3), Some(0..3));
        assert_eq!(cursor, 3, "the exec frame consumed exactly its own three");
    }

    #[test]
    fn two_exec_frames_split_one_queue_in_order() {
        let mut cursor = 0usize;
        assert_eq!(take_frame_fds(&mut cursor, 3, 6), Some(0..3));
        assert_eq!(take_frame_fds(&mut cursor, 3, 6), Some(3..6));
        assert_eq!(cursor, 6);
    }

    #[test]
    fn a_short_queue_fails_closed_without_consuming() {
        let mut cursor = 0usize;
        assert_eq!(take_frame_fds(&mut cursor, 3, 2), None);
        assert_eq!(cursor, 0, "a rejected declaration must not advance the queue");
    }

    #[test]
    fn zero_descriptor_frames_always_succeed() {
        let mut cursor = 0usize;
        for _ in 0..16 {
            assert_eq!(take_frame_fds(&mut cursor, 0, 0), Some(0..0));
        }
        assert_eq!(cursor, 0);
    }
}

#[cfg(test)]
mod signal_delivery_tests {
    use super::*;
    use std::collections::HashMap;

    fn child(pid: i32, pgid: i32, pidfd: i32) -> Child {
        Child {
            kind: ChildKind::ExecDetach,
            pid,
            pgid,
            pidfd,
        }
    }

    /// FUP-10: a group move OR a fresh session is an escape; the two-step
    /// setpgid→setsid corner (pgid back to the recorded value, session new)
    /// must still be classified as escaped.
    #[test]
    fn escaped_group_detects_moves_and_new_sessions() {
        assert!(!escaped_group(10, 10, 7, 7), "in-group child stays group-first");
        assert!(escaped_group(10, 11, 7, 7), "a group move must escape");
        assert!(escaped_group(10, 10, 10, 7), "two-step setpgid→setsid must escape");
        assert!(escaped_group(10, 11, 10, 7), "move plus new session must escape");
    }

    /// FUP-10: a live child sharing a pgid and a dead group whose pgid was
    /// recycled by a live child each produce exactly one killpg target.
    #[test]
    fn unique_signal_pgids_deduplicates_live_and_dead_groups() {
        let mut children = HashMap::new();
        children.insert(11, child(11, 11, 5));
        children.insert(12, child(12, 11, 6)); // shares pgid with child 11
        children.insert(13, child(13, 13, 7));
        let mut dead_groups = HashSet::new();
        dead_groups.insert(11); // recycled by the two live children above
        dead_groups.insert(99);

        assert_eq!(
            unique_signal_pgids(&children, &dead_groups),
            vec![11, 13, 99],
            "each pgid must be delivered exactly once"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An exec-shaped stdio triple: `(child ends, host ends)`, where the child
    /// ends are `[stdin read, stdout write, stderr write]` — exactly what
    /// `build_exec_stdio` hands to init over SCM_RIGHTS.
    fn exec_ends() -> ([RawFd; 3], [RawFd; 3]) {
        let mut p = [[0i32; 2]; 3];
        for pair in p.iter_mut() {
            assert_eq!(unsafe { libc::pipe2(pair.as_mut_ptr(), 0) }, 0, "pipe2");
        }
        ([p[0][0], p[1][1], p[2][1]], [p[0][1], p[1][0], p[2][0]])
    }

    fn read_up_to(fd: RawFd, want: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        while buf.len() < want {
            let mut chunk = [0u8; 64];
            let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut _, chunk.len()) };
            if n <= 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n as usize]);
        }
        buf
    }

    fn reaped_code(status: libc::c_int) -> i32 {
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1 - status
        }
    }

    /// Free our copies of the reserved range so the plan can use it. Only ever
    /// called in a forked child: closing an inherited copy says nothing about
    /// the parent's table.
    unsafe fn release_reserved_range() {
        for fd in EXEC_STDIO_BASE..EXEC_STDIO_BASE + 3 {
            libc::close(fd);
        }
    }

    /// FUP-23: an exec's stdio is wired from the reserved slots and the three
    /// streams stay separate end to end. The child runs the real
    /// `plan_exec_stdio` + `wire_exec_stdio` pair; the parent reads the host ends
    /// and asserts exact bytes, so a slot pointing at the wrong description
    /// (the FUP-23 failure) cannot pass.
    #[test]
    fn exec_child_wires_stdio_from_the_reserved_slots_without_cross_talk() {
        let (child, host) = exec_ends();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                release_reserved_range();
                let plan = plan_exec_stdio(child);
                let code = match wire_exec_stdio(&plan, child) {
                    Ok(()) => {
                        libc::write(1, b"O".as_ptr() as *const _, 1);
                        libc::write(2, b"E".as_ptr() as *const _, 1);
                        let mut b = [0u8; 1];
                        if libc::read(0, b.as_mut_ptr() as *mut _, 1) == 1 && b[0] == b'I' {
                            0
                        } else {
                            7
                        }
                    }
                    Err(_) => 9,
                };
                libc::_exit(code);
            }
        }
        unsafe {
            libc::write(host[0], b"I".as_ptr() as *const _, 1);
            libc::close(host[0]);
        }
        let out = read_up_to(host[1], 1);
        let err = read_up_to(host[2], 1);
        unsafe {
            libc::close(host[1]);
            libc::close(host[2]);
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            reaped_code(status),
            0,
            "the child must wire stdio and read its stdin (exit code in the \
             assertion above: 7 = stdin, 9 = wiring refused)"
        );
        assert_eq!(out, b"O", "stdout must carry exactly the child's stdout byte");
        assert_eq!(err, b"E", "stderr must carry exactly the child's stderr byte");
    }

    /// FUP-23 defence 1: the received ends are moved out of the low allocation
    /// range *before* the fork, which is the only window an outside party can
    /// hand a fresh child a descriptor at the number the child still dups from.
    #[test]
    fn exec_stdio_plan_relocates_the_received_ends_into_the_reserved_range() {
        let (child, host) = exec_ends();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                release_reserved_range();
                let plan = plan_exec_stdio(child);
                let ok = plan.relocated
                    && plan.slots
                        == [
                            EXEC_STDIO_BASE,
                            EXEC_STDIO_BASE + 1,
                            EXEC_STDIO_BASE + 2,
                        ]
                    && (0..3).all(|i| fd_identity(plan.slots[i]) == plan.expect[i])
                    && (0..3).all(|i| fd_identity(child[i]) == plan.expect[i]);
                libc::_exit(if ok { 0 } else { 1 });
            }
        }
        unsafe {
            for fd in host {
                libc::close(fd);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            reaped_code(status),
            0,
            "the plan must relocate all three ends into the reserved range and \
             keep their identity (slots/expect/received all agree)"
        );
    }

    /// Relocation must never destroy a descriptor somebody else still holds:
    /// `dup3` replaces its target without complaining, so an occupied reserved
    /// number makes the plan decline instead.
    #[test]
    fn exec_stdio_plan_declines_when_a_reserved_number_is_already_taken() {
        let (child, host) = exec_ends();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                release_reserved_range();
                let mut foreign = [0i32; 2];
                if libc::pipe2(foreign.as_mut_ptr(), 0) != 0 {
                    libc::_exit(2);
                }
                let taken = EXEC_STDIO_BASE + 1;
                if libc::dup3(foreign[0], taken, 0) < 0 {
                    libc::_exit(3);
                }
                let before = fd_identity(taken);
                let plan = plan_exec_stdio(child);
                let ok = !plan.relocated
                    && plan.slots == child
                    && fd_identity(taken) == before
                    && (0..3).all(|i| fd_identity(plan.slots[i]) == plan.expect[i]);
                libc::_exit(if ok { 0 } else { 1 });
            }
        }
        unsafe {
            for fd in host {
                libc::close(fd);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            reaped_code(status),
            0,
            "an occupied reserved number must make the plan fall back to the \
             received ends and leave the occupant untouched"
        );
    }

    /// FUP-23 defence 2: if a slot is swapped anyway, the wiring refuses to run
    /// the workload and nothing has been attached to 0/1/2 yet — the caller
    /// aborts the exec (exit 124) instead of losing its output silently.
    #[test]
    fn wire_exec_stdio_refuses_a_swapped_slot_before_touching_stdio() {
        let (child, host) = exec_ends();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                release_reserved_range();
                let plan = plan_exec_stdio(child);
                let mut foreign = [0i32; 2];
                if libc::pipe2(foreign.as_mut_ptr(), 0) != 0 {
                    libc::_exit(2);
                }
                // The FUP-23 clobber: a foreign read end lands on slot 1.
                if libc::dup3(foreign[0], plan.slots[1], 0) < 0 {
                    libc::_exit(3);
                }
                let stdio_before = (fd_identity(0), fd_identity(1), fd_identity(2));
                match wire_exec_stdio(&plan, child) {
                    Err(1) => {
                        let stdio_after = (fd_identity(0), fd_identity(1), fd_identity(2));
                        libc::_exit(if stdio_before == stdio_after { 0 } else { 4 });
                    }
                    Err(other) => libc::_exit(50 + other as i32),
                    Ok(()) => libc::_exit(5),
                }
            }
        }
        unsafe {
            for fd in host {
                libc::close(fd);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            reaped_code(status),
            0,
            "a swapped slot must be refused (Err(1)) with 0/1/2 still untouched \
             (4 = stdio already rewired, 5 = swap went unnoticed)"
        );
    }
}
