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
//! its own group** (best-effort `getpgid` check), so an in-group child gets
//! exactly one delivery from the group signal and an escapee (e.g. a child
//! that `setsid()`s away) is still reached by its pidfd while siblings are
//! never touched. When a child is reaped, its pgid is retained in a
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
    let frame = match proto::encode_frame(proto::FrameKind::Resp, &payload) {
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

/// fork+exec `argv` with optional cwd/env and optional stdio fds (0,1,2).
/// Returns the child pid, or -1 on fork failure.
fn spawn(
    argv: &[String],
    env: &[(String, String)],
    cwd: &Option<String>,
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
    let pid = unsafe { libc::fork() };
    if pid != 0 {
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
    if let Some(fds) = stdio {
        for (i, &fd) in fds.iter().enumerate() {
            unsafe {
                libc::dup2(fd, i as i32);
            }
        }
        for &fd in &fds {
            if fd > 2 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
    if let Some(c) = cwd {
        if let Ok(cs) = CString::new(c.as_str()) {
            unsafe {
                libc::chdir(cs.as_ptr());
            }
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
    }
    unsafe { libc::_exit(127) };
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

/// Deliver `signum` to one registered child. Group-first: `killpg` reaches
/// every process the child forked that stayed in its group (its subtree) —
/// including the child itself when it is still in that group — without
/// touching any sibling's group. The pidfd complement fires **only when the
/// child has escaped its own group** (best-effort `getpgid` compare): an
/// in-group child therefore receives exactly one delivery (killpg), while an
/// escapee (e.g. `setsid()`) is still signaled directly via its pidfd, which
/// never races on pid reuse. Accepted race: a child that changes groups
/// between the `getpgid` check and the `killpg` may miss this round's direct
/// signal (or, conversely, receive it via the group); escapee coverage is
/// best-effort by design. All calls are best-effort: ESRCH/empty-group
/// failures are expected once a child has exited.
fn signal_child(child: &Child, signum: i32) {
    let escaped = if child.pidfd >= 0 {
        let pg = unsafe { libc::getpgid(child.pid) };
        pg != child.pgid
    } else {
        false
    };
    if escaped {
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal as libc::c_long,
                child.pidfd,
                signum,
                std::ptr::null::<libc::c_void>(),
                0u32, // flags
            );
        }
    }
    unsafe {
        libc::killpg(child.pgid, signum);
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
    children: &HashMap<i32, Child>,
    dead_groups: &mut HashSet<i32>,
    signum: i32,
) {
    for child in children.values() {
        signal_child(child, signum);
    }
    let mut emptied = Vec::new();
    for &pgid in dead_groups.iter() {
        let r = unsafe { libc::killpg(pgid, signum) };
        if r != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            emptied.push(pgid);
        }
    }
    for pgid in emptied {
        dead_groups.remove(&pgid);
    }
}

/// Poll interval for the control channel: bounds how long a reaped child can
/// sit as a zombie when no control message is arriving (100 ms class).
const REAP_POLL_MS: i32 = 100;

/// RAII guard for the SCM_RIGHTS fds received in one control read (SL-5).
///
/// `fdrecv::recv` transfers ownership of every received fd into this guard at
/// the recvmsg boundary, so **every** exit from the receive branch — EOF,
/// frame/parse errors, `RunMain`/`Shutdown`/`Signal` carrying unexpected fds,
/// `RunExec` with too few fds, a failed fork — closes them when the guard
/// drops. Nothing is `mem::forget`ten and nothing escapes the guard except
/// the three fds a successful `RunExec` dup's into its child, which `spawn`
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
                                signal_all_children(&children, &mut dead_groups, libc::SIGKILL);
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

        // Wait up to REAP_POLL_MS for a control message so the loop is not a
        // busy poll, then loop back (the sweep at the top reaps children that
        // exited during the wait).
        let mut pfd = libc::pollfd {
            fd: ctl,
            events: libc::POLLIN,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, REAP_POLL_MS) };
        if pr < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break; // control fd unusable; treat like EOF below
        }
        if pr == 0 || (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) == 0 {
            continue; // timeout (or spurious wakeup): sweep again on top
        }

        let (bytes, fds) = match fdrecv::recv(ctl, 3) {
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
        // Decode every complete frame in this read unit (one sendmsg = one
        // frame; several whole frames may coalesce into one recvmsg). Replies
        // are deferred until the guard has dropped, so a reply can never be
        // observed before its frame's fds are closed.
        let mut replies: Vec<Resp> = Vec::new();
        let mut shutdown = false;
        let mut off = 0usize;
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
                            let pid = spawn(&argv, &env, &cwd, None);
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
                        Req::RunExec { argv, env, cwd, detach } => {
                            if received.fds.len() < 3 {
                                replies.push(Resp::Err { msg: "exec needs 3 fds".into() });
                                continue;
                            }
                            let stdio = [
                                received.fds[0].as_raw_fd(),
                                received.fds[1].as_raw_fd(),
                                received.fds[2].as_raw_fd(),
                            ];
                            let pid = spawn(&argv, &env, &cwd, Some(stdio));
                            if pid < 0 {
                                replies.push(Resp::Err { msg: "fork failed".into() });
                                continue;
                            }
                            // The fds were dup2'd into the child before exec;
                            // the guard still closes the parent's copies on
                            // drop but no longer counts them as guard-closed.
                            received.handed = 3;
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
                            signal_all_children(&children, &mut dead_groups, libc::SIGKILL);
                            shutdown = true;
                        }
                        Req::Signal { signum } => {
                            // Instance-level signal relayed by the supervisor:
                            // traverse the registered child-group set plus
                            // retained dead groups. No pid payload exists on
                            // this verb, so even a forged frame cannot address
                            // an arbitrary process (see the module docs,
                            // SECE-6 boundary).
                            signal_all_children(&children, &mut dead_groups, signum);
                        }
                    }
                }
            }
        }
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
