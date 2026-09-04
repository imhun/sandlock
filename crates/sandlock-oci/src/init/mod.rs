//! The confined in-sandbox PID-1 (`sandlock-init`) control loop and its wire
//! protocol.
//!
//! [`run_init`] is the loop: it reads [`Req`] messages on [`CONTROL_FD`] and
//! fork-execs the workload (`RunMain`) and additional `exec`'d commands
//! (`RunExec`). Every child inherits this process's seccomp filter and Landlock
//! ruleset, so they share the one supervisor. When the main workload exits, the
//! container is done: the loop kills the process group and exits.
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
//! and counted by a local reconciler counter (`reaped_unknown` in
//! [`run_init`]) — they are never reported, because the supervisor's F1.2
//! announced-registry would count an unexpected `Exited` as forged. Replies
//! are single-writer (only the main loop calls [`send`]), which keeps the
//! supervisor's `Started` → `Exited` correlation intact.
//!
//! # Wire protocol
//!
//! It runs **in-process** in the confined fork (see
//! `Sandbox::create_with_in_child_main`), not as a separately-exec'd binary:
//! the child is already a fork of the supervisor, so this code is mapped, and
//! nothing is exec'd for init itself, which sidesteps Landlock having to
//! authorize an execve of a path-less image.

pub mod proto;
mod fdrecv;

pub use proto::{Req, Resp, CONTROL_FD};

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::RawFd;

fn send(fd: RawFd, resp: &Resp) {
    if let Ok(mut v) = serde_json::to_vec(resp) {
        v.push(b'\n');
        unsafe {
            libc::write(fd, v.as_ptr() as *const _, v.len());
        }
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
        return pid;
    }
    // child
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
    /// kill the process group, and `_exit` init.
    Main,
    /// An attached `exec`: report `Exited` to the supervisor waiter.
    ExecAttach,
    /// A detached `exec`: reap silently (supervisor never registers a waiter).
    ExecDetach,
}

/// Poll interval for the control channel: bounds how long a reaped child can
/// sit as a zombie when no control message is arriving (100 ms class).
const REAP_POLL_MS: i32 = 100;

/// Run the confined PID-1 control loop on [`CONTROL_FD`]. Returns when the
/// daemon closes the channel or sends `Shutdown`; the main-workload reaper may
/// `_exit` the process first when the workload exits.
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
    let mut children: HashMap<i32, ChildKind> = HashMap::new();
    // Reconciler counter for adopted orphans init did not spawn: reaped
    // silently and counted here (observable via the absence of defuncts, the
    // same reconciliation surface the supervisor's F1.2 registry provides on
    // its side of the wire).
    let mut reaped_unknown: u64 = 0;
    loop {
        // Reap every exited child (known or adopted) before (re)blocking on
        // the control channel. Replies are only ever sent from this loop, so
        // the supervisor sees a strictly ordered Started -> Exited stream.
        while let Some((pid, code, signal)) = try_reap_one() {
            match children.remove(&pid) {
                Some(ChildKind::Main) => {
                    if code.is_some() || signal.is_some() {
                        send(ctl, &Resp::Exited { pid, code, signal });
                        unsafe {
                            libc::killpg(libc::getpgrp(), libc::SIGKILL);
                            // _exit rather than std::process::exit: this is a
                            // fork of the supervisor, so atexit handlers would
                            // run inherited (tokio/glibc) cleanup.
                            libc::_exit(0);
                        }
                    }
                }
                Some(ChildKind::ExecAttach) => {
                    send(ctl, &Resp::Exited { pid, code, signal });
                }
                Some(ChildKind::ExecDetach) => {
                    // Detached execs are silent: the supervisor forgot the
                    // pid and would count a late frame as unknown.
                }
                None => {
                    // Adopted orphan (double-fork descendant): reap, count,
                    // and drop. Never reply: the supervisor never announced
                    // this pid, so an Exited frame would be treated as forged.
                    reaped_unknown += 1;
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
        if bytes.is_empty() {
            break;
        } // daemon closed the channel
          // Trim trailing ASCII whitespace before parsing.
        let trimmed = &bytes[..bytes.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(0, |i| i + 1)];
        let req: Req = match serde_json::from_slice(trimmed) {
            Ok(r) => r,
            Err(e) => {
                send(ctl, &Resp::Err { msg: e.to_string() });
                continue;
            }
        };
        match req {
            Req::RunMain { argv, env, cwd } => {
                if children.values().any(|k| *k == ChildKind::Main) {
                    // Only one OCI start is legitimate; a second RunMain would
                    // otherwise overwrite the table entry and orphan the first
                    // main's exit routing.
                    send(ctl, &Resp::Err { msg: "main already running".into() });
                    continue;
                }
                let pid = spawn(&argv, &env, &cwd, None);
                if pid < 0 {
                    send(ctl, &Resp::Err { msg: "fork failed".into() });
                    continue;
                }
                children.insert(pid, ChildKind::Main);
                // main shares the process group already (init is the leader).
                send(ctl, &Resp::Started { pid });
            }
            Req::RunExec { argv, env, cwd, detach } => {
                if fds.len() < 3 {
                    for &fd in &fds {
                        unsafe {
                            libc::close(fd);
                        }
                    }
                    send(ctl, &Resp::Err { msg: "exec needs 3 fds".into() });
                    continue;
                }
                let stdio = [fds[0], fds[1], fds[2]];
                let pid = spawn(&argv, &env, &cwd, Some(stdio));
                for &fd in &fds {
                    unsafe {
                        libc::close(fd);
                    }
                } // parent drops its copies
                if pid < 0 {
                    send(ctl, &Resp::Err { msg: "fork failed".into() });
                    continue;
                }
                children.insert(
                    pid,
                    if detach { ChildKind::ExecDetach } else { ChildKind::ExecAttach },
                );
                send(ctl, &Resp::Started { pid });
            }
            Req::Shutdown => {
                if children.values().any(|k| *k == ChildKind::Main) {
                    unsafe {
                        libc::killpg(libc::getpgrp(), libc::SIGKILL);
                    }
                }
                break;
            }
        }
    }

    // Reached only on `Shutdown` or control-channel EOF (a main-workload exit
    // `_exit`s above). The counter has no wire consumer today — an
    // `Exited`/stat frame for an unannounced pid would be rejected by the
    // supervisor's announced registry — so it is deliberately local; keeping
    // it live documents the init-side reconciliation surface for future
    // metrics wiring.
    let _ = reaped_unknown;
}
