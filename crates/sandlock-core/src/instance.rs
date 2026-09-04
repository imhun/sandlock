//! Sandbox session instance — the explicit owner of a sandbox session's
//! lifecycle (M0 lifecycle lift, fork-plan F2.1).
//!
//! Before M0 the per-sandbox runtime block lived privately inside
//! [`Sandbox`](crate::sandbox::Sandbox): `do_create_stdio` assembled it
//! inline and `Sandbox::wait`/`Drop` tore it down inline, so there was no
//! object that *was* the session — a sandbox session died with its first
//! (and only) process. M0 lifts every session-scoped resource into this
//! module as a named, public type with one explicit teardown verb
//! ([`SandboxInstance::shutdown`]):
//!
//! * the seccomp-notify supervisor task, the `policy_fn` worker, the CPU
//!   throttle and load-average tasks, and the control-listener task;
//! * the F1.3 control directory (hashed dir + identity token + socket);
//! * the DNS gateway task and its per-sandbox loopback address;
//! * the supervisor-side [`ResourceState`](crate::seccomp::state::ResourceState),
//!   [`ProcessIndex`](crate::seccomp::state::ProcessIndex) (F1.4), COW /
//!   network / procfs / policy-fn / time state, and the COW branch.
//!
//! `Sandbox::run`/`popen`/`spawn` keep their exact external semantics by
//! driving a **one-shot instance**: the runtime a `Sandbox` allocates on its
//! first spawn *is* a `SandboxInstance`, and the sandbox's `wait()` is the
//! instance's `wait_one_shot()` — wait for the process, then `shutdown()`.
//! The standalone entry point ([`SandboxInstance::launch`]) hands the
//! session to the caller so it can outlive its first process; M1 adds
//! multi-process `exec`/`wait_child`/`kill_child` on top of this same owner.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::error::{SandboxRuntimeError, SandlockError};
use crate::result::{ExitStatus, RunResult};
use crate::sandbox::{BranchAction, SharedCow};

/// Lifecycle phase of a sandbox session (M0 skeleton).
///
/// The full [`docs/sandbox-exec-security.md` §5.2] state machine
/// (Provisioning/Ready/Active/Frozen/Draining/Dead) lands with F2.2/F2.3;
/// M0 only distinguishes a live session from a shut-down one, which is all
/// `shutdown` has to make idempotent and everything the four lifecycle
/// tests need to observe.
///
/// [`docs/sandbox-exec-security.md` §5.2]: ../../docs/sandbox-exec-security.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstancePhase {
    /// Session live: it owns its supervisor tasks, control directory and
    /// (when configured) DNS gateway; its single (M0) process may be running
    /// or may already have exited.
    Live,
    /// [`SandboxInstance::shutdown`] has run to completion. Every
    /// session-owned resource has been released. Calling `shutdown` again is
    /// a no-op (idempotent).
    ShutDown,
}

/// Session-scoped runtime state, present only while the sandbox is running.
///
/// M0 keeps the single-slot shape of the historical `Runtime` block
/// (one process per session, exactly as `Sandbox` exposes today); the child
/// table lands with M1's `exec`.
pub struct SandboxInstance {
    pub(crate) name: String,
    /// Per-process state of the session's single (M0) child.
    pub(crate) state: RuntimeState,
    pub(crate) child_pid: Option<i32>,
    /// Host PID of the sandbox's first process in its PID namespace (ns
    /// pid 1). `Some` only when `Sandbox::pid_ns` is enabled; the process
    /// group leader, and the pid `Sandbox::pid()` reports. The direct
    /// child (`child_pid`) is then the intermediate process that created
    /// the namespace, waits for the leader, and relays its exit status.
    pub(crate) leader_pid: Option<i32>,
    pub(crate) pidfd: Option<OwnedFd>,
    pub(crate) notif_handle: Option<JoinHandle<()>>,
    pub(crate) policy_fn_worker: Option<crate::policy_fn::PolicyFnWorker>,
    pub(crate) throttle_handle: Option<JoinHandle<()>>,
    pub(crate) loadavg_handle: Option<JoinHandle<()>>,
    pub(crate) control_handle: Option<JoinHandle<()>>,
    /// The F1.3 control directory (hashed per-sandbox dir under
    /// `/tmp/sandlock-ctl-<uid>`, holding `pid`/`token`/`name`/`mode` and,
    /// on the supervisor path, `control.sock`). Present once the runtime dir
    /// was created and kept until [`SandboxInstance::shutdown`].
    pub(crate) control_dir: Option<PathBuf>,
    pub(crate) _stdout_read: Option<OwnedFd>,
    pub(crate) _stderr_read: Option<OwnedFd>,
    // Drains of the capture pipes above, each holding either the task still
    // reading or the bytes it finished with (see `wait_child`). Both states
    // belong to the instance rather than to the `wait` that started them, so
    // a cancelled `wait` takes neither the reader nor what it has produced.
    pub(crate) stdout_drain: Option<ParkedDrain>,
    pub(crate) stderr_drain: Option<ParkedDrain>,
    // Parent-held write end of a piped stdin (popen). The caller takes it via
    // `Process::take_stdin`; closing it signals EOF to the child.
    pub(crate) _stdin_write: Option<OwnedFd>,
    pub(crate) seccomp_cow: Option<crate::cow::seccomp::SeccompCowBranch>,
    pub(crate) supervisor_resource:
        Option<Arc<tokio::sync::Mutex<crate::seccomp::state::ResourceState>>>,
    pub(crate) supervisor_processes: Option<Arc<crate::seccomp::state::ProcessIndex>>,
    pub(crate) supervisor_cow: Option<Arc<tokio::sync::Mutex<crate::seccomp::state::CowState>>>,
    pub(crate) supervisor_network: Option<Arc<tokio::sync::Mutex<crate::seccomp::state::NetworkState>>>,
    pub(crate) ctrl_fd: Option<OwnedFd>,
    pub(crate) stdout_pipe: Option<OwnedFd>,
    pub(crate) io_overrides: Option<(Option<i32>, Option<i32>, Option<i32>)>,
    pub(crate) extra_fds: Vec<(i32, i32)>,
    pub(crate) http_acl_handle: Option<crate::transparent_proxy::HttpAclProxyHandle>,
    pub(crate) dns_gateway_handle: Option<JoinHandle<()>>,
    /// The sandbox's DNS gateway address — a per-sandbox loopback address
    /// (`127.0.1.x`) in the default unprivileged shared-netns mode. The
    /// loopback `:53` listener dies with `dns_gateway_handle`; `shutdown`
    /// releases both, so a torn-down session leaves no stale nameserver.
    pub(crate) dns_gateway_addr: Option<std::net::Ipv4Addr>,
    #[allow(clippy::type_complexity)]
    pub(crate) on_bind: Option<Box<dyn Fn(&HashMap<u16, u16>) + Send + Sync>>,
    pub(crate) handlers: Vec<(i64, Arc<dyn crate::seccomp::dispatch::Handler>)>,
    pub(crate) ready_w: Option<OwnedFd>,
    /// Set when this sandbox is a stage of a [`Transaction`](crate::transaction::Transaction)
    /// that shares one COW upper across all stages. When present,
    /// `do_create_stdio` reuses this `CowState` (instead of building its own
    /// branch), and neither `shutdown` nor `Drop` take/commit/abort the
    /// branch — the transaction coordinator owns the single commit/abort.
    /// See [`SharedCow`].
    pub(crate) shared_cow: Option<SharedCow>,
    // The interactive child took the terminal's foreground process group at
    // spawn; whoever reaps it must hand the foreground back to this process.
    pub(crate) tty_foreground_taken: bool,
    /// Session phase (see [`InstancePhase`]).
    pub(crate) phase: InstancePhase,
    /// COW-branch disposition captured when the session was provisioned.
    ///
    /// Historically the branch action was read off the `Sandbox` config at
    /// `Drop` time. A `SandboxInstance` can outlive the `Sandbox` that
    /// provisioned it, so the instance carries its own copy from spawn on;
    /// the sandbox-side builder paths (`dry_run`, transactions) mutate these
    /// fields before spawn, which is exactly when the snapshot is taken.
    pub(crate) on_exit: BranchAction,
    pub(crate) on_error: BranchAction,
}

/// Lifecycle state of the session's single (M0) child.
#[derive(Clone)]
pub(crate) enum RuntimeState {
    Created,
    Running,
    Paused,
    Stopped(ExitStatus),
}

impl SandboxInstance {
    // ================================================================
    // Standalone entry point (explicit instance API)
    // ================================================================

    /// Launch a session from a config `Sandbox`: spawn the first process with
    /// capture stdio (stdin inherited; stdout/stderr piped and drained into
    /// the [`RunResult`] `wait_child` returns) and release it to `execve`,
    /// like `Sandbox::spawn` — except the assembled session state is handed
    /// to the returned instance instead of remaining inside the (consumed)
    /// policy `Sandbox`.
    ///
    /// M0 semantics: the instance owns exactly one process. The process can
    /// exit and the session stays alive — its runtime, control directory and
    /// DNS gateway remain until [`SandboxInstance::shutdown`]. M1 generalizes
    /// the single-process entry into `exec` with per-child ids/stdio.
    ///
    /// The `policy` must not already be started (`Sandbox` is one-process per
    /// session). On failure the child is cleaned up exactly as an abandoned
    /// `Sandbox` would be.
    pub async fn launch(
        mut policy: crate::sandbox::Sandbox,
        cmd: &[&str],
    ) -> Result<SandboxInstance, SandlockError> {
        // The one-shot `Sandbox::spawn` steps, assembled on the consumed
        // policy sandbox; the session block is then moved out into the
        // returned instance (see module docs).
        policy.ensure_runtime()?;
        policy.do_create(cmd, true).await?;
        policy.do_start()?;
        let rt = policy
            .runtime
            .take()
            .expect("do_create installed the session runtime");
        Ok(*rt)
    }

    // ================================================================
    // Session lifecycle verbs
    // ================================================================

    /// Wait for the session's process to exit and return its captured result.
    ///
    /// The session itself stays alive: the control directory, DNS gateway and
    /// supervisor-side state are *not* released here — that is
    /// [`SandboxInstance::shutdown`]'s job. Like the historical `Sandbox::wait`,
    /// this is cancellation-safe: a cancelled `wait_child` parks any output it
    /// had already drained and a later call (or `shutdown`) picks it up.
    pub async fn wait_child(&mut self) -> Result<RunResult, SandlockError> {
        let pid = self.child_pid.ok_or(SandboxRuntimeError::NotRunning)?;

        // Already reaped: hand back the same status again, plus whatever the
        // drains collected. They outlive the `wait` that started them, so a
        // second call still reports the output of a first one that was
        // cancelled — including one cancelled while joining them here, since a
        // join only unparks a drain once it has completed. A `wait` that ran
        // to the end took them with it, and both streams are then `None`.
        let stopped = match self.state {
            RuntimeState::Stopped(ref es) => Some(es.clone()),
            _ => None,
        };
        if let Some(exit_status) = stopped {
            let (stdout, stderr) = self.collect_pipe_drains().await;
            return Ok(RunResult { exit_status, stdout, stderr });
        }

        // Deliver EOF to a piped stdin the caller never took: otherwise a child
        // that reads stdin (e.g. `cat`) blocks forever and this wait never
        // returns. A taken stdin is already None here (the caller owns it).
        drop(self._stdin_write.take());

        // Start draining the capture pipes BEFORE waiting for the child to exit.
        //
        // Reading them after the exit wait deadlocks the moment the child writes
        // more than one pipe buffer (64 KiB by default): the pipe fills, the
        // child blocks in `write()` and can never exit, while this function waits
        // for exactly that exit. Draining concurrently keeps the pipe moving, so
        // the child can finish writing and exit, and the reads still end at EOF —
        // which arrives once the child and every descendant holding the write
        // end are gone.
        //
        // The drains are parked in the instance rather than in this future: a
        // caller that cancels `wait_child` (a `timeout` or `select!` around it)
        // must be able to call it again and still be given the output. The
        // `is_none()` guard is what makes that second call reuse them instead of
        // starting a second reader. A stream the caller took through
        // `Process::take_stdout`/`take_stderr` is `None` here and stays theirs.
        if self.stdout_drain.is_none() {
            if let Some(fd) = self._stdout_read.take() {
                self.stdout_drain = spawn_pipe_drain(fd);
            }
        }
        if self.stderr_drain.is_none() {
            if let Some(fd) = self._stderr_read.take() {
                self.stderr_drain = spawn_pipe_drain(fd);
            }
        }

        // Wait for the top-level child to exit. Prefer the child's pidfd via
        // `AsyncFd`: pidfd readiness fires only on *exit*, so — unlike a
        // `waitpid` loop — it never consumes the child's ptrace-stops, which
        // the `policy_fn` fork-tracking worker reaps (`waitpid` with any flags
        // reaps a tracee's ptrace-stops, so a concurrent `waitpid` here would
        // race the worker for fork events and hang it). Mirrors
        // `spawn_pid_watcher`. Falls back to a blocking `waitpid` only when no
        // pidfd is available (kernel without `pidfd_open`).
        let exit_status = match self.pidfd.take() {
            Some(pidfd) => wait_child_exit_via_pidfd(pidfd, pid).await,
            None => wait_child_exit_blocking(pid).await,
        };

        self.state = RuntimeState::Stopped(exit_status.clone());

        if self.tty_foreground_taken {
            // The foreground process group is the sandbox leader's (ns pid
            // 1); with a PID namespace that is `leader_pid`, not the direct
            // child we waited on.
            let fg_pid = self.leader_pid.unwrap_or(pid);
            restore_tty_foreground(fg_pid);
            self.tty_foreground_taken = false;
        }

        let (stdout, stderr) = self.collect_pipe_drains().await;

        Ok(RunResult { exit_status, stdout, stderr })
    }

    /// Shut the session down: release every session-owned resource.
    ///
    /// Idempotent — calling it again (or after the instance was already
    /// dropped) is a no-op. M0 ordering is the pragmatic subset of §5.3's
    /// fixed shutdown sequence needed to make teardown complete and leak-free;
    /// F2.2 formalizes the full seven-step order (Draining → init `Shutdown`
    /// frame + grace → per-child pidfd SIGKILL → group killpg sweep → host-side
    /// stdio close → task aborts → token-verified control-dir removal → port/
    /// budget/log return) and its escalation knobs.
    ///
    /// A session with a still-running first process is killed and reaped here,
    /// exactly like dropping an un-waited `Sandbox`; the process never
    /// survives its session.
    pub async fn shutdown(&mut self) -> Result<(), SandlockError> {
        if self.phase == InstancePhase::ShutDown {
            return Ok(());
        }

        // 1. Kill + reap a live first process (full §5.3 escalation is F2.2),
        //    so the control-dir removal below is final. Record the reaped
        //    status so a later `wait_child` stays well-defined.
        if let Some(exit) = self.kill_and_reap() {
            self.state = RuntimeState::Stopped(exit);
        }
        // 2. Abort the supervisor-side session tasks: notif supervisor,
        //    policy_fn worker, throttle, loadavg, control listener, and the
        //    DNS gateway (whose `:53` listener dies with its task).
        self.abort_session_tasks();
        // 3. Nobody is left to collect capture drains; aborting closes the
        //    read ends. A drain that already finished holds only bytes.
        self.abort_drains();
        // 4. Remove the F1.3 control directory (pid/token/name/mode/socket).
        if let Some(ref dir) = self.control_dir {
            crate::control::cleanup_runtime_dir(dir);
        }
        // 5. Take the COW branch out of the shared supervisor state so the
        //    instance's Drop applies Commit/Abort/Keep exactly once (the
        //    transactional-pipeline stage leaves its shared branch untouched —
        //    the coordinator owns that commit/abort).
        if self.shared_cow.is_none() {
            if let Some(ref cow_state) = self.supervisor_cow.clone() {
                let mut cow = cow_state.lock().await;
                self.seccomp_cow = cow.branch.take();
            }
        }

        self.phase = InstancePhase::ShutDown;
        Ok(())
    }

    /// One-shot session wait: `Sandbox::wait`'s implementation. Waits for the
    /// session's process and then shuts the session down, which is what keeps
    /// `Sandbox::run`/`popen`/`spawn` one-shot: their caller never sees a
    /// live session after the process exits.
    pub(crate) async fn wait_one_shot(&mut self) -> Result<RunResult, SandlockError> {
        let result = self.wait_child().await?;
        self.shutdown().await?;
        Ok(result)
    }

    /// Kill and reap the session's process if it is still running (the Drop /
    /// pre-shutdown backstop; mirrors the historical `Sandbox::drop` steps).
    /// Returns the reaped status when this call actually reaped the child
    /// (`None` when nothing was running, or when the child was already
    /// reaped). Like the historical `Drop`, this does *not* mutate `state`;
    /// callers decide whether to record the status (`shutdown` does, `Drop`
    /// deliberately does not, preserving the old drop-time disposition).
    fn kill_and_reap(&mut self) -> Option<ExitStatus> {
        if let Some(pid) = self.child_pid {
            let mut reaped: Option<ExitStatus> = None;
            if matches!(
                self.state,
                RuntimeState::Created | RuntimeState::Running | RuntimeState::Paused
            ) {
                // Signal the sandbox leader's process group (ns pid 1 with a
                // PID namespace); the direct child then exits on its own (it
                // waits for the leader) and is reaped below.
                let group = self.leader_pid.unwrap_or(pid);
                unsafe { libc::killpg(group, libc::SIGKILL) };
                let mut status: i32 = 0;
                if unsafe { libc::waitpid(pid, &mut status, 0) } > 0 {
                    reaped = Some(sandbox_wait_status_to_exit(status));
                }
            }
            if self.tty_foreground_taken {
                let fg_pid = self.leader_pid.unwrap_or(pid);
                restore_tty_foreground(fg_pid);
                self.tty_foreground_taken = false;
            }
            return reaped;
        }
        None
    }

    /// Abort every supervisor-side session task (best-effort; each handle is
    /// taken so repeated calls are no-ops).
    fn abort_session_tasks(&mut self) {
        if let Some(h) = self.notif_handle.take() {
            h.abort();
        }
        self.policy_fn_worker = None;
        if let Some(h) = self.throttle_handle.take() {
            h.abort();
        }
        if let Some(h) = self.loadavg_handle.take() {
            h.abort();
        }
        if let Some(h) = self.control_handle.take() {
            h.abort();
        }
        // The loopback `127.0.1.x:53` listener dies with this task, so a
        // session teardown does not leak a stale nameserver.
        if let Some(h) = self.dns_gateway_handle.take() {
            h.abort();
        }
    }

    /// Abort capture drains that are still reading (shutdown / Drop only).
    fn abort_drains(&mut self) {
        for slot in [self.stdout_drain.take(), self.stderr_drain.take()] {
            if let Some(ParkedDrain::Running(h)) = slot {
                h.abort();
            }
        }
    }

    /// Synchronous teardown used by `Drop` (both the `Sandbox` that embeds a
    /// session and a standalone instance): kill + reap, abort session tasks,
    /// abort drains, remove the control directory, and dispose a taken COW
    /// branch per the recorded disposition and exit status.
    pub(crate) fn drop_teardown(&mut self) {
        self.kill_and_reap();
        self.abort_session_tasks();
        self.abort_drains();

        // Clean up the per-sandbox runtime dir on abnormal exit / Drop.
        if let Some(ref dir) = self.control_dir {
            crate::control::cleanup_runtime_dir(dir);
        }

        let is_error = matches!(
            self.state,
            RuntimeState::Stopped(ref s) if !matches!(s, ExitStatus::Code(0))
        );
        let action = if is_error { &self.on_error } else { &self.on_exit };
        let action = action.clone();

        if let Some(ref mut cow) = self.seccomp_cow {
            match action {
                // NOTE: commit() is synchronous and blocks up to
                // DROP_COMMIT_LOCK_WAIT (5s) on a contended workdir before
                // deferring (bounded, no CPU spin). Do not drop a committing
                // instance on an async runtime worker.
                BranchAction::Commit => {
                    let _ = cow.commit();
                }
                BranchAction::Abort => {
                    let _ = cow.abort();
                }
                // Mark kept so the branch's Drop backstop preserves the upper
                // instead of cleaning it as an undisposed leak.
                BranchAction::Keep => cow.keep(),
            }
        }
    }

    /// Join the capture-pipe drains, if this session still holds them.
    ///
    /// Only called once the child has been reaped, so the EOF each drain is
    /// reading towards is already reachable — but not necessarily *reached*: a
    /// descendant that inherited the write end keeps the join blocked for as
    /// long as it lives, which is exactly when a caller's timeout fires. So
    /// each handle is joined in place and only unparked once that join
    /// completes; see `finish_parked_drain`.
    ///
    /// `None` means the stream was never piped, was taken by the caller, or was
    /// already collected by an earlier wait; a drain that panicked or was
    /// aborted reports empty bytes rather than failing the run.
    async fn collect_pipe_drains(&mut self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        // Finish both first — each stores its bytes into the instance as it
        // completes — and only then take them out. A cancellation between the
        // two joins therefore loses nothing: whatever finished is parked.
        // One statement per stream: each borrow of the instance ends with it.
        finish_parked_drain(&mut self.stdout_drain).await;
        finish_parked_drain(&mut self.stderr_drain).await;
        let stdout = take_drained(&mut self.stdout_drain);
        let stderr = take_drained(&mut self.stderr_drain);
        (stdout, stderr)
    }

    // ================================================================
    // Introspection (minimal M0 surface; stats exposure is F2.3)
    // ================================================================

    /// The session's lifecycle phase (see [`InstancePhase`]).
    pub fn phase(&self) -> InstancePhase {
        self.phase
    }

    /// The session's (single, M0) process PID, or `None` before launch. Remains
    /// `Some` after the process exits, until the instance is dropped.
    pub fn pid(&self) -> Option<i32> {
        self.leader_pid.or(self.child_pid)
    }

    /// The F1.3 control directory path, when the session created one
    /// (supervisor sessions always do; `control_socket=false` sessions do
    /// not). The directory exists while the session is live and is removed by
    /// [`SandboxInstance::shutdown`].
    pub fn control_dir(&self) -> Option<&PathBuf> {
        self.control_dir.as_ref()
    }

    /// The session's DNS gateway address (only when wildcard-domain rules made
    /// a gateway necessary). The gateway's `:53` listener is live while the
    /// session is live and is released by [`SandboxInstance::shutdown`].
    pub fn dns_gateway_addr(&self) -> Option<std::net::Ipv4Addr> {
        self.dns_gateway_addr
    }
}

impl Drop for SandboxInstance {
    fn drop(&mut self) {
        // Standalone instances and `Sandbox`-embedded sessions share one
        // synchronous backstop: a dropped session never leaves a live
        // process, task, control dir or un-disposed branch behind.
        self.drop_teardown();
    }
}

// ================================================================
// Parked drains
// ================================================================

pub(crate) enum ParkedDrain {
    Running(JoinHandle<Vec<u8>>),
    Done(Vec<u8>),
}

/// Spawn a task that reads one capture pipe to EOF, for `wait_child` to join
/// once the child has been reaped.
///
/// An ordinary task, not `spawn_blocking`: a blocking read would hold a thread
/// of the shared blocking pool for the child's entire lifetime (even for a
/// child that writes nothing), and that pool is also what the COW copier and
/// the fork-tracking worker need *while* a child is alive, so a saturated pool
/// is a deadlock rather than a slowdown.
///
/// `Receiver::from_owned_fd` sets O_NONBLOCK on this fd and registers it with
/// the runtime's I/O driver (which `wait_child` needs anyway, for the pidfd).
/// The flag belongs to the open file description behind the *read* end; the
/// child writes to the write end, a separate description, so its `write()`s
/// stay blocking, which is what keeps the pipe applying back-pressure rather
/// than dropping output. The conversion can only fail if the fd is not a
/// readable pipe, which cannot happen for the pipes `do_create_stdio` creates;
/// if it somehow did, the stream is left uncaptured rather than the run
/// failing.
fn spawn_pipe_drain(fd: OwnedFd) -> Option<ParkedDrain> {
    let mut rx = match tokio::net::unix::pipe::Receiver::from_owned_fd(fd) {
        Ok(rx) => rx,
        Err(_) => return None,
    };
    Some(ParkedDrain::Running(tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let _ = rx.read_to_end(&mut buf).await;
        buf
    })))
}

/// Drive one parked drain to completion, leaving its bytes in the slot.
///
/// The handle is awaited *through* the slot, and the store happens in the same
/// step as the await resolving, so there is no point at which the bytes exist
/// only inside this future: cancelling it leaves either the still-running task
/// or the finished bytes parked for the next wait. Taking the handle out first
/// would hand it to the awaiting future, so dropping that future (which is all
/// a caller's `timeout` or `select!` does) would drop the handle with it and
/// every later wait would report no output.
///
/// This join is not instantaneous: the child is reaped by the time it runs,
/// but a descendant still holding the write end keeps the read short of EOF,
/// which is precisely the case a caller times out on. `JoinHandle` is `Unpin`,
/// so it can be polled through `&mut`, and dropping this future does not abort
/// the task: the drain left behind is still reading and a later wait picks it
/// up.
///
/// A drain that panicked or was aborted parks empty bytes, so the run reports
/// an empty capture rather than failing.
pub(crate) async fn finish_parked_drain(slot: &mut Option<ParkedDrain>) {
    if let Some(ParkedDrain::Running(handle)) = slot.as_mut() {
        let buf = handle.await.unwrap_or_default();
        *slot = Some(ParkedDrain::Done(buf));
    }
}

/// Unpark the bytes of a drain that has finished. Not async on purpose: it runs
/// after every join, so no cancellation can land between the two streams.
pub(crate) fn take_drained(slot: &mut Option<ParkedDrain>) -> Option<Vec<u8>> {
    match slot.take() {
        Some(ParkedDrain::Done(buf)) => Some(buf),
        // Still running (nothing joined it) — leave it parked.
        other => {
            *slot = other;
            None
        }
    }
}

// ================================================================
// Exit-status helpers
// ================================================================

fn sandbox_wait_status_to_exit(status: i32) -> ExitStatus {
    if libc::WIFEXITED(status) {
        ExitStatus::Code(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        if sig == libc::SIGKILL {
            ExitStatus::Killed
        } else {
            ExitStatus::Signal(sig)
        }
    } else {
        ExitStatus::Killed
    }
}

/// Await the top-level child's exit via its `pidfd` (readable on exit only),
/// then reap the status. Because it never calls `waitpid` until the child has
/// already exited, it does not consume the child's ptrace-stops the way a
/// `waitpid`-loop would — so it doesn't race the `policy_fn` fork-tracking
/// worker. Falls back to the blocking waiter on any pidfd/`AsyncFd` error.
async fn wait_child_exit_via_pidfd(pidfd: OwnedFd, pid: libc::pid_t) -> ExitStatus {
    let async_fd = match tokio::io::unix::AsyncFd::with_interest(
        pidfd,
        tokio::io::Interest::READABLE,
    ) {
        Ok(fd) => fd,
        Err(_) => return wait_child_exit_blocking(pid).await,
    };

    loop {
        // pidfd becomes readable when the process exits; no data is read.
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(_) => return ExitStatus::Killed,
        };
        let mut status: i32 = 0;
        // The child has exited and is reapable now, so this never blocks.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r > 0 {
            return sandbox_wait_status_to_exit(status);
        }
        if r == 0 {
            // Spurious readiness (not yet reapable): clear and re-await.
            guard.clear_ready();
            continue;
        }
        // r < 0 (e.g. ECHILD): already reaped elsewhere. Status is unavailable.
        return ExitStatus::Killed;
    }
}

/// Blocking `waitpid` fallback for kernels without `pidfd_open`. Used only when
/// no pidfd is available; on such kernels `policy_fn` fork-tracking is the only
/// thing that could race it, and the lack of pidfd is itself rare.
async fn wait_child_exit_blocking(pid: libc::pid_t) -> ExitStatus {
    tokio::task::spawn_blocking(move || -> ExitStatus {
        let mut status: i32 = 0;
        loop {
            let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
            if ret < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return ExitStatus::Killed;
            }
            break;
        }
        sandbox_wait_status_to_exit(status)
    })
    .await
    .unwrap_or(ExitStatus::Killed)
}

// ================================================================
// TTY foreground handback
// ================================================================

/// Hand the terminal's foreground process group back to this process after
/// reaping an interactive child that took it. Restores only while the child's
/// group still owns the terminal, so a foreground the caller has since given
/// to someone else is left alone. SIGTTOU is blocked around `tcsetpgrp`:
/// this process is a background group at that moment, and an unblocked
/// SIGTTOU would stop it, which is the exact symptom being prevented.
fn restore_tty_foreground(child_pid: i32) {
    unsafe {
        if libc::isatty(0) != 1 || libc::tcgetpgrp(0) != child_pid {
            return;
        }
        let mut block: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut block);
        libc::sigaddset(&mut block, libc::SIGTTOU);
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, &block, &mut old);
        libc::tcsetpgrp(0, libc::getpgrp());
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
    }
}
