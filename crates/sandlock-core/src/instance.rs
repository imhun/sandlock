//! Sandbox session instance — the explicit owner of a sandbox session's
//! lifecycle (M0 lifecycle lift, fork-plan F2.1/F2.2).
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
//!
//! F2.2 formalizes [`SandboxInstance::shutdown`] as the seven-step §5.3
//! sequence (Draining → graceful request + grace → per-child pidfd SIGKILL →
//! group killpg → host-side stdio close → task aborts → token-verified
//! control-dir removal → port/budget/log return), fully idempotent and with
//! a configurable grace window.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::error::{SandboxRuntimeError, SandlockError};
use crate::init::executor::{open_child_pidfd, ExecLink};
use crate::init::{Req, Resp, CONTROL_FD};
use crate::result::{ExitStatus, RunResult};
use crate::sandbox::{BranchAction, SharedCow};
use crate::seccomp::notif::{NetworkPolicy, PortAllow};

pub use crate::exec_params::ExecParams;
use crate::exec_params::ExecCeiling;

/// Lifecycle phase of a sandbox session (M0 shutdown skeleton + M1 exec-mode
/// terminal semantics).
///
/// A `SandboxInstance` runs in one of two explicit modes:
///
/// * **one-shot mode** — created with [`SandboxInstance::launch`] (and every
///   `Sandbox::run`/`popen`/`spawn` session): its single M0 process may exit
///   while the session stays `Live` (outlives-first-process semantics) until
///   [`SandboxInstance::shutdown`] or drop;
/// * **exec mode** — created with [`SandboxInstance::launch_exec`] /
///   [`SandboxInstance::launch_exec_only`]: the confined direct child is
///   `sandlock-init`. In exec mode the session is **terminal when init
///   exits**: with a main child (id 0) that means the main workload's exit
///   ended the container (init collapses every group and exits); without a
///   main it means init died unexpectedly. The phase then reads `Exited` and
///   every exec/wait/kill/resize verb returns the unified
///   [`SandboxRuntimeError::InstanceClosed`] error; `shutdown` still cleans
///   the session up and ends at `ShutDown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstancePhase {
    /// Session live: it owns its supervisor tasks, control directory and
    /// (when configured) DNS gateway; its single (M0) process may be running
    /// or may already have exited.
    Live,
    /// §5.2 `Draining`: [`SandboxInstance::shutdown`] has begun. New work is
    /// refused (M0 has no `exec` verb to refuse — the phase is the M1 hook),
    /// and the fixed seven-step teardown is running. A shutdown future that is
    /// cancelled mid-flight leaves the instance here; the next `shutdown`
    /// call resumes from step 1 and each step is safe to re-run.
    Draining,
    /// [`SandboxInstance::shutdown`] has run to completion. Every
    /// session-owned resource has been released. Calling `shutdown` again is
    /// a no-op (idempotent).
    ShutDown,
    /// Exec mode only: the confined `sandlock-init` control link terminated
    /// on its own (the main child exited and init collapsed the container, or
    /// init died unexpectedly). The session is over — every exec-mode verb
    /// returns the unified closed-instance error, `children_live` reads 0,
    /// and a later `shutdown` only performs the resource cleanup tail.
    Exited,
}

/// M0 instance stats snapshot (fork-plan F2.3; the §5.6 subset expressible
/// with one direct child).
///
/// [`SandboxInstance::stats`] builds this from the supervisor-side process
/// accounting (F1.4) plus the instance's own child/phase bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceStats {
    /// Signed deviation between the supervisor's bookkeeping process count
    /// and its live pidfd-watcher count (`proc_count − live_watchers`).
    ///
    /// This is the F1.4 reconciler
    /// [`ProcessStats::drift`](crate::sandbox::ProcessStats::drift) exposed
    /// under the §5.6 name; the two fields are the same number and the F1.4
    /// surface keeps the raw counts. Zero is the quiescent expectation while
    /// the session is live (argv-safety mode); a persistent *positive* drift
    /// is the SL-8 orphan-leak alarm. Drift is transiently *negative* during
    /// exit cleanup: cleanup releases the `proc_count` slot before it
    /// unregisters the exiting process's `ProcessIndex` entry, so a snapshot
    /// in that window counts one fewer bookkeeping slot than live watchers —
    /// it resolves to zero once the unregister lands. Reports 0 before the
    /// supervisor state exists.
    pub proc_count_vs_live: i64,
    /// Live session-owned children.
    ///
    /// One-shot mode: the session has one direct child, so this is 0 or 1
    /// (the child counts from launch until reaped). Exec mode: announced
    /// children whose exit a wait has not consumed (N children with
    /// per-child exit state). Reads 0 once an exec-mode session is terminal
    /// (`Exited`) even before a verb re-synchronizes the stored phase.
    pub children_live: u32,
    /// The session's lifecycle phase (see [`InstancePhase`]) — `Live` /
    /// `Draining` / `ShutDown`, plus exec-mode `Exited` (terminal on init
    /// exit). The `Dead` error state with reason counters remains §5.6/F5.
    pub instance_state: InstancePhase,
}

/// Result of a session network update (fork-plan F4.3/S2).
///
/// A session-level `update_network` binds to **new execs only**: the policy
/// is captured per child at exec time (F4.4), so children already running
/// keep the policy they were created under and are reported here as stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkStaleness {
    /// Child ids of running (not yet reaped) children that keep their
    /// exec-time network policy — the update does not apply to them.
    pub stale_child_ids: Vec<u64>,
}

/// A per-child token assigned by an exec-capable session's executor. Child
/// ids are never pids: they name a registered child (F1.2 announced
/// registry), and per-child signals resolve the token to the child's pidfd
/// host-side (F1.7: no pid-addressed signal verb exists anywhere on the
/// init channel).
pub type ChildId = u64;

/// Stdio wiring for one `exec` child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStdio {
    /// Create three cloexec pipes; the child-side ends are delivered to init
    /// over SCM_RIGHTS and the caller keeps the host ends in the returned
    /// [`ExecHandle`] (stdin write end, stdout/stderr read ends).
    Piped,
    /// The child inherits the session process's stdio (0/1/2).
    Inherit,
    /// The child's stdio is wired to `/dev/null`.
    Null,
    /// Create a pty; the slave becomes the child's stdin/stdout/stderr and
    /// the caller keeps the master in [`ExecHandle::pty`] (usable with
    /// [`SandboxInstance::resize_child`]).
    Pty,
}

/// Result of [`SandboxInstance::exec`]: the registered child id plus the
/// caller-owned host ends of each requested stream.
#[derive(Debug)]
pub struct ExecHandle {
    /// Registered child id for `wait_child`/`kill_child`/`resize_child`.
    pub child_id: ChildId,
    /// Host pid of the registered child (init-reported, announced registry).
    pub pid: i32,
    /// Host write end of the piped stdin (Piped only).
    pub stdin: Option<OwnedFd>,
    /// Host read end of the piped stdout (Piped only).
    pub stdout: Option<OwnedFd>,
    /// Host read end of the piped stderr (Piped only).
    pub stderr: Option<OwnedFd>,
    /// Host-side pty master (Pty only), used by `resize_child`.
    pub pty: Option<OwnedFd>,
}

/// One configured inbound (S2.5 `net_bind_map`) mapping with its live
/// listener state — the supervise `ports` verb's per-entry view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundMapping {
    /// The port the sandbox binds and listens on inside its netns.
    pub sandbox_port: u16,
    /// The host-loopback port the supervisor listens on for this mapping
    /// (reserved 50005+ range).
    pub host_port: u16,
    /// Whether a live host-side listener currently exists for this mapping
    /// (the sandbox called `listen()` on `sandbox_port` and the supervisor's
    /// S2.5 listener is up and being served).
    pub live: bool,
}

/// Live network-port snapshot for a sandbox session (the supervise `ports`
/// verb surface): configured inbound mappings plus the live port-remap
/// table. Both halves come from the supervisor-side `NetworkState`, so the
/// report reflects the request-time truth rather than a static registry.
#[derive(Debug, Clone, Default)]
pub struct InstancePorts {
    /// Configured inbound mappings, sorted by sandbox port.
    pub inbound: Vec<InboundMapping>,
    /// Live virtual → real port-remap table (`port_remap`).
    pub port_remap: std::collections::HashMap<u16, u16>,
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
    /// F3.2 exec-mode session state. `Some` only for sessions launched with
    /// [`SandboxInstance::launch_exec`] /
    /// [`SandboxInstance::launch_exec_only`]; the M0 single-child fields
    /// above then describe the confined `sandlock-init` direct child and the
    /// per-child table lives here. `None` = one-shot mode (legacy `launch`
    /// / `Sandbox`-embedded sessions), whose outlives-first-process
    /// semantics are unchanged.
    pub(crate) exec_session: Option<Box<ExecSession>>,
    /// F4.2 (S9): the immutable per-exec ceiling captured from the policy at
    /// session creation. `Some` for exec-capable sessions only; the M0
    /// single-process sessions have no exec surface to validate.
    pub(crate) exec_ceiling: Option<ExecCeiling>,
}

/// Lifecycle state of the session's single (M0) child.
#[derive(Clone)]
pub(crate) enum RuntimeState {
    Created,
    Running,
    Paused,
    Stopped(ExitStatus),
}

/// Per-child bookkeeping for an exec-capable session (F3.2).
pub(crate) struct ExecSession {
    /// The daemon end of the control channel to the confined `sandlock-init`.
    link: Arc<ExecLink>,
    /// Next host-assigned child id. The main child (launch_exec argv) is
    /// registered as child id 0 at launch; `exec` children get 1, 2, ...
    next_child_id: u64,
    /// Per-child registry: id -> pid/pidfd/exit cache.
    children: HashMap<u64, ExecChild>,
    /// F4.3: the session network policy to bind to the **next** exec child
    /// (set by `update_network`). `None` = children use the instance default
    /// (shared live/static policy path). Running children are never rebound.
    next_net_policy: Option<crate::seccomp::notif::NetworkPolicy>,
    /// Generation of `next_net_policy`: bumped on every `update_network`.
    /// Each exec child records the generation it was bound under; staleness
    /// compares it to the current generation.
    next_net_gen: u64,
}

/// One registered child of an exec-capable session.
pub(crate) struct ExecChild {
    /// Host pid of the child (init-reported, announced registry).
    pid: i32,
    /// Host-side pidfd opened when the child was announced; the per-child
    /// signal handle for `kill_child` (never a pid-addressed wire verb).
    pidfd: Option<OwnedFd>,
    /// Host-side pty master for a pty exec (used by `resize_child`).
    pty: Option<OwnedFd>,
    /// Reaped exit status, cached for idempotent `wait_child`.
    status: Option<ExitStatus>,
    /// F4.3: session network-policy generation this child was bound under
    /// (0 = instance default). `update_network` reports children whose
    /// generation is older than the new one as stale.
    net_gen: u64,
}

impl SandboxInstance {
    // ================================================================
    // Standalone entry point (explicit instance API)
    // ================================================================

    /// Launch a session from a config `Sandbox`: spawn the first process with
    /// capture stdio (stdin inherited; stdout/stderr piped and drained into
    /// the [`RunResult`] `wait_child` returns) and release it to `execve`.
    /// The assembled session state is handed to the returned instance instead
    /// of remaining inside the (consumed) policy `Sandbox`.
    ///
    /// Unlike [`Sandbox::spawn`](crate::sandbox::Sandbox::spawn) — which is
    /// `create` + `start` **plus** `wait_until_exec` — this returns as soon
    /// as the child has been released, without the exec-completion barrier.
    /// `spawn` adds that barrier because its caller immediately inspects
    /// post-exec state (e.g. `checkpoint()` reads `/proc/<pid>/exe`); a
    /// session handed to the caller outlives its process, so exec completion
    /// is observable through `wait_child`/`shutdown` and M1 exposes an
    /// explicit release verb. `Sandbox::popen` has the same no-barrier
    /// shape.
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

    /// Launch an **exec-capable** session (F3.2): the confined direct child
    /// is `sandlock-init` (core::init::run_init) running over a CONTROL_FD
    /// socketpair, and `cmd` is registered as the session's main child
    /// (child id 0) via a `RunMain` request. Additional commands are added
    /// with [`SandboxInstance::exec`], each getting its own child id and
    /// stdio delivered to init over SCM_RIGHTS.
    ///
    /// This is the additive M1 sibling of [`SandboxInstance::launch`]: the
    /// M0 single-child fields of the returned instance describe the direct
    /// confined child (init), while the per-child table lives in the
    /// `exec_session` and `pid()` reports the main workload (child 0), not
    /// init. Legacy sessions created with `launch` (and every
    /// `Sandbox::run`/`popen`/`spawn` one-shot) keep their exact M0
    /// semantics; they are not exec-capable.
    ///
    /// `cmd` must be non-empty (argv[0] is the executable). On failure the
    /// session is cleaned up exactly as an abandoned `Sandbox` would be.
    async fn launch_exec_inner(
        mut policy: crate::sandbox::Sandbox,
        cmd: Option<&[&str]>,
    ) -> Result<SandboxInstance, SandlockError> {
        // F4.2 (S9): the ceiling is fixed from the policy *before* anything
        // mutates it — every later exec request is validated against this
        // snapshot and can never widen it.
        let ceiling = ExecCeiling::from_policy(&policy);
        if let Some(cmd) = cmd {
            if cmd.is_empty() {
                return Err(SandboxRuntimeError::Child(
                    "empty command for exec session".into(),
                )
                .into());
            }
        }
        let (daemon_ctl, child_ctl) = UnixStream::pair().map_err(SandboxRuntimeError::Io)?;
        // The confined init (and with it the RunMain workload, which inherits
        // init's stdio) is wired to /dev/null: an exec-capable session's
        // output is delivered per-child through `exec` stdio, and the
        // supervisor's own stdio must never fill up with workload output
        // (the legacy launch path discarded captures the same way).
        policy.ensure_runtime()?;
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(SandboxRuntimeError::Io)?;
        let null_raw = null.as_raw_fd();
        policy.set_child_stdio_override(Some(null_raw), Some(null_raw), Some(null_raw));
        policy
            .create_with_in_child_main(
                "sandlock-init",
                vec![(CONTROL_FD, child_ctl.as_raw_fd())],
                crate::init::run_init,
            )
            .await?;
        drop(child_ctl);
        policy.do_start()?;
        let mut rt = *policy
            .runtime
            .take()
            .expect("create_with_in_child_main installed the session runtime");

        // Daemon end of the control channel: a blocking dup for the writer
        // and a tokio stream for the background reader (same split the OCI
        // supervisor uses). The reader task is spawned on the current
        // runtime, which also drives the instance's supervisor tasks.
        let writer = daemon_ctl
            .try_clone()
            .map_err(SandboxRuntimeError::Io)?;
        daemon_ctl
            .set_nonblocking(true)
            .map_err(SandboxRuntimeError::Io)?;
        let reader = tokio::net::UnixStream::from_std(daemon_ctl)
            .map_err(SandboxRuntimeError::Io)?;
        let link = ExecLink::new(writer, reader);
        rt.exec_ceiling = Some(ceiling);
        rt.exec_session = Some(Box::new(ExecSession {
            link: link.clone(),
            next_child_id: 1,
            children: HashMap::new(),
            next_net_policy: None,
            next_net_gen: 0,
        }));

        // Register the main workload as child id 0 when the caller asked for
        // one. If this fails the half-built session is dropped here; the
        // exec-aware Drop backstop kills init and collapses whatever exists.
        if let Some(cmd) = cmd {
            let argv: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
            let reply = match link
                .request(
                    0,
                    &Req::RunMain {
                        argv,
                        env: vec![],
                        cwd: None,
                    },
                    &[],
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    drop(rt);
                    return Err(e);
                }
            };
            let pid = match reply {
                Resp::Started { pid } => pid,
                Resp::Err { msg } => {
                    drop(rt);
                    return Err(SandboxRuntimeError::Child(msg).into());
                }
                other => {
                    drop(rt);
                    return Err(SandboxRuntimeError::Child(format!(
                        "unexpected init reply to RunMain: {other:?}"
                    ))
                    .into());
                }
            };
            let session = rt
                .exec_session
                .as_mut()
                .expect("exec session installed before RunMain");
            session.children.insert(
                0,
                ExecChild {
                    pid,
                    pidfd: open_child_pidfd(pid),
                    pty: None,
                    status: None,
                    net_gen: 0,
                },
            );
        }
        Ok(rt)
    }

    /// Launch an **exec-capable** session with a main workload (child id 0),
    /// and:
    ///
    /// * [`SandboxInstance::launch_exec`] — `cmd` runs as the session's main
    ///   child, exactly as the F3.1 report maps M0's single process into the
    ///   per-child table;
    /// * [`SandboxInstance::launch_exec_only`] — no main process: the
    ///   session starts with `sandlock-init` only and every command arrives
    ///   through [`SandboxInstance::exec`] (the E2B S12 shape — no "main
    ///   process exit ends the container" semantic; the session ends only on
    ///   shutdown).
    pub async fn launch_exec(
        policy: crate::sandbox::Sandbox,
        cmd: &[&str],
    ) -> Result<SandboxInstance, SandlockError> {
        Self::launch_exec_inner(policy, Some(cmd)).await
    }

    /// Launch an exec-only session (no main process; see
    /// [`SandboxInstance::launch_exec`] for the distinction). `pid()` is
    /// always `None` for a mainless session — there is no single "process
    /// pid"; every exec child's pid lives on its [`ExecHandle`].
    pub async fn launch_exec_only(
        policy: crate::sandbox::Sandbox,
    ) -> Result<SandboxInstance, SandlockError> {
        Self::launch_exec_inner(policy, None).await
    }

    /// Refuse a per-child verb when the session is not exec-capable.
    fn not_exec_capable() -> SandlockError {
        SandboxRuntimeError::Child(
            "instance is not exec-capable: launch with `SandboxInstance::launch_exec` \
             before calling exec/wait_child/kill_child"
                .into(),
        )
        .into()
    }

    /// Whether this session is exec mode (launched with `launch_exec` /
    /// `launch_exec_only`) rather than one-shot mode (`launch`).
    fn is_exec_mode(&self) -> bool {
        self.exec_session.is_some()
    }

    /// Reconcile the stored phase/children when the exec-mode init control
    /// link terminated on its own (main child exit collapsed the container,
    /// or init died): drain any real buffered exit statuses into the child
    /// caches, mark every remaining child `Killed` (children_live → 0), and
    /// set the terminal `Exited` phase. Called at the entry of every
    /// exec-mode verb; read-only surfaces (`phase`, `stats`) observe the
    /// terminal state through the effective-phase check instead.
    fn enter_exec_terminal_if_needed(&mut self) {
        if self.phase != InstancePhase::Live || !self.is_exec_mode() {
            return;
        }
        let terminated = self
            .exec_session
            .as_ref()
            .map(|s| s.link.is_terminated())
            .unwrap_or(false);
        if !terminated {
            return;
        }
        let mut early: HashMap<u64, ExitStatus> = HashMap::new();
        if let Some(session) = self.exec_session.as_ref() {
            session.link.drain_early_exits(&mut early);
        }
        if let Some(session) = self.exec_session.as_mut() {
            for (child_id, child) in session.children.iter_mut() {
                if child.status.is_none() {
                    let status = early.remove(child_id).unwrap_or(ExitStatus::Killed);
                    child.status = Some(status);
                }
            }
        }
        self.phase = InstancePhase::Exited;
    }

    /// Borrow the exec session, mapping a missing session to the unified
    /// closed-instance error once the instance left `Live` (a legacy session
    /// is only "not exec-capable" while it is live). An exec-mode session
    /// whose init link terminated reads as closed (`Exited` ⇒ every verb
    /// fails with the same `InstanceClosed` error).
    fn exec_ref(&self) -> Result<&ExecSession, SandlockError> {
        match self.exec_session.as_ref() {
            Some(session) if matches!(self.phase(), InstancePhase::Live) => Ok(session),
            Some(_) => Err(SandboxRuntimeError::InstanceClosed.into()),
            None if matches!(self.phase(), InstancePhase::Live) => Err(Self::not_exec_capable()),
            None => Err(SandboxRuntimeError::InstanceClosed.into()),
        }
    }

    /// Run an additional command inside an exec-capable session (F3.2).
    ///
    /// The child is forked by the confined `sandlock-init` (so it shares the
    /// session's seccomp filter, Landlock ruleset, resource budget and
    /// network state) and registered under a fresh child id. Stdio child ends
    /// are delivered to init over SCM_RIGHTS; the caller keeps the host ends
    /// described by [`ExecStdio`] in the returned [`ExecHandle`].
    ///
    /// Only a `Live` session accepts `exec`; after `shutdown` (or when the
    /// exec link died / the channel closed) every call fails with the same
    /// unified [`SandboxRuntimeError::InstanceClosed`] error.
    /// Run an additional command inside an exec-capable session (F3.2)
    /// without per-exec parameters (equivalent to
    /// [`SandboxInstance::exec_params`] with `ExecParams::default()`).
    pub async fn exec(
        &mut self,
        argv: &[&str],
        stdio: ExecStdio,
    ) -> Result<ExecHandle, SandlockError> {
        self.exec_params(argv, &ExecParams::default(), stdio).await
    }

    /// Run an additional command inside an exec-capable session with per-exec
    /// parameters (F4.1): `cwd`/`env`/`clean_env` are applied by
    /// `sandlock-init` before execve, and `extra_writable`/`bind_ports` are
    /// validated against the instance-time policy ceiling (S9) and recorded
    /// for this child only. An out-of-ceiling request is refused with
    /// [`SandboxRuntimeError::PolicyTooWide`] before any child is spawned.
    pub async fn exec_params(
        &mut self,
        argv: &[&str],
        params: &ExecParams,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, SandlockError> {
        self.enter_exec_terminal_if_needed();
        if self.phase != InstancePhase::Live {
            return Err(SandboxRuntimeError::InstanceClosed.into());
        }
        if self.exec_session.is_none() {
            return Err(Self::not_exec_capable());
        }
        if argv.is_empty() {
            return Err(SandboxRuntimeError::Child(
                "exec: empty command (argv[0] is the executable)".into(),
            )
            .into());
        }
        let (host, child_ends) = build_exec_stdio(stdio)?;
        self.exec_with_fds_inner(argv, params, child_ends, host)
            .await
    }

    /// Exec with caller-supplied child-side stdio ends (the cross-process
    /// holder shape: a worker's fds arrive over the control channel and
    /// supervise hands them straight to init). The returned handle carries
    /// no host ends — the caller owns them. No per-exec parameters
    /// (equivalent to [`SandboxInstance::exec_with_fds_params`] with
    /// `ExecParams::default()`).
    pub async fn exec_with_fds(
        &mut self,
        argv: &[&str],
        fds: [OwnedFd; 3],
    ) -> Result<ExecHandle, SandlockError> {
        self.exec_with_fds_params(argv, &ExecParams::default(), fds)
            .await
    }

    /// Exec with caller-supplied child-side stdio ends and per-exec
    /// parameters (F4.1). This is the on-behalf fd-injection route: the
    /// worker-held fds bypass no checks — the same S9 subset validation the
    /// in-process `exec_params` path runs applies here (F4.2), so a wider
    /// per-exec grant is refused identically no matter which holder the
    /// request arrived through.
    pub async fn exec_with_fds_params(
        &mut self,
        argv: &[&str],
        params: &ExecParams,
        fds: [OwnedFd; 3],
    ) -> Result<ExecHandle, SandlockError> {
        self.enter_exec_terminal_if_needed();
        if self.phase != InstancePhase::Live {
            return Err(SandboxRuntimeError::InstanceClosed.into());
        }
        if self.exec_session.is_none() {
            return Err(Self::not_exec_capable());
        }
        if argv.is_empty() {
            return Err(SandboxRuntimeError::Child(
                "exec: empty command (argv[0] is the executable)".into(),
            )
            .into());
        }
        self.exec_with_fds_inner(argv, params, fds.into(), ExecHostStdio::default())
            .await
    }

    /// Shared exec body: send `RunExec` + the three child ends over the
    /// link, register the announced child, and return the handle.
    async fn exec_with_fds_inner(
        &mut self,
        argv: &[&str],
        params: &ExecParams,
        child_ends: Vec<OwnedFd>,
        host: ExecHostStdio,
    ) -> Result<ExecHandle, SandlockError> {
        // F4.2 (S9): single validation choke point for both holder routes.
        // The ceiling was fixed at session creation; an out-of-ceiling
        // request fails here — before any fd is consumed or frame sent.
        let ceiling = self
            .exec_ceiling
            .as_ref()
            .expect("exec-capable sessions always capture a policy ceiling");
        ceiling.validate(params)?;
        let session = self
            .exec_session
            .as_ref()
            .expect("exec session presence checked by callers");
        let child_id = session.next_child_id;
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let raw: Vec<RawFd> = child_ends.iter().map(|f| f.as_raw_fd()).collect();
        let req = Req::RunExec {
            argv,
            env: params.env.clone(),
            cwd: params.cwd.as_ref().map(|p| p.to_string_lossy().to_string()),
            detach: false,
            clean_env: params.clean_env,
            extra_writable: params
                .extra_writable
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            bind_ports: params.bind_ports.clone(),
        };
        let reply = session.link.request(child_id, &req, &raw).await?;
        drop(child_ends);
        let pid = match reply {
            Resp::Started { pid } => pid,
            Resp::Err { msg } => {
                return Err(SandboxRuntimeError::Child(msg).into());
            }
            other => {
                return Err(SandboxRuntimeError::Child(format!(
                    "unexpected init reply to RunExec: {other:?}"
                ))
                .into());
            }
        };
        // F4.3/F4.4: bind the announced child to the session network policy
        // current at exec time (an `update_network` in flight between the
        // request and the announcement applies to this exec — the request
        // was sent under the policy generation we read here). Running
        // children are never rebound by a later update.
        let (next_policy, net_gen) = {
            let session = self
                .exec_session
                .as_ref()
                .expect("exec session presence checked by callers");
            (session.next_net_policy.clone(), session.next_net_gen)
        };
        if let Some(policy) = next_policy {
            if let Some(network) = self.supervisor_network.as_ref() {
                network.lock().await.bind_child_policy(pid, policy);
            }
        }
        let session = self
            .exec_session
            .as_mut()
            .expect("exec session presence checked by callers");
        session.next_child_id = child_id + 1;
        let registry_pty = host
            .pty
            .as_ref()
            .and_then(|master| dup_fd_cloexec(master.as_raw_fd()));
        session.children.insert(
            child_id,
            ExecChild {
                pid,
                pidfd: open_child_pidfd(pid),
                // Best-effort registry copy: resize_child works even after the
                // caller's handle master was closed; the caller still owns
                // the handle's master either way.
                pty: registry_pty,
                status: None,
                net_gen,
            },
        );
        Ok(ExecHandle {
            child_id,
            pid,
            stdin: host.stdin,
            stdout: host.stdout,
            stderr: host.stderr,
            pty: host.pty,
        })
    }

    /// F4.3 (S2): session-level outbound network update.
    ///
    /// `allowed_ips` is the new outbound IP allow set (any port; an empty set
    /// denies all outbound destinations). The update binds to **new execs
    /// only**: every child currently running keeps the policy it was created
    /// under, and the returned [`NetworkStaleness`] names those children.
    /// The request must be a subset of the instance-time destination ceiling
    /// (S9): a requested IP not granted by the static TCP allowlist — or a
    /// ceiling whose port-scoped rules cannot express an IP-any-port subset —
    /// is refused with the named EPERM-class `PolicyTooWide` error.
    ///
    /// Online tightening through `PolicyFnState.live_policy` (the policy-fn
    /// `restrict_network` path) is deliberately untouched: it is the
    /// instance-wide, event-driven tightening channel, while this verb is the
    /// session-scoped, new-exec-only channel. Binding decisions for children
    /// exec'd under an update come from their per-child policy (F4.4), never
    /// from a sibling's or from later updates.
    pub async fn update_network(
        &mut self,
        allowed_ips: &[IpAddr],
    ) -> Result<NetworkStaleness, SandlockError> {
        self.enter_exec_terminal_if_needed();
        if self.phase != InstancePhase::Live {
            return Err(SandboxRuntimeError::InstanceClosed.into());
        }
        if self.exec_session.is_none() {
            return Err(Self::not_exec_capable());
        }
        let binding = self.session_network_binding(allowed_ips).await?;
        let gen = {
            let session = self
                .exec_session
                .as_mut()
                .expect("exec session presence checked above");
            session.next_net_policy = Some(binding);
            session.next_net_gen += 1;
            session.next_net_gen
        };
        let mut stale: Vec<u64> = self
            .exec_session
            .as_ref()
            .expect("exec session presence checked above")
            .children
            .iter()
            .filter(|(_, child)| child.status.is_none() && child.net_gen < gen)
            .map(|(id, _)| *id)
            .collect();
        stale.sort_unstable();
        Ok(NetworkStaleness {
            stale_child_ids: stale,
        })
    }

    /// Validate `allowed_ips` against the instance static TCP ceiling and
    /// build the per-child allowlist policy new execs will be bound to.
    async fn session_network_binding(
        &self,
        allowed_ips: &[IpAddr],
    ) -> Result<NetworkPolicy, SandlockError> {
        let network = self
            .supervisor_network
            .as_ref()
            .ok_or_else(|| {
                SandboxRuntimeError::Child(
                    "update_network: session has no supervisor network state".into(),
                )
            })?
            .clone();
        let ns = network.lock().await;
        for ip in allowed_ips {
            if !network_ceiling_allows(&ns.tcp_policy, *ip) {
                return Err(SandboxRuntimeError::PolicyTooWide {
                    field: "update_network",
                    value: ip.to_string(),
                }
                .into());
            }
        }
        Ok(ip_only_allowlist(allowed_ips))
    }

    /// Wait for an exec child to exit (F3.2). Resolves on the child's
    /// `Exited` frame routed through the F1.2 announced registry; a repeated
    /// wait returns the cached status (idempotent). If the session closes
    /// while a wait is pending, the child is reported `Killed` rather than
    /// the waiter hanging.
    pub async fn wait_child(&mut self, child_id: ChildId) -> Result<ExitStatus, SandlockError> {
        self.enter_exec_terminal_if_needed();
        let session = self.exec_ref()?;
        let child = session
            .children
            .get(&child_id)
            .ok_or(SandboxRuntimeError::UnknownChild(child_id))?;
        if let Some(status) = child.status.as_ref() {
            return Ok(status.clone());
        }
        let rx = session.link.register_exit(child_id);
        let status = match rx.await {
            Ok(s) => s,
            // The waiter's sender was dropped without a synthetic Killed
            // (defensive); never leave the caller hanging.
            Err(_) => ExitStatus::Killed,
        };
        if let Some(session) = self.exec_session.as_mut() {
            if let Some(child) = session.children.get_mut(&child_id) {
                child.status = Some(status.clone());
            }
        }
        Ok(status)
    }

    /// Deliver `signum` to one registered exec child (F3.2/F1.7).
    ///
    /// The child token is resolved through the session registry to the
    /// child's pid (its own process group, per F1.7's per-child-group
    /// layout) and its host-side pidfd. Delivery is group-first (the child's
    /// whole command subtree) with a pidfd direct complement only when the
    /// child escaped its own group — the same shape `sandlock-init` uses
    /// internally, performed host-side against a registry the guest can
    /// never name through a frame. A child whose exit was already reported
    /// makes this an idempotent no-op.
    pub fn kill_child(
        &self,
        child_id: ChildId,
        signum: i32,
    ) -> Result<(), SandlockError> {
        let session = self.exec_ref()?;
        let child = session
            .children
            .get(&child_id)
            .ok_or(SandboxRuntimeError::UnknownChild(child_id))?;
        if child.status.is_some() {
            return Ok(());
        }
        signal_registered_child(child, signum);
        Ok(())
    }

    /// Resize the pty of an exec child (F3.2): `TIOCSWINSZ` on the host-side
    /// master fd retained in the child registry. Fails when the child has no
    /// pty (it was not exec'd with [`ExecStdio::Pty`]).
    pub fn resize_child(
        &self,
        child_id: ChildId,
        rows: u16,
        cols: u16,
    ) -> Result<(), SandlockError> {
        let session = self.exec_ref()?;
        let child = session
            .children
            .get(&child_id)
            .ok_or(SandboxRuntimeError::UnknownChild(child_id))?;
        let master = child
            .pty
            .as_ref()
            .ok_or(SandboxRuntimeError::NoPtyMaster(child_id))?;
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let rc = unsafe {
            libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &ws)
        };
        if rc != 0 {
            return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
        }
        Ok(())
    }

    // ================================================================
    // Session lifecycle verbs
    // ================================================================

    /// Wait for the session's M0 process to exit and return its captured
    /// result. This is the *main* wait: on a legacy (non-exec) session the
    /// direct child is the session's process; on an exec-capable session the
    /// caller uses the per-child [`SandboxInstance::wait_child`] with the
    /// child id (the main child is id 0).
    ///
    /// The session itself stays alive: the control directory, DNS gateway and
    /// supervisor-side state are *not* released here — that is
    /// [`SandboxInstance::shutdown`]'s job. Like the historical `Sandbox::wait`,
    /// this is cancellation-safe: a cancelled `wait_main` parks any output it
    /// had already drained and a later call (or `shutdown`) picks it up.
    ///
    /// Once the child has been reaped, a completed `wait_child` also hands the
    /// COW branch from the shared supervisor state to the instance (see
    /// `take_cow_branch`) — that handoff is the *last* await of the wait,
    /// ordered after both drains have finished and before their bytes are
    /// taken out, so there is no point where captured output exists only in a
    /// cancellable future (F2.1 review B-3). The branch then stays owned by
    /// the instance and `Drop`'s backstop applies the recorded disposition
    /// using the reaped exit status exactly once — dropping right after
    /// `wait_child` commits/aborts/keeps exactly like the historical
    /// `Sandbox::wait`-then-drop path.
    pub async fn wait_main(&mut self) -> Result<RunResult, SandlockError> {
        // Exec-capable session: the main workload is child id 0 and its exit
        // is routed through the executor (its stdio is never captured — the
        // session was launched with inherited stdio).
        if self.exec_session.is_some() {
            let exit_status = self.wait_child(0).await?;
            return Ok(RunResult {
                exit_status,
                stdout: None,
                stderr: None,
            });
        }
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
            let (stdout, stderr) = self.collect_drained_output_and_branch().await;
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

        let (stdout, stderr) = self.collect_drained_output_and_branch().await;

        Ok(RunResult { exit_status, stdout, stderr })
    }

    /// Default grace window between the §5.3 step-2 shutdown request and the
    /// step-3 SIGKILL escalation.
    pub const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

    /// Shut the session down: release every session-owned resource, in the
    /// fixed seven-step order of [`docs/sandbox-exec-security.md` §5.3]
    /// (each step is commented with its §5.3 number in
    /// [`SandboxInstance::shutdown_with_grace`]).
    ///
    /// A session with a still-running first process is asked to shut down
    /// (SIGTERM to its process group) and killed by the escalation ladder
    /// once the grace window elapses; the process never survives its session.
    /// `Drop` remains the final backstop for an instance destroyed without an
    /// explicit shutdown (immediate SIGKILL there — a `Drop` must never
    /// hang).
    ///
    /// [`docs/sandbox-exec-security.md` §5.3]: ../../docs/sandbox-exec-security.md
    pub async fn shutdown(&mut self) -> Result<(), SandlockError> {
        self.shutdown_with_grace(Self::DEFAULT_SHUTDOWN_GRACE).await
    }

    /// Shut the session down with an explicit grace window.
    ///
    /// [`SandboxInstance::shutdown`] with a caller-chosen `grace`.
    ///
    /// Idempotent — calling it again (or after the instance was already
    /// dropped) is a no-op: repeated calls never re-kill, never re-remove the
    /// control directory, and leave the session in the terminal `ShutDown`
    /// phase. A shutdown future cancelled mid-flight leaves the phase at
    /// `Draining`; the next call resumes from step 1 and every step is safe
    /// to re-run because it takes its resources out of the instance.
    ///
    /// `grace` is the §5.3 step-2 window between the shutdown request and the
    /// step-3 SIGKILL escalation; a child that exits within the window is
    /// reaped with its real exit status and never escalated.
    pub async fn shutdown_with_grace(&mut self, grace: Duration) -> Result<(), SandlockError> {
        if self.phase == InstancePhase::ShutDown {
            return Ok(());
        }

        // §5.3 step 1 — Draining: refuse new work. M0 has no `exec` verb, so
        // the phase is the refusal hook M1 consults; it also makes a
        // cancelled shutdown future observable and resumable.
        self.phase = InstancePhase::Draining;

        // §5.3 steps 2–3 — graceful shutdown request + grace, then escalation.
        // Only a child this session has not yet reaped is drained; a child
        // already reaped (state `Stopped`) is left alone, so
        // repeated shutdowns never re-kill.
        if self.exec_session.is_some() {
            // Exec-capable session: step 2 is the init `Shutdown` frame
            // (init collapses every registered child group — §5.3 "init
            // Shutdown frame + grace" applies directly here), with the same
            // escalation ladder on grace expiry.
            if self.child_pid.is_some() && !matches!(self.state, RuntimeState::Stopped(_)) {
                let exit = self.shutdown_exec_child_after_grace(grace).await;
                self.state = RuntimeState::Stopped(exit);
            }
        } else if self.child_pid.is_some() && !matches!(self.state, RuntimeState::Stopped(_)) {
            let exit = self.shutdown_child_after_grace(grace).await;
            self.state = RuntimeState::Stopped(exit);
        }

        // Close the exec control channel now that init is gone: the writer
        // end drops here (the reader task observes the peer's EOF once init
        // closed its end) and the per-child registry fds (pidfds, pty
        // masters) are released with it. Post-shutdown per-child verbs
        // report the unified closed-instance error.
        drop(self.exec_session.take());

        // §5.3 step 4 — close the host side of the stdio pipes: capture read
        // ends that were never handed to a drain, an untaken piped stdin, and
        // the release pipe of a child that never reached `start()`. Subscribers
        // therefore see EOF instead of waiting on a session that is gone.
        drop(self._stdout_read.take());
        drop(self._stderr_read.take());
        drop(self._stdin_write.take());
        drop(self.ready_w.take());

        // §5.3 step 5 — abort the supervisor-side background tasks: notif
        // supervisor, policy_fn worker, CPU throttle, loadavg sampler, control
        // listener, DNS gateway (`:53` dies with its task), the HTTP ACL
        // proxy (B-5: dropping its handle sends the proxy its shutdown frame,
        // releasing the loopback listener), and capture drains still reading.
        self.abort_session_tasks();
        self.abort_drains();

        // Close the direct child's pidfd now that every task that could hold
        // its raw fd number (the notif supervisor's `SupervisorCtx`) has been
        // aborted. `wait_child` consumes the pidfd when it reaps; when
        // shutdown is the reaper (or the child was never waited), the fd would
        // otherwise stay open until Drop (F2.1 review B-5).
        drop(self.pidfd.take());

        // §5.3 step 6 — close the control socket and remove the F1.3 control
        // directory (pid/token/name/mode/control.sock), but only after
        // verifying the directory is still owned by this session: the pid
        // file's recorded supervisor identity (pid + `/proc/<pid>/stat`
        // starttime) must match this process. That is the same identity proof
        // F1.3 uses to refuse stale-dir preemption — a dir we cannot prove is
        // ours is never deleted (a recycled hash slot could belong to a live
        // sibling). The control channel's token check (sensitive verbs) is
        // F1.3's separately.
        self.remove_control_dir_owned();

        // §5.3 step 7 — return ports / budgets / logs. M0 core equivalents:
        // every host-side port-bearing listener (DNS `:53`, HTTP ACL proxy,
        // control socket, inbound map listeners) died with its task in steps
        // 4–5; supervisor-side accounting (`ResourceState`/`ProcessIndex`,
        // the COW/network state) is released by `Drop` as the final backstop
        // so legacy post-wait introspection keeps working until the owning
        // `Sandbox` drops; command-logs finalization lives on the E2B side,
        // not in this crate.

        // M0-specific tail — take the COW branch out of the shared supervisor
        // state so the instance's `Drop` applies Commit/Abort/Keep exactly
        // once (a transactional-pipeline stage leaves its shared branch
        // untouched — the coordinator owns that commit/abort). For a session
        // `wait_child` already reaped, this is a no-op: the branch was handed
        // over at the end of that wait (B-3). It is the last await of
        // shutdown, after which no output-bearing state exists in this future.
        self.take_cow_branch().await;

        self.phase = InstancePhase::ShutDown;
        Ok(())
    }

    /// §5.3 steps 2–3 for the M0 child set.
    ///
    /// Step 2: ask the session's process to shut down and give it `grace`.
    /// There is no separate init in the M0 core — the confined first process
    /// *is* the session's group leader, so signalling its process group with
    /// SIGTERM is the core equivalent of the §5.3 "init `Shutdown` frame +
    /// grace" rung (the OCI crate's init receives the frame and killpg's its
    /// own tree; core has no frame protocol). A paused group is resumed
    /// first so the request can be acted on.
    ///
    /// Step 3 (only when the grace window expires with the child alive): the
    /// escalation ladder — per-child pidfd SIGKILL, then the group sweep, then
    /// the instance-group fallback (see [`SandboxInstance::escalate_kill`]).
    /// Returns the reaped exit status (`Killed` if the status was already
    /// reaped elsewhere by the time we escalated).
    async fn shutdown_child_after_grace(&mut self, grace: Duration) -> ExitStatus {
        let pid = self.child_pid.expect("guarded by the shutdown caller");
        let group = self.leader_pid.unwrap_or(pid);

        // §5.3 step 2 — shutdown request + grace.
        if matches!(self.state, RuntimeState::Paused) {
            unsafe { libc::killpg(group, libc::SIGCONT) };
        }
        unsafe { libc::killpg(group, libc::SIGTERM) };

        if let Some(reaped) = self.wait_direct_child_exit(pid, grace).await {
            // The child (or its relayed status) exited within the grace
            // window, so the per-child SIGKILL rung (3a) is unnecessary. But
            // the group rungs (3b/3c) still run: a same-group descendant that
            // ignored or handled TERM must not survive just because the
            // direct child cooperated (reviewer I-1 — F2.1's shutdown was an
            // unconditional group SIGKILL, so the TERM-first corner must not
            // silently leak in-group residue). An empty group makes both
            // best-effort killpgs return ESRCH, which is harmless.
            self.sweep_session_groups(pid, group);
            if self.tty_foreground_taken {
                let fg_pid = self.leader_pid.unwrap_or(pid);
                restore_tty_foreground(fg_pid);
                self.tty_foreground_taken = false;
            }
            return reaped;
        }

        // §5.3 step 3 — escalation: the child ignored the shutdown request
        // (3a per-child SIGKILL, then the 3b/3c group sweep).
        self.escalate_kill(pid, group);

        // The direct child is dead or dying after the SIGKILL ladder; reap it.
        // (A `None` here means a concurrent reaper already took the status —
        // e.g. the fork-tracking worker — in which case `Killed` is recorded
        // so a later `wait_child` stays well-defined.)
        let reaped = reap_direct_child(pid).unwrap_or(ExitStatus::Killed);
        if self.tty_foreground_taken {
            let fg_pid = self.leader_pid.unwrap_or(pid);
            restore_tty_foreground(fg_pid);
            self.tty_foreground_taken = false;
        }
        reaped
    }

    /// §5.3 steps 2–3 for an exec-capable session: the confined direct child
    /// is `sandlock-init`, so step 2 is the actual `Shutdown` frame (init
    /// delivers SIGKILL over its registered child-group set — live plus
    /// retained dead groups — and exits), not an M0 SIGTERM-to-the-workload.
    ///
    /// Real exit statuses already reported by init are drained into the
    /// per-child caches *before* the teardown frame, so a later idempotent
    /// wait still sees a genuinely-exited child's true status; children
    /// killed by the teardown without a reported frame are cached as
    /// `Killed`. If the grace window expires with init alive, the escalation
    /// ladder mirrors M0: per-child pidfd SIGKILL on init, then a killpg
    /// sweep over every registered child group, then reap init.
    async fn shutdown_exec_child_after_grace(&mut self, grace: Duration) -> ExitStatus {
        let pid = self.child_pid.expect("guarded by the shutdown caller");

        // Preserve every exit init already reported (buffered early exits).
        let mut early: HashMap<u64, ExitStatus> = HashMap::new();
        if let Some(session) = self.exec_session.as_ref() {
            session.link.drain_early_exits(&mut early);
        }
        if let Some(session) = self.exec_session.as_mut() {
            for (child_id, status) in early {
                if let Some(child) = session.children.get_mut(&child_id) {
                    if child.status.is_none() {
                        child.status = Some(status);
                    }
                }
            }
        }

        // §5.3 step 2 — init `Shutdown` frame (fire-and-forget; init acts on
        // it, collapses the child groups, and exits).
        if let Some(session) = self.exec_session.as_ref() {
            session.link.send_shutdown().await;
        }

        if let Some(reaped) = self.wait_direct_child_exit(pid, grace).await {
            // Init exited within the grace window after collapsing every
            // registered group (including retained dead groups, so a
            // grandchild holding stdout dies with its group — §4.14). Belt:
            // sweep the registered child groups anyway (ESRCH is expected),
            // then cache Killed for anything init had not yet reported.
            self.sweep_exec_child_groups();
            self.mark_unreported_exec_children_killed();
            return reaped;
        }

        // §5.3 step 3 — escalation: init ignored/was stuck. Per-child pidfd
        // SIGKILL on init, group sweep over the registered children, reap.
        match self.pidfd.as_ref() {
            Some(pidfd) => {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal as libc::c_long,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::c_void>(),
                        0u32,
                    );
                }
            }
            None => {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
        self.sweep_exec_child_groups();
        let reaped = reap_direct_child(pid).unwrap_or(ExitStatus::Killed);
        self.mark_unreported_exec_children_killed();
        reaped
    }

    /// Best-effort SIGKILL sweep over every registered exec child group plus
    /// every deadline-orphaned/stray pid the reader recorded (I1: a child
    /// init announced after the request deadline discarded the reply is real
    /// but was never registered host-side — its group must still be
    /// collapsed). Used on escalation and belt paths; ESRCH after init
    /// already collapsed the groups is expected and harmless.
    fn sweep_exec_child_groups(&self) {
        let Some(session) = self.exec_session.as_ref() else {
            return;
        };
        for child in session.children.values() {
            unsafe {
                libc::killpg(child.pid, libc::SIGKILL);
            }
        }
        for stray_pid in session.link.stray_pids() {
            unsafe {
                libc::killpg(stray_pid, libc::SIGKILL);
            }
        }
    }

    /// Cache `Killed` for every registered child whose real exit was never
    /// reported (init died before reaping them), so post-shutdown idempotent
    /// waits stay well-defined. Genuine statuses drained earlier are left
    /// untouched.
    fn mark_unreported_exec_children_killed(&mut self) {
        let Some(session) = self.exec_session.as_mut() else {
            return;
        };
        for child in session.children.values_mut() {
            if child.status.is_none() {
                child.status = Some(ExitStatus::Killed);
            }
        }
    }

    /// §5.3 step 3 — the SIGKILL escalation ladder, reached when the grace
    /// window expired with the child still alive:
    ///
    /// 3a. per-child pidfd SIGKILL — targets the direct child through its
    ///     pidfd (no pid-reuse race); `kill(pid)` when no pidfd exists;
    /// 3b. group-set sweep — `killpg` the direct child's own process group,
    ///     covering every descendant that stayed in it. In M0's single-child
    ///     topology this group is the child's own (`pgid == child pid` after
    ///     `confine_child`'s `setpgid(0, 0)`); with a PID namespace the
    ///     direct child is the unconfined intermediate, which never created a
    ///     group, so this rung is an ESRCH no-op and the leader's group is the
    ///     real target of 3c. M1's per-child group table (the F1.7 OCI shape)
    ///     generalizes this rung to a sweep over every registered group;
    /// 3c. instance-group fallback — `killpg` the sandbox leader's group
    ///     (`leader_pid`, or the direct child without a PID namespace), so a
    ///     child that escaped its own group mid-escalation is still covered
    ///     by the instance-level kill.
    ///
    /// In M0's single-group topology rungs 3b and 3c address the same group
    /// (the second call returns ESRCH once the first emptied it), which is
    /// fine — both are best-effort and ESRCH after an earlier rung is the
    /// expected outcome, not an error. Rungs 3b/3c also run *after* a
    /// compliant in-grace reap ([`SandboxInstance::sweep_session_groups`]) so
    /// a TERM-ignoring same-group descendant cannot outlive shutdown just
    /// because the direct child exited within the grace window (reviewer
    /// I-1); 3a is skipped on that path because the direct child is already
    /// reaped.
    fn escalate_kill(&self, pid: i32, group: i32) {
        // 3a. Per-child pidfd SIGKILL.
        match self.pidfd.as_ref() {
            Some(pidfd) => {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal as libc::c_long,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::c_void>(),
                        0u32,
                    );
                }
            }
            None => {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
        self.sweep_session_groups(pid, group);
    }

    /// §5.3 step-3 group rungs (3b + 3c): best-effort SIGKILL sweep of the
    /// session's process groups, used on both the escalation path (after the
    /// grace window expired) and the compliant path (after an in-grace reap),
    /// so no same-group descendant survives shutdown. An empty group makes
    /// `killpg` return ESRCH, which is expected and harmless.
    fn sweep_session_groups(&self, pid: i32, group: i32) {
        // 3b. Direct child's own group (non-pid-ns: pgid == child pid;
        // pid-ns: the unconfined intermediate never created a group, ESRCH).
        unsafe { libc::killpg(pid, libc::SIGKILL) };
        // 3c. Instance-group fallback (leader group, or the direct child's
        // group without a PID namespace).
        unsafe { libc::killpg(group, libc::SIGKILL) };
    }

    /// Wait up to `grace` for the direct child to exit and be reaped.
    ///
    /// Prefers pidfd readiness (opened fresh so the instance keeps its own
    /// pidfd for the step-3 escalation): pidfd never consumes ptrace-stops
    /// the `policy_fn` fork-tracking worker owns. Falls back to a blocking
    /// `waitpid` only when no pidfd can be opened (the process is already
    /// reaped elsewhere, or the kernel has no pidfd support). Returns `None`
    /// when the grace window elapsed with the child still alive.
    async fn wait_direct_child_exit(&self, pid: i32, grace: Duration) -> Option<ExitStatus> {
        let waiter = async {
            match crate::sys::syscall::pidfd_open(pid as u32, 0) {
                Ok(pidfd) => wait_child_exit_via_pidfd(pidfd, pid).await,
                Err(_) => wait_child_exit_blocking(pid).await,
            }
        };
        match tokio::time::timeout(grace, waiter).await {
            Ok(exit) => Some(exit),
            Err(_) => None,
        }
    }

    /// §5.3 step 6 — remove the control directory only when its recorded
    /// supervisor identity still matches this process.
    fn remove_control_dir_owned(&mut self) {
        let Some(dir) = self.control_dir.clone() else {
            return;
        };
        let supervisor_pid = std::process::id() as i32;
        let content = match std::fs::read_to_string(crate::control::pid_path(&dir)) {
            Ok(content) => content,
            Err(_) => {
                eprintln!(
                    "sandlock: not removing control dir {:?}: pid file unreadable, \
                     identity cannot be verified",
                    dir
                );
                return;
            }
        };
        let mut lines = content.lines();
        let _child_pid: i32 = match lines.next().and_then(|l| l.trim().parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!(
                    "sandlock: not removing control dir {:?}: malformed pid file",
                    dir
                );
                return;
            }
        };
        let recorded_supervisor: i32 = match lines.next().and_then(|l| l.trim().parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!(
                    "sandlock: not removing control dir {:?}: malformed pid file",
                    dir
                );
                return;
            }
        };
        let recorded_starttime: Option<u64> =
            lines.next().and_then(|l| l.trim().parse().ok());
        let owned = recorded_supervisor == supervisor_pid
            && recorded_starttime.is_some()
            && crate::seccomp::state::read_pid_start_time(supervisor_pid)
                == recorded_starttime;
        if !owned {
            eprintln!(
                "sandlock: not removing control dir {:?}: recorded supervisor \
                 identity does not match this process",
                dir
            );
            return;
        }
        crate::control::cleanup_runtime_dir(&dir);
    }

    /// Hand the COW branch from the shared supervisor state to the instance.
    ///
    /// Only a non-shared session takes the branch (a transactional-pipeline
    /// stage's `shared_cow` is owned by the coordinator). Taking it out does
    /// not dispose it: the instance's `Drop` backstop applies Commit/Abort/
    /// Keep using the recorded disposition and the exit status captured in
    /// `state`. Calling this after the branch was already taken is a no-op
    /// that performs no await.
    async fn take_cow_branch(&mut self) {
        if self.shared_cow.is_none() && self.seccomp_cow.is_none() {
            if let Some(ref cow_state) = self.supervisor_cow.clone() {
                let mut cow = cow_state.lock().await;
                self.seccomp_cow = cow.branch.take();
            }
        }
    }

    /// One-shot session wait: `Sandbox::wait`'s implementation. Waits for the
    /// session's process and then shuts the session down, which is what keeps
    /// `Sandbox::run`/`popen`/`spawn` one-shot: their caller never sees a
    /// live session after the process exits.
    pub(crate) async fn wait_one_shot(&mut self) -> Result<RunResult, SandlockError> {
        let result = self.wait_main().await?;
        self.shutdown().await?;
        Ok(result)
    }

    /// Kill and reap the session's process if it is still running — the `Drop`
    /// backstop, mirroring the historical `Sandbox::drop` steps (SIGKILL,
    /// no grace: dropping must never hang). `shutdown` uses the §5.3
    /// grace-then-escalation ladder instead ([`SandboxInstance::escalate_kill`]).
    /// Returns the reaped status when this call actually reaped the child
    /// (`None` when nothing was running, or when the child was already
    /// reaped). Like the historical `Drop`, this does *not* mutate `state`;
    /// callers decide whether to record the status (`Drop` deliberately does
    /// not, preserving the old drop-time disposition).
    fn kill_and_reap(&mut self) -> Option<ExitStatus> {
        if self.exec_session.is_some() {
            return self.kill_and_reap_exec();
        }
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
                reaped = reap_direct_child(pid);
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

    /// Drop-backstop variant for exec-mode sessions. No grace: first ask a
    /// still-alive init to collapse **everything** it spawned (the best
    /// effort sync `Shutdown` frame covers children the host never
    /// registered — reviewer I1; F1.8's shutdown is deliberately not gated by
    /// Dead), then SIGKILL every registered child group (pidfd direct
    /// complement covers an escaped child) plus every recorded stray group,
    /// SIGKILL init's own group, reap init, and mark the link terminated so
    /// pending waiters resolve instead of hanging. Best-effort like the M0
    /// backstop — dropping must never hang.
    fn kill_and_reap_exec(&mut self) -> Option<ExitStatus> {
        // First resolve every pending waiter (nothing may hang on a dropped
        // session) and fail fast any later request.
        if let Some(session) = self.exec_session.as_ref() {
            session.link.mark_terminated();
            // Belt: init's own registry knows every child it spawned
            // (registered, stray, and their retained dead groups). Ask it to
            // collapse them before we reap it.
            session.link.send_shutdown_sync();
        }
        // Per-child SIGKILL: pidfd direct (escapee-proof) plus group killpg
        // (in-group descendants).
        if let Some(session) = self.exec_session.as_mut() {
            for child in session.children.values_mut() {
                if child.status.is_some() {
                    continue;
                }
                if let Some(pidfd) = child.pidfd.take() {
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal as libc::c_long,
                            pidfd.as_raw_fd(),
                            libc::SIGKILL,
                            std::ptr::null::<libc::c_void>(),
                            0u32,
                        );
                    }
                }
                unsafe {
                    libc::killpg(child.pid, libc::SIGKILL);
                }
            }
        }
        self.sweep_exec_child_groups();
        if let Some(session) = self.exec_session.as_ref() {
            session.link.clear_strays();
        }
        let mut reaped: Option<ExitStatus> = None;
        if let Some(pid) = self.child_pid {
            if matches!(
                self.state,
                RuntimeState::Created | RuntimeState::Running | RuntimeState::Paused
            ) {
                let group = self.leader_pid.unwrap_or(pid);
                unsafe { libc::killpg(group, libc::SIGKILL) };
                reaped = reap_direct_child(pid);
            }
        }
        reaped
    }

    /// Abort every supervisor-side session task (best-effort; each handle is
    /// taken so repeated calls are no-ops). §5.3 step 5.
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
        // The HTTP ACL proxy task dies when its handle drops (the handle's
        // Drop sends the proxy's shutdown frame), releasing the loopback
        // listener it bound — close it here rather than leaving it until the
        // instance's Drop (F2.1 review B-5).
        drop(self.http_acl_handle.take());
    }

    /// Abort capture drains that are still reading (shutdown / Drop only).
    fn abort_drains(&mut self) {
        for slot in [self.stdout_drain.take(), self.stderr_drain.take()] {
            if let Some(ParkedDrain::Running(h)) = slot {
                h.abort();
            }
        }
    }

    /// Synchronous teardown used by `Drop` — the single backstop shared by a
    /// `Sandbox`-embedded session and a standalone instance: kill + reap,
    /// abort session tasks, abort drains, remove the control directory, and
    /// dispose a taken COW branch per the recorded disposition and exit
    /// status. F2.1 review B-2: `Sandbox::drop` no longer calls this inline —
    /// the embedded `Box<SandboxInstance>`'s own `Drop` is the one and only
    /// invocation, so the historical steps run exactly once per session.
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

    /// Join the capture-pipe drains (if this session still holds them), hand
    /// the COW branch to the instance, and only then take the drained bytes
    /// out — the ordered tail of `wait_child`.
    ///
    /// Only called once the child has been reaped, so the EOF each drain is
    /// reading towards is already reachable — but not necessarily *reached*: a
    /// descendant that inherited the write end keeps the join blocked for as
    /// long as it lives, which is exactly when a caller's timeout fires. So
    /// each handle is joined in place and only unparked once that join
    /// completes; see `finish_parked_drain`.
    ///
    /// Cancellation ordering (F2.1 review B-3): both drains are finished first
    /// with their bytes still parked in the instance; the COW-branch handoff
    /// is the *last* await; and the bytes are taken out only afterwards, with
    /// no further await in between. A cancellation therefore never finds the
    /// captured output only inside this future — it is either parked in the
    /// instance (drains unfinished or branch handoff in flight) or already in
    /// the caller's hands.
    ///
    /// `None` means the stream was never piped, was taken by the caller, or was
    /// already collected by an earlier wait; a drain that panicked or was
    /// aborted reports empty bytes rather than failing the run.
    async fn collect_drained_output_and_branch(&mut self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        // Finish both first — each stores its bytes into the instance as it
        // completes. A cancellation between the two joins loses nothing:
        // whatever finished is parked. One statement per stream: each borrow
        // of the instance ends with it.
        finish_parked_drain(&mut self.stdout_drain).await;
        finish_parked_drain(&mut self.stderr_drain).await;
        // The final await: hand the branch over while the bytes are still
        // parked (see the ordering note above).
        self.take_cow_branch().await;
        // Synchronous tail: no cancellation can land between here and the
        // returned `RunResult`.
        let stdout = take_drained(&mut self.stdout_drain);
        let stderr = take_drained(&mut self.stderr_drain);
        (stdout, stderr)
    }

    // ================================================================
    // Introspection (minimal M0 surface; stats exposure is F2.3)
    // ================================================================

    /// The session's lifecycle phase (see [`InstancePhase`]).
    pub fn phase(&self) -> InstancePhase {
        // Exec mode: an init control link that terminated on its own (main
        // child exit collapsed the container, or init died) means the session
        // is over even before a &mut verb re-synchronizes the stored phase —
        // read-only surfaces observe the terminal `Exited` state directly.
        if self.phase == InstancePhase::Live {
            if let Some(session) = self.exec_session.as_ref() {
                if session.link.is_terminated() {
                    return InstancePhase::Exited;
                }
            }
        }
        self.phase
    }

    /// Snapshot the session's stats surface (fork-plan F2.3):
    /// `proc_count_vs_live` (the F1.4 process reconciliation under the §5.6
    /// name), `children_live` (per-mode record semantics), and
    /// `instance_state` (the current [`InstancePhase`]).
    ///
    /// The process half is read from the supervisor's `ResourceState` /
    /// `ProcessIndex` and is identical to
    /// [`ProcessStats`](crate::sandbox::ProcessStats) `drift`; the
    /// child/phase halves come from the instance's own bookkeeping and stay
    /// exact even after the supervisor state is gone.
    pub async fn stats(&self) -> InstanceStats {
        let proc_count_vs_live = match (
            self.supervisor_resource.as_ref(),
            self.supervisor_processes.as_ref(),
        ) {
            (Some(res), Some(procs)) => {
                let rs = res.lock().await;
                rs.proc_count as i64 - procs.len() as i64
            }
            _ => 0,
        };
        let effective_phase = self.phase();
        let children_live = if self.is_exec_mode() {
            if effective_phase == InstancePhase::Exited {
                // Terminal: init collapsed every group; children reconcile to
                // zero even before a verb drains the caches.
                0
            } else {
                // Exec session: announced children whose exit has not been
                // consumed by a wait (the F3.1 report's announced-minus-reaped
                // generalization of the M0 record).
                self.exec_session
                    .as_ref()
                    .map(|s| {
                        s.children
                            .values()
                            .filter(|c| c.status.is_none())
                            .count() as u32
                    })
                    .unwrap_or(0)
            }
        } else {
            u32::from(
                self.child_pid.is_some() && !matches!(self.state, RuntimeState::Stopped(_)),
            )
        };
        InstanceStats {
            proc_count_vs_live,
            children_live,
            instance_state: effective_phase,
        }
    }

    /// Snapshot the session's live port surface (fork-plan F2b.3 `ports`
    /// verb): configured S2.5 inbound mappings with live-listener state and
    /// the live `port_remap` virtual→real table.
    ///
    /// Reports an empty snapshot when the supervisor network state does not
    /// exist yet (the session was never launched, or ran without a
    /// supervisor) — the caller distinguishes that via
    /// [`SandboxInstance::phase`]/its own launch bookkeeping.
    pub async fn ports(&self) -> InstancePorts {
        let mut inbound: Vec<InboundMapping> = Vec::new();
        let mut port_remap = std::collections::HashMap::new();
        if let Some(ref net) = self.supervisor_network {
            let ns = net.lock().await;
            let mut configured: Vec<(u16, u16)> = ns
                .inbound_map
                .iter()
                .map(|(&sandbox_port, &host_port)| (sandbox_port, host_port))
                .collect();
            configured.sort_unstable();
            for (sandbox_port, host_port) in configured {
                let live = ns
                    .inbound
                    .values()
                    .any(|listener| listener.sandbox_port == sandbox_port);
                inbound.push(InboundMapping {
                    sandbox_port,
                    host_port,
                    live,
                });
            }
            port_remap = ns.port_map.virtual_to_real.clone();
        }
        InstancePorts { inbound, port_remap }
    }

    /// The session's process PID.
    ///
    /// One-shot mode: the direct child's pid (remains `Some` after exit until
    /// drop). Exec mode with a main child (`launch_exec`): the main workload's
    /// pid (child id 0). Exec mode without a main (`launch_exec_only`):
    /// `None` — the session has no single "process pid"; each exec child's
    /// pid lives on its [`ExecHandle`]. Never reports the confined
    /// `sandlock-init` pid.
    pub fn pid(&self) -> Option<i32> {
        if let Some(session) = self.exec_session.as_ref() {
            // Exec-capable session: report the main workload (child id 0),
            // not the confined `sandlock-init` direct child.
            return session.children.get(&0).map(|child| child.pid);
        }
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

/// S9 ceiling check for an `update_network` request: is `ip` inside the
/// instance's static TCP destination ceiling at any-port granularity?
///
/// * `Unrestricted`/`DenyList` ceilings are default-allow — any requested IP
///   is a subset (the binding can only narrow them);
/// * an `AllowList` grants `ip` only through an explicit
///   `PortAllow::Any` entry (a port-scoped entry cannot express an
///   IP-any-port subset, so the request would silently widen ports and is
///   refused); any-IP-port rules have the same granularity problem and are
///   refused for non-empty updates;
/// * the empty update (deny all) is always a subset and is accepted by the
///   caller without consulting this helper.
fn network_ceiling_allows(tcp: &NetworkPolicy, ip: IpAddr) -> bool {
    match tcp {
        NetworkPolicy::Unrestricted | NetworkPolicy::DenyList { .. } => true,
        NetworkPolicy::AllowList {
            per_ip,
            cidrs,
            any_ip_ports,
            ..
        } => {
            if !any_ip_ports.is_empty() {
                return false;
            }
            if matches!(per_ip.get(&ip.to_canonical()), Some(PortAllow::Any)) {
                return true;
            }
            cidrs.iter().any(|(net, allow)| {
                net.contains(ip) && matches!(allow, PortAllow::Any)
            })
        }
    }
}

/// IP-only allowlist policy (any port to each listed IP) used to bind an
/// exec child to an `update_network` policy. Mirrors the legacy `policy_fn`
/// IP-override representation so the existing verdict path applies unchanged.
fn ip_only_allowlist(ips: &[IpAddr]) -> NetworkPolicy {
    let per_ip = ips.iter().map(|&ip| (ip, PortAllow::Any)).collect();
    NetworkPolicy::AllowList {
        per_ip,
        cidrs: Vec::new(),
        any_ip_ports: HashSet::new(),
        wildcard_domains: Vec::new(),
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
// F3.2 exec stdio helpers
// ================================================================

/// Host ends of one `exec` stdio setup (see [`build_exec_stdio`]).
struct ExecHostStdio {
    stdin: Option<OwnedFd>,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
    pty: Option<OwnedFd>,
}

impl Default for ExecHostStdio {
    fn default() -> Self {
        ExecHostStdio {
            stdin: None,
            stdout: None,
            stderr: None,
            pty: None,
        }
    }
}

/// Duplicate `fd` with FD_CLOEXEC (best-effort helper for registry-owned
/// pty masters).
fn dup_fd_cloexec(fd: RawFd) -> Option<OwnedFd> {
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if dup < 0 {
        None
    } else {
        Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(dup) })
    }
}

/// Build the stdio set for one exec child: host ends (kept by the caller)
/// and the three child-side ends that will be sent to `sandlock-init` via
/// SCM_RIGHTS.
fn build_exec_stdio(
    stdio: ExecStdio,
) -> Result<(ExecHostStdio, Vec<OwnedFd>), SandlockError> {
    use crate::sandbox::make_cloexec_pipe;

    match stdio {
        ExecStdio::Piped => {
            // stdin: the child reads, so the parent keeps the write end;
            // stdout/stderr: the child writes, so the parent keeps the read
            // ends. `make_cloexec_pipe` returns (read, write).
            let (stdin_r, stdin_w) = make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?;
            let (stdout_r, stdout_w) = make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?;
            let (stderr_r, stderr_w) = make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?;
            Ok((
                ExecHostStdio {
                    stdin: Some(stdin_w),
                    stdout: Some(stdout_r),
                    stderr: Some(stderr_r),
                    pty: None,
                },
                vec![stdin_r, stdout_w, stderr_w],
            ))
        }
        ExecStdio::Inherit => {
            // The child inherits the session process's stdio. Passing the raw
            // 0/1/2 through SCM_RIGHTS gives init duplicates of the same open
            // file descriptions; init's copies close after the dup2 and the
            // caller's originals are untouched.
            let mut child = Vec::with_capacity(3);
            for i in 0..3 {
                child.push(dup_fd_cloexec(i).ok_or_else(|| {
                    SandboxRuntimeError::Io(std::io::Error::last_os_error())
                })?);
            }
            Ok((ExecHostStdio::default(), child))
        }
        ExecStdio::Null => {
            let null = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")
                .map_err(SandboxRuntimeError::Io)?;
            let raw = null.as_raw_fd();
            let mut child = Vec::with_capacity(3);
            for _ in 0..3 {
                child.push(
                    dup_fd_cloexec(raw)
                        .ok_or_else(|| SandboxRuntimeError::Io(std::io::Error::last_os_error()))?,
                );
            }
            Ok((ExecHostStdio::default(), child))
        }
        ExecStdio::Pty => {
            let (master, slave) = open_pty_pair().map_err(SandboxRuntimeError::Io)?;
            let raw = slave.as_raw_fd();
            let mut child = Vec::with_capacity(3);
            for _ in 0..3 {
                child.push(
                    dup_fd_cloexec(raw)
                        .ok_or_else(|| SandboxRuntimeError::Io(std::io::Error::last_os_error()))?,
                );
            }
            drop(slave);
            Ok((
                ExecHostStdio {
                    stdin: None,
                    stdout: None,
                    stderr: None,
                    pty: Some(master),
                },
                child,
            ))
        }
    }
}

/// Open a pty pair: `(master, slave)` with the slave opened `O_RDWR` and
/// `O_NOCTTY`. The master stays host-side (resize/EOF source); the slave is
/// dup'd three times into the child's stdio.
fn open_pty_pair() -> std::io::Result<(OwnedFd, OwnedFd)> {
    use std::os::fd::FromRawFd;

    let master_raw = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master_raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let master = unsafe { OwnedFd::from_raw_fd(master_raw) };
    if unsafe { libc::grantpt(master.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::unlockpt(master.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut name = [0u8; 128];
    let rc = unsafe {
        libc::ptsname_r(
            master.as_raw_fd(),
            name.as_mut_ptr() as *mut libc::c_char,
            name.len(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let nul = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let slave_raw = unsafe {
        libc::open(
            name[..nul].as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_NOCTTY,
        )
    };
    if slave_raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((master, unsafe { OwnedFd::from_raw_fd(slave_raw) }))
}

/// Deliver `signum` to one registered child the way `sandlock-init` does
/// internally: group-first `killpg` over the child's own process group
/// (pid == pgid under F1.7's per-child-group layout), with a pidfd direct
/// complement only when the child escaped its own group. All best-effort:
/// ESRCH after the child exited is expected and harmless. This runs
/// host-side against the instance's own registry — there is no pid-addressed
/// signal verb on any wire (F1.7).
fn signal_registered_child(child: &ExecChild, signum: i32) {
    if let Some(pidfd) = child.pidfd.as_ref() {
        let group = unsafe { libc::getpgid(child.pid) };
        let escaped = group != child.pid;
        if escaped {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal as libc::c_long,
                    pidfd.as_raw_fd(),
                    signum,
                    std::ptr::null::<libc::c_void>(),
                    0u32,
                );
            }
        }
    }
    unsafe {
        libc::killpg(child.pid, signum);
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

/// Blocking `waitpid` of the direct child, mapping the raw status.
///
/// Only called once the child is already dead (the Drop backstop and the
/// shutdown escalation both SIGKILL first), so this never blocks on a live
/// child and never races the `policy_fn` fork-tracking worker for
/// ptrace-stops. Returns `None` when nothing was reaped here (e.g. `ECHILD`
/// because a concurrent reaper already took the status).
fn reap_direct_child(pid: libc::pid_t) -> Option<ExitStatus> {
    let mut status: i32 = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } > 0 {
        Some(sandbox_wait_status_to_exit(status))
    } else {
        None
    }
}

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
