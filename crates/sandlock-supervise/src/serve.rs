//! Single-generation control-channel serve (fork-plan F2b.2/F2b.3).
//!
//! Route B lifecycle: one `sandlock-supervise` process serves exactly one
//! sandbox generation.  The launcher provisions the generation's policy and
//! (when the generation has a workload) its program spec; this module builds
//! the session's [`SandboxInstance`] from the full-field policy, launches the
//! first process, and serves instance-level verbs over either control
//! transport until a `shutdown` verb completes the generation:
//!
//! * **fd handoff (transport 1)** — the launcher creates a control
//!   `socketpair()`, hands one end to this process as `--control-fd N` (the
//!   fd is the credential; no filesystem path is ever involved), and the
//!   worker keeps the other end.  Served by
//!   [`serve_control_fd`] via core's [`serve_fd_connection`] (one persistent
//!   frame stream).
//! * **registered path + token (transport 2)** — a route-B slot running as
//!   uid X binds a hashed socket in the shared 1777+sticky registry
//!   (deployer-agreed token via `--token`; peer uid allowlist via
//!   `--peer-uid`, default empty = same-uid-only).  Served by
//!   [`serve_registered_path`] with core's one-request-per-connection
//!   [`serve_registered_once`]: the accept loop keeps serving until a
//!   `shutdown` verb ends the generation — a refused or broken connection
//!   only ends that one connection.
//!
//! Single-generation is structural, not a policy: the serve loop runs once
//! per process and both serve entries return after the shutdown verb (or
//! after the worker drops / is refused); the binary then exits.  There is
//! deliberately no "serve another generation on this process" path — any
//! reuse of a supervise process would have to reset the whole runtime
//! (notif/listener/child table/accounting/token), which is exactly the
//! "clean-slate between generations" invariant route B enforces by process
//! restart (fork-plan-2026-09 §F2b).
//!
//! ## Identity boundary (fork-plan F2b.3)
//!
//! This process never changes its own host identity after startup, and it
//! never maps a *new* host uid for its mediator at runtime: the sandbox
//! mediator **is** this process, running as the uid the launcher provisioned
//! (`--uid X`, enforced by the startup self-check in `main.rs`).  The
//! forbidden "runtime re-map of the mediator to a new host uid" path (route-B
//! C-grade revival) is deliberately absent here and in `docs/
//! supervise-identity-handoff.md`; supervise exposes no verb, flag, or code
//! path that would setuid/setfsuid/setuid-map a live generation to another
//! host uid.  Multi-entry uid maps, `setuid` helpers, and CAP_SETUID live
//! strictly outside this crate (the deployer's launcher), never inside it.

use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::io::{OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;

use sandlock_core::control::{
    serve_fd_connection, serve_registered_once, write_response_frame, ControlHandler,
    ControlRequest, ControlResponse, ServeOutcome,
};
use sandlock_core::instance::{
    ExecParams, InstanceLifetime, InstancePhase, SandboxInstance,
};
use sandlock_core::profile::sandbox_to_profile;
use sandlock_core::result::ExitStatus;
use sandlock_core::Sandbox;

/// Default deadline for the `--policy <fd>` / `--program <fd>` startup read:
/// the fd is a one-shot trusted startup transport, so a stuck peer must fail
/// startup rather than hang the slot forever.
pub const POLICY_FD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum accepted policy/program document size for every transport (path +
/// fd).  A document larger than this is a protocol error, not a truncated
/// read.
pub const MAX_POLICY_BYTES: usize = 16 * 1024 * 1024;

/// The generation's workload spec: the argv of the session's first (M0)
/// process.  Deliberately separate from the full-field policy (fork-plan
/// F2b.1: the policy wire describes *what the sandbox allows*, not *what it
/// runs*); env/cwd/workdir/user all come from the policy fields, exactly like
/// `Sandbox::run(cmd)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramSpec {
    /// `argv[0]` is the executable path; remaining entries are its args.
    pub argv: Vec<String>,
}

impl ProgramSpec {
    /// Parse the `--program` document: a flat JSON object `{"argv": [...]}`
    /// with a non-empty string array.  Unknown keys fail by name so a launch
    /// document cannot silently drop a field this fork stage does not model.
    pub fn from_json(bytes: &[u8]) -> Result<ProgramSpec, String> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| format!("program JSON parse error: {e}"))?;
        let obj = value
            .as_object()
            .ok_or_else(|| "program spec must be a JSON object".to_string())?;
        let unknown: Vec<&String> = obj.keys().filter(|k| k.as_str() != "argv").collect();
        if !unknown.is_empty() {
            return Err(format!(
                "program spec contains unknown field(s): {}",
                unknown
                    .iter()
                    .map(|s| format!("`{s}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let argv = obj
            .get("argv")
            .ok_or_else(|| "program spec must contain an `argv` array".to_string())?;
        let arr = argv
            .as_array()
            .ok_or_else(|| "program spec `argv` must be an array of strings".to_string())?;
        if arr.is_empty() {
            return Err(
                "program spec `argv` must be non-empty (argv[0] is the executable)".to_string(),
            );
        }
        let mut parsed = Vec::with_capacity(arr.len());
        for (i, entry) in arr.iter().enumerate() {
            match entry.as_str() {
                Some(s) => parsed.push(s.to_string()),
                None => {
                    return Err(format!("program spec `argv[{i}]` must be a string"));
                }
            }
        }
        Ok(ProgramSpec { argv: parsed })
    }
}

/// One supervise generation: the policy snapshot, the provisioned program,
/// the live [`SandboxInstance`], and the tokio runtime that drives the
/// instance's supervisor tasks.
///
/// The instance is launched **first** when a program spec was provisioned
/// (launch-first: the slot starts its workload when it starts serving, and a
/// route-B generation owns exactly one M0 process).  Verb handlers that need
/// the async instance surface (`stats`, `ports`, `run`, `shutdown`) drive it
/// through the runtime with `block_on`; the control frame loop itself stays
/// synchronous and shared with core, so supervise and core can never drift
/// apart in framing or auth.
struct Generation {
    policy: Arc<Sandbox>,
    program: Option<ProgramSpec>,
    instance: Option<SandboxInstance>,
    // Declared after `instance` so a dropped Generation drops the instance
    // FIRST (its synchronous kill-and-clean backstop runs while the runtime
    // is still alive); the runtime field drops last and cancels any
    // remaining background task.
    rt: tokio::runtime::Runtime,
}

impl Generation {
    fn new(policy: Arc<Sandbox>, program: Option<ProgramSpec>) -> Result<Generation, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("build instance runtime: {e}"))?;
        let mut generation = Generation {
            policy,
            program,
            rt,
            instance: None,
        };
        // Launch-first (F2b.3): a generation with a provisioned workload
        // starts it before serving any verb.  A generation without one stays
        // unlaunched (stats/ports report `launched: false`; `run` explains
        // the F3 boundary).
        if generation.program.is_some() {
            generation.launch_first()?;
        }
        Ok(generation)
    }

    /// Launch the generation's first (M0) process from the provisioned
    /// program spec.  Idempotent: a second call (the `run` verb after
    /// launch-first) reports the already-launched instance.
    fn launch_first(&mut self) -> Result<(), String> {
        if self.instance.is_some() {
            return Ok(());
        }
        let program = self.program.clone().ok_or_else(|| {
            "generation has no program spec: run/launch needs --program at slot start"
                .to_string()
        })?;
        let policy = (*self.policy).clone();
        let cmd: Vec<&str> = program.argv.iter().map(|arg| arg.as_str()).collect();
        // I2: generation lifetime is deployment-owned. The core `T_max`
        // default (24 h) would force-drain a long-lived generation even
        // while its workload is alive — the deployment (slot pool / W1-W2
        // recycle, docs/supervise-identity-handoff.md §6) owns when a
        // generation ends, so supervise disables the core max-lifetime cap.
        // Idle reclaim keeps the core default (15 min) and only fires when
        // the child table is empty with no wait subscriber, which a running
        // workload prevents. Callers that want a cap must keep their own
        // outer timeout / reclamation loop.
        let lifetime = InstanceLifetime {
            max_lifetime: None,
            ..InstanceLifetime::default()
        };
        let instance = self
            .rt
            .block_on(SandboxInstance::launch_exec_with_lifetime(
                policy, &cmd, lifetime,
            ))
            .map_err(|e| format!("instance launch failed: {e}"))?;
        self.instance = Some(instance);
        Ok(())
    }

    /// Finish the generation according to how the transport ended.
    ///
    /// A `shutdown` verb runs the instance's graceful seven-step teardown
    /// ([`SandboxInstance::shutdown`]) and reports success — the binary then
    /// exits 0.  Any abnormal end (EOF/refusal/accept failure) drops the
    /// instance so its synchronous backstop SIGKILLs the workload and cleans
    /// every session-owned resource before the binary exits non-zero; a
    /// crashed or attacking peer can never leave a live workload behind.
    fn finish(&mut self, outcome: ServeOutcome) -> Result<(), String> {
        match outcome {
            ServeOutcome::Shutdown => {
                if let Some(mut instance) = self.instance.take() {
                    if let Err(e) = self.rt.block_on(instance.shutdown()) {
                        // The instance's Drop backstop still cleans up; report
                        // the failed teardown so the exit code stays non-zero.
                        drop(instance);
                        return Err(format!("instance shutdown failed: {e}"));
                    }
                }
                Ok(())
            }
            other => {
                // Abnormal end: the instance field drops first (declaration
                // order), running its synchronous kill-and-clean backstop
                // while the runtime is still alive.
                // Exec-mode exception: when the generation's main process
                // (child id 0) exits, `sandlock-init` collapses every group
                // and exits — the channel EOF that follows is the container's
                // *natural* end, matching init semantics, not an abnormal
                // peer end. The instance's effective phase reads `Exited`;
                // run the cleanup tail and exit 0.
                if self
                    .instance
                    .as_ref()
                    .map(|i| i.phase() == InstancePhase::Exited)
                    .unwrap_or(false)
                {
                    if let Some(mut instance) = self.instance.take() {
                        if let Err(e) = self.rt.block_on(instance.shutdown()) {
                            drop(instance);
                            return Err(format!("instance cleanup after main exit failed: {e}"));
                        }
                    }
                    return Ok(());
                }
                // FUP-03: like the clean paths, an abnormal end must run the
                // synchronous instance shutdown (kill + reap + control-dir
                // cleanup) BEFORE this process exits. Relying on Drop alone
                // raced the runtime teardown against process exit and could
                // leave a live/zombie workload reparented under pid 1.
                if let Some(mut instance) = self.instance.take() {
                    if let Err(e) = self.rt.block_on(instance.shutdown()) {
                        return Err(format!(
                            "control channel ended abnormally (outcome {other:?}); \
                             only a shutdown verb completes a generation \
                             (instance cleanup failed: {e})"
                        ));
                    }
                }
                Err(format!(
                    "control channel ended abnormally (outcome {other:?}); \
                     only a shutdown verb completes a generation"
                ))
            }
        }
    }

    fn stats_value(&self) -> serde_json::Value {
        match &self.instance {
            Some(instance) => {
                let stats = self.rt.block_on(instance.stats());
                let state = match stats.instance_state {
                    InstancePhase::Live => "Live",
                    InstancePhase::Draining => "Draining",
                    InstancePhase::ShutDown => "ShutDown",
                    InstancePhase::Exited => "Exited",
                    InstancePhase::Dead => "Dead",
                };
                serde_json::json!({
                    "launched": true,
                    "instance_state": state,
                    "children_live": stats.children_live,
                    "proc_count_vs_live": stats.proc_count_vs_live,
                    // Which identity the guest really gets: `uid-0-in-userns`
                    // (self-mapped, parity with a privileged supervisor) or
                    // `host-uid` (no usable unprivileged namespace, or the
                    // mediator already runs as the target uid by design).
                    "guest_uid": if self.policy.userns_self_map {
                        "uid-0-in-userns"
                    } else {
                        "host-uid"
                    },
                    "pid": instance.pid(),
                })
            }
            None => serde_json::json!({ "launched": false }),
        }
    }

    fn ports_value(&self) -> serde_json::Value {
        match &self.instance {
            Some(instance) => {
                let ports = self.rt.block_on(instance.ports());
                let inbound: Vec<serde_json::Value> = ports
                    .inbound
                    .iter()
                    .map(|mapping| {
                        serde_json::json!({
                            "sandbox_port": mapping.sandbox_port,
                            "host_port": mapping.host_port,
                            "live": mapping.live,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "launched": true,
                    "inbound": inbound,
                    "port_remap": ports.port_remap,
                })
            }
            None => serde_json::json!({
                "launched": false,
                "inbound": [],
                "port_remap": {},
            }),
        }
    }

    /// Serve an `exec` verb: install the worker's three stdio fds into a new
    /// registered child of the generation's instance and report its child id.
    /// `fds` arrive attached to the exec frame over SCM_RIGHTS (one protocol
    /// for both holders — the same `RunExec` frame the in-process executor
    /// sends to `sandlock-init`). F4.1 per-exec params (`cwd`/`env`/
    /// `clean_env`/`extra_writable`/`bind_ports`) travel in the frame's args
    /// and are validated against the instance ceiling host-side, exactly like
    /// the in-process exec surface.
    fn handle_exec(
        &mut self,
        args: &serde_json::Value,
        fds: &[OwnedFd],
    ) -> Result<serde_json::Value, String> {
        if fds.len() < 3 {
            return Err("exec requires 3 stdio fds attached via SCM_RIGHTS".to_string());
        }
        let argv: Vec<String> = args
            .get("argv")
            .and_then(|a| serde_json::from_value(a.clone()).ok())
            .ok_or_else(|| "exec requires an `argv` string array".to_string())?;
        if argv.is_empty() {
            return Err("exec: empty argv (argv[0] is the executable)".to_string());
        }
        let instance = self.instance.as_mut().ok_or_else(|| {
            "generation has no instance: exec requires a launched session \
             (provision --program at slot start)"
                .to_string()
        })?;
        // Dup all three fds into owned handles first: if a mid-loop dup fails,
        // the Vec's Drop closes the earlier dups (no fd leak on the error
        // path), and only then do we form the fixed-size array.
        let mut owned = Vec::with_capacity(3);
        for (i, fd) in fds.iter().take(3).enumerate() {
            let dup = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if dup < 0 {
                return Err(format!(
                    "dup stdio fd {} for exec: {}",
                    i,
                    std::io::Error::last_os_error()
                ));
            }
            owned.push(unsafe { OwnedFd::from_raw_fd(dup) });
        }
        let child_fds: [OwnedFd; 3] = owned
            .try_into()
            .map_err(|_| "exec requires exactly 3 stdio fds".to_string())?;
        let params = exec_params_from_args(args)?;
        let arg_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let handle = self
            .rt
            .block_on(instance.exec_with_fds_params(&arg_refs, &params, child_fds))
            .map_err(|e| format!("instance exec failed: {e}"))?;
        Ok(serde_json::json!({
            "child_id": handle.child_id,
            "pid": handle.pid,
        }))
    }

    /// Serve an `update_network` verb (F4.3/S2): the session's outbound IP
    /// allow set changes for **new execs only**; running children keep their
    /// exec-time policy and their child ids are returned as the staleness
    /// report.
    fn handle_update_network(
        &mut self,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let ips: Vec<std::net::IpAddr> = args
            .get("ips")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str())
                    .filter_map(|s| s.parse().ok())
                    .collect()
            })
            .ok_or_else(|| "update_network requires an `ips` string array".to_string())?;
        if ips.len() != args.get("ips").and_then(|v| v.as_array()).map_or(0, Vec::len) {
            return Err("update_network: every `ips` entry must be an IP literal".to_string());
        }
        let instance = self.instance.as_mut().ok_or_else(|| {
            "generation has no instance: update_network requires a launched session".to_string()
        })?;
        let report = self
            .rt
            .block_on(instance.update_network(&ips))
            .map_err(|e| format!("instance update_network failed: {e}"))?;
        Ok(serde_json::json!({
            "stale_child_ids": report.stale_child_ids,
        }))
    }

    /// Serve a `wait_child` verb: block until the named child exits and
    /// report its status (exit routing runs through the core executor's F1.2
    /// announced registry).
    fn handle_wait_child(&mut self, args: &serde_json::Value) -> Result<serde_json::Value, String> {
        let child_id: u64 = args
            .get("child_id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "wait_child requires a numeric `child_id`".to_string())?;
        let instance = self.instance.as_mut().ok_or_else(|| {
            "generation has no instance: wait_child requires a launched session".to_string()
        })?;
        let status = self
            .rt
            .block_on(instance.wait_child(child_id))
            .map_err(|e| format!("instance wait_child failed: {e}"))?;
        Ok(exit_status_json(&status))
    }

    /// Serve a `kill_child` verb: deliver `signum` to the named child through
    /// its registered pid/pidfd (never an arbitrary-pid verb).
    fn handle_kill_child(&mut self, args: &serde_json::Value) -> Result<serde_json::Value, String> {
        let child_id: u64 = args
            .get("child_id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "kill_child requires a numeric `child_id`".to_string())?;
        let signum: i32 = args
            .get("signum")
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok())
            .ok_or_else(|| "kill_child requires a numeric `signum`".to_string())?;
        let instance = self.instance.as_mut().ok_or_else(|| {
            "generation has no instance: kill_child requires a launched session".to_string()
        })?;
        instance
            .kill_child(child_id, signum)
            .map_err(|e| format!("instance kill_child failed: {e}"))?;
        Ok(serde_json::json!({}))
    }
}

/// Decode F4.1 per-exec parameters from an `exec` verb's args object. Every
/// field is optional; missing fields mean "no per-exec change" for that
/// dimension. The core instance then runs the S9 subset validation, so a
/// wider-than-ceiling grant over this cross-process route is refused
/// identically to the in-process surface.
fn exec_params_from_args(args: &serde_json::Value) -> Result<ExecParams, String> {
    let mut params = ExecParams::default();
    if let Some(cwd) = args.get("cwd").and_then(|v| v.as_str()) {
        params.cwd = Some(PathBuf::from(cwd));
    }
    params.clean_env = args
        .get("clean_env")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if let Some(env) = args.get("env").and_then(|v| v.as_object()) {
        for (name, value) in env {
            let value = value
                .as_str()
                .ok_or_else(|| format!("exec env {name:?} must be a string"))?;
            params.env.push((name.clone(), value.to_string()));
        }
    }
    if let Some(extra) = args.get("extra_writable").and_then(|v| v.as_array()) {
        for entry in extra {
            let s = entry
                .as_str()
                .ok_or_else(|| "exec extra_writable entries must be strings".to_string())?;
            params.extra_writable.push(PathBuf::from(s));
        }
    }
    if let Some(ports) = args.get("bind_ports").and_then(|v| v.as_array()) {
        for port in ports {
            let n = port
                .as_u64()
                .ok_or_else(|| "exec bind_ports entries must be integers".to_string())?;
            let n = u16::try_from(n)
                .map_err(|_| format!("exec bind_ports entry {n} is out of range"))?;
            params.bind_ports.push(n);
        }
    }
    Ok(params)
}

/// JSON form of an exec child's exit status for the `wait_child` verb.
fn exit_status_json(status: &ExitStatus) -> serde_json::Value {
    match status {
        ExitStatus::Code(c) => {
            serde_json::json!({ "code": c, "signal": null, "killed": false, "timed_out": false })
        }
        ExitStatus::Signal(s) => {
            serde_json::json!({ "code": null, "signal": s, "killed": false, "timed_out": false })
        }
        ExitStatus::Killed => {
            serde_json::json!({ "code": null, "signal": null, "killed": true, "timed_out": false })
        }
        ExitStatus::Timeout => {
            serde_json::json!({ "code": null, "signal": null, "killed": false, "timed_out": true })
        }
    }
}

fn ok_response(data: serde_json::Value) -> ControlResponse {
    ControlResponse {
        v: 1,
        ok: true,
        data: Some(data),
        err: None,
    }
}

fn err_response(err: &str) -> ControlResponse {
    ControlResponse {
        v: 1,
        ok: false,
        data: None,
        err: Some(err.to_string()),
    }
}

/// Verb handler for one generation.
///
/// Instance-level verbs (fork-plan F2b.3):
///
/// * `config` — policy snapshot (unchanged from F2b.2);
/// * `stats` — F2.3 `InstanceStats` (`instance_state`/`children_live`/
///   `proc_count_vs_live`) plus the launched pid;
/// * `ports` — live inbound (S2.5) mappings + the live `port_remap` table;
/// * `run` — launch-first trigger/state query: ok with the pid once the M0
///   process is running, explicit error when no program was provisioned;
/// * `exec` — register a new child with the worker's three stdio fds
///   (SCM_RIGHTS) and reply with its child id;
/// * `wait_child` / `kill_child` — per-child exit/status verbs by child id;
/// * `shutdown` — ends the generation (instance teardown runs after the
///   response is written, in [`Generation::finish`]).
impl ControlHandler for Generation {
    fn handle(
        &mut self,
        stream: &mut UnixStream,
        req: &ControlRequest,
        fds: &[OwnedFd],
    ) -> ServeOutcome {
        match req.verb.as_str() {
            "config" => {
                let profile = sandbox_to_profile(&self.policy, &[]);
                let data = serde_json::to_value(&profile).unwrap_or_else(
                    |e| serde_json::json!({"error": format!("serialize config: {e}")}),
                );
                let _ = write_response_frame(stream, &ok_response(data));
                ServeOutcome::Continue
            }
            "stats" => {
                let _ = write_response_frame(stream, &ok_response(self.stats_value()));
                ServeOutcome::Continue
            }
            "ports" => {
                let _ = write_response_frame(stream, &ok_response(self.ports_value()));
                ServeOutcome::Continue
            }
            "run" => {
                let resp = if !req.args.as_object().map(|o| o.is_empty()).unwrap_or(true) {
                    err_response(
                        "run takes no arguments in this fork stage: the generation's program \
                         is provisioned at slot start (--program)",
                    )
                } else {
                    match self.launch_first() {
                        Ok(()) => {
                            let pid = self.instance.as_ref().and_then(|i| i.pid());
                            ok_response(serde_json::json!({ "launched": true, "pid": pid }))
                        }
                        Err(e) => err_response(&e),
                    }
                };
                let _ = write_response_frame(stream, &resp);
                ServeOutcome::Continue
            }
            "exec" => {
                let resp = match self.handle_exec(&req.args, fds) {
                    Ok(data) => ok_response(data),
                    Err(e) => err_response(&e),
                };
                let _ = write_response_frame(stream, &resp);
                ServeOutcome::Continue
            }
            "wait_child" => {
                let resp = match self.handle_wait_child(&req.args) {
                    Ok(data) => ok_response(data),
                    Err(e) => err_response(&e),
                };
                let _ = write_response_frame(stream, &resp);
                ServeOutcome::Continue
            }
            "kill_child" => {
                let resp = match self.handle_kill_child(&req.args) {
                    Ok(data) => ok_response(data),
                    Err(e) => err_response(&e),
                };
                let _ = write_response_frame(stream, &resp);
                ServeOutcome::Continue
            }
            "update_network" => {
                let resp = match self.handle_update_network(&req.args) {
                    Ok(data) => ok_response(data),
                    Err(e) => err_response(&e),
                };
                let _ = write_response_frame(stream, &resp);
                ServeOutcome::Continue
            }
            "shutdown" => {
                let _ = write_response_frame(stream, &ok_response(serde_json::json!({})));
                ServeOutcome::Shutdown
            }
            other => {
                let resp = err_response(&format!("unknown verb: {other}"));
                let _ = write_response_frame(stream, &resp);
                ServeOutcome::Continue
            }
        }
    }
}

/// Does an unprivileged process here get a usable user namespace?
///
/// Route B restores "root inside the sandbox, host uid outside" by having the
/// confined child self-map `0 -> its own euid` (see `Sandbox::userns_self_map`),
/// which needs an unprivileged `unshare(CLONE_NEWUSER)` *and* a map write.
/// Kernels and LSMs differ (`kernel.apparmor_restrict_unprivileged_userns=1`
/// on Ubuntu 24.04 makes unshare succeed and the map write fail), so probe once
/// in a throwaway child and run the generation with whichever shape actually
/// works -- reported through `stats.guest_uid` so the worker can log it.
pub fn probe_userns_self_map() -> bool {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        // A privileged mediator needs none of this: it writes the child's maps
        // itself.
        return false;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // The probe child exits; it never returns into the supervisor.
        let ok = unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0
            && std::fs::write("/proc/self/uid_map", format!("0 {euid} 1\n")).is_ok()
            && std::fs::write("/proc/self/setgroups", "deny\n").is_ok()
            && std::fs::write("/proc/self/gid_map", format!("0 {euid} 1\n")).is_ok();
        unsafe { libc::_exit(i32::from(!ok)) };
    }
    let mut status: libc::c_int = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return false;
    }
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// Serve the handed-off control fd until a shutdown verb completes the
/// generation (or the worker closes / is refused).  `policy` is the
/// validated full-field policy of this generation; `program` is the
/// provisioned workload argv (launch-first at serve start when present).
///
/// The frame loop itself is core's [`serve_fd_connection`] (transport 1's
/// shared session): parse/version/token refusals and EOF are classified
/// there.  This function only supplies the generation's verb handler and the
/// fd, so supervise and the core fd transport can never drift apart in
/// framing or auth.  Returns `Ok(())` only after a shutdown verb AND a
/// successful instance teardown; everything else is an `Err` naming the
/// abnormal end (the binary then exits non-zero).
pub fn serve_control_fd(
    control_fd: RawFd,
    policy: Arc<Sandbox>,
    program: Option<ProgramSpec>,
    expected_token: Option<&str>,
) -> Result<(), String> {
    // The handed-off fd is the connected worker end of the launcher's
    // socketpair.  Taking ownership is correct for the serve duration: this
    // process exits right after serving.
    let stream = unsafe { UnixStream::from_raw_fd(control_fd) };
    // Put `FD_CLOEXEC` back before anything is launched.  The launcher had to
    // clear it so the descriptor would survive its own `exec`, and leaving it
    // cleared leaks the supervisor's control endpoint into `sandlock-init` and
    // therefore into every workload process it spawns -- the SL-4 class: a
    // confined process would hold the same socket the worker frames its
    // `exec`/`wait_child` requests on (reading frames addressed to the worker,
    // including the SCM_RIGHTS stdio descriptors), and it would also pin the
    // connection open so the generation outlives a dead worker instead of
    // tearing itself down on EOF.  The flag is per descriptor, so the worker's
    // own end is untouched.
    //
    // SL-11 tracks this as a *guard*, not a repair: measured 2026-09-09, core
    // hands `sandlock-init` an explicit fd set, so the confined fd table was
    // observably clean both with and without the restore.  It is applied
    // unconditionally anyway, so a future change to that hand-off set cannot
    // silently reopen the SL-4 family (pinned by
    // `test_supervise_control_fd_stays_out_of_the_confined_tree`).
    if unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(format!(
            "set FD_CLOEXEC on the handed-over control fd: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut generation = Generation::new(policy, program)?;
    let outcome = serve_fd_connection(stream, expected_token, &mut generation);
    generation.finish(outcome)
}

/// Rate limiter for a registered slot's abnormal-connection log (FUP-11c).
///
/// Every refused or broken peer on the registered path is a real event, but
/// it is *one event per connection*: a slot serves many workers over its
/// lifetime, so an unthrottled `eprintln!` turns a connection flood (or a
/// misconfigured worker retry loop) into an unbounded log flood.  The fd
/// transport cannot hit this — one stream, one verdict.
///
/// Posture: the **first** abnormal end is always reported (so a genuine
/// regression is attributable without any counting), and afterwards only
/// every [`AbnormalEndLog::REPORT_EVERY`]-th one — each line carrying the
/// running total, so the swallowed volume stays visible.
#[derive(Debug, Default)]
pub struct AbnormalEndLog {
    /// Abnormal ends seen so far (including the ones that stayed quiet).
    seen: u64,
}

impl AbnormalEndLog {
    /// Abnormal ends that may pass between two log lines after the first.
    pub const REPORT_EVERY: u64 = 256;

    /// Record one abnormal end.  `Some(total)` means "print the line now"
    /// (the first end, then every [`Self::REPORT_EVERY`]-th); `None` means
    /// stay quiet and keep counting.
    pub fn note(&mut self) -> Option<u64> {
        self.seen += 1;
        if self.seen == 1 || self.seen % Self::REPORT_EVERY == 0 {
            Some(self.seen)
        } else {
            None
        }
    }

    /// Total abnormal ends recorded (teardown summaries, tests).
    pub fn total(&self) -> u64 {
        self.seen
    }
}

/// The exact line a slot prints for abnormal registered-connection end
/// number `total` (1 for the naming first line).
pub fn registered_abnormal_end_line(total: u64) -> String {
    format!(
        "sandlock-supervise: registered connection ended abnormally \
         (refused or broken peer) [{total} total]; the slot keeps serving"
    )
}

/// Serve a registered-path slot until a shutdown verb completes the
/// generation.  The slot binds its channel before this is called (see
/// `main.rs`); every worker verb arrives on its own connection and is served
/// by core's [`serve_registered_once`] (peer uid allowlist + token).
///
/// Abnormal connection ends (peer outside the allowlist, EOF, parse/version
/// or token refusal) return [`ServeOutcome::PeerGone`] for that one
/// connection: the slot logs and keeps accepting — only a `shutdown` verb
/// ends the generation, so a garbage/attacking connection can neither kill
/// the slot nor masquerade as a clean end.  Returns `Ok(())` only after a
/// shutdown verb AND a successful instance teardown.
///
/// FUP-11c: the per-connection log goes through [`AbnormalEndLog`], so a
/// flood of refused connections cannot flood the slot's stderr.
pub fn serve_registered_path(
    listener: &Arc<UnixListener>,
    token: &str,
    allowed_peer_uids: &[u32],
    policy: Arc<Sandbox>,
    program: Option<ProgramSpec>,
) -> Result<(), String> {
    let mut generation = Generation::new(policy, program)?;
    let mut abnormal_ends = AbnormalEndLog::default();
    loop {
        match serve_registered_once(listener, token, allowed_peer_uids, &mut generation) {
            Some(ServeOutcome::Continue) => {}
            Some(ServeOutcome::Shutdown) => return generation.finish(ServeOutcome::Shutdown),
            Some(ServeOutcome::PeerGone) => {
                if let Some(total) = abnormal_ends.note() {
                    eprintln!("{}", registered_abnormal_end_line(total));
                }
            }
            None => {
                drop(generation);
                return Err("registered listener accept failed".to_string());
            }
        }
    }
}

/// Read a policy/program document from an already-open fd with a timeout and
/// a hard size cap: the fd is a one-shot trusted startup transport (the
/// launcher writes the JSON once and closes), so a peer that stalls past the
/// deadline or streams more than [`MAX_POLICY_BYTES`] must fail startup —
/// never hang the slot nor accept a truncated document.
pub fn read_policy_fd(fd: RawFd, timeout: std::time::Duration) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    let started = std::time::Instant::now();
    let mut buf = [0u8; 8192];
    loop {
        // Poll with the REMAINING deadline before every read: a writer that
        // stalls mid-stream (after delivering the first bytes) must still
        // fail within the deadline instead of hanging the slot forever.
        let elapsed = started.elapsed();
        let remaining = timeout.saturating_sub(elapsed);
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let rc = unsafe {
            libc::poll(
                &mut pfd,
                1,
                remaining.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if rc < 0 {
            return Err(format!(
                "policy fd {fd}: poll failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if rc == 0 {
            return Err(format!(
                "policy fd {fd}: timed out after {} ms of a {} ms deadline waiting for bytes",
                elapsed.as_millis(),
                timeout.as_millis()
            ));
        }
        // POLLHUP with no POLLIN means the writer closed: EOF.
        if pfd.revents & libc::POLLIN == 0 && pfd.revents & libc::POLLHUP != 0 {
            break;
        }
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("policy fd {fd}: read failed: {e}"))?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(format!(
                "policy fd {fd}: document exceeds {} bytes",
                MAX_POLICY_BYTES
            ));
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_spec_parses_argv() {
        let spec = ProgramSpec::from_json(br#"{"argv": ["/bin/sh", "-c", "echo hi"]}"#)
            .expect("valid program spec parses");
        assert_eq!(
            spec.argv,
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hi".to_string()
            ]
        );
    }

    #[test]
    fn program_spec_rejects_empty_argv() {
        let err = ProgramSpec::from_json(br#"{"argv": []}"#).unwrap_err();
        assert_eq!(
            err,
            "program spec `argv` must be non-empty (argv[0] is the executable)"
        );
    }

    #[test]
    fn program_spec_rejects_unknown_fields_by_name() {
        let err =
            ProgramSpec::from_json(br#"{"argv": ["/bin/true"], "env": {"A": "1"}}"#).unwrap_err();
        assert_eq!(
            err,
            "program spec contains unknown field(s): `env`",
            "unknown program field must be named, got: {err}"
        );
    }

    #[test]
    fn program_spec_rejects_non_string_argv_entry() {
        let err = ProgramSpec::from_json(br#"{"argv": ["/bin/true", 42]}"#).unwrap_err();
        assert_eq!(err, "program spec `argv[1]` must be a string");
    }

    /// FUP-11c: the registered slot reports the FIRST abnormal connection end
    /// verbatim and afterwards only one line per `REPORT_EVERY` ends — each
    /// line carries the running total, so a connection flood cannot become an
    /// unbounded stderr flood while a real regression stays attributable.
    #[test]
    fn abnormal_end_log_reports_first_then_throttles() {
        let mut log = AbnormalEndLog::default();
        assert_eq!(
            log.note(),
            Some(1),
            "the first abnormal end must always be reported"
        );
        for n in 2..AbnormalEndLog::REPORT_EVERY {
            assert_eq!(log.note(), None, "abnormal end {n} must stay quiet");
        }
        assert_eq!(
            log.note(),
            Some(AbnormalEndLog::REPORT_EVERY),
            "every REPORT_EVERY-th abnormal end must print the running total"
        );
        assert_eq!(
            log.total(),
            AbnormalEndLog::REPORT_EVERY,
            "swallowed ends must still be counted"
        );
    }

    /// FUP-11c: the slot's log line is a fixed string (the integration suite
    /// pins the whole stderr of a slot that refused one connection).
    #[test]
    fn registered_abnormal_end_line_is_pinned() {
        assert_eq!(
            registered_abnormal_end_line(1),
            "sandlock-supervise: registered connection ended abnormally \
             (refused or broken peer) [1 total]; the slot keeps serving"
        );
        assert_eq!(
            registered_abnormal_end_line(256),
            "sandlock-supervise: registered connection ended abnormally \
             (refused or broken peer) [256 total]; the slot keeps serving"
        );
    }
}
