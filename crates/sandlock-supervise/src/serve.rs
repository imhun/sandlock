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

use std::os::fd::FromRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use sandlock_core::control::{
    serve_fd_connection, serve_registered_once, write_response_frame, ControlHandler,
    ControlRequest, ControlResponse, ServeOutcome,
};
use sandlock_core::instance::{InstancePhase, SandboxInstance};
use sandlock_core::profile::sandbox_to_profile;
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
            "generation has no program spec: run/launch needs --program at slot start; \
                 multi-process exec arrives with F3"
                .to_string()
        })?;
        let policy = (*self.policy).clone();
        let cmd: Vec<&str> = program.argv.iter().map(|arg| arg.as_str()).collect();
        let instance = self
            .rt
            .block_on(SandboxInstance::launch(policy, &cmd))
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
                drop(self.instance.take());
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
                };
                serde_json::json!({
                    "launched": true,
                    "instance_state": state,
                    "children_live": stats.children_live,
                    "proc_count_vs_live": stats.proc_count_vs_live,
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
/// * `exec` — explicit F3 skeleton error (multi-process exec arrives later);
/// * `shutdown` — ends the generation (instance teardown runs after the
///   response is written, in [`Generation::finish`]).
impl ControlHandler for Generation {
    fn handle(&mut self, stream: &mut UnixStream, req: &ControlRequest) -> ServeOutcome {
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
                         is provisioned at slot start (--program); the exec verb arrives with F3",
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
                let resp = err_response(
                    "exec verb arrives with F3 (multi-process exec); this generation serves \
                     one M0 process launched at serve start (launch-first)",
                );
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
    let mut generation = Generation::new(policy, program)?;
    let outcome = serve_fd_connection(stream, expected_token, &mut generation);
    generation.finish(outcome)
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
pub fn serve_registered_path(
    listener: &Arc<UnixListener>,
    token: &str,
    allowed_peer_uids: &[u32],
    policy: Arc<Sandbox>,
    program: Option<ProgramSpec>,
) -> Result<(), String> {
    let mut generation = Generation::new(policy, program)?;
    loop {
        match serve_registered_once(listener, token, allowed_peer_uids, &mut generation) {
            Some(ServeOutcome::Continue) => {}
            Some(ServeOutcome::Shutdown) => return generation.finish(ServeOutcome::Shutdown),
            Some(ServeOutcome::PeerGone) => {
                eprintln!(
                    "sandlock-supervise: registered connection ended abnormally \
                     (refused or broken peer); the slot keeps serving"
                );
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
        assert!(
            err.contains("non-empty"),
            "empty argv must be rejected by name, got: {err}"
        );
    }

    #[test]
    fn program_spec_rejects_unknown_fields_by_name() {
        let err =
            ProgramSpec::from_json(br#"{"argv": ["/bin/true"], "env": {"A": "1"}}"#).unwrap_err();
        assert!(
            err.contains("`env`"),
            "unknown program field must be named, got: {err}"
        );
    }

    #[test]
    fn program_spec_rejects_non_string_argv_entry() {
        let err = ProgramSpec::from_json(br#"{"argv": ["/bin/true", 42]}"#).unwrap_err();
        assert!(
            err.contains("argv[1]"),
            "non-string argv entry must be named by index, got: {err}"
        );
    }
}
