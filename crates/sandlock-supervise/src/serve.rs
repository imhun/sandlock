//! Single-generation control-channel serve (fork-plan F2b.2).
//!
//! Route B lifecycle: one `sandlock-supervise` process serves exactly one
//! sandbox generation.  The launcher creates a control `socketpair()`,
//! hands one end to this process as `--control-fd N` (fd handoff transport;
//! no filesystem path is ever involved — the fd is the credential), and the
//! worker keeps the other end.  This module serves that handed-off stream
//! with the shared control protocol (4-byte big-endian length + JSON, the
//! same verb/frame/auth layer as the core registered-path channel), until a
//! `shutdown` verb completes the generation.
//!
//! Single-generation is structural, not a policy: the serve loop runs once
//! per process and [`serve_control_fd`] returns after the shutdown verb (or
//! when the worker drops its end); the binary then exits.  There is
//! deliberately no "serve another generation on this process" path — any
//! reuse of a supervise process would have to reset the whole runtime
//! (notif/listener/child table/accounting/token), which is exactly the
//! "clean-slate between generations" invariant route B enforces by process
//! restart (fork-plan-2026-09 §F2b).

use std::os::fd::FromRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;

use sandlock_core::control::{
    serve_fd_connection, write_response_frame, ControlHandler, ControlRequest, ControlResponse,
    ServeOutcome,
};
use sandlock_core::profile::sandbox_to_profile;
use sandlock_core::Sandbox;

/// Default deadline for the `--policy <fd>` startup read: the policy fd is a
/// one-shot trusted startup transport, so a stuck peer must fail startup
/// rather than hang the slot forever.
pub const POLICY_FD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum accepted policy-document size for every transport (path + fd).  A
/// policy larger than this is a protocol error, not a truncated read.
pub const MAX_POLICY_BYTES: usize = 16 * 1024 * 1024;

/// Serve the handed-off control fd until a shutdown verb completes the
/// generation (or the worker closes its end).  `policy` is the validated
/// sandbox policy of this generation — the `config` verb serves its
/// snapshot.  No workload has been launched yet (the exec/launch verb lands
/// with F2b.3/F3), so the single generation is the control-channel
/// generation.
///
/// The frame loop itself is core's [`serve_fd_connection`] (transport 1's
/// shared session): parse/version/token refusals and EOF are classified
/// there.  This function only supplies the generation's verb handler and
/// the fd, so supervise and the core fd transport can never drift apart in
/// framing or auth.
pub fn serve_control_fd(
    control_fd: RawFd,
    policy: std::sync::Arc<Sandbox>,
    expected_token: Option<&str>,
) -> ServeOutcome {
    // The handed-off fd is the connected worker end of the launcher's
    // socketpair.  Taking ownership is correct for the serve duration: this
    // process exits right after serving.
    let stream = unsafe { UnixStream::from_raw_fd(control_fd) };
    let mut handler = GenerationHandler { policy };
    serve_fd_connection(stream, expected_token, &mut handler)
}

/// Verb handler for one generation: `config` returns the policy snapshot;
/// `shutdown` completes the generation.  The snapshot has no dynamic
/// policy_fn denies (supervise validates a static policy; the dynamic
/// callback machinery is launcher/Python-side and not part of this entry).
struct GenerationHandler {
    policy: std::sync::Arc<Sandbox>,
}

impl ControlHandler for GenerationHandler {
    fn handle(&mut self, stream: &mut UnixStream, req: &ControlRequest) -> ServeOutcome {
        match req.verb.as_str() {
            "config" => {
                let profile = sandbox_to_profile(&self.policy, &[]);
                let data = serde_json::to_value(&profile).unwrap_or_else(
                    |e| serde_json::json!({"error": format!("serialize config: {e}")}),
                );
                let resp = ControlResponse {
                    v: 1,
                    ok: true,
                    data: Some(data),
                    err: None,
                };
                let _ = write_response_frame(stream, &resp);
                ServeOutcome::Continue
            }
            "shutdown" => {
                let resp = ControlResponse {
                    v: 1,
                    ok: true,
                    data: None,
                    err: None,
                };
                let _ = write_response_frame(stream, &resp);
                ServeOutcome::Shutdown
            }
            other => {
                let resp = ControlResponse {
                    v: 1,
                    ok: false,
                    data: None,
                    err: Some(format!("unknown verb: {other}")),
                };
                let _ = write_response_frame(stream, &resp);
                ServeOutcome::Continue
            }
        }
    }
}

/// Read a policy document from an already-open fd with a timeout and a hard
/// size cap: the fd is a one-shot trusted startup transport (the launcher
/// writes the JSON once and closes), so a peer that stalls past the timeout
/// or streams more than [`MAX_POLICY_BYTES`] must fail startup — never hang
/// the slot nor accept a truncated policy.
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
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis().min(i32::MAX as u128) as i32) };
        if rc < 0 {
            return Err(format!(
                "policy fd {fd}: poll failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if rc == 0 {
            return Err(format!(
                "policy fd {fd}: timed out after {} ms waiting for policy bytes",
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
