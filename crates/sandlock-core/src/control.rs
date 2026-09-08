//! Per-sandbox Unix control socket for introspection.
//!
//! Every sandbox (CLI, Python SDK, embedded) gets a runtime directory under a
//! per-uid, owner-only state root that is **not** part of a sandbox's
//! Landlock filesystem view:
//!
//! * default root: `/tmp/sandlock-ctl-$UID` (override with the
//!   `SANDBOX_CTL_ROOT` environment variable — used by the integration tests
//!   for isolation).  The old `/dev/shm/sandlock-$UID` root was visible to
//!   sibling sandboxes that mount `/dev` (the SL-7 cross-sandbox read); the
//!   new root is unreachable unless a config explicitly grants it.
//! * per-sandbox dir: `<fnv1a16(name)>.d` — a 64-bit FNV-1a hash of the
//!   sandbox name, so the raw name is never a path component (a sibling that
//!   can enumerate the root still cannot map names to dirs without the hash,
//!   and the dir the sandbox actually runs with is never an obvious target).
//!
//! Each runtime dir contains:
//!
//! * `pid` — three-line pid file (`child_pid\nsupervisor_pid\nstarttime\n`);
//!   lets `sandlock ps` list and prune dead sandboxes without opening the
//!   socket. The child PID is used for `/proc` introspection (UPTIME, CMD);
//!   the supervisor PID owns the control socket; the third line records the
//!   supervisor's `/proc/<pid>/stat` starttime (field 22), so liveness and
//!   stale-reclaim decisions compare identities instead of trusting
//!   `kill(pid, 0)` on a possibly reused pid.
//! * `name` — the raw sandbox name (metadata for `sandlock ps` display).
//! * `token` — random per-sandbox identity token (0600), read by the client
//!   and required by the sensitive `config`/`ports` verbs.
//! * `control.sock` — Unix stream socket bound by the supervisor before the
//!   child is forked.  Serves the introspection wire protocol.
//!
//! ## Wire protocol
//!
//! 4-byte big-endian length prefix, then UTF-8 JSON.  One client at a time per
//! socket; the server closes the connection after serving (or refusing) one
//! request.
//!
//! Request:
//! ```json
//! {"v": 1, "verb": "config", "args": {}, "token": "<identity token>"}
//! ```
//!
//! Response:
//! ```json
//! {"v": 1, "ok": true, "data": { ...effective Sandbox policy... }}
//! ```
//! or
//! ```json
//! {"v": 1, "ok": false, "err": "..."}
//! ```
//!
//! ## Authentication model (SL-7, fork-plan-2026-09 F1.3)
//!
//! 1. The state root and every runtime dir are 0700 and the socket is 0600,
//!    so the kernel DAC owner check stops other uids before the socket.
//! 2. The root is outside the Landlock view of every sandbox this codebase
//!    creates, so a sibling sandbox cannot even reach the socket (verified by
//!    `integration/test_control.rs::test_sibling_sandbox_cannot_read_other_policy`).
//! 3. As a belt for shared-directory / future fd-less transports, the server
//!    reads `SO_PEERCRED` on every connection and **closes** the connection
//!    (no response, no log) when the peer uid differs from the supervisor's.
//! 4. Sensitive verbs (`config`, `ports`) require the runtime dir's identity
//!    token; a missing or mismatched token is refused explicitly and the
//!    connection is closed.
//!
//! Name collisions never preempt: when a runtime dir exists, setup refuses
//! unless the recorded owner is provably gone (a valid pid file whose
//! recorded supervisor starttime no longer matches `/proc/<pid>/stat`).  A
//! pid file that is missing, unreadable, or carries no starttime is
//! `Ambiguous` **regardless of the dir's age** (F1.3: create time must never
//! `remove_dir_all` a pid-less dir — it may be a live sandbox whose pid file
//! was lost); genuinely dead pid-less debris is reclaimed only by the
//! explicit `list_live_sandboxes`/`sandlock ps` pruning path with its own
//! recency guard.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::init::fdpass;
use crate::sandbox::Sandbox;
use crate::seccomp::ctx::SupervisorCtx;

// ============================================================
// Public API — runtime dir helpers (used by core + CLI)
// ============================================================

/// Environment override for the per-user control state root.  The
/// integration tests set this to a per-process root under `/tmp` so several
/// suites can share a container without enumerating each other's sandboxes.
pub const CTL_ROOT_ENV: &str = "SANDBOX_CTL_ROOT";

/// Return the per-user runtime directory root.
pub(crate) fn runtime_dir_uid(uid: u32) -> PathBuf {
    if let Ok(root) = std::env::var(CTL_ROOT_ENV) {
        if !root.is_empty() {
            return PathBuf::from(root);
        }
    }
    // /tmp is host-reachable for the same uid, writable by the unprivileged
    // supervisor, and never granted to a sandbox by this codebase's default
    // fs config (the sandbox would need an explicit -r/-w for it).
    PathBuf::from(format!("/tmp/sandlock-ctl-{}", uid))
}

/// Deterministic 64-bit FNV-1a hash of `name`, rendered as 16 lowercase hex
/// digits (mirrors the sandlock-oci supervisor socket naming, which was
/// measured to be sandbox-unreachable).  Public so the F2b.2 registered-path
/// transport (and clients that need to locate a channel without the raw
/// name) uses the same digest.
pub fn fnv1a_hex(name: &str) -> String {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for b in name.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    format!("{:016x}", h)
}

/// Return the per-sandbox runtime directory for a given name.
///
/// The directory is `<state root>/<fnv1a16(name)>.d`: the raw name is never
/// a path component (the caller still validates names so that the uid-wide
/// name key and the `name` metadata stay single-token strings).
pub fn sandbox_dir(name: &str) -> PathBuf {
    let uid = unsafe { libc::getuid() };
    runtime_dir_uid(uid).join(format!("{}.d", fnv1a_hex(name)))
}

/// Return the pid file path inside a sandbox runtime dir.
pub fn pid_path(dir: &Path) -> PathBuf {
    dir.join("pid")
}

/// Return the identity-token file path inside a sandbox runtime dir.
pub fn token_path(dir: &Path) -> PathBuf {
    dir.join("token")
}

/// Return the raw-name metadata file path inside a sandbox runtime dir.
pub fn name_path(dir: &Path) -> PathBuf {
    dir.join("name")
}

/// Return the control socket path inside a sandbox runtime dir.
pub fn sock_path(dir: &Path) -> PathBuf {
    dir.join("control.sock")
}

/// Read a sandbox's operating-mode marker (e.g. "learn") from its runtime
/// dir. `None` for ordinary runs, which write no mode file.
pub fn sandbox_mode(name: &str) -> Option<String> {
    let s = std::fs::read_to_string(sandbox_dir(name).join("mode")).ok()?;
    let s = s.trim();
    if s.is_empty() { None } else { Some(s.to_string()) }
}

/// Read a runtime dir's pid file.
///
/// Format: `child_pid\nsupervisor_pid\nsupervisor_starttime\n`.  The
/// starttime (field 22 of `/proc/<pid>/stat`, in clock ticks) is the
/// recorded identity of the supervisor process that created the dir; it lets
/// liveness/staleness checks detect pid reuse instead of trusting
/// `kill(pid, 0)`.  Returns `None` if the file is missing or unparseable.
/// A legacy two-line file (no starttime) parses with `starttime == None`.
fn read_pid_file(dir: &Path) -> Option<(i32, i32, Option<u64>)> {
    let content = std::fs::read_to_string(pid_path(dir)).ok()?;
    let mut lines = content.lines();
    let child_pid: i32 = lines.next()?.trim().parse().ok()?;
    let supervisor_pid: i32 = lines.next()?.trim().parse().ok()?;
    let starttime: Option<u64> = lines.next().and_then(|l| l.trim().parse().ok());
    Some((child_pid, supervisor_pid, starttime))
}

/// Read the raw-name metadata file from a runtime dir.
fn read_name(dir: &Path) -> Option<String> {
    let s = std::fs::read_to_string(name_path(dir)).ok()?;
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Read the identity token from a runtime dir's token file.
fn read_token(dir: &Path) -> Option<String> {
    let s = std::fs::read_to_string(token_path(dir)).ok()?;
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Constant-time-ish token comparison (no early exit on the first differing
/// byte).  Length mismatch is inherently visible; the token is only one layer
/// of the auth model (DAC 0700/0600 and the sandbox-unreachable root are the
/// primary ones).
pub fn token_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================
// Runtime dir lifecycle — called from sandbox-core
// ============================================================

/// Create the per-sandbox runtime directory, write the identity files, and
/// bind the control socket — shared by the supervisor and no_supervisor
/// paths.  Returns the dir path.
///
/// # Name collision
///
/// If a runtime directory already exists for `name`, this returns
/// `ErrorKind::AlreadyExists` unless the directory can be **proven** stale:
/// a valid pid file exists AND its recorded supervisor starttime is readable
/// and no longer matches `/proc/<pid>/stat` (the recorded owner is gone).
/// Every other state — including a missing/unreadable pid file or a legacy
/// two-line pid file with no starttime, **regardless of the dir's age** —
/// refuses with `Ambiguous`; create time never `remove_dir_all`s a pid-less
/// dir (the SL-7 regression test pins both fresh and backdated pid-less
/// dirs).
///
/// # no_supervisor callers
///
/// The `no_supervisor` path in `do_spawn` calls this directly (without the
/// socket) instead of duplicating a bare `remove_dir_all` + `create_dir_all`
/// that had no liveness check and would wipe a live sandbox's pid file on a
/// name collision.
pub(crate) fn setup_runtime_dir(
    name: &str,
    child_pid: i32,
    supervisor_pid: i32,
    mode: Option<&str>,
) -> Result<(UnixListener, PathBuf), std::io::Error> {
    let dir = setup_runtime_dir_no_socket(name, child_pid, supervisor_pid, mode)?;

    // Bind control socket.
    let sp = sock_path(&dir);
    let listener = UnixListener::bind(&sp)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sp, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok((listener, dir))
}

/// Create the per-sandbox runtime directory and write the identity files
/// (token, name, mode, pid), without binding a control socket.  Used by the
/// `no_supervisor` path (no socket exists) and as the common prefix of
/// `setup_runtime_dir` for the supervisor path.
pub(crate) fn setup_runtime_dir_no_socket(
    name: &str,
    child_pid: i32,
    supervisor_pid: i32,
    mode: Option<&str>,
) -> Result<PathBuf, std::io::Error> {
    let dir = sandbox_dir(name);

    // Refuse instead of preempting: an existing dir is a live candidate, and
    // is only reclaimed when provably stale (see classify_existing_dir).
    if dir.exists() {
        match classify_existing_dir(&dir, name)? {
            ExistingDir::Live { supervisor_pid } => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("sandbox '{}' is already running (PID {})", name, supervisor_pid),
                ));
            }
            ExistingDir::Ambiguous => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "sandbox '{}' state dir exists but cannot be proven stale; \
                         refusing to preempt it",
                        name
                    ),
                ));
            }
            ExistingDir::Stale => {
                // Provably abandoned: recorded owner gone / old incomplete dir.
                std::fs::remove_dir_all(&dir)?;
            }
        }
    }

    // Owner-only per-user root; created on demand so `sandlock ps` and the
    // clients can rely on it existing once any sandbox has run.
    let root = runtime_dir_uid(unsafe { libc::getuid() });
    std::fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    }
    std::fs::create_dir_all(&dir)?;

    // Restrict to owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }

    // Identity token first: the dir is not complete without it, and a
    // concurrent enumerator that sees the dir before the pid file must not
    // mistake a mid-setup dir for a live sandbox.  Created in one step with
    // the final 0600 mode (create_new fails closed if the file exists).
    let token = generate_token()?;
    let token_file = token_path(&dir);
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token_file)?;
        writeln!(f, "{}", token)?;
    }

    // Raw-name metadata (for `sandlock ps`; the dir name itself is hashed).
    std::fs::write(name_path(&dir), format!("{}\n", name))?;

    // Write pid file atomically via temp + rename so list_live_sandboxes
    // never sees a partially-written or empty pid file.  The third line is
    // the supervisor's starttime (see read_pid_file); recording the identity
    // of the writing process is what lets later setup/list code detect pid
    // reuse instead of trusting kill(pid, 0).
    let starttime = crate::seccomp::state::read_pid_start_time(supervisor_pid).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("cannot read starttime of supervisor pid {}", supervisor_pid),
        )
    })?;

    // Operating-mode marker for the `sandlock ps` STATUS column. Written
    // before the pid file so a listing never sees the sandbox without it.
    if let Some(m) = mode {
        std::fs::write(dir.join("mode"), m)?;
    }

    let pid_path = pid_path(&dir);
    let tmp_path = dir.join(".pid.tmp");
    std::fs::write(
        &tmp_path,
        format!("{}\n{}\n{}\n", child_pid, supervisor_pid, starttime),
    )?;
    std::fs::rename(&tmp_path, &pid_path)?;

    Ok(dir)
}

/// Generate a fresh random identity token (64 hex chars from 32 bytes of
/// kernel entropy).  Also used by the F2b.2 dual-transport channels.
pub fn generate_token() -> Result<String, std::io::Error> {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Classification of an existing runtime dir when a new sandbox wants the
/// same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingDir {
    /// The recorded supervisor process is alive and owns the dir.
    Live { supervisor_pid: i32 },
    /// The dir exists but staleness cannot be proven — refuse.
    Ambiguous,
    /// The dir is provably abandoned — safe to reclaim.
    Stale,
}

/// Decide whether an existing runtime dir may be reclaimed.
///
/// Refusal is the default.  Exactly one case reclaims at create time:
///
/// * a valid pid file exists AND its recorded supervisor starttime is
///   readable and no longer matches `/proc/<pid>/stat` — the recorded owner
///   is unambiguously gone (and if the pid was reused, the starttime
///   mismatch proves this dir predates the current occupant).
///
/// Every other state refuses with `Ambiguous` at create time: a current
/// starttime that cannot be read (the process may be alive behind an
/// unreadable /proc), a legacy two-line pid file with no recorded starttime
/// (`kill(pid, 0)` cannot detect pid reuse), and a missing or unparseable
/// pid file **regardless of the dir's age** — the dir may be a live sandbox
/// whose pid file was lost (the SL-7 regression test pins exactly this, with
/// both a fresh and a backdated dir), or a setup still in progress.  Create
/// time must never `remove_dir_all` a pid-less dir; genuinely dead pid-less
/// debris is reclaimed only by the explicit `list_live_sandboxes`/`sandlock
/// ps` pruning path, which applies its own recency guard.
fn classify_existing_dir(dir: &Path, name: &str) -> Result<ExistingDir, std::io::Error> {
    // A foreign dir squatting in this hash slot is never ours to reclaim.
    if let Some(existing_name) = read_name(dir) {
        if existing_name != name {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "sandbox '{}': state-dir hash slot is occupied by sandbox '{}'",
                    name, existing_name
                ),
            ));
        }
    }

    match read_pid_file(dir) {
        Some((_, supervisor_pid, Some(recorded_starttime))) => {
            match crate::seccomp::state::read_pid_start_time(supervisor_pid) {
                Some(current) if current == recorded_starttime => {
                    Ok(ExistingDir::Live { supervisor_pid })
                }
                Some(_) => {
                    // Starttime mismatch: the recorded owner is gone and the
                    // pid was reused — provably stale.
                    Ok(ExistingDir::Stale)
                }
                None => {
                    // Current starttime unreadable (process gone or /proc
                    // restricted): staleness is not unambiguously proven, so
                    // refuse at create time; ps pruning reclaims dead dirs.
                    Ok(ExistingDir::Ambiguous)
                }
            }
        }
        Some((_, _, None)) => {
            // Legacy two-line pid file with no recorded starttime: staleness
            // cannot be proven (kill(pid,0) cannot detect pid reuse), so
            // refuse at create time; `sandlock ps` pruning handles such
            // leftovers.
            Ok(ExistingDir::Ambiguous)
        }
        // Missing or unparseable pid file: never reclaimable at create time
        // (the dir could belong to a live sandbox whose pid file was lost, no
        // matter how old the dir looks).
        None => Ok(ExistingDir::Ambiguous),
    }
}

/// Remove the per-sandbox runtime directory. Best-effort: failures are logged
/// but never propagated (called from Drop paths).
pub fn cleanup_runtime_dir(dir: &Path) {
    for file in [
        pid_path(dir),
        token_path(dir),
        name_path(dir),
        dir.join("mode"),
    ] {
        if file.exists() {
            let _ = std::fs::remove_file(&file);
        }
    }
    let sp = sock_path(dir);
    if sp.exists() {
        let _ = std::fs::remove_file(&sp);
    }
    if dir.exists() {
        let _ = std::fs::remove_dir(dir);
    }
}

// ============================================================
// Control loop — spawned as a dedicated tokio task
// ============================================================

/// Spawn the control-loop task.  Returns immediately after spawning; the task
/// runs until the listener is closed or the supervisor shuts down.
///
/// Takes ownership of `sandbox` (moved into the task) so the config snapshot
/// lives for the lifetime of the control loop.  The sandbox clone has
/// `init_fn = None` (FnOnce can't be cloned), so the value is `Send`.
pub(crate) fn spawn_control_loop(
    listener: UnixListener,
    ctx: Arc<SupervisorCtx>,
    sandbox: Sandbox,
    dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    // Use a Mutex to satisfy Sync (Sandbox is not Sync due to the type-level
    // presence of Box<dyn FnOnce>, even though our clone has init_fn=None).
    // The control loop only reads, so a Mutex is fine.
    let sandbox = Arc::new(tokio::sync::Mutex::new(sandbox));
    tokio::spawn(async move {
        control_loop(listener, ctx, sandbox, dir).await;
    })
}

/// Accept connections on the control socket and serve one request per
/// connection (single-client-at-a-time, no concurrency).
///
/// `dir` supplies the runtime-dir identity token used to authenticate the
/// sensitive verbs (read once: the token never changes while the sandbox
/// runs).
async fn control_loop(
    listener: UnixListener,
    ctx: Arc<SupervisorCtx>,
    sandbox: Arc<tokio::sync::Mutex<Sandbox>>,
    dir: PathBuf,
) {
    // Convert std listener to tokio.
    listener.set_nonblocking(true).ok();
    let listener = match tokio::net::UnixListener::from_std(listener) {
        Ok(l) => l,
        Err(_) => return,
    };
    let expected_token = read_token(&dir);

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };

        // Peer-credential boundary (SL-7): SO_PEERCRED must match the
        // supervisor's uid.  On mismatch the connection is closed immediately
        // — no response, no warning eprintln (the old behavior logged and
        // kept serving, which is exactly the cross-uid hole).  With the
        // owner-only dir this is a belt, not the primary boundary; it becomes
        // the primary one for future shared-directory transports (F2b.2).
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let raw = stream.as_raw_fd();
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            } == 0
            {
                let my_uid = unsafe { libc::getuid() };
                if cred.uid != my_uid {
                    // Close without serving: the peer has no business on this
                    // socket regardless of what it sends next.
                    drop(stream);
                    continue;
                }
            }
        }

        // Serve one request; close after.
        serve_one(stream, &ctx, &sandbox, expected_token.as_deref()).await;
    }
}

// ============================================================
// Request handling
// ============================================================

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct ControlRequest {
    pub v: u32,
    pub verb: String,
    /// Identity token from the runtime dir's `token` file.  Optional on the
    /// wire so old clients still parse; sensitive verbs require it.
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub args: serde_json::Value,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ControlResponse {
    pub v: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

async fn serve_one(
    stream: tokio::net::UnixStream,
    ctx: &Arc<SupervisorCtx>,
    sandbox: &Arc<tokio::sync::Mutex<Sandbox>>,
    expected_token: Option<&str>,
) {
    use tokio::io::AsyncReadExt;

    let mut stream = stream;
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let body_len = u32::from_be_bytes(len_buf) as usize;
    // Reject unreasonable sizes.
    if body_len > 65536 {
        return;
    }
    let mut body = vec![0u8; body_len];
    if stream.read_exact(&mut body).await.is_err() {
        return;
    }

    let req: ControlRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("parse error: {}", e)),
            };
            let _ = write_response(&mut stream, &resp).await;
            return;
        }
    };

    if req.v != 1 {
        let resp = ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!("unsupported protocol version: {}", req.v)),
        };
        let _ = write_response(&mut stream, &resp).await;
        return;
    }

    let verb = req.verb.as_str();

    // Verb-graded authentication: `config` and `ports` expose the sandbox's
    // full policy/network state, so they require the runtime dir's identity
    // token.  A missing or mismatched token is refused explicitly, then the
    // connection is closed (the function returns and the stream drops).
    if verb_requires_token(verb) {
        let authorized = match (req.token.as_deref(), expected_token) {
            (Some(given), Some(expected)) => token_eq(given, expected),
            _ => false,
        };
        if !authorized {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!(
                    "permission denied: verb '{}' requires a valid control token \
                     (missing or mismatched)",
                    verb
                )),
            };
            let _ = write_response(&mut stream, &resp).await;
            return;
        }
    }

    match verb {
        "config" => handle_config(&mut stream, ctx, sandbox).await,
        "ports" => handle_ports(&mut stream, ctx).await,
        _ => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("unknown verb: {}", req.verb)),
            };
            let _ = write_response(&mut stream, &resp).await;
        }
    }
}

/// Sensitive verbs need the identity token; future verbs choose their own
/// grade here (e.g. an exec-class verb would need a per-session key).
fn verb_requires_token(verb: &str) -> bool {
    matches!(verb, "config" | "ports")
}

async fn handle_config(
    stream: &mut tokio::net::UnixStream,
    ctx: &Arc<SupervisorCtx>,
    sandbox: &Arc<tokio::sync::Mutex<Sandbox>>,
) {
    // Collect dynamic policy_fn denies.
    let dynamic_denied: Vec<String> = {
        let pfn = ctx.policy_fn.lock().await;
        pfn.denied.denied_paths()
    };

    // Build the effective profile.
    let sb = sandbox.lock().await;
    let profile = crate::profile::sandbox_to_profile(&sb, &dynamic_denied);

    // Emit JSON.  Wrap in a "policy" key so the top-level response is
    // structured; the data field is the full ProfileInput.
    let data = match serde_json::to_value(&profile) {
        Ok(v) => v,
        Err(e) => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("serialize error: {}", e)),
            };
            let _ = write_response(stream, &resp).await;
            return;
        }
    };

    let resp = ControlResponse {
        v: 1,
        ok: true,
        data: Some(data),
        err: None,
    };
    let _ = write_response(stream, &resp).await;
}

async fn handle_ports(
    stream: &mut tokio::net::UnixStream,
    ctx: &Arc<SupervisorCtx>,
) {
    // Read the current virtual→real port map from the supervisor's
    // NetworkState.  This is the live mapping at request-time — more
    // accurate than a static registry that only refreshes on bind and
    // goes stale on SIGKILL.
    let ports: std::collections::HashMap<u16, u16> = {
        let ns = ctx.network.lock().await;
        ns.port_map.virtual_to_real.clone()
    };

    let data = match serde_json::to_value(&ports) {
        Ok(v) => v,
        Err(e) => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("serialize error: {}", e)),
            };
            let _ = write_response(stream, &resp).await;
            return;
        }
    };

    let resp = ControlResponse {
        v: 1,
        ok: true,
        data: Some(data),
        err: None,
    };
    let _ = write_response(stream, &resp).await;
}

/// Write a length-prefixed JSON response.  Rejects bodies over 64 KB
/// (mirrors the client-side cap in `send_control_request`).
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    resp: &ControlResponse,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    const MAX_RESPONSE_BYTES: usize = 65536;

    let body = serde_json::to_vec(resp).unwrap_or_else(|_| {
        serde_json::to_vec(&ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some("internal error".to_string()),
        })
        .unwrap_or_default()
    });

    // Cap oversized responses on the server side too.
    let body = if body.len() > MAX_RESPONSE_BYTES {
        serde_json::to_vec(&ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!(
                "response too large ({} bytes, max {})",
                body.len(),
                MAX_RESPONSE_BYTES
            )),
        })
        .unwrap_or_default()
    } else {
        body
    };

    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&body).await?;
    Ok(())
}

// ============================================================
// Pruning — called by sandlock ps to clean up stale dirs
// ============================================================

/// Walk the per-user control state root and return entries for every live
/// sandbox.  Dead sandboxes (recorded supervisor identity is gone) are
/// pruned.
///
/// Returns `(name, child_pid)` pairs for live sandboxes; `name` is read from
/// the dir's `name` metadata (the dir name itself is the name's FNV-1a hash).
/// The child PID is used by `sandlock ps` for `/proc/<pid>/stat` and
/// `/proc/<pid>/cmdline`.
///
/// Directories younger than 2 seconds are never pruned, even if the pid
/// file is missing or unparseable — this avoids a race with
/// `setup_runtime_dir`, which creates the dir before writing the pid file,
/// and (since F1.3) protects a live sandbox whose pid file was lost.
pub fn list_live_sandboxes() -> Result<Vec<(String, i32)>, std::io::Error> {
    let uid = unsafe { libc::getuid() };
    let root = runtime_dir_uid(uid);
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut live = Vec::new();
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(_) => return Ok(Vec::new()),
    };

    let now = std::time::SystemTime::now();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        // Only per-sandbox runtime dirs (`<16-hex>.d`) are candidates for
        // liveness/pruning.  Anything else under the root — including the
        // registered-channel registry if it ever lives here — is not a
        // sandbox state dir and must never be `remove_dir_all`'d as "stale
        // debris" (F2b.2 review I1: a live registry carries no pid file and
        // would otherwise be pruned after the 2 s recency window).
        if !is_sandbox_state_dir(&dir) {
            continue;
        }

        // Parse the pid file.  Format: child_pid\nsupervisor_pid\nstarttime\n
        let (child_pid, supervisor_pid, recorded_starttime) = match read_pid_file(&dir) {
            Some(triple) => triple,
            None => {
                // No pid file — could be a dir being set up concurrently, or
                // a live sandbox whose pid file was lost.  Don't prune if the
                // dir was modified less than 2 seconds ago.
                if !dir_is_recent(&dir, &now) {
                    let _ = std::fs::remove_dir_all(&dir);
                }
                continue;
            }
        };

        // The dir name is hashed, so the display name comes from metadata.
        // Metadata is written before the pid file, so a dir with a complete
        // pid file normally has it; a name-less dir is inconsistent and is
        // only pruned once it is no longer recent.
        let name = match read_name(&dir) {
            Some(n) => n,
            None => {
                if !dir_is_recent(&dir, &now) {
                    let _ = std::fs::remove_dir_all(&dir);
                }
                continue;
            }
        };

        // Liveness check: use supervisor PID since the supervisor owns
        // the control socket.  If the supervisor is dead, the sandbox is
        // effectively dead even if the child still runs.  When the pid file
        // recorded the supervisor's starttime (F1.3 format), compare
        // identities so a reused pid cannot masquerade as the owner; legacy
        // two-line pid files fall back to kill(pid, 0).
        let alive = match recorded_starttime {
            Some(recorded) => match crate::seccomp::state::read_pid_start_time(supervisor_pid) {
                Some(current) => current == recorded,
                // /proc unreadable: fall back to kill(pid, 0) rather than
                // pruning a live dir on a transient read failure.
                None => (unsafe { libc::kill(supervisor_pid, 0) }) == 0,
            },
            None => (unsafe { libc::kill(supervisor_pid, 0) }) == 0,
        };
        if alive {
            live.push((name, child_pid));
        } else {
            // Dead: prune.
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    // Sort by name for deterministic output.
    live.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(live)
}

/// True when `dir`'s file name is the per-sandbox `<fnv1a_hex(name)>.d`
/// shape (16 ASCII hex digits plus `.d`, either case — the runtime's own
/// `fnv1a_hex` emits lowercase, and the check accepts uppercase hex too so
/// a foreign directory is never misclassified on case alone).
/// `list_live_sandboxes` uses this to distinguish sandbox state dirs from
/// any other directory that may share the control root.
fn is_sandbox_state_dir(dir: &Path) -> bool {
    let name = match dir.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    let stem = match name.strip_suffix(".d") {
        Some(s) => s,
        None => return false,
    };
    stem.len() == 16 && stem.chars().all(|c| c.is_ascii_hexdigit())
}

/// Return true if `dir` was modified less than 2 seconds ago.
fn dir_is_recent(dir: &Path, now: &std::time::SystemTime) -> bool {
    if let Ok(meta) = std::fs::metadata(dir) {
        if let Ok(mtime) = meta.modified() {
            if let Ok(elapsed) = now.duration_since(mtime) {
                return elapsed.as_secs() < 2;
            }
        }
    }
    false
}

// ============================================================
// Client helpers — used by sandlock-cli to talk to the socket
// ============================================================

/// Send a request to a sandbox's control socket and return the JSON response
/// body (the `data` field, or error).
pub fn send_control_request(
    name: &str,
    verb: &str,
    args: serde_json::Value,
) -> Result<ControlResponse, String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let dir = sandbox_dir(name);

    // Check supervisor liveness before attempting connect.  If the
    // supervisor is dead the socket is stale and connect() would fail
    // with a confusing "No such file" — give a clearer message.  Uses the
    // recorded starttime when available (pid-reuse-safe); falls back to
    // kill(pid, 0) for legacy two-line pid files.
    if let Some((_, supervisor_pid, recorded_starttime)) = read_pid_file(&dir) {
        let alive = match recorded_starttime {
            Some(recorded) => match crate::seccomp::state::read_pid_start_time(supervisor_pid) {
                Some(current) => current == recorded,
                None => (unsafe { libc::kill(supervisor_pid, 0) }) == 0,
            },
            None => (unsafe { libc::kill(supervisor_pid, 0) }) == 0,
        };
        if !alive {
            return Err(format!(
                "sandbox '{}' supervisor (PID {}) is not running",
                name, supervisor_pid
            ));
        }
    }

    let sp = sock_path(&dir);
    let mut stream = UnixStream::connect(&sp)
        .map_err(|e| format!("connect to {:?}: {}", sp, e))?;

    // Set a 2-second timeout on reads so a wedged supervisor does not
    // block the CLI forever.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("set_write_timeout: {}", e))?;

    // Attach the runtime dir's identity token (read automatically, like the
    // pid file): the sensitive verbs reject requests without a matching
    // token.  `sandlock ps` never uses this function for its enumeration, so
    // listing stays token-free (minimal auth surface).
    let token = read_token(&dir);
    let req = serde_json::json!({
        "v": 1,
        "verb": verb,
        "args": args,
        "token": token,
    });
    let body = serde_json::to_vec(&req)
        .map_err(|e| format!("serialize request: {}", e))?;

    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(|e| format!("write len: {}", e))?;
    stream.write_all(&body).map_err(|e| format!("write body: {}", e))?;

    // Read response.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| format!("read len: {}", e))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 65536 {
        return Err("response too large".to_string());
    }
    let mut resp_body = vec![0u8; resp_len];
    stream.read_exact(&mut resp_body).map_err(|e| format!("read body: {}", e))?;

    serde_json::from_slice(&resp_body)
        .map_err(|e| format!("parse response: {}", e))
}

// ============================================================
// Dual-transport control channel (fork-plan-2026-09 F2b.2)
// ============================================================
//
// Route B serves one supervise process per sandbox generation.  The worker
// (host uid 65534) is no longer the same uid as the server, so the F1.3
// auth model ("peer uid == mine, owner-only dir") must generalise to two
// transports that share one verb/frame/auth session:
//
//  * fd handoff — a `socketpair()` created at generation-create time; one
//    end is handed to the supervise process (`--control-fd N`, SCM_RIGHTS /
//    exec-time descriptor).  There is no path, so the sandbox cannot
//    enumerate or connect to the channel: the fd IS the credential.  A
//    per-channel token is layered on top as a belt (a third party that
//    somehow obtains the descriptor still cannot authenticate).
//  * registered path — a pre-started slot binds a socket in a shared
//    1777+sticky hashed registry dir and the worker connects by path.
//    Authentication is `SO_PEERCRED` membership in an explicit allowlist
//    PLUS the token.  The single-machine/CLI same-uid mode is the
//    allowlist-only-self special case of this transport.
//
// Both transports use the same session as the historical `control.sock`
// (4-byte big-endian length + JSON, `{"v":1,"verb":...}` with a token) and
// the same 64 KiB body cap.  They deliberately do NOT use the sandlock-oci
// init framing: that frame (SLKF magic/kind/length) is bound to the init
// socketpair's `recvmsg`+SCM_RIGHTS semantics — an fd arrives attached to
// specific bytes and init routes by frame kind before parsing — while the
// control channel never carries fds and already versioned its JSON body.

/// Largest accepted request/response body on a control frame (4-byte length
/// prefix + JSON).  Mirrors the client/server caps used above.
pub const MAX_FRAME_BYTES: usize = 65536;

/// The shared registry root for registered-path control channels.
///
/// Route B slots run as uid X while the worker connects as a different uid
/// (default 65534), so this root must NOT be a child of the historical
/// owner-only per-user root: the worker would be EACCES-blocked at the 0700
/// parent before ever reaching the registry.  It is therefore a *sibling* of
/// the per-user root under a traversable parent (default `/tmp`; the
/// `SANDBOX_CTL_ROOT` test override maps to a sibling `<root>-registry`), and
/// is created 1777+sticky so every uid can publish its own hashed slot dir
/// while nobody can delete another uid's dir.  Per-sandbox runtime dirs stay
/// owner-only (0700/0600); only the socket a slot explicitly publishes is
/// world-connectable, and it is additionally protected by the `SO_PEERCRED`
/// allowlist + token.
pub fn channel_registry_root() -> PathBuf {
    if let Ok(root) = std::env::var(CTL_ROOT_ENV) {
        if !root.is_empty() {
            // Sibling of the per-process per-uid root so the two live under
            // the same isolated parent for tests, but the registry chain is
            // traversable by the worker uid.
            return PathBuf::from(format!("{}-registry", root.trim_end_matches('/')));
        }
    }
    PathBuf::from(format!("/tmp/sandlock-ctl-{}-registry", unsafe {
        libc::getuid()
    }))
}

/// Ensure the shared registry root exists with 1777+sticky permissions and
/// return its path.
pub fn ensure_channel_registry() -> std::io::Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let root = channel_registry_root();
        std::fs::create_dir_all(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o1777))?;
        Ok(root)
    }
    #[cfg(not(unix))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "control channels require unix sockets",
        ))
    }
}

/// Peer-credential gate for a registered-path connection: returns true when
/// the peer's `SO_PEERCRED` uid is in `allow`.  An empty `allow` is the
/// same-uid special case (peer uid == this process's uid), which is what the
/// historical per-sandbox owner-only channel enforced.  The caller closes
/// without serving when this returns false.
pub fn peer_uid_allowed(stream: &std::os::unix::net::UnixStream, allow: &[u32]) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    } != 0
    {
        return false;
    }
    if allow.is_empty() {
        cred.uid == (unsafe { libc::getuid() })
    } else {
        allow.contains(&cred.uid)
    }
}

/// Read one length-prefixed request body (blocking) from a control stream.
/// Returns `None` on EOF/error or when the declared body exceeds
/// [`MAX_FRAME_BYTES`].
pub fn read_request_body(stream: &mut std::os::unix::net::UnixStream) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let body_len = u32::from_be_bytes(len_buf) as usize;
    if body_len > MAX_FRAME_BYTES {
        return None;
    }
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).ok()?;
    Some(body)
}

/// Read one length-prefixed request frame (blocking), returning its JSON
/// body plus any SCM_RIGHTS fds that arrived attached to the request (the
/// F3.2 `exec` verb carries its three stdio fds this way).
///
/// The sender must write the 4-byte length + JSON body in **one** `sendmsg`
/// when fds are attached (fdpass semantics: ancillary data binds to the
/// bytes of that one sendmsg). The first read of a frame therefore captures
/// any fds; the body is completed with further reads (plain frames may still
/// be split arbitrarily by the stream). Returns `None` on EOF/error or when
/// the declared body exceeds [`MAX_FRAME_BYTES`].
pub fn read_request_frame(
    stream: &mut std::os::unix::net::UnixStream,
) -> Option<(Vec<u8>, Vec<std::os::fd::OwnedFd>)> {
    use std::os::unix::io::AsRawFd;

    let mut data: Vec<u8> = Vec::new();
    let mut fds: Vec<std::os::fd::OwnedFd> = Vec::new();
    loop {
        let (chunk, chunk_fds) = fdpass::recv_with_fds(stream.as_raw_fd(), 3).ok()?;
        if chunk.is_empty() {
            // EOF: at a clean boundary the caller distinguishes a requestless
            // close; mid-frame this is a truncated request.
            return None;
        }
        fds.extend(chunk_fds);
        data.extend_from_slice(&chunk);
        if data.len() < 4 {
            continue;
        }
        let body_len = u32::from_be_bytes(data[..4].try_into().expect("4-byte length")) as usize;
        if body_len > MAX_FRAME_BYTES {
            return None;
        }
        let total = 4 + body_len;
        if data.len() >= total {
            if data.len() > total {
                // More bytes than one request: frame misalignment (a
                // pipelined request) is not a supported wire shape.
                return None;
            }
            return Some((data[4..].to_vec(), fds));
        }
    }
}

/// Write one length-prefixed JSON response body (blocking), capping
/// oversized bodies the same way the async server does.
pub fn write_response_frame(
    stream: &mut std::os::unix::net::UnixStream,
    resp: &ControlResponse,
) -> std::io::Result<()> {
    use std::io::Write;
    let body = serde_json::to_vec(resp).unwrap_or_else(|_| {
        serde_json::to_vec(&ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some("internal error".to_string()),
        })
        .unwrap_or_default()
    });
    let body = if body.len() > MAX_FRAME_BYTES {
        serde_json::to_vec(&ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!(
                "response too large ({} bytes, max {})",
                body.len(),
                MAX_FRAME_BYTES
            )),
        })
        .unwrap_or_default()
    } else {
        body
    };
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&body)?;
    Ok(())
}

/// Outcome of a served request / serve loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeOutcome {
    /// Keep serving on this transport.
    Continue,
    /// A `shutdown` verb completed the generation: shut the transport down
    /// cleanly (exit 0 for a supervise generation).
    Shutdown,
    /// The transport ended without a clean shutdown: the peer closed /
    /// disappeared mid-generation, or a request was refused (parse error,
    /// bad protocol version, missing/mismatched token).  A supervise
    /// generation must exit non-zero so a crashed or attacking peer cannot
    /// masquerade as a clean generation end.
    PeerGone,
}

/// Handles one authenticated control verb and writes its response.
///
/// Implementations receive the validated request and return whether the
/// transport should keep serving.  The historical verbs (`config`, `ports`)
/// are served by the async in-process loop; the dual-transport serve path
/// serves the verbs the caller registered (probe `ping` in tests, supervise
/// `config`/`shutdown` in the binary).
pub trait ControlHandler {
    fn handle(
        &mut self,
        stream: &mut std::os::unix::net::UnixStream,
        req: &ControlRequest,
        fds: &[std::os::fd::OwnedFd],
    ) -> ServeOutcome;
}

/// Serve one accepted connection on a registered-path listener.
///
/// The registered path is per-connection (like the historical per-sandbox
/// `control.sock`): one request per connection, then the connection closes.
/// `token` is the channel token every verb must carry; `allow` is the peer
/// uid allowlist (empty = same-uid-only special case).  Returns `None` only
/// when `accept` itself failed.
///
/// Outcome semantics match the persistent transports: only a `shutdown`
/// verb returns [`ServeOutcome::Shutdown`]; an abnormal connection end
/// (peer uid outside the allowlist, EOF without a request, parse/version
/// refusal, or token refusal) returns [`ServeOutcome::PeerGone`] — a slot's
/// accept loop treats that as one refused connection and keeps serving the
/// next one (only a `shutdown` verb ends the generation).
pub fn serve_registered_once(
    listener: &std::os::unix::net::UnixListener,
    token: &str,
    allow: &[u32],
    handler: &mut dyn ControlHandler,
) -> Option<ServeOutcome> {
    let (stream, _) = listener.accept().ok()?;
    Some(serve_connection(stream, Some(token), allow, handler))
}

/// Serve the handed-off end of an fd-handoff channel (transport 1).
///
/// The fd transport is a *persistent* peer stream — unlike the registered
/// path's accept-per-connection model — so this serve loop reads frame after
/// frame from the single stream until a handler asks for shutdown or the
/// worker closes its end.  The fd itself is the credential (no
/// `SO_PEERCRED` check: the descriptor proves the peer is the launcher's
/// supervise child), so the only gate is the per-channel token — the belt
/// against a third party that somehow obtained the descriptor.
///
/// Outcomes are split so the caller can distinguish a clean generation end
/// ([`ServeOutcome::Shutdown`], from a `shutdown` verb) from an abnormal end
/// ([`ServeOutcome::PeerGone`]: EOF, parse/version refusal, or token
/// refusal) — supervise exits 0 only on Shutdown.
pub fn serve_fd_connection(
    stream: std::os::unix::net::UnixStream,
    expected_token: Option<&str>,
    handler: &mut dyn ControlHandler,
) -> ServeOutcome {
    let mut stream = stream;
    loop {
        let Some((body, fds)) = read_request_frame(&mut stream) else {
            return ServeOutcome::PeerGone;
        };
        let req: ControlRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                let resp = ControlResponse {
                    v: 1,
                    ok: false,
                    data: None,
                    err: Some(format!("parse error: {}", e)),
                };
                let _ = write_response_frame(&mut stream, &resp);
                return ServeOutcome::PeerGone;
            }
        };
        if req.v != 1 {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("unsupported protocol version: {}", req.v)),
            };
            let _ = write_response_frame(&mut stream, &resp);
            return ServeOutcome::PeerGone;
        }
        if let Some(expected) = expected_token {
            let authorized = match req.token.as_deref() {
                Some(given) => token_eq(given, expected),
                None => false,
            };
            if !authorized {
                let resp = ControlResponse {
                    v: 1,
                    ok: false,
                    data: None,
                    err: Some(format!(
                        "permission denied: verb '{}' requires a valid channel token \
                         (missing or mismatched)",
                        req.verb
                    )),
                };
                let _ = write_response_frame(&mut stream, &resp);
                return ServeOutcome::PeerGone;
            }
        }
        match handler.handle(&mut stream, &req, &fds) {
            ServeOutcome::Continue => {}
            ServeOutcome::Shutdown => return ServeOutcome::Shutdown,
            // Handlers describe verbs (Continue/Shutdown); PeerGone is
            // transport-level and only returned by the frame/auth paths
            // above — defensively propagate it if a handler ever returns it.
            ServeOutcome::PeerGone => return ServeOutcome::PeerGone,
        }
    }
}

/// Serve one request/response cycle on a connected stream (blocking).
///
/// Authentication order: (1) peer uid allowlist (registered path; an empty
/// allowlist is the same-uid special case), (2) channel token on every verb.
/// A peer outside the allowlist is closed without a response and without a
/// log (the F1.3 posture); a token mismatch is refused explicitly and the
/// connection is closed after the refusal.  The fd-handoff transport serves
/// its single persistent stream in [`serve_fd_connection`], where the
/// descriptor itself is the credential and the only gate is the token.
///
/// Abnormal ends (peer uid mismatch, EOF, parse/version/token refusal) all
/// return [`ServeOutcome::PeerGone`] — never `Shutdown`, so a caller cannot
/// mistake a refused or vanished peer for a clean generation end.  In the
/// registered path's one-request-per-connection model that `PeerGone` closes
/// exactly this connection; the slot's accept loop decides whether to keep
/// accepting.
pub fn serve_connection(
    mut stream: std::os::unix::net::UnixStream,
    expected_token: Option<&str>,
    allowed_peer_uids: &[u32],
    handler: &mut dyn ControlHandler,
) -> ServeOutcome {
    if allowed_peer_uids.is_empty() {
        if !peer_uid_allowed(&stream, &[]) {
            return ServeOutcome::PeerGone;
        }
    } else if !peer_uid_allowed(&stream, allowed_peer_uids) {
        return ServeOutcome::PeerGone;
    }

    let Some((body, fds)) = read_request_frame(&mut stream) else {
        return ServeOutcome::PeerGone;
    };

    let req: ControlRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("parse error: {}", e)),
            };
            let _ = write_response_frame(&mut stream, &resp);
            return ServeOutcome::PeerGone;
        }
    };

    if req.v != 1 {
        let resp = ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!("unsupported protocol version: {}", req.v)),
        };
        let _ = write_response_frame(&mut stream, &resp);
        return ServeOutcome::PeerGone;
    }

    // Channel token: on the dual transports every verb carries the channel
    // token (the fd handoff layers it over the fd credential; the registered
    // path layers it over the peer allowlist).
    if let Some(expected) = expected_token {
        let authorized = match req.token.as_deref() {
            Some(given) => token_eq(given, expected),
            None => false,
        };
        if !authorized {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!(
                    "permission denied: verb '{}' requires a valid channel token \
                     (missing or mismatched)",
                    req.verb
                )),
            };
            let _ = write_response_frame(&mut stream, &resp);
            return ServeOutcome::PeerGone;
        }
    }

    handler.handle(&mut stream, &req, &fds)
}

/// Worker/client side of a control channel: send one verb with the channel
/// token attached and return the parsed response.  Sets 2-second read/write
/// timeouts so a wedged server cannot hang the caller.
pub fn channel_request(
    stream: &mut std::os::unix::net::UnixStream,
    token: &str,
    verb: &str,
    args: serde_json::Value,
) -> Result<ControlResponse, String> {
    channel_request_with_fds(stream, token, verb, args, &[])
}

/// Worker/client side of a control channel with SCM_RIGHTS fd delivery (the
/// F3.2 `exec` verb): send one verb with the channel token attached and up to
/// three stdio fds, and return the parsed response. Header + body + fds are
/// written in **one** `sendmsg` so the fds bind to the request frame
/// (fdpass semantics); plain verbs call this with an empty fd slice.
/// Sets 2-second read/write timeouts so a wedged server cannot hang the
/// caller.
pub fn channel_request_with_fds(
    stream: &mut std::os::unix::net::UnixStream,
    token: &str,
    verb: &str,
    args: serde_json::Value,
    fds: &[std::os::fd::RawFd],
) -> Result<ControlResponse, String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("set_write_timeout: {}", e))?;

    let req = ControlRequest {
        v: 1,
        verb: verb.to_string(),
        token: Some(token.to_string()),
        args,
    };
    let body = serde_json::to_vec(&req).map_err(|e| format!("serialize request: {}", e))?;
    let len = (body.len() as u32).to_be_bytes();
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len);
    frame.extend_from_slice(&body);
    fdpass::send_with_fds(stream, &frame, fds)
        .map_err(|e| format!("write request: {}", e))?;

    let Some(resp_body) = read_request_body(stream) else {
        return Err("server closed without a response".to_string());
    };
    serde_json::from_slice(&resp_body).map_err(|e| format!("parse response: {}", e))
}

/// Worker-side client for a registered slot (transport 2): connect by path,
/// attach the channel token, and issue one verb — optionally handing over
/// descriptors (`exec` needs exactly three stdio ends). Response bytes come
/// back as-is so the caller keeps the existing JSON contract. One request per
/// connection, matching the registered transport's accept-per-connection
/// model; `fds` ride the same `sendmsg` as the request frame (F3.2).
pub fn registered_request(
    sock_path: &std::path::Path,
    token: &str,
    verb: &str,
    args: serde_json::Value,
    fds: &[std::os::fd::RawFd],
) -> Result<ControlResponse, String> {
    let mut stream = std::os::unix::net::UnixStream::connect(sock_path)
        .map_err(|e| format!("connect {:?}: {}", sock_path, e))?;
    channel_request_with_fds(&mut stream, token, verb, args, fds)
}

/// Transport 1 — fd handoff.  Created with one `socketpair()` at
/// generation-create time; the launcher hands [`FdHandoffChannel::server`]
/// to the supervise process (`--control-fd N`) and keeps
/// [`FdHandoffChannel::worker`].  No path ever exists; the fd is the
/// credential and the token is layered on top.
pub struct FdHandoffChannel {
    /// Per-channel token both sides authenticate with.
    pub token: String,
    /// Worker end (the launcher keeps this; used with
    /// [`channel_request`]).
    pub worker: std::os::unix::net::UnixStream,
    /// Server end handed to supervise.
    pub server: std::os::unix::net::UnixStream,
}

impl FdHandoffChannel {
    /// Create a fresh fd-handoff channel.
    pub fn new() -> std::io::Result<FdHandoffChannel> {
        let (worker, server) = std::os::unix::net::UnixStream::pair()?;
        let token = generate_token()?;
        Ok(FdHandoffChannel {
            token,
            worker,
            server,
        })
    }

}

/// Transport 2 — registered path + token.  A slot binds a socket in the
/// shared registry; the worker connects by the hashed path and authenticates
/// with `SO_PEERCRED` allowlist membership + the channel token.  The
/// single-machine/CLI same-uid mode passes an empty allowlist (= same uid).
pub struct RegisteredPathChannel {
    name: String,
    token: String,
    allowed_peer_uids: Vec<u32>,
    listener: Arc<std::os::unix::net::UnixListener>,
    sock_path: PathBuf,
    dir: PathBuf,
}

impl RegisteredPathChannel {
    /// Bind a registered channel for `name` under the shared registry.
    ///
    /// `allowed_peer_uids` is the worker allowlist (route B default: the
    /// worker uid, conventionally 65534).  Empty = same-uid-only (the
    /// single-machine special case), which the server enforces via
    /// `SO_PEERCRED == getuid()`.
    pub fn bind(name: &str, allowed_peer_uids: Vec<u32>) -> std::io::Result<Self> {
        let token = generate_token()?;
        Self::bind_with_token(name, allowed_peer_uids, &token)
    }

    /// Bind a registered channel for `name` with a caller-provided token.
    ///
    /// The deployer-agreed variant of [`RegisteredPathChannel::bind`]: a
    /// route-B slot started out-of-band (transport 2) must use the same
    /// token the worker side was provisioned with — a token generated inside
    /// the slot could never be learned by the worker.  `token` must be
    /// non-empty (an empty token would silently disable the channel's second
    /// auth layer whenever a caller passes `None` as the expected token).
    pub fn bind_with_token(
        name: &str,
        allowed_peer_uids: Vec<u32>,
        token: &str,
    ) -> std::io::Result<Self> {
        if token.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "registered channel token must be non-empty",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let root = ensure_channel_registry()?;
            let dir = root.join(format!("{}.d", fnv1a_hex(name)));
            // Inside the shared registry, the hashed slot dir is
            // world-traversable and sticky so a slot running as any uid can
            // publish it and only the owner can remove it.  Cleanup happens
            // on the slot's shutdown (Drop removes socket + dir).
            std::fs::create_dir_all(&dir)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777))?;
            let sock_path = dir.join("control.sock");
            let listener = Arc::new(std::os::unix::net::UnixListener::bind(&sock_path)?);
            // The worker uid must be able to connect() the socket inode even
            // though it does not own the slot dir: make the socket
            // world-connectable (auth is the allowlist + token, not DAC).
            std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o666))?;
            Ok(RegisteredPathChannel {
                name: name.to_string(),
                token: token.to_string(),
                allowed_peer_uids,
                listener,
                sock_path,
                dir,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (name, allowed_peer_uids, token);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "control channels require unix sockets",
            ))
        }
    }

    /// Path a worker connects to (hashed; never contains `name`).
    pub fn socket_path(&self) -> &Path {
        &self.sock_path
    }

    /// Channel token the worker must present on every verb.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Registration name (raw name kept out of the filesystem path).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Peer uid allowlist (empty = same-uid-only special case).
    pub fn allowed_peer_uids(&self) -> &[u32] {
        &self.allowed_peer_uids
    }

    /// Worker-side connect + one request (attaches the channel token).
    pub fn connect_and_request(
        &self,
        verb: &str,
        args: serde_json::Value,
    ) -> Result<ControlResponse, String> {
        let mut stream = std::os::unix::net::UnixStream::connect(&self.sock_path)
            .map_err(|e| format!("connect to {:?}: {}", self.sock_path, e))?;
        channel_request(&mut stream, &self.token, verb, args)
    }

    /// Share the accept side with a serving thread while the creator keeps
    /// the channel metadata (token/path) for the worker side.
    pub fn listener(&self) -> Arc<std::os::unix::net::UnixListener> {
        Arc::clone(&self.listener)
    }

    /// Remove the socket and the hashed slot dir (best-effort).
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.sock_path);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

impl Drop for RegisteredPathChannel {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_dir_paths() {
        let dir = sandbox_dir("test-sandbox");
        let s = dir.to_string_lossy();
        // The raw name must never be a path component (SL-7 hashed dirs).
        assert!(
            !s.contains("test-sandbox"),
            "hashed dir must not contain the raw name: {}",
            s
        );
        // <state root>/<16-hex>.d
        let root = runtime_dir_uid(unsafe { libc::getuid() });
        assert_eq!(dir.parent(), Some(root.as_path()));
        let file_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        assert!(file_name.ends_with(".d"), "dir should end in .d: {}", file_name);
        let stem = file_name.trim_end_matches(".d");
        assert_eq!(stem.len(), 16, "hash stem should be 16 hex chars: {}", stem);
        assert!(
            stem.chars().all(|c| c.is_ascii_hexdigit()),
            "hash stem should be hex: {}",
            stem
        );

        let pid_file = pid_path(&dir);
        assert_eq!(pid_file.file_name().unwrap(), "pid");

        let token_file = token_path(&dir);
        assert_eq!(token_file.file_name().unwrap(), "token");

        let name_file = name_path(&dir);
        assert_eq!(name_file.file_name().unwrap(), "name");

        let sock = sock_path(&dir);
        assert_eq!(sock.file_name().unwrap(), "control.sock");
    }

    #[test]
    fn test_runtime_dir_mode_file_roundtrip() {
        // Unique name: sandbox names are uid-wide, never reuse a fixed one.
        let name = format!("test-mode-{}", std::process::id());
        let pid = std::process::id() as i32;

        let dir = setup_runtime_dir_no_socket(&name, pid, pid, Some("learn")).unwrap();
        assert_eq!(sandbox_mode(&name).as_deref(), Some("learn"));
        // Identity files are written by setup and removed by cleanup.
        let token_file = token_path(&dir);
        assert!(token_file.exists(), "token file should exist after setup");
        let token = std::fs::read_to_string(&token_file).unwrap();
        assert!(!token.trim().is_empty(), "token must be non-empty");
        assert_eq!(token.trim().len(), 64, "token should be 64 hex chars");
        assert_eq!(
            read_name(&dir).as_deref(),
            Some(name.as_str()),
            "name metadata should round-trip"
        );
        cleanup_runtime_dir(&dir);
        assert!(!dir.exists(), "cleanup should remove the runtime dir");

        let dir = setup_runtime_dir_no_socket(&name, pid, pid, None).unwrap();
        assert_eq!(sandbox_mode(&name), None);
        cleanup_runtime_dir(&dir);
    }

    #[test]
    fn test_list_live_sandboxes_empty() {
        // When no sandboxes are running, returns empty.
        let result = list_live_sandboxes().unwrap();
        // May or may not be empty depending on test environment; just ensure
        // it doesn't error.
        assert!(result.iter().all(|(_, pid)| *pid > 0));
    }
}
