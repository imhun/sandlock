//! Supervisor process — drives the OCI container lifecycle via sandlock-core.
//!
//! `run_supervisor` converts the OCI policy into a `sandlock_core::Sandbox` and
//! drives the two-phase OCI lifecycle:
//!
//! 1. `sandbox.create_interactive(cmd)` — forks the child, installs the full
//!    sandlock policy (Landlock + seccomp-notify + resource limits + network
//!    ACL), and parks the child before execve.
//! 2. The supervisor writes the child PID to the caller's pipe and then waits
//!    on its Unix socket for a `Start` command.
//! 3. On `Start`: `sandbox.start()` releases the parked child to execve.
//! 4. `sandbox.wait()` collects the exit status and persists it to state.json.
//!
//! Communication with the CLI is newline-delimited JSON over a Unix socket in
//! the sandbox's state directory.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::oneshot;

use crate::init::proto::{self, FrameKind};
use crate::init::{Req, Resp, CONTROL_FD};

use crate::policy::OciPolicy;
use crate::state::SandboxState;

/// Demultiplexer for the single control channel to `sandlock-init`.
///
/// All replies (`Started`, `Exited`, `Err`) arrive on one socket and must be
/// routed: a `Started`/`Err` is the immediate reply to the request just sent
/// (requests are serialized by holding the writer lock across the await, so the
/// correlation is unambiguous), while an `Exited{pid}` is routed to the waiter
/// registered for that pid (an exec, or the main workload). An `Exited` that
/// arrives before its waiter registers is buffered in `early_exits`.
///
/// Two guards keep `Exited` routing bounded against forged/compromised frames:
///
/// - `announced` holds exactly the pids init has announced via `Started` (the
///   only children whose exit is legitimately expected). An `Exited` for any
///   other pid is dropped and counted in `unknown_exits` — never buffered and
///   never allowed to resolve a waiter.
/// - `early_exits` is capped at `early_exit_cap` (default
///   [`InitLink::DEFAULT_EARLY_EXIT_CAP`] = 1024, configurable at
///   construction). An insert beyond the cap drops the frame and counts it in
///   `overflow_drops`, so a hostile peer cannot grow memory without limit.
///
/// A request that exceeds its per-request deadline marks the link `Dead`: the
/// in-flight reply sender is dropped (`pending` cleared, so a late
/// `Started`/`Err` is discarded), and every later `request` fails fast without
/// sending. `Dead` does **not** touch exit routing (`exit_waiters`,
/// `announced`, `early_exits`): an announced child's exit still resolves its
/// waiter through the real path, and those registries are only cleared by the
/// channel-close teardown at the end of `reader_task`.
struct LinkState {
    /// Sender for the reply to the in-flight request (a `Started` or `Err`).
    pending: Option<oneshot::Sender<Resp>>,
    /// Per-pid exit waiters (main workload + attached execs).
    exit_waiters: HashMap<i32, oneshot::Sender<Resp>>,
    /// Exits that arrived before a waiter registered.
    early_exits: HashMap<i32, Resp>,
    /// Pids announced via `Started` whose exit has not yet been delivered
    /// (buffered, waiter-resolved, overflow-dropped, or detached-forgotten).
    announced: HashSet<i32>,
    /// Exited frames dropped because the pid was never announced.
    unknown_exits: u64,
    /// Exited frames dropped because `early_exits` was full.
    overflow_drops: u64,
    /// Maximum `early_exits` size (default 1024; configurable at construction).
    early_exit_cap: usize,
    /// True once a request exceeded its deadline: requests fail fast and the
    /// in-flight reply was discarded (see the struct docs for Dead semantics).
    dead: bool,
    /// Per-request reply deadline (default 5 s; configurable at construction).
    request_timeout: Duration,
}

/// Snapshot of the link's routing state, for tests and future metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinkStats {
    /// Live early-exit buffer entries (arrived before waiter registration).
    early_exits: usize,
    /// Announced pids whose exit is still expected.
    announced: usize,
    /// Dropped because the pid was never announced.
    unknown_exits: u64,
    /// Dropped because the `early_exits` buffer was full.
    overflow_drops: u64,
    /// Configured `early_exits` cap.
    early_exit_cap: usize,
    /// Whether the link is Dead (an earlier request exceeded its deadline).
    dead: bool,
}

struct InitLink {
    /// Write half (a dup of the control socket) used for blocking `sendmsg`.
    writer: tokio::sync::Mutex<std::os::unix::net::UnixStream>,
    state: StdMutex<LinkState>,
}

impl InitLink {
    /// Default cap on buffered early-exit frames (see [`LinkState`]).
    const DEFAULT_EARLY_EXIT_CAP: usize = 1024;
    /// Default per-request reply deadline (see [`LinkState`]).
    const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

    /// Build the link and spawn the background reader that routes replies.
    fn new(
        writer: std::os::unix::net::UnixStream,
        reader: tokio::net::UnixStream,
    ) -> Arc<Self> {
        Self::with_early_exit_cap(writer, reader, Self::DEFAULT_EARLY_EXIT_CAP)
    }

    /// Like [`InitLink::new`], with a configurable `early_exits` cap. The cap
    /// bounds the number of exit frames buffered for announced-but-unwaited
    /// children; frames beyond it are dropped and counted (never unbounded).
    /// The request deadline stays at the default.
    fn with_early_exit_cap(
        writer: std::os::unix::net::UnixStream,
        reader: tokio::net::UnixStream,
        early_exit_cap: usize,
    ) -> Arc<Self> {
        Self::with_options(writer, reader, early_exit_cap, Self::DEFAULT_REQUEST_TIMEOUT)
    }

    /// Like [`InitLink::new`], with a configurable per-request reply deadline.
    /// A request whose `Started`/`Err` reply does not arrive within the
    /// deadline returns a timeout error and marks the link Dead (see
    /// [`LinkState`]). The `early_exits` cap stays at the default.
    fn with_request_timeout(
        writer: std::os::unix::net::UnixStream,
        reader: tokio::net::UnixStream,
        request_timeout: Duration,
    ) -> Arc<Self> {
        Self::with_options(writer, reader, Self::DEFAULT_EARLY_EXIT_CAP, request_timeout)
    }

    /// Full constructor: configurable `early_exits` cap and request deadline.
    fn with_options(
        writer: std::os::unix::net::UnixStream,
        reader: tokio::net::UnixStream,
        early_exit_cap: usize,
        request_timeout: Duration,
    ) -> Arc<Self> {
        let link = Arc::new(InitLink {
            writer: tokio::sync::Mutex::new(writer),
            state: StdMutex::new(LinkState {
                pending: None,
                exit_waiters: HashMap::new(),
                early_exits: HashMap::new(),
                announced: HashSet::new(),
                unknown_exits: 0,
                overflow_drops: 0,
                early_exit_cap,
                dead: false,
                request_timeout,
            }),
        });
        let weak = link.clone();
        tokio::spawn(async move { reader_task(weak, reader).await });
        link
    }

    /// Send a request (optionally with SCM_RIGHTS `fds`) and return its
    /// immediate `Started`/`Err` reply. The writer lock is held across the
    /// await so requests are serialized and each reply pairs with its request.
    ///
    /// A request whose reply does not arrive within the configured deadline
    /// (default 5 s) fails with a `TimedOut` error and marks the link Dead:
    /// the in-flight reply sender is dropped so a late reply is discarded, and
    /// every subsequent request fails fast without sending. Exit waiting
    /// (`register_exit`/`forget_detached`) is unaffected by Dead — only the
    /// channel-close path clears waiters.
    async fn request(&self, req: &Req, fds: &[RawFd]) -> std::io::Result<Resp> {
        if self.is_dead() {
            return Err(dead_link_error());
        }
        let payload = serde_json::to_vec(req)?;
        let bytes = proto::encode_frame(FrameKind::Req, &payload, fds.len() as u8)?;
        let writer = self.writer.lock().await;
        // Re-check under the writer lock: the only way the link turns Dead is
        // a timed-out request, which marks it while still holding this lock,
        // so a request that passed the first check must not send afterwards.
        if self.is_dead() {
            return Err(dead_link_error());
        }
        let (tx, rx) = oneshot::channel();
        let request_timeout = {
            let mut st = self.state.lock().unwrap();
            st.pending = Some(tx);
            st.request_timeout
        };
        crate::fdpass::send_with_fds(&writer, &bytes, fds)?;
        // Hold the writer lock until the reply lands so a concurrent request
        // cannot overwrite `pending` before this one is answered.
        let reply = tokio::time::timeout(request_timeout, rx).await;
        if reply.is_err() {
            // Deadline exceeded. Still holding the writer lock, so no other
            // request can interleave: drop the reply sender (a late reply is
            // then discarded by `reader_task`) and mark the link Dead so
            // subsequent requests fail fast without sending.
            let mut st = self.state.lock().unwrap();
            st.pending.take();
            st.dead = true;
        }
        drop(writer);
        match reply {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "sandlock-init closed control channel",
            )),
            Err(_) => Err(request_timeout_error(request_timeout)),
        }
    }

    /// Whether the link is Dead (an earlier request timed out).
    fn is_dead(&self) -> bool {
        self.state.lock().unwrap().dead
    }

    /// Register interest in the exit of `pid`. If the exit was already reported
    /// (buffered), the receiver resolves immediately.
    fn register_exit(&self, pid: i32) -> oneshot::Receiver<Resp> {
        let (tx, rx) = oneshot::channel();
        let mut st = self.state.lock().unwrap();
        if let Some(resp) = st.early_exits.remove(&pid) {
            st.announced.remove(&pid);
            let _ = tx.send(resp);
        } else {
            // Belt: waiters are only ever created for pids init announced via
            // `Started` (routed before `request` returns), so a waiter pid is
            // announced by construction — keep the registry consistent.
            st.announced.insert(pid);
            st.exit_waiters.insert(pid, tx);
        }
        rx
    }

    /// Drop exit interest in a pid that will never be waited on (a detached
    /// exec, which init does not report an `Exited` for). Any stale buffered
    /// frame is discarded with it; a later frame for the pid is treated as
    /// expected-silent (dropped + counted), never buffered.
    fn forget_detached(&self, pid: i32) {
        let mut st = self.state.lock().unwrap();
        st.announced.remove(&pid);
        st.early_exits.remove(&pid);
    }

    /// Snapshot of routing sizes and drop counters (tests / future metrics).
    fn stats(&self) -> LinkStats {
        let st = self.state.lock().unwrap();
        LinkStats {
            early_exits: st.early_exits.len(),
            announced: st.announced.len(),
            unknown_exits: st.unknown_exits,
            overflow_drops: st.overflow_drops,
            early_exit_cap: st.early_exit_cap,
            dead: st.dead,
        }
    }

    /// Send a request frame without expecting a reply (fire-and-forget). Used
    /// for verbs init acts on without answering: `Shutdown` (init exits) and
    /// instance-level `Signal` (init traverses its child-group set). Holding
    /// the writer lock keeps these serialized against request/reply traffic.
    async fn send(&self, req: &Req) {
        if let Ok(payload) = serde_json::to_vec(req) {
            if let Ok(bytes) = proto::encode_frame(FrameKind::Req, &payload, 0) {
                let writer = self.writer.lock().await;
                let _ = crate::fdpass::send_with_fds(&writer, &bytes, &[]);
            }
        }
    }

    /// Send `Shutdown` to init. No reply is expected (init exits).
    async fn shutdown(&self) {
        self.send(&Req::Shutdown).await;
    }
}

/// Error returned when a request's reply did not arrive within its deadline
/// and the link was marked Dead (F1.8). F5/M3 will fold the Dead/timeout
/// surface into the unified S5 error code; until then the io error carries
/// the deadline semantics explicitly.
fn request_timeout_error(request_timeout: Duration) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!(
            "request to sandlock-init timed out after {:?} (no reply); \
             control link marked Dead: late replies are discarded and further requests fail fast",
            request_timeout
        ),
    )
}

/// Error returned by a request sent after the link was marked Dead: fail fast,
/// without sending (F1.8). F5/M3 unification note: same as
/// [`request_timeout_error`].
fn dead_link_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "init control link is Dead (an earlier request timed out); request not sent",
    )
}

/// Read one framed `Resp` payload from init. `Ok(None)` is a clean EOF at a
/// frame boundary. Frame-level corruption — bad magic/version/type, an
/// oversize declaration, or EOF in the middle of a frame — is an
/// `InvalidData` error: byte alignment is unrecoverable, so `reader_task`
/// treats it like a channel close (a well-framed but unparseable payload is
/// *not* an error; the caller skips it because its boundary is known).
async fn read_resp_frame(
    reader: &mut tokio::net::UnixStream,
) -> std::io::Result<Option<Vec<u8>>> {
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; proto::FRAME_HEADER_LEN];
    let mut got = 0usize;
    while got < header.len() {
        let n = reader.read(&mut header[got..]).await?;
        if n == 0 {
            if got == 0 {
                return Ok(None); // clean EOF at a frame boundary
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "truncated control frame header from sandlock-init",
            ));
        }
        got += n;
    }
    let header = proto::decode_header(&header).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad control frame from sandlock-init: {e}"),
        )
    })?;
    if header.kind != FrameKind::Resp {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sandlock-init sent a req-type control frame to the daemon",
        ));
    }
    let len = header.payload_len;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "truncated control frame payload from sandlock-init",
        )
    })?;
    Ok(Some(payload))
}

/// Background reader: decode framed `Resp` frames from init and route each.
/// init never sends fds to the daemon, so a plain frame reader is sufficient.
async fn reader_task(link: Arc<InitLink>, mut reader: tokio::net::UnixStream) {
    loop {
        let payload = match read_resp_frame(&mut reader).await {
            Ok(Some(p)) => p,
            // Clean EOF at a frame boundary or a framing violation: both end
            // the loop, and the teardown below drops pending senders and
            // waiters. A framing violation cannot be resynced byte-by-byte,
            // so continuing would only misroute later frames.
            Ok(None) | Err(_) => break,
        };
        let resp: Resp = match serde_json::from_slice(&payload) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut st = link.state.lock().unwrap();
        match resp {
            Resp::Started { pid } => {
                // A `Started` is only legitimate as the reply to the in-flight
                // request. A stray one (no pending request) is forged: ignore
                // it entirely rather than announcing a pid that never existed.
                if let Some(tx) = st.pending.take() {
                    st.announced.insert(pid);
                    if tx.send(Resp::Started { pid }).is_err() {
                        // The requesting task is gone (deadline exceeded —
                        // link Dead — or the task was canceled), so its
                        // receiver was dropped before this reply was routed.
                        // A Started that was never delivered must leave no
                        // registry entry: remove the announcement so the late
                        // reply cannot pollute the announced set.
                        st.announced.remove(&pid);
                    }
                }
            }
            Resp::Err { .. } => {
                if let Some(tx) = st.pending.take() {
                    let _ = tx.send(resp);
                }
            }
            Resp::Exited { pid, .. } => {
                // Waiter present: the supervisor itself registered interest in
                // this pid after its `Started`, so this is the authoritative
                // resolution — only this path may decide an exec's exit.
                if let Some(tx) = st.exit_waiters.remove(&pid) {
                    st.announced.remove(&pid);
                    let _ = tx.send(resp);
                } else if st.announced.contains(&pid) {
                    // Early-exit race: announced but the waiter has not
                    // registered yet. Buffer it, bounded by the cap. Either
                    // outcome consumes the pid's expectation: a buffered frame
                    // will be resolved by `register_exit`, a dropped one can
                    // never be delivered.
                    st.announced.remove(&pid);
                    if st.early_exits.len() < st.early_exit_cap {
                        st.early_exits.insert(pid, resp);
                    } else {
                        st.overflow_drops += 1;
                    }
                } else {
                    // Never announced (and no waiter): forged/unknown frame.
                    st.unknown_exits += 1;
                }
            }
        }
    }
    // Channel closed: drop senders so any pending request/waiter unblocks with a
    // RecvError rather than hanging forever.
    let mut st = link.state.lock().unwrap();
    st.pending.take();
    st.exit_waiters.clear();
    st.announced.clear();
    st.early_exits.clear();
}

/// Map an init `Resp::Exited` (if any) to the on-disk `ExitInfo`.
fn exit_info_from_resp(resp: Option<Resp>) -> Option<crate::state::ExitInfo> {
    match resp {
        Some(Resp::Exited { code, signal, .. }) => {
            Some(crate::state::ExitInfo { code, signal })
        }
        _ => None,
    }
}

/// Commands the CLI sends to the Supervisor over the Unix socket.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum SupervisorCmd {
    /// Release the parked child to execve.
    Start,
    /// Query the child PID.
    Ping,
    /// Terminate the supervisor without starting the child (used by `delete`
    /// when the sandbox was never started).  The sandbox `Drop` kills the
    /// parked child.
    Shutdown,
    /// Capture a checkpoint of the running child into `dir`.
    Checkpoint { dir: String },
    /// Run an additional process inside the running container. Carries 3
    /// ancillary fds (stdin, stdout, stderr) over SCM_RIGHTS alongside this
    /// JSON. `detach` means the CLI will not wait for an `Exit` reply.
    Exec {
        args: Vec<String>,
        env: Vec<(String, String)>,
        cwd: Option<String>,
        detach: bool,
    },
    /// Deliver `signum` to the whole running container — every process group
    /// `sandlock-init` registered for its children, not init's own group.
    /// Used by `kill --all` and `delete --force`. The verb carries **no pid**:
    /// there is no per-pid forwarding channel (SECE-6 / F1.7), so a caller can
    /// only ever request instance-level delivery.
    Signal { signum: i32 },
}

/// Responses from the Supervisor.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum SupervisorReply {
    Ok,
    Pid { pid: i32 },
    Err { msg: String },
    /// Final status of an exec'd process (attached exec only).
    Exit { code: Option<i32>, signal: Option<i32> },
}

/// Deterministic 64-bit FNV-1a hash of `id` as 16 lowercase hex chars.
///
/// Keeps the supervisor socket path short enough for `sockaddr_un.sun_path`
/// (108 bytes incl. NUL) even when the runtime root and container id are long
/// (containerd passes a 64-char id under /run/containerd/runc/<ns>). Only needs
/// to be stable within a single binary: bind and connect run the same build.
fn fnv1a_hex(id: &str) -> String {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for b in id.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    format!("{:016x}", h)
}

/// Returns the path to the supervisor socket for the given sandbox ID.
///
/// Lives directly under the state dir as `<fnv16(id)>.sock` (not under the
/// per-id state subdir) so the path stays well under the `sun_path` limit.
pub fn socket_path(id: &str) -> PathBuf {
    PathBuf::from(crate::state::state_dir()).join(format!("{}.sock", fnv1a_hex(id)))
}

/// Send a command to a running supervisor and return its reply (blocking).
///
/// The protocol is newline-delimited JSON over a Unix socket.
pub fn send_command(id: &str, cmd: SupervisorCmd) -> Result<SupervisorReply> {
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixStream;

    let path = socket_path(id);
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("connect to supervisor socket {:?}", path))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    // The protocol is newline-delimited JSON: send the request and its
    // delimiter in ONE write. Two writes are legal on a stream socket but let
    // the receiver act (and close) between them, which turns the tail write
    // into an `EPIPE` — and `kill --all` treats any send error as "the daemon
    // never got it" and re-delivers the signal by hand.
    let mut msg = serde_json::to_string(&cmd)?;
    msg.push('\n');
    stream.write_all(msg.as_bytes())?;
    stream.flush()?;

    let mut reader = std::io::BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    serde_json::from_str(line.trim()).context("parse supervisor reply")
}

/// Run the supervisor in the **current process**.
///
/// Builds a `Sandbox` from the OCI policy, drives the full create/start/wait
/// lifecycle using `sandlock_core`, and communicates the child PID back to the
/// CLI via `pid_write_fd`.
pub fn run_supervisor(
    id: &str,
    cmd: &[String],
    policy: OciPolicy,
    pid_write_fd: i32,
) -> Result<Option<crate::state::ExitInfo>> {
    if cmd.is_empty() {
        anyhow::bail!("OCI spec error: process.args is empty");
    }

    // Create backing dirs for emulated tmpfs mounts before building the
    // sandbox so each bind redirect has a target on disk.  They live under the
    // sandbox state dir and are removed with it on `delete`.
    for dir in &policy.scratch_dirs {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create tmpfs backing dir {:?}", dir))?;
    }

    // Build the Sandbox from the OCI policy — this carries chroot, env, fs
    // rules, resource limits, and network policy into sandlock-core.
    let mut sandbox = policy.to_sandbox().context("build Sandbox from OCI policy")?;
    sandbox.set_name(id);

    let sock_path = socket_path(id);
    if sock_path.exists() {
        std::fs::remove_file(&sock_path).ok();
    }

    // A multi-threaded runtime is required: sandlock-core spawns tokio tasks
    // for the seccomp-notify supervisor, CPU throttle, and load-avg tracking.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    rt.block_on(supervisor_main(id, cmd, sandbox, sock_path, pid_write_fd))
}

/// Write a line to the notification pipe and close it.  Used for both the
/// success case (`OK <pid>`) and the failure case (`ERR <message>`).
fn pipe_write(fd: i32, line: &str) {
    let s = format!("{}\n", line);
    unsafe {
        libc::write(fd, s.as_ptr() as *const libc::c_void, s.len());
        libc::close(fd);
    }
}

/// Async body of `run_supervisor`.
///
/// Instead of running the workload directly, this launches a confined
/// `sandlock-init` (PID-1) that runs in-process in the forked child (no exec)
/// and relays OCI verbs to it over a control socket: the workload and any
/// exec'd processes are forked by `sandlock-init` and so share the one sandbox
/// (seccomp filter + Landlock ruleset + notify supervisor).
async fn supervisor_main(
    id: &str,
    cmd: &[String],
    mut sandbox: sandlock_core::Sandbox,
    sock_path: PathBuf,
    pid_write_fd: i32,
) -> Result<Option<crate::state::ExitInfo>> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;

    // Bind the socket BEFORE create() so the CLI can call `start` the moment
    // `create` returns without a race on socket availability.
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR bind socket: {}", e));
            anyhow::bail!("bind supervisor socket {:?}: {}", sock_path, e);
        }
    };

    // Restrict connects to the owner (root, same as the runtime). Best-effort:
    // the path-length fix is what matters; a chmod failure must not abort create.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o700));
    }

    // Set up the control channel. The child end is mapped onto CONTROL_FD inside
    // the confined process; the daemon keeps the other end to drive
    // RunMain/RunExec/Shutdown.
    let (daemon_ctl, child_ctl) = match std::os::unix::net::UnixStream::pair() {
        Ok(p) => p,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR control socketpair: {}", e));
            anyhow::bail!("control socketpair: {}", e);
        }
    };
    let extra_fds = vec![(CONTROL_FD, child_ctl.as_raw_fd())];

    // OCI `create` of the CONFINED sandlock-init: forks the child, installs the
    // full sandlock policy, maps CONTROL_FD, and parks. The child runs the
    // in-process `run_init` control loop instead of exec'ing a separate binary:
    // it is already a fork of this supervisor, so the init code is mapped, and
    // because nothing is exec'd there is no execve for Landlock to authorize.
    if let Err(e) = sandbox
        .create_with_in_child_main("sandlock-init", extra_fds, crate::init::run_init)
        .await
    {
        pipe_write(pid_write_fd, &format!("ERR create: {}", e));
        return Err(anyhow::anyhow!("sandbox create_with_in_child_main: {}", e));
    }
    // The child inherited child_ctl at fork and dup'd it onto CONTROL_FD; drop
    // the daemon's copy so it holds only daemon_ctl (and so EOF on daemon_ctl
    // tracks init exiting).
    drop(child_ctl);

    // Release sandlock-init to run its control loop. It then blocks reading
    // CONTROL_FD for the first request. This happens at create/supervisor time
    // (not OCI start) so init is alive to receive RunMain when the OCI `start`
    // arrives.
    if let Err(e) = sandbox.start() {
        pipe_write(pid_write_fd, &format!("ERR start init: {}", e));
        return Err(anyhow::anyhow!("start sandlock-init: {}", e));
    }

    let init_pid = sandbox.pid().unwrap_or(0) as i32;

    // Build the demuxing control link to sandlock-init. `daemon_ctl` is a std
    // socket; a dup serves the blocking fd-passing writer while the original is
    // converted to a nonblocking tokio socket for the async reader. set_nonblocking
    // sets O_NONBLOCK on the shared open file description, but the writer only
    // sends tiny control messages, so a nonblocking `sendmsg` never short-writes.
    let writer = match daemon_ctl.try_clone() {
        Ok(w) => w,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR dup control: {}", e));
            anyhow::bail!("dup control socket: {}", e);
        }
    };
    if let Err(e) = daemon_ctl.set_nonblocking(true) {
        pipe_write(pid_write_fd, &format!("ERR control nonblock: {}", e));
        anyhow::bail!("set control nonblocking: {}", e);
    }
    let reader = match tokio::net::UnixStream::from_std(daemon_ctl) {
        Ok(r) => r,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR control tokio: {}", e));
            anyhow::bail!("convert control socket to tokio: {}", e);
        }
    };
    let link = InitLink::new(writer, reader);

    // Notify the CLI: `OK <pid>` on success. Before OCI `start` there is no
    // workload yet, so the reported/recorded PID is sandlock-init's (the
    // container PID-1); OCI `start` updates state.pid to the workload PID.
    // Report two pids: the supervisor daemon's own pid (this process, which is
    // the containerd shim's child and what the shim reaps to detect exit) and
    // sandlock-init's pid (the OCI container init, recorded as state.pid).
    pipe_write(pid_write_fd, &format!("OK {} {}", std::process::id(), init_pid));

    {
        let mut state = SandboxState::load(id)
            .unwrap_or_else(|_| SandboxState::new(id, Path::new("/"), "1.0.2"));
        state.set_created(init_pid);
        state.save().ok();
    }

    // PRE-START accept-loop: serve CLI commands until `Start` (transition to the
    // running-serve loop) or `Shutdown`/error (return so the Sandbox Drop kills
    // and reaps init, which collapses the whole group).
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return Ok(None),
        };

        // Same newline-delimited framing rule as the running loop: never act
        // on (or answer) a request fragment.
        let buf = match read_control_request(&mut stream, 0).await {
            Ok(Some((buf, _fds))) => buf,
            Ok(None) => continue,
            Err(e) => {
                let reply = serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                    .unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
                continue;
            }
        };

        let incoming: SupervisorCmd = match serde_json::from_slice(&buf) {
            Ok(c) => c,
            Err(e) => {
                let reply = serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                    .unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
                continue;
            }
        };

        match incoming {
            SupervisorCmd::Ping => {
                let reply =
                    serde_json::to_vec(&SupervisorReply::Pid { pid: init_pid }).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
            SupervisorCmd::Start => {
                // OCI `start`: tell init to fork the workload. The reply pid is
                // the workload PID (not init), which becomes state.pid.
                let req = Req::RunMain {
                    argv: cmd.to_vec(),
                    env: vec![],
                    cwd: None,
                };
                match link.request(&req, &[]).await {
                    Ok(Resp::Started { pid }) => {
                        let main_exit = link.register_exit(pid);
                        if let Ok(mut s) = SandboxState::load(id) {
                            s.set_created(pid);
                            s.set_running();
                            s.save().ok();
                        }
                        let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                        // Workload is running: keep serving the control socket
                        // (Ping/Exec/Checkpoint) until it exits or Shutdown.
                        let exit_info =
                            serve_running_init(id, &link, &mut sandbox, &listener, pid, main_exit)
                                .await;
                        if let Ok(mut s) = SandboxState::load(id) {
                            s.set_stopped(exit_info.clone());
                            s.save().ok();
                        }
                        return Ok(exit_info);
                    }
                    Ok(Resp::Err { msg }) => {
                        let reply = serde_json::to_vec(&SupervisorReply::Err { msg })
                            .unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                        return Ok(None);
                    }
                    Err(e) => {
                        // The request could not be answered: the channel
                        // closed, or the reply deadline expired (link marked
                        // Dead). Surface the reason to the CLI instead of
                        // hanging (F1.8).
                        let reply = serde_json::to_vec(&SupervisorReply::Err {
                            msg: e.to_string(),
                        })
                        .unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                        return Ok(None);
                    }
                    other => {
                        let msg = format!("unexpected init reply to RunMain: {:?}", other);
                        let reply = serde_json::to_vec(&SupervisorReply::Err { msg })
                            .unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                        return Ok(None);
                    }
                }
            }
            SupervisorCmd::Shutdown => {
                // `delete` before `start`: tell init to exit, then return so
                // the Sandbox Drop reaps it.
                // Ok is an enqueue ack only: init acts on the frame and exits
                // asynchronously.
                link.shutdown().await;
                let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
                return Ok(None);
            }
            SupervisorCmd::Checkpoint { dir } => {
                let reply = match sandbox.checkpoint().await {
                    Ok(mut cp) => {
                        cp.name = id.to_string();
                        match cp.save(std::path::Path::new(&dir)) {
                            Ok(()) => serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default(),
                            Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() }).unwrap_or_default(),
                        }
                    }
                    Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() }).unwrap_or_default(),
                };
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
            SupervisorCmd::Exec { .. } => {
                let reply = serde_json::to_vec(&SupervisorReply::Err {
                    msg: "container is not running; start it before exec".into(),
                })
                .unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
            SupervisorCmd::Signal { .. } => {
                let reply = serde_json::to_vec(&SupervisorReply::Err {
                    msg: "container not running".into(),
                })
                .unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
        }
    }
}

/// Serve the control socket while the workload (forked by sandlock-init) runs,
/// returning its recorded exit info once it exits or a Shutdown is received.
///
/// Exit is detected via the init control channel (`main_exit` resolves when init
/// reports the workload's `Exited`), not a pidfd: init owns the workload and
/// reports its status authoritatively. `sandbox` is kept alive (and is used for
/// `checkpoint`) so the shared seccomp-notify supervisor keeps servicing the
/// workload and any exec'd processes.
async fn serve_running_init(
    id: &str,
    link: &Arc<InitLink>,
    sandbox: &mut sandlock_core::Sandbox,
    listener: &tokio::net::UnixListener,
    workload_pid: i32,
    mut main_exit: oneshot::Receiver<Resp>,
) -> Option<crate::state::ExitInfo> {
    loop {
        tokio::select! {
            res = &mut main_exit => {
                // Workload exited; init kills the group and exits too. The
                // Sandbox Drop reaps init.
                return exit_info_from_resp(res.ok());
            }
            conn = listener.accept() => {
                match conn {
                    Ok((stream, _)) => {
                        match serve_one_running_init(stream, link, sandbox, id, workload_pid).await {
                            RunningCmd::Continue => {}
                            RunningCmd::Shutdown => {
                                link.shutdown().await;
                                return None;
                            }
                        }
                    }
                    Err(_) => {
                        // Listener broke: fall back to waiting for the workload
                        // exit so we still record a final state.
                        return exit_info_from_resp((&mut main_exit).await.ok());
                    }
                }
            }
        }
    }
}

/// Largest control request the supervisor will assemble (exec argv/env can be
/// large; the pre-fix single-`recvmsg` read silently truncated anything past
/// its 8 KiB buffer).
const MAX_CONTROL_REQUEST: usize = 64 * 1024;

/// How long a client may take to finish a request it has started. A peer that
/// never sends the frame's `\n` delimiter is a protocol violation (see
/// [`read_control_request`]); the deadline only bounds how long the
/// single-connection accept loop waits on such a peer.
const CONTROL_REQUEST_DEADLINE: Duration = Duration::from_secs(2);

/// Read one **complete** control request from an accepted connection: the
/// newline-delimited JSON frame the CLI sends, plus whatever SCM_RIGHTS
/// descriptors ride with it.
///
/// A stream socket preserves no write boundaries. The CLI writes the payload
/// and its `\n` delimiter as two sends, and under load the receiver's first
/// `recvmsg` returns only the payload — so a supervisor that treats one
/// `recvmsg` as the whole request answers before the client has finished
/// writing, and the client's delimiter write then fails with `EPIPE`.
/// `kill --all` reacts to any send error by falling back to a direct
/// `killpg(state.pid, signum)`, which delivers the instance signal a *second*
/// time (the F1.7/SECE-6 exactly-once contract, pinned by
/// `test_signal_to_sibling_pid_rejected`). Read to the delimiter instead,
/// bounded in size and time; a request that never terminates is rejected
/// rather than half-acted on.
///
/// `Ok(None)` means the peer closed without sending a request (nothing to
/// answer); `Err` is a request-level failure the caller reports as `Err`.
async fn read_control_request(
    stream: &mut tokio::net::UnixStream,
    max_fds: usize,
) -> std::io::Result<Option<(Vec<u8>, Vec<std::os::unix::io::OwnedFd>)>> {
    let (mut buf, fds) = crate::fdpass::recv_with_fds_async(stream, max_fds).await?;
    if buf.is_empty() {
        // EOF: a probe connection (or a client that gave up). No reply.
        return Ok(None);
    }
    if !buf.contains(&b'\n') {
        let deadline = tokio::time::Instant::now() + CONTROL_REQUEST_DEADLINE;
        loop {
            if buf.contains(&b'\n') || buf.len() >= MAX_CONTROL_REQUEST {
                break;
            }
            let read =
                tokio::time::timeout_at(deadline, crate::fdpass::recv_with_fds_async(stream, 0))
                    .await;
            match read {
                // Only the frame's first fragment carries its descriptors.
                Ok(Ok((bytes, extra))) => {
                    drop(extra);
                    if bytes.is_empty() {
                        break; // peer half-closed: no delimiter is coming
                    }
                    buf.extend_from_slice(&bytes);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => break, // deadline: no delimiter is coming
            }
        }
        if !buf.contains(&b'\n') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "control request is not newline-terminated ({} bytes buffered); the CLI \
                     and the supervisor must come from the same build",
                    buf.len()
                ),
            ));
        }
    }
    Ok(Some((buf, fds)))
}

/// Handle one accepted connection while the container is RUNNING (init path).
/// Reads the command via recvmsg so exec stdio fds arrive with the bytes.
async fn serve_one_running_init(
    mut stream: tokio::net::UnixStream,
    link: &Arc<InitLink>,
    sandbox: &mut sandlock_core::Sandbox,
    id: &str,
    workload_pid: i32,
) -> RunningCmd {
    use tokio::io::AsyncWriteExt;

    let (buf, fds) = match read_control_request(&mut stream, 3).await {
        Ok(Some(pair)) => pair,
        // Peer closed without a request, or the request never terminated.
        Ok(None) => return RunningCmd::Continue,
        Err(e) => {
            let reply = serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                .unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            return RunningCmd::Continue;
        }
    };
    let incoming: SupervisorCmd = match serde_json::from_slice(&buf) {
        Ok(c) => c,
        Err(e) => {
            let reply = serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                .unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            return RunningCmd::Continue;
        }
    };
    match incoming {
        SupervisorCmd::Ping => {
            let reply =
                serde_json::to_vec(&SupervisorReply::Pid { pid: workload_pid }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Start => {
            // Already running: idempotent no-op.
            let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Exec { args, env, cwd, detach } => {
            handle_exec(stream, link.clone(), args, env, cwd, detach, fds).await;
            RunningCmd::Continue
        }
        SupervisorCmd::Checkpoint { dir } => {
            // Capture the WORKLOAD, not sandlock-init (which is the sandbox's
            // direct child and would only snapshot the init process blocked in
            // recvmsg).
            let reply = match sandbox.checkpoint_pid(workload_pid).await {
                Ok(mut cp) => {
                    cp.name = id.to_string();
                    match cp.save(std::path::Path::new(&dir)) {
                        Ok(()) => serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default(),
                        Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                            .unwrap_or_default(),
                    }
                }
                Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                    .unwrap_or_default(),
            };
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Signal { signum } => {
            // F1.7 (SECE-6): every exec'd child is now its own group leader,
            // so a host-side killpg(sandbox.pid()) would reach only init's own
            // group (init alone) and miss the workload entirely. Relay the
            // instance-level request to init over the control channel; init
            // traverses its registered child-group set (group-first killpg +
            // pidfd_send_signal complement). Fire-and-forget like Shutdown:
            // init acts on the frame without answering, and a SIGKILLed main
            // workload reports its own Exited through the normal reaper path.
            link.send(&Req::Signal { signum }).await;
            // Ok is an enqueue ack only (fire-and-forget frame): init may
            // deliver asynchronously, so Ok does not mean delivery happened.
            let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Shutdown => {
            // Ok is an enqueue ack only; the actual Shutdown frame is sent by
            // the caller (serve_running_init) after this reply.
            let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Shutdown
        }
    }
}

/// Forward an exec to sandlock-init: send `RunExec` + the 3 stdio fds, relay the
/// `Started` pid back to the CLI as `Pid`, then (attached only) wait for the
/// init `Exited` and relay it as `Exit`. The daemon's fd copies are dropped once
/// init has dup'd them via SCM_RIGHTS.
#[allow(clippy::too_many_arguments)]
async fn handle_exec(
    mut stream: tokio::net::UnixStream,
    link: Arc<InitLink>,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<String>,
    detach: bool,
    fds: Vec<std::os::unix::io::OwnedFd>,
) {
    use tokio::io::AsyncWriteExt;

    if fds.len() < 3 {
        let reply = serde_json::to_vec(&SupervisorReply::Err {
            msg: "exec requires 3 stdio fds".into(),
        })
        .unwrap_or_default();
        let _ = stream.write_all(&reply).await;
        let _ = stream.write_all(b"\n").await;
        return;
    }
    if args.is_empty() {
        let reply = serde_json::to_vec(&SupervisorReply::Err { msg: "exec: empty command".into() })
            .unwrap_or_default();
        let _ = stream.write_all(&reply).await;
        let _ = stream.write_all(b"\n").await;
        return;
    }

    let raw: Vec<RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
    let req = Req::RunExec {
        argv: args,
        env,
        cwd,
        detach,
        clean_env: false,
        extra_writable: vec![],
        bind_ports: vec![],
    };
    let started = link.request(&req, &raw).await;
    // init has now dup'd the fds (SCM_RIGHTS); drop the daemon's copies.
    drop(fds);

    match started {
        Ok(Resp::Started { pid }) => {
            let reply = serde_json::to_vec(&SupervisorReply::Pid { pid }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            if !detach {
                // Register the waiter before yielding so a fast Exited is not
                // missed, then relay it on a background task to keep the serve
                // loop responsive.
                let rx = link.register_exit(pid);
                tokio::spawn(async move {
                    if let Ok(Resp::Exited { code, signal, .. }) = rx.await {
                        let reply = serde_json::to_vec(&SupervisorReply::Exit { code, signal })
                            .unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                    }
                });
            } else {
                // Detached execs are never waited on and init never reports
                // their exit, so drop the announced registration: a later
                // frame for this pid is expected-silent (dropped + counted),
                // never buffered.
                link.forget_detached(pid);
            }
        }
        Ok(Resp::Err { msg }) => {
            let reply = serde_json::to_vec(&SupervisorReply::Err { msg }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
        }
        Err(e) => {
            // The request could not be answered (channel closed or deadline
            // exceeded / link Dead); relay the reason to the CLI (F1.8).
            let reply =
                serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
        }
        other => {
            let msg = format!("unexpected init reply to RunExec: {:?}", other);
            let reply = serde_json::to_vec(&SupervisorReply::Err { msg }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
        }
    }
}

/// Convert a `RunResult` (or wait error) into the on-disk `ExitInfo`.
fn exit_info_from(
    res: Result<sandlock_core::RunResult, sandlock_core::SandlockError>,
) -> Option<crate::state::ExitInfo> {
    use crate::state::ExitInfo;
    use sandlock_core::ExitStatus;
    match res {
        Ok(r) => match r.exit_status {
            ExitStatus::Code(code) => Some(ExitInfo { code: Some(code), signal: None }),
            ExitStatus::Signal(sig) => Some(ExitInfo { code: None, signal: Some(sig) }),
            ExitStatus::Killed => Some(ExitInfo { code: None, signal: Some(libc::SIGKILL) }),
            ExitStatus::Timeout => Some(ExitInfo { code: Some(124), signal: None }),
        },
        Err(_) => None,
    }
}

/// Open an independent pidfd for `pid` as an AsyncFd readiness source for child
/// exit, WITHOUT consuming the sandbox's own pidfd. A pidfd becomes readable
/// when the process exits. Returns None if pidfd_open is unavailable or the
/// child is already gone (caller then falls back to a plain wait()).
fn exit_watcher(pid: i32) -> Option<tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>> {
    use std::os::unix::io::{FromRawFd, OwnedFd};
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return None;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    tokio::io::unix::AsyncFd::with_interest(fd, tokio::io::Interest::READABLE).ok()
}

/// Outcome of handling one running-container control command.
enum RunningCmd {
    Continue,
    Shutdown,
}

/// Handle a single accepted connection while the container is RUNNING. Serves
/// Ping, Checkpoint, Start (idempotent no-op since already running), and
/// Shutdown. Returns whether to keep serving or shut down.
async fn serve_one_running(
    stream: &mut tokio::net::UnixStream,
    sandbox: &mut sandlock_core::Sandbox,
    id: &str,
    child_pid: i32,
) -> RunningCmd {
    use tokio::io::AsyncWriteExt;
    let buf = match read_control_request(stream, 0).await {
        Ok(Some((buf, _fds))) => buf,
        Ok(None) => return RunningCmd::Continue,
        Err(e) => {
            let reply = serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                .unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            return RunningCmd::Continue;
        }
    };
    let incoming: SupervisorCmd = match serde_json::from_slice(&buf) {
        Ok(c) => c,
        Err(e) => {
            let reply = serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                .unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            return RunningCmd::Continue;
        }
    };
    match incoming {
        SupervisorCmd::Ping => {
            let reply =
                serde_json::to_vec(&SupervisorReply::Pid { pid: child_pid }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Start => {
            // Already running: idempotent no-op.
            let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Checkpoint { dir } => {
            let reply = match sandbox.checkpoint().await {
                Ok(mut cp) => {
                    cp.name = id.to_string();
                    match cp.save(std::path::Path::new(&dir)) {
                        Ok(()) => serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default(),
                        Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                            .unwrap_or_default(),
                    }
                }
                Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                    .unwrap_or_default(),
            };
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Exec { .. } => {
            // exec inside a restored container is not supported (restore has no
            // sandlock-init relay). Reject so the CLI surfaces a clear error.
            let reply = serde_json::to_vec(&SupervisorReply::Err {
                msg: "exec is not supported on a restored container".into(),
            })
            .unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Signal { signum } => {
            // Restore shape: one workload child (core's setpgid(0,0)), with no
            // sandlock-init and therefore no per-child registry to traverse.
            // child_pid is the workload's pid (== pgid), so a host-side killpg
            // is the entire instance here — unlike the init path, where Signal
            // is relayed to init to traverse the child-group set (F1.7/SECE-6).
            if child_pid > 0 {
                unsafe { libc::killpg(child_pid, signum) };
                let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            } else {
                let reply = serde_json::to_vec(&SupervisorReply::Err { msg: "no container process group".into() }).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
            RunningCmd::Continue
        }
        SupervisorCmd::Shutdown => {
            // Ok is an accept ack only: the caller kills the restored child
            // after this reply, so Ok does not mean the child is gone yet.
            let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Shutdown
        }
    }
}

/// Serve the control socket while the (already-running) child executes,
/// returning the recorded exit info once the child exits or a Shutdown is
/// received. Uses an independent pidfd watcher so the sandbox's own pidfd is
/// consumed only by the final `wait()`, after exit. `AsyncFd::readable()` is
/// cancel-safe and borrows only the watcher, so accepted commands can use
/// `sandbox` freely.
async fn serve_running(
    id: &str,
    sandbox: &mut sandlock_core::Sandbox,
    listener: &tokio::net::UnixListener,
    child_pid: i32,
) -> Option<crate::state::ExitInfo> {
    let watcher = match exit_watcher(child_pid) {
        Some(w) => w,
        None => {
            // Cannot watch concurrently: just wait for exit (no serving).
            return reap_and_collapse(sandbox, child_pid).await;
        }
    };
    loop {
        tokio::select! {
            ready = watcher.readable() => {
                // Child exited (pidfd readable), or the watcher errored: either
                // way collect the status via the sandbox's own pidfd. We return
                // immediately, so there is no need to clear readiness.
                let _ = ready;
                return reap_and_collapse(sandbox, child_pid).await;
            }
            conn = listener.accept() => {
                match conn {
                    Ok((mut stream, _)) => {
                        match serve_one_running(&mut stream, sandbox, id, child_pid).await {
                            RunningCmd::Continue => {}
                            RunningCmd::Shutdown => {
                                let _ = sandbox.kill();
                                return exit_info_from(sandbox.wait().await);
                            }
                        }
                    }
                    Err(_) => return reap_and_collapse(sandbox, child_pid).await,
                }
            }
        }
    }
}

/// Collect the main process's exit status, then collapse its process group
/// (restore / single-child supervisor shape only).
///
/// sandlock uses no PID namespace, so when the container's main process exits
/// the kernel does not tear down the processes it spawned (background children,
/// which share the workload's group). Send SIGKILL to the whole group so
/// nothing outlives the container with a now-dead supervisor. `child_pid` is
/// the group's pgid (core does `setpgid(0, 0)` in the child); `killpg` reaches
/// any remaining members and is a harmless `ESRCH` when the group is already
/// empty. In the init shape the equivalent collapse happens inside
/// `sandlock-init` (main-exit/Shutdown traversal of the registered child-group
/// set), not here; the `Shutdown` path does not call this because
/// `sandbox.kill()` already SIGKILLs the same process group.
async fn reap_and_collapse(
    sandbox: &mut sandlock_core::Sandbox,
    child_pid: i32,
) -> Option<crate::state::ExitInfo> {
    let info = exit_info_from(sandbox.wait().await);
    if child_pid > 0 {
        unsafe { libc::killpg(child_pid, libc::SIGKILL) };
    }
    info
}

/// Run the supervisor in the **current process** for an OCI `restore`.
///
/// Unlike [`run_supervisor`], the policy comes from the checkpoint image (the
/// saved `Sandbox`), not from an `OciPolicy`, and there is no separate `start`:
/// `restore_interactive` both creates the child and resumes it, so the sandbox
/// is `Running` the moment restore returns.
pub fn run_supervisor_restore(id: &str, image_dir: &str, pid_write_fd: i32) -> Result<()> {
    // Load the checkpoint image. On failure report back through the pid pipe so
    // the CLI surfaces a clear error rather than a bare EOF.
    let cp = match sandlock_core::Checkpoint::load(std::path::Path::new(image_dir)) {
        Ok(c) => c,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR load checkpoint: {}", e));
            return Err(anyhow::anyhow!("load checkpoint from {:?}: {}", image_dir, e));
        }
    };

    // Build the Sandbox from the SAVED policy (cp.policy is a Sandbox with a
    // manual Clone), not from an OciPolicy.
    let mut sandbox = cp.policy.clone();
    sandbox.set_name(id);

    let sock_path = socket_path(id);
    if sock_path.exists() {
        std::fs::remove_file(&sock_path).ok();
    }

    // Same multi-threaded runtime requirement as run_supervisor.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    rt.block_on(supervisor_restore_main(id, sandbox, cp, sock_path, pid_write_fd))
}

/// Async body of [`run_supervisor_restore`].
async fn supervisor_restore_main(
    id: &str,
    mut sandbox: sandlock_core::Sandbox,
    cp: sandlock_core::Checkpoint,
    sock_path: PathBuf,
    pid_write_fd: i32,
) -> Result<()> {
    use tokio::net::UnixListener;

    // Bind the control socket BEFORE restore (mirrors create binding before
    // create) so the CLI never races on socket availability.
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR bind socket: {}", e));
            anyhow::bail!("bind supervisor socket {:?}: {}", sock_path, e);
        }
    };

    // Restrict connects to the owner (root, same as the runtime). Best-effort:
    // the path-length fix is what matters; a chmod failure must not abort restore.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o700));
    }

    // Restore: forks the child under the saved policy, injects the checkpoint,
    // and RESUMES it. The child is already running on return — there is no
    // separate start step.
    if let Err(e) = sandbox.restore_interactive(&cp).await {
        pipe_write(pid_write_fd, &format!("ERR restore: {}", e));
        return Err(anyhow::anyhow!("sandbox restore_interactive: {}", e));
    }
    for f in sandbox.restore_skipped() {
        eprintln!("sandlock: fd {} not transparently restored: {}", f.fd, f.path);
    }

    let child_pid = sandbox.pid().unwrap_or(0);

    // Notify the CLI: `OK <pid>` on success.
    pipe_write(pid_write_fd, &format!("OK {}", child_pid));

    // Restore resumes the child immediately, so persist RUNNING right away
    // (set_created records the PID, set_running flips the status).
    {
        let mut state = SandboxState::load(id)
            .unwrap_or_else(|_| SandboxState::new(id, Path::new("/"), "1.0.2"));
        state.set_created(child_pid);
        state.set_running();
        state.save().ok();
    }

    // Serve the control socket while the resumed child runs (shared with the
    // create+start path). There is no `Start` (the child is already running): a
    // stray `Start` is an idempotent no-op. An independent pidfd watcher detects
    // exit so the sandbox's own pidfd is consumed exactly once, by the final
    // `wait()`, avoiding the cancellation hazard of re-creating `wait()` per
    // select iteration.
    let exit_info = serve_running(id, &mut sandbox, &listener, child_pid).await;

    if let Ok(mut s) = SandboxState::load(id) {
        s.set_stopped(exit_info);
        s.save().ok();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_uses_short_hashed_name_under_state_dir() {
        let p = socket_path("my-sandbox");
        let s = p.to_str().unwrap();
        assert!(s.starts_with(&crate::state::state_dir()));
        assert!(s.ends_with(".sock"));
        // file name is 16 hex chars + ".sock" = 21 bytes, never the raw id.
        assert_eq!(p.file_name().unwrap().to_str().unwrap().len(), 21);
        assert!(!s.contains("my-sandbox"));
    }

    #[test]
    fn socket_filename_keeps_path_under_sun_len_for_cri_root() {
        // containerd's runc-v2 shim passes this root plus a 64-char id.
        let cri_root = "/run/containerd/runc/k8s.io";
        let id = "a".repeat(64);
        let full = format!("{}/{}.sock", cri_root, fnv1a_hex(&id));
        assert!(full.len() < 108, "socket path too long: {} bytes", full.len());
    }

    #[test]
    fn fnv1a_hex_is_deterministic_and_distinct() {
        assert_eq!(fnv1a_hex("abc"), fnv1a_hex("abc"));
        assert_ne!(fnv1a_hex("abc"), fnv1a_hex("abd"));
        assert_eq!(fnv1a_hex("abc").len(), 16);
        assert!(fnv1a_hex("abc").chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn supervisor_cmd_start_serde() {
        let cmd = SupervisorCmd::Start;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("start"));
    }

    #[test]
    fn supervisor_cmd_ping_serde() {
        let cmd = SupervisorCmd::Ping;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("ping"));
    }

    #[test]
    fn supervisor_cmd_shutdown_serde() {
        let cmd = SupervisorCmd::Shutdown;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("shutdown"));
    }

    #[test]
    fn supervisor_reply_ok_serde() {
        let reply = SupervisorReply::Ok;
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("ok"));
    }

    #[test]
    fn supervisor_reply_pid_serde() {
        let reply = SupervisorReply::Pid { pid: 42 };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("42"));
    }

    #[test]
    fn supervisor_reply_err_serde() {
        let reply = SupervisorReply::Err { msg: "test error".into() };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("err"));
        assert!(json.contains("test error"));
    }

    #[test]
    fn supervisor_cmd_checkpoint_serde() {
        let cmd = SupervisorCmd::Checkpoint { dir: "/tmp/img".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("checkpoint"));
        assert!(json.contains("/tmp/img"));
        let back: SupervisorCmd = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, SupervisorCmd::Checkpoint { .. }));
    }

    #[test]
    fn supervisor_cmd_signal_serde() {
        let cmd = SupervisorCmd::Signal { signum: libc::SIGKILL };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("signal"));
        let back: SupervisorCmd = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, SupervisorCmd::Signal { signum: 9 }));
    }

    // ── F1.2 H1/H2: bounded early_exits + registered-pid exit routing ──────
    //
    // Reader-driven by design: the supervisor's control channel is an internal
    // socketpair read by `reader_task`, and since F1.1 no workload can write
    // the child end (CONTROL_FD is CLOEXEC). The faithful injection point is
    // therefore the peer end of a real socketpair feeding the same `InitLink`
    // + `reader_task` path the supervisor runs (see tmp/sdd/f1.2-report.md).

    /// Resident set size in bytes, from /proc/self/statm (Linux gate env).
    fn rss_bytes() -> u64 {
        let statm =
            std::fs::read_to_string("/proc/self/statm").expect("read /proc/self/statm (Linux)");
        let pages: u64 = statm
            .split_whitespace()
            .nth(1)
            .expect("statm resident field")
            .parse()
            .expect("statm resident pages numeric");
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        pages * page
    }

    /// Build an `InitLink` over a real socketpair with the given early-exit
    /// cap and return it plus the CHILD end, exactly as `supervisor_main`
    /// wires them (writer + reader are dups of the daemon end). The test owns
    /// the child end and plays sandlock-init: it reads `Req`s and writes
    /// `Resp` frames — including forged ones — through the same `reader_task`
    /// the live supervisor runs.
    fn reader_driven_link(cap: usize) -> (Arc<InitLink>, tokio::net::UnixStream) {
        let (daemon, child) = std::os::unix::net::UnixStream::pair().unwrap();
        daemon.set_nonblocking(true).unwrap();
        child.set_nonblocking(true).unwrap();
        let writer = daemon.try_clone().unwrap();
        let reader = tokio::net::UnixStream::from_std(daemon).unwrap();
        let child = tokio::net::UnixStream::from_std(child).unwrap();
        (InitLink::with_early_exit_cap(writer, reader, cap), child)
    }

    /// Like [`reader_driven_link`], with a configurable per-request deadline
    /// (F1.8 tests use a short one so the timeout path runs in milliseconds).
    fn reader_driven_link_with_timeout(
        request_timeout: Duration,
    ) -> (Arc<InitLink>, tokio::net::UnixStream) {
        let (daemon, child) = std::os::unix::net::UnixStream::pair().unwrap();
        daemon.set_nonblocking(true).unwrap();
        child.set_nonblocking(true).unwrap();
        let writer = daemon.try_clone().unwrap();
        let reader = tokio::net::UnixStream::from_std(daemon).unwrap();
        let child = tokio::net::UnixStream::from_std(child).unwrap();
        (InitLink::with_request_timeout(writer, reader, request_timeout), child)
    }

    /// Write one framed `Resp` frame on the init -> daemon wire.
    async fn write_resp(peer: &mut tokio::net::UnixStream, resp: &Resp) {
        use tokio::io::AsyncWriteExt;
        let payload = serde_json::to_vec(resp).unwrap();
        let frame = proto::encode_frame(FrameKind::Resp, &payload, 0).unwrap();
        peer.write_all(&frame).await.unwrap();
    }

    /// Read one framed `Req` from the daemon end and return its JSON payload.
    async fn read_req_frame(peer: &mut tokio::net::UnixStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut header = [0u8; proto::FRAME_HEADER_LEN];
        peer.read_exact(&mut header)
            .await
            .expect("read request frame header");
        let header = proto::decode_header(&header).expect("valid request frame header");
        assert_eq!(header.kind, FrameKind::Req, "fake init must read a Req frame");
        let len = header.payload_len;
        let mut payload = vec![0u8; len];
        peer.read_exact(&mut payload)
            .await
            .expect("read request frame payload");
        payload
    }

    /// Spawn a fake-sandlock-init task that answers the next `pids.len()`
    /// requests with `Started { pid }` each, then returns the child stream.
    fn spawn_init_announcer(
        mut child: tokio::net::UnixStream,
        pids: Vec<i32>,
    ) -> tokio::task::JoinHandle<tokio::net::UnixStream> {
        tokio::spawn(async move {
            for pid in pids {
                let payload = read_req_frame(&mut child).await;
                assert!(
                    String::from_utf8_lossy(&payload).contains("req"),
                    "expected a request frame, got {:?}",
                    payload
                );
                write_resp(&mut child, &Resp::Started { pid }).await;
            }
            child
        })
    }

    /// Poll until `pred` holds for the link's routed state (frames are routed
    /// by the background `reader_task`, so tests wait for quiescence).
    async fn wait_for(link: &InitLink, pred: impl Fn(&LinkStats) -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !pred(&link.stats()) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for frame routing: {:?}",
                link.stats()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn early_exits_cap_drops_overflow() {
        const CAP: usize = 8;
        const CHILDREN: i32 = 10;
        let (link, child) = reader_driven_link(CAP);
        let req = Req::RunExec {
            argv: vec!["true".into()],
            env: vec![],
            cwd: None,
            detach: false,
            clean_env: false,
            extra_writable: vec![],
            bind_ports: vec![],
        };

        // Announce CAP + 2 children through the real request/Started path
        // (each `request` resolves with init's `Started`), leaving every child
        // announced-but-unregistered exactly like the early-exit race window.
        let announcer = spawn_init_announcer(child, (1..=CHILDREN).collect());
        for pid in 1..=CHILDREN {
            match link.request(&req, &[]).await.expect("request must be answered") {
                Resp::Started { pid: got } => assert_eq!(got, pid),
                other => panic!("expected Started, got {:?}", other),
            }
        }
        let mut child = announcer.await.expect("init announcer");
        assert_eq!(link.stats().announced, CHILDREN as usize);

        // Now deliver their Exited frames before any waiter registers — the
        // early-exit race the buffer exists for — so the buffer fills to the
        // cap and the two excess frames are dropped + counted.
        for pid in 1..=(CAP as i32 + 2) {
            write_resp(
                &mut child,
                &Resp::Exited { pid, code: Some(pid), signal: None },
            )
            .await;
        }
        wait_for(&link, |s| s.overflow_drops == 2).await;

        let stats = link.stats();
        assert_eq!(stats.early_exits, CAP, "buffer must stop at the configured cap");
        assert_eq!(stats.early_exit_cap, CAP, "cap must be the configured value");
        assert_eq!(stats.announced, 0, "every announced exit was delivered or dropped");
        assert_eq!(stats.unknown_exits, 0);
        assert_eq!(stats.overflow_drops, 2, "frames beyond the cap are dropped + counted");
        {
            let st = link.state.lock().unwrap();
            for pid in 1..=CAP as i32 {
                assert!(
                    st.early_exits.contains_key(&pid),
                    "pid {} (first-come) must be the buffered frame",
                    pid
                );
            }
            assert!(!st.early_exits.contains_key(&(CAP as i32 + 1)));
            assert!(!st.early_exits.contains_key(&(CAP as i32 + 2)));
            assert!(st.exit_waiters.is_empty());
            assert!(st.pending.is_none());
        }

        // A duplicate frame for the overflow-dropped pid is now unknown too:
        // its registry entry was consumed by the drop, so nothing re-buffers.
        write_resp(
            &mut child,
            &Resp::Exited { pid: CAP as i32 + 1, code: Some(0), signal: None },
        )
        .await;
        wait_for(&link, |s| s.unknown_exits == 1).await;
        let stats = link.stats();
        assert_eq!(stats.early_exits, CAP);
        assert_eq!(stats.overflow_drops, 2);

        // Detached-exec lifecycle: after Started the supervisor drops the
        // registration (init never reports a detached exec's exit), so a late
        // frame for that pid is expected-silent: dropped + counted, buffered
        // nowhere.
        const DETACHED: i32 = 77;
        let detach_req = Req::RunExec {
            argv: vec!["true".into()],
            env: vec![],
            cwd: None,
            detach: true,
            clean_env: false,
            extra_writable: vec![],
            bind_ports: vec![],
        };
        let announcer = spawn_init_announcer(child, vec![DETACHED]);
        match link.request(&detach_req, &[]).await.expect("request must be answered") {
            Resp::Started { pid } => assert_eq!(pid, DETACHED),
            other => panic!("expected Started, got {:?}", other),
        }
        let mut child = announcer.await.expect("init announcer");
        assert_eq!(link.stats().announced, 1);
        // handle_exec's detach branch drops the registration after Started.
        link.forget_detached(DETACHED);
        assert_eq!(link.stats().announced, 0);
        write_resp(
            &mut child,
            &Resp::Exited { pid: DETACHED, code: Some(0), signal: None },
        )
        .await;
        wait_for(&link, |s| s.unknown_exits == 2).await;
        let stats = link.stats();
        assert_eq!(stats.early_exits, CAP);
        assert_eq!(stats.announced, 0);
        assert_eq!(stats.unknown_exits, 2);
        assert_eq!(stats.overflow_drops, 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_unknown_pid_exit_frame_bounded() {
        // Default (unconfigured) cap: 1024.
        const FORGED: i32 = 424_242;
        const UNKNOWN_FRAMES: u64 = 60_000;
        let (link, child) = reader_driven_link(InitLink::DEFAULT_EARLY_EXIT_CAP);
        assert_eq!(link.stats().early_exit_cap, 1024);
        let req = Req::RunExec {
            argv: vec!["true".into()],
            env: vec![],
            cwd: None,
            detach: false,
            clean_env: false,
            extra_writable: vec![],
            bind_ports: vec![],
        };

        // (a) A forged Exited whose pid matches a FUTURE exec (announced only
        // later) must be dropped as unknown — never buffered — so it cannot
        // become that exec's recorded exit.
        // The fake init writes the forged frame BEFORE its real Started, while
        // the supervisor's request is already in flight.
        let mut child = child;
        let announcer = tokio::spawn(async move {
            let payload = read_req_frame(&mut child).await;
            assert!(String::from_utf8_lossy(&payload).contains("req"));
            write_resp(
                &mut child,
                &Resp::Exited { pid: FORGED, code: Some(9), signal: None },
            )
            .await;
            write_resp(&mut child, &Resp::Started { pid: FORGED }).await;
            child
        });
        match link.request(&req, &[]).await.expect("request must be answered") {
            Resp::Started { pid } => assert_eq!(pid, FORGED),
            other => panic!("expected Started, got {:?}", other),
        }
        let mut child = announcer.await.expect("fake init");
        // Deterministic: the forged frame precedes Started on the socket, so it
        // was routed (and dropped as unknown) before the request resolved.
        assert_eq!(link.stats().unknown_exits, 1);
        assert_eq!(link.stats().early_exits, 0, "forged frame must not buffer");

        // handle_exec then registers its waiter for the announced pid.
        assert_eq!(link.stats().announced, 1);
        let mut rx = link.register_exit(FORGED);
        assert!(
            matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
            "a forged pre-announcement Exited must never resolve an exec waiter"
        );

        // (b) 60k forged frames for never-announced pids: all dropped, memory
        // stays flat (acceptance: RSS growth < 1 MB after 60k frames).
        let before = rss_bytes();
        for i in 0..UNKNOWN_FRAMES {
            write_resp(
                &mut child,
                &Resp::Exited {
                    pid: 1_000_000 + i as i32,
                    code: Some(1),
                    signal: None,
                },
            )
            .await;
        }
        wait_for(&link, |s| s.unknown_exits == UNKNOWN_FRAMES + 1).await;
        let stats = link.stats();
        assert_eq!(stats.unknown_exits, UNKNOWN_FRAMES + 1);
        assert_eq!(stats.early_exits, 0, "unknown frames must never buffer");
        assert_eq!(stats.overflow_drops, 0);
        let grown = rss_bytes().saturating_sub(before);
        assert!(
            grown < 1024 * 1024,
            "60k forged Exited frames must grow RSS by < 1 MB (grew {} bytes)",
            grown
        );

        // (c) Only the real wait path decides the exit: init's genuine Exited
        // for the registered pid resolves the waiter with its exact values.
        write_resp(
            &mut child,
            &Resp::Exited { pid: FORGED, code: Some(0), signal: None },
        )
        .await;
        let resp = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("real Exited must resolve the waiter")
            .expect("oneshot must not be canceled before delivery");
        match resp {
            Resp::Exited { pid, code, signal } => {
                assert_eq!(pid, FORGED);
                assert_eq!(code, Some(0));
                assert_eq!(signal, None);
            }
            other => panic!("expected real Exited, got {:?}", other),
        }
        let stats = link.stats();
        assert_eq!(stats.announced, 0, "waiter resolution clears the registry");
        assert_eq!(stats.unknown_exits, UNKNOWN_FRAMES + 1);
        assert_eq!(stats.early_exits, 0);
        assert_eq!(stats.overflow_drops, 0);
    }

    // ── F1.8: per-request deadline + Dead link (fork-plan-2026-09 F1.8) ─────
    //
    // Reader-driven like the F1.2 pair: a real socketpair feeds the same
    // `InitLink` + `reader_task` path the live supervisor runs, and the test
    // owns the peer end, playing a sandlock-init that answers one request and
    // then goes silent. No live-supervisor harness verb can inject a hang
    // (there is no protocol frame that makes init stop answering; a real wedge
    // would need process-state surgery on a root-mode e2e container), so the
    // wedge is expressed at the exact injection point — the request await —
    // with a short configurable deadline (see tmp/sdd/f1.8-report.md).
    #[tokio::test(flavor = "multi_thread")]
    async fn test_request_timeout_returns_error_within_deadline() {
        const TIMEOUT: Duration = Duration::from_millis(200);
        assert_eq!(
            InitLink::DEFAULT_REQUEST_TIMEOUT,
            Duration::from_secs(5),
            "production default deadline must stay 5s"
        );
        let (link, child) = reader_driven_link_with_timeout(TIMEOUT);
        let req = Req::RunExec {
            argv: vec!["true".into()],
            env: vec![],
            cwd: None,
            detach: false,
            clean_env: false,
            extra_writable: vec![],
            bind_ports: vec![],
        };

        // (a) One healthy request/Started round-trip announces pid 111, then
        // register the attached-exec waiter the supervisor would hold — the
        // exit-waiter that Dead must NOT clear.
        let announcer = spawn_init_announcer(child, vec![111]);
        match link.request(&req, &[]).await.expect("request must be answered") {
            Resp::Started { pid } => assert_eq!(pid, 111),
            other => panic!("expected Started, got {:?}", other),
        }
        let mut child = announcer.await.expect("init announcer");
        let mut exit_rx = link.register_exit(111);
        assert_eq!(link.stats().announced, 1);

        // (b) Peer goes silent: the request must fail at ~the configured
        // deadline (within the deadline + 1s acceptance), never hang.
        let started = tokio::time::Instant::now();
        let err = link
            .request(&req, &[])
            .await
            .expect_err("request to a silent peer must return an error");
        let elapsed = started.elapsed();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            err.to_string(),
            "request to sandlock-init timed out after 200ms (no reply); \
             control link marked Dead: late replies are discarded and further requests fail fast"
        );
        assert!(
            elapsed >= TIMEOUT.saturating_sub(Duration::from_millis(50)),
            "request returned before its deadline elapsed ({:?})",
            elapsed
        );
        assert!(
            elapsed <= TIMEOUT + Duration::from_secs(1),
            "request exceeded the deadline + 1s acceptance ({:?})",
            elapsed
        );
        {
            let st = link.state.lock().unwrap();
            assert!(st.dead, "a timeout must mark the link Dead");
            assert!(
                st.pending.is_none(),
                "a timeout must clear the pending sender so late replies are discarded"
            );
            assert!(
                st.exit_waiters.contains_key(&111),
                "Dead must not clear registered exit waiters"
            );
        }
        assert!(link.stats().dead, "Dead must be visible in the stats snapshot");

        // (c) Second request on the Dead link: fail fast, without sending and
        // without waiting out another deadline.
        let started = tokio::time::Instant::now();
        let err = link
            .request(&req, &[])
            .await
            .expect_err("request on a Dead link must fail");
        let elapsed = started.elapsed();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            err.to_string(),
            "init control link is Dead (an earlier request timed out); request not sent"
        );
        assert!(
            elapsed < TIMEOUT,
            "Dead request must fail fast, waited {:?}",
            elapsed
        );

        // (d) The exit waiter registered before the timeout is untouched: the
        // announced child's genuine Exited still resolves it exactly.
        write_resp(
            &mut child,
            &Resp::Exited { pid: 111, code: Some(7), signal: None },
        )
        .await;
        let resp = tokio::time::timeout(Duration::from_secs(5), &mut exit_rx)
            .await
            .expect("genuine Exited must resolve the waiter")
            .expect("oneshot must not be canceled by Dead");
        match resp {
            Resp::Exited { pid, code, signal } => {
                assert_eq!(pid, 111);
                assert_eq!(code, Some(7));
                assert_eq!(signal, None);
            }
            other => panic!("expected Exited, got {:?}", other),
        }

        // (e) The timed-out request's late Started arrives after Dead: with no
        // pending sender it must be discarded without announcing the pid.
        write_resp(&mut child, &Resp::Started { pid: 4242 }).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        {
            let st = link.state.lock().unwrap();
            assert!(st.dead);
            assert!(st.pending.is_none());
            assert!(
                !st.announced.contains(&4242),
                "a late Started must not announce a pid on a Dead link"
            );
            assert!(st.announced.is_empty(), "waiter resolution consumed pid 111");
            assert!(st.exit_waiters.is_empty());
            assert!(st.early_exits.is_empty());
            assert_eq!(st.unknown_exits, 0);
        }
    }
}
