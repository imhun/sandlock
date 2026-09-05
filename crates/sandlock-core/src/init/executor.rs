//! Daemon-side executor for an exec-capable [`SandboxInstance`] session.
//!
//! F3.2's per-child verbs (`exec`, `wait_child`, `kill_child`) drive one
//! confined `sandlock-init` control loop through this link. It is the core
//! home of the demux semantics that previously lived in the OCI supervisor's
//! `InitLink`:
//!
//! * requests are serialized (the writer lock is held across each reply
//!   await) and each immediate `Started`/`Err` reply is paired with its
//!   request;
//! * exits are routed **per child id** through the announced registry
//!   (F1.2): a `Started{pid}` announces `pid -> child id`, and an
//!   `Exited{pid}` for an announced child resolves the child's waiter (or is
//!   buffered in the bounded `early_exits` set when the waiter has not
//!   registered yet). An `Exited` for a pid that was never announced is
//!   dropped and counted — it can never resolve a waiter;
//! * every request has a deadline (F1.8). A deadline miss marks the link
//!   Dead and every later request fails fast with the unified
//!   closed-instance error, exactly like a completed `shutdown` or a closed
//!   channel (F5.4 S5 semantics, reserved on F3.2's terms);
//! * channel teardown (init exited — the main child died, or Shutdown ran)
//!   resolves every pending waiter with `ExitStatus::Killed` so no waiter
//!   hangs, and marks the link terminated.
//!
//! The wire itself is unchanged from the F3.1 move: pid-keyed
//! `Started`/`Exited` frames over the SLKF envelope. Child ids are a
//! **host-side** token assigned by this executor; kill/teardown never send a
//! pid-addressed signal verb to init (F1.7 posture) — per-child signals go
//! through the pidfds this executor opened for its own registered children.

use std::collections::HashMap;
use std::os::fd::RawFd;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use tokio::sync::{oneshot, Mutex as TokioMutex};

use crate::error::{SandboxRuntimeError, SandlockError};
use crate::init::proto::{self, FrameKind};
use crate::init::{fdpass, Req, Resp};
use crate::result::ExitStatus;

/// Default cap on buffered early-exit frames per exec session (F1.2).
const DEFAULT_EARLY_EXIT_CAP: usize = 1024;

/// Default per-request reply deadline (F1.8).
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The reply expected for the in-flight request.
struct PendingReply {
    /// Child id the in-flight request belongs to. A `Started{pid}` for it
    /// announces `pid -> child_id` in the registry.
    child_id: u64,
    tx: oneshot::Sender<Resp>,
}

/// Routing state shared between the request path and the reader task.
struct ExecLinkState {
    pending: Option<PendingReply>,
    /// Per-child exit waiters (keyed by child id, registered on demand by
    /// `wait_child`).
    exit_waiters: HashMap<u64, oneshot::Sender<ExitStatus>>,
    /// Exits that arrived before a waiter registered (bounded by
    /// `early_exit_cap`).
    early_exits: HashMap<u64, ExitStatus>,
    /// Announced pids (F1.2): the only pids whose `Exited` may resolve a
    /// waiter. Inserted when a `Started` is routed; removed when its
    /// `Exited` is consumed.
    pid_to_child: HashMap<i32, u64>,
    /// `Exited` frames dropped because the pid was never announced.
    unknown_exits: u64,
    /// `Exited` frames dropped because `early_exits` was full.
    overflow_drops: u64,
    /// Maximum `early_exits` size.
    early_exit_cap: usize,
    /// True once a request exceeded its deadline: requests fail fast and the
    /// in-flight reply is discarded.
    dead: bool,
    /// True once the channel closed (init exited / Shutdown completed):
    /// requests fail fast with the closed-instance error.
    terminated: bool,
    /// Per-request reply deadline.
    request_timeout: Duration,
}

/// The daemon half of the control channel to a confined `sandlock-init`.
pub(crate) struct ExecLink {
    writer: TokioMutex<std::os::unix::net::UnixStream>,
    state: StdMutex<ExecLinkState>,
}

impl ExecLink {
    /// Build the link over `writer` (a blocking dup used for `sendmsg`) and
    /// `reader` (a tokio stream the background reader task demuxes), and
    /// start the reader task. Must be called inside a tokio runtime.
    pub(crate) fn new(
        writer: std::os::unix::net::UnixStream,
        reader: tokio::net::UnixStream,
    ) -> std::sync::Arc<ExecLink> {
        let link = std::sync::Arc::new(ExecLink {
            writer: TokioMutex::new(writer),
            state: StdMutex::new(ExecLinkState {
                pending: None,
                exit_waiters: HashMap::new(),
                early_exits: HashMap::new(),
                pid_to_child: HashMap::new(),
                unknown_exits: 0,
                overflow_drops: 0,
                early_exit_cap: DEFAULT_EARLY_EXIT_CAP,
                dead: false,
                terminated: false,
                request_timeout: DEFAULT_REQUEST_TIMEOUT,
            }),
        });
        let weak = std::sync::Arc::downgrade(&link);
        tokio::spawn(async move {
            if let Some(link) = weak.upgrade() {
                reader_task(&link, reader).await;
            }
        });
        link
    }

    /// Send a request (optionally with SCM_RIGHTS `fds`) and return its
    /// immediate `Started`/`Err` reply for `child_id`. The writer lock is
    /// held across the await so requests are serialized and each reply pairs
    /// with its request.
    ///
    /// A request whose reply does not arrive within the deadline fails with
    /// the unified closed-instance error and marks the link Dead (F1.8); a
    /// link that is already Dead or terminated fails fast without sending.
    pub(crate) async fn request(
        &self,
        child_id: u64,
        req: &Req,
        fds: &[RawFd],
    ) -> Result<Resp, SandlockError> {
        if self.is_closed() {
            return Err(SandboxRuntimeError::InstanceClosed.into());
        }
        let payload = serde_json::to_vec(req)
            .map_err(|e| SandboxRuntimeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())))?;
        let bytes = proto::encode_frame(FrameKind::Req, &payload)
            .map_err(|e| SandboxRuntimeError::Io(e))?;
        let writer = self.writer.lock().await;
        // Re-check under the writer lock: the only way the link turns closed
        // is a timed-out request (which marks it while still holding this
        // lock) or the reader teardown; a request that passed the first check
        // must not send afterwards.
        if self.is_closed() {
            return Err(SandboxRuntimeError::InstanceClosed.into());
        }
        let (tx, rx) = oneshot::channel();
        let request_timeout = {
            let mut st = self.state.lock().unwrap();
            st.pending = Some(PendingReply { child_id, tx });
            st.request_timeout
        };
        fdpass::send_with_fds(&writer, &bytes, fds)
            .map_err(|e| SandboxRuntimeError::Io(e))?;
        let reply = tokio::time::timeout(request_timeout, rx).await;
        if reply.is_err() {
            // Deadline exceeded. Still holding the writer lock, so no other
            // request can interleave: drop the reply sender (a late reply is
            // then discarded by `reader_task`) and mark the link Dead.
            let mut st = self.state.lock().unwrap();
            st.pending.take();
            st.dead = true;
        }
        drop(writer);
        match reply {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(SandboxRuntimeError::InstanceClosed.into()),
            Err(_) => Err(SandboxRuntimeError::InstanceClosed.into()),
        }
    }

    /// Send a fire-and-forget `Shutdown` request. Init acts on the frame and
    /// exits without replying; the reader sees EOF and tears the link down.
    pub(crate) async fn send_shutdown(&self) {
        let payload = match serde_json::to_vec(&Req::Shutdown) {
            Ok(p) => p,
            Err(_) => return,
        };
        let bytes = match proto::encode_frame(FrameKind::Req, &payload) {
            Ok(b) => b,
            Err(_) => return,
        };
        let writer = self.writer.lock().await;
        let _ = fdpass::send_with_fds(&writer, &bytes, &[]);
    }

    /// Register interest in the exit of `child_id`. If the exit was already
    /// reported (buffered), the receiver resolves immediately with the real
    /// status; if the link already terminated and nothing was buffered, the
    /// receiver resolves immediately with `Killed`.
    pub(crate) fn register_exit(&self, child_id: u64) -> oneshot::Receiver<ExitStatus> {
        let (tx, rx) = oneshot::channel();
        let mut st = self.state.lock().unwrap();
        if let Some(status) = st.early_exits.remove(&child_id) {
            let _ = tx.send(status);
        } else if st.terminated {
            let _ = tx.send(ExitStatus::Killed);
        } else {
            st.exit_waiters.insert(child_id, tx);
        }
        rx
    }

    /// Whether the link is Dead or terminated — every later request fails
    /// fast with the unified closed-instance error.
    pub(crate) fn is_closed(&self) -> bool {
        let st = self.state.lock().unwrap();
        st.dead || st.terminated
    }

    /// Drain every buffered early exit into `out` (used by shutdown so real
    /// exit statuses are preserved before the session closes).
    pub(crate) fn drain_early_exits(&self, out: &mut HashMap<u64, ExitStatus>) {
        let mut st = self.state.lock().unwrap();
        for (child_id, status) in st.early_exits.drain() {
            out.entry(child_id).or_insert(status);
        }
    }

    /// Mark the link closed without waiting for reader EOF (used by the
    /// synchronous Drop backstop after the init channel has been torn down).
    pub(crate) fn mark_terminated(&self) {
        let mut st = self.state.lock().unwrap();
        st.terminated = true;
        st.pending.take();
        for (_, tx) in st.exit_waiters.drain() {
            let _ = tx.send(ExitStatus::Killed);
        }
        st.pid_to_child.clear();
    }
}

/// Map an init exit reply into the core `ExitStatus` (SIGKILL bottoms out to
/// [`ExitStatus::Killed`], matching the rest of the crate).
fn exit_status_from_resp(resp: Resp) -> ExitStatus {
    match resp {
        Resp::Exited { code: Some(c), .. } => ExitStatus::Code(c),
        Resp::Exited { signal: Some(s), .. } if s == libc::SIGKILL => ExitStatus::Killed,
        Resp::Exited { signal: Some(s), .. } => ExitStatus::Signal(s),
        _ => ExitStatus::Killed,
    }
}

/// Read one framed `Resp` payload from init (mirrors the OCI supervisor's
/// frame reader). `Ok(None)` is a clean EOF at a frame boundary.
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
    let kind = proto::decode_header(&header).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad control frame from sandlock-init: {e}"),
        )
    })?;
    if kind != FrameKind::Resp {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sandlock-init sent a req-type control frame to the daemon",
        ));
    }
    let len = u32::from_le_bytes(header[6..10].try_into().expect("10-byte header")) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "truncated control frame payload from sandlock-init",
        )
    })?;
    Ok(Some(payload))
}

/// Background reader: decode framed `Resp` frames from init and route each
/// through the announced registry (F1.2). init never sends fds to the daemon,
/// so a plain frame reader is sufficient.
async fn reader_task(link: &std::sync::Arc<ExecLink>, mut reader: tokio::net::UnixStream) {
    loop {
        let payload = match read_resp_frame(&mut reader).await {
            Ok(Some(p)) => p,
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
                // it entirely rather than announcing a child that never
                // existed.
                if let Some(pending) = st.pending.take() {
                    st.pid_to_child.insert(pid, pending.child_id);
                    if pending.tx.send(Resp::Started { pid }).is_err() {
                        // The requesting task is gone (deadline exceeded —
                        // link Dead — or the task was canceled), so its
                        // receiver was dropped before this reply was routed.
                        // A Started that was never delivered must leave no
                        // registry entry.
                        st.pid_to_child.remove(&pid);
                    }
                }
            }
            Resp::Err { .. } => {
                if let Some(pending) = st.pending.take() {
                    let _ = pending.tx.send(resp);
                }
            }
            Resp::Exited { pid, .. } => {
                let child_id = match st.pid_to_child.remove(&pid) {
                    Some(id) => id,
                    // Never announced (and no waiter): forged/unknown frame.
                    None => {
                        st.unknown_exits += 1;
                        continue;
                    }
                };
                let status = exit_status_from_resp(resp);
                if let Some(tx) = st.exit_waiters.remove(&child_id) {
                    let _ = tx.send(status);
                } else if st.early_exits.len() < st.early_exit_cap {
                    // Early-exit race: announced but the waiter has not
                    // registered yet. Buffer it, bounded by the cap.
                    st.early_exits.insert(child_id, status);
                } else {
                    st.overflow_drops += 1;
                }
            }
        }
    }
    // Channel closed: drop the pending reply sender (a request awaiting a
    // reply unblocks with the closed-instance error), resolve every pending
    // waiter as Killed (nothing may hang on a session whose init is gone),
    // and mark the link terminated so later requests fail fast.
    let mut st = link.state.lock().unwrap();
    st.pending.take();
    for (_, tx) in st.exit_waiters.drain() {
        let _ = tx.send(ExitStatus::Killed);
    }
    st.pid_to_child.clear();
    st.terminated = true;
}

/// Open a host-side pidfd for an announced child (`-1` when the kernel or the
/// child's liveness refuses). This is the per-child signal handle: kill_child
/// never sends a pid-addressed signal verb to init (F1.7) — the registry
/// resolves the child token to this fd.
pub(crate) fn open_child_pidfd(pid: i32) -> Option<std::os::fd::OwnedFd> {
    crate::sys::syscall::pidfd_open(pid as u32, 0).ok()
}
