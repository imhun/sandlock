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
    /// Pids init announced in a `Started` whose reply could never be
    /// delivered: the request's deadline already discarded `pending` (late
    /// reply) or the requesting task was cancelled, so the host never
    /// registered the child. The child is real (init spawned it), so it must
    /// still be collapsed at teardown — otherwise a deadline-orphaned child
    /// would escape the Drop backstop (reviewer I1). Bounded by
    /// `early_exit_cap`; an overflow is counted in `overflow_drops`.
    stray_pids: Vec<i32>,
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
    /// F5.4: sticky record that the main workload's (child id 0) `Exited`
    /// frame was routed before the channel terminated. init sends that frame
    /// immediately before its deliberate main-exit collapse, so its presence
    /// distinguishes a graceful container end (`Exited` phase) from an
    /// unexpected init death (`Dead` phase).
    main_exit_seen: bool,
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
                stray_pids: Vec::new(),
                unknown_exits: 0,
                overflow_drops: 0,
                early_exit_cap: DEFAULT_EARLY_EXIT_CAP,
                dead: false,
                terminated: false,
                main_exit_seen: false,
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
        let bytes = proto::encode_frame(FrameKind::Req, &payload, fds.len() as u8)
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
        let bytes = match proto::encode_frame(FrameKind::Req, &payload, 0) {
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

    /// Whether the init channel terminated (init exited / the reader saw
    /// EOF) as opposed to the link merely being marked Dead by a timed-out
    /// request. Used by the instance to observe the exec-mode terminal state.
    pub(crate) fn is_terminated(&self) -> bool {
        self.state.lock().unwrap().terminated
    }

    /// Whether the link was marked Dead by a request deadline (as opposed to
    /// merely terminated by channel EOF).
    pub(crate) fn is_dead(&self) -> bool {
        self.state.lock().unwrap().dead
    }

    /// Whether the main child's (child id 0) `Exited` frame was routed before
    /// the channel terminated — the signature of init's deliberate main-exit
    /// collapse (F5.4).
    pub(crate) fn main_exit_reported(&self) -> bool {
        self.state.lock().unwrap().main_exit_seen
    }

    /// Whether any `wait_child` exit waiter is currently registered
    /// (F5.5 idle eligibility: a pending subscriber keeps the session
    /// non-idle).
    pub(crate) fn has_exit_waiters(&self) -> bool {
        !self.state.lock().unwrap().exit_waiters.is_empty()
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

    /// Snapshot of the deadline-orphaned/stray pids recorded by the reader
    /// (children init announced but the host never registered). Teardown
    /// sweeps their process groups before clearing.
    pub(crate) fn stray_pids(&self) -> Vec<i32> {
        self.state.lock().unwrap().stray_pids.clone()
    }

    /// Drop the stray-pid record after the teardown sweep has signalled them.
    pub(crate) fn clear_strays(&self) {
        self.state.lock().unwrap().stray_pids.clear();
    }

    /// Best-effort synchronous `Shutdown` frame for the Drop backstop:
    /// init collapses **all** of its children (registered, stray and
    /// grandchild groups) before the host reaps it. `try_lock` means this
    /// never blocks an in-flight async request; if the writer is busy the
    /// caller's registered+stray group sweep below is the deterministic
    /// fallback.
    pub(crate) fn send_shutdown_sync(&self) {
        let Ok(writer) = self.writer.try_lock() else {
            return;
        };
        let payload = match serde_json::to_vec(&Req::Shutdown) {
            Ok(p) => p,
            Err(_) => return,
        };
        let bytes = match proto::encode_frame(FrameKind::Req, &payload, 0) {
            Ok(b) => b,
            Err(_) => return,
        };
        let _ = fdpass::send_with_fds(&writer, &bytes, &[]);
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
                // request. A stray one (no pending request) means either a
                // forged frame or — the real case this guard exists for — a
                // late reply whose request deadline already discarded
                // `pending` (F1.8). Either way the pid is **not** announced;
                // but when the frame is real, init has spawned a live child
                // the host never registered. Record it so teardown collapses
                // it (reviewer I1); it never resolves a waiter either way.
                if let Some(pending) = st.pending.take() {
                    st.pid_to_child.insert(pid, pending.child_id);
                    if pending.tx.send(Resp::Started { pid }).is_err() {
                        // The requesting task is gone (deadline exceeded —
                        // link Dead — or the task was canceled), so its
                        // receiver was dropped before this reply was routed.
                        // The child is real but was never registered
                        // host-side: remove the announcement and keep the pid
                        // for the teardown sweep.
                        st.pid_to_child.remove(&pid);
                        record_stray(&mut st, pid);
                    }
                } else {
                    record_stray(&mut st, pid);
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
                if child_id == 0 {
                    st.main_exit_seen = true;
                }
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

/// Record a pid init announced but the host never registered (deadline-
/// orphaned child or forged frame), bounded by the early-exit cap.
fn record_stray(st: &mut ExecLinkState, pid: i32) {
    if st.stray_pids.len() < st.early_exit_cap {
        st.stray_pids.push(pid);
    } else {
        st.overflow_drops += 1;
    }
}

/// Open a host-side pidfd for an announced child (`-1` when the kernel or the
/// child's liveness refuses). This is the per-child signal handle: kill_child
/// never sends a pid-addressed signal verb to init (F1.7) — the registry
/// resolves the child token to this fd.
pub(crate) fn open_child_pidfd(pid: i32) -> Option<std::os::fd::OwnedFd> {
    crate::sys::syscall::pidfd_open(pid as u32, 0).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{Duration, Instant};

    fn started_frame(pid: i32) -> Vec<u8> {
        let payload = serde_json::to_vec(&Resp::Started { pid }).unwrap();
        proto::encode_frame(FrameKind::Resp, &payload, 0).unwrap()
    }

    async fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if cond() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Reviewer I1 branch (a): a `Started` that arrives after its request's
    /// deadline discarded `pending` is a **real child init spawned** but one
    /// the host never registered. The reader must record the pid for the
    /// teardown sweep instead of silently dropping it — otherwise a
    /// deadline-orphaned child escapes the Drop backstop. (A forged frame is
    /// treated the same way; the host may sweep a same-uid pid its sandbox
    /// could already signal itself.)
    #[tokio::test]
    async fn late_started_without_pending_is_recorded_for_teardown() {
        let (daemon, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let writer = daemon.try_clone().unwrap();
        daemon.set_nonblocking(true).unwrap();
        let reader = tokio::net::UnixStream::from_std(daemon).unwrap();
        let link = ExecLink::new(writer, reader);

        // No request in flight: the F1.8 deadline already took `pending`.
        peer.write_all(&started_frame(4242)).unwrap();
        assert!(
            wait_until(|| link.stray_pids().contains(&4242)).await,
            "late Started must be recorded as a teardown stray"
        );
        assert!(
            link.state.lock().unwrap().pid_to_child.is_empty(),
            "a stray Started is never announced"
        );

        peer.write_all(&started_frame(4243)).unwrap();
        assert!(wait_until(|| link.stray_pids().contains(&4243)).await);
        assert_eq!(link.stray_pids(), vec![4242, 4243]);
        assert!(!link.is_closed(), "recording strays must not close the link");
    }

    /// Reviewer I1 branch (b): the reader routed the `Started` (announced the
    /// pid) but the requesting task's receiver was already dropped (deadline
    /// fired / caller cancelled). The announcement must be retracted **and**
    /// the pid kept for the teardown sweep — same orphan risk as branch (a).
    #[tokio::test]
    async fn started_with_dropped_receiver_is_recorded_for_teardown() {
        let (daemon, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let writer = daemon.try_clone().unwrap();
        daemon.set_nonblocking(true).unwrap();
        let reader = tokio::net::UnixStream::from_std(daemon).unwrap();
        let link = ExecLink::new(writer, reader);

        let (tx, rx) = oneshot::channel();
        drop(rx); // the deadline/cancel dropped the reply receiver
        link.state.lock().unwrap().pending =
            Some(PendingReply { child_id: 9, tx });

        peer.write_all(&started_frame(5555)).unwrap();
        assert!(
            wait_until(|| link.stray_pids().contains(&5555)).await,
            "a Started whose receiver was dropped must be recorded as a stray"
        );
        assert!(
            link.state.lock().unwrap().pid_to_child.is_empty(),
            "an undeliverable Started must not stay announced"
        );
    }
}
