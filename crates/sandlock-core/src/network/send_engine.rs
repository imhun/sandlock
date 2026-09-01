// Execute phase: the only code that performs on-behalf sends.
//
// Consumes MaterializedMsg values (already parsed, validated, and owned)
// and resolves them to a terminal NotifAction, deferring off the
// notification loop when a blocking child's send cannot complete on the
// first non-blocking attempt.

use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

use crate::seccomp::notif::{write_child_mem, NotifAction};

use super::materialize::MaterializedMsg;

/// True iff this send should block until it completes: the socket is in blocking
/// mode (`O_NONBLOCK` clear — the dup shares the child's file description, so it
/// reflects the child's own mode) *and* the per-call `send_flags` did not request
/// non-blocking with `MSG_DONTWAIT`. A child that passes `MSG_DONTWAIT` on a
/// blocking socket wants the immediate short-count/`EAGAIN`, not a deferred
/// block-to-completion, so it must not be deferred.
pub(crate) fn wants_blocking(fd: RawFd, send_flags: i32) -> bool {
    if send_flags & libc::MSG_DONTWAIT != 0 {
        return false;
    }
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    fl >= 0 && (fl & libc::O_NONBLOCK) == 0
}

/// One `sendmsg` of `m` starting at byte `offset`. The destination address and
/// control ancillary are attached only at `offset == 0`: `SCM_RIGHTS` transmits
/// exactly once, and a stream continuation carries no new address. Returns the
/// kernel result (>= 0 bytes, or -1 with errno in `*__errno_location`).
fn send_materialized_at(fd: RawFd, m: &MaterializedMsg, offset: usize, flags: i32) -> isize {
    let iov = libc::iovec {
        iov_base: unsafe { m.data.as_ptr().add(offset) } as *mut libc::c_void,
        iov_len: m.data.len() - offset,
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    if offset == 0 {
        if !m.addr.is_empty() {
            msg.msg_name = m.addr.as_ptr() as *mut libc::c_void;
            msg.msg_namelen = m.addr.len() as u32;
        }
        if let Some(ref c) = m.control {
            msg.msg_control = c.as_ptr() as *mut libc::c_void;
            msg.msg_controllen = c.len();
        }
    }
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    unsafe { libc::sendmsg(fd, &msg, flags) }
}

/// Resolve a materialized send to a terminal action. The first attempt is
/// non-blocking (`MSG_DONTWAIT`) on the seccomp loop, so it never blocks there.
/// A non-blocking child gets whatever that one attempt returns (short count or
/// `EAGAIN`), exactly as the kernel would give it. A blocking child whose whole
/// message didn't fit is completed off the loop (`defer_send`), preserving the
/// kernel's "a blocking send of N returns N" contract without occupying the
/// loop or a worker thread — a stream send that partially fit continues from
/// the sent offset; a full send buffer defers from offset 0.
pub(crate) fn resolve_send(dup_fd: OwnedFd, m: MaterializedMsg, flags: i32, child_blocking: bool) -> NotifAction {
    let ret = send_materialized_at(dup_fd.as_raw_fd(), &m, 0, flags | libc::MSG_DONTWAIT);
    if ret >= 0 {
        let sent = ret as usize;
        if !child_blocking || sent >= m.data.len() {
            return NotifAction::ReturnValue(ret as i64);
        }
        // Blocking stream socket, partial fit: finish the remainder off the loop.
        return NotifAction::defer(defer_send(dup_fd, m, flags, sent));
    }
    let err = unsafe { *libc::__errno_location() };
    if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
        if child_blocking {
            return NotifAction::defer(defer_send(dup_fd, m, flags, 0));
        }
        return NotifAction::Errno(libc::EAGAIN);
    }
    NotifAction::Errno(err)
}

/// Byte-level completion core: await writability on the dup'd fd through the
/// Tokio IO driver's epoll (never blocking a worker thread) and push the rest of
/// the message, advancing `offset` past each partial send, until the whole
/// message is delivered or a real error occurs. Bounded by the supervisor's
/// deferred-work timeout, so a peer that never drains can wedge only this one
/// send for that bound — never the notification loop.
///
/// `Ok(n)` is the total bytes sent: the full length on success, or the bytes
/// queued before a hard error interrupted a partially-sent stream. `Err(e)` is
/// returned only when nothing at all was sent. Shared by the single-message
/// deferral ([`defer_send`]) and the batch tail ([`complete_batch_entry`]).
async fn push_until_done(
    dup_fd: OwnedFd,
    m: MaterializedMsg,
    flags: i32,
    mut offset: usize,
) -> Result<usize, i32> {
    let afd = tokio::io::unix::AsyncFd::with_interest(dup_fd, tokio::io::Interest::WRITABLE)
        .map_err(|_| libc::EIO)?;
    loop {
        let mut guard = afd.writable().await.map_err(|_| libc::EIO)?;
        let ret = send_materialized_at(afd.get_ref().as_raw_fd(), &m, offset, flags | libc::MSG_DONTWAIT);
        if ret >= 0 {
            offset += ret as usize;
            if offset >= m.data.len() {
                return Ok(m.data.len());
            }
            // More to send; the next writability edge (or an EAGAIN below) gates it.
            continue;
        }
        let err = unsafe { *libc::__errno_location() };
        if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
            guard.clear_ready();
            continue;
        }
        return if offset > 0 { Ok(offset) } else { Err(err) };
    }
}

/// Deferred tail of [`resolve_send`] for a single message: complete the send and
/// return the byte count (matching a blocking send of N returning N; a partial
/// stream then error returns the partial count).
async fn defer_send(dup_fd: OwnedFd, m: MaterializedMsg, flags: i32, offset: usize) -> NotifAction {
    match push_until_done(dup_fd, m, flags, offset).await {
        Ok(n) => NotifAction::ReturnValue(n as i64),
        Err(e) => NotifAction::Errno(e),
    }
}

/// Deferred tail shared by the three `sendmmsg` batch loops. Completes entry
/// `prior_count` (which either would-block entirely, offset 0, or partially sent
/// a stream, offset > 0) off the loop, then reports the *message* count — not a
/// byte count — as `sendmmsg` requires.
///
/// Aligns with the kernel's blocking-stream semantics: a `sendmsg` that makes
/// any progress returns that byte count and is a completed message; a hard error
/// after partial progress surfaces on the child's *next* call. So for any
/// `Ok(n)` (n is the full length on success, or the bytes queued before a hard
/// error) we write `n` back as this entry's `msg_len` and count it as
/// `prior_count + 1`. This never returns 0 for `vlen > 0`, and — crucially —
/// never leaves an already-queued entry uncounted, which would make the child
/// re-send bytes the kernel already accepted (duplicate data) or spin forever on
/// a zero-progress retry. `Err(e)` (nothing sent at all) reports the errno only
/// when nothing has been sent yet (`prior_count == 0`), else the prior count.
/// Entries beyond this one are left for the child to retry, so the batch is
/// never materialized whole.
fn complete_batch_entry(
    dup_fd: OwnedFd,
    m: MaterializedMsg,
    flags: i32,
    offset: usize,
    notif_fd: RawFd,
    notif_id: u64,
    notif_pid: u32,
    msglen_addr: u64,
    prior_count: usize,
) -> NotifAction {
    NotifAction::defer(async move {
        match push_until_done(dup_fd, m, flags, offset).await {
            Ok(n) => {
                let bytes = (n as u32).to_ne_bytes();
                let _ = write_child_mem(notif_fd, notif_id, notif_pid, msglen_addr, &bytes);
                NotifAction::ReturnValue((prior_count + 1) as i64)
            }
            Err(e) => {
                if prior_count == 0 {
                    NotifAction::Errno(e)
                } else {
                    NotifAction::ReturnValue(prior_count as i64)
                }
            }
        }
    })
}

/// Outcome of one `sendmmsg` batch entry.
pub(crate) enum BatchStep {
    /// Entry completed inline; its `msg_len` was written back. Count it and
    /// move to the next entry.
    Sent,
    /// Entry left the loop (entry 0 fully blocked, or a blocking stream entry
    /// that partially sent); the whole syscall resolves to this action.
    Done(NotifAction),
    /// Batch stops at this entry; the errno to report when nothing was sent.
    Stop(i32),
}

/// Execute phase for one batch entry, shared by the three `sendmmsg` loops:
/// one `MSG_DONTWAIT` attempt on the notification loop, then the only two
/// cases that may leave it (entry 0 fully blocked, or a blocking stream entry
/// that partially sent) are completed off the loop via `complete_batch_entry`,
/// so a caller ignoring per-entry `msg_len` is never silently truncated and a
/// blocking child never sees a spurious `EAGAIN`. A would-block at a later
/// entry, or at entry 0 of a non-blocking child, is a contract-legal
/// `Stop(EAGAIN)`; a hard error is `Stop(err)`.
///
/// `child_blocking` is the CHILD socket's blocking mode (computed by the
/// caller with [`wants_blocking`] on the child's dup), not the mode of
/// `dup_fd` itself: the S2.4 host-socket substitution sends a batch through a
/// fresh, blocking host-side socket even when the child socket is
/// non-blocking, and the kernel contract to reproduce is the child's — a
/// non-blocking child must get `EAGAIN`, never a deferred "success".
///
/// `dup_fd` is borrowed; the two deferred cases `try_clone` it (a `dup(2)` of
/// the same file description, so semantics match handing over the original).
/// If the clone fails after a partial send, the entry is counted with its
/// truthful partial `msg_len` (`Sent`) — bytes already committed to the stream
/// must never be re-sent by a retry. A clone failure before anything was sent
/// (entry 0 fully blocked) is a fail-closed `Stop(EIO)`.
pub(crate) fn batch_send_step(
    dup_fd: &OwnedFd,
    m: MaterializedMsg,
    flags: i32,
    child_blocking: bool,
    notif_fd: RawFd,
    notif_id: u64,
    notif_pid: u32,
    msglen_addr: u64,
    prior_count: usize,
) -> BatchStep {
    let ret = send_materialized_at(dup_fd.as_raw_fd(), &m, 0, flags | libc::MSG_DONTWAIT);
    if ret >= 0 {
        if child_blocking && (ret as usize) < m.data.len() {
            // Partial stream on a blocking socket: finish this entry off the
            // loop and report it as completed with its full byte count.
            let dup = match dup_fd.try_clone() {
                Ok(d) => d,
                Err(_) => {
                    // Can't complete off-loop, but `ret` bytes are already
                    // committed to the stream: report the partial count
                    // truthfully so a retry never duplicates them.
                    let bytes = (ret as u32).to_ne_bytes();
                    let _ = write_child_mem(notif_fd, notif_id, notif_pid, msglen_addr, &bytes);
                    return BatchStep::Sent;
                }
            };
            return BatchStep::Done(complete_batch_entry(
                dup, m, flags, ret as usize, notif_fd, notif_id, notif_pid, msglen_addr,
                prior_count,
            ));
        }
        let bytes = (ret as u32).to_ne_bytes();
        let _ = write_child_mem(notif_fd, notif_id, notif_pid, msglen_addr, &bytes);
        return BatchStep::Sent;
    }
    let err = unsafe { *libc::__errno_location() };
    if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
        if prior_count == 0 && child_blocking {
            // Entry 0 would block entirely: a blocking socket never returns
            // EAGAIN, so complete it off the loop.
            let dup = match dup_fd.try_clone() {
                Ok(d) => d,
                Err(_) => return BatchStep::Stop(libc::EIO),
            };
            return BatchStep::Done(complete_batch_entry(
                dup, m, flags, 0, notif_fd, notif_id, notif_pid, msglen_addr, 0,
            ));
        }
        return BatchStep::Stop(libc::EAGAIN);
    }
    BatchStep::Stop(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::FromRawFd;

    fn materialized(data: Vec<u8>) -> MaterializedMsg {
        MaterializedMsg {
            data,
            control: None,
            addr: Vec::new(),
            _scm_fds: Vec::new(),
            _pinned: None,
        }
    }

    /// S2.4 regression lock: a `sendmmsg` batch's blocking decision must come
    /// from the CHILD socket's mode, not from the send fd's own flags. The
    /// host-socket substitution hands the batch to a fresh, blocking host-side
    /// socket even when the child is non-blocking; if the supervisor deferred
    /// a would-block into "delayed success" instead of `EAGAIN`, the child's
    /// event-loop semantics would silently change. The test reproduces that
    /// exact shape — a blocking (host-like) fd with a full send buffer driven
    /// by a non-blocking child — using a stream socketpair: a deterministic
    /// full buffer is not reliably reproducible on UDP, and the would-block /
    /// blocking-mode semantics under test are identical.
    #[test]
    fn batch_send_step_would_block_follows_child_mode_not_send_fd_mode() {
        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0,
            "socketpair(2) must succeed"
        );
        let (sender, receiver) = (fds[0], fds[1]);

        // Fill the send buffer while the fd is non-blocking; stop on the first
        // EAGAIN, then confirm the buffer is truly at capacity with a 1-byte
        // probe (the final fill may have partially fit).
        let orig_fl = unsafe { libc::fcntl(sender, libc::F_GETFL) };
        assert!(orig_fl >= 0, "F_GETFL must succeed");
        unsafe { libc::fcntl(sender, libc::F_SETFL, orig_fl | libc::O_NONBLOCK) };
        let chunk = vec![0xABu8; 64 << 10];
        let mut fills = 0usize;
        loop {
            let rc = unsafe {
                libc::send(sender, chunk.as_ptr() as *const libc::c_void, chunk.len(), 0)
            };
            if rc < 0 {
                assert_eq!(
                    unsafe { *libc::__errno_location() },
                    libc::EAGAIN,
                    "filling a non-blocking stream socket must end in EAGAIN"
                );
                break;
            }
            assert!(rc > 0, "send during fill must make progress");
            fills += 1;
            assert!(fills < 8192, "send buffer did not fill (infinite-loop guard)");
        }
        let one = [0u8; 1];
        let rc = unsafe { libc::send(sender, one.as_ptr() as *const libc::c_void, 1, 0) };
        assert_eq!(rc, -1, "the send buffer must be at capacity");
        assert_eq!(unsafe { *libc::__errno_location() }, libc::EAGAIN);

        // Restore blocking mode: the fd now looks like a fresh host-side
        // socket (blocking), while the child we model is non-blocking.
        unsafe { libc::fcntl(sender, libc::F_SETFL, orig_fl) };
        assert!(wants_blocking(sender, 0), "premise: the send fd itself is blocking");

        let sender_owned = unsafe { OwnedFd::from_raw_fd(sender) };

        // Non-blocking child on a full buffer: the kernel contract is EAGAIN.
        // The fixed code must not defer it into a "delayed success".
        let step = batch_send_step(
            &sender_owned, materialized(vec![0xCDu8; 64 << 10]), 0, false,
            -1, 0, 0, 0, 0,
        );
        assert!(
            matches!(step, BatchStep::Stop(e) if e == libc::EAGAIN),
            "a non-blocking child on a full buffer must Stop(EAGAIN), never defer"
        );

        // Same shape, blocking child: entry 0 would-block must defer off the
        // loop (`Done`), preserving the kernel's no-spurious-EAGAIN contract
        // for blocking sockets. Nothing was sent by the call above, so the
        // buffer is still full.
        let step = batch_send_step(
            &sender_owned, materialized(vec![0xCDu8; 64 << 10]), 0, true,
            -1, 0, 0, 0, 0,
        );
        assert!(
            matches!(step, BatchStep::Done(_)),
            "a blocking child on a full buffer must defer to completion, not Stop(EAGAIN)"
        );

        unsafe { libc::close(receiver) };
    }
}
