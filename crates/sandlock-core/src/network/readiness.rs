// E7.1 / S2.5 extension: poll/epoll readiness synthesis for inbound-mapped
// listeners.
//
// An event-loop server (uvicorn/asyncio, Node, Go) only calls `accept()` when
// its listening socket reports readable. Host-side connections queued by the
// S2.5 eager-accept worker never land in the sandbox's own kernel backlog (the
// host listener lives in the supervisor's netns), so the sandbox's listener fd
// never becomes readable on its own — the event loop parks forever and the
// MCP gateway never serves. These handlers trap `poll`/`ppoll`/
// `epoll_wait`/`epoll_pwait` only when the `inbound_port_map` feature is
// active, duplicate the watched fds from the blocked child (sharing file
// descriptions, so readiness is real),
// poll them supervisor-side in small slices, OR in synthetic POLLIN/EPOLLIN
// for mapped listeners with queued connections, and write the combined events
// back into the child's memory before responding with the event count.
//
// `epoll_wait` reads the registrations from the kernel's own
// `/proc/<pid>/fdinfo/<epfd>` rather than tracking `epoll_ctl`: the kernel
// already keeps that table, and a supervisor-side copy had to be told about
// `close` (so `close` sat in the notification table) and could answer from a
// stale entry after an fd number was reused (N88 ②).
//
// Syscalls without a mapped listener are returned to the kernel (`Continue`),
// so sandboxes without inbound mappings never take this path. Epoll wakeups
// are edge-free level-triggered reports: a synthetic readable on an EPOLLET
// listener is a spurious-but-harmless wakeup (a queued connection exists, so
// accept() succeeds); real readiness of the other watched fds is always
// composed from the duplicated-fd poll.

use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{
    dup_fd_from_pid, id_valid, read_child_mem, write_child_mem, NotifAction,
};
use crate::sys::structs::SeccompNotif;

use super::inbound::{live_sandbox_port, socket_ino};

/// `struct pollfd` on every sandlock target: `{ int fd; short events;
/// short revents; }` — 8 bytes on LP64.
const POLLFD_SIZE: usize = 8;
/// `struct epoll_event` is `{ uint32_t events; uint64_t data; }`, and its
/// *layout* is per-ABI: libc marks the struct `repr(packed)` on x86_64 (and
/// 32-bit x86), so it is 12 bytes with `data` at offset 4 there, while every
/// other LP64 ABI keeps the natural alignment — 16 bytes, `data` at offset 8
/// (measured with a C probe on both: x86_64 12/4, aarch64 16/8). The child's
/// array is read and written through these two numbers, so a hardcoded 12/4
/// reads the wrong half of every record on aarch64 and writes back records
/// the kernel reads as garbage. Both come from libc's own definition, which
/// is where the packed/natural distinction lives.
const EPOLL_EVENT_SIZE: usize = std::mem::size_of::<libc::epoll_event>();
/// Offset of the trailing `data` field inside one [`EPOLL_EVENT_SIZE`] record.
const EPOLL_EVENT_DATA_OFFSET: usize = std::mem::offset_of!(libc::epoll_event, u64);
/// Supervisor-side poll slice: bounds how long a newly queued host connection
/// waits before the synthesized wakeup, and how quickly a cancelled wait
/// (child died) terminates.
const POLL_SLICE_MS: i32 = 20;

/// Encode `(data, events)` pairs into the array layout the child reads back
/// from `epoll_wait`.
fn encode_epoll_events(ready: &[(u64, u32)]) -> Vec<u8> {
    let mut buf = vec![0u8; ready.len() * EPOLL_EVENT_SIZE];
    for (i, (data, events)) in ready.iter().enumerate() {
        let off = i * EPOLL_EVENT_SIZE;
        buf[off..off + 4].copy_from_slice(&events.to_ne_bytes());
        buf[off + EPOLL_EVENT_DATA_OFFSET..off + EPOLL_EVENT_DATA_OFFSET + 8]
            .copy_from_slice(&data.to_ne_bytes());
    }
    buf
}

/// One registration the kernel reports for a sandbox epoll fd, read from
/// `/proc/<pid>/fdinfo/<epfd>`. `target_ino` is the watched file's inode as
/// the kernel reports it (`None` on kernels whose fdinfo omits it), used to
/// spot inbound-mapped listeners without duplicating every watched fd.
#[derive(Clone, Copy, Debug)]
struct EpollRegistration {
    fd: i32,
    events: u32,
    data: u64,
    target_ino: Option<u64>,
}

/// Read the child's epoll registrations from the kernel's own fdinfo.
///
/// This replaced a supervisor-side `epoll_ctl` ADD/MOD/DEL bookkeeping map
/// (N88 ②). That map had to be told about `close` — which meant trapping the
/// hottest syscall in the sandbox — and when the notification was gone an fd
/// number that came back as something else was answered from the stale entry
/// (measured: `epoll_wait` on a reused number returned a synthesized `0`
/// where the kernel must say `EINVAL`). The kernel already keeps exactly this
/// table per epoll fd; reading it has no state to go stale, so `close` and
/// `epoll_ctl` both leave the notification table.
///
/// Format, stable since 2.6.28 (`pos:`/`ino:`/`sdev:` were appended later):
///   `tfd: %8d events: %8x data: %16llx  pos:%lli ino:%lx sdev:%x`
fn read_epoll_registrations(pid: u32, epfd: i32) -> Option<Vec<EpollRegistration>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{epfd}")).ok()?;
    Some(parse_epoll_fdinfo(&text))
}

/// Parse the `tfd:` lines out of an epoll fdinfo body. Split out from the read
/// so the format assumption above is unit-tested against the kernel's literal
/// spelling (both the modern line and the pre-`ino:` one) instead of only
/// against whatever the running kernel happens to print.
fn parse_epoll_fdinfo(text: &str) -> Vec<EpollRegistration> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut tok = line.split_whitespace();
        if tok.next() != Some("tfd:") {
            continue;
        }
        let Some(fd) = tok.next().and_then(|t| t.parse::<i32>().ok()) else {
            continue;
        };
        if tok.next() != Some("events:") {
            continue;
        }
        let Some(events) = tok.next().and_then(|t| u32::from_str_radix(t, 16).ok()) else {
            continue;
        };
        if tok.next() != Some("data:") {
            continue;
        }
        let Some(data) = tok.next().and_then(|t| u64::from_str_radix(t, 16).ok()) else {
            continue;
        };
        let target_ino =
            tok.find_map(|t| t.strip_prefix("ino:").and_then(|h| u64::from_str_radix(h, 16).ok()));
        out.push(EpollRegistration {
            fd,
            events,
            data,
            target_ino,
        });
    }
    out
}

/// One entry of the child's `pollfd` array, with the mapped-listener marker.
#[derive(Clone, Copy)]
struct PollEntry {
    fd: i32,
    /// The child's requested `events` mask (revents are masked by it).
    events: i16,
    /// The socket inode when `fd` is an inbound-mapped listener.
    mapped_ino: Option<u64>,
}

fn mapped_listener_pending(ctx: &Arc<SupervisorCtx>, ino: u64) -> bool {
    let ns = ctx.network.blocking_lock();
    match ns.inbound.get(&ino) {
        Some(l) => l.pending.load(Ordering::SeqCst) > 0,
        None => false,
    }
}

/// Resolve `fd` to its socket inode when it is a *live* inbound-mapped
/// listener.
///
/// The mapping is keyed by socket inode and the kernel recycles inodes, so
/// the entry is only accepted while the socket behind `fd` is still bound to
/// the port the mapping was created for (see `network::inbound`); a mismatch
/// evicts the stale entry and treats the fd as ordinary.
async fn mapped_listener_ino(pid: u32, fd: i32, ctx: &Arc<SupervisorCtx>) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    let dup = dup_fd_from_pid(pid, fd).ok()?;
    let ino = socket_ino(dup.as_raw_fd())?;
    let mut ns = ctx.network.lock().await;
    let live = match ns.inbound.get(&ino) {
        Some(l) => live_sandbox_port(&ns, dup.as_raw_fd()) == Some(l.sandbox_port),
        None => return None,
    };
    if live {
        Some(ino)
    } else {
        ns.inbound.remove(&ino);
        None
    }
}

fn read_timespec_ms(notif_fd: RawFd, notif: &SeccompNotif, ptr: u64) -> Option<i64> {
    if ptr == 0 {
        return None; // infinite
    }
    let raw = read_child_mem(notif_fd, notif.id, notif.pid, ptr, 16).ok()?;
    let sec = i64::from_ne_bytes(raw[0..8].try_into().ok()?);
    let nsec = i64::from_ne_bytes(raw[8..16].try_into().ok()?);
    if sec < 0 || nsec < 0 {
        return None;
    }
    Some(sec.saturating_mul(1000).saturating_add(nsec / 1_000_000))
}

/// `poll(fds, nfds, timeout)`.
pub(crate) async fn handle_poll(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    handle_poll_impl(
        notif,
        ctx,
        notif_fd,
        notif.data.args[0],
        notif.data.args[1] as usize,
        notif.data.args[2] as i64,
    )
    .await
}

/// `ppoll(fds, nfds, sigmask, timeout)` — the sigmask is not applied by the
/// supervisor-side wait (documented limitation; servers use an empty mask).
pub(crate) async fn handle_ppoll(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let timeout_ms = match read_timespec_ms(notif_fd, notif, notif.data.args[3]) {
        Some(ms) => ms,
        None => -1,
    };
    handle_poll_impl(
        notif,
        ctx,
        notif_fd,
        notif.data.args[0],
        notif.data.args[1] as usize,
        timeout_ms,
    )
    .await
}

async fn handle_poll_impl(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
    fds_ptr: u64,
    nfds: usize,
    timeout_ms: i64,
) -> NotifAction {
    if nfds == 0 || fds_ptr == 0 {
        // The kernel sleeps for `timeout` (nfds == 0) or fails with EFAULT;
        // nothing to synthesize.
        return NotifAction::Continue;
    }
    let Some(size) = nfds.checked_mul(POLLFD_SIZE) else {
        return NotifAction::Errno(libc::EINVAL);
    };
    let raw = match read_child_mem(notif_fd, notif.id, notif.pid, fds_ptr, size) {
        Ok(b) if b.len() == size => b,
        _ => return NotifAction::Errno(libc::EFAULT),
    };
    let mut entries: Vec<PollEntry> = Vec::with_capacity(nfds);
    let mut any_mapped = false;
    for i in 0..nfds {
        let off = i * POLLFD_SIZE;
        let fd = i32::from_ne_bytes(raw[off..off + 4].try_into().unwrap());
        let events = i16::from_ne_bytes(raw[off + 4..off + 6].try_into().unwrap());
        let mapped_ino = mapped_listener_ino(notif.pid, fd, ctx).await;
        if mapped_ino.is_some() {
            any_mapped = true;
        }
        entries.push(PollEntry {
            fd,
            events,
            mapped_ino,
        });
    }
    if !any_mapped {
        return NotifAction::Continue;
    }
    let ctx = Arc::clone(ctx);
    let notif_owned = *notif;
    NotifAction::defer(async move {
        run_poll_wait(notif_fd, notif_owned, ctx, fds_ptr, entries, timeout_ms).await
    })
}

async fn run_poll_wait(
    notif_fd: RawFd,
    notif: SeccompNotif,
    ctx: Arc<SupervisorCtx>,
    fds_ptr: u64,
    entries: Vec<PollEntry>,
    timeout_ms: i64,
) -> NotifAction {
    let id = notif.id;
    let pid = notif.pid;
    let deadline = if timeout_ms < 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
    };
    let spawned = tokio::task::spawn_blocking(move || {
        let mut dups: Vec<Option<OwnedFd>> = Vec::with_capacity(entries.len());
        let mut pollfds: Vec<libc::pollfd> = Vec::with_capacity(entries.len());
        for e in &entries {
            if e.fd < 0 {
                dups.push(None);
                pollfds.push(libc::pollfd {
                    fd: e.fd,
                    events: e.events,
                    revents: 0,
                });
                continue;
            }
            match dup_fd_from_pid(pid, e.fd) {
                Ok(dup) => {
                    pollfds.push(libc::pollfd {
                        fd: dup.as_raw_fd(),
                        events: e.events,
                        revents: 0,
                    });
                    dups.push(Some(dup));
                }
                // The child's fd vanished between the trap and the dup (another
                // thread closed it): the kernel view at syscall time is NVAL.
                Err(_) => {
                    dups.push(None);
                    pollfds.push(libc::pollfd {
                        fd: e.fd,
                        events: e.events,
                        revents: libc::POLLNVAL,
                    });
                }
            }
        }

        loop {
            if id_valid(notif_fd, id).is_err() {
                return NotifAction::Errno(libc::EIO);
            }
            for p in pollfds.iter_mut() {
                p.revents = 0;
            }
            let rc = unsafe {
                libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, POLL_SLICE_MS)
            };
            if rc < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error();
                if errno == Some(libc::EINTR) {
                    continue;
                }
                return NotifAction::Errno(errno.unwrap_or(libc::EIO));
            }

            let mut ready_count = 0usize;
            let mut writebacks: Vec<(usize, i16)> = Vec::new();
            for (i, e) in entries.iter().enumerate() {
                let mut revents = pollfds[i].revents;
                if let Some(ino) = e.mapped_ino {
                    if mapped_listener_pending(&ctx, ino) {
                        revents |= libc::POLLIN | libc::POLLRDNORM;
                    }
                }
                if revents != 0 {
                    ready_count += 1;
                    writebacks.push((i, revents));
                }
            }
            if ready_count > 0 {
                for (i, revents) in writebacks {
                    let off = i * POLLFD_SIZE + 6;
                    let bytes = revents.to_ne_bytes();
                    if write_child_mem(notif_fd, id, pid, fds_ptr + off as u64, &bytes).is_err() {
                        return NotifAction::Errno(libc::EFAULT);
                    }
                }
                return NotifAction::ReturnValue(ready_count as i64);
            }
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    return NotifAction::ReturnValue(0);
                }
            }
        }
    });
    match spawned.await {
        Ok(action) => action,
        Err(_) => NotifAction::Errno(libc::EIO),
    }
}

/// `epoll_wait(epfd, events, maxevents, timeout)`.
pub(crate) async fn handle_epoll_wait(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    handle_epoll_wait_impl(
        notif,
        ctx,
        notif_fd,
        notif.data.args[0] as i32,
        notif.data.args[1],
        notif.data.args[2] as i32,
        notif.data.args[3] as i64,
    )
    .await
}

/// `epoll_pwait(epfd, events, maxevents, timeout, sigmask)` — the sigmask is
/// not applied by the supervisor-side wait (documented limitation).
pub(crate) async fn handle_epoll_pwait(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    handle_epoll_wait_impl(
        notif,
        ctx,
        notif_fd,
        notif.data.args[0] as i32,
        notif.data.args[1],
        notif.data.args[2] as i32,
        notif.data.args[3] as i64,
    )
    .await
}

async fn handle_epoll_wait_impl(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    timeout_ms: i64,
) -> NotifAction {
    if events_ptr == 0 || maxevents <= 0 {
        // Kernel semantics (EFAULT / EINVAL) need no synthesis.
        return NotifAction::Continue;
    }
    // The kernel's own table for this epoll fd: a closed fd (fdinfo gone) or
    // an fd that is not an epoll instance (no `tfd:` lines) leaves the
    // syscall to the kernel, which answers EBADF/EINVAL exactly as it should.
    let Some(regs) = read_epoll_registrations(notif.pid, epfd) else {
        return NotifAction::Continue;
    };
    let any_candidate = {
        let ns = ctx.network.lock().await;
        regs.iter()
            .any(|r| r.target_ino.map_or(true, |ino| ns.inbound.contains_key(&ino)))
    };
    if !any_candidate {
        return NotifAction::Continue;
    }
    let ctx = Arc::clone(ctx);
    let notif_owned = *notif;
    NotifAction::defer(async move {
        run_epoll_wait(
            notif_fd,
            notif_owned,
            ctx,
            events_ptr,
            maxevents,
            timeout_ms,
            regs,
        )
        .await
    })
}

fn poll_events_to_epoll(revents: i16, registered: u32) -> u32 {
    let mut out = 0u32;
    if revents & (libc::POLLIN as i16) != 0 && registered & libc::EPOLLIN as u32 != 0 {
        out |= libc::EPOLLIN as u32;
    }
    if revents & (libc::POLLOUT as i16) != 0 && registered & libc::EPOLLOUT as u32 != 0 {
        out |= libc::EPOLLOUT as u32;
    }
    if revents & (libc::POLLPRI as i16) != 0 && registered & libc::EPOLLPRI as u32 != 0 {
        out |= libc::EPOLLPRI as u32;
    }
    if revents & (libc::POLLRDHUP as i16) != 0 && registered & libc::EPOLLRDHUP as u32 != 0 {
        out |= libc::EPOLLRDHUP as u32;
    }
    // ERR/HUP are always reported by epoll, matching poll.
    if revents & libc::POLLERR as i16 != 0 {
        out |= libc::EPOLLERR as u32;
    }
    if revents & libc::POLLHUP as i16 != 0 {
        out |= libc::EPOLLHUP as u32;
    }
    out
}

async fn run_epoll_wait(
    notif_fd: RawFd,
    notif: SeccompNotif,
    ctx: Arc<SupervisorCtx>,
    events_ptr: u64,
    maxevents: i32,
    timeout_ms: i64,
    regs: Vec<EpollRegistration>,
) -> NotifAction {
    let id = notif.id;
    let pid = notif.pid;
    // Which of the kernel's registrations point at a *live* inbound-mapped
    // listener? Only the candidates are duplicated here (their fdinfo inode
    // is a current mapping key, or the kernel did not report one); the
    // validation re-reads the socket's own port so a recycled inode cannot
    // inherit a mapping that belonged to a socket the sandbox already closed.
    let mut resolved: Vec<(i32, u32, u64, Option<u64>)> = Vec::with_capacity(regs.len());
    {
        let mut ns = ctx.network.lock().await;
        let mut stale: Vec<u64> = Vec::new();
        for r in &regs {
            let candidate = r.target_ino.map_or(true, |ino| ns.inbound.contains_key(&ino));
            let mut mapped_ino = None;
            if candidate {
                if let Ok(dup) = dup_fd_from_pid(pid, r.fd) {
                    if let Some(ino) = socket_ino(dup.as_raw_fd()) {
                        match ns.inbound.get(&ino) {
                            Some(l)
                                if live_sandbox_port(&ns, dup.as_raw_fd())
                                    == Some(l.sandbox_port) =>
                            {
                                mapped_ino = Some(ino);
                            }
                            Some(_) => stale.push(ino),
                            None => {}
                        }
                    }
                }
            }
            resolved.push((r.fd, r.events, r.data, mapped_ino));
        }
        for ino in stale {
            ns.inbound.remove(&ino);
        }
    }
    if !resolved.iter().any(|(_, _, _, ino)| ino.is_some()) {
        // Nothing mapped is registered: the kernel's own wait is the answer.
        return NotifAction::Continue;
    }
    let deadline = if timeout_ms < 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(timeout_ms as u64))
    };
    let spawned = tokio::task::spawn_blocking(move || {
        let mut dups: Vec<Option<OwnedFd>> = Vec::with_capacity(resolved.len());
        let mut pollfds: Vec<libc::pollfd> = Vec::with_capacity(resolved.len());
        for (fd, events, _, _) in &resolved {
            match dup_fd_from_pid(pid, *fd) {
                Ok(dup) => {
                    let events = ((*events & (libc::EPOLLIN as u32 | libc::EPOLLOUT as u32
                        | libc::EPOLLPRI as u32 | libc::EPOLLRDHUP as u32)) as i16)
                        & (libc::POLLIN as i16
                            | libc::POLLOUT as i16
                            | libc::POLLPRI as i16
                            | libc::POLLRDHUP as i16);
                    pollfds.push(libc::pollfd {
                        fd: dup.as_raw_fd(),
                        events,
                        revents: 0,
                    });
                    dups.push(Some(dup));
                }
                Err(_) => {
                    dups.push(None);
                    // Kernel epoll_wait reports EPOLLHUP (then removes the fd
                    // for level-triggered) when the registered fd is closed;
                    // surface ERR/HUP so the event loop drops it.
                    pollfds.push(libc::pollfd {
                        fd: *fd,
                        events: 0,
                        revents: libc::POLLERR | libc::POLLHUP,
                    });
                }
            }
        }

        loop {
            if id_valid(notif_fd, id).is_err() {
                return NotifAction::Errno(libc::EIO);
            }
            for p in pollfds.iter_mut() {
                p.revents = 0;
            }
            let rc = unsafe {
                libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, POLL_SLICE_MS)
            };
            if rc < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error();
                if errno == Some(libc::EINTR) {
                    continue;
                }
                return NotifAction::Errno(errno.unwrap_or(libc::EIO));
            }

            let mut ready: Vec<(u64, u32)> = Vec::new();
            for (i, (_, events, data, mapped_ino)) in resolved.iter().enumerate() {
                let mut ep_events = poll_events_to_epoll(pollfds[i].revents, *events);
                if let Some(ino) = mapped_ino {
                    if mapped_listener_pending(&ctx, *ino) {
                        ep_events |= libc::EPOLLIN as u32;
                    }
                }
                if ep_events != 0 {
                    ready.push((*data, ep_events));
                }
            }
            if !ready.is_empty() {
                let buf =
                    encode_epoll_events(&ready[..ready.len().min(maxevents as usize)]);
                if write_child_mem(notif_fd, id, pid, events_ptr, &buf).is_err() {
                    return NotifAction::Errno(libc::EFAULT);
                }
                return NotifAction::ReturnValue(ready.len().min(maxevents as usize) as i64);
            }
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    return NotifAction::ReturnValue(0);
                }
            }
        }
    });
    match spawned.await {
        Ok(action) => action,
        Err(_) => NotifAction::Errno(libc::EIO),
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_events_to_epoll_maps_interest_and_always_reports_err_hup() {
        assert_eq!(
            poll_events_to_epoll(libc::POLLIN as i16, libc::EPOLLIN as u32),
            libc::EPOLLIN as u32
        );
        // Only registered interest is surfaced.
        assert_eq!(
            poll_events_to_epoll(libc::POLLIN as i16, libc::EPOLLOUT as u32),
            0
        );
        assert_eq!(
            poll_events_to_epoll(libc::POLLOUT as i16, libc::EPOLLOUT as u32),
            libc::EPOLLOUT as u32
        );
        // ERR/HUP ride through regardless of the interest mask.
        assert_eq!(
            poll_events_to_epoll(libc::POLLHUP as i16 | libc::POLLERR as i16, 0),
            libc::EPOLLHUP as u32 | libc::EPOLLERR as u32
        );
        assert_eq!(
            poll_events_to_epoll(libc::POLLRDHUP as i16, libc::EPOLLRDHUP as u32),
            libc::EPOLLRDHUP as u32
        );
    }

    #[test]
    fn pollfd_and_epoll_event_layouts_match_lp64() {
        assert_eq!(POLLFD_SIZE, std::mem::size_of::<libc::pollfd>());
        assert_eq!(EPOLL_EVENT_SIZE, std::mem::size_of::<libc::epoll_event>());
        assert_eq!(EPOLL_EVENT_DATA_OFFSET, EPOLL_EVENT_SIZE - 8);
        // Spelled out per ABI so a change in libc's definitions cannot move
        // the record silently: x86_64's kernel ABI is the packed one.
        if cfg!(target_arch = "x86_64") {
            assert_eq!((EPOLL_EVENT_SIZE, EPOLL_EVENT_DATA_OFFSET), (12, 4));
        } else {
            assert_eq!((EPOLL_EVENT_SIZE, EPOLL_EVENT_DATA_OFFSET), (16, 8));
        }
    }

    /// The child reads back an array of `struct epoll_event`, so the bytes the
    /// supervisor writes have to be in *the ABI's* layout, not in x86_64's.
    /// The record is compared through `libc::epoll_event` itself, which is
    /// where the packed/natural distinction lives, so this asserts against the
    /// syscall ABI rather than against a number this file picked. (Since N88 ②
    /// the decode direction is gone: registrations are read from the kernel's
    /// own fdinfo, never parsed out of the child's array.)
    ///
    /// Only the two *fields* are compared. A non-x86_64 ABI leaves four bytes
    /// of padding between them, and that padding is not part of the ABI: the
    /// kernel copies a `struct epoll_event` whose padding holds whatever its
    /// stack did, and no reader may depend on it.
    #[test]
    fn encoded_epoll_events_land_in_the_arch_layout() {
        let events = libc::EPOLLIN as u32 | libc::EPOLLOUT as u32;
        let data: u64 = 0x0f0e_0d0c_0b0a_0908;
        let encoded = encode_epoll_events(&[(data, events)]);
        assert_eq!(encoded.len(), EPOLL_EVENT_SIZE);
        let mut decoded: libc::epoll_event = unsafe { std::mem::zeroed() };
        unsafe {
            std::ptr::copy_nonoverlapping(
                encoded.as_ptr(),
                (&mut decoded as *mut libc::epoll_event).cast::<u8>(),
                EPOLL_EVENT_SIZE,
            );
        }
        let decoded_events: u32 = decoded.events;
        let decoded_data: u64 = decoded.u64;
        assert_eq!(decoded_events, events);
        assert_eq!(decoded_data, data);
    }

    /// The registrations come from the kernel's fdinfo spelling, so pin both
    /// shapes that spelling has taken: the modern line (`pos:`/`ino:`/`sdev:`
    /// appended) and the pre-`ino:` one. `data` is hex; a decimal read of the
    /// modern line would be a wildly different number, which is the mistake
    /// this test exists to catch.
    #[test]
    fn epoll_fdinfo_parses_the_kernels_tfd_lines() {
        let modern = "pos:\t0\nflags:\t02000002\nmnt_id:\t18\nino:\t3087\n\
                      tfd:        5 events: 80000019 data:     7ffc00000005  pos:0 ino:8648e8 sdev:a\n\
                      tfd:        9 events:        1 data:               2a\n";
        let parsed = parse_epoll_fdinfo(modern);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].fd, 5);
        assert_eq!(parsed[0].events, 0x8000_0019);
        assert_eq!(parsed[0].data, 0x7ffc_0000_0005);
        assert_eq!(parsed[0].target_ino, Some(0x8648_e8));
        assert_eq!(parsed[1].fd, 9);
        assert_eq!(parsed[1].events, 1);
        assert_eq!(parsed[1].data, 0x2a);
        assert_eq!(parsed[1].target_ino, None);

        // A non-epoll fd's fdinfo has no `tfd:` line at all, which is what
        // makes a reused fd number fall through to the kernel (N88 nail).
        assert!(parse_epoll_fdinfo("pos:\t0\nflags:\t02100000\nmnt_id:\t2917\nino:\t5\n").is_empty());
    }

    /// Live check of the assumption itself: the kernel prints the registrations
    /// this file reads, for a real epoll fd of the running process.
    #[test]
    fn the_kernel_reports_a_live_epoll_fds_registrations() {
        let epfd = unsafe { libc::epoll_create1(0) };
        assert!(epfd >= 0, "epoll_create1 failed");
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) }, 0);
        let watched = fds[0];
        let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
        ev.events = libc::EPOLLIN as u32;
        ev.u64 = 0x0123_4567_89ab_cdef;
        assert_eq!(unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, watched, &mut ev) }, 0);

        let regs = read_epoll_registrations(std::process::id(), epfd)
            .expect("the kernel must expose this process's own fdinfo");
        assert_eq!(regs.len(), 1, "one registered fd, got {regs:?}");
        assert_eq!(regs[0].fd, watched);
        assert_eq!(regs[0].data, 0x0123_4567_89ab_cdef);
        assert!(
            regs[0].events & libc::EPOLLIN as u32 != 0,
            "the registered read interest must survive the round trip: {:#x}",
            regs[0].events
        );
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(watched, &mut st) }, 0);
        assert_eq!(
            regs[0].target_ino,
            Some(st.st_ino),
            "fdinfo's ino is the watched file's inode"
        );
        unsafe { libc::close(fds[1]) };
        unsafe { libc::close(watched) };
        unsafe { libc::close(epfd) };
    }
}
