//! S2.5 bind injection: serve an inbound-mapped sandbox port with a real
//! host-loopback socket instead of a host listener plus readiness synthesis.
//!
//! Why this exists: the host-listener design (`network::inbound`) can never
//! make the sandbox's *own* listener readable — the queued connection lives in
//! the host netns — so it has to trap `poll`/`ppoll`/`epoll_wait`/`epoll_pwait`
//! and synthesize readiness (`network::readiness`). An event-loop server like
//! uvicorn/uvloop keeps its listener registered in every `epoll_pwait` it
//! makes, so *every* event-loop wait in that process goes through the
//! supervisor. Measured on the E2B deployment (2026-09-16): an MCP request
//! cost ~390 ms per request under `net_isolation` versus ~8 ms on a
//! shared-netns worker (170/226 ms split over the two directions, with the
//! server's own work at 0.2 ms).
//!
//! With injection the sandbox's `bind()` on a mapped sandbox port is answered
//! by creating a supervisor-side socket bound to `127.0.0.1:<host_port>` in
//! the *host* netns and replacing the sandbox's socket fd with it
//! (`SECCOMP_ADDFD_FLAG_SETFD` — the mechanism `fd_inject_connect` already
//! uses). Everything after that is ordinary kernel work on a host-netns
//! socket: `listen()` (left to the kernel), `accept()` (a real accept — the
//! listener is not in `NetworkState::inbound`, so the accept handler and the
//! readiness synthesizer both `Continue`), and the event loop's own waits.
//! The supervisor leaves the data path entirely.
//!
//! Deliberate limits:
//! * TCP only. The mapping path is TCP-only in practice (MCP's HTTP listener),
//!   and a UDP "listener" has no accept()/backlog to serve.
//! * The host socket is bound to loopback (`127.0.0.1` / `::1`), never
//!   `0.0.0.0`: exposing a sandbox port on the worker's routable interfaces is
//!   a broadening, not a port. `getsockname()` inside the sandbox therefore
//!   reports the loopback address rather than the `0.0.0.0` the code asked
//!   for — the same address the host-listener design serves on.
//! * Fail closed: if the host socket cannot be created or bound (port taken,
//!   no route to loopback), the sandbox's `bind()` fails with that errno
//!   instead of silently binding inside its own netns, where nothing could
//!   reach it.

use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use crate::network::{query_socket_protocol, Protocol};
use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{dup_fd_from_pid, read_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;

/// Create a socket in the host (worker) netns of the same family as the
/// sandbox's socket, mirroring `SO_REUSEADDR`, and bind it to the mapped host
/// port on loopback. Returns the bound fd, or the errno to fail the sandbox's
/// `bind()` with.
fn create_host_bound_socket(
    family: u16,
    host_port: u16,
    child_fd: RawFd,
) -> Result<OwnedFd, i32> {
    let domain = if family == libc::AF_INET6 as u16 {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // Mirror the sandbox's SO_REUSEADDR: servers (uvicorn among them) set it
    // before bind, and a host socket without it would fail where the
    // sandbox-side bind would have succeeded (TIME_WAIT from a previous
    // sandbox's listener on the same pool port).
    let mut reuse: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let mirrored = unsafe {
        libc::getsockopt(
            child_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &mut reuse as *mut _ as *mut libc::c_void,
            &mut len,
        )
    } == 0
        && reuse != 0;
    if mirrored {
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    let ret = if domain == libc::AF_INET6 {
        let sa = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: host_port.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                // ::1 — loopback only, like the host-listener path.
                s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            },
            sin6_scope_id: 0,
        };
        unsafe {
            libc::bind(
                fd,
                &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    } else {
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: host_port.to_be(),
            // 127.0.0.1
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            libc::bind(
                fd,
                &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
    };
    if ret != 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    Ok(owned)
}

/// `bind(fd, addr, len)` handler for bind-injection mode (S2.5).
///
/// Returns `Continue` for everything that is not a mapped TCP port (other
/// families, ephemeral binds, unmapped ports), so the normal bind chain —
/// netlink cookies, `port_remap`, the deny-list handler — keeps governing it
/// exactly as before.
pub(crate) async fn handle_bind(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let sockfd = notif.data.args[0] as i32;
    let addr_ptr = notif.data.args[1];
    let addr_len = notif.data.args[2] as usize;

    // AF_INET/AF_INET6 sockaddr_in{,6} need at least 8 bytes; anything shorter
    // is the kernel's to reject (EFAULT/EINVAL).
    if addr_ptr == 0 || addr_len < 8 {
        return NotifAction::Continue;
    }
    let bytes = match read_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, addr_len.min(128)) {
        Ok(b) => b,
        Err(_) => return NotifAction::Errno(libc::EIO),
    };
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != libc::AF_INET as u16 && family != libc::AF_INET6 as u16 {
        return NotifAction::Continue;
    }
    let sandbox_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    if sandbox_port == 0 {
        // Ephemeral bind: nothing is mapped, nothing to inject.
        return NotifAction::Continue;
    }
    let host_port = {
        let ns = ctx.network.lock().await;
        ns.inbound_map.get(&sandbox_port).copied()
    };
    let Some(host_port) = host_port else {
        return NotifAction::Continue;
    };

    let dup_fd = match dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    // TCP only: an injected datagram socket would be a receive-only channel
    // with no backlog, and the mapping path never served UDP either.
    if query_socket_protocol(dup_fd.as_raw_fd()) != Some(Protocol::Tcp) {
        return NotifAction::Continue;
    }

    let host = match create_host_bound_socket(family, host_port, dup_fd.as_raw_fd()) {
        Ok(fd) => fd,
        // Fail closed: the mapping is the point of this bind, so a host socket
        // we cannot create or bind must fail the sandbox's bind() rather than
        // leave it bound-but-unreachable inside its own netns.
        Err(errno) => return NotifAction::Errno(errno),
    };
    // Record virtual -> real so `getsockname()` can translate back: the socket
    // the sandbox now holds is bound to the *host* port, while the sandbox asked
    // for `sandbox_port` (N91 -- with `host_port == sandbox_port`, which is how
    // the E2B MCP gateway allocates, the two numbers coincide and
    // `record_bind` stores only the bound-port entry). No other bookkeeping is
    // needed: `net_bind_inject` also takes `listen`/`accept4`/`poll`/
    // `epoll_wait` out of the notification table (`seccomp_plan`), so the
    // kernel drives this listener end to end -- which is the point of the mode.
    ctx.network
        .lock()
        .await
        .port_map
        .record_bind(sandbox_port, host_port);
    NotifAction::InjectFdAt {
        srcfd: host,
        targetfd: sockfd,
        newfd_flags: 0,
    }
}
