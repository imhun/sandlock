//! Netlink virtualization handlers — interpose AF_NETLINK sockets as
//! unix socketpairs driven by a synthesized NETLINK_ROUTE responder.
//!
//! Continue safety (issue #27): every Continue here is dispatch routing
//! based on register args (socket domain, fd number) or a fall-through
//! after harmless cosmetic adjustments (recvmsg pre-zeroing). Decisions
//! that require security enforcement (non-NETLINK_ROUTE protocol) return
//! Errno; substitution returns InjectFdSendTracked. The fd-cookie check
//! (`state.is_cookie(tgid, fd)`) examines a register arg, not user memory,
//! so the seccomp_unotify TOCTOU class doesn't apply: a racing thread
//! cannot change the fd number stored in another thread's syscall
//! registers.

use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use crate::netlink::{proxy, state::NetlinkState};
use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction, OnInjectSuccess};
use crate::sys::structs::SeccompNotif;

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const AF_KEY: u64 = 15;
const AF_NETLINK: u64 = 16;
const AF_RXRPC: u64 = 33;
const NETLINK_ROUTE: u64 = 0;
const NETLINK_XFRM: u64 = 6;
const NETLINK_KEY: u64 = 16;

/// Families that are refused **and have a named reason**.
///
/// This list is documentation, not the enforcement mechanism — `family_allowed`
/// is a whitelist, so everything absent is refused regardless of whether it is
/// named here. It exists because a whitelist's refusals are otherwise
/// indistinguishable from an oversight: a reader cannot tell "we deliberately
/// closed AF_RXRPC" from "nobody ever thought about AF_RXRPC", and the second
/// reading is what produces a later patch that "helpfully" adds it.
///
/// Every entry was measured in a live sandbox on 2026-10-04 (k0s, arm64
/// kernel 6.12), together with the same probe run *outside* the sandbox as a
/// control — without the control, a refusal that also happens on the host is
/// indistinguishable from one the sandbox made.
///
/// * `AF_RXRPC` — the RxRPC socket family. CVE-2026-43500 (the third
///   "Dirty Frag" variant, alongside CVE-2026-43284 in IPsec/ESP and
///   CVE-2026-53362 in IPv6 corking) is an unprivileged LPE in this exact
///   subsystem, and it is in CISA's KEV catalog as confirmed-exploited.
///   Measured: refused both in the sandbox and in the worker container, i.e.
///   the module happens to be unavailable here — which is *not* a security
///   property. It can be loaded by an unrelated package, so the refusal has to
///   be structural. Named here so that it is.
pub(crate) const REFUSED_FAMILIES: &[(u64, &str)] = &[
    (AF_RXRPC, "CVE-2026-43500 Dirty Frag (rxrpc), KEV-confirmed-exploited LPE"),
];

/// Netlink protocols refused **and have a named reason**. Same relationship to
/// `handle_socket` as [`REFUSED_FAMILIES`] has to `family_allowed`: the check
/// is `protocol != NETLINK_ROUTE`, and this names the ones that matter.
///
/// * `NETLINK_XFRM` — IPsec state management. This is the input path for
///   CVE-2026-43284 ("Dirty Frag", the IPsec/ESP in-place-decrypt-on-shared-
///   pages bug, KEV-confirmed-exploited, public PoC). Exploitation needs an
///   ESP SA to decrypt into; the kernel lets an unprivileged process add XFRM
///   state in its own user namespace, so denying the socket is the control —
///   there is no CAP_NET_ADMIN to check and no Landlock right that covers it.
///   Measured: created in the worker container, refused in the sandbox.
/// * `NETLINK_KEY` — the same keyring subsystem as `AF_KEY`, reached over
///   AF_NETLINK instead. `add_key`/`request_key`/`keyctl` are already refused at
///   the blocklist, so closing the socket is defence in depth for a different
///   door onto the same subsystem. Measured: created in the worker container,
///   refused in the sandbox.
pub(crate) const REFUSED_NETLINK_PROTOCOLS: &[(u64, &str)] = &[
    (NETLINK_XFRM, "CVE-2026-43284 Dirty Frag (IPsec/ESP), KEV-confirmed-exploited LPE"),
    (NETLINK_KEY, "keyring subsystem, same as the refused add_key/request_key/keyctl"),
];

/// Socket families allowed to reach the kernel. Everything else returns
/// EAFNOSUPPORT — the same errno the kernel itself uses for unknown
/// families, so callers see a normal "not supported" error rather than a
/// sandbox-flavored one.
///
/// The set is intentionally tiny: an XOA agent has no legitimate need for
/// AF_ALG, AF_PACKET, AF_VSOCK, AF_XDP, AF_TIPC, AF_RDS, AF_BLUETOOTH, and
/// the rest of the niche families that have historically yielded LPEs
/// (Copy Fail / CVE-2026-31431 via AF_ALG, Dirty Pipe-adjacent splice
/// primitives, AF_PACKET PACKET_MMAP UAFs, etc.). Closing the surface
/// once is cheaper than chasing one CVE per family.
///
/// Deliberately named refusals are listed in [`REFUSED_FAMILIES`] with their
/// reason; read that before adding a family here.
fn family_allowed(domain: u64) -> bool {
    matches!(domain, AF_UNIX | AF_INET | AF_INET6 | AF_NETLINK)
}

/// Resolve `notif.pid` (which is a TID per the kernel's `task_pid_vnr`) to
/// the enclosing thread group id.  fds are shared across all threads of a
/// process, so cookie entries must be keyed by TGID — otherwise a cookie
/// created by thread A is invisible to thread B in the same process.
fn tgid_of(tid: i32) -> i32 {
    let path = format!("/proc/{}/status", tid);
    if let Ok(s) = std::fs::read_to_string(&path) {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Tgid:") {
                if let Ok(v) = rest.trim().parse::<i32>() {
                    return v;
                }
            }
        }
    }
    // Fallback: if we can't read status, treat the tid as the tgid.
    tid
}

/// Read a POD struct `T` from child memory via `process_vm_readv`, with the
/// shared `notif::read_child_mem` helper that ID-validates the notification
/// before and after the read.
fn read_struct<T: Copy>(
    notif_fd: RawFd,
    id: u64,
    pid: u32,
    addr: usize,
) -> Option<T> {
    let bytes = read_child_mem(notif_fd, id, pid, addr as u64, std::mem::size_of::<T>()).ok()?;
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}

/// Intercept `socket(AF_NETLINK, *, NETLINK_ROUTE)` and substitute one end
/// of a `socketpair(AF_UNIX, SOCK_SEQPACKET)`. A tokio task takes the
/// supervisor-side end and speaks synthesized NETLINK_ROUTE replies.
/// Allowed domains pass through; AF_NETLINK is virtualized; everything
/// else (and non-NETLINK_ROUTE netlink protocols) returns EAFNOSUPPORT.
pub async fn handle_socket(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
    net_isolation: bool,
) -> NotifAction {
    let domain   = notif.data.args[0];
    let protocol = notif.data.args[2];

    if !family_allowed(domain) {
        return NotifAction::Errno(libc::EAFNOSUPPORT);
    }
    if domain != AF_NETLINK {
        return NotifAction::Continue;
    }
    if protocol != NETLINK_ROUTE {
        return NotifAction::Errno(libc::EAFNOSUPPORT);
    }

    let mut fds = [0i32; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return NotifAction::Errno(libc::ENOMEM);
    }
    // fds[0] → supervisor side (responder owns)
    // fds[1] → child side (injected)
    //
    // The supervisor end is driven by a tokio task via AsyncFd, so it
    // must be non-blocking. The child end stays blocking (glibc's
    // netlink code expects blocking semantics).
    let flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return NotifAction::Errno(libc::ENOMEM);
    }
    let responder_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    // tgid, not tid: fds are process-scoped, so the cookie set must be
    // keyed per-process to be visible across threads of the same app.
    // The responder also uses tgid as `nlmsg_pid` in its replies so the
    // value is consistent with what `handle_getsockname` writes for the
    // same process (glibc compares incoming nlmsg_pid against the value
    // it read back from getsockname — they must agree).
    let tgid = tgid_of(notif.pid as i32);
    // Per-sandbox netns isolation (S2.2): the real netns contains only
    // loopback (brought up by the child), so the responder synthesizes the
    // loopback-only view instead of the shared-netns lo + virtual-eth0
    // view — `ip addr` / AI_ADDRCONFIG see exactly what the kernel would
    // show for the sandbox's own netns.
    proxy::spawn_responder(responder_fd, tgid as u32, Arc::clone(state), net_isolation);

    // Record the (tgid, fd) once the kernel's ADDFD ioctl returns the
    // child-side fd number.  Doing it from the on-success callback
    // (rather than guessing via inode matching afterwards) closes the
    // TOCTOU gap: the entry lands in the state map *before* the child's
    // syscall unblocks, and the key is the exact fd slot the kernel
    // allocated — not derivable by racing the child.
    let state = Arc::clone(state);
    NotifAction::InjectFdSendTracked {
        srcfd: child_fd,
        newfd_flags: libc::O_CLOEXEC as u32,
        on_success: OnInjectSuccess::new(move |child_fd_num| {
            state.register(tgid, child_fd_num);
        }),
    }
}

/// Zero out the `msg_name` region of a recvmsg/recvfrom before the kernel
/// runs the syscall, so that the source address glibc sees has
/// `nl_pid == 0` (the kernel only writes `sun_family` = AF_UNIX = 2 bytes
/// into a unix-socketpair recvmsg's source address; bytes 2..end remain as
/// whatever we pre-filled).
///
/// glibc's netlink receive loop rejects messages where
/// `source_addr.nl_pid != 0` with a silent `continue`, interpreting them as
/// coming from a non-kernel peer.  Without this zeroing the `nl_pid` bits
/// are uninitialized stack and the check is flaky.
pub async fn handle_netlink_recvmsg(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
    notif_fd: RawFd,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let tgid = tgid_of(notif.pid as i32);
    if !state.is_cookie(tgid, fd) {
        return NotifAction::Continue;
    }

    let nr = notif.data.nr as i64;
    let sockaddr_nl_len: usize = 12;
    let zeros = [0u8; 12];
    let pid = notif.pid;
    let id = notif.id;

    if nr == libc::SYS_recvmsg {
        // args: (fd, msghdr*, flags)
        let msghdr_ptr = notif.data.args[1] as usize;
        if let Some(hdr) = read_struct::<libc::msghdr>(notif_fd, id, pid, msghdr_ptr) {
            if !hdr.msg_name.is_null() && (hdr.msg_namelen as usize) >= sockaddr_nl_len {
                let _ = write_child_mem(notif_fd, id, pid, hdr.msg_name as u64, &zeros);
            }
        }
    } else if nr == libc::SYS_recvfrom {
        // args: (fd, buf, len, flags, src_addr*, addrlen_ptr)
        let src_addr = notif.data.args[4] as u64;
        let addrlen_ptr = notif.data.args[5] as u64;
        if src_addr != 0 && addrlen_ptr != 0 {
            if let Ok(b) = read_child_mem(notif_fd, id, pid, addrlen_ptr, 4) {
                let cap = u32::from_ne_bytes(b.try_into().unwrap_or([0; 4])) as usize;
                if cap >= sockaddr_nl_len {
                    let _ = write_child_mem(notif_fd, id, pid, src_addr, &zeros);
                }
            }
        }
    }

    NotifAction::Continue
}

pub async fn handle_bind(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let tgid = tgid_of(notif.pid as i32);
    if state.is_cookie(tgid, fd) {
        return NotifAction::ReturnValue(0);
    }
    NotifAction::Continue
}

/// Remove `(tgid, fd)` from the cookie set when the child closes a
/// tracked netlink socket.  Lets the kernel actually close the fd too.
pub async fn handle_close(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let tgid = tgid_of(notif.pid as i32);
    if state.is_cookie(tgid, fd) {
        state.unregister(tgid, fd);
    }
    NotifAction::Continue
}

pub async fn handle_getsockname(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
    notif_fd: RawFd,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let tgid = tgid_of(notif.pid as i32);
    if !state.is_cookie(tgid, fd) {
        return NotifAction::Continue;
    }

    // struct sockaddr_nl { u16 nl_family; u16 _pad; u32 nl_pid; u32 nl_groups; }
    //
    // We use the tgid as the synthesized nl_pid so it's stable across
    // threads of the same process — matching the real kernel's netlink
    // auto-bind behavior which assigns one nl_pid per netlink socket.
    let mut addr = [0u8; 12];
    let nl_family = libc::AF_NETLINK as u16;
    addr[0..2].copy_from_slice(&nl_family.to_ne_bytes());
    addr[4..8].copy_from_slice(&(tgid as u32).to_ne_bytes());

    let addr_ptr = notif.data.args[1] as u64;
    let addrlen_ptr = notif.data.args[2] as u64;
    let pid = notif.pid;
    let id = notif.id;

    let cur = match read_child_mem(notif_fd, id, pid, addrlen_ptr, 4) {
        Ok(b) => u32::from_ne_bytes(b.try_into().unwrap_or([0; 4])) as usize,
        Err(_) => return NotifAction::Errno(libc::EFAULT),
    };
    let to_write = cur.min(addr.len());
    if write_child_mem(notif_fd, id, pid, addr_ptr, &addr[..to_write]).is_err() {
        return NotifAction::Errno(libc::EFAULT);
    }
    let actual = (addr.len() as u32).to_ne_bytes();
    let _ = write_child_mem(notif_fd, id, pid, addrlen_ptr, &actual);
    NotifAction::ReturnValue(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The socket-domain gate. Written as a table rather than a loop over
    /// `REFUSED_FAMILIES` so that adding a family to the whitelist is a
    /// deliberate edit here too, not just in `family_allowed`.
    #[test]
    fn socket_family_gate() {
        // The four that reach the kernel.
        for d in [AF_UNIX, AF_INET, AF_INET6, AF_NETLINK] {
            assert!(family_allowed(d), "family {d} must be allowed");
        }
        // Every family named as deliberately refused stays refused.
        for (domain, why) in REFUSED_FAMILIES {
            assert!(
                !family_allowed(*domain),
                "family {domain} is named as refused ({why}) but family_allowed accepts it",
            );
        }
        // Niche families with no legitimate use in a sandbox.
        for d in [AF_KEY, 17 /* AF_PACKET */, 38 /* AF_ALG */, 40 /* AF_VSOCK */] {
            assert!(!family_allowed(d), "family {d} must be refused");
        }
        // Nothing outside the whitelist may pass: the gate is an allow list, so
        // an unlisted family is the normal case, not the exception.
        for d in 0..=64u64 {
            if d == AF_UNIX || d == AF_INET || d == AF_INET6 || d == AF_NETLINK {
                continue;
            }
            assert!(!family_allowed(d), "family {d} must not be allowed");
        }
    }

    /// The protocol gate inside `handle_socket`.
    #[test]
    fn netlink_protocol_gate() {
        // NETLINK_ROUTE is the one the supervisor answers synthetically.
        assert_eq!(NETLINK_ROUTE, 0);
        // The named refusals are not NETLINK_ROUTE, which is what makes the
        // `protocol != NETLINK_ROUTE` check refuse them.
        for (proto, why) in REFUSED_NETLINK_PROTOCOLS {
            assert_ne!(
                *proto, NETLINK_ROUTE,
                "{why}: a listed protocol cannot be NETLINK_ROUTE or it would be answered",
            );
        }
        assert_eq!(NETLINK_XFRM, 6);
        assert_eq!(NETLINK_KEY, 16);
        assert_eq!(AF_RXRPC, 33);
        assert_eq!(AF_KEY, 15);
        assert_eq!(AF_NETLINK, 16);
    }

    /// The number is only meaningful if it is the real one: a wrong family
    /// number makes the refusal test above pass for the wrong reason.
    #[test]
    fn family_numbers_are_the_kernels() {
        assert_eq!(AF_UNIX, libc::AF_UNIX as u64);
        assert_eq!(AF_INET, libc::AF_INET as u64);
        assert_eq!(AF_INET6, libc::AF_INET6 as u64);
        assert_eq!(AF_NETLINK, libc::AF_NETLINK as u64);
        assert_eq!(AF_KEY, libc::AF_KEY as u64);
        assert_eq!(AF_RXRPC, libc::AF_RXRPC as u64);
    }
}
