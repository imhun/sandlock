// S2.5 inbound port mapping: supervisor host-side listeners serving a
// `net_isolation` sandbox's `accept()` on mapped ports (the MCP-server path).
//
// The sandbox binds and listens normally INSIDE its loopback-only netns, so
// `getsockname`/`poll`/`local_addr` keep working and sandbox-internal
// loopback connections still land in its own accept queue. When the sandbox
// `listen()`s on a port with a `net_bind_map(host_port, sandbox_port)` entry,
// the supervisor additionally:
//
//   1. listens on 127.0.0.1:host_port in the HOST netns (>= 50005);
//   2. records the host listener keyed by the sandbox listening socket's
//      inode (stable across fork/dup of the listening fd);
//   3. serves the sandbox's `accept()`/`accept4()` on that fd with a
//      connection accepted from the host listener (external) or the
//      sandbox's own accept queue (sandbox-internal), injecting the accepted
//      fd into the sandbox — `accept()` returns the injected fd number and
//      the data plane is the injected socket (kernel-direct, no user-space
//      copy).
//
// N88 ②(a) -- who tears the mapping down, and when. `close` is no longer in
// the notification table at all (it is the hottest syscall in the sandbox, and
// the netlink cookie set plus this module now each stand on their own), so the
// mapping outlives the sandbox closing its listening socket. It is released at
// sandbox teardown, and *replaced* when a later socket listens on the same
// mapped port (`handle_listen`). The host port is the platform's own
// allocation for this sandbox (`50005+`), so living a little longer than the
// listener costs nothing that is contended -- and the alternative was a
// supervisor round trip on every `close` in every sandbox (measured: the whole
// `openclose` ladder halving).
//
// The entries are keyed by the sandbox listening socket's inode, which the
// kernel recycles, so every use re-validates: the entry is only live while the
// socket behind the caller's fd is still bound to the port the mapping was
// created for ([`live_sandbox_port`]). A mismatch evicts the entry.
//
// Each mapped listener gets a dedicated blocking worker (a `spawn_blocking`
// thread) that polls BOTH the host listener and the sandbox's own accept
// queue and eagerly accepts into a bounded queue. The accept handler never
// blocks the notification loop: it pops a queued connection immediately, or
// defers to an async future that waits on the queue. That is what makes a
// sandbox-internal connect to a mapped port work — the supervisor loop stays
// free to run the connect handler that puts the connection into the sandbox's
// own accept queue, which the worker then accepts and injects.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;

/// Host-side listener for one mapped sandbox port. Owns the host listening
/// socket; dropping the entry closes the listener (the sandbox `close`
/// handler or sandbox teardown).
pub struct InboundListener {
    /// The host-netns listener on `host_port`. Dropping it closes the port.
    pub host_listener: OwnedFd,
    // Ports kept for introspection; the mapping key is the socket inode.
    #[allow(dead_code)]
    pub host_port: u16,
    #[allow(dead_code)]
    pub sandbox_port: u16,
    /// Connections accepted by the worker but not yet handed to the sandbox's
    /// `accept()`. Shared so concurrent accepts on the same listener (or a
    /// fork-inherited fd) can wait on one queue.
    pub conns: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<OwnedFd>>>,
    /// E7.1: number of connections currently queued in `conns`. The
    /// poll/epoll readiness synthesizer peeks this without consuming, so an
    /// event-loop server wakes and calls `accept()`.
    pub pending: Arc<AtomicUsize>,
    /// The eager-accept worker. Aborted (and cancellation flagged) on drop.
    pub worker: tokio::task::JoinHandle<()>,
    cancel: Arc<AtomicBool>,
}

impl Drop for InboundListener {
    fn drop(&mut self) {
        // Stop the eager-accept worker; its dup'd listeners then close, so the
        // host port is released within one poll slice of teardown.
        self.cancel.store(true, Ordering::Relaxed);
        self.worker.abort();
    }
}

/// Bounded queue size for accepted-but-not-yet-injected connections. The
/// worker's `blocking_send` blocks when the queue is full, so an overloaded
/// sandbox that stops calling `accept()` backs up in the kernel backlog
/// instead of unboundedly growing supervisor memory.
const INBOUND_QUEUE_CAP: usize = 16;

/// Poll-slice length for the eager-accept worker: bounds how long a cancelled
/// worker keeps its dup'd host listener open after teardown.
const WORKER_POLL_SLICE_MS: i32 = 2000;

/// The sandbox listening socket's inode, used as the stable key for the
/// inbound mapping. For sockets `fstat` returns the socket inode, shared by
/// every dup/fork of the same socket.
pub(crate) fn socket_ino(fd: RawFd) -> Option<u64> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } == 0 {
        Some(st.st_ino)
    } else {
        None
    }
}

/// The local TCP port a socket is bound to (via `getsockname`), or `None`
/// when it is not bound to an IP port. Called on the supervisor's dup of the
/// sandbox socket, which lives in the sandbox's netns — so it reports the
/// sandbox-side port.
pub(crate) fn local_port(fd: RawFd) -> Option<u16> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            fd,
            &mut storage as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret != 0 || len < 4 {
        return None;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(&storage as *const _ as *const u8, len as usize)
    };
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as u32;
    match family {
        f if f == libc::AF_INET as u32 || f == libc::AF_INET6 as u32 => {
            Some(u16::from_be_bytes([bytes[2], bytes[3]]))
        }
        _ => None,
    }
}

/// The port the *sandbox* thinks the socket is bound to.
///
/// `local_port` reports the real port, which `port_remap` may have moved: a
/// re-`bind()` of a port something else in the sandbox netns still holds
/// (notably this module's own eager-accept worker, which duplicates the
/// sandbox's listening socket) is retried with port 0, and the kernel's answer
/// is recorded as a virtual→real mapping. The inbound mapping is configured on
/// the port the app asked for, so the lookup has to translate back.
pub(crate) fn live_sandbox_port(ns: &crate::seccomp::state::NetworkState, fd: RawFd) -> Option<u16> {
    let real = local_port(fd)?;
    Some(ns.port_map.get_virtual(real).unwrap_or(real))
}

/// Create a host-netns listener on 127.0.0.1:host_port with the given
/// backlog. `SO_REUSEADDR` is set so a supervisor restart can re-bind a port
/// whose old socket is in TIME_WAIT. Returns the errno on failure.
fn create_host_listener(host_port: u16, backlog: i32) -> Result<OwnedFd, i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
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
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = host_port.to_be();
    sa.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    let ret = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    let ret = unsafe { libc::listen(fd, backlog) };
    if ret != 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    Ok(owned)
}

/// Dup an fd (with `FD_CLOEXEC`), returning the errno on failure.
fn duplicate_fd(fd: RawFd) -> Result<OwnedFd, i32> {
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        Err(unsafe { *libc::__errno_location() })
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(dup) })
    }
}

/// Blocking-mode probe for a socket (shared file status flags).
fn socket_nonblocking(fd: RawFd) -> bool {
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    fl >= 0 && fl & libc::O_NONBLOCK != 0
}

/// Poll the host listener and the sandbox's own listener, then accept from
/// the first ready one (host first, so external connections are preferred
/// over sandbox-internal ones). Runs on the dedicated worker thread; returns
/// `None` on cancellation (flag set) or a fatal accept error (e.g. EBADF
/// after the listener closed).
fn worker_accept_one(
    host_listener: RawFd,
    sandbox_listener: RawFd,
    cancel: &AtomicBool,
) -> Option<OwnedFd> {
    loop {
        let mut fds = [
            libc::pollfd {
                fd: host_listener,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: sandbox_listener,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, WORKER_POLL_SLICE_MS) };
        if ret < 0 {
            let err = unsafe { *libc::__errno_location() };
            if err == libc::EINTR {
                continue;
            }
            return None;
        }
        if ret == 0 {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            continue;
        }
        let source = if fds[0].revents & libc::POLLIN != 0 {
            host_listener
        } else {
            sandbox_listener
        };
        let fd = unsafe { libc::accept(source, std::ptr::null_mut(), std::ptr::null_mut()) };
        if fd >= 0 {
            return Some(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let err = unsafe { *libc::__errno_location() };
        // A concurrent accept may have stolen the connection between poll and
        // accept; keep waiting.
        if err == libc::EAGAIN || err == libc::EWOULDBLOCK || err == libc::EINTR {
            continue;
        }
        return None;
    }
}

/// Spawn the eager-accept worker for one mapped listener. It owns dups of the
/// host listener and the sandbox's listening socket, accepts connections from
/// either, and pushes them into `conns` (blocking when the queue is full).
/// Exits when the queue receiver is dropped (mapping removed) or the
/// cancellation flag is set (listener dropped).
fn spawn_inbound_worker(
    host_listener: RawFd,
    sandbox_listener: RawFd,
    cancel: Arc<AtomicBool>,
) -> Result<
    (
        tokio::sync::mpsc::Receiver<OwnedFd>,
        tokio::task::JoinHandle<()>,
        Arc<AtomicUsize>,
    ),
    i32,
> {
    let host_dup = duplicate_fd(host_listener)?;
    let sandbox_dup = duplicate_fd(sandbox_listener)?;
    let (tx, rx) = tokio::sync::mpsc::channel::<OwnedFd>(INBOUND_QUEUE_CAP);
    let pending = Arc::new(AtomicUsize::new(0));
    let pending_for_worker = Arc::clone(&pending);
    let cancel_for_worker = Arc::clone(&cancel);
    let worker = tokio::task::spawn_blocking(move || {
        let host = host_dup;
        let sandbox = sandbox_dup;
        loop {
            if cancel_for_worker.load(Ordering::Relaxed) {
                break;
            }
            let Some(fd) =
                worker_accept_one(host.as_raw_fd(), sandbox.as_raw_fd(), &cancel_for_worker)
            else {
                break;
            };
            if tx.blocking_send(fd).is_err() {
                break;
            }
            pending_for_worker.fetch_add(1, Ordering::SeqCst);
        }
    });
    Ok((rx, worker, pending))
}

/// `handle_listen` — a sandbox `listen()` on a mapped port:
///
/// 1. The sandbox's own socket listens in its netns (preserving internal
///    loopback, `poll`, and `getsockname` semantics).
/// 2. A host listener on the mapped host port is created and recorded under
///    the socket inode, with an eager-accept worker.
///
/// Unmapped ports fall through to the kernel (`Continue`). A host listener
/// that cannot be created (e.g. EADDRINUSE from another sandbox) fails the
/// sandbox's `listen()` closed rather than silently running without the
/// mapping.
pub(crate) async fn handle_listen(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    _notif_fd: RawFd,
) -> NotifAction {
    let sockfd = notif.data.args[0] as i32;
    let backlog = notif.data.args[1] as i32;

    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let ino = match socket_ino(dup_fd.as_raw_fd()) {
        Some(i) => i,
        None => return NotifAction::Errno(libc::EIO),
    };
    // The sandbox must have bound the socket already; an unbound listen is
    // left to the kernel (it returns EINVAL exactly as it would without us).
    // The mapping is configured on the port the *app* asked for, which
    // `port_remap` may have moved underneath it.
    let (sandbox_port, host_port, stale) = {
        let ns = ctx.network.lock().await;
        let Some(port) = live_sandbox_port(&ns, dup_fd.as_raw_fd()) else {
            return NotifAction::Continue;
        };
        let Some(host_port) = ns.inbound_map.get(&port).copied() else {
            return NotifAction::Continue;
        };
        if ns.inbound.contains_key(&ino) {
            // Re-listen on an already-mapped socket: keep the existing host
            // listener and worker, just re-run the sandbox-side listen.
            let ret = unsafe { libc::listen(dup_fd.as_raw_fd(), backlog) };
            return if ret == 0 {
                NotifAction::ReturnValue(0)
            } else {
                NotifAction::Errno(unsafe { *libc::__errno_location() })
            };
        }
        // Any other entry for this sandbox port belongs to a socket the
        // sandbox has already closed (option ②(a): `close` no longer tears
        // the mapping down). It is replaced below.
        let stale: Vec<u64> = ns
            .inbound
            .iter()
            .filter(|(k, l)| l.sandbox_port == port && **k != ino)
            .map(|(k, _)| *k)
            .collect();
        (port, host_port, stale)
    };
    if !stale.is_empty() {
        for key in &stale {
            ctx.network.lock().await.inbound.remove(key);
        }
        // The replaced listener's eager-accept worker holds a duplicate of the
        // old host listener for up to one poll slice, so the rebind can see
        // EADDRINUSE for a moment. Do the wait off the notification loop.
        let ctx = Arc::clone(ctx);
        return NotifAction::defer(async move {
            install_mapping(&ctx, dup_fd, ino, sandbox_port, host_port, backlog, true).await
        });
    }
    install_mapping(ctx, dup_fd, ino, sandbox_port, host_port, backlog, false).await
}

/// Create the host listener for a mapped sandbox port, run the sandbox-side
/// `listen()`, and record the mapping under the listening socket's inode.
///
/// `retry_port` is for the lazy-replacement path, where the previous mapping's
/// worker may still hold the host port for one poll slice; the plain first
/// listen keeps the original fail-closed behavior (a host port another sandbox
/// owns fails this `listen()` rather than running unmapped).
async fn install_mapping(
    ctx: &Arc<SupervisorCtx>,
    dup_fd: OwnedFd,
    ino: u64,
    sandbox_port: u16,
    host_port: u16,
    backlog: i32,
    retry_port: bool,
) -> NotifAction {
    let host_listener = if retry_port {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match create_host_listener(host_port, backlog) {
                Ok(l) => break l,
                Err(errno) if errno == libc::EADDRINUSE && std::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(errno) => return NotifAction::Errno(errno),
            }
        }
    } else {
        match create_host_listener(host_port, backlog) {
            Ok(l) => l,
            Err(errno) => return NotifAction::Errno(errno),
        }
    };
    let ret = unsafe { libc::listen(dup_fd.as_raw_fd(), backlog) };
    if ret != 0 {
        return NotifAction::Errno(unsafe { *libc::__errno_location() });
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let (rx, worker, pending) =
        match spawn_inbound_worker(host_listener.as_raw_fd(), dup_fd.as_raw_fd(), Arc::clone(&cancel))
        {
            Ok(w) => w,
            Err(errno) => return NotifAction::Errno(errno),
        };
    let conns = Arc::new(tokio::sync::Mutex::new(rx));
    ctx.network.lock().await.inbound.insert(
        ino,
        InboundListener {
            host_listener,
            host_port,
            sandbox_port,
            conns,
            pending,
            worker,
            cancel,
        },
    );
    NotifAction::ReturnValue(0)
}

/// `handle_accept4` — see [`handle_accept_impl`]. `accept4(fd, addr,
/// addrlen, flags)`: flags carry SOCK_CLOEXEC / SOCK_NONBLOCK for the new fd.
pub(crate) async fn handle_accept4(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    handle_accept_impl(notif, ctx, notif_fd, notif.data.args[3] as i32).await
}

/// Legacy `accept(fd, addr, addrlen)` (x86_64; absent on generic-ABI arches):
/// no flags — the new fd inherits the listener's status flags.
pub(crate) async fn handle_accept(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    handle_accept_impl(notif, ctx, notif_fd, 0).await
}

async fn handle_accept_impl(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
    flags: i32,
) -> NotifAction {
    let sockfd = notif.data.args[0] as i32;
    let addr_ptr = notif.data.args[1];
    let addrlen_ptr = notif.data.args[2];

    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let ino = match socket_ino(dup_fd.as_raw_fd()) {
        Some(i) => i,
        None => return NotifAction::Errno(libc::EIO),
    };
    // Snapshot the shared queue while holding the network lock briefly; the
    // accept itself (queued-pop or deferred wait) happens outside it. The
    // entry is validated against the live socket before it is used: the inode
    // key can be recycled, and the mapping outlives the sandbox closing its
    // listener (option ②(a)), so an entry with no live socket behind it must
    // not serve this accept.
    let (conns, pending) = {
        let mut ns = ctx.network.lock().await;
        match ns.inbound.get(&ino) {
            Some(l) if live_sandbox_port(&ns, dup_fd.as_raw_fd()) == Some(l.sandbox_port) => {
                (Arc::clone(&l.conns), Arc::clone(&l.pending))
            }
            Some(_) => {
                ns.inbound.remove(&ino);
                return NotifAction::Continue;
            }
            None => return NotifAction::Continue,
        }
    };
    let nonblocking = socket_nonblocking(dup_fd.as_raw_fd());

    // Fast path: a connection is already queued (eager worker accepted it).
    {
        let mut guard = conns.lock().await;
        match guard.try_recv() {
            Ok(fd) => {
                pending.fetch_sub(1, Ordering::SeqCst);
                return finish_accept(
                    fd,
                    notif,
                    notif_fd,
                    addr_ptr,
                    addrlen_ptr,
                    flags,
                    nonblocking,
                );
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                return NotifAction::Errno(libc::EIO);
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
        }
    }
    if nonblocking {
        return NotifAction::Errno(libc::EAGAIN);
    }

    // Blocking accept with no connection yet: defer to a worker future that
    // waits on the queue. The notification loop stays free (a sandbox-internal
    // connect needs it to reach this listener's own queue). The future
    // terminates when a connection arrives, the mapping is dropped (receiver
    // closed), or the child dies (`id_valid` guard) — see the unbounded
    // deferral handling for accept in `handle_notification`.
    let notif_owned = *notif;
    NotifAction::defer(async move {
        loop {
            let mut guard = conns.lock().await;
            let recv = guard.recv();
            tokio::select! {
                r = recv => {
                    return match r {
                        Some(fd) => {
                            pending.fetch_sub(1, Ordering::SeqCst);
                            finish_accept(
                                fd,
                                &notif_owned,
                                notif_fd,
                                addr_ptr,
                                addrlen_ptr,
                                flags,
                                nonblocking,
                            )
                        }
                        None => NotifAction::Errno(libc::EIO),
                    };
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                    drop(guard);
                    if crate::seccomp::notif::id_valid(notif_fd, notif_owned.id).is_err() {
                        return NotifAction::Errno(libc::EIO);
                    }
                }
            }
        }
    })
}

/// Tail of a served accept: mirror status flags, write the peer address into
/// the child's sockaddr buffer, and inject the accepted fd as the syscall's
/// result.
fn finish_accept(
    accepted: OwnedFd,
    notif: &SeccompNotif,
    notif_fd: RawFd,
    addr_ptr: u64,
    addrlen_ptr: u64,
    flags: i32,
    listener_nonblocking: bool,
) -> NotifAction {
    // Status flags on the injected fd: accept4's SOCK_NONBLOCK wins; legacy
    // accept() inherits the listener's O_NONBLOCK (Linux accept semantics).
    let accept_nonblocking = flags & libc::SOCK_NONBLOCK != 0;
    if accept_nonblocking || (!accept_nonblocking && listener_nonblocking) {
        unsafe {
            libc::fcntl(accepted.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
        }
    }

    // Peer address: accept() must fill the child's sockaddr buffer. On a
    // write failure the syscall fails with EFAULT and the accepted socket is
    // consumed (closed), matching kernel accept semantics.
    if addr_ptr != 0 && addrlen_ptr != 0 {
        if let Err(errno) =
            write_peer_addr(notif_fd, notif, accepted.as_raw_fd(), addr_ptr, addrlen_ptr)
        {
            return NotifAction::Errno(errno);
        }
    }

    let newfd_flags = if flags & libc::SOCK_CLOEXEC != 0 {
        libc::O_CLOEXEC as u32
    } else {
        0
    };
    NotifAction::InjectFdSend {
        srcfd: accepted,
        newfd_flags,
    }
}

/// Write the accepted connection's peer address into the child's `accept()`
/// sockaddr buffer, truncating to the caller's buffer size and storing the
/// full address length at `addrlen_ptr` (kernel accept semantics). Returns
/// the errno to surface (EFAULT) on failure.
fn write_peer_addr(
    notif_fd: RawFd,
    notif: &SeccompNotif,
    accepted_fd: RawFd,
    addr_ptr: u64,
    addrlen_ptr: u64,
) -> Result<(), i32> {
    let len_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, addrlen_ptr, 4) {
        Ok(b) if b.len() >= 4 => b,
        _ => return Err(libc::EFAULT),
    };
    let buf_len = u32::from_ne_bytes(len_bytes[..4].try_into().unwrap()) as usize;

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut actual_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let ret = unsafe {
        libc::getpeername(
            accepted_fd,
            &mut storage as *mut _ as *mut libc::sockaddr,
            &mut actual_len,
        )
    };
    if ret != 0 {
        return Err(libc::EFAULT);
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(&storage as *const _ as *const u8, actual_len as usize)
    };
    let to_write = bytes.len().min(buf_len);
    write_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, &bytes[..to_write])
        .map_err(|_| libc::EFAULT)?;
    write_child_mem(
        notif_fd,
        notif.id,
        notif.pid,
        addrlen_ptr,
        &(bytes.len() as u32).to_ne_bytes(),
    )
    .map_err(|_| libc::EFAULT)
}
