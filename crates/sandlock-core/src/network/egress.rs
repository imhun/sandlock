//! SOCKS5 egress proxy (Block C, R12–R14).
//!
//! When an egress proxy is configured, every **TCP** connect that passes the
//! destination allow/deny filter is tunneled through the user's SOCKS5
//! upstream instead of being dialed directly. UDP/ICMP are not tunneled
//! (matching E2B semantics). The tunnel runs in the supervisor on the
//! on-behalf connect path, so it applies to every sandboxed process —
//! including static/Go binaries that never call `getaddrinfo` — and cannot
//! be bypassed by clearing `LD_PRELOAD`.
//!
//! Fail-closed invariants (R13): a proxy that is unreachable, that answers a
//! non-SOCKS5 greeting, that selects an unsupported/refused auth method, or
//! that rejects the CONNECT turns the sandboxed connect into `ECONNREFUSED` —
//! the supervisor never falls back to a direct connection. The proxy endpoint
//! itself is dialed by the supervisor and is *not* added to the sandbox's
//! allowlist, so the sandbox cannot reach the proxy directly and skip the
//! tunnel/filter.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::os::unix::io::RawFd;
use std::time::Duration;

use crate::error::SandboxError;
use crate::sys::structs::ECONNREFUSED;

/// User-facing egress proxy configuration (address + optional RFC 1929
/// username/password). The password is a secret: this type is never
/// serialized into a policy/profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressProxyConfig {
    pub address: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Supervisor-side resolved proxy: a literal endpoint plus credential bytes.
/// `addr` is resolved at sandbox build time (the supervisor has DNS).
#[derive(Clone, Debug)]
pub struct EgressProxy {
    pub addr: SocketAddr,
    pub username: Option<Vec<u8>>,
    pub password: Option<Vec<u8>>,
}

/// Resolve and validate an egress proxy spec. `address` is `host:port` or
/// `[v6]:port`; hostnames are resolved supervisor-side at build time.
pub fn resolve_egress_proxy(
    address: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<EgressProxy, SandboxError> {
    let (host, port_s) = address
        .rsplit_once(':')
        .ok_or_else(|| SandboxError::Invalid(format!("egress proxy address must be host:port, got {address:?}")))?;
    if host.is_empty() {
        return Err(SandboxError::Invalid(format!(
            "egress proxy address must be host:port, got {address:?}"
        )));
    }
    let port: u16 = port_s.parse().map_err(|_| {
        SandboxError::Invalid(format!("egress proxy port must be 1-65535, got {port_s:?}"))
    })?;
    if port == 0 {
        return Err(SandboxError::Invalid(format!(
            "egress proxy port must be 1-65535, got {port_s:?}"
        )));
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addr = match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => {
            let addrs: Vec<SocketAddr> = (host, port)
                .to_socket_addrs()
                .map_err(|e| {
                    SandboxError::Invalid(format!("egress proxy host {host:?} does not resolve: {e}"))
                })?
                .collect();
            *addrs.first().ok_or_else(|| {
                SandboxError::Invalid(format!("egress proxy host {host:?} resolved to no addresses"))
            })?
        }
    };
    Ok(EgressProxy {
        addr,
        username: username.map(|s| s.as_bytes().to_vec()),
        password: password.map(|s| s.as_bytes().to_vec()),
    })
}

/// Destination of a SOCKS5 CONNECT request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Socks5Dest {
    /// Remote DNS: the proxy resolves the hostname (ATYP=domain).
    Domain(String),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// Cap on the SOCKS5 handshake so a dead-but-accepting proxy cannot stall the
/// supervisor's notification loop forever. 10s is far above any sane LAN
/// proxy and keeps the sandboxed connect from hanging indefinitely.
const SOCKS5_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect `fd` (a dup of the sandbox's socket) to `proxy` and complete a
/// SOCKS5 CONNECT for `dest:port`. On success the fd is left connected and
/// handed back to the sandbox with the tunnel established; on any failure the
/// dup is closed and `Err(ECONNREFUSED)` is returned (fail closed).
///
/// `is_ipv6_socket` selects the sockaddr family for the proxy connect: a
/// dual-stack AF_INET6 socket dialing an IPv4 proxy uses the v4-mapped
/// address, exactly like the HTTP ACL redirect path.
pub fn socks5_connect(
    fd: RawFd,
    proxy: &EgressProxy,
    dest: &Socks5Dest,
    port: u16,
    is_ipv6_socket: bool,
) -> Result<(), i32> {
    let proxy_bytes = proxy_sockaddr_bytes(proxy.addr, is_ipv6_socket)?;
    let rc = unsafe {
        libc::connect(
            fd,
            proxy_bytes.as_ptr() as *const libc::sockaddr,
            proxy_bytes.len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let errno = unsafe { *libc::__errno_location() };
        if errno != libc::EINPROGRESS {
            return Err(errno);
        }
        // Non-blocking socket (python's create_connection sets O_NONBLOCK on
        // the shared open file description): wait for the connection to
        // complete, then read the pending error via SO_ERROR.
        poll_fd(fd, libc::POLLOUT)?;
        let mut sock_err: libc::c_int = 0;
        let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let so = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut sock_err as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if so != 0 || sock_err != 0 {
            return Err(ECONNREFUSED);
        }
    }
    socks5_handshake(fd, proxy, dest, port)
}

/// Run the SOCKS5 greeting/auth/CONNECT exchange on `fd` (already connected
/// to the proxy). On success the fd is left open and tunneled; on any failure
/// the dup is closed and `Err(ECONNREFUSED)` returned (fail closed).
fn socks5_handshake(
    fd: RawFd,
    proxy: &EgressProxy,
    dest: &Socks5Dest,
    port: u16,
) -> Result<(), i32> {
    // 1. Greeting: SOCKS5 + offered methods (no-auth; user/pass when creds).
    let has_creds = proxy.username.is_some() || proxy.password.is_some();
    let mut greeting = vec![0x05u8, if has_creds { 2 } else { 1 }];
    if has_creds {
        greeting.push(0x02); // RFC 1929 username/password
        greeting.push(0x00); // no-auth (refused below when creds are set)
    } else {
        greeting.push(0x00);
    }
    write_all_poll(fd, &greeting)?;
    let mut sel = [0u8; 2];
    if read_exact_poll(fd, &mut sel).is_err() || sel[0] != 0x05 {
        return Err(ECONNREFUSED); // not SOCKS5
    }
    match sel[1] {
        0xFF => return Err(ECONNREFUSED), // no acceptable method
        0x00 if has_creds => {
            // Server offered no-auth but the user demanded auth: refuse rather
            // than silently sending the secret-bearing request unauthenticated.
            return Err(ECONNREFUSED);
        }
        0x02 => {
            let user = proxy.username.as_deref().unwrap_or(b"");
            let pass = proxy.password.as_deref().unwrap_or(b"");
            if user.len() > 255 || pass.len() > 255 {
                return Err(ECONNREFUSED);
            }
            let mut auth = vec![0x01u8, user.len() as u8];
            auth.extend_from_slice(user);
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass);
            write_all_poll(fd, &auth)?;
            let mut aresp = [0u8; 2];
            if read_exact_poll(fd, &mut aresp).is_err() || aresp[0] != 0x01 || aresp[1] != 0x00 {
                return Err(ECONNREFUSED);
            }
        }
        0x00 => {}
        _ => return Err(ECONNREFUSED),
    }

    // 2. CONNECT request (RFC 1928): VER=5, CMD=1, RSV=0, ATYP, DST.ADDR, DST.PORT.
    let mut req = vec![0x05u8, 0x01, 0x00];
    match dest {
        Socks5Dest::Domain(d) => {
            if d.is_empty() || d.len() > 255 {
                return Err(ECONNREFUSED);
            }
            req.push(0x03); // ATYP=domain
            req.push(d.len() as u8);
            req.extend_from_slice(d.as_bytes());
        }
        Socks5Dest::V4(v) => {
            req.push(0x01); // ATYP=IPv4
            req.extend_from_slice(&v.octets());
        }
        Socks5Dest::V6(v) => {
            req.push(0x04); // ATYP=IPv6
            req.extend_from_slice(&v.octets());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    write_all_poll(fd, &req)?;

    // 3. Reply: VER=5, REP, RSV, ATYP, BND.ADDR, BND.PORT. REP 0 = success.
    let mut head = [0u8; 4];
    if read_exact_poll(fd, &mut head).is_err() || head[0] != 0x05 || head[2] != 0x00 {
        return Err(ECONNREFUSED);
    }
    if head[1] != 0x00 {
        return Err(ECONNREFUSED);
    }
    let bind_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            if read_exact_poll(fd, &mut l).is_err() {
                return Err(ECONNREFUSED);
            }
            l[0] as usize
        }
        _ => return Err(ECONNREFUSED),
    };
    let mut bind = vec![0u8; bind_len + 2];
    if read_exact_poll(fd, &mut bind).is_err() {
        return Err(ECONNREFUSED);
    }

    // Tunnel established; the fd stays owned by the caller and is handed back
    // to the sandbox connected to the proxy.
    Ok(())
}

/// Poll `fd` for `events` with the SOCKS5 timeout; `Err(ECONNREFUSED)` on
/// timeout, error, or hangup (fail closed).
fn poll_fd(fd: RawFd, events: i16) -> Result<(), i32> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let deadline = std::time::Instant::now() + SOCKS5_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(ECONNREFUSED);
        }
        let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ECONNREFUSED);
        }
        if rc == 0 {
            return Err(ECONNREFUSED); // timed out
        }
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(ECONNREFUSED);
        }
        if pfd.revents & events != 0 {
            return Ok(());
        }
    }
}

/// Send all of `buf`, polling for writability (non-blocking-safe).
fn write_all_poll(fd: RawFd, mut buf: &[u8]) -> Result<(), i32> {
    while !buf.is_empty() {
        poll_fd(fd, libc::POLLOUT)?;
        let n = unsafe {
            libc::send(
                fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(ECONNREFUSED);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// Receive exactly `buf.len()` bytes, polling for readability.
fn read_exact_poll(fd: RawFd, mut buf: &mut [u8]) -> Result<(), i32> {
    while !buf.is_empty() {
        poll_fd(fd, libc::POLLIN)?;
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n == 0 {
            return Err(ECONNREFUSED); // EOF before the full reply
        }
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(ECONNREFUSED);
        }
        buf = &mut buf[n as usize..];
    }
    Ok(())
}

/// Build the sockaddr bytes for dialing `proxy` in the socket's own family
/// (IPv4-mapped for a dual-stack v6 socket dialing an IPv4 proxy).
fn proxy_sockaddr_bytes(proxy: SocketAddr, is_ipv6_socket: bool) -> Result<Vec<u8>, i32> {
    if is_ipv6_socket {
        let mut sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sa6.sin6_family = libc::AF_INET6 as u16;
        sa6.sin6_port = proxy.port().to_be();
        sa6.sin6_addr.s6_addr = match proxy {
            SocketAddr::V4(v4) => v4.ip().to_ipv6_mapped().octets(),
            SocketAddr::V6(v6) => v6.ip().octets(),
        };
        Ok(unsafe {
            std::slice::from_raw_parts(
                &sa6 as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_in6>(),
            )
        }
        .to_vec())
    } else {
        let SocketAddr::V4(v4) = proxy else {
            return Err(libc::EAFNOSUPPORT);
        };
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as u16;
        sa.sin_port = proxy.port().to_be();
        sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
        Ok(unsafe {
            std::slice::from_raw_parts(
                &sa as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            )
        }
        .to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::IntoRawFd;

    /// Run a SOCKS5 "server" script in a thread over one end of a socketpair
    /// and return the client fd for `socks5_handshake`. Panics inside the
    /// server thread propagate via the JoinHandle.
    fn pair_with_server(
        server: impl FnOnce(RawFd) + Send + 'static,
    ) -> (RawFd, std::thread::JoinHandle<()>) {
        use std::os::unix::net::UnixStream;
        let (server_sock, client_sock) = UnixStream::pair().unwrap();
        let server_fd = server_sock.into_raw_fd();
        let client_fd = client_sock.into_raw_fd();
        let handle = std::thread::spawn(move || server(server_fd));
        (client_fd, handle)
    }

    #[test]
    fn resolve_parses_host_port_and_creds() {
        let p = resolve_egress_proxy("127.0.0.1:1080", Some("u"), Some("p")).unwrap();
        assert_eq!(p.addr, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(p.username.as_deref(), Some(b"u".as_slice()));
        assert_eq!(p.password.as_deref(), Some(b"p".as_slice()));
    }

    #[test]
    fn resolve_accepts_ipv6_literal() {
        let p = resolve_egress_proxy("[::1]:1080", None, None).unwrap();
        assert_eq!(p.addr, "[::1]:1080".parse().unwrap());
    }

    #[test]
    fn resolve_rejects_bad_specs() {
        assert!(resolve_egress_proxy("noport", None, None).is_err());
        assert!(resolve_egress_proxy(":1080", None, None).is_err());
        assert!(resolve_egress_proxy("host:0", None, None).is_err());
        assert!(resolve_egress_proxy("host:99999", None, None).is_err());
        assert!(resolve_egress_proxy("no.such.host.invalid:1080", None, None).is_err());
    }

    /// Hermetic SOCKS5 server + client handshake proof over a socketpair:
    /// the client sends a domain CONNECT and the server asserts the exact
    /// wire bytes (greeting, request, ATYP=domain), then replies success.
    #[test]
    fn socks5_connect_completes_domain_handshake() {
        let proxy = EgressProxy {
            username: None,
            password: None,
            addr: "127.0.0.1:9".parse().unwrap(), // unused by handshake
        };
        let dest = Socks5Dest::Domain("api.example.com".to_string());

        let (client_fd, server) = pair_with_server(move |fd| {
            let mut buf = [0u8; 64];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 64) };
            assert_eq!(n, 3);
            assert_eq!(&buf[..3], &[0x05, 0x01, 0x00]);
            unsafe { libc::write(fd, b"\x05\x00".as_ptr() as *const libc::c_void, 2) };
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 64) };
            assert_eq!(n as usize, 4 + 1 + "api.example.com".len() + 2);
            assert_eq!(&buf[..4], &[0x05, 0x01, 0x00, 0x03]);
            assert_eq!(buf[4], "api.example.com".len() as u8);
            assert_eq!(&buf[5..5 + 15], b"api.example.com");
            assert_eq!(&buf[5 + 15..5 + 15 + 2], &443u16.to_be_bytes());
            unsafe {
                libc::write(
                    fd,
                    b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00".as_ptr() as *const libc::c_void,
                    10,
                )
            };
        });

        let res = socks5_handshake(client_fd, &proxy, &dest, 443);
        server.join().unwrap();
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn socks5_fails_closed_on_server_reject() {
        let proxy = EgressProxy {
            addr: "127.0.0.1:9".parse().unwrap(),
            username: None,
            password: None,
        };
        let dest = Socks5Dest::V4(Ipv4Addr::LOCALHOST);

        let (client_fd, server) = pair_with_server(move |fd| {
            let mut buf = [0u8; 64];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 64) };
            assert_eq!(n, 3);
            unsafe { libc::write(fd, b"\x05\x00".as_ptr() as *const libc::c_void, 2) };
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 64) };
            assert!(n > 0);
            // REP=5 (connection refused) → client must fail closed.
            unsafe {
                libc::write(
                    fd,
                    b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00".as_ptr() as *const libc::c_void,
                    10,
                )
            };
        });

        let res = socks5_handshake(client_fd, &proxy, &dest, 80);
        server.join().unwrap();
        assert_eq!(res, Err(ECONNREFUSED));
    }

    #[test]
    fn socks5_refuses_no_auth_when_creds_required() {
        let proxy = EgressProxy {
            addr: "127.0.0.1:9".parse().unwrap(),
            username: Some(b"u".to_vec()),
            password: Some(b"p".to_vec()),
        };
        let dest = Socks5Dest::V4(Ipv4Addr::LOCALHOST);

        let (client_fd, server) = pair_with_server(move |fd| {
            let mut buf = [0u8; 64];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 64) };
            assert_eq!(n, 4);
            assert_eq!(&buf[..4], &[0x05, 0x02, 0x02, 0x00]);
            // Malicious/naive proxy picks no-auth despite creds being required.
            unsafe { libc::write(fd, b"\x05\x00".as_ptr() as *const libc::c_void, 2) };
        });

        let res = socks5_handshake(client_fd, &proxy, &dest, 80);
        server.join().unwrap();
        assert_eq!(res, Err(ECONNREFUSED));
    }

    #[test]
    fn socks5_rfc1929_auth_flow() {
        let proxy = EgressProxy {
            addr: "127.0.0.1:9".parse().unwrap(),
            username: Some(b"user".to_vec()),
            password: Some(b"pass".to_vec()),
        };
        let dest = Socks5Dest::V4(Ipv4Addr::new(93, 184, 216, 34));

        let (client_fd, server) = pair_with_server(move |fd| {
            let mut buf = [0u8; 64];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 64) };
            assert_eq!(n, 4);
            unsafe { libc::write(fd, b"\x05\x02".as_ptr() as *const libc::c_void, 2) };
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 64) };
            assert_eq!(n, 1 + 1 + 4 + 1 + 4);
            assert_eq!(&buf[..2], &[0x01, 0x04]);
            assert_eq!(&buf[2..6], b"user");
            assert_eq!(buf[6], 4);
            assert_eq!(&buf[7..11], b"pass");
            unsafe { libc::write(fd, b"\x01\x00".as_ptr() as *const libc::c_void, 2) };
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 64) };
            assert_eq!(n, 10);
            assert_eq!(&buf[..6], &[0x05, 0x01, 0x00, 0x01, 93, 184]);
            unsafe {
                libc::write(
                    fd,
                    b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00".as_ptr() as *const libc::c_void,
                    10,
                )
            };
        });

        let res = socks5_handshake(client_fd, &proxy, &dest, 443);
        server.join().unwrap();
        assert_eq!(res, Ok(()));
    }
}
