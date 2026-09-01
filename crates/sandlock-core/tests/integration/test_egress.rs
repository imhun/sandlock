//! SOCKS5 egress proxy integration tests (Block C, R12–R14).
//!
//! The sandbox's TCP connects are tunneled through a local SOCKS5 forwarder
//! after allow/deny filtering; UDP/ICMP stay direct. The proxy endpoint is
//! never in the sandbox's allowlist, and a dead proxy fails the connect
//! closed (ECONNREFUSED, never a direct fallback).

use sandlock_core::Sandbox;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Mutex;

use crate::net_fixture::WorkerLocalHost;

fn base_policy() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
}

fn stdout_of(result: &sandlock_core::result::RunResult) -> String {
    String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).into_owned()
}

/// What the SOCKS5 forwarder saw on its CONNECT request.
#[derive(Clone, Debug)]
struct SeenConnect {
    atyp: u8,
    host: String,
    port: u16,
}

/// Minimal RFC 1928 SOCKS5 forwarder: no auth, reads CONNECT, records the
/// destination, connects to it, replies success, then pipes bytes both ways.
fn spawn_socks5_forwarder() -> (
    u16,
    std::thread::JoinHandle<()>,
    std::sync::Arc<Mutex<Option<SeenConnect>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(Mutex::new(None));
    let seen_cap = seen.clone();
    let handle = std::thread::spawn(move || {
        // One connection per forwarder instance; the thread exits after it,
        // so the test never needs to interrupt a blocked accept.
        if let Ok((mut client, _)) = listener.accept() {
            // Greeting: read methods, answer no-auth.
            let mut buf = [0u8; 4];
            let n = client.read(&mut buf).unwrap_or(0);
            if n < 2 || buf[0] != 0x05 {
                return;
            }
            client.write_all(&[0x05, 0x00]).unwrap();
            // CONNECT: VER CMD RSV ATYP ...
            let mut head = [0u8; 4];
            if client.read_exact(&mut head).is_err() || head[0] != 0x05 || head[1] != 0x01 {
                return;
            }
            let (dest_host, bind_len) = match head[3] {
                0x01 => {
                    let mut a = [0u8; 4];
                    if client.read_exact(&mut a).is_err() {
                        return;
                    }
                    (
                        std::net::Ipv4Addr::from(a).to_string(),
                        4usize,
                    )
                }
                0x03 => {
                    let mut l = [0u8; 1];
                    if client.read_exact(&mut l).is_err() {
                        return;
                    }
                    let mut h = vec![0u8; l[0] as usize];
                    if client.read_exact(&mut h).is_err() {
                        return;
                    }
                    (String::from_utf8_lossy(&h).into_owned(), l[0] as usize)
                }
                0x04 => {
                    let mut a = [0u8; 16];
                    if client.read_exact(&mut a).is_err() {
                        return;
                    }
                    (
                        std::net::Ipv6Addr::from(a).to_string(),
                        16usize,
                    )
                }
                _ => return,
            };
            let mut port_b = [0u8; 2];
            if client.read_exact(&mut port_b).is_err() {
                return;
            }
            let dest_port = u16::from_be_bytes(port_b);
            *seen_cap.lock().unwrap() = Some(SeenConnect {
                atyp: head[3],
                host: dest_host.clone(),
                port: dest_port,
            });

            let dest: SocketAddr = match (dest_host.parse::<std::net::IpAddr>(), bind_len) {
                (Ok(ip), _) => SocketAddr::new(ip, dest_port),
                (Err(_), _) => {
                    // Domain: resolve worker-side (the fixture lives in /etc/hosts).
                    let Ok(ip) = (dest_host.as_str(), dest_port).to_socket_addrs()
                        .map(|mut it| it.next().map(|sa| sa.ip()))
                    else {
                        return;
                    };
                    let Some(ip) = ip else { return };
                    SocketAddr::new(ip, dest_port)
                }
            };
            let Ok(mut upstream) = TcpStream::connect(dest) else {
                client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
                return;
            };
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
            let mut c2u = client.try_clone().unwrap();
            let mut u2c = upstream.try_clone().unwrap();
            let t1 = std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    let n = match c2u.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if upstream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
            let t2 = std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    let n = match u2c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if client.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
            let _ = t1.join();
            let _ = t2.join();
        }
    });
    (port, handle, seen)
}

/// Allowed TCP is tunneled through the SOCKS5 proxy: the child connects to
/// the origin address, the supervisor dials the proxy, and the origin sees
/// the request — the child never talks to the origin directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_socks5_tunnels_tcp_after_filter() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_socks5_tunnels_tcp_after_filter_inner(),
    )
    .await
    .expect("socks5 tunnel test timed out");
}

async fn test_socks5_tunnels_tcp_after_filter_inner() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let origin_server = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().unwrap();
        stream.write_all(b"TUNNELED-OK").unwrap();
    });
    let (proxy_port, proxy_handle, seen) = spawn_socks5_forwarder();

    // The destination filter allows only the origin; the proxy endpoint is
    // NOT in net_allow, so the sandbox cannot dial it directly.
    let mut policy = base_policy()
        .net_allow(format!("127.0.0.1:{}", origin_port))
        .egress_proxy(format!("127.0.0.1:{}", proxy_port))
        .build()
        .unwrap();
    let script = format!(
        "import socket\n\
         s = socket.create_connection(('127.0.0.1', {port}), timeout=10)\n\
         print(s.recv(64).decode())\n\
         s.close()\n",
        port = origin_port
    );
    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = stdout_of(&result);
    assert!(
        out.contains("TUNNELED-OK"),
        "child should reach origin through the tunnel, stdout={out:?} stderr={:?}",
        result
            .stderr
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
    );

    origin_server.await.unwrap();
    let _ = proxy_handle.join();
    let seen = seen.lock().unwrap().clone().expect("proxy must see a CONNECT");
    assert_eq!(seen.atyp, 0x01, "literal IP target uses ATYP=IPv4");
    assert_eq!(seen.host, "127.0.0.1");
    assert_eq!(seen.port, origin_port);
}

/// A dead proxy fails the sandboxed connect closed — no direct fallback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_socks5_fail_closed_when_proxy_unreachable() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_socks5_fail_closed_when_proxy_unreachable_inner(),
    )
    .await
    .expect("fail-closed test timed out");
}

async fn test_socks5_fail_closed_when_proxy_unreachable_inner() {
    // Grab an ephemeral port that nothing listens on.
    let dead_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = dead_proxy.local_addr().unwrap().port();
    drop(dead_proxy);

    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();

    let mut policy = base_policy()
        .net_allow(format!("127.0.0.1:{}", origin_port))
        .egress_proxy(format!("127.0.0.1:{}", dead_port))
        .build()
        .unwrap();
    let script = format!(
        "import socket\n\
         try:\n\
         \x20 s = socket.create_connection(('127.0.0.1', {port}), timeout=10)\n\
         \x20 print('CONNECTED')\n\
         except OSError as e:\n\
         \x20 print(f'ERR:{{e.errno}}')\n",
        port = origin_port
    );
    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = stdout_of(&result);
    assert!(
        out.contains("ERR:111"),
        "dead proxy must fail the connect with ECONNREFUSED (never direct), got: {out}"
    );
}

/// With `fd_inject_connect` on, an allowed TCP connect is still tunneled
/// through the SOCKS5 egress proxy: the fresh host-side socket dials the
/// proxy, the tunnel is injected into the sandbox, and the trapped connect()
/// returns the injected fd number — never a direct path to the origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_socks5_tunnels_tcp_with_fd_injection() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_socks5_tunnels_tcp_with_fd_injection_inner(),
    )
    .await
    .expect("socks5 fd-injection tunnel test timed out");
}

async fn test_socks5_tunnels_tcp_with_fd_injection_inner() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let origin_server = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().unwrap();
        stream.write_all(b"TUNNELED-OK").unwrap();
    });
    let (proxy_port, proxy_handle, seen) = spawn_socks5_forwarder();

    // The destination filter allows only the origin; the proxy endpoint is
    // NOT in net_allow, so the sandbox cannot dial it directly.
    let mut policy = base_policy()
        .net_allow(format!("127.0.0.1:{}", origin_port))
        .egress_proxy(format!("127.0.0.1:{}", proxy_port))
        .fd_inject_connect(true)
        .build()
        .unwrap();
    let script = format!(concat!(
        "import ctypes, socket, struct\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "libc.connect.restype = ctypes.c_int\n",
        "libc.recv.restype = ctypes.c_ssize_t\n",
        "fd = libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0)\n",
        "addr = struct.pack('<H', socket.AF_INET) + struct.pack('!H', {origin}) + socket.inet_aton('127.0.0.1') + b'\\x00' * 8\n",
        "buf = ctypes.create_string_buffer(addr)\n",
        "ctypes.set_errno(0)\n",
        "ret = libc.connect(fd, buf, len(addr))\n",
        "if ret < 0:\n",
        "  print(f'CONNECT_ERR:{{ctypes.get_errno()}}')\n",
        "  raise SystemExit(0)\n",
        "data = b''\n",
        "buf2 = ctypes.create_string_buffer(64)\n",
        "while len(data) < 11:\n",
        "  n = libc.recv(fd, buf2, 64, 0)\n",
        "  if n <= 0:\n",
        "    break\n",
        "  data += buf2.raw[:n]\n",
        "print(f'RET={{ret}} FD={{fd}} DATA={{data[:11].decode()}}')\n",
    ), origin = origin_port);

    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = stdout_of(&result);
    let parts: Vec<&str> = out.split_whitespace().collect();
    assert_eq!(parts.len(), 3, "unexpected stdout: {out:?}");
    let ret: i32 = parts[0]
        .strip_prefix("RET=")
        .expect("RET field")
        .parse()
        .unwrap();
    let fd: i32 = parts[1]
        .strip_prefix("FD=")
        .expect("FD field")
        .parse()
        .unwrap();
    assert_eq!(
        ret, fd,
        "injected connect must return the fd number under egress, got: {out:?}"
    );
    assert_eq!(
        parts[2], "DATA=TUNNELED-OK",
        "child must reach the origin through the tunnel under fd injection, got: {out:?}"
    );

    origin_server.await.unwrap();
    let _ = proxy_handle.join();
    let seen = seen.lock().unwrap().clone().expect("proxy must see a CONNECT");
    assert_eq!(seen.atyp, 0x01, "literal IP target uses ATYP=IPv4");
    assert_eq!(seen.host, "127.0.0.1");
    assert_eq!(seen.port, origin_port);
}

/// A wildcard-domain destination keeps its name: the proxy receives
/// ATYP=domain and resolves it remotely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_socks5_wildcard_uses_atyp_domain() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_socks5_wildcard_uses_atyp_domain_inner(),
    )
    .await
    .expect("atyp domain test timed out");
}

async fn test_socks5_wildcard_uses_atyp_domain_inner() {
    let _host = WorkerLocalHost::setup("api.egress.test");
    let origin = TcpListener::bind((_host.addr(), 0)).unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let origin_server = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().unwrap();
        stream.write_all(b"DOMAIN-OK").unwrap();
    });
    let (proxy_port, proxy_handle, seen) = spawn_socks5_forwarder();

    let mut policy = base_policy()
        .net_allow(format!("*.egress.test:{}", origin_port))
        .egress_proxy(format!("127.0.0.1:{}", proxy_port))
        .build()
        .unwrap();
    let script = format!(
        "import socket\n\
         s = socket.create_connection(('api.egress.test', {port}), timeout=10)\n\
         print(s.recv(64).decode())\n\
         s.close()\n",
        port = origin_port
    );
    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = stdout_of(&result);
    assert!(
        out.contains("DOMAIN-OK"),
        "wildcard-domain child should reach origin through the tunnel, got: {out}"
    );

    origin_server.await.unwrap();
    let _ = proxy_handle.join();
    let seen = seen.lock().unwrap().clone().expect("proxy must see a CONNECT");
    assert_eq!(seen.atyp, 0x03, "wildcard domain must use ATYP=domain (remote DNS)");
    assert_eq!(seen.host, "api.egress.test");
    assert_eq!(seen.port, origin_port);
}
