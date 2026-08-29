//! Per-sandbox network namespace integration tests.
//!
//! These require a privileged container (CAP_SYS_ADMIN + CAP_NET_ADMIN) and
//! run inside the sandlock-dev / test-runner images. They verify the three
//! properties the feature promises:
//!   1. loopback isolation — the sandbox cannot reach the worker's
//!      127.0.0.1 services;
//!   2. wildcard DNS — the sandbox's getaddrinfo for a wildcard subdomain
//!      returns a synthetic IP from the supervisor's gateway;
//!   3. wildcard connect — a TCP connect to the subdomain is resolved
//!      supervisor-side and reaches the real destination.

use sandlock_core::Sandbox;
use std::io::{Read, Write};
use std::net::TcpListener;

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

/// True when `ip` lies in the synthetic DNS range (127.0.0.2/8).
fn is_synthetic(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let n = u32::from(ip);
    (0x7f00_0002..=0x7fff_fffe).contains(&n)
}

fn stdout_of(result: &sandlock_core::result::RunResult) -> String {
    String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).into_owned()
}

/// Worker-side fixture: map `host` to 198.18.0.99 (a benchmarking-range
/// address the SSRF guard deliberately allows) and put that address on the
/// worker's loopback so local servers can bind it. Returns a guard whose
/// Drop restores `/etc/hosts` and removes the address.
struct WorkerLocalHost {
    hosts_backup: Vec<u8>,
    added: bool,
}

impl WorkerLocalHost {
    fn setup(host: &str) -> Self {
        let _ = std::process::Command::new("ip")
            .args(["addr", "add", "198.18.0.99/32", "dev", "lo"])
            .status();
        let hosts_backup = std::fs::read("/etc/hosts").unwrap_or_default();
        let hosts = String::from_utf8_lossy(&hosts_backup).into_owned();
        let added = if hosts.contains(host) {
            false
        } else {
            let mut h = hosts;
            h.push_str(&format!("198.18.0.99 {}\n", host));
            let _ = std::fs::write("/etc/hosts", h);
            true
        };
        WorkerLocalHost { hosts_backup, added }
    }
}

impl Drop for WorkerLocalHost {
    fn drop(&mut self) {
        if self.added {
            let _ = std::fs::write("/etc/hosts", &self.hosts_backup);
        }
        let _ = std::process::Command::new("ip")
            .args(["addr", "del", "198.18.0.99/32", "dev", "lo"])
            .status();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_netns_isolates_host_loopback() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_netns_isolates_host_loopback_inner(),
    )
    .await
    .expect("netns isolation test timed out");
}

async fn test_netns_isolates_host_loopback_inner() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let script = format!(
        "import socket\n\
         try:\n\
         \x20 s = socket.create_connection(('127.0.0.1', {port}), timeout=2)\n\
         \x20 print('CONNECTED')\n\
         except OSError as e:\n\
         \x20 print(f'ERR:{{e.errno}}')\n",
        port = port
    );

    // With per-sandbox netns the sandbox's loopback is its own: the worker's
    // 127.0.0.1:port must be unreachable (refused), not CONNECTED.
    let mut policy = base_policy()
        .netns(true)
        .net_allow(format!("127.0.0.1:{}", port))
        .build()
        .unwrap();
    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = stdout_of(&result);
    assert!(!out.contains("CONNECTED"), "netns sandbox reached host loopback: {out}");
    assert!(out.contains("ERR:"), "expected refusal, got: {out}");

    // Control: without netns the same sandbox reaches the worker's loopback.
    let mut policy = base_policy()
        .net_allow(format!("127.0.0.1:{}", port))
        .build()
        .unwrap();
    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = stdout_of(&result);
    assert!(out.contains("CONNECTED"), "control sandbox should reach host loopback: {out}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_netns_wildcard_dns_returns_synthetic_ip() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_netns_wildcard_dns_returns_synthetic_ip_inner(),
    )
    .await
    .expect("netns DNS test timed out");
}

async fn test_netns_wildcard_dns_returns_synthetic_ip_inner() {
    let mut policy = base_policy()
        .netns(true)
        .net_allow("*.example.com:443")
        .build()
        .unwrap();
    let script = "import socket\n\
                  try:\n\
                  \x20 print(socket.gethostbyname('api.example.com'))\n\
                  except OSError as e:\n\
                  \x20 print(f'ERR:{e}')\n";
    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = stdout_of(&result);
    let ip = out.trim();
    assert!(
        is_synthetic(ip),
        "wildcard subdomain should resolve to a synthetic IP, got: {out}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_netns_wildcard_connect_reaches_real_destination() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_netns_wildcard_connect_reaches_real_destination_inner(),
    )
    .await
    .expect("netns connect test timed out");
}

async fn test_netns_wildcard_connect_reaches_real_destination_inner() {
    // Fully hermetic: the wildcard subdomain resolves (worker-side) to a
    // local address, so no external DNS / NAT is involved; the supervisor
    // resolution, SSRF guard, sockaddr rewrite and veth path are still all
    // exercised.
    let _host = WorkerLocalHost::setup("conn.example.com");
    let listener = TcpListener::bind("198.18.0.99:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"OK").unwrap();
    });

    let mut policy = base_policy()
        .netns(true)
        .net_allow(format!("*.example.com:{}", port))
        .build()
        .unwrap();
    let script = format!(
        "import socket\n\
         s = socket.create_connection(('conn.example.com', {port}), timeout=10)\n\
         print(s.recv(8).decode())\n\
         s.close()\n",
        port = port
    );
    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = stdout_of(&result);
    assert!(out.contains("OK"), "wildcard connect failed: {out}");
    tokio::time::timeout(std::time::Duration::from_secs(30), server)
        .await
        .expect("connect server task timed out")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_netns_wildcard_udp_reaches_real_destination() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_netns_wildcard_udp_reaches_real_destination_inner(),
    )
    .await
    .expect("netns UDP test timed out");
}

async fn test_netns_wildcard_udp_reaches_real_destination_inner() {
    let _host = WorkerLocalHost::setup("udp.example.com");
    let udp = std::net::UdpSocket::bind("198.18.0.99:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let (n, peer) = udp.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"PING", "expected the sandbox's UDP payload");
        udp.send_to(b"PONG", peer).unwrap();
    });

    let mut policy = base_policy()
        .netns(true)
        .net_allow(format!("*.example.com:{}", port))
        .build()
        .unwrap();
    let script = format!(
        "import socket\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         s.settimeout(5)\n\
         ip = socket.gethostbyname('udp.example.com')\n\
         s.sendto(b'PING', (ip, {port}))\n\
         data, _ = s.recvfrom(64)\n\
         print(data.decode())\n",
        port = port
    );
    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = stdout_of(&result);
    assert!(
        out.contains("PONG"),
        "UDP wildcard send did not reach the real destination: {out}"
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), server)
        .await
        .expect("UDP server task timed out")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_netns_http_acl_proxy_redirect() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_netns_http_acl_proxy_redirect_inner(),
    )
    .await
    .expect("netns HTTP ACL test timed out");
}

async fn test_netns_http_acl_proxy_redirect_inner() {
    // Use an IP-literal HTTP host so the rule never needs the (broken) host
    // resolver; 198.18.0.99 is placed on the worker's loopback and is
    // deliberately allowed by the SSRF guard.
    let _host = WorkerLocalHost::setup("http.test");
    let listener = TcpListener::bind("198.18.0.99:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(req.contains("GET /hello"), "unexpected request: {req}");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            .unwrap();
    });

    let mut policy = base_policy()
        .netns(true)
        .http_port(port)
        .http_allow("GET 198.18.0.99/*")
        .build()
        .unwrap();
    let script = format!(
        "import urllib.request\n\
         print(urllib.request.urlopen('http://198.18.0.99:{port}/hello', timeout=10).read().decode())\n",
        port = port
    );
    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = stdout_of(&result);
    assert!(
        out.contains("hello"),
        "HTTP ACL redirect through the netns gateway proxy failed: {out}"
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), server)
        .await
        .expect("HTTP server task timed out")
        .unwrap();
}
