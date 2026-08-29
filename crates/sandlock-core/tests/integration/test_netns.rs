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

#[tokio::test]
async fn test_netns_isolates_host_loopback() {
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

#[tokio::test]
async fn test_netns_wildcard_dns_returns_synthetic_ip() {
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
    let result = policy.run(&["python3", "-c", script]).await.unwrap();
    let out = stdout_of(&result);
    let ip = out.trim();
    assert!(
        is_synthetic(ip),
        "wildcard subdomain should resolve to a synthetic IP, got: {out}"
    );
}

#[tokio::test]
async fn test_netns_wildcard_connect_reaches_real_destination() {
    // The test container's own resolver is usually broken (Docker-generated
    // nameserver that does not resolve public names). Point it at a public
    // resolver for the duration of the test: the supervisor resolves the
    // wildcard destination with the *host* resolver, and the DNS gateway
    // forwards non-wildcard queries to the same upstream.
    let resolv_backup = std::fs::read("/etc/resolv.conf").unwrap_or_default();
    let _ = std::fs::write("/etc/resolv.conf", "nameserver 8.8.8.8\n");

    // Best-effort egress plumbing for the veth pool: the sandbox's traffic
    // leaves through the host (test) netns, so it needs forwarding + NAT for
    // 10.200.0.0/16. Cleaned up after the test.
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .status();
    let present = std::process::Command::new("iptables")
        .args([
            "-t", "nat", "-C", "POSTROUTING", "-s", "10.200.0.0/16", "-j",
            "MASQUERADE",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !present {
        let _ = std::process::Command::new("iptables")
            .args([
                "-t", "nat", "-A", "POSTROUTING", "-s", "10.200.0.0/16", "-j",
                "MASQUERADE",
            ])
            .status();
    }

    let mut policy = base_policy()
        .netns(true)
        .net_allow("*.example.com:443")
        .build()
        .unwrap();
    let script = "import socket\n\
                  try:\n\
                  \x20 s = socket.create_connection(('api.example.com', 443), timeout=15)\n\
                  \x20 print('CONNECTED')\n\
                  \x20 s.close()\n\
                  except OSError as e:\n\
                  \x20 print(f'ERR:{e}')\n";
    let result = policy.run(&["python3", "-c", script]).await.unwrap();
    let out = stdout_of(&result);
    assert!(out.contains("CONNECTED"), "wildcard connect failed: {out}");

    let _ = std::process::Command::new("iptables")
        .args([
            "-t", "nat", "-D", "POSTROUTING", "-s", "10.200.0.0/16", "-j",
            "MASQUERADE",
        ])
        .status();
    let _ = std::fs::write("/etc/resolv.conf", &resolv_backup);
}
