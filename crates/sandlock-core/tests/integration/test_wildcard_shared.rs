//! Wildcard-domain rules in the default **unprivileged** mode: no per-sandbox
//! netns, no veth — the sandbox shares the host network namespace and reaches
//! its per-sandbox DNS gateway on a `127.0.1.x` loopback address. This is the
//! path that keeps sandlock usable by any unprivileged process.

use sandlock_core::Sandbox;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::TcpListener;

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

fn is_synthetic(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    let n = u32::from(ip);
    (0x0afa_0002..=0x0afa_fffe).contains(&n)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shared_netns_wildcard_dns() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_shared_netns_wildcard_dns_inner(),
    )
    .await
    .expect("shared-netns DNS test timed out");
}

async fn test_shared_netns_wildcard_dns_inner() {
    // No .netns(true): the sandbox shares the host network namespace.
    let mut policy = base_policy()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shared_netns_wildcard_connect() {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        test_shared_netns_wildcard_connect_inner(),
    )
    .await
    .expect("shared-netns connect test timed out");
}

async fn test_shared_netns_wildcard_connect_inner() {
    let _host = WorkerLocalHost::setup("conn.example.com");
    let listener = TcpListener::bind((_host.addr(), 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"OK").unwrap();
    });

    let mut policy = base_policy()
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
    let err = String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default()).into_owned();
    assert!(
        out.contains("OK"),
        "shared-netns wildcard connect failed: out={out} err={err}"
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), server)
        .await
        .expect("connect server task timed out")
        .unwrap();
}
