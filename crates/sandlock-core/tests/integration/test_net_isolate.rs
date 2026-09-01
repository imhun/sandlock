//! fd-injection connect path (S2.1, per-sandbox network isolation plan 1).
//!
//! With the `fd_inject_connect` switch on, the supervisor performs the
//! connect on a fresh host-side socket and injects it into the sandbox via
//! `SECCOMP_ADDFD_FLAG_SETFD|SEND`, so the trapped `connect()` returns the
//! child-side fd number (not 0) and the data plane is the injected fd.
//! With the switch off (default) the legacy dup-based on-behalf connect
//! returns 0. Policy decisions (allow verdict, synthetic-IP refusal) run
//! before the host connect in both modes.

use sandlock_core::Sandbox;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

fn temp_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sandlock-test-netisol-{}-{}", name, std::process::id()))
}

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

/// Local TCP echo server that answers exactly one connection with the bytes
/// it received (deterministic payload, so the assertion can be exact).
fn spawn_echo_server() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let mut buf = [0u8; 4];
            if conn.read_exact(&mut buf).is_ok() {
                let _ = conn.write_all(&buf);
            }
        }
    });
    (port, handle)
}

/// Raw `connect()` via libc so the test can observe the syscall's return
/// value: 0 on the legacy on-behalf path, the fd number under fd injection.
fn connect_script(port: u16, out: &std::path::Path) -> String {
    format!(
        concat!(
            "import ctypes, errno, select, socket, struct\n",
            "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
            "libc.connect.restype = ctypes.c_int\n",
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "s.settimeout(5)\n",
            "fd = s.fileno()\n",
            "addr = struct.pack('<H', socket.AF_INET) + struct.pack('!H', {port}) + socket.inet_aton('127.0.0.1') + b'\\x00' * 8\n",
            "buf = ctypes.create_string_buffer(addr)\n",
            "ctypes.set_errno(0)\n",
            "ret = libc.connect(fd, buf, len(addr))\n",
            "if ret < 0:\n",
            "  err = ctypes.get_errno()\n",
            "  if err != errno.EINPROGRESS:\n",
            "    open('{out}', 'w').write(f'connect_err={{err}}')\n",
            "    s.close()\n",
            "    raise SystemExit(0)\n",
            // settimeout put the socket in non-blocking mode: the on-behalf
            // path faithfully surfaces EINPROGRESS, so wait for completion
            // and read the pending error, then normalize to 0 (kernel view
            // of a successful connect).
            "  select.select([], [s], [], 5)\n",
            "  soerr = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)\n",
            "  if soerr != 0:\n",
            "    open('{out}', 'w').write(f'connect_err={{soerr}}')\n",
            "    s.close()\n",
            "    raise SystemExit(0)\n",
            "  ret = 0\n",
            // Re-apply the timeout on the (possibly injected) fd so a hung
            // echo cannot block the sandboxed child forever.
            "s.settimeout(5)\n",
            "s.sendall(b'ping')\n",
            "data = s.recv(4)\n",
            "s.close()\n",
            "open('{out}', 'w').write(f'ret={{ret}} fd={{fd}} echo={{data.decode()}}')\n",
        ),
        out = out.display(),
        port = port,
    )
}

/// With `fd_inject_connect` on, the trapped connect returns the child-side
/// fd number (SECCOMP_ADDFD_FLAG_SEND semantics) and the data plane is the
/// injected fd: an echo round-trip over that fd succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_fd_inject_connect_returns_injected_fd_and_echoes() {
    let out = temp_file("inject-echo");
    let (port, srv) = spawn_echo_server();

    let policy = base_policy()
        .net_allow(format!("127.0.0.1:{}", port))
        .fd_inject_connect(true)
        .build()
        .unwrap();

    let script = connect_script(port, &out);
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(
        result.success(),
        "exit={:?} stderr={:?}",
        result.code(),
        result.stderr
    );

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    srv.join().unwrap();

    // ret == fd proves the ADDFD|SEND path returned the injected fd number
    // rather than 0; echo over that fd proves the data plane is live.
    let parts: Vec<&str> = content.split_whitespace().collect();
    assert_eq!(
        parts.len(),
        3,
        "unexpected result line: {content} stderr={:?}",
        result.stderr
    );
    let (ret, fd, echo) = (parts[0], parts[1], parts[2]);
    let ret_val: i32 = ret
        .strip_prefix("ret=")
        .expect("ret field")
        .parse()
        .unwrap();
    let fd_val: i32 = fd.strip_prefix("fd=").expect("fd field").parse().unwrap();
    assert_eq!(
        ret_val, fd_val,
        "connect must return the injected fd number, got: {content}"
    );
    assert_eq!(echo, "echo=ping", "echo over the injected fd must work");
}

/// Direct connect to an unregistered synthetic IP must still be refused with
/// ECONNREFUSED under the injection switch: the verdict runs before the host
/// connect (a synthetic destination can never borrow a wildcard rule).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_fd_inject_connect_still_refuses_direct_synthetic_ip() {
    let out = temp_file("inject-synth");

    // Synthetic range is 10.250.0.2..=10.250.255.254; 10.250.1.1 is inside it
    // and never registered by any wildcard rule.
    let policy = base_policy()
        .net_allow("127.0.0.1:80")
        .fd_inject_connect(true)
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.settimeout(5)\n",
        "try:\n",
        "  s.connect(('10.250.1.1', 80))\n",
        "  open('{out}', 'w').write('ALLOWED')\n",
        "except OSError as e:\n",
        "  open('{out}', 'w').write(f'ERR:{{e.errno}}')\n",
        "s.close()\n",
    ), out = out.display());

    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(
        result.success(),
        "exit={:?} stderr={:?}",
        result.code(),
        result.stderr
    );

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        content, "ERR:111",
        "direct connect to a synthetic IP must be refused with ECONNREFUSED"
    );
}

/// Default (switch off): the legacy dup-based on-behalf connect is unchanged
/// — the trapped connect returns 0 and the data plane still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_default_connect_unchanged_returns_zero() {
    let out = temp_file("legacy-echo");
    let (port, srv) = spawn_echo_server();

    let policy = base_policy()
        .net_allow(format!("127.0.0.1:{}", port))
        .build()
        .unwrap();

    let script = connect_script(port, &out);
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(
        result.success(),
        "exit={:?} stderr={:?}",
        result.code(),
        result.stderr
    );

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    srv.join().unwrap();

    let parts: Vec<&str> = content.split_whitespace().collect();
    assert_eq!(parts.len(), 3, "unexpected result line: {content}");
    let ret_val: i32 = parts[0]
        .strip_prefix("ret=")
        .expect("ret field")
        .parse()
        .unwrap();
    assert_eq!(ret_val, 0, "legacy on-behalf connect must return 0");
    assert_eq!(parts[2], "echo=ping", "legacy data plane must still work");
}
