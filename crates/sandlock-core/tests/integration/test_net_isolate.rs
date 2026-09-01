//! fd-injection connect path (S2.1) and per-sandbox netns isolation (S2.2,
//! per-sandbox network isolation plan 1).
//!
//! With the `fd_inject_connect` switch on, the supervisor performs the
//! connect on a fresh host-side socket and injects it into the sandbox via
//! `SECCOMP_ADDFD_FLAG_SETFD|SEND`, so the trapped `connect()` returns the
//! child-side fd number (not 0) and the data plane is the injected fd.
//! With the switch off (default) the legacy dup-based on-behalf connect
//! returns 0. Policy decisions (allow verdict, synthetic-IP refusal) run
//! before the host connect in both modes.
//!
//! With the `net_isolation` switch on (default off), the sandbox spawns in
//! its own network namespace containing only loopback, brought up from
//! inside the sandbox's user namespace (no privilege in the parent
//! namespace). The default shared-netns path is unchanged. Each spawn gets
//! its own fresh netns: a dual-sandbox test below locks the contract that
//! two concurrent netns sandboxes are mutually invisible (and that a
//! future shared/pooled netns refactor cannot silently pass).

use sandlock_core::Sandbox;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;

use crate::net_fixture::WorkerLocalHost;

fn temp_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sandlock-test-netisol-{}-{}", name, std::process::id()))
}

fn is_synthetic(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    let n = u32::from(ip);
    (0x0afa_0002..=0x0afa_fffe).contains(&n)
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

/// The injected fd must preserve the child's own close-on-exec: ADDFD's
/// `newfd_flags` (not fcntl on the supervisor's copy) decides the child-side
/// FD_CLOEXEC, and the supervisor derives it from `/proc/<pid>/fdinfo/<fd>`.
/// A `SOCK_CLOEXEC` socket stays close-on-exec after injection; a plain
/// socket must not gain it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_fd_inject_connect_preserves_child_cloexec() {
    for (mode, expect_cloexec) in [("CLOEXEC", true), ("PLAIN", false)] {
        let out = temp_file(&format!("inject-cloexec-{mode}"));
        let (port, srv) = spawn_echo_server();
        let policy = base_policy()
            .net_allow(format!("127.0.0.1:{}", port))
            .fd_inject_connect(true)
            .build()
            .unwrap();

        let script = format!(concat!(
            "import ctypes, socket, struct, fcntl\n",
            "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
            "libc.connect.restype = ctypes.c_int\n",
            "libc.send.restype = ctypes.c_ssize_t\n",
            "libc.recv.restype = ctypes.c_ssize_t\n",
            "if '{mode}' == 'CLOEXEC':\n",
            "  fd = libc.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC, 0)\n",
            "else:\n",
            "  fd = libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0)\n",
            "cloexec_before = bool(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)\n",
            "addr = struct.pack('<H', socket.AF_INET) + struct.pack('!H', {port}) + socket.inet_aton('127.0.0.1') + b'\\x00' * 8\n",
            "buf = ctypes.create_string_buffer(addr)\n",
            "ctypes.set_errno(0)\n",
            "ret = libc.connect(fd, buf, len(addr))\n",
            "if ret < 0:\n",
            "  open('{out}', 'w').write(f'connect_err={{ctypes.get_errno()}}')\n",
            "  raise SystemExit(0)\n",
            "cloexec_after = bool(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)\n",
            "payload = b'ping'\n",
            "n = libc.send(fd, payload, 4, 0)\n",
            "buf2 = ctypes.create_string_buffer(4)\n",
            "n2 = libc.recv(fd, buf2, 4, 0)\n",
            "open('{out}', 'w').write(f'ret={{ret}} fd={{fd}} cloexec_before={{cloexec_before}} cloexec_after={{cloexec_after}} echo={{buf2.raw[:n2].decode()}}')\n",
        ), mode = mode, port = port, out = out.display());

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
        assert_eq!(parts.len(), 5, "unexpected result line: {content}");
        let ret_val: i32 = parts[0]
            .strip_prefix("ret=")
            .expect("ret field")
            .parse()
            .unwrap();
        let fd_val: i32 = parts[1].strip_prefix("fd=").expect("fd field").parse().unwrap();
        assert_eq!(
            ret_val, fd_val,
            "connect must return the injected fd number, got: {content}"
        );
        assert_eq!(
            parts[2],
            format!(
                "cloexec_before={}",
                if expect_cloexec { "True" } else { "False" }
            ),
            "child-side FD_CLOEXEC before connect must match the socket mode"
        );
        assert_eq!(
            parts[3],
            format!("cloexec_after={}", if expect_cloexec { "True" } else { "False" }),
            "injected fd must preserve the child's FD_CLOEXEC, got: {content}"
        );
        assert_eq!(parts[4], "echo=ping", "echo over the injected fd must work");
    }
}

/// fd_inject_connect is a seccomp-supervisor feature; with no_supervisor
/// there is no listener to intercept connect(), so the switch would be
/// silently ignored. The combination must fail fast, never run weaker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_fd_inject_connect_rejected_with_no_supervisor() {
    let policy = base_policy()
        .no_supervisor(true)
        .fd_inject_connect(true)
        .build()
        .unwrap();
    let err = policy
        .clone()
        .run_interactive(&["python3", "-c", "pass"])
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "process error: child process error: fd_inject_connect requires the seccomp \
         supervisor and is incompatible with no_supervisor=true",
        "no_supervisor + fd_inject_connect must fail closed"
    );
}

// ============================================================
// S2.2: per-sandbox netns isolation (net_isolation)
// ============================================================

/// In-process probe for the netns isolation behavior. Writes exact result
/// lines to fd 3 and exits:
///
/// - `ifnames=...`: sorted interface-name list seen from inside the sandbox
///   (via glibc `if_nameindex`, which is netlink-backed).
/// - `lo_echo=ok`: a 127.0.0.1 TCP echo round-trip inside the sandbox
///   succeeded. This is the ping-equivalent: a down `lo` makes the
///   connect/bind fail, so `ok` proves loopback is up AND usable.
/// - `host_echo=errno=N` / `host_echo=reachable`: the outcome of connecting
///   to the test's host-side echo server on 127.0.0.1 (`HOST_ECHO_PORT`).
///
/// The in-sandbox listener binds a caller-chosen port (`LOOPBACK_PORT`)
/// that the policy allows via `net_allow` + `net_allow_bind_port` — Landlock
/// handles TCP bind/connect by default, so an unlisted port is denied
/// regardless of the network namespace.
fn netns_probe() {
    let mut out = unsafe { std::fs::File::from_raw_fd(3) };
    let mut line = String::new();

    // Interface enumeration: exactly what `ip addr` / glibc sees. In the
    // netns-isolated sandbox the real netns view is passed through, so this
    // must be exactly ["lo"]; in the default shared-netns sandbox the
    // virtualized view is the fixed ["eth0", "lo"] pair.
    let mut names: Vec<String> = Vec::new();
    let head = unsafe { libc::if_nameindex() };
    if head.is_null() {
        line.push_str(&format!(
            "ifnames_errno={}\n",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        ));
    } else {
        let mut p = head;
        while !unsafe { (*p).if_name }.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr((*p).if_name) }
                .to_string_lossy()
                .into_owned();
            names.push(name);
            p = unsafe { p.add(1) };
        }
        unsafe { libc::if_freenameindex(head) };
        names.sort_unstable();
        line.push_str(&format!("ifnames={:?}\n", names));
    }

    // Loopback data plane inside the sandbox: bind+listen on the allowed
    // 127.0.0.1:LOOPBACK_PORT,
    // connect from the same process, deterministic 4-byte echo. Requires lo
    // to be UP (a down loopback fails the connect with ENETUNREACH).
    let loopback_port = match std::env::var("LOOPBACK_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
    {
        Some(p) => p,
        None => {
            let _ = out.write_all(b"lo_echo=no_port\n");
            let _ = out.flush();
            unsafe { libc::_exit(0) };
        }
    };
    match TcpListener::bind(("127.0.0.1", loopback_port)) {
        Ok(listener) => {
            let handle = std::thread::spawn(move || {
                if let Ok((mut conn, _)) = listener.accept() {
                    let mut buf = [0u8; 4];
                    if conn.read_exact(&mut buf).is_ok() {
                        let _ = conn.write_all(&buf);
                    }
                }
            });
            match std::net::TcpStream::connect(("127.0.0.1", loopback_port)) {
                Ok(mut stream) => {
                    let mut buf = [0u8; 4];
                    let sent = stream.write_all(b"ping").is_ok();
                    let recvd = stream.read_exact(&mut buf).is_ok();
                    line.push_str(&format!(
                        "lo_echo={}\n",
                        if sent && recvd && &buf == b"ping" { "ok" } else { "bad" }
                    ));
                }
                Err(e) => line.push_str(&format!(
                    "lo_echo=connect_errno={}\n",
                    e.raw_os_error().unwrap_or(-1)
                )),
            }
            handle.join().unwrap();
        }
        Err(e) => line.push_str(&format!(
            "lo_echo=bind_errno={}\n",
            e.raw_os_error().unwrap_or(-1)
        )),
    }

    // Host visibility: the test's echo server lives on the HOST loopback.
    // A netns-isolated sandbox's 127.0.0.1 is its own lo, so the connect must
    // fail; the default shared-netns sandbox must reach it.
    match std::env::var("HOST_ECHO_PORT").ok().and_then(|v| v.parse::<u16>().ok()) {
        Some(port) => match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(_) => line.push_str("host_echo=reachable\n"),
            Err(e) => line.push_str(&format!(
                "host_echo=errno={}\n",
                e.raw_os_error().unwrap_or(-1)
            )),
        },
        None => line.push_str("host_echo=no_port\n"),
    }

    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
    unsafe { libc::_exit(0) };
}

/// Build a sandbox running `entry` in-process with a result pipe on fd 3,
/// start it, and read everything the probe wrote. Returns (output, sandbox).
async fn run_netns_probe(
    entry: fn(),
    name: &str,
    env: &[(&str, &str)],
    net_isolation: bool,
    loopback_port: u16,
    host_echo_port: u16,
) -> (String, Sandbox) {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let (r, w) = (fds[0], fds[1]);
    let mut b = base_policy()
        .net_isolation(net_isolation)
        .net_allow(format!("127.0.0.1:{}", loopback_port))
        .net_allow(format!("127.0.0.1:{}", host_echo_port))
        .net_allow_bind_port(loopback_port)
        .env_var("LOOPBACK_PORT", &loopback_port.to_string());
    for (k, v) in env {
        b = b.env_var(*k, *v);
    }
    let mut sb = b.build().unwrap();
    sb.create_with_in_child_main(name, vec![(3, w)], entry)
        .await
        .unwrap();
    unsafe { libc::close(w) };
    sb.start().unwrap();
    let buf = tokio::task::spawn_blocking(move || {
        let mut buf = String::new();
        let mut f = unsafe { std::fs::File::from_raw_fd(r) };
        f.read_to_string(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();
    (buf, sb)
}

/// With `net_isolation` on, the sandbox runs in its own network namespace:
/// exactly one interface (`lo`), loopback up and usable (TCP echo round-trip
/// over 127.0.0.1), and the host's loopback echo server invisible
/// (ECONNREFUSED — the sandbox's 127.0.0.1 is its own lo, not the host's).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_net_isolation_loopback_only_lo_up_host_invisible() {
    let (port, srv) = spawn_echo_server();
    let loopback_port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (output, mut sb) = run_netns_probe(
        netns_probe,
        "netns-probe",
        &[("HOST_ECHO_PORT", &port.to_string())],
        true,
        loopback_port,
        port,
    )
    .await;
    let result = sb.wait().await.unwrap();
    assert!(
        result.success(),
        "sandbox failed: {:?}\nprobe output:\n{}",
        result.exit_status,
        output
    );
    // The echo server is intentionally never reached from the netns sandbox,
    // so its accept thread never returns; drop the handle instead of joining.
    drop(srv);

    let mut ifnames = None;
    let mut lo_echo = None;
    let mut host_echo = None;
    for l in output.lines() {
        if let Some(v) = l.strip_prefix("ifnames=") {
            ifnames = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("lo_echo=") {
            lo_echo = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("host_echo=") {
            host_echo = Some(v.to_string());
        }
    }
    assert_eq!(
        ifnames.as_deref(),
        Some("[\"lo\"]"),
        "netns-isolated sandbox must see exactly lo:\n{}",
        output
    );
    assert_eq!(
        lo_echo.as_deref(),
        Some("ok"),
        "loopback must be up and echo 127.0.0.1 (ping-equivalent):\n{}",
        output
    );
    assert_eq!(
        host_echo.as_deref(),
        Some("errno=111"),
        "host loopback echo must be unreachable from a netns-isolated sandbox:\n{}",
        output
    );
}

/// Default (switch off) contrast: the shared-netns path is unchanged — the
/// sandbox still sees the virtualized interface view (lo + eth0) and reaches
/// the host's loopback echo server (loopback is shared).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_default_shared_netns_contrast_loopback_shared() {
    let (port, srv) = spawn_echo_server();
    let loopback_port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (output, mut sb) = run_netns_probe(
        netns_probe,
        "shared-netns-probe",
        &[("HOST_ECHO_PORT", &port.to_string())],
        false,
        loopback_port,
        port,
    )
    .await;
    let result = sb.wait().await.unwrap();
    assert!(
        result.success(),
        "sandbox failed: {:?}\nprobe output:\n{}",
        result.exit_status,
        output
    );
    srv.join().unwrap();

    let mut ifnames = None;
    let mut lo_echo = None;
    let mut host_echo = None;
    for l in output.lines() {
        if let Some(v) = l.strip_prefix("ifnames=") {
            ifnames = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("lo_echo=") {
            lo_echo = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("host_echo=") {
            host_echo = Some(v.to_string());
        }
    }
    assert_eq!(
        ifnames.as_deref(),
        Some("[\"eth0\", \"lo\"]"),
        "default sandbox keeps the virtualized interface view:\n{}",
        output
    );
    assert_eq!(
        lo_echo.as_deref(),
        Some("ok"),
        "loopback must still work in the default shared-netns path:\n{}",
        output
    );
    assert_eq!(
        host_echo.as_deref(),
        Some("reachable"),
        "default shared-netns sandbox must reach the host loopback echo:\n{}",
        output
    );
}

/// `net_isolation` + `fd_inject_connect` is the full plan-1 path: the
/// sandbox's connect is trapped, the supervisor connects on a host-side
/// socket (host netns) and injects the connected fd, so the sandbox reaches
/// the host echo server from inside its loopback-only netns. The trapped
/// connect returns the injected fd number.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_net_isolation_with_fd_inject_reaches_host_echo() {
    let out = temp_file("netns-inject-echo");
    let (port, srv) = spawn_echo_server();

    let policy = base_policy()
        .net_isolation(true)
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

    let parts: Vec<&str> = content.split_whitespace().collect();
    assert_eq!(parts.len(), 3, "unexpected result line: {content}");
    let ret_val: i32 = parts[0]
        .strip_prefix("ret=")
        .expect("ret field")
        .parse()
        .unwrap();
    let fd_val: i32 = parts[1]
        .strip_prefix("fd=")
        .expect("fd field")
        .parse()
        .unwrap();
    assert_eq!(
        ret_val, fd_val,
        "connect must return the injected fd number, got: {content}"
    );
    assert_eq!(
        parts[2], "echo=ping",
        "echo over the injected fd must reach the host server: {content}"
    );
}

/// `net_isolation` without `fd_inject_connect`: the shared-netns dup-based
/// on-behalf path cannot borrow external connectivity (the dup'd socket lives
/// in the sandbox's loopback-only netns), so the host echo stays unreachable
/// (ECONNREFUSED). The combination degrades to loopback-only, never to a
/// silent shared-netns escape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_net_isolation_without_fd_inject_host_unreachable() {
    let out = temp_file("netns-noinject-host");
    let (port, srv) = spawn_echo_server();

    let policy = base_policy()
        .net_isolation(true)
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
    // The echo server is never reached (ECONNREFUSED in the sandbox netns),
    // so its accept thread never returns; drop the handle instead of joining.
    drop(srv);
    assert_eq!(
        content, "connect_err=111",
        "netns sandbox without fd injection must fail the host connect with ECONNREFUSED"
    );
}

// ============================================================
// S2.3: in-netns DNS gateway — wildcard DNS under net_isolation
// ============================================================

/// S2.3: under `net_isolation` the wildcard DNS gateway binds inside the
/// sandbox's own netns (bound from the sandbox's userns, so
/// `ip_unprivileged_port_start` is not involved). A wildcard subdomain must
/// resolve to a synthetic IP through that gateway, while the bare apex
/// domain must NOT be synthesized (wildcard rules grant subdomains only —
/// the apex resolves through the gateway's upstream forwarder instead).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_net_isolation_wildcard_dns_resolves_subdomain_and_refuses_bare() {
    let mut policy = base_policy()
        .net_isolation(true)
        .net_allow("*.example.com:443")
        .build()
        .unwrap();
    let script = "import socket\n\
                  try:\n\
                  \x20 ip = socket.gethostbyname('api.example.com')\n\
                  \x20 print(f'IP:{ip}')\n\
                  except socket.gaierror as e:\n\
                  \x20 print(f'ERR:{e.errno}')\n\
                  try:\n\
                  \x20 ip = socket.gethostbyname('example.com')\n\
                  \x20 print(f'BARE:{ip}')\n\
                  except socket.gaierror as e:\n\
                  \x20 print(f'BARE_ERR:{e.errno}')\n";
    let result = policy.run(&["python3", "-c", script]).await.unwrap();
    let out = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).into_owned();
    let err = String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default()).into_owned();
    assert!(
        result.success(),
        "netns wildcard DNS sandbox failed: exit={:?} out={out} err={err}",
        result.code()
    );
    let mut lines = out.lines();
    let ip_line = lines.next().expect("missing first result line");
    let ip = ip_line
        .strip_prefix("IP:")
        .expect("first line must be IP:<addr>, got: {out}");
    assert!(
        is_synthetic(ip),
        "wildcard subdomain must resolve to a synthetic IP, got: {out}"
    );
    let bare_line = lines.next().expect("missing bare-apex result line");
    let bare_ip = bare_line
        .strip_prefix("BARE:")
        .expect("bare apex line must be BARE:<addr>, got: {out}");
    assert!(
        !is_synthetic(bare_ip),
        "bare apex domain must not be synthesized by the wildcard rule, got: {out}"
    );
    assert_eq!(lines.next(), None, "unexpected extra output: {out}");
}

/// S2.3 + S2.1: a netns-isolated sandbox with `fd_inject_connect` resolves a
/// wildcard subdomain through its in-netns gateway (synthetic IP), connects
/// to the synthetic address, and reaches the real destination through the
/// injected connected fd — deterministic 4-byte echo, exact assertion. The
/// bare apex domain must be refused at connect time (the wildcard rule
/// grants subdomains only; the supervisor verdict denies before any
/// host-side connect, ECONNREFUSED). The client uses the raw
/// `connect()`/send/recv form like the S2.1 fd-injection tests: CPython's
/// `socket.connect()` requires an exact 0 return, while the ADDFD|SEND
/// injection semantics return the injected fd number (positive) — a known
/// wrapper incompatibility, not a data-plane failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_net_isolation_wildcard_connect_with_fd_inject() {
    let _host = WorkerLocalHost::setup("conn.example.com");
    let listener = TcpListener::bind((_host.addr(), 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"PONG").unwrap();
    });

    let mut policy = base_policy()
        .net_isolation(true)
        .fd_inject_connect(true)
        .net_allow(format!("*.example.com:{}", port))
        .build()
        .unwrap();
    let script = format!(
        concat!(
            "import ctypes, errno, select, socket, struct\n",
            "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
            "libc.connect.restype = ctypes.c_int\n",
            "ip = socket.gethostbyname('conn.example.com')\n",
            "print(f'IP:{{ip}}')\n",
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "s.settimeout(5)\n",
            "fd = s.fileno()\n",
            "addr = struct.pack('<H', socket.AF_INET) + struct.pack('!H', {port}) + socket.inet_aton(ip) + b'\\x00' * 8\n",
            "buf = ctypes.create_string_buffer(addr)\n",
            "ctypes.set_errno(0)\n",
            "ret = libc.connect(fd, buf, len(addr))\n",
            "if ret < 0:\n",
            "  err = ctypes.get_errno()\n",
            "  if err != errno.EINPROGRESS:\n",
            "    print(f'CONNECT_ERR:{{err}}')\n",
            "    raise SystemExit(0)\n",
            "  select.select([], [s], [], 5)\n",
            "  soerr = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)\n",
            "  if soerr != 0:\n",
            "    print(f'CONNECT_ERR:{{soerr}}')\n",
            "    raise SystemExit(0)\n",
            "s.settimeout(5)\n",
            "s.sendall(b'ping')\n",
            "data = s.recv(4)\n",
            "s.close()\n",
            "print(f'ECHO:{{data.decode()}}')\n",
            "try:\n",
            "  b = socket.create_connection(('example.com', {port}), timeout=5)\n",
            "  b.close()\n",
            "  print('BARE_ALLOWED')\n",
            "except OSError as e:\n",
            "  print(f'BARE_ERR:{{e.errno}}')\n",
        ),
        port = port
    );
    let result = policy.run(&["python3", "-c", &script]).await.unwrap();
    let out = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).into_owned();
    let err = String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default()).into_owned();
    assert!(
        result.success(),
        "netns wildcard connect sandbox failed: exit={:?} out={out} err={err}",
        result.code()
    );
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "unexpected output: {out} err={err}");
    let ip = lines[0]
        .strip_prefix("IP:")
        .expect("first line must be IP:<addr>, got: {out}");
    assert!(
        is_synthetic(ip),
        "wildcard subdomain must resolve to a synthetic IP, got: {out}"
    );
    assert_eq!(
        lines[1], "ECHO:PONG",
        "wildcard connect over in-netns DNS must echo PONG, got: out={out} err={err}"
    );
    assert_eq!(
        lines[2], "BARE_ERR:111",
        "bare apex domain connect must be refused with ECONNREFUSED, got: out={out} err={err}"
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), server)
        .await
        .expect("connect server task timed out")
        .unwrap();
}

// ============================================================
// S2.2 dual-sandbox: two concurrent netns sandboxes are mutually
// invisible (cross-sandbox netns isolation contract)
// ============================================================

/// The sandbox's network-namespace identifier as seen from inside it:
/// the target of `/proc/self/ns/net`, e.g. `net:[4026532000]`. Two
/// concurrently live sandboxes with independent netns have different
/// inodes; a shared or pooled netns would hand out the same one, so
/// comparing the two probes' identifiers directly locks the per-spawn
/// `unshare(CLONE_NEWNET)` contract (not just the host-invisibility
/// behavior, which a synthetic-view change could mask).
fn read_netns_inode() -> String {
    match std::fs::read_link("/proc/self/ns/net") {
        Ok(target) => target.to_string_lossy().into_owned(),
        Err(e) => format!("errno={}", e.raw_os_error().unwrap_or(-1)),
    }
}

/// Pair probe A (netns sandbox A): binds a TCP listener on its own
/// loopback at `LOOPBACK_PORT` (allowed via `net_allow_bind_port`), signals
/// B on fd 4 (`ready`, listener is bound), then polls the listener and the
/// fd 5 `done` pipe. If a connection ever arrives, B reached A's netns
/// (regression); under correct per-sandbox isolation only `done` arrives.
/// Also reports its netns inode for the cross-sandbox identifier check.
/// Result goes to fd 3.
fn netns_pair_probe_a() {
    let mut out = unsafe { std::fs::File::from_raw_fd(3) };
    let mut sync_to_b = unsafe { std::fs::File::from_raw_fd(4) };
    let sync_from_b = unsafe { std::fs::File::from_raw_fd(5) };
    let mut line = String::new();
    line.push_str(&format!("netns_inode={}\n", read_netns_inode()));

    let loopback_port = match std::env::var("LOOPBACK_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
    {
        Some(p) => p,
        None => {
            let _ = out.write_all(b"a_bind=no_port\n");
            let _ = out.flush();
            unsafe { libc::_exit(0) };
        }
    };
    let listener = match TcpListener::bind(("127.0.0.1", loopback_port)) {
        Ok(l) => l,
        Err(e) => {
            line.push_str(&format!("a_bind=errno={}\n", e.raw_os_error().unwrap_or(-1)));
            // Signal B anyway so it never hangs waiting for readiness.
            let _ = sync_to_b.write_all(b"ready");
            let _ = out.write_all(line.as_bytes());
            let _ = out.flush();
            unsafe { libc::_exit(0) };
        }
    };
    line.push_str("a_bind=ok\n");
    let _ = sync_to_b.write_all(b"ready");
    let _ = sync_to_b.flush();

    // Wait for either an incoming connection (regression: B reached A's
    // netns) or B's `done` signal. The done pipe normally arrives in
    // milliseconds; 10s is only a safety bound so a broken sync can never
    // hang the suite.
    let listener_fd = listener.as_raw_fd();
    let done_fd = sync_from_b.as_raw_fd();
    let mut fds = [
        libc::pollfd {
            fd: listener_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: done_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, 10_000) };
    if rc < 0 {
        line.push_str(&format!(
            "a_poll=errno={}\n",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        ));
    } else if rc == 0 {
        line.push_str("a_poll=timeout\n");
    } else if fds[0].revents & libc::POLLIN != 0 {
        // A connection arrived on A's listener: B reached this netns.
        let _ = listener.accept();
        line.push_str("a_accept=conn\n");
    } else {
        line.push_str("a_accept=none\n");
    }

    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
    unsafe { libc::_exit(0) };
}

/// Pair probe B (netns sandbox B): waits on fd 4 for A's `ready` (listener
/// bound), reports its own netns inode, then connects to A's listener at
/// `127.0.0.1:PEER_PORT` (allowed via `net_allow`, so a failure can only be
/// a netns-level ECONNREFUSED, never a policy denial). Signals `done` on fd
/// 5 and writes the result to fd 3.
fn netns_pair_probe_b() {
    let mut out = unsafe { std::fs::File::from_raw_fd(3) };
    let mut sync_from_a = unsafe { std::fs::File::from_raw_fd(4) };
    let mut sync_to_a = unsafe { std::fs::File::from_raw_fd(5) };
    let mut line = String::new();

    // Block until A's listener is bound (10s safety bound; normally instant).
    let ready_fd = sync_from_a.as_raw_fd();
    let mut fds = [libc::pollfd {
        fd: ready_fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 1, 10_000) };
    if rc <= 0 || fds[0].revents & libc::POLLIN == 0 {
        line.push_str("b_ready=timeout\n");
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
        unsafe { libc::_exit(0) };
    }
    let mut ready = [0u8; 5];
    let _ = sync_from_a.read_exact(&mut ready);
    line.push_str(&format!("netns_inode={}\n", read_netns_inode()));

    let peer_port = match std::env::var("PEER_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
    {
        Some(p) => p,
        None => {
            line.push_str("b_connect=no_port\n");
            let _ = sync_to_a.write_all(b"done");
            let _ = out.write_all(line.as_bytes());
            let _ = out.flush();
            unsafe { libc::_exit(0) };
        }
    };
    match std::net::TcpStream::connect(("127.0.0.1", peer_port)) {
        Ok(_) => line.push_str("b_connect=reachable\n"),
        Err(e) => line.push_str(&format!(
            "b_connect=errno={}\n",
            e.raw_os_error().unwrap_or(-1)
        )),
    }
    let _ = sync_to_a.write_all(b"done");
    let _ = sync_to_a.flush();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
    unsafe { libc::_exit(0) };
}

/// Two concurrent `net_isolation` sandboxes must be mutually invisible:
/// sandbox A listens on 127.0.0.1:P inside its own netns, sandbox B's
/// connect to 127.0.0.1:P must fail with ECONNREFUSED (B's loopback is its
/// own lo, nothing is listening), and A must never accept a connection.
/// Additionally the two `/proc/self/ns/net` inodes must differ, proving
/// each spawn got its own netns rather than a shared/pooled one. The sync
/// pipes make the ordering deterministic: B only connects after A's
/// listener is bound, and A only exits after B finished its attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_net_isolation_two_sandboxes_mutually_invisible() {
    // Pick a free port on the host loopback, then close it so A can bind it
    // inside its own netns (each netns has its own loopback, so no clash).
    let loopback_port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    // Per-sandbox result pipes (fd 3) and the cross-sandbox sync pipes:
    // A->B `ready` and B->A `done`.
    let mut a_out = [0i32; 2];
    let mut b_out = [0i32; 2];
    let mut ready = [0i32; 2];
    let mut done = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(a_out.as_mut_ptr()) }, 0, "a result pipe failed");
    assert_eq!(unsafe { libc::pipe(b_out.as_mut_ptr()) }, 0, "b result pipe failed");
    assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0, "ready pipe failed");
    assert_eq!(unsafe { libc::pipe(done.as_mut_ptr()) }, 0, "done pipe failed");

    // Sandbox A: fd 3 = result, fd 4 = ready write end, fd 5 = done read end.
    let mut a = base_policy()
        .net_isolation(true)
        .net_allow_bind_port(loopback_port)
        .env_var("LOOPBACK_PORT", &loopback_port.to_string())
        .build()
        .unwrap();
    a.create_with_in_child_main(
        "netns-pair-a",
        vec![(3, a_out[1]), (4, ready[1]), (5, done[0])],
        netns_pair_probe_a,
    )
    .await
    .unwrap();

    // Sandbox B: fd 3 = result, fd 4 = ready read end, fd 5 = done write end.
    let mut b = base_policy()
        .net_isolation(true)
        .net_allow(format!("127.0.0.1:{}", loopback_port))
        .env_var("PEER_PORT", &loopback_port.to_string())
        .build()
        .unwrap();
    b.create_with_in_child_main(
        "netns-pair-b",
        vec![(3, b_out[1]), (4, ready[0]), (5, done[1])],
        netns_pair_probe_b,
    )
    .await
    .unwrap();

    // Close the parent-side copies; the children hold their own dups.
    unsafe { libc::close(a_out[1]) };
    unsafe { libc::close(b_out[1]) };
    unsafe { libc::close(ready[0]) };
    unsafe { libc::close(ready[1]) };
    unsafe { libc::close(done[0]) };
    unsafe { libc::close(done[1]) };

    a.start().unwrap();
    b.start().unwrap();

    // Read B first (it exits right after its connect attempt), then A
    // (it exits as soon as B's `done` arrives). Blocking pipe reads must
    // run off the tokio executor that pumps the seccomp supervisors.
    let out_b = tokio::task::spawn_blocking(move || {
        let mut buf = String::new();
        let mut f = unsafe { std::fs::File::from_raw_fd(b_out[0]) };
        f.read_to_string(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();
    let out_a = tokio::task::spawn_blocking(move || {
        let mut buf = String::new();
        let mut f = unsafe { std::fs::File::from_raw_fd(a_out[0]) };
        f.read_to_string(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();

    let result_b = b.wait().await.unwrap();
    assert!(
        result_b.success(),
        "sandbox B failed: {:?}\nprobe B output:\n{}",
        result_b.exit_status,
        out_b
    );
    let result_a = a.wait().await.unwrap();
    assert!(
        result_a.success(),
        "sandbox A failed: {:?}\nprobe A output:\n{}",
        result_a.exit_status,
        out_a
    );

    let mut a_inode = None;
    let mut a_bind = None;
    let mut a_accept = None;
    let mut b_inode = None;
    let mut b_connect = None;
    for l in out_a.lines() {
        if let Some(v) = l.strip_prefix("netns_inode=") {
            a_inode = Some(v);
        } else if let Some(v) = l.strip_prefix("a_bind=") {
            a_bind = Some(v);
        } else if let Some(v) = l.strip_prefix("a_accept=") {
            a_accept = Some(v);
        }
    }
    for l in out_b.lines() {
        if let Some(v) = l.strip_prefix("netns_inode=") {
            b_inode = Some(v);
        } else if let Some(v) = l.strip_prefix("b_connect=") {
            b_connect = Some(v);
        }
    }

    assert_eq!(
        a_bind, Some("ok"),
        "sandbox A must bind its listener:\n{}",
        out_a
    );
    assert_eq!(
        a_accept, Some("none"),
        "sandbox B must never reach sandbox A's listener (a_accept=none expected):\nA:\n{}\nB:\n{}",
        out_a, out_b
    );
    assert_eq!(
        b_connect, Some("errno=111"),
        "sandbox B must fail to reach sandbox A's 127.0.0.1 listener with ECONNREFUSED:\nB:\n{}\nA:\n{}",
        out_b, out_a
    );

    // Both inodes must parse as `net:[<inode>]` and differ: two concurrently
    // live sandboxes share a netns iff they got the same one (pooling/sharing
    // would equalize them).
    let inode_a = a_inode
        .expect("netns_inode line missing from A")
        .strip_prefix("net:[")
        .and_then(|s| s.strip_suffix(']'))
        .expect("A netns inode must be net:[...]")
        .parse::<u64>()
        .expect("A netns inode must be numeric");
    let inode_b = b_inode
        .expect("netns_inode line missing from B")
        .strip_prefix("net:[")
        .and_then(|s| s.strip_suffix(']'))
        .expect("B netns inode must be net:[...]")
        .parse::<u64>()
        .expect("B netns inode must be numeric");
    assert_ne!(
        inode_a, inode_b,
        "concurrent net_isolation sandboxes must have distinct netns \
         identifiers (per-spawn unshare), got A={} B={}",
        inode_a, inode_b
    );
}

// ============================================================
// S2.4: UDP — connected injection + datagram on-behalf under net_isolation
// ============================================================

/// UDP echo server on the host loopback that answers exactly `count`
/// datagrams with the bytes it received (deterministic payloads, so the
/// assertion can be exact). The caller keeps the original socket to close it
/// at test end; the worker runs on a `try_clone` (same file description, so
/// closing the original does NOT wake it) and a read timeout bounds the
/// worker so a sandbox that never sends cannot hang the suite.
fn spawn_udp_echo_server(
    count: usize,
) -> (u16, UdpSocket, std::thread::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    let worker = sock.try_clone().unwrap();
    worker
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        for _ in 0..count {
            let Ok((n, peer)) = worker.recv_from(&mut buf) else {
                break;
            };
            let _ = worker.send_to(&buf[..n], peer);
        }
    });
    (port, sock, handle)
}

/// UDP collector bound on `ip` (a host-netns fixture address) that forwards
/// every received datagram payload to the returned receiver as exact bytes,
/// so a test can assert the sandbox's on-behalf datagram actually arrived at
/// the host-side server (not just that the syscall returned success — an
/// unconnected UDP send reports success even when the datagram is dropped).
fn spawn_udp_collector(
    ip: Ipv4Addr,
    count: usize,
) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    let sock = UdpSocket::bind((ip, 0)).unwrap();
    let port = sock.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        for _ in 0..count {
            let Ok((n, _)) = sock.recv_from(&mut buf) else {
                break;
            };
            if tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    (port, rx)
}

/// Connected UDP under `net_isolation` + `fd_inject_connect` is the full
/// plan-1 UDP path: the supervisor mints a host-side UDP socket, connect()s
/// it to the host echo server, and injects it (ADDFD|SEND), so the trapped
/// connect returns the injected fd number and the data plane is the injected
/// fd — kernel-direct send/recv, no supervisor in the data path. QUIC-style:
/// one connect, then multiple datagram round-trips over the same fd.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_net_isolation_connected_udp_injected_quic_echo() {
    let out = temp_file("netns-udp-connect");
    let (port, sock, srv) = spawn_udp_echo_server(2);

    let policy = base_policy()
        .net_isolation(true)
        .net_allow(format!("127.0.0.1:{}", port))
        .fd_inject_connect(true)
        .build()
        .unwrap();

    // Raw libc connect: the ADDFD|SEND injection makes the syscall return the
    // injected fd number (positive), which CPython's socket.connect() wrapper
    // rejects — same known wrapper incompatibility as the TCP injection tests.
    let script = format!(
        concat!(
            "import ctypes, socket, struct\n",
            "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
            "libc.connect.restype = ctypes.c_int\n",
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
            "s.settimeout(5)\n",
            "fd = s.fileno()\n",
            "addr = struct.pack('<H', socket.AF_INET) + struct.pack('!H', {port}) + socket.inet_aton('127.0.0.1') + b'\\x00' * 8\n",
            "buf = ctypes.create_string_buffer(addr)\n",
            "ctypes.set_errno(0)\n",
            "ret = libc.connect(fd, buf, len(addr))\n",
            "if ret < 0:\n",
            "  open('{out}', 'w').write(f'connect_err={{ctypes.get_errno()}}')\n",
            "  raise SystemExit(0)\n",
            "s.send(b'ping')\n",
            "d1 = s.recv(4)\n",
            "s.send(b'pong')\n",
            "d2 = s.recv(4)\n",
            "s.close()\n",
            "open('{out}', 'w').write(f'ret={{ret}} fd={{fd}} echo1={{d1.decode()}} echo2={{d2.decode()}}')\n",
        ),
        port = port,
        out = out.display(),
    );
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
    drop(sock);
    srv.join().unwrap();

    let parts: Vec<&str> = content.split_whitespace().collect();
    assert_eq!(parts.len(), 4, "unexpected result line: {content}");
    let ret_val: i32 = parts[0]
        .strip_prefix("ret=")
        .expect("ret field")
        .parse()
        .unwrap();
    let fd_val: i32 = parts[1].strip_prefix("fd=").expect("fd field").parse().unwrap();
    assert_eq!(
        ret_val, fd_val,
        "UDP connect must return the injected fd number, got: {content}"
    );
    assert_eq!(
        parts[2], "echo1=ping",
        "first datagram over the injected fd must reach the host echo server"
    );
    assert_eq!(
        parts[3], "echo2=pong",
        "second datagram over the same injected fd must reach the host echo server"
    );
}

/// Unconnected datagram sendto under `net_isolation` reuses the on-behalf
/// send path: there is no connect to inject, so the supervisor performs the
/// send. The sandbox's loopback-only netns cannot route a non-loopback
/// destination, so the supervisor must send from a fresh host-side socket —
/// the sandbox socket would otherwise drop the datagram (or fail
/// ENETUNREACH). The host-side collector on a pre-seeded fixture address is
/// the reachability proof: exact payload, not just a successful sendto.
///
/// The same sandbox also round-trips a UDP datagram on its OWN loopback
/// (allowed fixed port): that destination must stay in the sandbox netns
/// (dup'd-fd path), so in-sandbox UDP services (e.g. the S2.3 DNS gateway)
/// are not misrouted to the host's loopback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_net_isolation_datagram_sendto_on_behalf_reaches_host() {
    // Pre-seeded by the container entrypoint (unprivileged fixture): the test
    // harness runs as uid 65534 and cannot mutate /etc/hosts or add lo
    // addresses itself, so the hostname must be one the entrypoint prepared.
    let _host = WorkerLocalHost::setup("api.egress.test");
    let loopback_port: u16 = 47_999;
    let out = temp_file("netns-udp-dgram");
    let (port, rx) = spawn_udp_collector(_host.addr(), 1);

    let policy = base_policy()
        .net_isolation(true)
        .net_allow(format!("127.0.0.1:{}", loopback_port))
        .net_allow(format!("{}:{}", _host.addr(), port))
        .build()
        .unwrap();
    let script = format!(
        concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
            "s.settimeout(5)\n",
            // In-sandbox UDP loopback must stay sandbox-local (dup'd fd).
            "l = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
            "l.bind(('127.0.0.1', {loopback_port}))\n",
            "l2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
            "l2.sendto(b'lo', ('127.0.0.1', {loopback_port}))\n",
            "ldata, _ = l.recvfrom(4)\n",
            "l.close()\n",
            "l2.close()\n",
            // External datagram: on-behalf, host-side socket under net_isolation.
            "try:\n",
            "  n = s.sendto(b'ping', ('{ip}', {port}))\n",
            "  open('{out}', 'w').write(f'lo={{ldata.decode()}} sent={{n}}')\n",
            "except OSError as e:\n",
            "  open('{out}', 'w').write(f'lo={{ldata.decode()}} send_err={{e.errno}}')\n",
            "s.close()\n",
        ),
        loopback_port = loopback_port,
        ip = _host.addr(),
        port = port,
        out = out.display(),
    );
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
        content, "lo=lo sent=4",
        "in-sandbox UDP loopback must round-trip locally and the external \
         sendto must report 4 bytes, got: {content}"
    );

    // Reachability proof: the datagram must arrive at the host-side server
    // with exactly the sent payload (no partial match, no dropped packet).
    let got = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("on-behalf datagram never arrived at the host collector");
    assert_eq!(got, b"ping", "host collector must receive exactly b'ping'");
}

/// Contrast contract: connected UDP under `net_isolation` WITHOUT
/// `fd_inject_connect` must NOT reach the host. The dup'd-socket on-behalf
/// connect lands on the sandbox's own loopback (UDP connect sends no packet,
/// so it succeeds); the send to the empty sandbox loopback is queued and the
/// ICMP port-unreachable surfaces as ECONNREFUSED on the next recv — the host
/// echo server must never receive anything. This locks the "no injection, no
/// egress" degradation for connected UDP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_net_isolation_connected_udp_without_fd_inject_not_reachable() {
    let out = temp_file("netns-udp-noinject");
    // Bind the host-side UDP socket only (no worker): the sandbox's datagram
    // must never arrive, so there is nothing to receive.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();

    let policy = base_policy()
        .net_isolation(true)
        .net_allow(format!("127.0.0.1:{}", port))
        .build()
        .unwrap();
    let script = format!(
        concat!(
            "import ctypes, socket, struct\n",
            "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
            "libc.connect.restype = ctypes.c_int\n",
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
            "s.settimeout(2)\n",
            "fd = s.fileno()\n",
            "addr = struct.pack('<H', socket.AF_INET) + struct.pack('!H', {port}) + socket.inet_aton('127.0.0.1') + b'\\x00' * 8\n",
            "buf = ctypes.create_string_buffer(addr)\n",
            "ctypes.set_errno(0)\n",
            "ret = libc.connect(fd, buf, len(addr))\n",
            "if ret < 0:\n",
            "  open('{out}', 'w').write(f'connect_err={{ctypes.get_errno()}}')\n",
            "  raise SystemExit(0)\n",
            "s.send(b'ping')\n",
            "try:\n",
            "  d = s.recv(4)\n",
            "  open('{out}', 'w').write(f'ret={{ret}} recv_ok')\n",
            "except OSError as e:\n",
            "  open('{out}', 'w').write(f'ret={{ret}} recv_err={{e.errno}}')\n",
            "s.close()\n",
        ),
        port = port,
        out = out.display(),
    );
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
        content, "ret=0 recv_err=111",
        "netns UDP connect without injection must stay sandbox-local: the \
         send to the empty sandbox loopback must surface ECONNREFUSED (ICMP \
         port unreachable) on the next recv, \
         got: {content}"
    );
    drop(sock);
}
