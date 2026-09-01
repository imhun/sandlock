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
//! namespace). The default shared-netns path is unchanged.

use sandlock_core::Sandbox;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::io::FromRawFd;
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

/// The wildcard-domain DNS gateway binds a 127.0.1.x address in the SHARED
/// netns; from a netns-isolated sandbox that loopback address is the
/// sandbox's own lo with nothing listening, so wildcard rules cannot work
/// (until the in-netns DNS gateway lands, S2.3). The combination must fail
/// fast at spawn, never silently run a broken DNS path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_net_isolation_wildcard_dns_restricted() {
    let policy = base_policy()
        .net_isolation(true)
        .net_allow("*.example.com:443")
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
        "process error: child process error: net_isolation sandboxes cannot use \
         wildcard-domain DNS rules: the shared-netns 127.0.1.x gateway is unreachable \
         from a per-sandbox netns (only loopback); wildcard DNS under net_isolation is \
         restricted until the in-netns DNS gateway lands (S2.3)",
        "net_isolation + wildcard rules must fail closed"
    );
}
