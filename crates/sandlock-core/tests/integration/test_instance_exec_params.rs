//! F4 (M2) per-exec parameter tests for an exec-capable `SandboxInstance`.
//!
//! F4.1/F4.2 pin:
//!
//! * per-exec `cwd`/`env`/`clean_env` are applied by `sandlock-init` before
//!   execve — cwd is a real `chdir`, env overrides the inherited session env
//!   (or starts from an empty env when `clean_env` is set);
//! * an exec request is never wider than the instance-time policy ceiling
//!   (S9): out-of-ceiling `extra_writable`/`bind_ports`/`cwd` (and paths the
//!   instance `fs_deny`s) are refused with the named `PolicyTooWide`
//!   EPERM-class error, and the on-behalf fd-injection entry point
//!   (`exec_with_fds_params`) goes through the exact same check;
//! * a per-exec `bind_ports` grant inside the ceiling reaches the sandbox
//!   listener: the child binds the allowed port and a host-side TCP client
//!   connects to the in-sandbox listener.

use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sandlock_core::error::SandboxRuntimeError;
use sandlock_core::instance::{ExecParams, ExecStdio, SandboxInstance};
use sandlock_core::result::ExitStatus;
use sandlock_core::{Sandbox, SandlockError};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

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

static SEQ: AtomicU64 = AtomicU64::new(1);

fn scratch(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "/tmp/sandlock-f4-{name}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Launch a mainless exec session whose policy also chdirs init into `/tmp`
/// (so a default exec child's cwd is deterministic).
async fn launch_exec_only_tmp(builder: sandlock_core::SandboxBuilder) -> SandboxInstance {
    SandboxInstance::launch_exec_only(builder.cwd("/tmp").build().unwrap())
        .await
        .expect("launch exec-only session")
}

/// Read the child's piped stdout to EOF (the child and its direct stdout
/// writers are gone once `wait_child` returned, so EOF is prompt).
fn read_all_stdout(fd: OwnedFd) -> Vec<u8> {
    let mut file = std::fs::File::from(fd);
    let mut out = Vec::new();
    file.read_to_end(&mut out)
        .expect("read child stdout to EOF");
    out
}

/// Exec `argv` with piped stdio and `params`, drop stdin, wait, and return
/// (exit status, stdout bytes).
async fn exec_and_wait(
    inst: &mut SandboxInstance,
    argv: &[&str],
    params: &ExecParams,
) -> (ExitStatus, Vec<u8>) {
    let h = inst
        .exec_params(argv, params, ExecStdio::Piped)
        .await
        .expect("exec child");
    drop(h.stdin);
    let status = inst
        .wait_child(h.child_id)
        .await
        .expect("wait child");
    let out = read_all_stdout(h.stdout.expect("piped stdout"));
    (status, out)
}

/// Matrix F4.1 case: per-exec `cwd`/`env`/`clean_env` apply at execve.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_per_exec_cwd_and_env_apply() {
    let dir = scratch("cwd");
    std::fs::create_dir_all(&dir).expect("create exec cwd dir");

    let mut inst = launch_exec_only_tmp(base_policy()).await;

    // (a) cwd + env override on one exec.
    let params = ExecParams {
        cwd: Some(dir.clone()),
        env: vec![("F4_MARKER".to_string(), "alpha".to_string())],
        ..Default::default()
    };
    let (status, out) = exec_and_wait(
        &mut inst,
        &["sh", "-c", "/bin/pwd; printf '%s' \"$F4_MARKER\""],
        &params,
    )
    .await;
    assert_eq!(status, ExitStatus::Code(0), "cwd/env exec must succeed");
    let text = String::from_utf8(out).expect("ascii child output");
    let mut lines = text.lines();
    let cwd_line = lines.next().expect("pwd output line");
    assert_eq!(
        PathBuf::from(cwd_line.trim()),
        dir,
        "per-exec cwd must be the chdir target"
    );
    assert_eq!(
        lines.collect::<String>(),
        "alpha",
        "per-exec env must reach the child"
    );

    // (b) a default exec (no params) inherits the session cwd (/tmp) and
    // does not see the per-exec env of (a).
    let (status, out) = exec_and_wait(&mut inst, &["sh", "-c", "/bin/pwd"], &ExecParams::default())
        .await;
    assert_eq!(status, ExitStatus::Code(0));
    assert_eq!(
        String::from_utf8(out).expect("ascii").trim(),
        "/tmp",
        "no-params exec must inherit the session cwd"
    );

    // (c) clean_env=true per exec starts from an empty env: `/usr/bin/env`
    // must print exactly the requested variable and nothing else.
    let params = ExecParams {
        clean_env: true,
        env: vec![("F4_ONLY".to_string(), "1".to_string())],
        ..Default::default()
    };
    let (status, out) = exec_and_wait(&mut inst, &["/usr/bin/env"], &params).await;
    assert_eq!(status, ExitStatus::Code(0), "clean_env exec must succeed");
    assert_eq!(
        String::from_utf8(out).expect("ascii"),
        "F4_ONLY=1\n",
        "clean_env must drop every inherited variable"
    );

    let _ = std::fs::remove_dir_all(&dir);
    inst.shutdown().await.expect("shutdown");
}

/// Matrix S9 case: an exec request wider than the instance-time ceiling is
/// refused with the named EPERM-class error — never silently granted — and
/// the on-behalf fd-injection entry point enforces the same check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wider_policy_is_rejected() {
    let allowed_port = free_port();
    let denied_dir = scratch("denied");
    std::fs::create_dir_all(&denied_dir).expect("create denied dir");

    let policy = base_policy()
        .net_allow_bind_port(allowed_port)
        .fs_deny(denied_dir.clone());
    let mut inst = launch_exec_only_tmp(policy).await;

    fn assert_policy_too_wide(e: &SandlockError, field: &str, value: &str) {
        match e {
            SandlockError::Runtime(SandboxRuntimeError::PolicyTooWide {
                field: f,
                value: v,
            }) => {
                assert_eq!(*f, field, "error must name the offending field");
                assert_eq!(v.as_str(), value, "error must name the offending value");
            }
            other => panic!("expected PolicyTooWide, got {other:?}"),
        }
        let msg = format!("{e}");
        assert!(msg.contains(field), "log-visible error must name field: {msg}");
        assert!(msg.contains(value), "log-visible error must name value: {msg}");
        assert!(
            msg.contains("EPERM"),
            "wider-policy rejection must be EPERM-class: {msg}"
        );
    }

    // extra_writable outside the writable ceiling (/etc is only readable).
    let wide = ExecParams {
        extra_writable: vec![PathBuf::from("/etc")],
        ..Default::default()
    };
    let e = inst
        .exec_params(&["true"], &wide, ExecStdio::Null)
        .await
        .expect_err("read-only extra_writable must be refused");
    assert_policy_too_wide(&e, "extra_writable", "/etc");

    // cwd outside every fs grant.
    let wide = ExecParams {
        cwd: Some(PathBuf::from("/root")),
        ..Default::default()
    };
    let e = inst
        .exec_params(&["true"], &wide, ExecStdio::Null)
        .await
        .expect_err("out-of-ceiling cwd must be refused");
    assert_policy_too_wide(&e, "cwd", "/root");

    // bind_ports outside the net_allow_bind ceiling.
    let other_port = free_port();
    assert_ne!(other_port, allowed_port);
    let wide = ExecParams {
        bind_ports: vec![other_port],
        ..Default::default()
    };
    let e = inst
        .exec_params(&["true"], &wide, ExecStdio::Null)
        .await
        .expect_err("out-of-ceiling bind_ports must be refused");
    assert_policy_too_wide(&e, "bind_ports", &other_port.to_string());

    // A path the instance fs_deny's can never be granted per-exec.
    let denied_str = denied_dir.to_string_lossy().to_string();
    let wide = ExecParams {
        extra_writable: vec![denied_dir.clone()],
        ..Default::default()
    };
    let e = inst
        .exec_params(&["true"], &wide, ExecStdio::Null)
        .await
        .expect_err("extra_writable under fs_deny must be refused");
    assert_policy_too_wide(&e, "extra_writable", &denied_str);

    // The on-behalf fd-injection entry point (worker-held stdio fds over the
    // control channel) runs the same validation — identical field/value.
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .expect("open /dev/null");
    let mut owned = Vec::with_capacity(3);
    for _ in 0..3 {
        let dup = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        assert!(dup >= 0, "dup stdio fd for fd-injection exec");
        owned.push(unsafe { OwnedFd::from_raw_fd(dup) });
    }
    let fds: [OwnedFd; 3] = owned
        .try_into()
        .expect("three dup'd stdio fds");
    let e = inst
        .exec_with_fds_params(&["true"], &wide, fds)
        .await
        .expect_err("fd-injection exec must apply the same subset check");
    assert_policy_too_wide(&e, "extra_writable", &denied_str);

    // The instance stays usable with an in-ceiling request.
    let params = ExecParams {
        bind_ports: vec![allowed_port],
        ..Default::default()
    };
    let h = inst
        .exec_params(&["true"], &params, ExecStdio::Null)
        .await
        .expect("in-ceiling exec still works");
    let status = inst.wait_child(h.child_id).await.expect("wait child");
    assert_eq!(status, ExitStatus::Code(0));

    let _ = std::fs::remove_dir_all(&denied_dir);
    inst.shutdown().await.expect("shutdown");
}

/// Matrix F4.1 case: a per-exec `bind_ports` grant inside the ceiling lets
/// the child bind that port, and a host-side TCP client reaches the
/// in-sandbox listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_per_exec_bind_port_reaches_listener() {
    let port = free_port();
    let policy = base_policy().net_allow_bind_port(port);
    let mut inst = launch_exec_only_tmp(policy).await;

    let script = format!(
        concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
            "s.bind(('127.0.0.1', {port}))\n",
            "s.listen(1)\n",
            "conn, _ = s.accept()\n",
            "conn.sendall(b'PONG')\n",
            "conn.close()\n",
            "s.close()\n",
        ),
        port = port
    );
    let params = ExecParams {
        bind_ports: vec![port],
        ..Default::default()
    };
    let h = inst
        .exec_params(&["/usr/bin/python3", "-c", &script], &params, ExecStdio::Null)
        .await
        .expect("exec bind-port child");

    // Retry the host-side connect until the child's listener is up.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut pong = Vec::new();
    loop {
        if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut buf = [0u8; 4];
            let n = stream.read(&mut buf).unwrap_or(0);
            pong.extend_from_slice(&buf[..n]);
            if n > 0 {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "host client never reached the child listener"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(pong, b"PONG", "host client must reach the in-sandbox listener");

    let status = inst.wait_child(h.child_id).await.expect("wait child");
    assert_eq!(status, ExitStatus::Code(0));
    inst.shutdown().await.expect("shutdown");
}

/// Spawn a daemon-side loopback sink listener at `ip`; every successful TCP
/// connect is accepted and recorded. Returns (port, accept log).
fn spawn_sink_listener(ip: IpAddr) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind((ip, 0)).expect("bind sink listener");
    let port = listener.local_addr().unwrap().port();
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&log);
    std::thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking sink");
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                    seen.lock().unwrap().push(peer);
                    drop(stream);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (port, log)
}

/// Matrix F4.3/F4.4 case: `update_network` binds to **new execs only** and
/// reports staleness for running children; the child bound at exec keeps its
/// own network policy, so a narrow sibling can never inherit (or be denied
/// by) a wide sibling's decisions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_update_network_applies_to_new_exec_only_and_reports_staleness() {
    let (port_lo, log_lo) = spawn_sink_listener("127.0.0.1".parse().unwrap());
    let (port_hi, log_hi) = spawn_sink_listener("127.0.0.2".parse().unwrap());

    // Any-port destination ceiling over loopback: update_network may narrow
    // it per child, and the pre-update child keeps the full ceiling.
    let policy = base_policy().net_allow("*");
    let mut inst = launch_exec_only_tmp(policy).await;

    let dir = scratch("net-update");
    std::fs::create_dir_all(&dir).expect("create net-update dir");
    let a_go1 = dir.join("a-go1");
    let a_go2 = dir.join("a-go2");
    let a_out = dir.join("a-out");
    let b_out = dir.join("b-out");
    std::fs::create_dir_all(&a_out).expect("create A output dir");
    std::fs::create_dir_all(&b_out).expect("create B output dir");

    // Child A runs *before* the update: it must keep the wide exec-time
    // policy even after `update_network` narrows the session. Its connects
    // are marker-gated so they happen after the update and after sibling B
    // was bound to the narrow policy.
    let a_script = format!(
        concat!(
            "import os, socket, time\n",
            "def wait(f):\n",
            "    while not os.path.exists(f):\n",
            "        time.sleep(0.05)\n",
            "def probe(ip, port, out):\n",
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "    s.settimeout(3)\n",
            "    try:\n",
            "        s.connect((ip, port))\n",
            "        open(out, 'w').write('OK')\n",
            "    except OSError as e:\n",
            "        open(out, 'w').write('ERR%d' % e.errno)\n",
            "    finally:\n",
            "        s.close()\n",
            "wait('{go1}')\n",
            "probe('127.0.0.1', {p_lo}, '{o_lo}')\n",
            "wait('{go2}')\n",
            "probe('127.0.0.2', {p_hi}, '{o_hi}')\n",
        ),
        go1 = a_go1.display(),
        go2 = a_go2.display(),
        p_lo = port_lo,
        p_hi = port_hi,
        o_lo = a_out.join("lo").display(),
        o_hi = a_out.join("hi").display(),
    );
    let a = inst
        .exec_params(&["/usr/bin/python3", "-c", &a_script], &ExecParams::default(), ExecStdio::Null)
        .await
        .expect("exec pre-update child A");

    // Session-level update: new execs only. A is still running under the old
    // policy, so the API must report A as stale.
    let stale = inst
        .update_network(&["127.0.0.1".parse::<IpAddr>().unwrap()])
        .await
        .expect("update_network narrows the session to loopback-low");
    assert!(
        stale.stale_child_ids.contains(&a.child_id),
        "running pre-update child A must be reported stale, got {stale:?}"
    );

    // Child B execs after the update: bound to the narrow policy — loopback
    // 127.0.0.1 only. Its connect to the wide sibling's 127.0.0.2 listener
    // must be refused even though the *instance* ceiling still allows it.
    let b_script = format!(
        concat!(
            "import socket\n",
            "def probe(ip, port, out):\n",
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "    s.settimeout(3)\n",
            "    try:\n",
            "        s.connect((ip, port))\n",
            "        open(out, 'w').write('OK')\n",
            "    except OSError as e:\n",
            "        open(out, 'w').write('ERR%d' % e.errno)\n",
            "    finally:\n",
            "        s.close()\n",
            "probe('127.0.0.1', {p_lo}, '{o_lo}')\n",
            "probe('127.0.0.2', {p_hi}, '{o_hi}')\n",
        ),
        p_lo = port_lo,
        p_hi = port_hi,
        o_lo = b_out.join("lo").display(),
        o_hi = b_out.join("hi").display(),
    );
    let b = inst
        .exec_params(&["/usr/bin/python3", "-c", &b_script], &ExecParams::default(), ExecStdio::Null)
        .await
        .expect("exec post-update child B");

    let status_b = inst.wait_child(b.child_id).await.expect("wait child B");
    assert_eq!(status_b, ExitStatus::Code(0));
    assert_eq!(
        std::fs::read_to_string(b_out.join("lo")).unwrap_or_default(),
        "OK",
        "post-update child B may reach its bound 127.0.0.1 destination"
    );
    assert_eq!(
        std::fs::read_to_string(b_out.join("hi")).unwrap_or_default(),
        "ERR111",
        "post-update child B must be denied the wide child's destination (ECONNREFUSED)"
    );

    // Release A's two marker gates: A connects after B's narrow binding is
    // live, proving the running child kept its exec-time (wide) policy.
    std::fs::write(&a_go1, b"go").expect("release A gate 1");
    std::fs::write(&a_go2, b"go").expect("release A gate 2");
    let status_a = inst.wait_child(a.child_id).await.expect("wait child A");
    assert_eq!(status_a, ExitStatus::Code(0));
    assert_eq!(
        std::fs::read_to_string(a_out.join("lo")).unwrap_or_default(),
        "OK",
        "pre-update child A keeps its loopback-low grant"
    );
    assert_eq!(
        std::fs::read_to_string(a_out.join("hi")).unwrap_or_default(),
        "OK",
        "pre-update child A keeps its wide 127.0.0.2 grant after the update"
    );

    // Both listeners were actually reached exactly as the policies allowed:
    // low by A + B, high by A only.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let low = log_lo.lock().unwrap().len();
        let high = log_hi.lock().unwrap().len();
        if low == 2 && high == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(log_lo.lock().unwrap().len(), 2, "low listener: A + B");
    assert_eq!(log_hi.lock().unwrap().len(), 1, "high listener: A only");

    let _ = std::fs::remove_dir_all(&dir);
    inst.shutdown().await.expect("shutdown");
}
