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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    // Run (a) manually so the host-side per-child record (I3) can be asserted
    // against the exact request.
    let h = inst
        .exec_params(
            &["sh", "-c", "/bin/pwd; printf '%s' \"$F4_MARKER\""],
            &params,
            ExecStdio::Piped,
        )
        .await
        .expect("exec cwd/env child");
    let recorded = inst.child_params(h.child_id).expect("child_params record");
    assert_eq!(
        recorded, params,
        "the per-exec params must be recorded host-side per child"
    );
    drop(h.stdin);
    let status = inst.wait_child(h.child_id).await.expect("wait cwd/env child");
    let out = read_all_stdout(h.stdout.expect("piped stdout"));
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
    // I3: the S9-validated grants are recorded per child (the audit surface);
    // the listener reachability below is what the current shared-Landlock
    // domain can honestly assert (per-child *narrowing* is not yet
    // kernel-enforced — see the report).
    let recorded = inst.child_params(h.child_id).expect("child_params record");
    assert_eq!(recorded.bind_ports, vec![port]);
    assert!(recorded.extra_writable.is_empty());

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

/// End-state B: an `update_network` narrowing is **instance-wide and
/// immediate**. A child that is already running is judged against it from its
/// next connect on, exactly like one exec'd later — there is no exec-time
/// policy to keep and no staleness to report. (D4=A, the shape this replaced,
/// kept a running child on its exec-time policy and named it stale.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_update_network_narrows_a_running_child_immediately() {
    let (port_lo, log_lo) = spawn_sink_listener("127.0.0.1".parse().unwrap());
    let (port_hi, log_hi) = spawn_sink_listener("127.0.0.2".parse().unwrap());

    // Any-port destination ceiling over both loopback addresses: the narrowing
    // below is expressible, and it must bite the *running* child.
    let policy = base_policy().net_allow("127.0.0.1").net_allow("127.0.0.2");
    let mut inst = launch_exec_only_tmp(policy).await;

    let dir = scratch("net-update-live");
    std::fs::create_dir_all(&dir).expect("create net-update dir");
    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).expect("create out dir");
    let go = dir.join("go");
    let lo_out = out_dir.join("lo");
    let hi_out = out_dir.join("hi");

    // The child is exec'd *before* the update and connects only after the
    // marker is released: both probes observe the narrowed policy.
    let script = format!(
        concat!(
            "import os, socket, time\n",
            "while not os.path.exists('{go}'):\n",
            "    time.sleep(0.05)\n",
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
        go = go.display(),
        p_lo = port_lo,
        p_hi = port_hi,
        o_lo = lo_out.display(),
        o_hi = hi_out.display(),
    );
    let child = inst
        .exec_params(
            &["/usr/bin/python3", "-c", &script],
            &ExecParams::default(),
            ExecStdio::Null,
        )
        .await
        .expect("exec pre-update child");

    // Session-level narrowing while the child runs: it applies at once.
    inst.update_network(&["127.0.0.1".parse::<IpAddr>().unwrap()])
        .await
        .expect("narrow the session to loopback-low");

    std::fs::write(&go, b"go").expect("release the running child");
    let status = inst.wait_child(child.child_id).await.expect("wait child");
    assert_eq!(status, ExitStatus::Code(0));
    assert_eq!(
        std::fs::read_to_string(&lo_out).unwrap_or_default(),
        "OK",
        "the narrowed-in destination stays reachable for the running child"
    );
    assert_eq!(
        std::fs::read_to_string(&hi_out).unwrap_or_default(),
        "ERR111",
        "a running child must be refused the narrowed-away destination at once"
    );

    // The refused connect never reached the listener: the answer came from the
    // verdict, not from a dead port.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && log_lo.lock().unwrap().len() < 1 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        log_lo.lock().unwrap().len(),
        1,
        "the narrowed-in listener must be reached exactly once"
    );
    assert_eq!(
        log_hi.lock().unwrap().len(),
        0,
        "the narrowed-away listener must never be reached"
    );

    let _ = std::fs::remove_dir_all(&dir);
    inst.shutdown().await.expect("shutdown");
}

/// End-state B: a descendant that escapes its process group (`setsid`) is
/// judged by the sandbox's current policy exactly like everything else — the
/// narrowing is instance-wide, so an escapee is denied the narrowed-away
/// destination without any ancestor attribution being consulted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_setsid_escapee_is_denied_the_narrowed_away_destination() {
    let (port_hi, log_hi) = spawn_sink_listener("127.0.0.2".parse().unwrap());
    let dir = scratch("escapee");
    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).expect("create escapee out dir");
    let go = dir.join("go");
    let esc_out = out_dir.join("esc");

    let policy = base_policy()
        .net_allow("127.0.0.1")
        .net_allow("127.0.0.2");
    let mut inst = launch_exec_only_tmp(policy).await;
    inst.update_network(&["127.0.0.1".parse::<IpAddr>().unwrap()])
        .await
        .expect("narrow the session to 127.0.0.1");

    // The escapee's code is carried through an env var so it can run with
    // `python3 -c` inside a `setsid`-prefixed Popen (no shell quoting).
    let escapee_code = format!(
        concat!(
            "import os, socket, time\n",
            "while not os.path.exists('{go}'):\n",
            "    time.sleep(0.05)\n",
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "s.settimeout(3)\n",
            "try:\n",
            "    s.connect(('127.0.0.2', {port}))\n",
            "    open('{out}', 'w').write('OK')\n",
            "except OSError as e:\n",
            "    open('{out}', 'w').write('ERR%d' % e.errno)\n",
            "finally:\n",
            "    s.close()\n",
        ),
        go = go.display(),
        port = port_hi,
        out = esc_out.display(),
    );
    let root_code = concat!(
        "import os, subprocess, sys\n",
        "p = subprocess.Popen([sys.executable, '-c', os.environ['F4_ESCAPEE_CODE']],\n",
        "                     preexec_fn=os.setsid)\n",
        "sys.exit(p.wait())\n",
    );
    let params = ExecParams {
        env: vec![("F4_ESCAPEE_CODE".to_string(), escapee_code)],
        ..Default::default()
    };
    let h = inst
        .exec_params(&["/usr/bin/python3", "-c", root_code], &params, ExecStdio::Null)
        .await
        .expect("exec the escapee's root child");

    std::fs::write(&go, b"go").expect("release escapee");
    let status = inst.wait_child(h.child_id).await.expect("wait root child");
    assert_eq!(status, ExitStatus::Code(0));
    assert_eq!(
        std::fs::read_to_string(&esc_out).unwrap_or_default(),
        "ERR111",
        "a setsid escapee must stay under the sandbox's current policy"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if log_hi.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        log_hi.lock().unwrap().is_empty(),
        "the escapee must never reach the narrowed-away destination"
    );

    let _ = std::fs::remove_dir_all(&dir);
    inst.shutdown().await.expect("shutdown");
}

/// Reviewer I4: the policy-fn live-policy tightening channel still applies on
/// top of the instance-wide `update_network` narrowing (deny wins). A running
/// child whose narrowed policy allows an IP is denied it once a later event
/// tightens `live_policy` — the incident-response deny path keeps working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_live_policy_tightening_denies_a_running_child() {
    use sandlock_core::policy_fn::Verdict;

    let (port_lo, _log_lo) = spawn_sink_listener("127.0.0.1".parse().unwrap());
    let (port_hi, log_hi) = spawn_sink_listener("127.0.0.2".parse().unwrap());
    let dir = scratch("live-tighten");
    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).expect("create live-tighten out dir");
    let go = dir.join("go");
    let lo_out = out_dir.join("lo");
    let hi_out = out_dir.join("hi");

    let restricted = Arc::new(AtomicBool::new(false));
    let restricted_flag = Arc::clone(&restricted);
    let policy = base_policy()
        .net_allow("127.0.0.1")
        .net_allow("127.0.0.2")
        .policy_fn(move |event, ctx| {
        if event.syscall == "execve"
            && event
                .argv
                .as_deref()
                .map(|a| a.iter().any(|s| s == "F4RESTRICT"))
                .unwrap_or(false)
            && !restricted_flag.swap(true, Ordering::SeqCst)
        {
            // Incident-response tightening: after this event, the only live
            // network grant is loopback-low.
            ctx.restrict_network(&["127.0.0.1".parse().unwrap()]);
        }
        Verdict::Allow
    });
    let mut inst = launch_exec_only_tmp(policy).await;

    inst.update_network(&[
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        "127.0.0.2".parse::<IpAddr>().unwrap(),
    ])
    .await
    .expect("narrow the sandbox to loopback-low and loopback-high");

    // A runs under the two-destination narrowing. It waits for a marker, then
    // re-execs itself with an argv marker — the execve event triggers the
    // policy-fn live restriction *while A is still running* — and the inner
    // process probes both destinations afterwards.
    let inner = format!(
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
        o_lo = lo_out.display(),
        o_hi = hi_out.display(),
    );
    let outer = format!(
        concat!(
            "import os, sys, time\n",
            "while not os.path.exists('{go}'):\n",
            "    time.sleep(0.05)\n",
            "os.execv(sys.executable,\n",
            "        [sys.executable, '-c', os.environ['F4_INNER'], 'F4RESTRICT'])\n",
        ),
        go = go.display(),
    );
    let params = ExecParams {
        env: vec![("F4_INNER".to_string(), inner)],
        ..Default::default()
    };
    let a = inst
        .exec_params(
            &["/usr/bin/python3", "-c", &outer],
            &params,
            ExecStdio::Null,
        )
        .await
        .expect("exec child A");

    std::fs::write(&go, b"go").expect("release child A");
    let status_a = inst.wait_child(a.child_id).await.expect("wait child A");
    assert_eq!(status_a, ExitStatus::Code(0));
    assert_eq!(
        std::fs::read_to_string(&lo_out).unwrap_or_default(),
        "OK",
        "the live grant (loopback-low) still applies to the running child"
    );
    assert_eq!(
        std::fs::read_to_string(&hi_out).unwrap_or_default(),
        "ERR111",
        "live_policy tightening must deny the running child its pre-tightening IP"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if log_hi.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        log_hi.lock().unwrap().is_empty(),
        "the tightened running child must never reach loopback-high"
    );

    let _ = std::fs::remove_dir_all(&dir);
    inst.shutdown().await.expect("shutdown");
}

/// Reviewer R2: the main workload (child id 0) keeps its egress after an
/// exec-child announcement — there is no attribution left to lose, so the
/// sandbox's shared live/static policy governs it throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_main_workload_egress_survives_exec_child_announcement() {
    let (port_hi, log_hi) = spawn_sink_listener("127.0.0.2".parse().unwrap());
    let dir = scratch("main-attributed");
    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).expect("create main out dir");
    let go = dir.join("go");
    let out = out_dir.join("main");

    let policy = base_policy()
        .net_allow("127.0.0.1")
        .net_allow("127.0.0.2");
    let main_script = format!(
        concat!(
            "import os, socket, time\n",
            "while not os.path.exists('{go}'):\n",
            "    time.sleep(0.05)\n",
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "s.settimeout(3)\n",
            "try:\n",
            "    s.connect(('127.0.0.2', {port}))\n",
            "    open('{out}', 'w').write('OK')\n",
            "except OSError as e:\n",
            "    open('{out}', 'w').write('ERR%d' % e.errno)\n",
            "finally:\n",
            "    s.close()\n",
        ),
        go = go.display(),
        port = port_hi,
        out = out.display(),
    );
    let mut inst = SandboxInstance::launch_exec(
        policy.build().unwrap().with_name("f4-main-attributed"),
        &["/usr/bin/python3", "-c", &main_script],
    )
    .await
    .expect("launch exec session with main workload");

    // Announce (and reap) an exec child: the main workload's verdict must not
    // change because a sibling appeared and left.
    let child = inst
        .exec(&["true"], ExecStdio::Null)
        .await
        .expect("exec additional child");
    let status = inst.wait_child(child.child_id).await.expect("wait child");
    assert_eq!(status, ExitStatus::Code(0));

    // The main (child 0) stays on the shared live/static policy — an exec
    // child announcement changes nothing about its verdict — and reaches the
    // listener.
    std::fs::write(&go, b"go").expect("release main workload");
    let status = inst.wait_child(0).await.expect("wait main workload");
    assert_eq!(status, ExitStatus::Code(0));
    assert_eq!(
        std::fs::read_to_string(&out).unwrap_or_default(),
        "OK",
        "the main workload must keep egress after an exec child announcement"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if log_hi.lock().unwrap().len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(log_hi.lock().unwrap().len(), 1, "the main's connect must land");

    let _ = std::fs::remove_dir_all(&dir);
    inst.shutdown().await.expect("shutdown");
}

/// End-state B / D8: a helper whose parent exits (so it reparents away before
/// its first mediated syscall) is judged by the sandbox's **current** policy —
/// no attribution is consulted, so it keeps egress to the allowed destination
/// and is refused the narrowed-away one. (Under D4=A this shape was blanket
/// `ECONNREFUSED`: the orphan was unattributed and failed closed.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_orphan_that_reparents_away_keeps_the_current_policy() {
    let (port_lo, log_lo) = spawn_sink_listener("127.0.0.1".parse().unwrap());
    let (port_hi, log_hi) = spawn_sink_listener("127.0.0.2".parse().unwrap());
    let dir = scratch("orphan-policy");
    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).expect("create orphan out dir");
    let go = dir.join("go");
    let lo_out = out_dir.join("lo");
    let hi_out = out_dir.join("hi");

    let policy = base_policy()
        .net_allow("127.0.0.1")
        .net_allow("127.0.0.2");
    let mut inst = launch_exec_only_tmp(policy).await;
    inst.update_network(&["127.0.0.1".parse::<IpAddr>().unwrap()])
        .await
        .expect("narrow the sandbox to 127.0.0.1");

    let helper_code = format!(
        concat!(
            "import os, socket, time\n",
            "while not os.path.exists('{go}'):\n",
            "    time.sleep(0.05)\n",
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
        go = go.display(),
        p_lo = port_lo,
        p_hi = port_hi,
        o_lo = lo_out.display(),
        o_hi = hi_out.display(),
    );
    let root_code = concat!(
        "import os, subprocess, sys\n",
        "p = subprocess.Popen([sys.executable, '-c', os.environ['F4_HELPER_CODE']])\n",
        "sys.exit(0)\n",
    );
    let params = ExecParams {
        env: vec![("F4_HELPER_CODE".to_string(), helper_code)],
        ..Default::default()
    };
    let h = inst
        .exec_params(&["/usr/bin/python3", "-c", root_code], &params, ExecStdio::Null)
        .await
        .expect("exec the orphan's parent");
    let status = inst.wait_child(h.child_id).await.expect("wait parent");
    assert_eq!(status, ExitStatus::Code(0));

    // The parent is reaped; the helper has reparented away. Its first mediated
    // syscall is the connect below.
    tokio::time::sleep(Duration::from_millis(300)).await;
    std::fs::write(&go, b"go").expect("release orphan");
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if std::fs::read_to_string(&hi_out).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        std::fs::read_to_string(&lo_out).unwrap_or_default(),
        "OK",
        "an orphan keeps egress to the sandbox's current allow set"
    );
    assert_eq!(
        std::fs::read_to_string(&hi_out).unwrap_or_default(),
        "ERR111",
        "an orphan is refused the narrowed-away destination"
    );
    assert_eq!(
        log_lo.lock().unwrap().len(),
        1,
        "the orphan's allowed connect must reach its listener"
    );
    assert!(
        log_hi.lock().unwrap().is_empty(),
        "the narrowed-away listener must never be reached"
    );

    let _ = std::fs::remove_dir_all(&dir);
    inst.shutdown().await.expect("shutdown");
}

/// Minor: a failing per-exec chdir is loud — the child reports the errno on
/// its stderr and exits 125, so `wait_child` surfaces it instead of the
/// workload silently running in the wrong cwd.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_failed_chdir_is_loud_exit_125() {
    let missing = scratch("missing-cwd");
    assert!(!missing.exists(), "scratch cwd must not exist");
    let mut inst = launch_exec_only_tmp(base_policy()).await;

    let params = ExecParams {
        cwd: Some(missing),
        ..Default::default()
    };
    let h = inst
        .exec_params(&["sh", "-c", "exit 0"], &params, ExecStdio::Piped)
        .await
        .expect("exec with missing cwd");
    drop(h.stdin);
    let status = inst.wait_child(h.child_id).await.expect("wait child");
    assert_eq!(
        status,
        ExitStatus::Code(125),
        "a failed pre-exec chdir must exit with the setup-failure code 125"
    );
    let err = read_all_stdout(h.stderr.expect("piped stderr"));
    let text = String::from_utf8_lossy(&err);
    assert!(
        text.contains("chdir") && text.contains("errno"),
        "the child must report the chdir errno on stderr: {text}"
    );
    inst.shutdown().await.expect("shutdown");
}

/// Minor: an instance built with a DenyList policy refuses an update that
/// names an explicitly denied destination (S9, from the instance verb).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_update_network_refuses_static_denylist_destination() {
    // net_allow and net_deny are mutually exclusive at build time: a pure
    // DenyList instance is default-allow except the explicit denies.
    let policy = base_policy().net_deny("127.0.0.2");
    let mut inst = launch_exec_only_tmp(policy).await;

    let err = inst
        .update_network(&["127.0.0.2".parse::<IpAddr>().unwrap()])
        .await
        .expect_err("a statically denied destination must be refused");
    match err {
        SandlockError::Runtime(SandboxRuntimeError::PolicyTooWide {
            field: "update_network",
            value,
        }) => assert_eq!(value, "127.0.0.2"),
        other => panic!("expected update_network PolicyTooWide, got {other:?}"),
    }

    // A destination outside the static denies can still be narrowed to.
    inst
        .update_network(&["127.0.0.1".parse::<IpAddr>().unwrap()])
        .await
        .expect("non-denied destination update must succeed");
    inst.shutdown().await.expect("shutdown");
}
