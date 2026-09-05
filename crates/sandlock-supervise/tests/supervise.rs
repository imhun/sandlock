//! End-to-end `sandlock-supervise` binary tests (fork-plan F2b.1).
//!
//! These live in the new crate's own integration target because
//! `CARGO_BIN_EXE_sandlock-supervise` is only available there (the plan's
//! `integration/test_supervise.rs` path belongs to the core suite, which
//! cannot see this crate's binary env var).

use std::os::fd::FromRawFd;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-supervise")
}

fn repo_tmp_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest.join("../../tmp");
    std::fs::create_dir_all(&dir).expect("create repo tmp dir");
    dir
}

fn write_policy(name: &str, body: &str) -> PathBuf {
    let path = repo_tmp_dir().join(format!("supervise-{name}-{}.json", std::process::id()));
    std::fs::write(&path, body).expect("write policy file");
    path
}

fn write_secret(name: &str) -> PathBuf {
    let path = repo_tmp_dir().join(format!("supervise-{name}-{}.secret", std::process::id()));
    std::fs::write(&path, "s3cret\n").expect("write test secret");
    path
}

fn spawn(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("spawn sandlock-supervise")
}

/// Spawn `sandlock-supervise` with `args` (which must include the caller's
/// `--control-fd N`).  `control_fd` is that same descriptor: CLOEXEC is
/// cleared at exec so the child sees the open SOCK_STREAM socket, exactly as
/// the launcher's fd handoff delivers it.
fn spawn_with_control_fd(
    args: &[&str],
    control_fd: std::os::unix::io::RawFd,
) -> std::process::Child {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            let flags = libc::fcntl(control_fd, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(control_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sandlock-supervise");
    child
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Current euid of the test process (the gate runs this suite as uid 65534).
fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

#[test]
fn test_supervise_refuses_wrong_uid() {
    // A valid (minimal) policy is provided so the refusal is attributable to
    // the uid self-check, which must run before the policy is even read.
    let policy = write_policy("wrong-uid", "{}");
    let wrong_uid = euid().wrapping_add(1);
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &wrong_uid.to_string(),
        // Required by the CLI; the uid self-check runs before any fd probe,
        // so the value only needs to parse.
        "--control-fd",
        "2",
    ]);
    assert!(
        !out.status.success(),
        "supervise must refuse to start when euid != --uid"
    );
    let err = stderr(&out);
    assert!(
        err.contains("refusing to start") && err.contains("--uid"),
        "stderr must explain the refusal, got: {err}"
    );
    assert!(
        err.contains(&euid().to_string()) && err.contains(&wrong_uid.to_string()),
        "stderr must name both uids, got: {err}"
    );
}

#[test]
fn test_policy_roundtrip_covers_every_field() {
    // Full-field policy through the real binary: every union field is
    // provided with a distinctive value; startup must succeed only if each
    // one parsed, applied, and read back equal. Any missing/un-landed field
    // makes the binary fail and name the field.
    let secret = write_secret("roundtrip");
    let body = sandlock_supervise::policy::example_policy_json(&secret);
    let policy = write_policy("roundtrip", &body);
    let (_worker, server) = std::os::unix::net::UnixStream::pair().expect("control socketpair");
    let control_fd = server.as_raw_fd();
    let child = spawn_with_control_fd(
        &[
            "--policy",
            policy.to_str().unwrap(),
            "--uid",
            &euid().to_string(),
            "--control-fd",
            &control_fd.to_string(),
        ],
        control_fd,
    );
    drop(server);
    let out = child.wait_with_output().expect("wait supervise roundtrip");
    let err = stderr(&out);
    assert!(
        out.status.success(),
        "full-field policy must start cleanly; stderr: {err}"
    );
    assert!(
        err.is_empty(),
        "successful startup must not write to stderr, got: {err}"
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&secret);
}

#[test]
fn test_supervise_rejects_unknown_policy_field_by_name() {
    let policy = write_policy(
        "unknown-field",
        r#"{"fs_readable": ["/usr"], "not_a_real_field": 1}"#,
    );
    let (_worker, server) = std::os::unix::net::UnixStream::pair().expect("control socketpair");
    let control_fd = server.as_raw_fd();
    let child = spawn_with_control_fd(
        &[
            "--policy",
            policy.to_str().unwrap(),
            "--uid",
            &euid().to_string(),
            "--control-fd",
            &control_fd.to_string(),
        ],
        control_fd,
    );
    drop(server);
    let out = child.wait_with_output().expect("wait supervise unknown field");
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("`not_a_real_field`"),
        "unknown field must be named, got: {err}"
    );
    let _ = std::fs::remove_file(&policy);
}

#[test]
fn test_supervise_rejects_closed_control_fd() {
    let policy = write_policy("closed-control-fd", "{}");
    // 999 is not open in a fresh test process.
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        "--control-fd",
        "999",
    ]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("control fd 999") && err.contains("not open"),
        "closed control fd must be refused by name, got: {err}"
    );
    let _ = std::fs::remove_file(&policy);
}

// ============================================================
// F2b.2: real --policy <fd> transport + single-generation serve
// ============================================================

/// Spawn `sandlock-supervise` with `--policy <fd>` where `<fd>` is a fresh
/// pipe read end handed to the child at exec (CLOEXEC cleared).  Returns the
/// child plus the parent's write end, so the test controls when the policy
/// document arrives (and whether it arrives at all).
fn spawn_with_policy_pipe(
    extra_env: &[(&str, &str)],
    extra_args: &[&str],
) -> (std::process::Child, std::os::unix::io::RawFd) {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let (read_fd, write_fd) = (fds[0], fds[1]);
    // The control fd must be a real SOCK_STREAM socket (supervise validates
    // SO_TYPE), so give the child one end of a socketpair; the parent keeps
    // the worker end alive while supervise runs.
    let (_ctrl_worker, ctrl_server) =
        std::os::unix::net::UnixStream::pair().expect("control socketpair");
    let control_fd = ctrl_server.as_raw_fd();
    let mut cmd = Command::new(bin());
    cmd.arg("--policy")
        .arg(read_fd.to_string())
        .arg("--uid")
        .arg(euid().to_string())
        .arg("--control-fd")
        .arg(control_fd.to_string())
        .args(extra_args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            let ctrl_flags = libc::fcntl(control_fd, libc::F_GETFD);
            if ctrl_flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(control_fd, libc::F_SETFD, ctrl_flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(read_fd, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(read_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sandlock-supervise with policy pipe");
    // Parent closes its read end: only the child (and the write end we
    // return) keeps the pipe alive, so EOF semantics are exactly "the
    // launcher wrote everything and closed".
    unsafe {
        libc::close(read_fd);
    }
    drop(ctrl_server);
    (child, write_fd)
}

/// Write bytes to `fd` WITHOUT taking ownership of the descriptor (callers
/// that need the write end to stay open afterwards — e.g. the mid-stream
/// stall test — wrap it themselves).
fn write_all_fd(fd: std::os::unix::io::RawFd, bytes: &[u8]) {
    use std::io::Write;
    unsafe {
        let dup = libc::dup(fd);
        assert!(dup >= 0, "dup policy pipe write end");
        let mut f = std::fs::File::from_raw_fd(dup);
        // The child may exit as soon as it has enough bytes to fail (the
        // oversize test): a broken pipe then races our final write.  The
        // child's verdict is authoritative — tolerate EPIPE here.
        let _ = f.write_all(bytes);
    }
}

/// Spawn `sandlock-supervise --serve` over a real socketpair (the fd
/// handoff) and return the child plus the worker end the test drives.
fn spawn_serve_supervisor(policy: &PathBuf, extra_args: &[&str]) -> (std::process::Child, std::os::unix::net::UnixStream) {
    use std::os::unix::process::CommandExt;

    let (worker, server) = std::os::unix::net::UnixStream::pair().expect("control socketpair");
    let control_fd = server.as_raw_fd();
    let mut cmd = Command::new(bin());
    cmd.arg("--policy")
        .arg(policy.to_str().unwrap())
        .arg("--uid")
        .arg(euid().to_string())
        .arg("--control-fd")
        .arg(control_fd.to_string())
        .arg("--serve")
        .args(extra_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    unsafe {
        cmd.pre_exec(move || {
            let flags = libc::fcntl(control_fd, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(control_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn serve supervise");
    drop(server);
    (child, worker)
}

/// Send one control frame over the worker end and read the response.
fn roundtrip_frame(worker: &mut std::os::unix::net::UnixStream, body: &serde_json::Value) -> serde_json::Value {
    use std::io::{Read, Write};
    let bytes = serde_json::to_vec(body).expect("serialize frame");
    worker
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| worker.write_all(&bytes))
        .expect("write control frame");
    let mut len_buf = [0u8; 4];
    worker
        .read_exact(&mut len_buf)
        .expect("read response length");
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    assert!(resp_len <= 65536, "response cap");
    let mut resp = vec![0u8; resp_len];
    worker.read_exact(&mut resp).expect("read response");
    serde_json::from_slice(&resp).expect("response is JSON")
}

/// A real `--policy <fd>` happy path: the launcher writes the JSON document
/// to a pipe and supervise reads it from the handed-over descriptor (with a
/// deadline and a hard size cap), validates it, and — without `--serve` —
/// exits 0.
#[test]
fn test_supervise_reads_policy_from_real_fd() {
    let policy = r#"{"fs_readable": ["/usr"], "net_allow": ["tcp://1.1.1.1:443"]}"#;
    let (child, write_fd) = spawn_with_policy_pipe(&[], &[]);
    write_all_fd(write_fd, policy.as_bytes());
    unsafe {
        libc::close(write_fd);
    }

    let out = child.wait_with_output().expect("wait supervise");
    assert!(
        out.status.success(),
        "policy-from-fd must validate and exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "successful fd-policy startup must not write stderr, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Timeout semantics on the fd transport: when the launcher never writes the
/// policy document, supervise must fail startup after the deadline instead
/// of hanging the slot forever.
#[test]
fn test_supervise_policy_fd_times_out() {
    let (child, write_fd) = spawn_with_policy_pipe(
        &[("SANDBOX_SUPERVISE_POLICY_TIMEOUT_MS", "300")],
        &[],
    );
    // Keep the write end open and write nothing: supervise must time out.
    let _writer = unsafe { std::fs::File::from_raw_fd(write_fd) };

    let out = child.wait_with_output().expect("wait supervise timeout");
    assert!(
        !out.status.success(),
        "a policy fd that never delivers bytes must fail startup"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("timed out"),
        "timeout failure must be named, got: {err}"
    );
}

/// I4: a writer that stalls MID-stream (after delivering the first bytes)
/// must fail within the deadline too — the poll deadline applies to every
/// read, not just the first byte.
#[test]
fn test_supervise_policy_fd_partial_write_stall_times_out() {
    let (child, write_fd) = spawn_with_policy_pipe(
        &[("SANDBOX_SUPERVISE_POLICY_TIMEOUT_MS", "400")],
        &[],
    );
    // Deliver the beginning of a policy document, then stall without
    // closing the pipe: supervise must time out waiting for the rest.
    write_all_fd(write_fd, br#"{"fs_readable": ["/usr""#);
    let _writer = unsafe { std::fs::File::from_raw_fd(write_fd) };

    let out = child.wait_with_output().expect("wait supervise partial stall");
    assert!(
        !out.status.success(),
        "a mid-stream stall must fail startup within the deadline"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("timed out"),
        "mid-stream timeout must be named, got: {err}"
    );
}

/// Limit semantics on the fd transport: a document larger than the cap is a
/// protocol error, never a silently truncated policy.
#[test]
fn test_supervise_policy_fd_rejects_oversize() {
    let huge = "x".repeat(sandlock_supervise::serve::MAX_POLICY_BYTES + 1);
    let (child, write_fd) = spawn_with_policy_pipe(&[], &[]);
    write_all_fd(write_fd, huge.as_bytes());
    unsafe {
        libc::close(write_fd);
    }

    let out = child.wait_with_output().expect("wait supervise oversize");
    assert!(!out.status.success(), "oversize policy must fail startup");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("exceeds") && err.contains("bytes"),
        "oversize failure must name the cap, got: {err}"
    );
}

/// Single-generation serve over the handed-off control fd: the launcher
/// keeps one socketpair end, supervise serves the other until a `shutdown`
/// verb, then exits 0.
#[test]
fn test_supervise_serves_control_fd_until_shutdown() {
    let policy = write_policy("serve-lifecycle", "{}");
    let (child, mut worker) = spawn_serve_supervisor(&policy, &[]);

    // Send a shutdown verb (fd transport: the fd is the credential; no token
    // was agreed for this generation).
    let resp = roundtrip_frame(&mut worker, &serde_json::json!({
        "v": 1,
        "verb": "shutdown",
        "args": {},
    }));
    assert_eq!(resp["ok"], serde_json::Value::Bool(true));

    let out = child.wait_with_output().expect("wait supervise serve");
    assert!(
        out.status.success(),
        "single-generation serve must exit 0 after shutdown; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&policy);
}

/// I2: a worker that disappears without a `shutdown` verb is an abnormal
/// generation end — supervise must exit non-zero, not 0.
#[test]
fn test_supervise_serve_eof_without_shutdown_exits_nonzero() {
    let policy = write_policy("serve-eof", "{}");
    let (child, worker) = spawn_serve_supervisor(&policy, &[]);
    // Drop the worker end without sending anything: the serve loop sees EOF.
    drop(worker);

    let out = child.wait_with_output().expect("wait supervise eof");
    assert!(
        !out.status.success(),
        "EOF without a shutdown verb must exit non-zero; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("abnormally"),
        "the abnormal end must be named, got: {err}"
    );
    let _ = std::fs::remove_file(&policy);
}

/// I2: a peer that presents a missing/wrong channel token is refused and the
/// generation ends abnormally — supervise must exit non-zero.
#[test]
fn test_supervise_serve_wrong_token_exits_nonzero() {
    let policy = write_policy("serve-wrong-token", "{}");
    let (child, mut worker) = spawn_serve_supervisor(&policy, &["--token", "expected-token"]);

    // Missing token: explicit refusal, then abnormal end.
    let resp = roundtrip_frame(&mut worker, &serde_json::json!({
        "v": 1,
        "verb": "config",
        "args": {},
    }));
    assert_eq!(resp["ok"], serde_json::Value::Bool(false));
    assert!(
        resp["err"].as_str().unwrap_or_default().contains("token"),
        "missing-token refusal must name the token: {resp:?}"
    );
    let out = child.wait_with_output().expect("wait supervise wrong token");
    assert!(
        !out.status.success(),
        "a refused peer must exit non-zero; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&policy);
}

/// I2: `--control-fd` must name a SOCK_STREAM socket; a regular file passed
/// with --serve must fail by name instead of silently exiting 0.
#[test]
fn test_supervise_rejects_non_socket_control_fd() {
    let policy = write_policy("control-fd-not-socket", "{}");
    // stderr is an open pipe — open, but not a socket.
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        "--control-fd",
        "2",
        "--serve",
    ]);
    assert!(!out.status.success(), "a non-socket control fd must be refused");
    let err = stderr(&out);
    assert!(
        err.contains("control fd 2") && err.contains("not a socket"),
        "the refusal must name the fd and the socket requirement, got: {err}"
    );
    let _ = std::fs::remove_file(&policy);
}
