//! End-to-end `sandlock-supervise` binary tests (fork-plan F2b.1).
//!
//! These live in the new crate's own integration target because
//! `CARGO_BIN_EXE_sandlock-supervise` is only available there (the plan's
//! `integration/test_supervise.rs` path belongs to the core suite, which
//! cannot see this crate's binary env var).

use std::os::fd::FromRawFd;
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
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        "--control-fd",
        "2",
    ]);
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
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        "--control-fd",
        "2",
    ]);
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
    // The policy read end is consumed (closed) by the child's bounded read,
    // so the control-fd liveness probe must use a descriptor that stays open
    // for the whole process — stderr — exactly like the F2b.1 tests (the fd
    // is not used by the serve path without --serve).
    let mut cmd = Command::new(bin());
    cmd.arg("--policy")
        .arg(read_fd.to_string())
        .arg("--uid")
        .arg(euid().to_string())
        .arg("--control-fd")
        .arg("2")
        .args(extra_args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
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
    (child, write_fd)
}

fn write_all_fd(fd: std::os::unix::io::RawFd, bytes: &[u8]) {
    use std::io::Write;
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    f.write_all(bytes).expect("write policy bytes");
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
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;

    let policy = write_policy("serve-lifecycle", "{}");
    let (mut worker, server) = std::os::unix::net::UnixStream::pair().expect("control socketpair");
    let control_fd = server.as_raw_fd();

    let mut cmd = Command::new(bin());
    cmd.arg("--policy")
        .arg(policy.to_str().unwrap())
        .arg("--uid")
        .arg(euid().to_string())
        .arg("--control-fd")
        .arg(control_fd.to_string())
        .arg("--serve")
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
    // The child now owns its copy of the control socket; the parent's copy
    // must close so EOF on the worker side tracks the child exiting.
    drop(server);

    // Send a shutdown verb (fd transport: the fd is the credential; no token
    // was agreed for this generation).
    let body = serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "verb": "shutdown",
        "args": {},
    }))
    .expect("serialize shutdown");
    {
        use std::io::{Read, Write};
        worker
            .write_all(&(body.len() as u32).to_be_bytes())
            .and_then(|_| worker.write_all(&body))
            .expect("write shutdown verb");
        let mut len_buf = [0u8; 4];
        worker
            .read_exact(&mut len_buf)
            .expect("read shutdown response length");
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        assert!(resp_len <= 65536, "response cap");
        let mut resp = vec![0u8; resp_len];
        worker.read_exact(&mut resp).expect("read shutdown response");
        let parsed: serde_json::Value = serde_json::from_slice(&resp).expect("response is JSON");
        assert_eq!(parsed["ok"], serde_json::Value::Bool(true));
    }

    let out = child.wait_with_output().expect("wait supervise serve");
    assert!(
        out.status.success(),
        "single-generation serve must exit 0 after shutdown; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&policy);
}
