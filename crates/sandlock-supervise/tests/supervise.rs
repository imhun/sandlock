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
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-supervise")
}

/// The exact abnormal generation end a supervise process reports when the
/// peer vanishes or is refused (`serve::Generation::finish`, FUP-11a): one
/// stderr line, naming the transport outcome.
const ABNORMAL_END_LINE: &str = "sandlock-supervise: control channel ended abnormally \
                                 (outcome PeerGone); only a shutdown verb completes a generation";

/// The exact dual-transport channel-token refusal (`core::control`'s shared
/// `serve_connection`, FUP-11a), presented to the worker in the `err` field.
const CHANNEL_TOKEN_REFUSAL: &str = "permission denied: verb 'config' requires a valid \
                                     channel token (missing or mismatched)";

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

/// FUP-11a: supervise reports a startup/protocol failure as exactly ONE
/// stderr line (`sandlock-supervise: <reason>`, see `main::main`).  Pinning
/// the whole line — instead of a keyword — makes a message rewrite that loses
/// diagnostic detail, or a stray extra line, fail loudly.
fn single_stderr_line(output: &Output) -> String {
    let err = stderr(output);
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "supervise must report exactly one stderr line, got: {err:?}"
    );
    lines[0].to_string()
}

/// Assert the whole single stderr line (no dynamic part).
fn assert_stderr_line(output: &Output, want: &str) {
    assert_eq!(single_stderr_line(output).as_str(), want);
}

/// Pin the `--policy <fd>` deadline failure:
/// `policy fd <N>: timed out after <E> ms of a <D> ms deadline waiting for
/// bytes`.  `<N>` (the descriptor the test handed over) and `<D>` (the
/// deadline the test set) are known, so everything but the elapsed counter is
/// exact — and the counter must be a plain integer that honoured the
/// deadline instead of silently extending it.
fn assert_policy_fd_timeout(output: &Output, policy_fd: i32, deadline_ms: u64) {
    let line = single_stderr_line(output);
    let prefix =
        format!("sandlock-supervise: policy read failed: policy fd {policy_fd}: timed out after ");
    let suffix = format!(" ms of a {deadline_ms} ms deadline waiting for bytes");
    let elapsed = line
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix(&suffix))
        .unwrap_or_else(|| {
            panic!(
                "timeout failure must be exactly {prefix:?}<elapsed ms>{suffix:?}, got: {line:?}"
            )
        });
    let elapsed: u64 = elapsed
        .parse()
        .expect("the elapsed part must be a plain millisecond count");
    assert!(
        elapsed <= deadline_ms + 2_000,
        "deadline of {deadline_ms} ms must be honoured, failed after {elapsed} ms"
    );
}

/// Current euid of the test process (the gate runs this suite as uid 65534).
fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Per-process control-root override shared by every supervise test in this
/// binary (spawned supervise processes inherit it), so instance runtime dirs
/// and the registered-path registry never collide with another suite's.
fn isolate_ctl_root() -> PathBuf {
    static SET: std::sync::Once = std::sync::Once::new();
    let root = repo_tmp_dir().join(format!("supervise-ctl-{}", std::process::id()));
    SET.call_once(|| {
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var("SANDBOX_CTL_ROOT", &root);
    });
    root
}

/// Base filesystem grant set for launching real system programs (python3,
/// /bin/sh) under a sandbox, mirroring the core integration suites.
fn base_read_paths() -> Vec<String> {
    let mut paths = vec![
        "/usr".to_string(),
        "/lib".to_string(),
        "/bin".to_string(),
        "/etc".to_string(),
        "/proc".to_string(),
        "/dev".to_string(),
    ];
    if std::path::Path::new("/lib64").exists() {
        paths.push("/lib64".to_string());
    }
    paths
}

/// A minimal instance-launchable policy: real programs need the base read
/// grants plus a writable evidence directory inside the repo tmp.
fn instance_policy(evidence_dir: &str) -> String {
    let mut readable = base_read_paths();
    readable.push(evidence_dir.to_string());
    serde_json::json!({
        "fs_readable": readable,
        "fs_writable": [evidence_dir],
    })
    .to_string()
}

/// Wait (polling) until `predicate` is true or the deadline passes.
fn wait_until(deadline: Instant, what: &str, mut predicate: impl FnMut() -> bool) {
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One verb over the registered path (one connection per verb).
fn registered_verb(sock_path: &std::path::Path, token: &str, verb: &str) -> serde_json::Value {
    let mut stream =
        std::os::unix::net::UnixStream::connect(sock_path).expect("connect registered socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("write timeout");
    roundtrip_frame(
        &mut stream,
        &serde_json::json!({
            "v": 1,
            "verb": verb,
            "token": token,
            "args": {},
        }),
    )
}

/// One `exec` verb over the registered path: a fresh connection carries the
/// verb plus the three child-side stdio fds (SCM_RIGHTS), and the response
/// is read on the same connection.
fn registered_exec(
    sock_path: &std::path::Path,
    token: &str,
    argv: &[&str],
    child_ends: &[i32; 3],
) -> serde_json::Value {
    let mut stream =
        std::os::unix::net::UnixStream::connect(sock_path).expect("connect registered socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .expect("read timeout");
    let body = serde_json::json!({
        "v": 1,
        "verb": "exec",
        "token": token,
        "args": { "argv": argv },
    });
    roundtrip_frame_with_fds(&mut stream, &body, child_ends)
}

/// Spawn `sandlock-supervise --serve` (fd handoff) with an instance-launching
/// program and return the child, the worker end the test drives, and the
/// socket inode of the descriptor handed over as `--control-fd`.
///
/// That third element is the supervisor's *own* endpoint as the child sees
/// it.  The two ends of a `socketpair()` are two distinct sockets with
/// different `st_ino`s (measured on this tree), so an fd-table invariant about
/// the supervisor's copy must be compared against the handed-over end — the
/// test's own end is a different socket and would make the comparison
/// vacuous.
fn spawn_serve_supervisor_with_program(
    policy: &PathBuf,
    program: &PathBuf,
    extra_args: &[&str],
) -> (std::process::Child, std::os::unix::net::UnixStream, u64) {
    use std::os::unix::process::CommandExt;

    let (worker, server) = std::os::unix::net::UnixStream::pair().expect("control socketpair");
    let control_fd = server.as_raw_fd();
    let control_inode = socket_inode(control_fd);
    let mut cmd = Command::new(bin());
    cmd.arg("--policy")
        .arg(policy.to_str().unwrap())
        .arg("--uid")
        .arg(euid().to_string())
        .arg("--control-fd")
        .arg(control_fd.to_string())
        .arg("--program")
        .arg(program.to_str().unwrap())
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
    (child, worker, control_inode)
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
    assert_stderr_line(
        &out,
        &format!(
            "sandlock-supervise: refusing to start: euid {} does not match --uid {}; \
             the launcher must drop privileges before exec (otherwise the sandbox would \
             silently run in the wrong identity class)",
            euid(),
            wrong_uid
        ),
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
    assert_stderr_line(
        &out,
        "sandlock-supervise: policy rejected: policy contains unknown field(s): `not_a_real_field`",
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
    let ebadf = std::io::Error::from_raw_os_error(libc::EBADF);
    assert_stderr_line(
        &out,
        &format!("sandlock-supervise: control fd 999 is not open: {ebadf}"),
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
) -> (
    std::process::Child,
    std::os::unix::io::RawFd,
    std::os::unix::io::RawFd,
) {
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
    // The child inherits the descriptor table, so `read_fd` is also the fd
    // number supervise sees (FUP-11a: needed to pin the failure line fully).
    (child, write_fd, read_fd)
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
    roundtrip_frame_with_fds(worker, body, &[])
}

/// Send one control frame (with optional SCM_RIGHTS fds — the F3.2 exec
/// verb's stdio delivery) in a single `sendmsg` and read the response.
fn roundtrip_frame_with_fds(
    worker: &mut std::os::unix::net::UnixStream,
    body: &serde_json::Value,
    fds: &[i32],
) -> serde_json::Value {
    let bytes = serde_json::to_vec(body).expect("serialize frame");
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(&bytes);
    sandlock_core::init::fdpass::send_with_fds(worker, &frame, fds)
        .expect("write control frame with fds");
    read_control_response(worker)
}

/// Read one length-prefixed control response.
fn read_control_response(worker: &mut std::os::unix::net::UnixStream) -> serde_json::Value {
    use std::io::Read;
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

/// Create the three pipes an exec worker owns: returns
/// `(host_stdin_write, host_stdout_read, host_stderr_read)` and the three
/// child-side ends to send over SCM_RIGHTS.
fn make_exec_stdio() -> (
    std::os::unix::io::OwnedFd,
    std::os::unix::io::OwnedFd,
    std::os::unix::io::OwnedFd,
    [i32; 3],
) {
    use std::os::fd::FromRawFd;
    let mut pipes = [[0i32; 2]; 3];
    for p in pipes.iter_mut() {
        assert_eq!(
            unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "pipe2: {}",
            std::io::Error::last_os_error()
        );
    }
    // pipes[i] = (read, write). stdin: child reads (0), host writes (1);
    // stdout: child writes (2), host reads (3); stderr likewise (4, 5).
    let host_stdin = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(pipes[0][1]) };
    let host_stdout = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(pipes[1][0]) };
    let host_stderr = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(pipes[2][0]) };
    (
        host_stdin,
        host_stdout,
        host_stderr,
        [pipes[0][0], pipes[1][1], pipes[2][1]],
    )
}

/// A real `--policy <fd>` happy path: the launcher writes the JSON document
/// to a pipe and supervise reads it from the handed-over descriptor (with a
/// deadline and a hard size cap), validates it, and — without `--serve` —
/// exits 0.
#[test]
fn test_supervise_reads_policy_from_real_fd() {
    let policy = r#"{"fs_readable": ["/usr"], "net_allow": ["tcp://1.1.1.1:443"]}"#;
    let (child, write_fd, _policy_fd) = spawn_with_policy_pipe(&[], &[]);
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
    let (child, write_fd, policy_fd) = spawn_with_policy_pipe(
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
    assert_policy_fd_timeout(&out, policy_fd, 300);
}

/// I4: a writer that stalls MID-stream (after delivering the first bytes)
/// must fail within the deadline too — the poll deadline applies to every
/// read, not just the first byte.
#[test]
fn test_supervise_policy_fd_partial_write_stall_times_out() {
    let (child, write_fd, policy_fd) = spawn_with_policy_pipe(
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
    assert_policy_fd_timeout(&out, policy_fd, 400);
}

/// Limit semantics on the fd transport: a document larger than the cap is a
/// protocol error, never a silently truncated policy.
#[test]
fn test_supervise_policy_fd_rejects_oversize() {
    let huge = "x".repeat(sandlock_supervise::serve::MAX_POLICY_BYTES + 1);
    let (child, write_fd, policy_fd) = spawn_with_policy_pipe(&[], &[]);
    write_all_fd(write_fd, huge.as_bytes());
    unsafe {
        libc::close(write_fd);
    }

    let out = child.wait_with_output().expect("wait supervise oversize");
    assert!(!out.status.success(), "oversize policy must fail startup");
    assert_stderr_line(
        &out,
        &format!(
            "sandlock-supervise: policy read failed: policy fd {policy_fd}: document exceeds {} bytes",
            sandlock_supervise::serve::MAX_POLICY_BYTES
        ),
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
    assert_stderr_line(&out, ABNORMAL_END_LINE);
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
    assert_eq!(
        resp["err"].as_str(),
        Some(CHANNEL_TOKEN_REFUSAL),
        "missing-token refusal must be the exact shared refusal"
    );
    let out = child.wait_with_output().expect("wait supervise wrong token");
    assert!(
        !out.status.success(),
        "a refused peer must exit non-zero; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_stderr_line(&out, ABNORMAL_END_LINE);
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
    let enotsock = std::io::Error::from_raw_os_error(libc::ENOTSOCK);
    assert_stderr_line(
        &out,
        &format!("sandlock-supervise: control fd 2 is not a socket: {enotsock}"),
    );
    let _ = std::fs::remove_file(&policy);
}

/// F2b.3 residual: a SOCK_STREAM socket in the WRONG DOMAIN (AF_INET) must
/// also be refused — SO_TYPE alone would let a TCP stream masquerade as the
/// unix control channel.
#[test]
fn test_supervise_rejects_non_unix_socket_control_fd() {
    let policy = write_policy("control-fd-not-unix", "{}");
    // A connected TCP stream: open, SOCK_STREAM, but AF_INET.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let addr = listener.local_addr().expect("listener addr");
    let client = std::net::TcpStream::connect(addr).expect("connect tcp");
    let (server, _) = listener.accept().expect("accept tcp");
    drop(client);
    let tcp_fd = server.as_raw_fd();

    let mut cmd = Command::new(bin());
    cmd.args([
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        "--control-fd",
        &tcp_fd.to_string(),
        "--serve",
    ]);
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            let flags = libc::fcntl(tcp_fd, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(tcp_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().expect("run supervise with tcp control fd");
    assert!(!out.status.success(), "an AF_INET control fd must be refused");
    assert_stderr_line(
        &out,
        &format!(
            "sandlock-supervise: control fd {tcp_fd} is an AF_INET stream socket, \
             not AF_UNIX: the fd transport serves the unix control socketpair end"
        ),
    );
    drop(server);
    let _ = std::fs::remove_file(&policy);
}

// ============================================================
// F2b.3: instance wiring — SandboxInstance built from the policy,
// workload launched, instance-level verbs served (both transports)
// ============================================================

/// fd transport, full instance verbs: config / run / stats / ports / exec
/// skeleton / shutdown against a live SandboxInstance whose workload writes
/// an evidence file before parking.
#[test]
fn test_supervise_fd_serve_launches_instance_and_serves_instance_verbs() {
    isolate_ctl_root();
    let workdir = repo_tmp_dir().join(format!("supervise-fd-verbs-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).expect("create fd-verbs workdir");
    let evidence = workdir.join("evidence.txt");
    let policy = write_policy(
        "fd-instance-verbs",
        &instance_policy(workdir.to_str().expect("workdir utf8")),
    );
    let script = format!(
        "printf 'hello-from-workload\\n' > {} && exec sleep 30",
        evidence.display()
    );
    let program = write_policy(
        "fd-instance-program",
        &serde_json::json!({ "argv": ["/bin/sh", "-c", script] }).to_string(),
    );

    let (child, mut worker, _control_inode) =
        spawn_serve_supervisor_with_program(&policy, &program, &[]);

    // config: policy snapshot served against the live generation.
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "config", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "config: {resp:?}");

    // run: launch-first already launched the workload; the verb is an
    // idempotent state query with the instance pid.
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "run", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "run: {resp:?}");
    assert_eq!(
        resp["data"]["launched"],
        serde_json::Value::Bool(true),
        "run must report the launched instance: {resp:?}"
    );
    let pid = resp["data"]["pid"].as_i64().expect("run reports a pid");

    // stats: live instance, M0 child running, reconciler quiescent. The
    // pidfd-watcher registration settles a moment after launch, so poll the
    // verb until the exact live snapshot holds (assertions stay exact).
    let stats_deadline = Instant::now() + Duration::from_secs(15);
    let mut settled = false;
    while Instant::now() < stats_deadline {
        let resp = roundtrip_frame(
            &mut worker,
            &serde_json::json!({ "v": 1, "verb": "stats", "args": {} }),
        );
        assert_eq!(resp["ok"], serde_json::Value::Bool(true), "stats: {resp:?}");
        if resp["data"]["instance_state"] == "Live"
            && resp["data"]["children_live"] == 1
            && resp["data"]["proc_count_vs_live"] == 0
            && resp["data"]["pid"].as_i64() == Some(pid)
        {
            settled = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        settled,
        "stats must settle to the live reconciled snapshot (Live, one live \
         child, drift 0, pid {pid})"
    );

    // ports: no inbound mapping configured; empty but live-shaped response.
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "ports", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "ports: {resp:?}");
    assert_eq!(resp["data"]["launched"], serde_json::Value::Bool(true));
    assert_eq!(resp["data"]["inbound"], serde_json::json!([]));

    // exec (F3.2): the worker's stdio fds arrive over SCM_RIGHTS; supervise
    // registers a second child and reports its child id.
    let (host_stdin, host_stdout, host_stderr, child_ends) = make_exec_stdio();
    let resp = roundtrip_frame_with_fds(
        &mut worker,
        &serde_json::json!({
            "v": 1,
            "verb": "exec",
            "args": { "argv": ["/bin/sh", "-c", "printf hello-from-exec"] },
        }),
        &child_ends,
    );
    for fd in child_ends {
        unsafe {
            libc::close(fd);
        }
    }
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "exec: {resp:?}");
    let exec_pid = resp["data"]["pid"].as_i64().expect("exec reports a pid");
    let child_id = resp["data"]["child_id"].as_u64().expect("exec child id");
    assert!(
        process_alive(exec_pid as i32),
        "the exec'd child must be running right after exec"
    );

    // wait_child: exit routing through the generation's instance registry.
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({
            "v": 1,
            "verb": "wait_child",
            "args": { "child_id": child_id },
        }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "wait_child: {resp:?}");
    assert_eq!(resp["data"]["code"], 0, "exec child must exit 0: {resp:?}");
    assert_eq!(resp["data"]["killed"], serde_json::Value::Bool(false));

    // The worker's stdout pipe carries exactly the child's payload.
    let mut out = Vec::new();
    std::io::Read::read_to_end(
        &mut std::fs::File::from(host_stdout),
        &mut out,
    )
    .expect("read exec stdout");
    assert_eq!(out, b"hello-from-exec");
    drop(host_stdin);
    drop(host_stderr);

    // F4.1 over the fd transport: per-exec params travel in the exec frame
    // args and are applied at execve (cwd + clean_env + env through the
    // generation's instance).
    let (host_stdin2, host_stdout2, host_stderr2, child_ends2) = make_exec_stdio();
    let resp = roundtrip_frame_with_fds(
        &mut worker,
        &serde_json::json!({
            "v": 1,
            "verb": "exec",
            "args": {
                "argv": ["/usr/bin/env"],
                "cwd": workdir.to_str().expect("workdir utf8"),
                "clean_env": true,
                "env": { "F4_SUPERVISE": "zeta" },
            },
        }),
        &child_ends2,
    );
    for fd in child_ends2 {
        unsafe {
            libc::close(fd);
        }
    }
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "exec params: {resp:?}");
    let params_child_id = resp["data"]["child_id"].as_u64().expect("params child id");
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({
            "v": 1,
            "verb": "wait_child",
            "args": { "child_id": params_child_id },
        }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "wait params child: {resp:?}");
    assert_eq!(resp["data"]["code"], 0, "params child must exit 0: {resp:?}");
    let mut params_out = Vec::new();
    std::io::Read::read_to_end(
        &mut std::fs::File::from(host_stdout2),
        &mut params_out,
    )
    .expect("read params exec stdout");
    assert_eq!(
        params_out,
        b"F4_SUPERVISE=zeta\n",
        "per-exec cwd/env/clean_env must reach the cross-process child"
    );
    drop(host_stdin2);
    drop(host_stderr2);

    // S9 over the fd transport: a wider-than-ceiling grant is refused by the
    // same host-side validation as the in-process exec surface.
    let (_h0, _h1, _h2, child_ends3) = make_exec_stdio();
    let resp = roundtrip_frame_with_fds(
        &mut worker,
        &serde_json::json!({
            "v": 1,
            "verb": "exec",
            "args": {
                "argv": ["true"],
                "bind_ports": [65000],
            },
        }),
        &child_ends3,
    );
    for fd in child_ends3 {
        unsafe {
            libc::close(fd);
        }
    }
    assert_eq!(resp["ok"], serde_json::Value::Bool(false), "wide exec must fail: {resp:?}");
    assert_eq!(
        resp["err"].as_str(),
        Some(
            "instance exec failed: process error: exec params exceed the instance policy ceiling: bind_ports 65000 is outside the allowed set (EPERM)"
        ),
        "cross-process S9 refusal must be pinned in full: {resp:?}"
    );
    // F19/SL-13: the same refusal is machine-readable -- a *Live* session
    // refusing a wider-than-ceiling grant is `policy_denied`, never a
    // generation-gone code (the worker must not rebuild on it).
    assert_eq!(
        resp["code"].as_str(),
        Some("policy_denied"),
        "the S9 ceiling refusal must carry the policy_denied code: {resp:?}"
    );

    // update_network verb (F4.3): the main workload (child id 0) is still
    // running under the pre-update policy, so the verb reports it stale;
    // the update itself applies to new execs only.
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({
            "v": 1,
            "verb": "update_network",
            "args": { "ips": ["127.0.0.1"] },
        }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "update_network: {resp:?}");
    assert_eq!(
        resp["data"]["stale_child_ids"],
        serde_json::json!([0]),
        "the running main child must be the stale pre-update child: {resp:?}"
    );

    // The workload really ran and wrote its evidence.
    wait_until(
        Instant::now() + Duration::from_secs(15),
        "workload evidence file",
        || {
            std::fs::read_to_string(&evidence)
                .map(|s| s == "hello-from-workload\n")
                .unwrap_or(false)
        },
    );

    // shutdown: instance teardown, clean exit 0.
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "shutdown", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "shutdown: {resp:?}");
    let out = child.wait_with_output().expect("wait supervise fd verbs");
    assert!(
        out.status.success(),
        "generation must exit 0 after shutdown; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The workload process must not survive its generation.
    wait_until(
        Instant::now() + Duration::from_secs(10),
        "workload process reap",
        || !process_alive(pid as i32),
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
    let _ = std::fs::remove_dir_all(&workdir);
}

// ---------------------------------------------------------------------------
// N25: pushed append accounting and the live per-file tightening.
// ---------------------------------------------------------------------------

/// Spawn a serving supervisor that also holds the one-way events descriptor,
/// returning the child, the control end, and the events end the test reads.
fn spawn_serve_supervisor_with_events(
    policy: &PathBuf,
    program: &PathBuf,
    extra_args: &[&str],
) -> (
    std::process::Child,
    std::os::unix::net::UnixStream,
    std::os::unix::net::UnixStream,
) {
    use std::os::unix::process::CommandExt;

    let (worker, server) = std::os::unix::net::UnixStream::pair().expect("control socketpair");
    let (events_reader, events_writer) =
        std::os::unix::net::UnixStream::pair().expect("events socketpair");
    let control_fd = server.as_raw_fd();
    let events_fd = events_writer.as_raw_fd();
    let mut cmd = Command::new(bin());
    cmd.arg("--policy")
        .arg(policy.to_str().unwrap())
        .arg("--uid")
        .arg(euid().to_string())
        .arg("--control-fd")
        .arg(control_fd.to_string())
        .arg("--events-fd")
        .arg(events_fd.to_string())
        .arg("--program")
        .arg(program.to_str().unwrap())
        .arg("--serve")
        .args(extra_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    unsafe {
        cmd.pre_exec(move || {
            for fd in [control_fd, events_fd] {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn serve supervise with events");
    drop(server);
    drop(events_writer);
    (child, worker, events_reader)
}

/// Read NDJSON events for `window`, summing the `append` payloads.
///
/// The reader is non-blocking because the publisher only writes when
/// something grew: "no events" is a legitimate state to observe for a while,
/// not a read that should block the test.
fn sum_appended_events(events: &std::os::unix::net::UnixStream, window: Duration) -> (u64, usize) {
    use std::io::Read;
    events
        .set_nonblocking(true)
        .expect("events reader non-blocking");
    let deadline = Instant::now() + window;
    let mut total = 0u64;
    let mut count = 0usize;
    let mut greeted = 0usize;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut peek = events;
    while Instant::now() < deadline {
        match peek.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => panic!("reading events: {e}"),
        }
        while let Some(pos) = buffer.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buffer.drain(..=pos).collect();
            let text = String::from_utf8_lossy(&line[..line.len() - 1]).to_string();
            if text.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("event line is not JSON ({e}): {text}"));
            assert_eq!(value["v"], 1, "event protocol version: {value}");
            match value["event"].as_str() {
                // The greeting proves the channel is wired before any write;
                // it is the one event that is not about bytes.
                Some("hello") => greeted += 1,
                Some("append") => {
                    let bytes = value["bytes"].as_u64().expect("event carries bytes");
                    if bytes > 0 {
                        total += bytes;
                        count += 1;
                    }
                }
                other => panic!("unexpected event kind {other:?} in {value}"),
            }
        }
    }
    assert_eq!(greeted, 1, "the channel greets exactly once");
    (total, count)
}

/// A policy with a file-size ceiling: the ceiling is what installs the
/// ignored `SIGXFSZ` that makes a past-the-limit write fail with EFBIG, so a
/// generation that will be tightened has to start with one.
fn instance_policy_with_file_size(evidence_dir: &str, ceiling: &str) -> String {
    let mut readable = base_read_paths();
    readable.push(evidence_dir.to_string());
    serde_json::json!({
        "fs_readable": readable,
        "fs_writable": [evidence_dir],
        "max_file_size": ceiling,
    })
    .to_string()
}

/// The same policy, in the **chroot** shape (`chroot: "/"`, so virtual paths
/// and host paths are the same string but the path handlers are live).
///
/// The append watch is fed by the `openat` handler, which only exists in the
/// chroot shape -- the pure (Landlock-only) shape never traps a path syscall,
/// so there is nothing to record a descriptor from. That is the same
/// structural difference the dirty-directory ledger has.
///
/// `writable` is a *root* the shape can actually reach: the chroot shape
/// mediates paths itself, and a nested directory whose ancestors are not in
/// the readable set is not reachable through them (measured: the same
/// workload that writes happily to `/tmp` writes nothing at all under a
/// deeply nested repo path, with its diagnostics going to the M0 child's
/// `/dev/null`). `/tmp` keeps the test independent of where the repo lives.
fn instance_policy_chrooted(writable: &str) -> String {
    let mut readable = base_read_paths();
    readable.push(writable.to_string());
    serde_json::json!({
        "chroot": "/",
        "fs_readable": readable,
        "fs_writable": [writable],
    })
    .to_string()
}

/// The chroot shape **with** a file-size ceiling: the deployment's shape.
///
/// The two matter together, for different reasons: `chroot` is what makes the
/// mediator trap `openat` (and therefore see the descriptors a writer holds),
/// and the ceiling is what installs the ignored `SIGXFSZ` that turns a
/// past-the-limit write into `EFBIG` instead of a killed process.
fn instance_policy_chrooted_with_file_size(writable: &str, ceiling: &str) -> String {
    let mut readable = base_read_paths();
    readable.push(writable.to_string());
    serde_json::json!({
        "chroot": "/",
        "fs_readable": readable,
        "fs_writable": [writable],
        "max_file_size": ceiling,
    })
    .to_string()
}

/// The chroot shape **with a pid namespace**: the deployment's shape.
///
/// It is what the append watch is sensitive to, and the reason this fixture
/// exists. A `pid_ns` sandbox's notifications carry pids in the sandbox's
/// *own* namespace -- a task the supervisor can read as host pid 121 arrives
/// as `7` -- so a watch that registers the notification pid verbatim opens a
/// path that names a different process, or nothing. Measured on the cluster
/// that is exactly what happened: `watching: 0` for 1515 consecutive ticks
/// while a writer was busy, no pushed appends, and a 1024 MiB budget exceeded
/// by 124 MiB. Without this fixture the whole unit suite passes while the
/// feature is dead in production.
fn instance_policy_chrooted_pid_ns(writable: &str) -> String {
    let mut readable = base_read_paths();
    readable.push(writable.to_string());
    serde_json::json!({
        "chroot": "/",
        "fs_readable": readable,
        "fs_writable": [writable],
        "pid_ns": true,
    })
    .to_string()
}

/// The same, **plus the single-entry user namespace route B always has**: the
/// real shape.
///
/// Naming the slot's own `uid`/`gid` in the policy is what makes the sandbox
/// run in a user namespace that maps the guest's uid 0 onto that host uid --
/// route B launches the slot as the leased uid (`--uid 10003`) and passes the
/// same uid here. That is the difference this fixture exists to pin, and it is
/// not cosmetic: measured on the cluster the push channel was dead for its
/// whole life in exactly this shape, while a hand-launched slot *without* it
/// (the probe's `setpriv` shape) pushed events fine. The leader is
/// mid-transition when the mediator first reads its PID-namespace identity,
/// and a refused read there used to leave an empty map -- which silently hides
/// every numeric entry from the sandbox's own `/proc` (measured: `/proc/self`
/// does not even exist) and leaves the append watch unable to translate a
/// single notification.
/// The chroot shape with **a pid namespace and a file-size ceiling**: what the
/// deployment runs, for the live tightening.
///
/// The ceiling is what installs the ignored `SIGXFSZ` (a write past the limit
/// is `EFBIG`, not a death), and the pid namespace is what makes the
/// notification pid something the mediator has to translate before it can read
/// the descriptor -- so this is the fixture under which "the bytes a file has
/// already written" has to survive that translation.
fn instance_policy_chrooted_pid_ns_with_file_size(writable: &str, ceiling: &str) -> String {
    let mut readable = base_read_paths();
    readable.push(writable.to_string());
    serde_json::json!({
        "chroot": "/",
        "fs_readable": readable,
        "fs_writable": [writable],
        "max_file_size": ceiling,
        "pid_ns": true,
    })
    .to_string()
}

fn instance_policy_chrooted_pid_ns_self_userns(writable: &str, uid: u32) -> String {
    let mut readable = base_read_paths();
    readable.push(writable.to_string());
    serde_json::json!({
        "chroot": "/",
        "fs_readable": readable,
        "fs_writable": [writable],
        "pid_ns": true,
        "uid": uid,
        "gid": uid,
    })
    .to_string()
}

#[test]
fn test_dirty_dirs_reports_the_directory_a_write_landed_in() {
    // The written-directory ledger is what keeps the disk accounting from
    // re-walking a whole tree, and this is its end-to-end shape over the
    // control channel: a workload writes into a directory, the worker asks,
    // and the answer names that directory (the parent of what was written).
    isolate_ctl_root();
    let workdir =
        std::path::PathBuf::from(format!("/tmp/sandlock-dirty-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).expect("create dirty workdir");
    let policy = write_policy("dirty-verb", &instance_policy_chrooted("/tmp"));
    let script = format!(
        "mkdir -p {0}/sub && printf hi > {0}/sub/blob.bin && exec sleep 30",
        workdir.display()
    );
    let program = write_policy(
        "dirty-verb-program",
        &serde_json::json!({ "argv": ["/bin/sh", "-c", script] }).to_string(),
    );
    let (child, mut worker, _events) =
        spawn_serve_supervisor_with_events(&policy, &program, &[]);

    let written = workdir.join("sub").join("blob.bin");
    let deadline = Instant::now() + Duration::from_secs(10);
    wait_until(deadline, "the workload to write its file", || written.exists());

    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "dirty_dirs", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "dirty_dirs: {resp:?}");
    let dirs: Vec<String> = resp["data"]["dirs"]
        .as_array()
        .expect("dirs array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    let sub = workdir.join("sub").to_string_lossy().into_owned();
    assert!(
        dirs.contains(&sub),
        "the directory the file landed in must be reported; got {dirs:?}"
    );
    assert_eq!(resp["data"]["overflow"], serde_json::Value::Bool(false));

    // Draining is a take: the second answer must not repeat what the first
    // already reported (the consumer re-walks what it is told, once).
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "dirty_dirs", "args": {} }),
    );
    let again: Vec<String> = resp["data"]["dirs"]
        .as_array()
        .expect("dirs array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        !again.contains(&sub),
        "a drain is a take; the second drain repeated {sub}: {again:?}"
    );

    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "shutdown", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "shutdown: {resp:?}");
    let _ = child.wait_with_output();
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
    let _ = std::fs::remove_dir_all(&workdir);
}

#[test]
fn test_events_fd_reports_a_running_writers_growth() {
    isolate_ctl_root();
    let workdir =
        std::path::PathBuf::from(format!("/tmp/sandlock-events-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).expect("create events workdir");
    let blob = workdir.join("blob.bin");
    let policy = write_policy(
        "events-append",
        // `pid_ns` + the user namespace on purpose: this is the test that has
        // to fail when the watch is handed namespace pids it cannot read, or
        // when the PID-namespace identity is lost to a refused read while the
        // leader starts (see the fixtures).
        &instance_policy_chrooted_pid_ns_self_userns("/tmp", euid()),
    );
    // One descriptor, held open across eight 1 MiB appends 150 ms apart:
    // the shape this signal exists for (a writer filling a file), and one
    // where the count must be exact rather than merely non-zero.
    //
    // The other shape -- a new `dd` per file, each living a few ms -- is
    // deliberately *not* what this asserts on: a descriptor that opens,
    // writes and closes inside one sampling interval is not observed, and
    // that is by design (the bytes still reach the accounting through the
    // filesystem walk, just later). See `docs/k8s-deployment.md` §22.5.
    let script = format!(
        "exec 3>>{}; i=0; while [ $i -lt 8 ]; do \
         dd if=/dev/zero bs=1M count=1 status=none >&3; \
         i=$((i+1)); sleep 0.15; done; exec sleep 30",
        blob.display()
    );
    let program = write_policy(
        "events-program",
        &serde_json::json!({ "argv": ["/bin/sh", "-c", script] }).to_string(),
    );

    let (child, mut worker, events) =
        spawn_serve_supervisor_with_events(&policy, &program, &[]);

    let (appended, events_seen) = sum_appended_events(&events, Duration::from_secs(10));
    let written = std::fs::metadata(&blob).map(|m| m.len()).unwrap_or(0);
    assert_eq!(
        written,
        8 * 1024 * 1024,
        "the workload must have written exactly 8 MiB before the assertions"
    );
    assert!(
        events_seen > 0,
        "the slot must push at least one append event for a writer"
    );
    assert_eq!(
        appended, written,
        "a single descriptor held open across the whole write must account for \
         exactly the bytes appended"
    );

    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "shutdown", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "shutdown: {resp:?}");
    let out = child.wait_with_output().expect("wait events supervise");
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
    let _ = std::fs::remove_dir_all(&workdir);
    assert!(
        out.status.success(),
        "the generation must end cleanly; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}


/// Print whatever the slot has written to stderr so far (test diagnostics).
///
/// The slot's stderr is a pipe nobody reads until the process ends, and a
/// panicking test never gets there -- so a failing assertion would otherwise
/// hide the one line that explains it.
fn dump_child_stderr(child: &mut std::process::Child) {
    use std::io::Read;
    let Some(err) = child.stderr.as_mut() else {
        return;
    };
    let fd = err.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let mut buf = vec![0u8; 65536];
    if let Ok(n) = err.read(&mut buf) {
        eprintln!("slot stderr so far:\n{}", String::from_utf8_lossy(&buf[..n]));
    }
}

#[test]
fn test_a_tightening_does_not_cut_off_the_file_that_caused_it() {
    // The number the worker sends is "what is left of the *tree* budget", and
    // the bytes a file has already written are part of the usage that number
    // came from. Applying it as-is would let a file eat its own tail: a legal
    // 900 MiB file in a 1 GiB budget gets refused at 324 MiB the moment the
    // tree's remaining falls to 324. What the limit has to mean is "this file
    // may keep growing until the tree reaches its budget", which is
    // `sent + what this descriptor has grown by`.
    isolate_ctl_root();
    let workdir = std::path::PathBuf::from(format!(
        "/tmp/sandlock-tail-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&workdir).expect("create tail workdir");
    let blob = workdir.join("tail.bin");
    let policy = write_policy(
        "tail-limit",
        // The deployment's shape: the ceiling *and* the pid namespace. Without
        // the namespace the watch key is already the host pid, so the
        // translation this exercises is a no-op and the bug is invisible.
        &instance_policy_chrooted_pid_ns_with_file_size("/tmp", "512M"),
    );
    let script = format!(
        "exec 3>>{}; i=0; while [ $i -lt 400 ]; do          dd if=/dev/zero bs=1M count=1 status=none >&3;          i=$((i+1)); sleep 0.06; done",
        blob.display()
    );
    let program = write_policy(
        "tail-program",
        &serde_json::json!({ "argv": ["/bin/sh", "-c", script] }).to_string(),
    );
    let (mut child, mut worker, _events) =
        spawn_serve_supervisor_with_events(&policy, &program, &[]);

    let grown_to = |bytes: u64| {
        std::fs::metadata(&blob).map(|m| m.len() >= bytes).unwrap_or(false)
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    wait_until(deadline, "the writer to reach 8 MiB", || grown_to(8 * 1024 * 1024));
    let before = std::fs::metadata(&blob).map(|m| m.len()).unwrap_or(0);
    assert!(before >= 8 * 1024 * 1024, "sanity: the file is at {before}");

    // "Only 6 MiB of tree budget left" -- far less than the file already is.
    let limit = 6 * 1024 * 1024u64;
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({
            "v": 1,
            "verb": "update_file_size_limit",
            "args": { "bytes": limit },
        }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "tighten: {resp:?}");
    assert_eq!(resp["data"]["applied_bytes"], limit, "{resp:?}");

    std::thread::sleep(Duration::from_millis(1500));
    dump_child_stderr(&mut child);
    let after = std::fs::metadata(&blob).map(|m| m.len()).unwrap_or(0);
    assert!(
        after > before,
        "the file that caused the drop must not be frozen where it stands \
         ({before} -> {after})"
    );
    assert!(
        after <= before + limit + 4 * 1024 * 1024,
        "the remaining budget bounds it: {before} + {limit} (+ slack) >= {after}"
    );

    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "shutdown", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "shutdown: {resp:?}");
    let _ = child.wait_with_output();
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
    let _ = std::fs::remove_dir_all(&workdir);
}

#[test]
fn test_update_file_size_limit_stops_a_running_writer() {
    isolate_ctl_root();
    let workdir = repo_tmp_dir().join(format!("supervise-tighten-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).expect("create tighten workdir");
    let blob = workdir.join("grow.bin");
    // The ceiling is far above what the test tightens to; it exists so the
    // sandbox runs with SIGXFSZ ignored (EFBIG, not death).
    let policy = write_policy(
        "tighten-limit",
        &instance_policy_with_file_size(workdir.to_str().expect("workdir utf8"), "256M"),
    );
    // A shell loop that appends 1 MiB every 50 ms: the shape the per-exec
    // ceiling cannot stop once it is under way, because the limit was fixed
    // at exec time and the loop keeps opening new files.
    let script = format!(
        "i=0; while [ $i -lt 400 ]; do \
         dd if=/dev/zero of={} bs=1M count=1 seek=$i conv=notrunc status=none || exit 7; \
         i=$((i+1)); sleep 0.05; done",
        blob.display()
    );
    let program = write_policy(
        "tighten-program",
        &serde_json::json!({ "argv": ["/bin/sh", "-c", script] }).to_string(),
    );

    let (child, mut worker, _events) =
        spawn_serve_supervisor_with_events(&policy, &program, &[]);

    // Wait until the writer is under way, then tighten well below where it
    // would have got to on its own.
    let grew = Instant::now() + Duration::from_secs(15);
    wait_until(grew, "the workload to start writing", || {
        std::fs::metadata(&blob).map(|m| m.len() >= 2 * 1024 * 1024).unwrap_or(false)
    });
    let before = std::fs::metadata(&blob).map(|m| m.len()).unwrap_or(0);
    let limit = 6 * 1024 * 1024u64;

    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({
            "v": 1,
            "verb": "update_file_size_limit",
            "args": { "bytes": limit },
        }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "tighten: {resp:?}");
    assert_eq!(resp["data"]["applied_bytes"], limit, "{resp:?}");
    assert!(
        resp["data"]["tightened"].as_u64().unwrap_or(0) >= 1,
        "the running group must have been tightened: {resp:?}"
    );

    // The loop must now fail (EFBIG at `limit`) rather than reach 400 MiB:
    // wait for the size to stop moving, which is what "the writer can no
    // longer grow this file" looks like from the outside.
    let stopped = Instant::now() + Duration::from_secs(20);
    let mut last = std::fs::metadata(&blob).map(|m| m.len()).unwrap_or(0);
    let after = loop {
        std::thread::sleep(Duration::from_millis(400));
        let now = std::fs::metadata(&blob).map(|m| m.len()).unwrap_or(0);
        if now == last {
            break now;
        }
        last = now;
        assert!(
            Instant::now() < stopped,
            "the tightened writer never stopped; it reached {now} bytes"
        );
    };
    assert!(
        after > before,
        "the writer had to make some progress after the tightening ({before} -> {after})"
    );
    assert!(
        after <= limit + 1024 * 1024,
        "the file must stop at the tightened limit ({limit}): it reached {after}"
    );

    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "shutdown", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "shutdown: {resp:?}");
    let out = child.wait_with_output().expect("wait tighten supervise");
    assert!(
        out.status.success(),
        "the generation must end cleanly; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
    let _ = std::fs::remove_dir_all(&workdir);
}

/// `st_ino` of an open descriptor.  For a unix socket that is the socket
/// inode, which is what `/proc/<pid>/fd` reports as `socket:[<ino>]`; the
/// fd-table comparison in the SL-11 case below reads it from the handed-over
/// end (an inherited copy is a dup of that same socket, so it shares the
/// inode).  The two *ends* of a `socketpair()` are distinct sockets and do
/// **not** share an inode — see the case's comment.
fn socket_inode(fd: std::os::unix::io::RawFd) -> u64 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::fstat(fd, &mut st) },
        0,
        "fstat: {}",
        std::io::Error::last_os_error()
    );
    st.st_ino as u64
}

/// Descriptor names under `/proc/<pid>/fd` whose symlink target is exactly
/// `socket:[<inode>]`, sorted.  A descriptor that closes between `read_dir`
/// and `read_link` (or that the caller may not stat) is skipped: only
/// surviving matches are reported, and the caller decides whether the result
/// must be empty or non-empty.
fn fd_table_socket_fds(pid: i32, inode: u64) -> Vec<String> {
    let dir = PathBuf::from(format!("/proc/{pid}/fd"));
    let want = format!("socket:[{inode}]");
    let mut found = Vec::new();
    for entry in
        std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
    {
        let entry = entry.expect("fd entry");
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        if target.to_string_lossy().into_owned() == want {
            found.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    found.sort();
    found
}

/// Read the octal `flags:` line of `/proc/<pid>/fdinfo/<fd>` (the file-status
/// flags, where `O_CLOEXEC` is bit `02000000`) and assert the descriptor
/// carries `O_CLOEXEC`.
fn assert_fd_is_cloexec(pid: i32, fd_name: &str) {
    let path = PathBuf::from(format!("/proc/{pid}/fdinfo/{fd_name}"));
    let info = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let flags_line = info
        .lines()
        .find(|line| line.starts_with("flags:"))
        .unwrap_or_else(|| panic!("{} must have a flags: line; got {info:?}", path.display()));
    let flags = u32::from_str_radix(flags_line["flags:".len()..].trim(), 8)
        .unwrap_or_else(|e| panic!("{} flags must be octal: {e}; got {flags_line:?}", path.display()));
    assert_ne!(
        flags & libc::O_CLOEXEC as u32,
        0,
        "{} must carry O_CLOEXEC (02000000); got {flags:o}",
        path.display()
    );
}

/// Kill-on-drop guard for a spawned `sandlock-supervise`: the SL-11 case
/// below asserts *before* the normal `wait_with_output`, so a panicking assert
/// would otherwise leave the slot (and its `sleep 30` workload) alive for the
/// rest of the suite. `disarm()` hands the child back to the normal reaping
/// path.
struct SuperviseChild(Option<std::process::Child>);

impl SuperviseChild {
    fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().expect("supervise child armed").id()
    }

    fn disarm(mut self) -> std::process::Child {
        self.0.take().expect("supervise child armed")
    }
}

impl Drop for SuperviseChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// SL-11 guard: the supervisor's own control endpoint must not be reachable
/// from the confined tree.
///
/// `--control-fd` only arrives exec-inheritable, i.e. the launcher had to
/// clear `FD_CLOEXEC` on it; `serve::serve_control_fd` re-sets the flag on its
/// own copy before anything is launched.  The property can be checked exactly
/// by reading the socket inode: an inherited copy is a dup of that very
/// socket, so it appears as the same `socket:[<ino>]` in the confined fd
/// table.  Note the inode has to come from the *handed-over* end
/// (`spawn_serve_supervisor_with_program` returns it) — the two ends of a
/// `socketpair()` are distinct sockets with different inodes, so comparing
/// the test's own (client) end would silently match nothing and make the case
/// vacuous.
///
/// This is a *guard*, not a bug reproduction.  Measured (2026-09-09): core
/// already hands `sandlock-init` an explicit fd set, so the confined tree was
/// observably clean with and without the restore -- which is exactly why the
/// `fdinfo` half matters: it pins the `F_SETFD` call itself, while the
/// `/proc/<pid>/fd` half pins the invariant and will bite if a future change
/// to that hand-off set puts the control endpoint into a confined process
/// (reading frames addressed to the worker, including the SCM_RIGHTS stdio
/// ends, and pinning the connection open past a dead worker -- the SL-4
/// family).  The supervisor-side half is also what keeps the negative half
/// honest: an empty confined scan is only meaningful once the same scan has
/// located the endpoint on the supervisor.
#[test]
fn test_supervise_control_fd_stays_out_of_the_confined_tree() {
    isolate_ctl_root();
    let workdir = repo_tmp_dir().join(format!("supervise-fd-no-leak-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).expect("create fd-no-leak workdir");
    let policy = write_policy(
        "fd-no-leak",
        &instance_policy(workdir.to_str().expect("workdir utf8")),
    );
    let program = write_policy(
        "fd-no-leak-program",
        &serde_json::json!({ "argv": ["/bin/sh", "-c", "exec sleep 30"] }).to_string(),
    );

    let (child, mut worker, control_inode) =
        spawn_serve_supervisor_with_program(&policy, &program, &[]);
    let child = SuperviseChild::new(child);

    // The slot answers `stats` with the confined init's pid once the
    // launch-first instance is Live; that fd table is the thing under test.
    let deadline = Instant::now() + Duration::from_secs(15);
    let pid = loop {
        let resp = roundtrip_frame(
            &mut worker,
            &serde_json::json!({ "v": 1, "verb": "stats", "args": {} }),
        );
        assert_eq!(resp["ok"], serde_json::Value::Bool(true), "stats: {resp:?}");
        if resp["data"]["instance_state"] == "Live" {
            break resp["data"]["pid"]
                .as_i64()
                .expect("the Live instance reports its pid") as i32;
        }
        assert!(
            Instant::now() < deadline,
            "the launch-first instance must reach Live; last stats: {resp:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(process_alive(pid), "the confined init (pid {pid}) must be running");

    // Positive control: the same scan finds the control socket in the
    // supervisor's own fd table, and the supervisor's copy carries
    // `O_CLOEXEC` (the `serve_control_fd` restore).  Without this half an
    // empty confined result could be a vacuous read (wrong pid, unreadable
    // /proc, or an inode nothing ever compared).
    let slot_fds = fd_table_socket_fds(child.id() as i32, control_inode);
    assert!(
        !slot_fds.is_empty(),
        "the supervise slot itself must hold the control socket [inode {control_inode}]"
    );
    for fd_name in &slot_fds {
        assert_fd_is_cloexec(child.id() as i32, fd_name);
    }

    let confined_fds = fd_table_socket_fds(pid, control_inode);
    assert_eq!(
        confined_fds,
        Vec::<String>::new(),
        "the confined tree (pid {pid}) must not inherit the supervisor's control \
         socket [inode {control_inode}]; it was visible as fd(s) {confined_fds:?}"
    );

    // The guard must not have cost the generation its own channel: the same
    // session still serves verbs, and shutdown tears the workload down.
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "shutdown", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "shutdown: {resp:?}");
    let out = child
        .disarm()
        .wait_with_output()
        .expect("wait fd-no-leak supervise");
    assert!(
        out.status.success(),
        "generation must exit 0 after shutdown; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    wait_until(
        Instant::now() + Duration::from_secs(10),
        "confined workload reap",
        || !process_alive(pid),
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
    let _ = std::fs::remove_dir_all(&workdir);
}

/// Registered path (transport 2), full instance verbs: a refused connection
/// must not kill the slot, and the generation ends only via a shutdown verb
/// served to a token-authenticated worker.
#[test]
fn test_supervise_path_serve_launches_instance_and_serves_verbs_until_shutdown() {
    let ctl_root = isolate_ctl_root();
    let workdir = repo_tmp_dir().join(format!("supervise-path-verbs-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).expect("create path-verbs workdir");
    let evidence = workdir.join("evidence.txt");
    let policy = write_policy(
        "path-instance-verbs",
        &instance_policy(workdir.to_str().expect("workdir utf8")),
    );
    let script = format!(
        "printf 'hello-from-path-workload\\n' > {} && exec sleep 30",
        evidence.display()
    );
    let program = write_policy(
        "path-instance-program",
        &serde_json::json!({ "argv": ["/bin/sh", "-c", script] }).to_string(),
    );
    let name = format!("supervise-path-verbs-{}", std::process::id());
    let token = "path-verbs-token-0123456789abcdef";

    let mut cmd = Command::new(bin());
    cmd.args([
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        "--serve-path",
        &name,
        "--token",
        token,
        "--program",
        program.to_str().unwrap(),
    ])
    .env("SANDBOX_CTL_ROOT", &ctl_root)
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    let child = cmd.spawn().expect("spawn path supervise");

    // The worker computes the hashed socket path exactly like the slot
    // (registry root + fnv1a_hex(name) + ".d/control.sock").
    let registry = ctl_root.as_path().join(format!(
        "{}-registry",
        ctl_root.to_string_lossy().trim_end_matches('/')
    ));
    let sock_path = registry
        .join(format!("{}.d", sandlock_core::control::fnv1a_hex(&name)))
        .join("control.sock");
    wait_until(
        Instant::now() + Duration::from_secs(15),
        "registered socket to appear",
        || sock_path.exists(),
    );

    // A refused connection (wrong token) must NOT kill the slot: the next
    // valid worker is still served.  FUP-11a pins the refusal itself, and
    // FUP-11b pins that transport 2 carries the same remap-free verb surface
    // as the fd transport (an unknown `map-uid`-class verb is refused by
    // name, and the generation survives it).
    {
        let refused = registered_verb(&sock_path, "wrong-token", "config");
        assert_eq!(
            refused["ok"],
            serde_json::Value::Bool(false),
            "wrong-token connection must be refused: {refused:?}"
        );
        assert_eq!(
            refused["err"].as_str(),
            Some(CHANNEL_TOKEN_REFUSAL),
            "registered-path token refusal must be the exact shared refusal: {refused:?}"
        );
        let refused = registered_verb(&sock_path, token, "map-uid");
        assert_eq!(
            refused["ok"],
            serde_json::Value::Bool(false),
            "map-uid must be refused on the registered path too: {refused:?}"
        );
        assert_eq!(
            refused["err"].as_str(),
            Some("unknown verb: map-uid"),
            "no remap surface on transport 2: {refused:?}"
        );
    }

    // config / run / stats / ports through the registered path.
    let resp = registered_verb(&sock_path, token, "config");
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "config: {resp:?}");
    let resp = registered_verb(&sock_path, token, "run");
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "run: {resp:?}");
    assert_eq!(
        resp["data"]["launched"],
        serde_json::Value::Bool(true),
        "run: {resp:?}"
    );
    let pid = resp["data"]["pid"].as_i64().expect("path run pid");
    let stats_deadline = Instant::now() + Duration::from_secs(15);
    let mut settled = false;
    while Instant::now() < stats_deadline {
        let resp = registered_verb(&sock_path, token, "stats");
        assert_eq!(resp["ok"], serde_json::Value::Bool(true), "stats: {resp:?}");
        if resp["data"]["instance_state"] == "Live"
            && resp["data"]["children_live"] == 1
            // FUP-11e: same settle strength as the fd-transport sister case —
            // a reconciled snapshot must show zero accounting drift, not just
            // the live child count.
            && resp["data"]["proc_count_vs_live"] == 0
            && resp["data"]["pid"].as_i64() == Some(pid)
        {
            settled = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        settled,
        "path stats must settle to the live reconciled snapshot (Live, one live \
         child, zero accounting drift, pid {pid})"
    );
    let resp = registered_verb(&sock_path, token, "ports");
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "ports: {resp:?}");
    assert_eq!(resp["data"]["inbound"], serde_json::json!([]));

    wait_until(
        Instant::now() + Duration::from_secs(15),
        "path workload evidence file",
        || {
            std::fs::read_to_string(&evidence)
                .map(|s| s == "hello-from-path-workload\n")
                .unwrap_or(false)
        },
    );

    // exec over the registered path (F3.2): the child-side stdio ends arrive
    // on a dedicated connection; kill_child and wait_child use their own
    // connections afterwards (one request per connection).
    let (_host_stdin, _host_stdout, _host_stderr, child_ends) = make_exec_stdio();
    let resp = registered_exec(
        &sock_path,
        token,
        &["/bin/sh", "-c", "exec sleep 30"],
        &child_ends,
    );
    for fd in child_ends {
        unsafe {
            libc::close(fd);
        }
    }
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "path exec: {resp:?}");
    let exec_pid = resp["data"]["pid"].as_i64().expect("path exec pid");
    let child_id = resp["data"]["child_id"].as_u64().expect("path exec child id");
    assert!(
        process_alive(exec_pid as i32),
        "the path exec'd child must be running"
    );

    // kill_child: per-child signal by registered child id (never a pid
    // verb), then wait_child reports the Killed exit on its own connection.
    let resp = registered_verb(
        &sock_path,
        token,
        "kill_child",
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(false), "kill without args: {resp:?}");
    let resp = roundtrip_frame_with_fds(
        &mut std::os::unix::net::UnixStream::connect(&sock_path).expect("connect kill socket"),
        &serde_json::json!({
            "v": 1,
            "verb": "kill_child",
            "token": token,
            "args": { "child_id": child_id, "signum": 9 },
        }),
        &[],
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "path kill_child: {resp:?}");
    let resp = roundtrip_frame_with_fds(
        &mut std::os::unix::net::UnixStream::connect(&sock_path).expect("connect wait socket"),
        &serde_json::json!({
            "v": 1,
            "verb": "wait_child",
            "token": token,
            "args": { "child_id": child_id },
        }),
        &[],
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "path wait_child: {resp:?}");
    assert_eq!(
        resp["data"]["killed"],
        serde_json::Value::Bool(true),
        "kill_child must make wait_child report Killed: {resp:?}"
    );
    wait_until(
        Instant::now() + Duration::from_secs(10),
        "path exec'd child reap",
        || !process_alive(exec_pid as i32),
    );

    // shutdown ends the generation; the slot exits 0.
    let resp = registered_verb(&sock_path, token, "shutdown");
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "shutdown: {resp:?}");
    let out = child.wait_with_output().expect("wait path supervise");
    assert!(
        out.status.success(),
        "path generation must exit 0 after shutdown; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // FUP-11c: the refused wrong-token connection above is reported as the
    // slot's FIRST abnormal-end line (pinned verbatim by serve.rs's unit
    // test) with a running total of exactly 1 — the `unknown verb` refusal is
    // a Continue, so it is not counted, and no other connection ended
    // abnormally.  Before this change every such connection printed its own
    // line, so a worker retry loop could flood the slot's stderr.
    assert_stderr_line(
        &out,
        &sandlock_supervise::serve::registered_abnormal_end_line(1),
    );
    assert!(
        !sock_path.exists(),
        "the registered socket must be cleaned up on exit"
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
    let _ = std::fs::remove_dir_all(&workdir);
}

/// Reviewer I2 (supervise): when the generation's main process exits,
/// `sandlock-init` collapses the container and the instance reads `Exited`
/// through the stats verb; the worker then closing the channel is the
/// generation's *natural* end and must exit 0 (not the abnormal non-zero path
/// reserved for a vanished/refused peer). A main exit alone cannot end the
/// single-threaded serve loop while the worker keeps its end open — the
/// worker observes `Exited` via stats and closes, exactly the E2B flow.
#[test]
fn test_supervise_main_exit_ends_generation_cleanly() {
    isolate_ctl_root();
    let workdir = repo_tmp_dir().join(format!("supervise-main-exit-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).expect("create main-exit workdir");
    let policy = write_policy(
        "main-exit",
        &instance_policy(workdir.to_str().expect("workdir utf8")),
    );
    let program = write_policy(
        "main-exit-program",
        &serde_json::json!({ "argv": ["/bin/sh", "-c", "exit 0"] }).to_string(),
    );
    let (child, mut worker, _control_inode) =
        spawn_serve_supervisor_with_program(&policy, &program, &[]);

    // Poll stats until the instance reports the terminal Exited state (main
    // exit collapsed init; the serve loop stays responsive to worker verbs).
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut exited = false;
    while Instant::now() < deadline {
        let resp = roundtrip_frame(
            &mut worker,
            &serde_json::json!({ "v": 1, "verb": "stats", "args": {} }),
        );
        assert_eq!(resp["ok"], serde_json::Value::Bool(true), "stats: {resp:?}");
        if resp["data"]["instance_state"] == "Exited" {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(exited, "stats must report Exited after the main process exits");

    // The worker closing the channel after main exit is the natural end.
    drop(worker);
    let out = child.wait_with_output().expect("wait supervise main exit");
    assert!(
        out.status.success(),
        "a generation whose main exited must end cleanly; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
    let _ = std::fs::remove_dir_all(&workdir);
}

/// Route-B invariant pin (fork-plan F2b.3): the wire surface exposes NO
/// runtime mediator re-map verb.  The forbidden "give this generation a new
/// host uid" path must not exist under any name — a `map-uid`-class request
/// is refused as an unknown verb and the generation still ends cleanly.
#[test]
fn test_supervise_refuses_runtime_uid_map_verbs() {
    isolate_ctl_root();
    let policy = write_policy("no-uid-map", "{}");
    let (child, mut worker) = spawn_serve_supervisor(&policy, &[]);

    for verb in ["map-uid", "remap-mediator", "setuid-host"] {
        let resp = roundtrip_frame(
            &mut worker,
            &serde_json::json!({
                "v": 1, "verb": verb, "args": {"uid": 65533},
            }),
        );
        assert_eq!(
            resp["ok"],
            serde_json::Value::Bool(false),
            "{verb} must be refused: {resp:?}"
        );
        assert_eq!(
            resp["err"].as_str(),
            Some(format!("unknown verb: {verb}").as_str()),
            "{verb} must be refused as an unknown verb (no remap surface): {resp:?}"
        );
    }

    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "shutdown", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true));
    let out = child.wait_with_output().expect("wait no-uid-map supervise");
    assert!(
        out.status.success(),
        "generation must still end cleanly after refused verbs; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Unknown-verb refusals are ordinary responses on a live generation
    // (Continue), not abnormal ends: unlike a token refusal, they must leave
    // the slot's stderr empty (FUP-11c's counter stays at zero).
    assert!(
        out.stderr.is_empty(),
        "refused verbs must not be logged as abnormal ends, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&policy);
}

/// FUP-11b: `FORBIDDEN_RUNTIME_MEDIATOR_REMAP` must be a *tested* invariant,
/// not a greppable comment that can rot.  Pinned here: the exact wording of
/// the claim, and the CLI surface that proves it (no runtime uid re-map flag
/// of any kind — the only uid the binary takes is the exec-time `--uid`
/// self-check the constant names).  The wire half of the same claim lives in
/// `test_supervise_refuses_runtime_uid_map_verbs` (fd transport) and the
/// registered-path refusal in the path-verbs test.
#[test]
fn test_runtime_mediator_remap_invariant_is_pinned() {
    assert_eq!(
        sandlock_supervise::FORBIDDEN_RUNTIME_MEDIATOR_REMAP,
        "supervise never maps a live generation's mediator to a new host uid; \
         the mediator host uid is fixed at exec (--uid self-check) and the \
         sandbox's userns maps only the supervisor's own uid",
        "the constant IS the contract — reword it here and in \
         docs/supervise-identity-handoff.md together"
    );

    let out = spawn(&["--help"]);
    assert!(out.status.success(), "supervise --help must run");
    let help = String::from_utf8_lossy(&out.stdout);
    for forbidden in [
        "--map-uid",
        "--remap",
        "--setuid",
        "--host-uid",
        "--mediator-uid",
        "--run-as",
    ] {
        assert!(
            !help.contains(forbidden),
            "the CLI must expose no runtime re-map flag {forbidden}, got:\n{help}"
        );
    }
    assert!(
        help.contains("--uid <X>"),
        "the exec-time self-check must stay the only uid binding, got:\n{help}"
    );
}

/// FUP-11f: the F2b.1 validate-and-exit mode (no `--serve`, no
/// `--serve-path`) is still the launcher's pre-flight, and `--program`
/// participates in it — the document is parsed, the control descriptor is
/// validated, and NOTHING is launched.
#[test]
fn test_validate_exit_mode_parses_program_without_launching() {
    let workdir = repo_tmp_dir().join(format!("supervise-validate-exit-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).expect("create validate-exit workdir");
    let evidence = workdir.join("evidence.txt");
    let script = format!("printf 'launched\\n' > {} && exit 0", evidence.display());
    let program = write_policy(
        "validate-exit-program",
        &serde_json::json!({ "argv": ["/bin/sh", "-c", script] }).to_string(),
    );
    let policy = write_policy("validate-exit", "{}");

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
            "--program",
            program.to_str().unwrap(),
        ],
        control_fd,
    );
    drop(server);
    let out = child.wait_with_output().expect("wait validate-exit");
    assert!(
        out.status.success(),
        "a valid policy + program must pass the pre-flight; stderr: {}",
        stderr(&out)
    );
    assert!(
        out.stderr.is_empty(),
        "the pre-flight must stay silent, got: {}",
        stderr(&out)
    );
    assert!(
        !evidence.exists(),
        "validate-and-exit must never launch the workload"
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
    let _ = std::fs::remove_dir_all(&workdir);
}

/// FUP-11f: a rejected program document fails the pre-flight by name — the
/// same field-naming posture the serve modes have.
#[test]
fn test_validate_exit_mode_refuses_bad_program_by_name() {
    let program = write_policy("validate-exit-empty-argv", r#"{"argv": []}"#);
    let policy = write_policy("validate-exit-bad-program", "{}");
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        // Never probed: the program is refused before the fd check.
        "--control-fd",
        "2",
        "--program",
        program.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "an empty-argv program must fail");
    assert_stderr_line(
        &out,
        "sandlock-supervise: program rejected: program spec `argv` must be non-empty \
         (argv[0] is the executable)",
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
}

/// FUP-11f: an unreadable program document is a startup failure naming the
/// path and the OS error, not a silent "no workload" exit.
#[test]
fn test_validate_exit_mode_refuses_unreadable_program() {
    let missing = repo_tmp_dir().join("supervise-validate-exit-missing-program.json");
    let _ = std::fs::remove_file(&missing);
    let policy = write_policy("validate-exit-missing-program", "{}");
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        "--control-fd",
        "2",
        "--program",
        missing.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "a missing program file must fail");
    let enoent = std::io::Error::from_raw_os_error(libc::ENOENT);
    assert_stderr_line(
        &out,
        &format!(
            "sandlock-supervise: program read failed: read policy file {}: {enoent}",
            missing.display()
        ),
    );
    let _ = std::fs::remove_file(&policy);
}

/// Process-liveness probe used for post-shutdown residue assertions.
fn process_alive(pid: i32) -> bool {
    (unsafe { libc::kill(pid, 0) }) == 0
}

/// F19/SL-13: a refused verb carries a **stable code** beside its prose.
///
/// The generation is a container: when its M0 main exits, `sandlock-init`
/// collapses every group and the *slot keeps serving*, answering every later
/// verb with the unified closed-instance refusal. That refusal used to cross
/// the channel as prose alone, so the E2B worker had to ask the slot for
/// `stats` and reverse-infer "the generation is over ⇒ rebuild" from
/// `InstancePhase` (SL-12). Pinning the code here is what makes that
/// inference droppable: the worker can branch on `code` and never read the
/// sentence.
#[test]
fn test_supervise_refusal_carries_the_generation_closed_code() {
    isolate_ctl_root();
    let workdir = repo_tmp_dir().join(format!("supervise-closed-code-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).expect("create closed-code workdir");
    let policy = write_policy(
        "closed-code",
        &instance_policy(workdir.to_str().expect("workdir utf8")),
    );
    // A main that leaves at once: the container's natural end. The *slot*
    // is untouched by it -- that is the shape under test.
    let program = write_policy("closed-code-program", r#"{ "argv": ["/bin/true"] }"#);

    let (child, mut worker, _inode) =
        spawn_serve_supervisor_with_program(&policy, &program, &[]);

    // Wait for the collapse to be observable, and assert the phase is the
    // clean one (`Exited`), not `Dead`: the two forms must not be conflated
    // by the code they produce.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut state = String::new();
    while Instant::now() < deadline {
        let resp = roundtrip_frame(
            &mut worker,
            &serde_json::json!({ "v": 1, "verb": "stats", "args": {} }),
        );
        assert_eq!(resp["ok"], serde_json::Value::Bool(true), "stats: {resp:?}");
        state = resp["data"]["instance_state"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if state == "Exited" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        state, "Exited",
        "the killed-main generation must settle to the clean Exited phase"
    );

    // The refused verb, byte for byte what the worker has always received,
    // plus the code that says *why* without reading that sentence.
    let (_host_stdin, _host_stdout, _host_stderr, child_ends) = make_exec_stdio();
    let resp = roundtrip_frame_with_fds(
        &mut worker,
        &serde_json::json!({
            "v": 1,
            "verb": "exec",
            "args": { "argv": ["/bin/true"] },
        }),
        &child_ends,
    );
    for fd in child_ends {
        unsafe {
            libc::close(fd);
        }
    }
    assert_eq!(
        resp["ok"],
        serde_json::Value::Bool(false),
        "a collapsed generation must refuse the verb: {resp:?}"
    );
    assert_eq!(
        resp["err"].as_str(),
        Some(
            "instance exec failed: process error: instance is closed (shut down, or the init channel closed after the main-exit container end); no new work is accepted"
        ),
        "the closed refusal's prose must stay byte-identical: {resp:?}"
    );
    assert_eq!(
        resp["code"].as_str(),
        Some("generation_closed"),
        "the collapsed generation's refusal must carry generation_closed: {resp:?}"
    );

    // Every verb of that generation answers the same way -- the code is a
    // property of the generation, not of the `exec` handler.
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "wait_child", "args": { "child_id": 3 } }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(false), "{resp:?}");
    assert_eq!(resp["code"].as_str(), Some("generation_closed"), "{resp:?}");

    // A *Live* generation's refusal is a different code again: an unknown
    // verb is the generation refusing for its own reason, i.e. verb_refused.
    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "map-uid", "args": {} }),
    );
    assert_eq!(
        resp["err"].as_str(),
        Some("unknown verb: map-uid"),
        "{resp:?}"
    );
    assert_eq!(resp["code"].as_str(), Some("verb_refused"), "{resp:?}");

    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "shutdown", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "shutdown: {resp:?}");
    // A clean answer carries no code at all (the field is for refusals).
    assert_eq!(resp.get("code"), None, "an ok response must not carry a code: {resp:?}");
    let out = child.wait_with_output().expect("wait closed-code supervise");
    assert!(
        out.status.success(),
        "the generation must still end cleanly; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&program);
    let _ = std::fs::remove_dir_all(&workdir);
}
