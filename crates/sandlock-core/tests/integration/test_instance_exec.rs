//! F3.2 (M1) per-child exec tests for an exec-capable `SandboxInstance`.
//!
//! An exec-capable session is created with
//! [`SandboxInstance::launch_exec`]: the confined direct child is
//! `sandlock-init` (core::init::run_init) and every additional command is a
//! registered child (`exec`) with its own child id, stdio delivered over
//! SCM_RIGHTS to the init loop, and exit routing checked against the F1.2
//! announced registry. These tests pin the F3.2 acceptance matrix:
//!
//! * two concurrent exec children keep fully independent stdio;
//! * `wait_child(child_id)` is idempotent (a second wait returns the same
//!   exit status);
//! * closing a piped stdin does not deadlock the wait;
//! * `exec` after `shutdown` returns the same unified error every time
//!   (the F5.4 S5 closed-instance code, reserved here);
//! * §4.14: a child that exits while a grandchild still holds stdout does
//!   not hang `wait_child`, and shutdown collapses the retained group so the
//!   caller's pipe reaches EOF;
//! * the child registry rejects unknown child ids (F1.2 registration
//!   checking) and kill-after-reap is an idempotent no-op;
//! * a pty exec returns a host-side pty master and `resize_child` works.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sandlock_core::error::SandboxRuntimeError;
use sandlock_core::instance::{ChildId, ExecStdio, InstancePhase, SandboxInstance};
use sandlock_core::result::ExitStatus;
use sandlock_core::{Sandbox, SandlockError};

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

async fn launch_exec_session(name: &str) -> SandboxInstance {
    SandboxInstance::launch_exec(
        base_policy().build().unwrap().with_name(name),
        &["sh", "-c", "exec sleep 30"],
    )
    .await
    .expect("launch exec-capable session")
}

/// Read exactly `len` bytes from `fd` (blocking, on a blocking thread pool so
/// the multi-thread runtime keeps pumping the seccomp supervisor).
fn read_exact_bytes(fd: OwnedFd, len: usize) -> Vec<u8> {
    let mut file = std::fs::File::from(fd);
    let mut out = Vec::with_capacity(len);
    let mut chunk = [0u8; 4096];
    while out.len() < len {
        let want = (len - out.len()).min(chunk.len());
        let n = file.read(&mut chunk[..want]).expect("read child stdout");
        assert!(
            n > 0,
            "child stdout reached EOF before {} bytes were read",
            len
        );
        out.extend_from_slice(&chunk[..n]);
    }
    out
}

/// Try one nonblocking read; returns the bytes read, `None` when the read
/// would block (data or EOF not yet available).
fn try_read_nonblock(fd: &OwnedFd) -> Option<Vec<u8>> {
    let dup = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    assert!(dup >= 0, "dup stdout fd for nonblocking probe");
    let flags = unsafe { libc::fcntl(dup, libc::F_GETFL, 0) };
    assert!(flags >= 0, "get stdout fd flags");
    assert_eq!(unsafe { libc::fcntl(dup, libc::F_SETFL, flags | libc::O_NONBLOCK) }, 0);
    let mut file = unsafe { std::fs::File::from_raw_fd(dup) };
    let mut buf = [0u8; 64];
    match file.read(&mut buf) {
        Ok(0) => Some(Vec::new()),
        Ok(n) => Some(buf[..n].to_vec()),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(e) => panic!("nonblocking read failed: {e}"),
    }
}

async fn poll_until(mut cond: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// True when `pid` no longer exists or is a zombie (`/proc/<pid>/stat` state
/// `Z`): a process init collapsed but never reaped sits as a zombie until the
/// outer reaper collects it, so "collapsed" must accept the zombie state.
fn process_collapsed(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return true; // ENOENT: fully gone
    };
    let mut fields = stat.split_whitespace();
    let _pid = fields.next();
    let _comm = fields.next();
    matches!(fields.next(), Some("Z"))
}

static MARKER_SEQ: AtomicU64 = AtomicU64::new(1);

/// Matrix case 1: two concurrent exec children each write a large, distinct
/// payload to their own stdout; neither child's bytes may leak into the
/// other's pipe, and both exit 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_two_concurrent_exec_keep_independent_stdio() {
    let mut inst = launch_exec_session("exec-concurrent-stdio").await;

    let a = inst
        .exec(
            &["sh", "-c", "i=0; while [ $i -lt 2000 ]; do printf A; i=$((i+1)); done"],
            ExecStdio::Piped,
        )
        .await
        .expect("exec child A");
    let b = inst
        .exec(
            &["sh", "-c", "i=0; while [ $i -lt 2000 ]; do printf B; i=$((i+1)); done"],
            ExecStdio::Piped,
        )
        .await
        .expect("exec child B");
    assert_ne!(a.child_id, b.child_id, "each exec gets its own child id");

    // The host ends of A and B must be distinct open files.
    let a_stdout = a.stdout.expect("child A piped stdout");
    let b_stdout = b.stdout.expect("child B piped stdout");
    assert!(
        a.stdin.is_some(),
        "piped exec returns a stdin write end"
    );

    let status_a = inst.wait_child(a.child_id).await.expect("wait child A");
    let status_b = inst.wait_child(b.child_id).await.expect("wait child B");
    assert_eq!(status_a, ExitStatus::Code(0));
    assert_eq!(status_b, ExitStatus::Code(0));

    let out_a = read_exact_bytes(a_stdout, 2000);
    let out_b = read_exact_bytes(b_stdout, 2000);
    assert!(
        out_a.iter().all(|&c| c == b'A'),
        "child A stdout must contain only A bytes"
    );
    assert!(
        out_b.iter().all(|&c| c == b'B'),
        "child B stdout must contain only B bytes"
    );

    inst.shutdown().await.expect("shutdown");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
}

/// Matrix case 2: `wait_child(child_id)` is idempotent — the second wait
/// returns the exact same exit status without error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_double_wait_child_is_idempotent() {
    let mut inst = launch_exec_session("exec-double-wait").await;
    let h = inst
        .exec(&["sh", "-c", "exit 7"], ExecStdio::Piped)
        .await
        .expect("exec child");
    drop(h.stdin);

    let first = inst.wait_child(h.child_id).await.expect("first wait");
    let second = inst.wait_child(h.child_id).await.expect("second wait");
    assert_eq!(first, ExitStatus::Code(7));
    assert_eq!(second, first, "a repeated wait returns the cached status");

    inst.shutdown().await.expect("shutdown");
}

/// Matrix case 3: closing a piped stdin delivers EOF and the wait returns
/// (no deadlock), with the echoed output intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_close_stdin_does_not_deadlock() {
    let mut inst = launch_exec_session("exec-close-stdin").await;
    let h = inst
        .exec(&["cat"], ExecStdio::Piped)
        .await
        .expect("exec cat");

    let mut stdin = std::fs::File::from(h.stdin.expect("cat piped stdin"));
    stdin
        .write_all(b"hello-stdin\n")
        .expect("write to cat stdin");
    drop(stdin); // EOF so `cat` can exit.

    let status = tokio::time::timeout(
        Duration::from_secs(10),
        inst.wait_child(h.child_id),
    )
    .await
    .expect("wait_child must not deadlock after stdin EOF")
    .expect("wait cat");
    assert_eq!(status, ExitStatus::Code(0));

    let out = read_exact_bytes(
        h.stdout.expect("cat piped stdout"),
        b"hello-stdin\n".len(),
    );
    assert_eq!(out, b"hello-stdin\n");
    inst.shutdown().await.expect("shutdown");
}

/// Matrix case 4: after `shutdown` every `exec` fails with the same unified
/// error (the F5.4 S5 closed-instance code, reserved on this task's terms) —
/// never a different code or a silent re-launch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_exec_after_shutdown_returns_same_error() {
    let mut inst = launch_exec_session("exec-after-shutdown").await;
    let h = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Piped)
        .await
        .expect("exec before shutdown");
    drop(h.stdin);
    let status = inst
        .wait_child(h.child_id)
        .await
        .expect("wait pre-shutdown child");
    assert_eq!(status, ExitStatus::Code(0));

    inst.shutdown().await.expect("shutdown");

    let e1 = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Piped)
        .await
        .expect_err("exec after shutdown must fail");
    let e2 = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Piped)
        .await
        .expect_err("second exec after shutdown must fail the same way");
    let e3 = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Piped)
        .await
        .expect_err("third exec after shutdown must fail the same way");

    for e in [&e1, &e2, &e3] {
        assert!(
            matches!(e, SandlockError::Runtime(SandboxRuntimeError::InstanceClosed)),
            "exec after shutdown must return the unified closed-instance error, got: {e:?}"
        );
    }
    assert_eq!(format!("{e1}"), format!("{e2}"));
    assert_eq!(format!("{e2}"), format!("{e3}"));
}

/// §4.14: a child forks a grandchild that keeps holding the stdout write end
/// and then exits. `wait_child` must return promptly (the direct child is
/// reaped), the pipe must NOT reach EOF while the grandchild lives, and
/// `shutdown` must collapse the retained group so the pipe then EOFs — no
/// hang on either side.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_grandchild_holding_stdout_does_not_hang_wait_or_shutdown() {
    let mut inst = launch_exec_session("exec-grandchild-stdout").await;
    let h = inst
        .exec(
            &["sh", "-c", "(sleep 5) & exit 0"],
            ExecStdio::Piped,
        )
        .await
        .expect("exec child with forking grandchild");
    let stdout = h.stdout.expect("piped stdout");

    let status = tokio::time::timeout(
        Duration::from_secs(10),
        inst.wait_child(h.child_id),
    )
    .await
    .expect("wait_child must return promptly even while a grandchild holds stdout")
    .expect("wait child");
    assert_eq!(status, ExitStatus::Code(0));

    // The grandchild still owns the write end: a read must block (no EOF).
    assert!(
        poll_until(
            || try_read_nonblock(&stdout) == None,
            Duration::from_secs(5),
        )
        .await,
        "while the grandchild sleeps holding stdout, the pipe must not EOF"
    );

    // Shutdown collapses the retained child group; the write end then closes
    // and the caller's read reaches EOF instead of hanging.
    tokio::time::timeout(Duration::from_secs(10), inst.shutdown())
        .await
        .expect("shutdown must not hang on a grandchild holding stdout")
        .expect("shutdown");

    let eof = poll_until(
        || try_read_nonblock(&stdout) == Some(Vec::new()),
        Duration::from_secs(5),
    )
    .await;
    assert!(eof, "after shutdown the pipe write ends must be closed (EOF)");
}

/// F1.2 registration checking: wait/kill on an unknown child id is refused
/// with the registry error, never treated as a live child.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_child_registry_rejects_unknown_child_id() {
    let mut inst = launch_exec_session("exec-unknown-child").await;
    let unknown: ChildId = 4242;

    let wait_err = inst
        .wait_child(unknown)
        .await
        .expect_err("wait for an unregistered child id must fail");
    let kill_err = inst
        .kill_child(unknown, libc::SIGKILL)
        .expect_err("kill of an unregistered child id must fail");
    assert_eq!(format!("{wait_err}"), format!("{kill_err}"));
    assert!(
        matches!(
            wait_err,
            SandlockError::Runtime(SandboxRuntimeError::UnknownChild(4242))
        ),
        "registry error must name the unknown id exactly, got: {wait_err:?}"
    );

    inst.shutdown().await.expect("shutdown");
}

/// Kill-after-reap is an idempotent no-op (the python `Process.kill`
/// compatibility contract): killing a child whose exit was already reported
/// never signals anything and never errors.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_kill_child_after_reap_is_idempotent() {
    let mut inst = launch_exec_session("exec-kill-reaped").await;
    let h = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Piped)
        .await
        .expect("exec child");
    drop(h.stdin);
    let status = inst.wait_child(h.child_id).await.expect("wait child");
    assert_eq!(status, ExitStatus::Code(0));

    inst.kill_child(h.child_id, libc::SIGKILL)
        .expect("kill after reap is a no-op, not an error");

    inst.shutdown().await.expect("shutdown");
}

/// A pty exec returns the host-side pty master in the handle, and
/// `resize_child` drives TIOCSWINSZ through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_exec_pty_returns_master_and_resize_works() {
    let mut inst = launch_exec_session("exec-pty-resize").await;
    let h = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Pty)
        .await
        .expect("exec child on a pty");
    let pty = h.pty.expect("pty exec returns a master fd");
    inst.resize_child(h.child_id, 40, 120)
        .expect("resize_child drives TIOCSWINSZ on the master");

    let status = inst.wait_child(h.child_id).await.expect("wait pty child");
    assert_eq!(status, ExitStatus::Code(0));
    drop(pty);
    inst.shutdown().await.expect("shutdown");
}

/// Reviewer I2: exec-mode sessions are terminal when the main child (id 0)
/// exits — init collapses every group and exits, so the session is over.
/// The phase reads `Exited`, stats reconcile to zero, every per-child verb
/// returns the unified closed-instance error, and a later `shutdown` only
/// performs the resource cleanup. One-shot mode keeps its documented
/// outlives-first-process semantics (pinned by
/// `test_instance_lifecycle::test_instance_outlives_first_process`, which
/// must stay green).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_exec_mode_main_exit_is_terminal_and_verbs_close() {
    use sandlock_core::error::SandboxRuntimeError;

    let seq = MARKER_SEQ.fetch_add(1, Ordering::Relaxed);
    let marker = std::path::PathBuf::from(format!(
        "/tmp/sandlock-f323-main-exit-{}-{seq}",
        std::process::id()
    ));
    let script = format!(
        "while [ ! -f {} ]; do sleep 0.05; done; exit 0",
        marker.display()
    );
    let mut inst = SandboxInstance::launch_exec(
        base_policy().build().unwrap().with_name("exec-mode-main-exit"),
        &["sh", "-c", &script],
    )
    .await
    .expect("launch exec session");

    let child = inst
        .exec(&["sh", "-c", "exec sleep 30"], ExecStdio::Null)
        .await
        .expect("exec a second child while the main is alive");
    let child_pid = child.pid;
    assert_eq!(inst.phase(), InstancePhase::Live);
    let live = inst.stats().await;
    assert_eq!(live.instance_state, InstancePhase::Live);
    assert_eq!(live.children_live, 2, "main + exec child both announced");

    // Release the main: it exits, init collapses the container and exits.
    std::fs::write(&marker, b"go").expect("write main-exit marker");
    let terminal = poll_until(
        || inst.phase() == InstancePhase::Exited,
        Duration::from_secs(15),
    )
    .await;
    assert!(terminal, "exec-mode phase must become Exited on main exit");
    assert!(
        poll_until(|| process_collapsed(child_pid), Duration::from_secs(15)).await,
        "the exec child's group must be collapsed by init's main-exit teardown"
    );

    // Stats reconcile: terminal state, zero children.
    let stats = inst.stats().await;
    assert_eq!(stats.instance_state, InstancePhase::Exited);
    assert_eq!(stats.children_live, 0);

    // Every verb returns the same unified closed-instance error.
    let exec_err = inst
        .exec(&["true"], ExecStdio::Null)
        .await
        .expect_err("exec after main exit must fail");
    let wait_err = inst
        .wait_child(child.child_id)
        .await
        .expect_err("wait_child after main exit must fail");
    let kill_err = inst
        .kill_child(child.child_id, libc::SIGKILL)
        .expect_err("kill_child after main exit must fail");
    let resize_err = inst
        .resize_child(child.child_id, 40, 120)
        .expect_err("resize_child after main exit must fail");
    for e in [&exec_err, &wait_err, &kill_err, &resize_err] {
        assert!(
            matches!(e, SandlockError::Runtime(SandboxRuntimeError::InstanceClosed)),
            "terminal exec-mode verbs must return the unified closed error, got: {e:?}"
        );
    }

    // shutdown still performs the resource-cleanup tail.
    let dir = inst
        .control_dir()
        .expect("session control dir")
        .clone();
    inst.shutdown().await.expect("shutdown after main exit");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(!dir.exists(), "shutdown must still remove the control dir");
    let _ = std::fs::remove_file(&marker);
}

/// The session's parent can inject into an **init-spawned child** -- the
/// prerequisite for making a restored session exec-capable.
///
/// Why this is a test and not an assumption: route B's slot owns the sandbox, and
/// `checkpoint/restore` can only keep `exec` working if the resumed process is a
/// child of the session's `sandlock-init` (that is what serves `exec` at all --
/// OCI's restore path refuses it with "exec is not supported on a restored
/// container" precisely because its restore has no init). But then the supervisor
/// stops being the resumed process's parent and becomes its *grandparent*, and
/// the injection it performs (`process_vm_writev`, plus `PTRACE_ATTACH` for the
/// ptrace-shaped routes) asks `PTRACE_MODE_ATTACH` permission across that gap.
///
/// Measured 2026-09-25: both work -- `process_vm_writev` transfers the exact
/// payload into a writable mapping of the child, and `PTRACE_ATTACH` (followed by
/// `PTRACE_DETACH`) succeeds. Same host uid plus the same user namespace mapping
/// is the reason, and this pins it: if a kernel or a policy change ever breaks it,
/// the (b) design loses its footing and this test is where that shows up.
#[tokio::test]
async fn test_the_session_parent_can_write_into_an_init_spawned_child() {
    let mut session = launch_exec_session("spike-grandchild-write").await;
    let handle = session
        .exec(&["sh", "-c", "exec sleep 30"], ExecStdio::Piped)
        .await
        .expect("exec a child under init");
    let pid = handle.pid;
    assert!(pid > 0, "the session must report the child's host pid");

    // A writable anonymous mapping to poke at.
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("read child maps");
    let (start, end) = maps
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let range = parts.next()?;
            let perms = parts.next()?;
            let path = parts.nth(3).unwrap_or("");
            if !(perms.starts_with("rw") && path.is_empty()) {
                return None;
            }
            let (lo, hi) = range.split_once('-')?;
            Some((
                u64::from_str_radix(lo, 16).ok()?,
                u64::from_str_radix(hi, 16).ok()?,
            ))
        })
        .find(|(lo, hi)| hi - lo >= 4096)
        .expect("the child has a writable anonymous mapping");
    let _ = end;

    // 1. The plain injection path: process_vm_writev, no attach.
    let payload = [0x5Au8; 8];
    let local = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let remote = libc::iovec {
        iov_base: start as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let written = unsafe {
        libc::process_vm_writev(
            pid,
            &local as *const libc::iovec,
            1,
            &remote as *const libc::iovec,
            1,
            0,
        )
    };
    let write_err = std::io::Error::last_os_error();

    // 2. The attach path (what a ptrace-based injection would need).
    let attach = unsafe {
        libc::ptrace(
            libc::PTRACE_ATTACH,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    let attach_err = std::io::Error::last_os_error();
    if attach == 0 {
        let mut status = 0;
        let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
        let detach = unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        assert_eq!(detach, 0, "detach: {}", std::io::Error::last_os_error());
    }

    assert_eq!(
        written,
        payload.len() as isize,
        "process_vm_writev into an init-spawned child must transfer the payload \
         (errno {})",
        write_err.raw_os_error().unwrap_or(0)
    );
    assert_eq!(
        attach,
        0,
        "PTRACE_ATTACH into an init-spawned child must be permitted (errno {})",
        attach_err.raw_os_error().unwrap_or(0)
    );

    let _ = session.kill_child(handle.child_id, libc::SIGKILL);
    let _ = session.shutdown().await;
}

/// **The acceptance test for (b)**: a checkpoint restored *into a session* keeps
/// the session executable.
///
/// The shape follows from what serves `exec`: the session's `sandlock-init`. A
/// restore that produces the supervisor's own child can never be exec'd into
/// again -- OCI's restore path literally answers "exec is not supported on a
/// restored container" -- so a long-lived sandbox that pauses and resumes has to
/// get its process back *as a session child*. This asserts the three things a
/// caller depends on:
///
/// 1. the resumed process is running: the workload's counter advances, from a
///    file zeroed after the source session was torn down, so only the restored
///    process can have written it;
/// 2. the session **still serves `exec`** afterwards -- the entire point;
/// 3. the resumed child is a session child: `children_live` counts it, so
///    `wait_child`/`kill_child`/shutdown see it like any other exec.
#[tokio::test]
async fn test_a_child_restored_into_a_session_keeps_the_session_executable() {
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper — build.rs should have compiled it");
    let helper_s = helper.to_str().unwrap().to_string();
    let workdir = std::env::temp_dir().join(format!(
        "sandlock-session-restore-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir).unwrap();
    let counter = workdir.join("clock.cnt");
    let counter_s = counter.to_str().unwrap().to_string();
    let read_counter = || {
        std::fs::read_to_string(&counter)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    };

    // One policy for both sessions: the image was captured under it, and a
    // restore resolves the image's paths against the session it lands in.
    let policy = base_policy()
        .fs_read(helper.parent().unwrap())
        .fs_read(&workdir)
        .fs_write(&workdir)
        .build()
        .unwrap();

    // --- the session that gets checkpointed (its single child is the counter) ---
    let mut src = SandboxInstance::launch_exec(
        policy.clone().with_name("session-restore-src"),
        &[helper_s.as_str(), "clock-loop", counter_s.as_str()],
    )
    .await
    .expect("launch the session that will be checkpointed");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !read_counter().is_some_and(|v| v >= 3) {
        assert!(Instant::now() < deadline, "the counter must run before the checkpoint");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let cp = src.checkpoint().await.expect("checkpoint the session");
    src.shutdown().await.expect("tear the source session down");
    // Sentinel: from here only the restored process can move this file.
    std::fs::write(&counter, b"0\n").unwrap();

    // --- the session that resumes it ---
    // The destination session needs a long-lived first child: a session whose
    // M0 exits is *over* (that is the documented M0 semantic -- main exit
    // collapses the container), so a `true` here would tear the session down
    // before anything could be restored into it.
    let mut dst = SandboxInstance::launch_exec(
        policy.clone().with_name("session-restore-dst"),
        &["sh", "-c", "exec sleep 30"],
    )
    .await
    .expect("launch the session that resumes");
    let resumed = dst
        .restore_into_session(&cp)
        .await
        .expect("restore into the session");

    // 1. It is running.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !read_counter().is_some_and(|v| v > 0) {
        assert!(
            Instant::now() < deadline,
            "the restored process must resume and advance the counter"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 2. The session still execs. This is the assertion the (b) shape exists for:
    //    the same resume delivered to the supervisor's own child cannot do this.
    let echo = dst
        .exec(&[helper_s.as_str(), "echo", "still-execs"], ExecStdio::Piped)
        .await
        .expect("exec after a restore");
    let out = read_exact_bytes(echo.stdout.expect("piped stdout"), "still-execs\n".len());
    assert_eq!(String::from_utf8_lossy(&out), "still-execs\n");
    let exit = dst.wait_child(echo.child_id).await.expect("wait the exec");
    assert_eq!(exit, ExitStatus::Code(0));

    // 3. The resumed child is a session child, not a stranger beside it.
    let stats = dst.stats().await;
    assert!(
        stats.children_live >= 1,
        "the restored child must be counted by the session: {stats:?}"
    );

    // And the resumed child is addressable like any other exec.
    let _ = dst.kill_child(resumed.child_id, libc::SIGKILL);
    let _ = dst.shutdown().await;
    let _ = std::fs::remove_dir_all(&workdir);
}

/// The reason `checkpoint_excluding_main` exists: a **pooled** session's main
/// child is a park, so its workload is the single child beside it.
///
/// Route-B deployments launch a generation with a parking program, because
/// `sandlock-init` serves `exec` only while its main child lives and an envd
/// sandbox has no workload of its own at launch. Every such sandbox a user has
/// run something in therefore has **two** live children -- and the plain
/// capture refuses that shape, correctly (its message is asserted byte for
/// byte below, because "the deployment quietly captured the wrong thing" is
/// the failure this refusal prevents).
///
/// What must hold once the caller says "my main child is a park":
///
/// 1. the image is the *workload's* address space (its pid, not the park's);
/// 2. the capture is not a kill: both children keep running, and the workload
///    keeps writing (the engine resolved what it stopped);
/// 3. a session with nothing but the park left still refuses -- the park is not
///    a workload, so "capture the one child beside it" has no answer to give.
///
/// The `exclude_main` **verb** (what a pooled deployment actually calls) and the
/// `exec`-after-capture path are pinned elsewhere: the verb in
/// `sandlock-supervise`'s own suite, the exec path by the deployment acceptance
/// and the (b) restore test -- an exec into a *captured* session wedged in this
/// harness often enough to be useless as a pin, and that is recorded as FUP-29
/// rather than papered over.
#[tokio::test]
async fn test_a_sessions_workload_is_captured_with_the_park_left_out() {
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper — build.rs should have compiled it");
    let helper_s = helper.to_str().unwrap().to_string();
    let workdir = std::env::temp_dir().join(format!(
        "sandlock-park-capture-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir).unwrap();
    let counter = workdir.join("clock.cnt");
    let counter_s = counter.to_str().unwrap().to_string();
    let read_counter = || {
        std::fs::read_to_string(&counter)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    };

    let policy = base_policy()
        .fs_read(helper.parent().unwrap())
        .fs_read(&workdir)
        .fs_write(&workdir)
        .build()
        .unwrap();

    // The main child is a park, byte for byte the one envd's route-B sandbox
    // launches (`envd_service/route_b.py::PARKING_SCRIPT`): a shell that keeps
    // `sandlock-init` -- and therefore `exec` -- alive, and that stops itself
    // between checks. It never forks, which is also what the real one does
    // (`kill` is a shell builtin), so nothing here churns fork notifications
    // while the capture below holds them.
    let mut session = SandboxInstance::launch_exec(
        policy.with_name("park-capture"),
        &[
            "sh",
            "-c",
            "trap '' TERM HUP INT QUIT USR1 USR2 PIPE; while :; do kill -STOP $$; done",
        ],
    )
    .await
    .expect("launch the parked session");

    // The workload, as one exec child beside it.
    let work = session
        .exec(
            &[helper_s.as_str(), "clock-loop", counter_s.as_str()],
            ExecStdio::Piped,
        )
        .await
        .expect("exec the workload");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !read_counter().is_some_and(|v| v >= 3) {
        assert!(
            Instant::now() < deadline,
            "the workload must run before the capture"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        session.stats().await.children_live,
        2,
        "the parked shape is park + workload; that count is the whole point"
    );

    // 0. The plain capture refuses this shape, and says the count: an image is
    //    one address space, and choosing one of two would be a guess.
    let refused = session
        .checkpoint()
        .await
        .expect_err("a session with two live children must not be captured blind");
    assert_eq!(
        refused.to_string(),
        "process error: cannot checkpoint an exec session with 2 live children: \
         a checkpoint image captures one address space; wait for all but one \
         child first"
    );

    // 1. The scoped capture takes the workload: the image's pid is the exec
    //    child's, not the park's.
    let cp = session
        .checkpoint_excluding_main()
        .await
        .expect("capture the workload beside the park");
    assert_eq!(
        cp.process_state.pid, work.pid,
        "the image must be the workload's address space (the park stays out of it)"
    );

    // 2. Not a kill: both children are still registered and the workload is
    //    still writing.
    assert_eq!(session.stats().await.children_live, 2, "both children must live");
    let seen = read_counter().expect("the workload is still counting");
    let deadline = Instant::now() + Duration::from_secs(10);
    while read_counter().is_some_and(|v| v <= seen) {
        assert!(
            Instant::now() < deadline,
            "the workload must keep running through the capture"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 3. The session still serves exec after being captured.
    // 3. Not a kill: both children are still registered and the workload is
    //    still writing after the capture -- which is the "resolve what you
    //    stopped" half of the engine's capture contract.
    assert_eq!(session.stats().await.children_live, 2, "both children must live");
    let seen = read_counter().expect("the workload is still counting");
    let deadline = Instant::now() + Duration::from_secs(10);
    while read_counter().is_some_and(|v| v <= seen) {
        assert!(
            Instant::now() < deadline,
            "the workload must keep running through the capture"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // What this test deliberately does *not* do is `exec` into the captured
    // session: that path wedged intermittently here (one run in three, with the
    // workload still alive and the exec'd child gone), it is not root-caused,
    // and the deployment's own acceptance exercises it where it matters -- see
    // `docs/fork-plan-followups.md` (FUP-29).

    // 4. With the park alone left, there is no workload to capture -- and the
    //    scoped capture says so instead of imaging the park.
    let _ = session.kill_child(work.child_id, libc::SIGKILL);
    let _ = session.wait_child(work.child_id).await;
    assert_eq!(
        session.stats().await.children_live,
        1,
        "only the park is left"
    );
    let empty = session
        .checkpoint_excluding_main()
        .await
        .expect_err("a park is not a workload");
    assert_eq!(
        empty.to_string(),
        "process error: cannot checkpoint an exec session with no live child to capture"
    );

    // Tear the *park* down with SIGKILL, not just `shutdown()`: it traps TERM
    // and is SIGSTOPped, so a graceful end leaves it alive -- and a live session
    // child holds this test's **stdout/stderr** open (it inherited them at
    // launch). libtest's output-capture reader then never sees EOF and the whole
    // test binary hangs at exit, which looks exactly like a wedged engine. The
    // real deployment never has this problem: its slot tears the generation down
    // with the worker.
    let _ = session.kill_child(0, libc::SIGKILL);
    let _ = session.wait_child(0).await;
    let _ = session.shutdown().await;
    let _ = std::fs::remove_dir_all(&workdir);
}
