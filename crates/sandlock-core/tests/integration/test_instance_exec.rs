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
