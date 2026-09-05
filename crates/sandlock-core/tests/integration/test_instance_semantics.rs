//! M3 instance semantics (fork-plan F5): whole-box process accounting,
//! checkpoint refusal, unified Dead code, idle/T_max lifecycle, and pid-ns
//! /proc per-child narrowing.
//!
//! Test matrix (fork-plan-2026-09.md §F5 + §7 M3):
//!
//! * `test_max_processes_default_bounds_whole_box` — the process ceiling is
//!   shared by every exec child of one instance (not a per-command budget);
//!   the default (asserted at lib level) is 256 and the box's N+1-th fork is
//!   refused while earlier commands still hold their slots.
//! * `test_checkpoint_with_multiple_children_is_refused` — a checkpoint
//!   image captures one address space; with more than one live child it is
//!   refused explicitly instead of silently snapshotting one command.
//! * `test_dead_state_surfaces_single_error_code` — an unexpected control
//!   link death (listener/reaper/channel fatal) lands the instance in `Dead`;
//!   every later verb returns the same distinct code.
//! * `test_idle_timeout_drains_and_shuts_down` — with the child table empty
//!   and no wait subscribers, the instance drains after `T_idle`; a live
//!   child resets the clock.
//! * `test_pid_ns_procfs_scope_narrows_to_child` — with `pid_ns` on, the
//!   on-behalf `/proc` whitelist only serves a child's own subtree; a
//!   sibling's `cmdline`/`status` reads return EACCES.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sandlock_core::error::SandboxRuntimeError;
use sandlock_core::instance::{ExecStdio, InstancePhase, SandboxInstance};
use sandlock_core::Sandbox;

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

fn process_is_gone(pid: i32) -> bool {
    let r = unsafe { libc::kill(pid, 0) };
    r != 0
}

fn process_is_zombie(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return true; // gone is not a zombie
    };
    let after = stat.rsplit_once(") ").map(|(_, rest)| rest).unwrap_or("");
    after.split_whitespace().next() == Some("Z")
}

/// Host pid of the confined `sandlock-init` (the exec session's direct child
/// when `pid_ns` is off): the parent of every registered exec child.
fn init_host_pid_of(child_pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{child_pid}/stat")).ok()?;
    let after = stat.rsplit_once(") ")?.1;
    after.split_whitespace().nth(1)?.parse().ok()
}

static MARKER_SEQ: AtomicU64 = AtomicU64::new(1);

fn marker_path(tag: &str) -> PathBuf {
    let seq = MARKER_SEQ.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "/tmp/sandlock-f5-{tag}-{}-{seq}",
        std::process::id()
    ))
}

/// F5.1 (Q10): `max_processes` bounds the **whole box** — every exec child
/// of one session shares the accounting, so command N+1 is refused while
/// earlier commands still hold their process slots, and a slot released by a
/// reaped command is available to the next command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_max_processes_default_bounds_whole_box() {
    // 4 = the confined init (baseline slot) + 3 live fork slots. Exec children
    // A/B/C fill the box; the next command's fork (D) must be refused with
    // EAGAIN — a per-command ceiling would let D through.
    let mut inst = SandboxInstance::launch_exec_only(
        base_policy()
            .max_processes(4)
            .build()
            .unwrap()
            .with_name("f5-maxproc-whole-box"),
    )
    .await
    .expect("launch exec session");

    let a = inst
        .exec(&["sleep", "60"], ExecStdio::Null)
        .await
        .expect("exec A");
    let b = inst
        .exec(&["sleep", "60"], ExecStdio::Null)
        .await
        .expect("exec B");
    let c = inst
        .exec(&["sleep", "60"], ExecStdio::Null)
        .await
        .expect("exec C (box now at the ceiling)");
    assert!(process_is_alive(a.pid), "A must hold its process slot");
    assert!(process_is_alive(b.pid), "B must hold its process slot");
    assert!(process_is_alive(c.pid), "C must hold its process slot");

    let denied = inst
        .exec(&["sleep", "60"], ExecStdio::Null)
        .await
        .expect_err("the box's N+1-th fork must be refused across commands");
    assert!(
        matches!(
            &denied,
            sandlock_core::SandlockError::Runtime(SandboxRuntimeError::Child(msg))
                if msg == "fork failed"
        ),
        "init must surface the EAGAIN as the exact 'fork failed' reply, got: {denied:?}"
    );

    // Releasing one command's slot (kill + reap C) frees the budget for the
    // next command: whole-box accounting releases on exit, not on command
    // teardown boundaries (the exit watcher release is async, so poll).
    inst.kill_child(c.child_id, libc::SIGKILL).expect("kill C");
    let status = inst.wait_child(c.child_id).await.expect("reap C");
    assert_eq!(status, sandlock_core::result::ExitStatus::Killed);
    // The pidfd exit watcher releases the fork slot asynchronously; retry the
    // next command until the released budget lands (bounded).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut d_exec = None;
    while Instant::now() < deadline {
        match inst.exec(&["sleep", "1"], ExecStdio::Null).await {
            Ok(h) => {
                d_exec = Some(h);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let d = d_exec.expect("after C's slot is released, exec D must succeed");
    let d_status = inst.wait_child(d.child_id).await.expect("reap D");
    assert_eq!(d_status, sandlock_core::result::ExitStatus::Code(0));

    inst.shutdown().await.expect("shutdown");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
}

fn process_is_alive(pid: i32) -> bool {
    !process_is_gone(pid)
}
