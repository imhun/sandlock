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

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sandlock_core::error::SandboxRuntimeError;
use sandlock_core::instance::{ExecStdio, InstanceLifetime, InstancePhase, SandboxInstance};
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

static MARKER_SEQ: AtomicU64 = AtomicU64::new(1);

/// F5.3 (M3 S4): with `pid_ns` on, the on-behalf `/proc` whitelist serves a
/// child only its **own subtree** — reading a sibling's `cmdline` must fail
/// with EACCES instead of leaking the sibling's command line through the
/// supervisor's credentials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pid_ns_procfs_scope_narrows_to_child() {
    let seq = MARKER_SEQ.fetch_add(1, Ordering::Relaxed);
    let base = format!("/tmp/sandlock-f5-scope-{}-{seq}", std::process::id());
    let marker_b = format!("{base}.b");
    let out_self = format!("{base}.self.out");
    let out_other = format!("{base}.other.out");
    let err_self = format!("{base}.self.err");
    let err_other = format!("{base}.other.err");
    let result = format!("{base}.rc");

    let policy = base_policy().pid_ns(true);
    let mut inst = SandboxInstance::launch_exec_only(
        policy.build().unwrap().with_name("f5-procfs-scope"),
    )
    .await
    .expect("launch pid-ns exec session");

    // A: waits for B's marker, then reads its own /proc/<self>/status and
    // B's /proc/<other>/cmdline, recording each cat's exact exit code.
    let a_script = format!(
        "self=$$; \
         while [ ! -f {marker_b} ]; do sleep 0.05; done; \
         other=$(cat {marker_b}); \
         cat /proc/$self/status > {out_self} 2> {err_self}; \
         echo self_rc=$? > {result}; \
         cat /proc/$other/cmdline > {out_other} 2> {err_other}; \
         echo other_rc=$? >> {result}; \
         exit 0"
    );
    let a = inst
        .exec(&["sh", "-c", &a_script], ExecStdio::Piped)
        .await
        .expect("exec child A (probe)");

    // B: records its namespace pid, then stays alive so A has something to
    // probe.
    let b_script = format!(
        "echo $$ > {marker_b}; \
         exec sleep 60"
    );
    let b = inst
        .exec(&["sh", "-c", &b_script], ExecStdio::Piped)
        .await
        .expect("exec child B (sibling)");

    let a_status = tokio::time::timeout(Duration::from_secs(15), inst.wait_child(a.child_id))
        .await
        .expect("A must finish its probes")
        .expect("wait A");
    assert_eq!(a_status, sandlock_core::result::ExitStatus::Code(0));

    let rc = std::fs::read_to_string(&result).unwrap_or_default();
    let err_self_text = std::fs::read_to_string(&err_self).unwrap_or_default();
    let err_other_text = std::fs::read_to_string(&err_other).unwrap_or_default();
    assert!(
        rc == "self_rc=0\nother_rc=1\n",
        "A must read its own /proc metadata (rc 0) and fail on B's cmdline \
         (rc 1, EACCES): {rc:?} (self stderr: {err_self_text:?}, other stderr: {err_other_text:?})"
    );
    assert!(
        std::fs::read_to_string(&out_self)
            .map(|s| s.len() > 0)
            .unwrap_or(false),
        "A's own status must be readable"
    );
    assert_eq!(
        std::fs::read(&out_other).unwrap_or_default().len(),
        0,
        "B's cmdline bytes must never reach A (empty output)"
    );

    // B survives and the session stays live.
    assert!(process_is_alive(b.pid));
    assert_eq!(inst.phase(), InstancePhase::Live);
    inst.kill_child(b.child_id, libc::SIGKILL).expect("kill B");
    let _ = inst.wait_child(b.child_id).await;
    inst.shutdown().await.expect("shutdown");

    for p in [&marker_b, &out_self, &out_other, &err_self, &err_other, &result] {
        let _ = std::fs::remove_file(p);
    }
}

/// F5.4 (M3 S5): a fatal control-link failure (here: the confined
/// `sandlock-init` is killed out from under the session) lands the instance
/// in the distinct `Dead` state. Every later verb — exec, wait_child,
/// kill_child, resize_child — returns the **same** `InstanceDead` error,
/// never a different code and never a silent restart; `shutdown` still
/// performs the cleanup tail and afterwards the verbs report the
/// `InstanceClosed` code, so Dead and closed-by-shutdown stay
/// distinguishable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dead_state_surfaces_single_error_code() {
    let mut inst = SandboxInstance::launch_exec_only(
        base_policy().build().unwrap().with_name("f5-dead-code"),
    )
    .await
    .expect("launch exec session");
    let child = inst
        .exec(&["sleep", "60"], ExecStdio::Null)
        .await
        .expect("exec child");
    let init_pid = inst.control_pid().expect("confined init host pid");

    // Fatal channel failure: init dies without a Shutdown frame and without
    // the main-exit collapse sequence.
    unsafe { libc::kill(init_pid, libc::SIGKILL) };
    assert!(
        poll_until(
            || inst.phase() == InstancePhase::Dead,
            Duration::from_secs(10)
        )
        .await,
        "an unexpectedly terminated init must land the instance in Dead"
    );

    let e_exec = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Null)
        .await
        .expect_err("exec after Dead must fail");
    let e_wait = inst
        .wait_child(child.child_id)
        .await
        .expect_err("wait_child after Dead must fail");
    let e_kill = inst
        .kill_child(child.child_id, libc::SIGKILL)
        .expect_err("kill_child after Dead must fail");
    let e_resize = inst
        .resize_child(child.child_id, 40, 120)
        .expect_err("resize_child after Dead must fail");

    for e in [&e_exec, &e_wait, &e_kill, &e_resize] {
        assert!(
            matches!(
                e,
                sandlock_core::SandlockError::Runtime(SandboxRuntimeError::InstanceDead)
            ),
            "every post-Dead verb must return the unified InstanceDead code, got: {e:?}"
        );
    }
    assert_eq!(format!("{e_exec}"), format!("{e_wait}"));
    assert_eq!(format!("{e_wait}"), format!("{e_kill}"));
    assert_eq!(format!("{e_kill}"), format!("{e_resize}"));

    // Dead is observable on the stats surface, and shutdown still cleans up.
    let stats = inst.stats().await;
    assert_eq!(stats.instance_state, InstancePhase::Dead);
    inst.shutdown().await.expect("shutdown from Dead must clean up");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        !inst.control_dir().expect("control dir").exists(),
        "shutdown from Dead must still remove the control dir"
    );

    // After the cleanup tail the closed code is the *closed* one — Dead and
    // InstanceClosed remain distinct (no silent state confusion).
    let e_after = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Null)
        .await
        .expect_err("exec after shutdown-from-Dead must fail");
    assert!(
        matches!(
            &e_after,
            sandlock_core::SandlockError::Runtime(SandboxRuntimeError::InstanceClosed)
        ),
        "post-shutdown verbs report InstanceClosed, got: {e_after:?}"
    );
}

/// FUP-13: the Dead state semantics also hold under `pid_ns` — the confined
/// init is namespace PID 1 but its host pid is still the fatal-link anchor;
/// killing it must land the instance in `Dead` with the same unified code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pid_ns_init_killed_lands_dead_with_unified_code() {
    let mut inst = SandboxInstance::launch_exec_only(
        base_policy()
            .pid_ns(true)
            .build()
            .unwrap()
            .with_name("f5-dead-pidns"),
    )
    .await
    .expect("launch pid-ns exec session");
    let child = inst
        .exec(&["sleep", "60"], ExecStdio::Null)
        .await
        .expect("exec child");
    let init_pid = inst.control_pid().expect("confined init host pid");

    unsafe { libc::kill(init_pid, libc::SIGKILL) };
    assert!(
        poll_until(
            || inst.phase() == InstancePhase::Dead,
            Duration::from_secs(10)
        )
        .await,
        "a killed pid-ns init must land the instance in Dead"
    );

    let e_exec = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Null)
        .await
        .expect_err("exec after Dead must fail");
    let e_wait = inst
        .wait_child(child.child_id)
        .await
        .expect_err("wait_child after Dead must fail");
    assert!(
        matches!(
            &e_exec,
            sandlock_core::SandlockError::Runtime(SandboxRuntimeError::InstanceDead)
        ),
        "exec after pid-ns Dead must return InstanceDead, got: {e_exec:?}"
    );
    assert_eq!(format!("{e_exec}"), format!("{e_wait}"));

    let stats = inst.stats().await;
    assert_eq!(stats.instance_state, InstancePhase::Dead);
    inst.shutdown().await.expect("shutdown from Dead must clean up");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        !inst.control_dir().expect("control dir").exists(),
        "shutdown from pid-ns Dead must still remove the control dir"
    );
}

/// F5.5 (M3 S7): after the child table empties (and no wait_child subscriber
/// remains), a persistent `T_idle` drains the instance — the phase reads
/// `Draining`, the next verb performs the shutdown tail (children_live 0,
/// control dir gone, `ShutDown`), and the drain is idempotent. A live child
/// resets the clock: a session with a running workload must never idle out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_idle_timeout_drains_and_shuts_down() {
    let short_idle = InstanceLifetime {
        idle_timeout: Some(Duration::from_millis(400)),
        max_lifetime: None,
    };

    // Phase 1: children churn, the table empties, T_idle elapses -> Draining
    // and the next verb completes the shutdown tail.
    let mut inst = SandboxInstance::launch_exec_only_with_lifetime(
        base_policy().build().unwrap().with_name("f5-idle-churn"),
        short_idle,
    )
    .await
    .expect("launch exec session with short idle");
    let child = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Null)
        .await
        .expect("exec a short-lived child");
    let status = inst.wait_child(child.child_id).await.expect("reap child");
    assert_eq!(status, sandlock_core::result::ExitStatus::Code(0));
    assert_eq!(inst.phase(), InstancePhase::Live, "no idle yet");

    assert!(
        poll_until(
            || inst.phase() == InstancePhase::Draining,
            Duration::from_secs(10),
        )
        .await,
        "an empty child table with no wait subscribers must drain after T_idle"
    );
    let dir = inst.control_dir().expect("control dir").clone();
    let err = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Null)
        .await
        .expect_err("exec after idle drain must be refused");
    assert!(
        matches!(
            err,
            sandlock_core::SandlockError::Runtime(SandboxRuntimeError::InstanceClosed)
        ),
        "the idle drain refuses new work with the closed code"
    );
    assert_eq!(
        inst.phase(),
        InstancePhase::ShutDown,
        "the refused verb must drive the idle drain to completion"
    );
    assert!(!dir.exists(), "the idle drain must remove the control dir");
    let stats = inst.stats().await;
    assert_eq!(stats.children_live, 0);
    let err2 = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Null)
        .await
        .expect_err("a second post-drain verb must fail identically");
    assert!(matches!(
        err2,
        sandlock_core::SandlockError::Runtime(SandboxRuntimeError::InstanceClosed)
    ));
    inst.shutdown().await.expect("shutdown after drain is idempotent");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);

    // Phase 2: a live child must reset the idle clock — the session stays
    // Live for well over T_idle while the workload runs, and a second exec
    // still lands.
    let mut live = SandboxInstance::launch_exec_only_with_lifetime(
        base_policy().build().unwrap().with_name("f5-idle-live-child"),
        short_idle,
    )
    .await
    .expect("launch second session");
    let keeper = live
        .exec(&["sleep", "30"], ExecStdio::Null)
        .await
        .expect("exec the live keeper child");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        live.phase(),
        InstancePhase::Live,
        "a live child must prevent the idle drain"
    );
    let second = live
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Null)
        .await
        .expect("exec must still work while a child is live");
    let second_status = live.wait_child(second.child_id).await.expect("reap");
    assert_eq!(second_status, sandlock_core::result::ExitStatus::Code(0));

    // The keeper child also keeps the T_idle clock from draining once the
    // short-lived child's exit is reaped... then kill the keeper, reap it,
    // and the box drains.
    live.kill_child(keeper.child_id, libc::SIGKILL).expect("kill keeper");
    let _ = live.wait_child(keeper.child_id).await;
    assert!(
        poll_until(
            || live.phase() == InstancePhase::Draining,
            Duration::from_secs(10),
        )
        .await,
        "once the last child is reaped the idle drain must fire again"
    );
    let _ = live
        .exec(&["true"], ExecStdio::Null)
        .await
        .expect_err("post-drain exec refused");
    assert_eq!(live.phase(), InstancePhase::ShutDown);
}

/// F5.5 (M3 S7): `T_max` is a forced lifetime cap — even with a live child
/// the instance drains when the cap elapses, and repeated observations stay
/// idempotent (no double teardown).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_max_lifetime_forces_shutdown_with_live_child() {
    let short_max = InstanceLifetime {
        idle_timeout: None,
        max_lifetime: Some(Duration::from_millis(500)),
    };
    let mut inst = SandboxInstance::launch_exec_only_with_lifetime(
        base_policy().build().unwrap().with_name("f5-max-lifetime"),
        short_max,
    )
    .await
    .expect("launch exec session with short max lifetime");
    let child = inst
        .exec(&["sleep", "60"], ExecStdio::Null)
        .await
        .expect("exec a live child");

    assert!(
        poll_until(
            || inst.phase() == InstancePhase::Draining,
            Duration::from_secs(10),
        )
        .await,
        "T_max must force the instance to Draining even with a live child"
    );
    let err = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Null)
        .await
        .expect_err("exec after T_max must be refused");
    assert!(matches!(
        err,
        sandlock_core::SandlockError::Runtime(SandboxRuntimeError::InstanceClosed)
    ));
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        poll_until(
            || !process_is_alive(child.pid),
            Duration::from_secs(10),
        )
        .await,
        "the forced T_max drain must kill the live child"
    );
    inst.shutdown().await.expect("shutdown after T_max is idempotent");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
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

/// F5.2 (M3 S3): a checkpoint image captures **one** address space. An exec
/// session with more than one live child must refuse explicitly — silently
/// storing one command while a sibling keeps running would make the restored
/// box lie about what was snapshotted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_checkpoint_with_multiple_children_is_refused() {
    let mut inst = SandboxInstance::launch_exec_only(
        base_policy().build().unwrap().with_name("f5-ckpt-multi"),
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
    assert_ne!(a.child_id, b.child_id);

    let err = inst
        .checkpoint()
        .await
        .expect_err("checkpoint with two live children must be refused");
    assert!(
        matches!(
            &err,
            sandlock_core::SandlockError::Runtime(SandboxRuntimeError::CheckpointMultipleChildren { live: 2 })
        ),
        "the refusal must name the live-child count exactly, got: {err:?}"
    );

    // Both children are untouched by the refusal and the session stays live.
    assert_eq!(inst.phase(), InstancePhase::Live);
    assert!(process_is_alive(a.pid));
    assert!(process_is_alive(b.pid));

    inst.kill_child(a.child_id, libc::SIGKILL).expect("kill A");
    inst.kill_child(b.child_id, libc::SIGKILL).expect("kill B");
    let _ = inst.wait_child(a.child_id).await;
    let _ = inst.wait_child(b.child_id).await;
    inst.shutdown().await.expect("shutdown");
}

/// F5.2 companion: the single-live-child shape keeps the legacy checkpoint
/// semantics — the instance captures exactly that one address space (its
/// host pid, registers and maps) and the child survives the capture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_checkpoint_single_live_child_captures_that_child() {
    let mut inst = SandboxInstance::launch_exec_only(
        base_policy().build().unwrap().with_name("f5-ckpt-single"),
    )
    .await
    .expect("launch exec session");
    let child = inst
        .exec(&["sleep", "60"], ExecStdio::Null)
        .await
        .expect("exec the single live child");

    let cp = inst
        .checkpoint()
        .await
        .expect("checkpoint of the single live child must succeed");
    assert_eq!(
        cp.process_state.pid, child.pid,
        "the checkpoint must capture the live child's host pid"
    );
    assert!(!cp.process_state.regs.is_empty(), "registers must be captured");
    assert!(
        !cp.process_state.memory_maps.is_empty(),
        "memory maps must be captured"
    );
    assert!(
        process_is_alive(child.pid),
        "the child must still be running after the checkpoint"
    );
    assert_eq!(inst.phase(), InstancePhase::Live);

    inst.kill_child(child.child_id, libc::SIGKILL).expect("kill child");
    let _ = inst.wait_child(child.child_id).await;
    inst.shutdown().await.expect("shutdown");
}
