//! M0 lifecycle tests for the explicit session instance (fork-plan F2.1).
//!
//! A `SandboxInstance` is the explicit owner of a sandbox session's
//! resources (supervisor tasks, F1.3 control directory + token, DNS gateway,
//! supervisor state). These tests pin the M0 contract:
//!
//! * the session outlives its first process — `wait_child` returns the
//!   process's result but leaves the session (control dir, DNS gateway,
//!   runtime) alive;
//! * `shutdown` is idempotent across repeated calls (three-call acceptance),
//!   removes the control directory, and leaves no process or fd behind;
//! * `shutdown` releases the control directory and the DNS gateway with no
//!   leftover process or fd;
//! * the F2.2 escalation ladder kills a live child that ignores the graceful
//!   shutdown request once its grace window elapses;
//! * the F2.1 review minors are pinned where they are observable: a session
//!   shut down without `wait_child` closes its pidfd and HTTP ACL proxy
//!   (B-5), and dropping an instance right after `wait_child` still applies
//!   the recorded COW disposition (B-3 branch handoff);
//! * the legacy `Sandbox::run`/`popen`/`spawn` one-shot paths still reclaim
//!   everything exactly as before (they drive a one-shot instance whose
//!   `wait` runs `wait_child` + `shutdown`);
//! * (F2.3) the instance stats surface (`stats()`) reports the F1.4 process
//!   reconciliation (`proc_count_vs_live`), the M0 single-child liveness
//!   (`children_live`) and the lifecycle phase (`instance_state`) — live,
//!   terminal-after-shutdown, and Draining-while-cancelled.

use std::io::Read;
use std::net::UdpSocket;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use sandlock_core::control;
use sandlock_core::instance::{InstancePhase, InstanceStats, SandboxInstance};
use sandlock_core::sandbox::BranchAction;
use sandlock_core::{Sandbox, StdioMode};

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

/// A wildcard-domain network rule forces the session DNS gateway (a
/// per-sandbox `127.0.1.x` loopback `:53` listener) to exist.
fn base_policy_with_gateway() -> sandlock_core::SandboxBuilder {
    base_policy().net_allow("*.lifecycle.example:443")
}

/// Count this process's open fds (`/proc/self/fd`), used to pin "no leftover
/// fd" after a session shutdown. The counting test runs on a multi-thread
/// tokio runtime whose worker fds exist before the baseline is taken, so the
/// count is stable while the session is alive and must return to baseline once
/// the session's tasks (notif/control/DNS/drains) are gone.
fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd must be readable")
        .count()
}

fn process_is_gone(pid: i32) -> bool {
    let r = unsafe { libc::kill(pid, 0) };
    r != 0
}

/// Poll `cond` until it is true or `timeout` elapses; returns the last value.
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

/// Poll the instance's stats surface until it equals `want` (or the deadline
/// passes, returning the last snapshot for the exact assertion). Loop control
/// only — assertions on the outcome are exact `assert_eq!`s in the callers.
async fn wait_for_instance_stats(
    inst: &SandboxInstance,
    want: InstanceStats,
    timeout: Duration,
) -> InstanceStats {
    let deadline = Instant::now() + timeout;
    let mut last = inst.stats().await;
    while Instant::now() < deadline {
        last = inst.stats().await;
        if last == want {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    last
}

/// A live session's control socket must accept a connection (the listener task
/// is still serving) and its DNS gateway must still own `:53`.
fn assert_session_resources_live(inst: &SandboxInstance) {
    let dir = inst.control_dir().expect("session control dir");
    assert!(
        dir.exists(),
        "session control dir must still exist after the first process exits: {:?}",
        dir
    );
    let sock = control::sock_path(dir);
    UnixStream::connect(&sock).unwrap_or_else(|e| {
        panic!(
            "session control socket must still accept connections after the \
             first process exits ({}): {e}",
            sock.display()
        )
    });
    let gw = inst
        .dns_gateway_addr()
        .expect("wildcard rules must allocate a session DNS gateway");
    let rebound = UdpSocket::bind((gw, 53));
    assert!(
        rebound.is_err(),
        "session DNS gateway must still own {gw}:53 after the first process exits"
    );
}

/// The first process exits but the session stays alive: runtime, control
/// directory + socket, and the DNS gateway are all still present, and the
/// session can then be shut down on demand.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_instance_outlives_first_process() {
    let name = "inst-life-outlive";
    let mut inst = SandboxInstance::launch(
        base_policy_with_gateway().build().unwrap().with_name(name),
        &["sh", "-c", "printf first; exit 0"],
    )
    .await
    .expect("launch");
    let child_pid = inst.pid().expect("launched process pid");
    assert_eq!(inst.phase(), InstancePhase::Live);

    let result = inst.wait_main().await.expect("wait for first process");
    assert!(result.success(), "first process must exit 0");
    assert_eq!(
        result.stdout.as_deref(),
        Some(&b"first"[..]),
        "capture must survive the session, not be tied to the process wait"
    );

    // Process is reaped — but the session must be fully alive.
    assert!(
        process_is_gone(child_pid),
        "the first process must be reaped after wait_child"
    );
    assert_eq!(
        inst.phase(),
        InstancePhase::Live,
        "the session must not die with its first process"
    );
    assert_session_resources_live(&inst);

    inst.shutdown().await.expect("controlled shutdown");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        !inst.control_dir().unwrap().exists(),
        "shutdown must remove the session control dir"
    );
}

/// `shutdown` is idempotent: repeated calls do not panic, return the same
/// `Ok`, and leave the session in the terminal `ShutDown` phase — both after a
/// completed first process and when a live process has to be killed. The
/// three-call acceptance also asserts the control directory is gone and stays
/// gone across the repeats (F2.2: shutdown × 3, no panic, no residue).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shutdown_is_idempotent() {
    // Path 1: the first process already exited.
    let mut inst = SandboxInstance::launch(
        base_policy().build().unwrap().with_name("inst-life-idem-exited"),
        &["sh", "-c", "exit 0"],
    )
    .await
    .expect("launch");
    let dir = inst
        .control_dir()
        .expect("session control dir")
        .clone();
    assert!(dir.exists(), "control dir must exist while the session is live");
    inst.wait_main().await.expect("wait for first process");

    inst.shutdown().await.expect("first shutdown");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        !dir.exists(),
        "shutdown must remove the control dir (path 1)"
    );
    inst.shutdown().await.expect("second shutdown must be Ok, not panic");
    inst.shutdown().await.expect("third shutdown must be Ok, not panic");
    assert_eq!(
        inst.phase(),
        InstancePhase::ShutDown,
        "phase must stay terminal across repeated shutdowns"
    );
    assert!(
        !dir.exists(),
        "control dir must stay gone across repeated shutdowns (path 1)"
    );

    // Path 2: shutdown lands while the first process is still running — it is
    // killed and reaped, and repeated shutdowns stay no-ops.
    let mut inst = SandboxInstance::launch(
        base_policy().build().unwrap().with_name("inst-life-idem-live"),
        &["sleep", "100"],
    )
    .await
    .expect("launch");
    let child_pid = inst.pid().expect("launched process pid");
    let dir = inst
        .control_dir()
        .expect("session control dir")
        .clone();
    assert!(dir.exists(), "control dir must exist while the session is live");

    inst.shutdown().await.expect("shutdown with a live process");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        process_is_gone(child_pid),
        "a live process must not survive its session's shutdown"
    );
    assert!(
        !dir.exists(),
        "shutdown must remove the control dir (path 2)"
    );
    inst.shutdown().await.expect("repeat shutdown after live kill");
    inst.shutdown().await.expect("repeat shutdown after live kill");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        process_is_gone(child_pid),
        "repeated shutdowns must not re-create a process"
    );
    assert!(
        !dir.exists(),
        "control dir must stay gone across repeated shutdowns (path 2)"
    );
}

/// A session shut down *without* `wait_child` still closes every
/// session-owned handle while the instance is alive (F2.1 review B-5): the
/// direct child's pidfd and the HTTP ACL proxy handle used to survive until
/// `Drop`, contradicting `shutdown`'s "every session-owned resource released"
/// contract. The pidfd and the proxy's loopback listener both show up in the
/// process fd count, so the count must return to its baseline right after
/// `shutdown` — before the instance is dropped. Two more shutdown calls stay
/// no-ops and leave no residue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shutdown_without_wait_closes_pidfd_and_http_acl() {
    let name = "inst-life-live-b5";
    let fd_baseline = open_fd_count();
    let mut inst = SandboxInstance::launch(
        base_policy()
            .http_allow("GET 127.0.0.1/anything")
            .build()
            .unwrap()
            .with_name(name),
        &["sleep", "60"],
    )
    .await
    .expect("launch");
    let child_pid = inst.pid().expect("launched process pid");
    let dir = inst
        .control_dir()
        .expect("session control dir")
        .clone();

    inst.shutdown().await.expect("shutdown with a live process");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        process_is_gone(child_pid),
        "a live process must not survive its session's shutdown"
    );
    assert!(!dir.exists(), "shutdown must remove the session control dir");
    assert!(
        poll_until(
            || open_fd_count() == fd_baseline,
            Duration::from_secs(10)
        )
        .await,
        "shutdown must close the session pidfd and HTTP ACL listener while \
         the instance is still alive (baseline {fd_baseline}, final {})",
        open_fd_count()
    );

    inst.shutdown().await.expect("repeat shutdown");
    inst.shutdown().await.expect("repeat shutdown");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        process_is_gone(child_pid),
        "repeated shutdowns must not re-create a process"
    );
    assert!(!dir.exists(), "control dir must stay gone");
    assert_eq!(
        open_fd_count(),
        fd_baseline,
        "repeated shutdowns must not re-create session fds"
    );
}

/// Dropping an instance immediately after `wait_child` must still apply the
/// recorded COW disposition (F2.1 review B-3 semantics). `wait_child` hands
/// the COW branch to the instance before it returns, so the instance's `Drop`
/// backstop commits it exactly once — the same behavior the historical
/// `Sandbox::wait`-then-drop path had before the M0 lift.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_drop_after_wait_child_disposes_cow_branch() {
    let workdir = std::env::temp_dir().join(format!(
        "sandlock-inst-life-cow-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir).expect("create COW workdir");
    let new_file = workdir.join("waited.txt");

    let mut inst = SandboxInstance::launch(
        base_policy()
            .fs_write(&workdir)
            .workdir(&workdir)
            .on_exit(BranchAction::Commit)
            .build()
            .unwrap()
            .with_name("inst-life-cow-b3"),
        &["sh", "-c", &format!("touch {}", new_file.display())],
    )
    .await
    .expect("launch");
    let result = inst.wait_main().await.expect("wait for first process");
    assert!(result.success(), "touch must succeed");
    assert_eq!(
        inst.phase(),
        InstancePhase::Live,
        "wait_child must leave the session alive"
    );

    // The branch was handed to the instance by wait_child; Drop's backstop
    // commits it. Before the B-3 fix the branch still sat in the shared
    // supervisor state, so Drop cleaned it up instead of committing.
    drop(inst);
    assert!(
        new_file.exists(),
        "dropping after wait_child must apply the recorded Commit disposition"
    );

    let _ = std::fs::remove_dir_all(&workdir);
}

/// F2.2 escalation: a child that ignores the graceful shutdown request (TERM)
/// stays alive through the grace window and is then SIGKILLed by the §5.3
/// escalation ladder, after which shutdown completes normally — control dir
/// gone, process gone, terminal phase.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shutdown_escalates_after_grace_for_term_ignoring_child() {
    let name = "inst-life-escalate";
    let marker = std::env::temp_dir().join(format!(
        "sandlock-f22-escalate-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker);
    let marker_arg = marker.display().to_string();

    // The shell ignores TERM and keeps looping (each `sleep` child may or may
    // not inherit the ignore; the direct child is what shutdown waits on, and
    // it survives TERM either way), so only the escalation SIGKILL ends it.
    let mut inst = SandboxInstance::launch(
        base_policy().build().unwrap().with_name(name),
        &[
            "sh",
            "-c",
            &format!("trap '' TERM; touch {marker_arg}; while :; do sleep 1; done"),
        ],
    )
    .await
    .expect("launch");
    let child_pid = inst.pid().expect("launched process pid");
    assert!(
        poll_until(|| marker.exists(), Duration::from_secs(10)).await,
        "the child must install its TERM trap before shutdown is tested"
    );

    let grace = Duration::from_millis(800);
    let started = Instant::now();
    inst.shutdown_with_grace(grace)
        .await
        .expect("shutdown with escalation");
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(600),
        "shutdown must honor the grace window before escalating \
         (grace {grace:?}, elapsed {elapsed:?})"
    );
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        process_is_gone(child_pid),
        "escalation must kill the TERM-ignoring child"
    );
    assert!(
        !inst.control_dir().unwrap().exists(),
        "escalation shutdown must still remove the control dir"
    );

    let _ = std::fs::remove_file(&marker);
}

/// I-1 regression: when the direct child exits compliantly inside the grace
/// window (here: it traps TERM and exits 0), `shutdown` must still run the
/// §5.3 step-3 group SIGKILL sweep — a same-group descendant that ignored
/// TERM must not outlive the session just because the direct child itself
/// cooperated. The direct child keeps a foreground loop running (so it is
/// still alive when shutdown starts) while a backgrounded `sh` ignores TERM
/// and records its own pid after installing the ignore, then `exec`s a long
/// `sleep` (so it performs no further supervisor-gated syscalls after
/// shutdown — a looping child would otherwise be SIGSYS-killed by the closed
/// notif fd and mask the leak). Shutdown must reap the direct child with its
/// compliant exit status *and* kill the background descendant via the group
/// sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shutdown_group_sweep_after_compliant_grace_exit() {
    let marker = std::env::temp_dir().join(format!(
        "sandlock-f22-sweep-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker);
    let marker_arg = marker.display().to_string();

    let mut inst = SandboxInstance::launch(
        base_policy().build().unwrap().with_name("inst-life-sweep-i1"),
        &[
            "sh",
            "-c",
            &format!(
                "trap 'exit 0' TERM; \
                 sh -c 'trap \"\" TERM; echo $$ > {marker_arg}; \
                         exec sleep 1000' & \
                 while :; do sleep 1; done"
            ),
        ],
    )
    .await
    .expect("launch");
    let child_pid = inst.pid().expect("launched process pid");
    assert!(
        poll_until(|| marker.exists(), Duration::from_secs(10)).await,
        "the TERM-ignoring background child must install its trap before \
         shutdown is tested"
    );
    let bg_pid: i32 = std::fs::read_to_string(&marker)
        .expect("marker must hold the background child's pid")
        .trim()
        .parse()
        .expect("marker pid must parse");
    assert!(
        !process_is_gone(bg_pid),
        "the background child must still be running when shutdown starts"
    );

    let grace = Duration::from_secs(2);
    inst.shutdown_with_grace(grace)
        .await
        .expect("shutdown with compliant direct child");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    assert!(
        process_is_gone(child_pid),
        "the direct child must not survive its session's shutdown"
    );

    // The direct child exited compliantly (exit 0) inside the grace window:
    // shutdown recorded that status, which later wait_child hands back.
    let result = inst.wait_main().await.expect("wait_main after shutdown");
    assert!(
        result.success(),
        "the compliant direct child's exit status must be recorded (stderr: {:?})",
        result.stderr
    );

    // The group sweep must have killed the TERM-ignoring background
    // descendant even though the direct child never needed escalation.
    assert!(
        poll_until(|| process_is_gone(bg_pid), Duration::from_secs(5)).await,
        "the same-group TERM-ignoring descendant must not survive a compliant \
         shutdown (bg pid {bg_pid})"
    );

    let _ = std::fs::remove_file(&marker);
}

/// `shutdown` releases the F1.3 control directory (hashed dir + token +
/// socket) and the DNS gateway, and leaves no leftover process or fd behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shutdown_releases_control_dir_and_dns_gateway() {
    let name = "inst-life-release";
    let fd_baseline = open_fd_count();
    let mut inst = SandboxInstance::launch(
        base_policy_with_gateway().build().unwrap().with_name(name),
        &["sh", "-c", "exit 0"],
    )
    .await
    .expect("launch");
    let child_pid = inst.pid().expect("launched process pid");
    let dir = inst.control_dir().expect("session control dir").clone();
    let gw = inst
        .dns_gateway_addr()
        .expect("wildcard rules must allocate a session DNS gateway");

    assert_eq!(dir, control::sandbox_dir(name));
    assert!(dir.exists(), "control dir must exist while the session is live");
    inst.wait_main().await.expect("wait for first process");
    assert_session_resources_live(&inst);

    inst.shutdown().await.expect("shutdown");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);

    // Control directory: files (token/pid/name/mode/control.sock) removed and
    // the dir itself gone; the socket no longer accepts connections.
    assert!(
        !dir.exists(),
        "shutdown must remove the session control dir: {:?}",
        dir
    );
    assert!(!control::sock_path(&dir).exists(), "control.sock must be removed");
    assert!(
        UnixStream::connect(control::sock_path(&dir)).is_err(),
        "the control socket must refuse connections after shutdown"
    );

    // No leftover process (wait_child reaped it; shutdown must not re-create
    // anything).
    assert!(
        process_is_gone(child_pid),
        "no session process may survive shutdown"
    );

    // No leftover fd: the gateway socket, notif fd, control listener and drain
    // fds close once their tasks are aborted (abort is asynchronous, so poll).
    assert!(
        poll_until(
            || open_fd_count() == fd_baseline,
            Duration::from_secs(10)
        )
        .await,
        "shutdown must release every session fd (baseline {fd_baseline}, \
         final {})",
        open_fd_count()
    );

    // DNS gateway: the `:53` listener is gone, so the address is bindable
    // again (UDP has no TIME_WAIT).
    let rebound = UdpSocket::bind((gw, 53));
    assert!(
        rebound.is_ok(),
        "shutdown must release the DNS gateway address {gw}:53 (err: {:?})",
        rebound.err()
    );
}

/// The legacy one-shot paths (`run` / `popen` / `spawn`+`wait`) drive a
/// one-shot instance and must reclaim every resource exactly as before: the
/// control dir disappears, the child is reaped, and a wildcard-configured run
/// releases its DNS gateway.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_legacy_run_still_reclaims_all_resources() {
    // run (capture) with a DNS gateway: after run returns, the session the
    // sandbox drove is already shut down.
    let mut run_sb = base_policy_with_gateway()
        .build()
        .unwrap()
        .with_name("inst-life-legacy-run");
    let result = run_sb.run(&["echo", "legacy"]).await.expect("run");
    assert!(result.success());
    assert_eq!(result.stdout_str(), Some("legacy"));
    let gw = run_sb
        .dns_gateway_addr()
        .expect("wildcard run must allocate a gateway");
    let run_pid = run_sb.pid().expect("run pid");
    assert!(
        poll_until(
            || UdpSocket::bind((gw, 53)).is_ok(),
            Duration::from_secs(10)
        )
        .await,
        "legacy run must release its DNS gateway address {gw}:53"
    );
    assert!(
        process_is_gone(run_pid),
        "legacy run must reap its child"
    );
    assert!(
        !control::sandbox_dir("inst-life-legacy-run").exists(),
        "legacy run must remove its control dir"
    );
    drop(run_sb);
    assert!(
        !control::sandbox_dir("inst-life-legacy-run").exists(),
        "dropping the spent sandbox must leave no control dir behind"
    );

    // popen: streaming stdio, then Process::wait drives the one-shot teardown.
    let mut popen_sb = base_policy()
        .build()
        .unwrap()
        .with_name("inst-life-legacy-popen");
    let mut child = popen_sb
        .popen(
            &["echo", "p"],
            StdioMode::Inherit,
            StdioMode::Piped,
            StdioMode::Inherit,
        )
        .await
        .expect("popen");
    let mut stdout = String::new();
    std::fs::File::from(child.take_stdout().expect("stdout pipe"))
        .read_to_string(&mut stdout)
        .expect("read stdout");
    assert_eq!(stdout, "p\n");
    let result = child.wait().await.expect("popen wait");
    assert!(result.success());
    let popen_pid = popen_sb.pid().expect("popen pid");
    assert!(process_is_gone(popen_pid), "popen wait must reap its child");
    assert!(
        !control::sandbox_dir("inst-life-legacy-popen").exists(),
        "popen wait must remove its control dir"
    );

    // spawn + kill + wait: the kill path must also reclaim everything.
    let mut spawn_sb = base_policy()
        .build()
        .unwrap()
        .with_name("inst-life-legacy-spawn");
    spawn_sb
        .spawn(&["sh", "-c", "sleep 60"])
        .await
        .expect("spawn");
    let spawn_pid = spawn_sb.pid().expect("spawn pid");
    spawn_sb.kill().expect("kill");
    let result = spawn_sb.wait().await.expect("spawn wait");
    assert!(!result.success(), "a killed child must not report success");
    assert!(process_is_gone(spawn_pid), "spawn wait must reap its child");
    assert!(
        !control::sandbox_dir("inst-life-legacy-spawn").exists(),
        "spawn wait must remove its control dir"
    );
}

/// F2.3 (a): a live session's stats surface reconciles and reports the M0
/// single-child truth — once the supervisor's pidfd watcher has registered
/// the session's root process, `proc_count_vs_live` is 0 (bookkeeping matches
/// live watchers), `children_live` is 1 (the session's one direct child is
/// live and unreaped), and `instance_state` is `Live`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_instance_stats_live_reconciled() {
    let mut inst = SandboxInstance::launch(
        base_policy().build().unwrap().with_name("inst-f23-live-stats"),
        &["sleep", "60"],
    )
    .await
    .expect("launch");

    let want = InstanceStats {
        proc_count_vs_live: 0,
        mediation_downgrades: 0,
        children_live: 1,
        instance_state: InstancePhase::Live,
    };
    let settled = wait_for_instance_stats(&inst, want, Duration::from_secs(15)).await;
    assert_eq!(
        settled,
        want,
        "live session must reconcile proc_count against live watchers with \
         its single child live and phase Live; got {settled:?}",
    );

    inst.shutdown_with_grace(Duration::from_millis(200))
        .await
        .expect("cleanup shutdown");
}

/// F2.3 (b): once a one-shot `Sandbox` run has ended (`wait()` runs
/// `wait_child` + `shutdown`), the stats surface is terminal and internally
/// consistent: `instance_state` is `ShutDown`, `children_live` is 0 (the
/// direct child was reaped), and the supervisor accounting has quiesced — no
/// live watcher remains, `proc_count` still holds the root baseline slot the
/// session retains for legacy post-wait introspection, and the F2.3
/// `proc_count_vs_live` deviation settles to +1, exactly the F1.4 `drift`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_one_shot_stats_terminal_after_shutdown() {
    let mut sb = base_policy()
        .build()
        .unwrap()
        .with_name("inst-f23-terminal-stats");
    sb.create_interactive(&["sh", "-c", "exit 0"])
        .await
        .expect("create_interactive");
    sb.start().expect("start");
    let result = sb.wait().await.expect("one-shot wait");
    assert!(result.success(), "one-shot run must exit 0");

    // The instance side (phase/child) is terminal as soon as wait() returns;
    // the exit watcher's index cleanup settles a moment later, so poll the
    // reconciler until no live watcher remains.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut ps = sb.process_stats().await;
    let mut st = sb
        .stats()
        .await
        .expect("runtime must be present after a one-shot wait");
    while Instant::now() < deadline
        && (ps.live_watchers != 0 || st.proc_count_vs_live != 1)
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
        ps = sb.process_stats().await;
        st = sb
            .stats()
            .await
            .expect("runtime must be present after a one-shot wait");
    }

    assert_eq!(
        st.instance_state,
        InstancePhase::ShutDown,
        "one-shot wait must shut the session down; stats {st:?}, \
         process_stats {ps:?}",
    );
    assert_eq!(
        st.children_live,
        0,
        "the reaped direct child must report 0 live children; \
         stats {st:?}, process_stats {ps:?}",
    );
    assert_eq!(
        ps.live_watchers,
        0,
        "no pidfd watcher may survive a completed one-shot run; \
         stats {st:?}, process_stats {ps:?}",
    );
    assert_eq!(
        ps.proc_count,
        1,
        "the root baseline slot is retained for post-wait introspection; \
         stats {st:?}, process_stats {ps:?}",
    );
    assert_eq!(
        st.proc_count_vs_live,
        ps.drift,
        "the F2.3 reconciler field must agree with the F1.4 drift; \
         stats {st:?}, process_stats {ps:?}",
    );
    assert_eq!(
        st.proc_count_vs_live,
        1,
        "terminal deviation is the retained root baseline slot, not a live \
         leak; stats {st:?}, process_stats {ps:?}",
    );
}

/// F2.3 (c): `Draining` is observable on the stats surface while shutdown is
/// in flight. `shutdown_with_grace` takes `&mut self` for the whole drain, so
/// a test cannot sample `stats()` concurrently from a second task; instead it
/// cancels the shutdown future mid-grace (the documented cancellation
/// semantics: the phase stays `Draining` and the next call resumes from
/// step 1) and samples afterwards. A TERM-ignoring child keeps the grace
/// window open long enough for the cancel to land deterministically; it is a
/// single process (`exec sleep` — no grandchildren), so the reconciler is
/// free of fork-watcher bookkeeping skew while Draining.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shutdown_draining_observable_on_cancelled_shutdown() {
    let marker = std::env::temp_dir().join(format!(
        "sandlock-f23-draining-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker);
    let marker_arg = marker.display().to_string();

    let mut inst = SandboxInstance::launch(
        base_policy().build().unwrap().with_name("inst-f23-draining"),
        &[
            "sh",
            "-c",
            &format!("trap '' TERM; touch {marker_arg}; exec sleep 1000"),
        ],
    )
    .await
    .expect("launch");
    let child_pid = inst.pid().expect("launched process pid");
    assert!(
        poll_until(|| marker.exists(), Duration::from_secs(10)).await,
        "the child must install its TERM trap before shutdown is tested"
    );

    // Start shutdown with a long grace and cancel it mid-wait: the timeout
    // polls the shutdown future (advancing it through Draining into the grace
    // wait) and drops it on expiry, leaving the phase at Draining.
    let cancelled = tokio::time::timeout(
        Duration::from_millis(500),
        inst.shutdown_with_grace(Duration::from_secs(30)),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "shutdown with a 30 s grace must not finish inside 500 ms"
    );

    let draining = inst.stats().await;
    assert_eq!(
        draining,
        InstanceStats {
            proc_count_vs_live: 0,
            mediation_downgrades: 0,
            children_live: 1,
            instance_state: InstancePhase::Draining,
        },
        "a shutdown cancelled mid-grace must leave the session observable as \
         Draining with its single child still live and reconciled",
    );

    // Resume: the next shutdown call picks up from Draining and escalates
    // (zero grace), reaping the TERM-ignoring child.
    inst.shutdown_with_grace(Duration::ZERO)
        .await
        .expect("resumed shutdown");
    let terminal = inst.stats().await;
    assert_eq!(terminal.instance_state, InstancePhase::ShutDown);
    assert_eq!(terminal.children_live, 0);
    assert!(
        process_is_gone(child_pid),
        "the resumed shutdown must kill the TERM-ignoring child"
    );
    assert!(
        !inst.control_dir().unwrap().exists(),
        "the resumed shutdown must remove the control dir"
    );

    let _ = std::fs::remove_file(&marker);
}
