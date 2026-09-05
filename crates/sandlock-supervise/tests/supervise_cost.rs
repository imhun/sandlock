//! Route-B per-sandbox supervise cost harness (fork-plan F2b.4).
//!
//! Three tests against the **real `sandlock-supervise` binary** (this target
//! is run with `--release` by `scripts/test-all.sh` label `supervise_cost`,
//! so `CARGO_BIN_EXE_sandlock-supervise` is the release build — the
//! repository default release profile, not stripped; see
//! `docs/supervise-capacity.md` §5):
//!
//! * `test_per_sandbox_supervisor_rss_within_budget` — samples the
//!   supervisor's PSS (`/proc/<pid>/smaps_rollup`) at the four protocol
//!   points (idle / one command / 64 in-sandbox processes / after 1000 exec
//!   rounds) and asserts each stays within the budget derived from the
//!   2026-09-05 measurements documented in `docs/supervise-capacity.md`.
//! * `test_exec_roundtrip_latency_within_budget` — measures the exec
//!   round-trip (worker verb → child start → wait return) distribution and
//!   writes a per-round profile under `tmp/perf/`.
//! * `test_exit_frames_never_lost_over_1000_rounds` — 1000 exec+exit rounds
//!   with an exact child-id → exit-code match every round: no frame lost,
//!   none misrouted, no child id reused.
//!
//! Deterministic measurement configuration (the same cells the capacity doc
//! records): the spawned supervisor gets `TOKIO_WORKER_THREADS=1`
//! (multi-thread runtime pinned to one worker — the F2b.4 protocol's
//! single-mediator-thread cell) and `MALLOC_ARENA_MAX=1`.  The default
//! nproc-workers / default-arena variants were measured separately and are
//! recorded in the capacity doc; the per-thread cost is small and thread
//! count is a deployment performance choice (fork-plan F2b.4 conclusions).

use std::os::fd::FromRawFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Supervisor measurement config: one tokio worker thread.
const SUPERVISE_WORKER_THREADS: &str = "1";
/// Supervisor measurement config: one glibc malloc arena.
const SUPERVISE_ARENA_MAX: &str = "1";

/// PSS budgets in kB — measured 2026-09-05 in sandlock-dev:latest
/// (Linux 7.0.14-orbstack, release build, threads=1/arena=1); see
/// `docs/supervise-capacity.md` §2/§4.1.  Values are the measured point +
/// margin (idle ≈ 4.1-4.5 MB measured → 6 MB budget; after 1000 rounds
/// ≈ 4.7-5.2 MB measured → 6.5 MB budget).  No preset/legacy number: these
/// derive from the in-repo measurement recorded in that doc.
const BUDGET_IDLE_KB: u64 = 6_144;
const BUDGET_ONE_CMD_KB: u64 = 6_144;
const BUDGET_64_PROCS_KB: u64 = 6_144;
const BUDGET_AFTER_1000_KB: u64 = 6_656;

/// Exec round-trip latency budgets (milliseconds).  The wait leg has a
/// ~100 ms implementation floor: sandlock-init reaps exited children on its
/// 100 ms control-channel poll (`REAP_POLL_MS`, crates/sandlock-core/src/
/// init/mod.rs), so one exec+exit round measures ≈ 103 ms p50 in the
/// sandlock-dev:latest environment.  Budgets are the measured p50/p95 plus
/// margin (see docs/supervise-capacity.md), with a generous max bound for
/// scheduler stalls — a regression that removes the floor or a stall that
/// pushes p95 beyond the bound both fail here.
const LATENCY_P50_BUDGET_MS: f64 = 200.0;
const LATENCY_P95_BUDGET_MS: f64 = 300.0;
const LATENCY_MAX_BUDGET_MS: f64 = 2_000.0;

/// Exit-code rounds each test drives (the protocol's 1000-round point).
const EXIT_ROUNDS: usize = 1000;
/// Sequential (per-round latency) rounds the latency test measures after a
/// warm-up; the distribution is very narrow (≈ ±2 ms), so 300 rounds give
/// stable p50/p95 without re-paying the 100 ms floor 1000 times per gate.
const LATENCY_ROUNDS: usize = 300;
/// Warm-up rounds before latency sampling (first rounds include cold path
/// effects such as child-table growth / page faults).
const LATENCY_WARMUP: usize = 20;
/// Concurrent execs per batch during the 1000-round passes (whole-box
/// max_processes is 256; 48 keeps headroom while init's 100 ms reap poll
/// reaps a whole batch at once).
const EXEC_BATCH: usize = 48;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-supervise")
}

fn repo_tmp_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest.join("../../tmp");
    std::fs::create_dir_all(&dir).expect("create repo tmp dir");
    dir
}

fn perf_dir() -> PathBuf {
    let dir = repo_tmp_dir().join("perf");
    std::fs::create_dir_all(&dir).expect("create repo tmp/perf dir");
    dir
}

fn write_policy(name: &str, body: &str) -> PathBuf {
    let path = repo_tmp_dir().join(format!("supervise-cost-{name}-{}.json", std::process::id()));
    std::fs::write(&path, body).expect("write policy file");
    path
}

fn write_program(name: &str) -> PathBuf {
    let path = repo_tmp_dir().join(format!(
        "supervise-cost-{name}-program-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        serde_json::json!({ "argv": ["/bin/sleep", "900"] }).to_string(),
    )
    .expect("write program file");
    path
}

/// Base filesystem grant set for launching real system programs under a
/// sandbox (mirrors the other supervise/core integration suites).
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
/// grants.
fn instance_policy() -> String {
    serde_json::json!({ "fs_readable": base_read_paths() }).to_string()
}

/// Per-process control-root override shared by every test in this binary
/// (spawned supervise processes inherit it), so instance runtime dirs never
/// collide with another suite's.
fn isolate_ctl_root() -> PathBuf {
    static SET: std::sync::Once = std::sync::Once::new();
    let root = repo_tmp_dir().join(format!("supervise-cost-ctl-{}", std::process::id()));
    SET.call_once(|| {
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var("SANDBOX_CTL_ROOT", &root);
    });
    root
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Spawn `sandlock-supervise --serve` (fd handoff) with an M0 `sleep 900`
/// workload under the deterministic measurement config, and return the child
/// plus the worker end the test drives.
fn spawn_measured_supervisor(
    policy: &std::path::Path,
    program: &std::path::Path,
) -> (Child, UnixStream) {
    use std::os::unix::process::CommandExt;

    let (worker, server) = UnixStream::pair().expect("control socketpair");
    let control_fd = server.as_raw_fd();
    let mut cmd = Command::new(bin());
    cmd.arg("--policy")
        .arg(policy)
        .arg("--uid")
        .arg(euid().to_string())
        .arg("--control-fd")
        .arg(control_fd.to_string())
        .arg("--program")
        .arg(program)
        .arg("--serve")
        .env("TOKIO_WORKER_THREADS", SUPERVISE_WORKER_THREADS)
        .env("MALLOC_ARENA_MAX", SUPERVISE_ARENA_MAX)
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
    let child = cmd.spawn().expect("spawn measured supervise");
    drop(server);
    (child, worker)
}

/// Read one length-prefixed control response.
fn read_control_response(worker: &mut UnixStream) -> serde_json::Value {
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

/// Send one control frame (with optional SCM_RIGHTS fds) and read the
/// response, with a generous wall-clock bound so a lost frame fails the test
/// instead of hanging the gate.
fn roundtrip_frame_with_fds(
    worker: &mut UnixStream,
    body: &serde_json::Value,
    fds: &[i32],
) -> serde_json::Value {
    worker
        .set_read_timeout(Some(Duration::from_secs(120)))
        .expect("read timeout");
    let bytes = serde_json::to_vec(body).expect("serialize frame");
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(&bytes);
    sandlock_core::init::fdpass::send_with_fds(worker, &frame, fds)
        .expect("write control frame with fds");
    read_control_response(worker)
}

fn roundtrip_frame(worker: &mut UnixStream, body: &serde_json::Value) -> serde_json::Value {
    roundtrip_frame_with_fds(worker, body, &[])
}

/// Create the three pipes an exec worker owns: returns the three host ends
/// plus the three child-side ends to send over SCM_RIGHTS.
fn make_exec_stdio() -> (
    std::os::unix::io::OwnedFd,
    std::os::unix::io::OwnedFd,
    std::os::unix::io::OwnedFd,
    [i32; 3],
) {
    let mut pipes = [[0i32; 2]; 3];
    for p in pipes.iter_mut() {
        assert_eq!(
            unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "pipe2: {}",
            std::io::Error::last_os_error()
        );
    }
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

/// Send an `exec` verb for `argv` and return the child id.  The three
/// child-side stdio ends are closed here, as in production (the host ends
/// are the caller's to keep/drop).
fn exec_verb(worker: &mut UnixStream, argv: &[&str]) -> u64 {
    let (_h0, _h1, _h2, child_ends) = make_exec_stdio();
    let resp = roundtrip_frame_with_fds(
        worker,
        &serde_json::json!({ "v": 1, "verb": "exec", "args": { "argv": argv } }),
        &child_ends,
    );
    for fd in child_ends {
        unsafe {
            libc::close(fd);
        }
    }
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "exec: {resp:?}");
    resp["data"]["child_id"].as_u64().expect("exec child id")
}

fn wait_child_verb(worker: &mut UnixStream, child_id: u64) -> serde_json::Value {
    let resp = roundtrip_frame(
        worker,
        &serde_json::json!({
            "v": 1,
            "verb": "wait_child",
            "args": { "child_id": child_id },
        }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "wait: {resp:?}");
    resp["data"].clone()
}

fn kill_child_verb(worker: &mut UnixStream, child_id: u64) {
    let resp = roundtrip_frame(
        worker,
        &serde_json::json!({
            "v": 1,
            "verb": "kill_child",
            "args": { "child_id": child_id, "signum": 9 },
        }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "kill: {resp:?}");
}

fn stats_verb(worker: &mut UnixStream) -> serde_json::Value {
    let resp = roundtrip_frame(
        worker,
        &serde_json::json!({ "v": 1, "verb": "stats", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "stats: {resp:?}");
    resp["data"].clone()
}

/// Poll `stats` until the instance settles to exactly `want_live` live
/// children with zero reconciler drift (the F2b.3 settled-snapshot shape).
fn wait_stats_settled(worker: &mut UnixStream, want_live: i64) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut settled = false;
    while Instant::now() < deadline {
        let st = stats_verb(worker);
        if st["instance_state"] == "Live"
            && st["children_live"].as_i64() == Some(want_live)
            && st["proc_count_vs_live"].as_i64() == Some(0)
        {
            settled = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        settled,
        "stats must settle to Live with {want_live} live children and zero drift"
    );
}

/// PSS (and RSS/threads) of `pid` via `/proc/<pid>/smaps_rollup` + status.
fn sample_pss(pid: i32) -> (u64, u64, u64) {
    let rollup = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))
        .expect("read smaps_rollup (Linux gate env)");
    let mut pss = None;
    let mut rss = None;
    for line in rollup.lines() {
        if let Some(v) = line.strip_prefix("Pss:") {
            pss = v.split_whitespace().next().and_then(|s| s.parse().ok());
        } else if let Some(v) = line.strip_prefix("Rss:") {
            rss = v.split_whitespace().next().and_then(|s| s.parse().ok());
        }
    }
    let pss = pss.expect("Pss field");
    let rss = rss.expect("Rss field");
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read status");
    let threads = status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|l| l.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .expect("Threads field");
    (pss, rss, threads)
}

/// Median-of-3 PSS sample after letting the process settle ~600 ms.
fn settle_and_sample_pss(pid: i32, label: &str) -> (u64, u64, u64) {
    std::thread::sleep(Duration::from_millis(600));
    let mut samples = Vec::new();
    let mut rss = 0;
    let mut threads = 0;
    for _ in 0..3 {
        let (p, r, t) = sample_pss(pid);
        samples.push(p);
        rss = r;
        threads = t;
        std::thread::sleep(Duration::from_millis(200));
    }
    samples.sort_unstable();
    let pss = samples[1];
    eprintln!("[supervise_cost] {label}: Pss={pss}kB Rss={rss}kB threads={threads}");
    (pss, rss, threads)
}

/// Exec-only leg of one exit round: returns the child id.
fn exec_exit_round_exec_only(worker: &mut UnixStream, want_code: i32) -> u64 {
    let script = format!("exit {want_code}");
    let argv = ["/bin/sh", "-c", script.as_str()];
    let (_h0, _h1, _h2, child_ends) = make_exec_stdio();
    let resp = roundtrip_frame_with_fds(
        worker,
        &serde_json::json!({
            "v": 1,
            "verb": "exec",
            "args": { "argv": argv },
        }),
        &child_ends,
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "exec: {resp:?}");
    let child_id = resp["data"]["child_id"].as_u64().expect("exec child id");
    for fd in child_ends {
        unsafe {
            libc::close(fd);
        }
    }
    child_id
}

/// Drive `rounds` exec+exit rounds (batched) over the fd transport,
/// asserting an exact child-id → exit-code match every round and that no
/// child id is reused.  Returns every child id in wait order.
fn drive_exit_rounds_batched(worker: &mut UnixStream, rounds: usize) -> Vec<u64> {
    let mut all_ids = Vec::with_capacity(rounds);
    let mut base = 0usize;
    while base < rounds {
        let end = (base + EXEC_BATCH).min(rounds);
        // Exec a whole batch first (each exec is ~1-2 ms); init's 100 ms
        // reap poll then reaps the batch and routes every exit frame.
        let mut batch = Vec::with_capacity(end - base);
        for i in base..end {
            let code = (i % 256) as i32;
            batch.push((code, exec_exit_round_exec_only(worker, code)));
        }
        for (code, child_id) in batch {
            assert!(!all_ids.contains(&child_id), "child id {child_id} reused");
            let w = roundtrip_frame(
                worker,
                &serde_json::json!({
                    "v": 1,
                    "verb": "wait_child",
                    "args": { "child_id": child_id },
                }),
            );
            assert_eq!(w["ok"], serde_json::Value::Bool(true), "wait: {w:?}");
            let got = w["data"]["code"].as_i64();
            assert_eq!(
                got,
                Some(code as i64),
                "child {child_id} (round {}) must exit with exactly {code}, \
                 got: {w:?}",
                all_ids.len()
            );
            all_ids.push(child_id);
        }
        base = end;
    }
    all_ids
}

/// One exec+exit round over the fd transport; `want_code` must be the
/// child's exact exit status.  Returns the round's wall time in ms.
fn exec_exit_round(worker: &mut UnixStream, want_code: i32) -> f64 {
    let script = format!("exit {want_code}");
    let argv = ["/bin/sh", "-c", script.as_str()];
    let start = Instant::now();
    let (_h0, _h1, _h2, child_ends) = make_exec_stdio();
    let resp = roundtrip_frame_with_fds(
        worker,
        &serde_json::json!({
            "v": 1,
            "verb": "exec",
            "args": { "argv": argv },
        }),
        &child_ends,
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "exec: {resp:?}");
    let child_id = resp["data"]["child_id"].as_u64().expect("exec child id");
    for fd in child_ends {
        unsafe {
            libc::close(fd);
        }
    }
    let w = roundtrip_frame(
        worker,
        &serde_json::json!({
            "v": 1,
            "verb": "wait_child",
            "args": { "child_id": child_id },
        }),
    );
    let elapsed_ms = start.elapsed().as_secs_f64() * 1e3;
    assert_eq!(w["ok"], serde_json::Value::Bool(true), "wait: {w:?}");
    let got = w["data"]["code"].as_i64();
    assert_eq!(
        got,
        Some(want_code as i64),
        "child {child_id} must exit with exactly {want_code}, got: {w:?}"
    );
    elapsed_ms
}

fn shutdown_worker_and_wait(
    child: Child,
    worker: &mut UnixStream,
    policy: &std::path::Path,
    program: &std::path::Path,
) {
    let resp = roundtrip_frame(
        worker,
        &serde_json::json!({ "v": 1, "verb": "shutdown", "args": {} }),
    );
    assert_eq!(
        resp["ok"],
        serde_json::Value::Bool(true),
        "shutdown: {resp:?}"
    );
    let out = child.wait_with_output().expect("wait measured supervise");
    assert!(
        out.status.success(),
        "generation must exit 0 after shutdown; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(policy);
    let _ = std::fs::remove_file(program);
}

// ============================================================
// test_per_sandbox_supervisor_rss_within_budget
// ============================================================

/// Four-point PSS sampling of one release supervisor (fd transport, M0 sleep
/// parked): idle → one command → 64 in-sandbox processes → after 1000 exec
/// rounds.  Every point must stay under the measured budget (constants
/// above, derivation in docs/supervise-capacity.md).
#[test]
fn test_per_sandbox_supervisor_rss_within_budget() {
    isolate_ctl_root();
    let policy = write_policy("rss", &instance_policy());
    let program = write_program("rss");
    let (child, mut worker) = spawn_measured_supervisor(&policy, &program);

    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "run", "args": {} }),
    );
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "run: {resp:?}");
    let launch_pid = resp["data"]["pid"].as_i64().expect("run pid") as i32;
    wait_stats_settled(&mut worker, 1);
    let pid = child.id() as i32;

    // Point 1: 空载 — the live generation with only its M0 process.
    let (idle, idle_rss, idle_threads) = settle_and_sample_pss(pid, "idle_live_m0");

    // Point 2: one command — one extra live exec child.
    let child1 = exec_verb(&mut worker, &["/bin/sleep", "900"]);
    wait_stats_settled(&mut worker, 2);
    let (one, one_rss, one_threads) = settle_and_sample_pss(pid, "one_cmd");

    // Point 3: 64 in-sandbox processes (M0 + 63 exec children).
    let mut extra = Vec::new();
    for _ in 0..62 {
        extra.push(exec_verb(&mut worker, &["/bin/sleep", "900"]));
    }
    wait_stats_settled(&mut worker, 64);
    let (p64, p64_rss, p64_threads) = settle_and_sample_pss(pid, "64_procs");

    // Back to M0-only: kill + reap all 63 exec children.
    for cid in std::iter::once(child1).chain(extra) {
        kill_child_verb(&mut worker, cid);
        let w = wait_child_verb(&mut worker, cid);
        assert_eq!(
            w["killed"],
            serde_json::Value::Bool(true),
            "extra child {cid} must report Killed"
        );
    }
    wait_stats_settled(&mut worker, 1);

    // Point 4: after 1000 exec rounds (batched; exit routing asserted here
    // too so the PSS sample is taken over a fully-verified pass).
    let all_ids = drive_exit_rounds_batched(&mut worker, EXIT_ROUNDS);
    assert_eq!(all_ids.len(), EXIT_ROUNDS);
    wait_stats_settled(&mut worker, 1);
    let (after, after_rss, after_threads) = settle_and_sample_pss(pid, "after_1000_rounds");

    // Profile artifact (not committed; evidence for the capacity doc).
    let profile = serde_json::json!({
        "pid": pid,
        "launch_pid": launch_pid,
        "points": {
            "idle_live_m0": { "pss_kB": idle, "rss_kB": idle_rss, "threads": idle_threads },
            "one_cmd": { "pss_kB": one, "rss_kB": one_rss, "threads": one_threads },
            "64_procs": { "pss_kB": p64, "rss_kB": p64_rss, "threads": p64_threads },
            "after_1000_rounds": { "pss_kB": after, "rss_kB": after_rss, "threads": after_threads },
        },
        "budgets_kB": {
            "idle": BUDGET_IDLE_KB,
            "one_cmd": BUDGET_ONE_CMD_KB,
            "64_procs": BUDGET_64_PROCS_KB,
            "after_1000": BUDGET_AFTER_1000_KB,
        },
    });
    std::fs::write(
        perf_dir().join("supervise_cost_rss_4points.json"),
        serde_json::to_string_pretty(&profile).expect("serialize profile"),
    )
    .expect("write rss profile");

    assert!(
        idle <= BUDGET_IDLE_KB,
        "idle PSS {idle} kB exceeds budget {BUDGET_IDLE_KB} kB (measured + margin; \
         see docs/supervise-capacity.md)"
    );
    assert!(
        one <= BUDGET_ONE_CMD_KB,
        "one-command PSS {one} kB exceeds budget {BUDGET_ONE_CMD_KB} kB"
    );
    assert!(
        p64 <= BUDGET_64_PROCS_KB,
        "64-process PSS {p64} kB exceeds budget {BUDGET_64_PROCS_KB} kB"
    );
    assert!(
        after <= BUDGET_AFTER_1000_KB,
        "post-1000-round PSS {after} kB exceeds budget {BUDGET_AFTER_1000_KB} kB \
         (slow-leak guard)"
    );

    shutdown_worker_and_wait(child, &mut worker, &policy, &program);
}

// ============================================================
// test_exec_roundtrip_latency_within_budget
// ============================================================

/// Exec round-trip latency (worker verb → child start → wait return) over
/// the fd transport with an M0 parked.  Per-round times and the p50/p95/max
/// summary are written to tmp/perf/; p50/p95/max must stay within the
/// measured budgets (see docs/supervise-capacity.md).
#[test]
fn test_exec_roundtrip_latency_within_budget() {
    isolate_ctl_root();
    let policy = write_policy("latency", &instance_policy());
    let program = write_program("latency");
    let (child, mut worker) = spawn_measured_supervisor(&policy, &program);
    wait_stats_settled(&mut worker, 1);

    for i in 0..LATENCY_WARMUP {
        exec_exit_round(&mut worker, (i % 256) as i32);
    }
    let mut per_round = Vec::with_capacity(LATENCY_ROUNDS);
    for i in 0..LATENCY_ROUNDS {
        per_round.push(exec_exit_round(&mut worker, (i % 256) as i32));
    }
    per_round.sort_by(|a, b| a.partial_cmp(b).expect("finite duration"));
    let n = per_round.len();
    let p50 = per_round[n / 2];
    let p90 = per_round[(n as f64 * 0.90) as usize];
    let p95 = per_round[(n as f64 * 0.95) as usize];
    let p99 = per_round[(n as f64 * 0.99) as usize];
    let max = per_round[n - 1];
    let mean: f64 = per_round.iter().sum::<f64>() / n as f64;

    let mut profile = String::new();
    profile.push_str(&format!(
        "# supervise exec round-trip latency (release, threads={}, arena={})\n",
        SUPERVISE_WORKER_THREADS, SUPERVISE_ARENA_MAX
    ));
    profile.push_str(&format!(
        "# rounds={n} mean_ms={mean:.3} p50_ms={p50:.3} p90_ms={p90:.3} \
         p95_ms={p95:.3} p99_ms={p99:.3} max_ms={max:.3}\n",
    ));
    for (i, ms) in per_round.iter().enumerate() {
        profile.push_str(&format!("round {i}: {ms:.3}\n"));
    }
    std::fs::write(
        perf_dir().join("supervise_exec_roundtrip_latency.log"),
        profile,
    )
    .expect("write latency profile");
    eprintln!(
        "[supervise_cost] latency mean={mean:.2}ms p50={p50:.2}ms p95={p95:.2}ms \
         max={max:.2}ms"
    );

    assert!(
        p50 <= LATENCY_P50_BUDGET_MS,
        "p50 round-trip {p50:.1} ms exceeds budget {LATENCY_P50_BUDGET_MS} ms \
         (measured + margin; see docs/supervise-capacity.md)"
    );
    assert!(
        p95 <= LATENCY_P95_BUDGET_MS,
        "p95 round-trip {p95:.1} ms exceeds budget {LATENCY_P95_BUDGET_MS} ms"
    );
    assert!(
        max <= LATENCY_MAX_BUDGET_MS,
        "max round-trip {max:.1} ms exceeds budget {LATENCY_MAX_BUDGET_MS} ms"
    );

    shutdown_worker_and_wait(child, &mut worker, &policy, &program);
}

// ============================================================
// test_exit_frames_never_lost_over_1000_rounds
// ============================================================

/// 1000 exec+exit rounds: every wait_child must return the exact exit code
/// of its own child, no child id may be lost or reused, and the instance
/// must settle back to M0-only afterwards (no frame stranded in the child
/// table).
#[test]
fn test_exit_frames_never_lost_over_1000_rounds() {
    isolate_ctl_root();
    let policy = write_policy("frames", &instance_policy());
    let program = write_program("frames");
    let (child, mut worker) = spawn_measured_supervisor(&policy, &program);
    wait_stats_settled(&mut worker, 1);

    let all_ids = drive_exit_rounds_batched(&mut worker, EXIT_ROUNDS);
    assert_eq!(
        all_ids.len(),
        EXIT_ROUNDS,
        "every round must produce exactly one child id"
    );
    let unique: std::collections::HashSet<u64> = all_ids.iter().copied().collect();
    assert_eq!(
        unique.len(),
        EXIT_ROUNDS,
        "no child id may be lost or reused over {EXIT_ROUNDS} rounds"
    );
    assert_eq!(
        all_ids.first(),
        Some(&1u64),
        "the first exec child id must be 1 (M0 owns id 0)"
    );
    assert_eq!(
        all_ids.last(),
        Some(&(EXIT_ROUNDS as u64)),
        "the {EXIT_ROUNDS}th exec child id must be exactly {EXIT_ROUNDS}"
    );

    wait_stats_settled(&mut worker, 1);
    let st = stats_verb(&mut worker);
    assert_eq!(st["instance_state"], "Live");
    assert_eq!(st["children_live"], 1);

    // Evidence artifact (not committed).
    let mut log = String::new();
    log.push_str(&format!(
        "# 1000 exec+exit rounds: exact child_id -> exit-code routing\n\
         rounds={} unique_ids={} first_id={} last_id={}\n",
        all_ids.len(),
        unique.len(),
        all_ids[0],
        all_ids[EXIT_ROUNDS - 1]
    ));
    for (i, cid) in all_ids.iter().enumerate().take(5) {
        log.push_str(&format!("round {i}: child_id={cid} code={}\n", i % 256));
    }
    log.push_str("...\n");
    for (i, cid) in all_ids.iter().enumerate().skip(EXIT_ROUNDS - 5) {
        log.push_str(&format!("round {i}: child_id={cid} code={}\n", i % 256));
    }
    std::fs::write(
        perf_dir().join("supervise_exit_frames_1000_rounds.log"),
        log,
    )
    .expect("write exit-frame evidence");

    shutdown_worker_and_wait(child, &mut worker, &policy, &program);
}
