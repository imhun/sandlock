//! F1.7 (SECE-6) process-group tests: every `sandlock-init` child must live
//! in its **own** process group, and instance-level signal operations must
//! traverse the registered child-group set.
//!
//! Observation basis (root-mode OCI gate, Linux):
//!
//! - sandlock-oci runs without a PID namespace, so the guest pids the exec'd
//!   children write into their marker files are host-visible pids; the tests
//!   poll `/proc/<pid>/stat` directly (state/pgrp), exactly like the reaper
//!   integration tests.
//! - The workload and each exec'd child are real processes inside the one
//!   sandbox. `sandlock-init` is their common parent; before F1.7 every one
//!   of them sits in init's process group, so a guest `killpg(getpgid(0),
//!   SIGKILL)` kills the whole container (docs `sandbox-exec-security.md`
//!   §4.6/§10.2 V0). After F1.7 each child `setpgid(0,0)`s itself and the
//!   group-set traversal is the only instance-level kill path.
//! - The third test's "no arbitrary-pid forwarding" semantics are pinned at
//!   the surface that exists today: there is no pid-addressed signal channel
//!   anywhere (init does not forward, the supervisor is instance-level only).
//!   The runtime half sends a pid-bearing signal frame to the supervisor
//!   socket and asserts the pid is *not* honored — both siblings stop, never
//!   just the named one — which is the observable boundary the docs demand.
//!
//! The guest probe is a small static C binary compiled by the test (same
//! toolchain pattern as the reaper/checkpoint tests) and driven through
//! `sandlock-oci exec`.

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

use sandlock_oci::init::Req;
use sandlock_oci::supervisor::{SupervisorCmd, SupervisorReply};

/// Static C source for the process-group probe. Subcommands:
///
/// - `beat <tag> <info> <counter>`: write `<tag> pid=P pgid=G` to stdout and
///   to `<info>`, then overwrite `<counter>` with a fixed-width incrementing
///   value every 20 ms.
/// - `killpg-self <tag> <info>`: write the header, then
///   `killpg(getpgid(0), SIGKILL)` — the SECE-6 guest trigger.
/// - `spawn-then-exit <tag> <info> <gc-info> <gc-cnt>`: fork a grandchild
///   that **stays in this process's group** (no setpgid) and beats
///   `<gc-cnt>`; the parent writes its header to `<info>` and exits, so init
///   reaps the parent while the grandchild remains a live member of the dead
///   parent's group (dead-leader coverage probe).
/// - `sig-count <tag> <info> <count> <signum>`: install a handler for
///   `<signum>` that counts deliveries, write the header, then busy-spin.
///   After the first delivery, settle long enough for a would-be second
///   delivery to arrive, write the observed count to `<count>`, and exit 0
///   on exactly one delivery (7 otherwise).
const PGPROBE_C: &str = r##"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t term_count = 0;

static void on_term(int sig) {
    (void)sig;
    term_count++;
}

static void xwrite(int fd, const char *s, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, s, n);
        if (w < 0) _exit(2);
        s += w;
        n -= (size_t)w;
    }
}

static void header(const char *tag, const char *path) {
    char buf[160];
    int n = snprintf(buf, sizeof buf, "%s pid=%d pgid=%d\n",
                     tag, (int)getpid(), (int)getpgrp());
    if (n <= 0) _exit(3);
    xwrite(1, buf, (size_t)n);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) _exit(4);
    xwrite(fd, buf, (size_t)n);
    close(fd);
}

static void beat(int fd) {
    static unsigned long i = 0;
    char buf[24];
    i++;
    unsigned long v = i;
    for (int d = 19; d >= 0; d--) { buf[d] = '0' + (v % 10); v /= 10; }
    buf[20] = '\n';
    if (lseek(fd, 0, SEEK_SET) < 0) _exit(5);
    xwrite(fd, buf, 21);
}

static void write_count(const char *path, int v) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) _exit(8);
    char buf[32];
    int n = snprintf(buf, sizeof buf, "%d\n", v);
    if (n > 0) xwrite(fd, buf, (size_t)n);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2) return 100;
    if (strcmp(argv[1], "beat") == 0 && argc == 5) {
        header(argv[2], argv[3]);
        int fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) _exit(6);
        struct timespec t = { 0, 20000000 };
        for (;;) { beat(fd); nanosleep(&t, NULL); }
    }
    if (strcmp(argv[1], "killpg-self") == 0 && argc == 4) {
        header(argv[2], argv[3]);
        killpg(getpgrp(), SIGKILL);
        _exit(42); /* reachable only if the group kill did not kill us */
    }
    if (strcmp(argv[1], "spawn-then-exit") == 0 && argc == 6) {
        pid_t g = fork();
        if (g < 0) return 9;
        if (g == 0) {
            /* Grandchild: stays in the parent's process group (no setpgid). */
            header(argv[2], argv[4]);
            int fd = open(argv[5], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) _exit(10);
            struct timespec t = { 0, 20000000 };
            for (;;) { beat(fd); nanosleep(&t, NULL); }
        }
        header(argv[2], argv[3]);
        _exit(0);
    }
    if (strcmp(argv[1], "sig-count") == 0 && argc == 6) {
        int sig = atoi(argv[5]);
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_term;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if (sigaction(sig, &sa, NULL) != 0) return 11;
        header(argv[2], argv[3]);
        /* Busy-spin (no nanosleep): the process stays runnable so a second
         * delivery is not lost to scheduler delay. For a queued (realtime)
         * signal every injection is observable; standard signals like SIGTERM
         * coalesce if both arrive before the first is delivered, which is why
         * the count probe uses the realtime signal the test passes in. */
        volatile unsigned long sink = 0;
        struct timespec settle = { 0, 900000000 };
        for (;;) {
            if (term_count == 0) {
                sink++;
                continue;
            }
            /* Settle so a would-be double delivery is counted before exit. */
            nanosleep(&settle, NULL);
            write_count(argv[4], (int)term_count);
            _exit(term_count == 1 ? 0 : 7);
        }
    }
    return 101;
}
"##;

/// Linux uapi values used by the raw reaper syscalls. Declared as plain
/// `extern` so the test target needs no extra crate linkage.
const PR_SET_CHILD_SUBREAPER: i32 = 36;
const WNOHANG: i32 = 1;

extern "C" {
    fn prctl(option: i32, a2: usize, a3: usize, a4: usize, a5: usize) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

fn oci_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-oci")
}

fn rootfs_helper() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/rootfs-helper")
}

/// Minimal OCI bundle whose main process runs `cmd` inside the rootfs.
fn write_bundle_config(bundle: &Path, cmd: &[&str]) {
    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "root": { "path": "rootfs", "readonly": false },
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "cwd": "/",
            "args": cmd,
            "env": ["PATH=/usr/bin:/bin"]
        },
        "mounts": [],
        "linux": {
            "resources": {
                "devices": [ { "allow": false, "access": "rwm" } ]
            },
            "namespaces": [ { "type": "mount" } ]
        }
    });
    fs::write(
        bundle.join("config.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
}

/// Compile the static process-group probe into the rootfs (exec'd at
/// `/pgprobe`).
fn build_pgprobe(rootfs: &Path) -> Result<(), String> {
    let src = rootfs.join("pgprobe.c");
    let bin = rootfs.join("pgprobe");
    fs::write(&src, PGPROBE_C).unwrap();
    let cc = ["cc", "gcc"]
        .into_iter()
        .find(|c| {
            std::env::var_os("PATH").map_or(false, |paths| {
                std::env::split_paths(&paths).any(|d| d.join(c).is_file())
            })
        })
        .ok_or_else(|| "no C compiler (cc/gcc) available".to_string())?;
    let out = Command::new(cc)
        .args(["-static", "-O0", "-o"])
        .arg(&bin)
        .arg(&src)
        .output()
        .map_err(|e| format!("spawn {cc}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "pgprobe build failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    Ok(())
}

/// Make this test process a subreaper so processes orphaned mid-test (for
/// example the exec proxies the detached CLI forks) deterministically
/// reparent to us for reaping instead of accumulating under outer PID 1.
fn set_subreaper() -> bool {
    let r = unsafe { prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if r != 0 {
        eprintln!(
            "skipping: prctl(PR_SET_CHILD_SUBREAPER) failed: {}",
            std::io::Error::last_os_error()
        );
        return false;
    }
    true
}

/// Reap every adopted/child process of this test, used only after container
/// teardown.
fn reap_children(deadline: Duration) -> bool {
    let end = Instant::now() + deadline;
    loop {
        let mut status = 0i32;
        let r = unsafe { waitpid(-1, &mut status, WNOHANG) };
        if r <= 0 {
            return true;
        }
        if Instant::now() > end {
            return false;
        }
    }
}

/// (state, pgrp) for `pid` from /proc/<pid>/stat, or None when gone.
fn proc_stat(pid: i32) -> Option<(char, i32)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rfind(')')? + 2;
    let mut it = stat.get(after..)?.split_whitespace();
    let state = it.next()?.chars().next()?;
    let _ppid = it.next()?;
    let pgrp = it.next()?.parse().ok()?;
    Some((state, pgrp))
}

/// A process is "live" when it exists and is not a zombie (`Z`) or dead (`X`).
/// SIGKILLed children that init has not reaped yet are zombies: not live.
fn proc_live(pid: i32) -> bool {
    matches!(proc_stat(pid), Some((s, _)) if matches!(s, 'R' | 'S' | 'D' | 'T' | 't'))
}

/// Pids of *live* processes whose process group is one of `pgids`. Used to
/// prove an instance-level kill reached every registered child group (and
/// only those groups).
fn live_pids_with_pgrp(pgids: &[i32]) -> Vec<i32> {
    let set: HashSet<i32> = pgids.iter().copied().collect();
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if let Some((state, pgrp)) = proc_stat(pid) {
            if set.contains(&pgrp) && matches!(state, 'R' | 'S' | 'D' | 'T' | 't') {
                out.push(pid);
            }
        }
    }
    out
}

/// Read the fixed-width counter file written by the probe / spawn-loop.
fn read_counter(path: &Path) -> Option<u64> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Parsed probe header: `<tag> pid=P pgid=G\n`.
#[derive(Debug, Clone)]
struct ChildInfo {
    pid: i32,
    pgid: i32,
}

fn parse_info(s: &str) -> Option<ChildInfo> {
    let mut pid = None;
    let mut pgid = None;
    for tok in s.split_whitespace() {
        if let Some(v) = tok.strip_prefix("pid=") {
            pid = v.parse().ok();
        } else if let Some(v) = tok.strip_prefix("pgid=") {
            pgid = v.parse().ok();
        }
    }
    Some(ChildInfo { pid: pid?, pgid: pgid? })
}

fn wait_info(path: &Path, deadline: Duration) -> Option<ChildInfo> {
    let end = Instant::now() + deadline;
    loop {
        if let Some(info) = fs::read_to_string(path).ok().as_deref().and_then(parse_info) {
            return Some(info);
        }
        if Instant::now() > end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_counter_gt(path: &Path, min: u64, deadline: Duration) -> bool {
    let end = Instant::now() + deadline;
    loop {
        if read_counter(path).map(|v| v > min).unwrap_or(false) {
            return true;
        }
        if Instant::now() > end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_not_live(pids: &[i32], deadline: Duration) -> bool {
    let end = Instant::now() + deadline;
    loop {
        if pids.iter().all(|p| !proc_live(*p)) {
            return true;
        }
        if Instant::now() > end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_state_stopped(root: &Path, id: &str, deadline: Duration) -> bool {
    let end = Instant::now() + deadline;
    loop {
        let stopped = fs::read_to_string(root.join(id).join("state.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(|s| s == "stopped"))
            .unwrap_or(false);
        if stopped {
            return true;
        }
        if Instant::now() > end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Read the recorded `pid` field out of state.json (sandlock-init after
/// `create`, the workload after `start`).
fn state_pid(root: &Path, id: &str) -> Option<i32> {
    let s = fs::read_to_string(root.join(id).join("state.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    v.get("pid").and_then(|p| p.as_i64()).map(|p| p as i32)
}

/// Read the recorded `exit_info.code` out of state.json, if present.
fn state_exit_code(root: &Path, id: &str) -> Option<i32> {
    let s = fs::read_to_string(root.join(id).join("state.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    v.get("exit_info")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64())
        .map(|c| c as i32)
}

/// One OCI container under test.
struct Container {
    _tmp: TempDir,
    base: PathBuf,
    root: PathBuf,
    rootfs: PathBuf,
    bundle: PathBuf,
    id: String,
    log: PathBuf,
    /// Main workload pid (state.pid after `start`; the spawn-loop leader).
    main_pid: i32,
}

impl Container {
    /// Build the bundle, `create` + `start` the sandbox with `main_args`, and
    /// wait until the main workload is genuinely running (`ready_info` names
    /// an info-marker file the main process writes, or None to poll the
    /// spawn-loop keepalive counter). On partial failure the sandbox is
    /// deleted and reaped before returning `Err`.
    fn boot_impl(tag: &str, main_args: &[&str], ready_info: Option<&str>) -> Result<Self, String> {
        let tmp = TempDir::new().map_err(|e| format!("tempdir: {e}"))?;
        let base = tmp.path().to_path_buf();
        let root = base.join("root");
        let bundle = base.join("bundle");
        let rootfs = bundle.join("rootfs");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&rootfs).unwrap();
        fs::copy(rootfs_helper(), rootfs.join("rootfs-helper"))
            .map_err(|e| format!("copy rootfs-helper: {e}"))?;
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(rootfs.join("rootfs-helper"), fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        write_bundle_config(&bundle, main_args);
        build_pgprobe(&rootfs)?;

        let id = format!("f17-{tag}-{}", std::process::id());
        let log = base.join("lifecycle.log");
        let mut c = Container {
            _tmp: tmp,
            base,
            root,
            rootfs,
            bundle,
            id,
            log,
            main_pid: 0,
        };

        if !c.run(&["create", &c.id, "-b", c.bundle.to_str().unwrap()]).success() {
            let msg = format!("create failed:\n{}", c.log_text());
            let _ = c.run(&["delete", &c.id, "--force"]);
            let _ = reap_children(Duration::from_secs(2));
            return Err(msg);
        }
        if !c.run(&["start", &c.id]).success() {
            let msg = format!("start failed:\n{}", c.log_text());
            let _ = c.run(&["delete", &c.id, "--force"]);
            let _ = reap_children(Duration::from_secs(2));
            return Err(msg);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let ready = match ready_info {
                Some(name) => wait_info(&c.rootfs.join(name), Duration::from_millis(0)).is_some(),
                None => read_counter(&c.rootfs.join("keepalive.cnt"))
                    .map(|v| v > 2)
                    .unwrap_or(false),
            };
            if ready {
                c.main_pid = state_pid(&c.root, &c.id).expect("state.pid after start");
                return Ok(c);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let msg = format!("main workload never became ready:\n{}", c.log_text());
        let _ = c.run(&["delete", &c.id, "--force"]);
        let _ = reap_children(Duration::from_secs(2));
        Err(msg)
    }

    /// Boot with the long-lived `spawn-loop` keepalive main (advances
    /// `/keepalive.cnt`).
    fn boot(tag: &str) -> Result<Self, String> {
        Self::boot_impl(tag, &["/rootfs-helper", "spawn-loop", "/keepalive.cnt"], None)
    }

    /// Boot with a pgprobe main that writes `<main.info>` inside the rootfs
    /// when it is running.
    fn boot_pgprobe_main(tag: &str, main_args: &[&str]) -> Result<Self, String> {
        Self::boot_impl(tag, main_args, Some("main.info"))
    }

    fn log_text(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Run the OCI CLI with `argv` (after `--root <root>`); stdio goes to the
    /// lifecycle log file.
    fn run(&self, argv: &[&str]) -> std::process::ExitStatus {
        let out = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let err = out.try_clone().unwrap();
        let mut cmd = Command::new(oci_bin());
        cmd.arg("--root").arg(&self.root);
        for a in argv {
            cmd.arg(a);
        }
        cmd.stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .status()
            .unwrap_or_else(|e| panic!("failed to run sandlock-oci: {e}"))
    }

    /// Detached exec of an in-rootfs command. The CLI returns once the exec
    /// proxy is up; the exec'd process's stdout/stderr are the provided files
    /// (passed through SCM_RIGHTS), so each sibling's output is separable.
    fn exec_detached(
        &self,
        args: &[&str],
        out: &Path,
        err: &Path,
    ) -> std::process::ExitStatus {
        let mut full = vec!["exec".to_string(), "--detach".to_string(), self.id.clone()];
        full.extend(args.iter().map(|s| s.to_string()));
        let stdout = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(out)
            .unwrap();
        let stderr = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(err)
            .unwrap();
        Command::new(oci_bin())
            .arg("--root")
            .arg(&self.root)
            .args(&full)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .status()
            .unwrap_or_else(|e| panic!("failed to run sandlock-oci exec: {e}"))
    }

    /// Kill any still-live registered guest pids (host-side, same uid, root
    /// mode) — pure test hygiene for RED-phase leaks where a buggy teardown
    /// path left children running after the container was recorded stopped.
    fn cleanup_pids(&self, pids: &[i32]) {
        for &p in pids {
            if proc_live(p) {
                unsafe {
                    kill(p, libc::SIGKILL);
                }
            }
        }
    }

    /// `delete --force`, kill known strays, then reap whatever reparented to
    /// us (supervisor/exec proxies/guest processes).
    fn teardown(&self, strays: &[i32]) -> bool {
        let del_ok = self.run(&["delete", &self.id, "--force"]).success();
        self.cleanup_pids(strays);
        std::thread::sleep(Duration::from_millis(100));
        self.cleanup_pids(strays);
        let reaped = reap_children(Duration::from_secs(4));
        del_ok && reaped
    }
}

fn supported_env() -> bool {
    if !cfg!(target_os = "linux") || !cfg!(target_arch = "x86_64") {
        eprintln!("skipping: process-group probes are x86_64 Linux-only");
        return false;
    }
    if sandlock_core::landlock_abi_version().is_err() {
        eprintln!("skipping: Landlock unavailable on this host");
        return false;
    }
    if !rootfs_helper().exists() {
        eprintln!("skipping: no rootfs-helper binary");
        return false;
    }
    true
}

/// Wire-surface pin: the supervisor's signal command is instance-level and
/// carries **no pid** (the match is exhaustive; a per-pid variant would fail
/// to compile). `SupervisorCmd::Signal` is the only signal verb and its only
/// field is `signum`.
fn supervisor_signal_surface(cmd: SupervisorCmd) {
    match cmd {
        SupervisorCmd::Start | SupervisorCmd::Ping | SupervisorCmd::Shutdown => {}
        SupervisorCmd::Checkpoint { dir } => {
            let _ = dir;
        }
        SupervisorCmd::Exec { .. } => {}
        SupervisorCmd::Signal { signum } => {
            let _ = signum;
        }
    }
}

/// Wire-surface pin for the guest-visible init protocol: no pid-addressed
/// signal verb exists — `Signal` is instance-level only, `Shutdown` tears the
/// container down, and a compromised control-channel holder can name no
/// arbitrary process (exhaustive match; a per-pid variant would fail to
/// compile).
fn init_signal_surface(req: &Req) {
    match req {
        // 2026-10-05: `RunPlacedExec` is the restore-into-session request (the
        // program arrives as a descriptor); it names no signal either, so it
        // belongs with the other non-signal verbs. The arm is explicit on
        // purpose -- this match is the pin that makes a *per-pid* signal verb
        // fail to compile, so every new `Req` variant has to be classified here.
        Req::RunMain { .. }
        | Req::RunExec { .. }
        | Req::RunPlacedExec { .. }
        | Req::Shutdown => {}
        Req::Signal { signum } => {
            let _ = signum;
        }
    }
}

/// Send one raw supervisor frame (host-side, over the state-dir socket) and
/// return the parsed reply.
///
/// The control protocol is newline-delimited JSON, so the payload and its `\n`
/// delimiter are sent as **two** writes — a legal client pattern the CLI itself
/// used, and the one that used to make this suite flake. A stream socket
/// preserves no write boundaries, so the supervisor must not answer (or close)
/// the connection until the delimiter arrives: answering the payload fragment
/// makes the delimiter write fail with `EPIPE`, and `kill --all` reacts to any
/// send error by falling back to a direct `killpg(state.pid, …)` — delivering
/// an instance signal a *second* time. The readiness probe below pins that
/// boundary explicitly instead of hoping the two writes coalesce.
fn raw_supervisor_cmd(root: &Path, json: &str) -> Result<SupervisorReply, String> {
    let socks: Vec<PathBuf> = fs::read_dir(root)
        .map_err(|e| format!("read state root {:?}: {e}", root))?
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            p.extension().map(|x| x == "sock").unwrap_or(false).then_some(p)
        })
        .collect();
    if socks.len() != 1 {
        return Err(format!("expected exactly one supervisor socket under {:?}, found {:?}", root, socks));
    }
    let mut stream = UnixStream::connect(&socks[0]).map_err(|e| format!("connect {}: {e}", socks[0].display()))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| format!("set timeout: {e}"))?;
    stream
        .write_all(json.as_bytes())
        .map_err(|e| format!("write frame: {e}"))?;
    stream.flush().map_err(|e| format!("flush frame: {e}"))?;
    // A reply or an end-of-stream here means the supervisor acted on a request
    // that is not complete yet.
    let mut probe = [0u8; 1];
    let peeked = unsafe {
        libc::recv(
            std::os::unix::io::AsRawFd::as_raw_fd(&stream),
            probe.as_mut_ptr() as *mut libc::c_void,
            1,
            libc::MSG_PEEK,
        )
    };
    if peeked > 0 {
        return Err(format!(
            "supervisor answered the connection before the request's delimiter arrived \
             (frame {json:?}); a control request is only complete at its newline"
        ));
    }
    if peeked == 0 {
        return Err(format!(
            "supervisor closed the connection before the request's delimiter arrived \
             (frame {json:?}); a control request is only complete at its newline"
        ));
    }
    let probe_err = std::io::Error::last_os_error();
    if !matches!(
        probe_err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        return Err(format!("probe for an early reply: {probe_err}"));
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream.write_all(b"\n").map_err(|e| format!("write newline: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    let mut line = String::new();
    let read = BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|e| format!("read reply to frame {json:?}: {e}"))?;
    if read == 0 {
        return Err(format!(
            "supervisor closed the connection without answering frame {json:?} \
             (the request was newline-terminated)"
        ));
    }
    serde_json::from_str(line.trim())
        .map_err(|e| format!("parse reply {line:?} to frame {json:?}: {e}"))
}

/// Boot a three-command instance (main keepalive + two exec'd `beat`
/// siblings), wait until both siblings are live, and return their info plus
/// the paths of their counter/stdout witnesses.
fn boot_with_two_siblings(
    c: &Container,
    tag_a: &str,
    tag_b: &str,
) -> Result<(ChildInfo, ChildInfo, PathBuf, PathBuf, PathBuf, PathBuf), String> {
    let a_out = c.base.join("a.out");
    let a_err = c.base.join("a.err");
    let b_out = c.base.join("b.out");
    let b_err = c.base.join("b.err");
    let a_info = c.rootfs.join("a.info");
    let a_cnt = c.rootfs.join("a.cnt");
    let b_info = c.rootfs.join("b.info");
    let b_cnt = c.rootfs.join("b.cnt");

    let exec_b = c.exec_detached(
        &["/pgprobe", "beat", tag_b, "/b.info", "/b.cnt"],
        &b_out,
        &b_err,
    );
    if !exec_b.success() {
        return Err(format!("detached exec of B failed:\n{}", fs::read_to_string(&b_err).unwrap_or_default()));
    }
    let info_b = wait_info(&b_info, Duration::from_secs(5))
        .ok_or_else(|| "B never wrote its info marker".to_string())?;
    if !wait_counter_gt(&b_cnt, 3, Duration::from_secs(5)) {
        return Err("B never advanced its beat counter".to_string());
    }

    let exec_a = c.exec_detached(
        &["/pgprobe", "beat", tag_a, "/a.info", "/a.cnt"],
        &a_out,
        &a_err,
    );
    if !exec_a.success() {
        return Err(format!("detached exec of A failed:\n{}", fs::read_to_string(&a_err).unwrap_or_default()));
    }
    let info_a = wait_info(&a_info, Duration::from_secs(5))
        .ok_or_else(|| "A never wrote its info marker".to_string())?;
    if !wait_counter_gt(&a_cnt, 3, Duration::from_secs(5)) {
        return Err("A never advanced its beat counter".to_string());
    }
    Ok((info_a, info_b, a_cnt, b_cnt, a_out, b_out))
}

#[test]
fn test_child_killpg_does_not_hit_sibling() {
    if !supported_env() || !set_subreaper() {
        return;
    }
    let c = match Container::boot("killpg") {
        Ok(c) => c,
        Err(msg) => panic!("container boot failed: {msg}"),
    };

    // B: long-lived beat sibling (own process group after the fix).
    let b_out = c.base.join("b.out");
    let b_err = c.base.join("b.err");
    let b_info = c.rootfs.join("b.info");
    let b_cnt = c.rootfs.join("b.cnt");
    if !c
        .exec_detached(&["/pgprobe", "beat", "B", "/b.info", "/b.cnt"], &b_out, &b_err)
        .success()
    {
        let _ = c.teardown(&[]);
        panic!("detached exec of B failed:\n{}", fs::read_to_string(&b_err).unwrap_or_default());
    }
    let info_b = match wait_info(&b_info, Duration::from_secs(5)) {
        Some(i) => i,
        None => {
            let _ = c.teardown(&[]);
            panic!("B never wrote its info marker");
        }
    };
    if !wait_counter_gt(&b_cnt, 3, Duration::from_secs(5)) {
        let _ = c.teardown(&[info_b.pid]);
        panic!("B never advanced its beat counter");
    }

    // A: guest suicide by killpg(own pgid) — must take only A down.
    let a_out = c.base.join("a.out");
    let a_err = c.base.join("a.err");
    let a_info = c.rootfs.join("a.info");
    let exec_a = c.exec_detached(
        &["/pgprobe", "killpg-self", "A", "/a.info"],
        &a_out,
        &a_err,
    );
    if !exec_a.success() {
        let _ = c.teardown(&[info_b.pid]);
        panic!("detached exec of A failed:\n{}", fs::read_to_string(&a_err).unwrap_or_default());
    }
    let info_a = match wait_info(&a_info, Duration::from_secs(5)) {
        Some(i) => i,
        None => {
            let _ = c.teardown(&[info_b.pid]);
            panic!("A never wrote its info marker");
        }
    };
    let a_died = wait_not_live(&[info_a.pid], Duration::from_secs(5));

    // Siblings must keep living and advancing after A's self-killpg.
    let b_before = read_counter(&b_cnt).unwrap_or(0);
    let main_before = read_counter(&c.rootfs.join("keepalive.cnt")).unwrap_or(0);
    let b_advanced = wait_counter_gt(&b_cnt, b_before, Duration::from_secs(3));
    let main_advanced = wait_counter_gt(&c.rootfs.join("keepalive.cnt"), main_before, Duration::from_secs(3));

    let a_out_text = fs::read_to_string(&a_out).unwrap_or_default();
    let b_out_text = fs::read_to_string(&b_out).unwrap_or_default();
    let main_pid = c.main_pid;
    let cleaned = c.teardown(&[info_a.pid, info_b.pid, main_pid]);

    assert!(a_died, "A must die from killpg(its own group); A pid {} still live", info_a.pid);
    assert!(
        b_advanced,
        "sibling B (pid {}) must survive A's killpg(getpgid(0), SIGKILL): its beat \
         counter was {b_before} and never advanced afterwards. Before the per-child \
         group fix B shares init's group and dies with A (SECE-6); after the fix B \
         is in its own group and must keep beating. B info: {:?}, container log:\n{}",
        info_b.pid,
        info_b,
        c.log_text(),
    );
    assert!(
        main_advanced,
        "the main workload (pid {main_pid}) must survive A's killpg; its keepalive \
         counter was {main_before} and never advanced afterwards",
    );
    let expect_a = format!("A pid={} pgid={}\n", info_a.pid, info_a.pgid);
    let expect_b = format!("B pid={} pgid={}\n", info_b.pid, info_b.pgid);
    assert_eq!(
        a_out_text.trim_end(),
        expect_a.trim_end(),
        "A's output stream must contain only A's own header (no cross-sibling output)"
    );
    assert_eq!(
        b_out_text.trim_end(),
        expect_b.trim_end(),
        "B's output stream must contain only B's own header (no cross-sibling output)"
    );
    assert_eq!(
        info_a.pgid, info_a.pid,
        "each exec'd child must be its own process-group leader (A pgid {} != pid {})",
        info_a.pgid, info_a.pid
    );
    assert_eq!(
        info_b.pgid, info_b.pid,
        "each exec'd child must be its own process-group leader (B pgid {} != pid {})",
        info_b.pgid, info_b.pid
    );
    assert_ne!(
        info_a.pgid, info_b.pgid,
        "exec'd siblings must live in distinct process groups (A={}, B={})",
        info_a.pgid, info_b.pgid
    );
    assert!(cleaned, "delete --force and child reaping must succeed");
}

#[test]
fn test_instance_kill_covers_all_child_groups() {
    if !supported_env() || !set_subreaper() {
        return;
    }
    let c = match Container::boot("instkill") {
        Ok(c) => c,
        Err(msg) => panic!("container boot failed: {msg}"),
    };

    let (info_a, info_b, _a_cnt, _b_cnt, _a_out, _b_out) =
        match boot_with_two_siblings(&c, "A", "B") {
            Ok(x) => x,
            Err(msg) => {
                let _ = c.teardown(&[]);
                panic!("{msg}");
            }
        };
    let main_pid = c.main_pid;

    // Dead-leader coverage: exec child C forks a grandchild that STAYS in C's
    // group, then C exits and init reaps it. The grandchild remains a live
    // member of the dead C group, so the instance kill below must still reach
    // it via the retained dead-groups set (a reaped child's pgid must not
    // silently vanish from teardown coverage).
    let c_out = c.base.join("c.out");
    let c_err = c.base.join("c.err");
    let c_info = c.rootfs.join("c.info");
    let gc_info = c.rootfs.join("gc.info");
    let gc_cnt = c.rootfs.join("gc.cnt");
    let exec_c = c.exec_detached(
        &["/pgprobe", "spawn-then-exit", "C", "/c.info", "/gc.info", "/gc.cnt"],
        &c_out,
        &c_err,
    );
    if !exec_c.success() {
        let _ = c.teardown(&[info_a.pid, info_b.pid, main_pid]);
        panic!("detached exec of C failed:\n{}", fs::read_to_string(&c_err).unwrap_or_default());
    }
    let info_c = match wait_info(&c_info, Duration::from_secs(5)) {
        Some(i) => i,
        None => {
            let _ = c.teardown(&[info_a.pid, info_b.pid, main_pid]);
            panic!("C never wrote its info marker");
        }
    };
    // C exits immediately; wait until init has fully reaped it (removed from
    // the live child table) before the instance kill.
    let c_reaped = {
        let end = Instant::now() + Duration::from_secs(5);
        let mut gone = false;
        while Instant::now() < end {
            if !Path::new("/proc").join(info_c.pid.to_string()).exists() {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        gone
    };
    let info_gc = match wait_info(&gc_info, Duration::from_secs(5)) {
        Some(i) => i,
        None => {
            let _ = c.teardown(&[info_a.pid, info_b.pid, info_c.pid, main_pid]);
            panic!("grandchild never wrote its info marker");
        }
    };
    let gc_beating = wait_counter_gt(&gc_cnt, 3, Duration::from_secs(5));

    // Instance-level kill: CLI kill --all → SupervisorCmd::Signal{SIGKILL}.
    let kill_ok = c.run(&["kill", &c.id, "--all", "SIGKILL"]).success();
    let stopped = wait_state_stopped(&c.root, &c.id, Duration::from_secs(5));
    let all_dead = wait_not_live(
        &[info_a.pid, info_b.pid, main_pid, info_gc.pid],
        Duration::from_secs(5),
    );
    let groups = [info_a.pid, info_b.pid, main_pid, info_c.pid];
    let lingering = live_pids_with_pgrp(&groups);
    let cleaned = c.teardown(&[info_a.pid, info_b.pid, info_c.pid, info_gc.pid, main_pid]);

    assert!(c_reaped, "exec child C must be reaped by init before the instance kill");
    assert!(gc_beating, "the grandchild must be live and beating in C's group before the instance kill");
    assert_eq!(
        info_gc.pgid, info_c.pid,
        "the grandchild must stay in the dead child's group (gc pgid {} != C pid {}) — \
         scenario premise",
        info_gc.pgid,
        info_c.pid
    );
    assert!(kill_ok, "kill --all SIGKILL must succeed:\n{}", c.log_text());
    assert!(stopped, "container state must become stopped after the instance kill");
    assert!(
        all_dead,
        "instance kill must reach every registered child group AND every retained \
         dead child group: A={}, B={}, main={}, grandchild={} (in dead group of C={}) \
         still live",
        info_a.pid,
        info_b.pid,
        main_pid,
        info_gc.pid,
        info_c.pid
    );
    assert!(
        lingering.is_empty(),
        "no live process may remain in any registered or dead child group \
         ({groups:?}); still live: {lingering:?}. The grandchild is the \
         dead-leader case: C was reaped before the kill, so its pgid must be \
         retained in the dead-groups set or the grandchild outlives the kill",
    );
    assert!(cleaned, "delete --force and child reaping must succeed");
}

#[test]
fn test_signal_to_sibling_pid_rejected() {
    if !supported_env() || !set_subreaper() {
        return;
    }
    let c = match Container::boot("nofwd") {
        Ok(c) => c,
        Err(msg) => panic!("container boot failed: {msg}"),
    };

    let (info_a, info_b, a_cnt, b_cnt, _a_out, _b_out) =
        match boot_with_two_siblings(&c, "A", "B") {
            Ok(x) => x,
            Err(msg) => {
                let _ = c.teardown(&[]);
                panic!("{msg}");
            }
        };
    let main_pid = c.main_pid;
    let groups = [info_a.pid, info_b.pid, main_pid];

    // A pid-addressed SIGSTOP frame must NOT stop just the named sibling: no
    // per-pid forwarding channel exists, so the supervisor treats it as an
    // instance-level request and init stops every registered child group.
    // (If the frame were rejected outright the siblings would keep beating —
    // also a failure of the "no pid honored" boundary; the expected semantics
    // is instance-level delivery with the pid ignored.)
    let stop_frame = format!(
        r#"{{"cmd":"signal","pid":{},"signum":{}}}"#,
        info_b.pid,
        libc::SIGSTOP
    );
    let stop_reply = raw_supervisor_cmd(&c.root, &stop_frame);
    let stop_ok = matches!(stop_reply, Ok(SupervisorReply::Ok));
    // Settle past init's poll round, then require both siblings frozen.
    std::thread::sleep(Duration::from_millis(400));
    let a_frozen = read_counter(&a_cnt).unwrap_or(0);
    let b_frozen = read_counter(&b_cnt).unwrap_or(0);
    std::thread::sleep(Duration::from_millis(400));
    let a_later = read_counter(&a_cnt).unwrap_or(0);
    let b_later = read_counter(&b_cnt).unwrap_or(0);
    let stopped_clean = stop_ok && a_frozen == a_later && b_frozen == b_later;

    // Resume with a plain instance-level SIGCONT (no pid), then verify both
    // siblings actually run again.
    let cont_frame = format!(r#"{{"cmd":"signal","signum":{}}}"#, libc::SIGCONT);
    let cont_reply = raw_supervisor_cmd(&c.root, &cont_frame);
    let cont_ok = matches!(cont_reply, Ok(SupervisorReply::Ok));
    let resumed = cont_ok
        && wait_counter_gt(&a_cnt, a_frozen, Duration::from_secs(3))
        && wait_counter_gt(&b_cnt, b_frozen, Duration::from_secs(3));

    // Wire surface: no pid-addressed verb on either channel (exhaustive
    // matches; they fail to compile if such a variant is added).
    supervisor_signal_surface(SupervisorCmd::Signal { signum: libc::SIGKILL });
    init_signal_surface(&Req::Signal { signum: libc::SIGKILL });
    let killed = c.run(&["delete", &c.id, "--force"]).success();
    let cleaned = c.teardown(&groups);

    assert!(
        stopped_clean,
        "a pid-addressed signal frame must not stop a single sibling: the only \
         signal verb is instance-level, so both siblings (and the main workload) \
         stop together. A pid={} B pid={}; counters froze unevenly or kept \
         advancing (a per-pid channel or a rejected-instance fallback). \
         Stop frame {stop_frame} replied {stop_reply:?}",
        info_a.pid,
        info_b.pid
    );
    assert!(
        resumed,
        "instance-level SIGCONT must resume every stopped child group (A pid={}, B pid={}; \
         stop frame {stop_frame} replied {stop_reply:?}, cont frame {cont_frame} replied \
         {cont_reply:?})",
        info_a.pid,
        info_b.pid
    );
    assert!(
        killed,
        "delete --force after the stop/resume round must succeed:\n{}",
        c.log_text()
    );
    assert!(cleaned, "delete --force and child reaping must succeed");

    // ── Phase 2: instance signal must be delivered exactly once ─────────────
    // The main workload traps the signal, counts deliveries, settles (so a
    // would-be second delivery is observed), writes the count, and exits 0
    // only for exactly one. The probe uses SIGRTMIN (34): realtime signals
    // are queued, so every injection is observable — a killpg +
    // pidfd_send_signal pair would deterministically count 2 and exit 7. The
    // same double-injection path would deliver SIGTERM twice to a graceful
    // handler whenever the second injection lands while the first is being
    // handled (standard signals coalesce only if both arrive before the first
    // delivery starts), which is the review finding this pins.
    let rt_sig = libc::SIGRTMIN();
    let t = match Container::boot_pgprobe_main(
        "term",
        &[
            "/pgprobe",
            "sig-count",
            "MAIN",
            "/main.info",
            "/sig.count",
            &rt_sig.to_string(),
        ],
    ) {
        Ok(t) => t,
        Err(msg) => panic!("term container boot failed: {msg}"),
    };
    let main_info_path = t.rootfs.join("main.info");
    let main_info = match wait_info(&main_info_path, Duration::from_secs(5)) {
        Some(i) => i,
        None => panic!("sig-count main never wrote its info marker:\n{}", t.log_text()),
    };
    let main_pid = t.main_pid;
    let term_ok = t
        .run(&["kill", &t.id, "--all", &rt_sig.to_string()])
        .success();
    let stopped2 = wait_state_stopped(&t.root, &t.id, Duration::from_secs(10));
    let count_text = fs::read_to_string(t.rootfs.join("sig.count")).unwrap_or_default();
    let exit_code = state_exit_code(&t.root, &t.id);
    let cleaned2 = t.teardown(&[main_pid]);

    assert_eq!(
        main_info.pgid, main_pid,
        "sig-count main must be its own group leader (pgid {} != pid {})",
        main_info.pgid,
        main_pid
    );
    assert!(
        term_ok,
        "kill --all {rt_sig} must succeed:\n{}",
        t.log_text()
    );
    assert!(
        stopped2,
        "sig-count main must exit (and the container stop) after the instance signal"
    );
    assert_eq!(
        count_text.trim(),
        "1",
        "instance signal {rt_sig} must be delivered exactly once to an in-group \
         workload; got {count_text:?} deliveries. A killpg + pidfd_send_signal pair \
         double-delivers non-idempotent signums to children that never left their \
         group (SIGTERM twice breaks graceful handlers whenever the second lands \
         during the first)"
    );
    assert_eq!(
        exit_code,
        Some(0),
        "sig-count main must exit 0 on a single delivery (7 = double delivery); \
         state exit code: {exit_code:?}"
    );
    assert!(cleaned2, "delete --force and child reaping must succeed");
}
