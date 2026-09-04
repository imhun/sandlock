//! SL-6 reaper tests: `sandlock-init` must adopt and reap double-fork
//! descendants (orphans), so defuncts cannot grow across repeated double
//! forks.
//!
//! Observation basis (root-mode OCI gate, Linux):
//!
//! - sandlock-oci runs **without a PID namespace**, so the kernel's fallback
//!   for an orphaned descendant is the nearest *subreaper* ancestor; with no
//!   subreaper at all the orphan would go to the outer container PID 1.
//! - To make the observation deterministic regardless of what outer PID 1
//!   does, each test makes **the test process itself** a subreaper before
//!   running the OCI lifecycle. Today (init is not a subreaper) a double-fork
//!   orphan is therefore adopted by the test process: its `ppid` marker is
//!   the test pid, and after it exits it stays as a `<defunct>` child of the
//!   test process until reaped.
//! - With the fix, init sets `PR_SET_CHILD_SUBREAPER` (and is the nearest
//!   subreaper ancestor), so the orphan is adopted by *init* and init's
//!   `waitpid(-1, WNOHANG)` sweep reaps it: the marker's `ppid` is init's pid
//!   and the orphan's pid disappears from `/proc` (no defunct left under
//!   init or the test process).
//!
//! The guest double-fork probe is a small static C binary compiled by the
//! test (same toolchain pattern as the checkpoint/restore tests); it runs
//! inside the OCI rootfs via `sandlock-oci exec`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Static C source for the double-fork orphan probe. Built with `cc -static`;
/// the container rootfs has no shared libraries.
const ORPHAN_HELPER_C: &str = r##"
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 4) return 2;
    const char *outfile = argv[2];
    const char *round = argv[3];

    int p[2];
    if (pipe(p) != 0) return 3;
    pid_t a = fork();
    if (a < 0) return 4;
    if (a != 0) _exit(0);          /* P: exit, orphaning I */
    pid_t b = fork();
    if (b < 0) _exit(5);
    if (b != 0) _exit(0);          /* I: exit, orphaning O */

    /* O only: EOF on the pipe is I's exit; settle before sampling ppid. */
    close(p[1]);
    char ch;
    while (read(p[0], &ch, 1) > 0) { }
    close(p[0]);
    struct timespec ts = { 0, 100000000 };
    nanosleep(&ts, NULL);

    int fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) _exit(6);
    char buf[128];
    int n = snprintf(buf, sizeof buf, "round=%s pid=%d ppid=%d\n",
                     round, (int)getpid(), (int)getppid());
    if (n > 0) write(fd, buf, (size_t)n);
    close(fd);

    /* Hold briefly so the host can observe adoption, then exit (orphan). */
    ts.tv_sec = 0;
    ts.tv_nsec = 500000000;
    nanosleep(&ts, NULL);
    _exit(0);
}
"##;

/// Linux uapi values used by the raw reaper syscalls. Declared as plain
/// `extern` so the test target needs no extra crate: the test binary links
/// glibc through std, which exports these symbols.
const PR_SET_CHILD_SUBREAPER: i32 = 36;
const WNOHANG: i32 = 1;

extern "C" {
    fn prctl(option: i32, a2: usize, a3: usize, a4: usize, a5: usize) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

fn oci_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-oci")
}

fn rootfs_helper() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/rootfs-helper")
}

/// Minimal OCI bundle whose main process is the long-lived `spawn-loop`
/// keepalive; the exec'd static probe is dropped into the rootfs separately.
fn write_bundle_config(bundle: &Path) {
    let config = r#"{
  "ociVersion": "1.0.2",
  "root": { "path": "rootfs", "readonly": false },
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "cwd": "/",
    "args": ["/rootfs-helper", "spawn-loop", "/keepalive.cnt"],
    "env": ["PATH=/usr/bin:/bin"]
  },
  "mounts": [],
  "linux": {
    "resources": {
      "devices": [ { "allow": false, "access": "rwm" } ]
    },
    "namespaces": [ { "type": "mount" } ]
  }
}
"#;
    fs::write(bundle.join("config.json"), config).unwrap();
}

/// Compile the static orphan probe into the rootfs (exec'd at `/orphan-helper`).
fn build_orphan_helper(rootfs: &Path) -> Result<(), String> {
    let src = rootfs.join("orphan-helper.c");
    let bin = rootfs.join("orphan-helper");
    fs::write(&src, ORPHAN_HELPER_C).unwrap();
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
            "orphan-helper build failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    Ok(())
}

/// Make this test process a subreaper so orphaned descendants deterministically
/// reparent to *us* unless a closer subreaper (sandlock-init, after the fix)
/// claims them first. Returns false on unsupported kernels.
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

/// (state char, ppid) for `pid`, parsed from /proc/<pid>/stat.
fn proc_stat(pid: i32) -> Option<(char, i32)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rfind(')')? + 2;
    let rest = stat.get(after..)?;
    let mut it = rest.split_whitespace();
    let state = it.next()?.chars().next()?;
    let ppid = it.next()?.parse().ok()?;
    Some((state, ppid))
}

/// PIDs of defunct (`Z`) direct children of `parent`.
fn defunct_children_of(parent: i32) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if let Some((state, ppid)) = proc_stat(pid) {
            if state == 'Z' && ppid == parent {
                out.push(pid);
            }
        }
    }
    out
}

fn proc_exists(pid: i32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// Reap every child of this process. Used only after container teardown,
/// never while a defunct-accumulation observation is live.
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

/// Poll `path` until the marker contains `round=`, returning its contents.
fn wait_marker(path: &Path, round: i32, deadline: Duration) -> Option<String> {
    let end = Instant::now() + deadline;
    loop {
        if let Ok(s) = fs::read_to_string(path) {
            if s.contains(&format!("round={round} ")) {
                return Some(s);
            }
        }
        if Instant::now() > end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Parse `round=N pid=M ppid=K` from a marker line.
fn parse_marker(s: &str) -> Option<(i32, i32, i32)> {
    fn val(s: &str, key: &str) -> Option<i32> {
        let needle = format!("{key}=");
        let start = s.find(needle.as_str())? + needle.len();
        let rest = &s[start..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse().ok()
    }
    Some((val(s, "round")?, val(s, "pid")?, val(s, "ppid")?))
}

/// Read `state.json` under `root/<id>` and return the recorded pid.
fn state_pid(root: &Path, id: &str) -> Option<i32> {
    let s = fs::read_to_string(root.join(id).join("state.json")).ok()?;
    let start = s.find("\"pid\"")?;
    let rest = &s[start..];
    let digits: String = rest
        .chars()
        .skip_while(|c| *c != ':')
        .skip(1)
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn read_counter(path: &Path) -> Option<u64> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// One OCI container under test. Lifecycle helpers return results instead of
/// panicking so every test can tear the container down before asserting.
struct Container {
    _tmp: TempDir,
    root: PathBuf,
    rootfs: PathBuf,
    bundle: PathBuf,
    id: String,
    log: PathBuf,
    /// sandlock-init's pid, captured from state.json right after `create`
    /// (before `start` overwrites state.pid with the workload pid).
    init_pid: i32,
}

impl Container {
    /// Build the bundle, `create` + `start` the sandbox, and wait until the
    /// main keepalive workload is genuinely running. On partial failure the
    /// sandbox is deleted and reaped before returning `Err`.
    fn boot(tag: &str) -> Result<Self, String> {
        let tmp = TempDir::new().map_err(|e| format!("tempdir: {e}"))?;
        let base = tmp.path().to_path_buf();
        let root = base.join("root");
        let bundle = base.join("bundle");
        let rootfs = bundle.join("rootfs");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(rootfs.join("rounds")).unwrap();
        fs::copy(rootfs_helper(), rootfs.join("rootfs-helper"))
            .map_err(|e| format!("copy rootfs-helper: {e}"))?;
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                rootfs.join("rootfs-helper"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        write_bundle_config(&bundle);
        build_orphan_helper(&rootfs)?;

        let id = format!("f15-{tag}-{}", std::process::id());
        let log = base.join("lifecycle.log");
        let mut c = Container {
            _tmp: tmp,
            root,
            rootfs,
            bundle,
            id,
            log,
            init_pid: 0,
        };

        if !c
            .run(&["create", &c.id, "-b", c.bundle.to_str().unwrap()])
            .success()
        {
            let msg = format!("create failed:\n{}", c.log_text());
            let _ = c.run(&["delete", &c.id, "--force"]);
            let _ = reap_children(Duration::from_secs(2));
            return Err(msg);
        }
        c.init_pid = state_pid(&c.root, &c.id).expect("state.pid after create is sandlock-init");
        if !c.run(&["start", &c.id]).success() {
            let msg = format!("start failed:\n{}", c.log_text());
            let _ = c.run(&["delete", &c.id, "--force"]);
            let _ = reap_children(Duration::from_secs(2));
            return Err(msg);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if read_counter(&c.rootfs.join("keepalive.cnt"))
                .map(|v| v > 2)
                .unwrap_or(false)
            {
                return Ok(c);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let msg = format!("keepalive never advanced:\n{}", c.log_text());
        let _ = c.run(&["delete", &c.id, "--force"]);
        let _ = reap_children(Duration::from_secs(2));
        Err(msg)
    }

    fn log_text(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Run the OCI CLI with `argv` (after `--root <root>`); stdio goes to the
    /// lifecycle log file (the supervisor inherits it after `create`).
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
        cmd.stdout(std::process::Stdio::from(out))
            .stderr(std::process::Stdio::from(err))
            .status()
            .unwrap_or_else(|e| panic!("failed to run sandlock-oci: {e}"))
    }

    /// Attached exec of an in-rootfs command (returns when the exec'd process
    /// exits; stdio is redirected to the log, so a grandchild cannot hang it).
    fn exec(&self, args: &[&str]) -> std::process::ExitStatus {
        let mut argv = vec!["exec", &self.id];
        argv.extend_from_slice(args);
        self.run(&argv)
    }

    /// `delete --force`, then reap whatever reparented to us (the supervisor
    /// and, in a failing pre-fix run, adopted orphan defuncts).
    fn teardown(&self) -> bool {
        let del_ok = self.run(&["delete", &self.id, "--force"]).success();
        let reaped = reap_children(Duration::from_secs(3));
        del_ok && reaped
    }
}

fn supported_env() -> bool {
    if !cfg!(target_os = "linux") || !cfg!(target_arch = "x86_64") {
        eprintln!("skipping: double-fork probe is x86_64 Linux-only");
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

/// One double-fork round: exec the probe, read the orphan's marker, and wait
/// for the orphan to be reaped (pid gone from /proc).
struct RoundResult {
    exec_ok: bool,
    orphan_pid: Option<i32>,
    orphan_ppid: Option<i32>,
    reaped: bool,
}

fn run_orphan_round(c: &Container, round: i32) -> RoundResult {
    let marker_path = c.rootfs.join("rounds").join(format!("r{round}"));
    let guest_path = format!("/rounds/r{round}");
    let exec_ok = c
        .exec(&["/orphan-helper", "orphan", &guest_path, &round.to_string()])
        .success();
    let marker = wait_marker(&marker_path, round, Duration::from_secs(3));
    let parsed = marker.as_deref().and_then(parse_marker);
    let (orphan_pid, orphan_ppid) = parsed
        .map(|(_, pid, ppid)| (Some(pid), Some(ppid)))
        .unwrap_or((None, None));
    let reaped = orphan_pid.map_or(false, |pid| {
        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {
            if !proc_exists(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    });
    RoundResult {
        exec_ok,
        orphan_pid,
        orphan_ppid,
        reaped,
    }
}

/// The container must still accept an exec and keep its main workload alive
/// after orphan reaping (probe exec + keepalive advance).
fn usable_after(c: &Container) -> bool {
    let sentinel = c.rootfs.join("after-ok");
    let before = read_counter(&c.rootfs.join("keepalive.cnt")).unwrap_or(0);
    let exec_ok = c
        .exec(&["/rootfs-helper", "write", "/after-ok", "ok"])
        .success();
    let sentinel_ok = sentinel.exists()
        && fs::read_to_string(&sentinel)
            .map(|s| s.trim() == "ok")
            .unwrap_or(false);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut advanced = false;
    while Instant::now() < deadline {
        if read_counter(&c.rootfs.join("keepalive.cnt"))
            .map(|v| v > before)
            .unwrap_or(false)
        {
            advanced = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    exec_ok && sentinel_ok && advanced
}

#[test]
fn test_adopted_orphan_is_reaped() {
    if !supported_env() || !set_subreaper() {
        return;
    }
    let c = match Container::boot("adopt") {
        Ok(c) => c,
        Err(msg) => panic!("container boot failed: {msg}"),
    };

    let round = run_orphan_round(&c, 1);
    let self_pid = std::process::id() as i32;
    let init_defuncts = defunct_children_of(c.init_pid);
    let self_defuncts = defunct_children_of(self_pid);
    let usable = usable_after(&c);
    let cleaned = c.teardown();

    let orphan_pid = round.orphan_pid.expect("orphan marker must carry its pid");
    let round_ppid = round
        .orphan_ppid
        .expect("orphan marker must carry its ppid");
    assert!(
        round.exec_ok,
        "exec of the double-fork probe failed:\n{}",
        c.log_text()
    );
    assert_eq!(
        round_ppid, c.init_pid,
        "a double-fork orphan must be adopted by sandlock-init (the nearest \
         subreaper), not by the outer reaper; observed ppid={round_ppid}, \
         init={} (orphan pid {orphan_pid}). Without PR_SET_CHILD_SUBREAPER the \
         orphan reparents past init.",
        c.init_pid,
    );
    assert!(
        round.reaped,
        "adopted orphan pid {orphan_pid} must be reaped by init's \
         waitpid(-1, WNOHANG) sweep (still present in /proc after exit; \
         defuncts under init={init_defuncts:?}, under test subreaper={self_defuncts:?})",
    );
    assert!(
        init_defuncts.is_empty(),
        "no defunct may remain under sandlock-init after the adopted orphan \
         exits: {init_defuncts:?}"
    );
    assert!(
        self_defuncts.is_empty(),
        "the orphan must not leak as a defunct of the test subreaper: \
         {self_defuncts:?}"
    );
    assert!(
        usable,
        "container must stay usable after the adopted orphan is reaped"
    );
    assert!(cleaned, "delete --force and child reaping must succeed");
}

#[test]
fn test_no_defunct_after_double_fork() {
    if !supported_env() || !set_subreaper() {
        return;
    }
    let c = match Container::boot("storm") {
        Ok(c) => c,
        Err(msg) => panic!("container boot failed: {msg}"),
    };
    let self_pid = std::process::id() as i32;

    const ROUNDS: i32 = 5;
    let mut all_reaped = true;
    let mut first_unreaped = None;
    for round in 1..=ROUNDS {
        let r = run_orphan_round(&c, round);
        if !r.exec_ok {
            let _ = c.teardown();
            panic!(
                "round {round} exec of the double-fork probe failed:\n{}",
                c.log_text()
            );
        }
        let opid = match r.orphan_pid {
            Some(p) => p,
            _ => {
                let _ = c.teardown();
                panic!(
                    "round {round} orphan marker was never written:\n{}",
                    c.log_text()
                );
            }
        };
        if !r.reaped {
            all_reaped = false;
            first_unreaped.get_or_insert((round, opid));
        }
    }

    let init_defuncts = defunct_children_of(c.init_pid);
    let self_defuncts = defunct_children_of(self_pid);
    let usable = usable_after(&c);
    let cleaned = c.teardown();

    assert!(
        all_reaped,
        "every double-fork orphan must be reaped: round {round} orphan pid \
         {pid} was never reaped (defuncts under init={init_defuncts:?}, under \
         the test subreaper={self_defuncts:?}; init={init})",
        round = first_unreaped.map(|x| x.0).unwrap_or(0),
        pid = first_unreaped.map(|x| x.1).unwrap_or(0),
        init = c.init_pid,
    );
    assert!(
        init_defuncts.is_empty(),
        "defunct count under sandlock-init must not grow across {ROUNDS} \
         double forks: {init_defuncts:?}"
    );
    assert!(
        self_defuncts.is_empty(),
        "defunct count under the test subreaper must not grow across {ROUNDS} \
         double forks: {self_defuncts:?}"
    );
    assert!(
        usable,
        "container must remain usable (exec + keepalive) after {ROUNDS} double forks"
    );
    assert!(cleaned, "delete --force and child reaping must succeed");
}
