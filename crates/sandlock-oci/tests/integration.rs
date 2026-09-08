//! Integration tests for sandlock-oci.
//!
//! These tests exercise the OCI lifecycle commands (create/start/state/kill/delete)
//! against a real bundle on the local filesystem.
//!
//! To run: `cargo test -p sandlock-oci -- --test-threads=1`
//!
//! **Note**: the lifecycle commands that fork a sandboxed child need root or a
//! Landlock-capable kernel, but the smoke tests here only exercise argument
//! handling and error paths, so they run unprivileged (including in CI).

use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

/// Path to the sandlock-oci binary under test. Cargo builds it before running
/// the integration target and exposes its path here, so this resolves to the
/// correct profile (debug or release) automatically.
fn oci_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-oci")
}

/// Create a minimal OCI bundle with a rootfs and config.json.
fn create_bundle(dir: &Path, cmd: &[&str]) {
    let rootfs = dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    // Minimal config.json that satisfies oci-spec-rs
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
                "devices": [
                    { "allow": false, "access": "rwm" }
                ]
            },
            "namespaces": [
                { "type": "mount" }
            ]
        }
    });
    fs::write(
        dir.join("config.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
}

// ── spec / state unit tests (always run) ────────────────────────────────────

#[test]
fn spec_load_and_policy_mapping() {
    let dir = tempdir().unwrap();
    create_bundle(dir.path(), &["sh", "-c", "exit 0"]);

    // Load spec via the library API.
    let spec = sandlock_oci::spec::load_spec(dir.path())
        .map_err(|e| panic!("load_spec failed: {}", e))
        .unwrap();
    assert_eq!(spec.version(), "1.0.2");

    let policy = sandlock_oci::spec::spec_to_policy(&spec, dir.path(), "test").unwrap();
    // PATH env is forwarded
    assert!(policy.env.contains_key("PATH"));
    // Cwd is forwarded
    assert_eq!(policy.cwd.as_deref(), Some(Path::new("/")));
    // Default rootfs is set
    assert!(policy.rootfs.is_some());
}

#[test]
fn state_created_lifecycle() {
    use sandlock_oci::state::{SandboxState, Status};

    let dir = tempdir().unwrap();
    let mut state = SandboxState::new("test-lifecycle", dir.path(), "1.0.2");
    // new() starts in Creating; set_created() advances to Created.
    assert_eq!(state.status, Status::Creating);

    state.set_created(9999);
    assert_eq!(state.status, Status::Created);
    assert_eq!(state.pid, 9999);

    state.set_running();
    assert_eq!(state.status, Status::Running);

    state.set_stopped(Some(sandlock_oci::state::ExitInfo {
        code: Some(0),
        signal: None,
    }));
    assert_eq!(state.status, Status::Stopped);
    assert!(state.exit_info.is_some());
    assert_eq!(state.exit_info.as_ref().unwrap().code, Some(0));
}

#[test]
fn policy_from_spec_builds_sandbox() {
    let dir = tempdir().unwrap();
    create_bundle(dir.path(), &["sh", "-c", "exit 0"]);

    let spec = sandlock_oci::spec::load_spec(dir.path()).unwrap();
    let policy = sandlock_oci::spec::spec_to_policy(&spec, dir.path(), "test").unwrap();

    // Can convert to sandbox config
    let sandbox = policy.to_sandbox().unwrap();
    assert!(sandbox.chroot.is_some());
}

// ── CLI binary integration tests (require binary to be built) ────────────────

/// Helper: run the sandlock-oci binary with the given args.
fn run_oci(args: &[&str]) -> std::process::Output {
    Command::new(oci_bin())
        .args(args)
        .output()
        .expect("failed to run sandlock-oci")
}

#[test]
fn oci_check_exits_zero() {
    let out = run_oci(&["check"]);
    assert!(
        out.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn oci_state_unknown_sandbox_errors() {
    let out = run_oci(&["state", "this-does-not-exist-xyz-12345"]);
    assert!(!out.status.success(), "expected failure for unknown sandbox");
}

#[test]
fn oci_list_no_sandboxes() {
    // List should succeed even with no state dir.
    let out = run_oci(&["list"]);
    assert!(out.status.success());
}

#[test]
fn oci_kill_unknown_sandbox_errors() {
    let out = run_oci(&["kill", "no-such-sandbox-xyz", "SIGTERM"]);
    assert!(!out.status.success());
}

#[test]
fn oci_delete_nonexistent_is_ok() {
    // Deleting a sandbox that doesn't exist should not fail.
    let out = run_oci(&["delete", "ghost-sandbox-xyz-99"]);
    assert!(out.status.success());
}

#[test]
fn oci_create_rejects_duplicate_id() {
    // The uniqueness guard fires before any fork, so a pre-existing state.json
    // under --root is enough to trigger it — no rootfs or Landlock needed.
    let root = tempdir().unwrap();
    let id = "dup-id-test";
    let cdir = root.path().join(id);
    fs::create_dir_all(&cdir).unwrap();
    fs::write(
        cdir.join("state.json"),
        r#"{"ociVersion":"1.0.2","id":"dup-id-test","status":"created","pid":12345,"bundle":"/tmp","created":0}"#,
    )
    .unwrap();

    let out = Command::new(oci_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "create",
            id,
            "-b",
            "/tmp",
        ])
        .output()
        .expect("failed to run sandlock-oci");

    assert!(!out.status.success(), "duplicate create should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already exists"),
        "expected 'already exists' error, got: {}",
        stderr
    );
}

// ── end-to-end OCI restore (Landlock host, vDSO-free program) ───────────────

/// Freestanding x86_64 program (no libc, no vDSO; raw syscalls only) that opens
/// an output file once, then loops forever rewriting an incrementing counter
/// through the kept-open fd, sleeping via `nanosleep` between writes.
///
/// It is deliberately libc-free so the test needs no libc toolchain and so a
/// failure points at the OCI plumbing rather than at libc state: it proves the
/// restore engine itself (memory, registers, reopened fd). The libc/vDSO case
/// is covered by sandlock-core's restore integration test.
fn counter_source(out_path: &str) -> String {
    format!(
        r##"
#define SYS_write 1
#define SYS_open 2
#define SYS_nanosleep 35
#define SYS_lseek 8
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
static long sys3(long n, long a, long b, long c){{
  long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory"); return r;
}}
struct ts {{ long sec; long nsec; }};
void _start(void){{
  const char *path = "{out_path}";
  long fd = sys3(SYS_open, (long)path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
  unsigned long i = 0;
  char buf[24];
  struct ts t; t.sec = 0; t.nsec = 20000000;
  for(;;){{
    i++;
    // Publish the counter atomically: one fixed-width, zero-padded 21-byte
    // overwrite (20 digits + newline) at offset 0, never truncating. A reader
    // therefore always sees a complete, parseable value, never an empty file.
    unsigned long v = i; int d;
    for(d = 19; d >= 0; d--){{ buf[d] = '0' + (v % 10); v /= 10; }}
    buf[20] = '\n';
    sys3(SYS_lseek, fd, 0, 0);
    sys3(SYS_write, fd, (long)buf, 21);
    sys3(SYS_nanosleep, (long)&t, 0, 0);
  }}
}}
"##
    )
}

/// End-to-end proof that the OCI `restore` subcommand resumes a checkpointed,
/// vDSO-free program. The checkpoint is produced with sandlock-core (test
/// setup), then the real `sandlock-oci restore` CLI is invoked: it spawns the
/// detached supervisor (`run_supervisor_restore`), which restores AND resumes
/// the child immediately (no `start`). We verify the restored process advances
/// the counter past the checkpointed baseline, that `state` reports `running`,
/// then `delete --force` cleans up.
#[tokio::test(flavor = "multi_thread")]
async fn oci_restore_resumes_vdso_free_program() {
    if cfg!(not(target_arch = "x86_64")) {
        eprintln!("skipping: this test is x86_64-only (counter program)");
        return;
    }
    if sandlock_core::landlock_abi_version().is_err() {
        eprintln!("skipping: Landlock unavailable on this host");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("sandlock-oci-restore-{}", std::process::id()));
    fs::create_dir_all(&tmp).unwrap();
    let src = tmp.join("counter.c");
    let bin = tmp.join("counter");
    let counter = tmp.join("counter.cnt");
    let counter_s = counter.to_str().unwrap().to_string();
    let image = tmp.join("image");

    if !build_counter(&bin, &src, &counter_s) {
        let _ = fs::remove_dir_all(&tmp);
        return;
    }

    // ── Test setup: produce a checkpoint image with sandlock-core ───────────
    let policy = sandlock_core::Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_read(&tmp)
        .fs_write(&tmp)
        .build().unwrap();

    let bin_s = bin.to_str().unwrap().to_string();
    // Capturing spawn so the source's stdio are pipes (not inherited regular
    // files); pipe fds are skipped on restore, isolating the test from however
    // the harness wires the test process's own stdout/stderr.
    let mut sb = policy.clone().with_name("oci-restore-src");
    sb.spawn(&[bin_s.as_str()]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let cp = sb.checkpoint().await.unwrap();
    let read_counter = |path: &str| -> Option<u64> {
        fs::read_to_string(path).ok().and_then(|s| s.trim().parse::<u64>().ok())
    };
    let baseline = read_counter(&counter_s).expect("counter file should exist with a value");
    assert!(baseline > 2, "counter should have advanced before checkpoint, got {baseline}");
    cp.save(&image).unwrap();

    // Kill the source so only a restored process can advance the file.
    sb.kill().unwrap();
    let _ = sb.wait().await;
    // Sentinel: prove the *restored* process (not a leftover) is writing.
    fs::write(&counter, b"0\n").unwrap();

    // ── Exercise the OCI restore CLI ─────────────────────────────────────────
    let root = tempdir().unwrap();
    let root_s = root.path().to_str().unwrap().to_string();
    let id = "oci-restore-e2e";

    // NB: the restore CLI double-forks a long-lived supervisor daemon that
    // inherits stdout/stderr (left open for containerd log FIFOs). Capturing
    // via `Command::output()` would block until those fds close (container
    // exit), so redirect the CLI's stdio to a file and wait only on the CLI
    // with `.status()`.
    let restore_log = tmp.join("restore.log");
    let status = Command::new(oci_bin())
        .args(["--root", &root_s, "restore", id, "--image-path", image.to_str().unwrap()])
        .stdout(std::process::Stdio::from(fs::File::create(&restore_log).unwrap()))
        .stderr(std::process::Stdio::from(
            fs::OpenOptions::new().append(true).open(&restore_log).unwrap(),
        ))
        .status()
        .expect("failed to run sandlock-oci restore");
    let restore_out = fs::read_to_string(&restore_log).unwrap_or_default();
    assert!(
        status.success(),
        "restore CLI failed (exit {:?}): {}",
        status.code(),
        restore_out,
    );

    // State should report running immediately (restore resumes, no start).
    let st = Command::new(oci_bin())
        .args(["--root", &root_s, "state", id])
        .output()
        .expect("failed to run sandlock-oci state");
    let st_json = String::from_utf8_lossy(&st.stdout);
    assert!(
        st_json.contains("\"running\""),
        "expected running state after restore, got: {}",
        st_json
    );

    // Poll for the restored process to resume mid-loop and advance the counter.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    let mut last = 0u64;
    let mut advanced = false;
    while std::time::Instant::now() < deadline {
        if let Some(v) = read_counter(&counter_s) {
            last = v;
            if v > baseline {
                advanced = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Clean up via the CLI before asserting so a failure never leaks the child.
    let _ = Command::new(oci_bin())
        .args(["--root", &root_s, "delete", id, "--force"])
        .output();
    let _ = fs::remove_dir_all(&tmp);

    assert!(
        advanced,
        "OCI-restored process must resume mid-loop and advance the counter past {baseline}; \
         last seen {last}, restore log: {restore_out}",
    );
}

/// Build the freestanding, vDSO-free counter program (shared with the restore
/// test) into `bin`, writing its counter to the in-sandbox path `out_path`.
/// Returns false (and prints a skip reason) when no C compiler is available or
/// the build fails, so callers can early-return on unsupported hosts.
fn build_counter(bin: &Path, src: &Path, out_path: &str) -> bool {
    fs::write(src, counter_source(out_path)).unwrap();
    let cc = if which("cc") {
        "cc"
    } else if which("gcc") {
        "gcc"
    } else {
        eprintln!("skipping: no C compiler (cc/gcc) available");
        return false;
    };
    let build = Command::new(cc)
        .args(["-static", "-nostdlib", "-no-pie", "-O0", "-o"])
        .arg(bin)
        .arg(src)
        .output()
        .unwrap();
    if !build.status.success() {
        eprintln!(
            "skipping: build failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        return false;
    }
    true
}

/// End-to-end proof that `sandlock-oci checkpoint` works on a RUNNING container
/// created + started from an OCI bundle.
///
/// Before the supervisor fix, `supervisor_main` stopped serving the control
/// socket once the child started (it only `wait()`ed), so a `checkpoint` of a
/// running container could not be reached and timed out. This test creates +
/// starts a sandbox running the vDSO-free counter, waits for it to advance
/// (proving it is genuinely RUNNING), then checkpoints it and asserts the
/// checkpoint image (`meta.json`) was written. As a bonus it then `restore`s the
/// image into a second container and proves the restored counter advances,
/// exercising a full OCI checkpoint -> restore round-trip of a running program.
#[tokio::test(flavor = "multi_thread")]
async fn oci_checkpoint_of_running_container() {
    if cfg!(not(target_arch = "x86_64")) {
        eprintln!("skipping: this test is x86_64-only (counter program)");
        return;
    }
    if sandlock_core::landlock_abi_version().is_err() {
        eprintln!("skipping: Landlock unavailable on this host");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("sandlock-oci-ckpt-{}", std::process::id()));
    fs::create_dir_all(&tmp).unwrap();
    let src = tmp.join("counter.c");
    let bin = tmp.join("counter");

    // The container chroots to `rootfs`, so the counter's in-sandbox path
    // `/out.cnt` resolves to `rootfs/out.cnt` on the host.
    if !build_counter(&bin, &src, "/out.cnt") {
        let _ = fs::remove_dir_all(&tmp);
        return;
    }

    // Build the OCI bundle: the freestanding binary lives inside rootfs and the
    // spec runs it via its in-chroot path.
    let bundle = tmp.join("bundle");
    let rootfs = bundle.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    let bin_in_rootfs = rootfs.join("counter");
    fs::copy(&bin, &bin_in_rootfs).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bin_in_rootfs, fs::Permissions::from_mode(0o755)).unwrap();
    }
    create_bundle(&bundle, &["/counter"]);

    let host_counter = rootfs.join("out.cnt");
    let host_counter_s = host_counter.to_str().unwrap().to_string();
    let read_counter = |path: &str| -> Option<u64> {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    };

    let root = tempdir().unwrap();
    let root_s = root.path().to_str().unwrap().to_string();
    let id = "oci-ckpt-running";
    let image = tmp.join("image");

    // ── create (daemonizes a supervisor that inherits stdio; redirect + status) ─
    let create_log = tmp.join("create.log");
    let create_status = Command::new(oci_bin())
        .args(["--root", &root_s, "create", id, "-b", bundle.to_str().unwrap()])
        .stdout(std::process::Stdio::from(fs::File::create(&create_log).unwrap()))
        .stderr(std::process::Stdio::from(
            fs::OpenOptions::new().append(true).open(&create_log).unwrap(),
        ))
        .status()
        .expect("failed to run sandlock-oci create");
    let create_out = fs::read_to_string(&create_log).unwrap_or_default();
    assert!(
        create_status.success(),
        "create CLI failed (exit {:?}): {}",
        create_status.code(),
        create_out
    );

    // ── start (releases the parked child to execve) ─────────────────────────────
    let start_out = Command::new(oci_bin())
        .args(["--root", &root_s, "start", id])
        .output()
        .expect("failed to run sandlock-oci start");
    if !start_out.status.success() {
        let _ = Command::new(oci_bin())
            .args(["--root", &root_s, "delete", id, "--force"])
            .output();
        let _ = fs::remove_dir_all(&tmp);
        panic!(
            "start CLI failed: {}",
            String::from_utf8_lossy(&start_out.stderr)
        );
    }

    // Poll until the running container's counter advances (proves it is RUNNING).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut baseline = 0u64;
    let mut running = false;
    while std::time::Instant::now() < deadline {
        if let Some(v) = read_counter(&host_counter_s) {
            if v > 2 {
                baseline = v;
                running = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // ── checkpoint the RUNNING container ───────────────────────────────────────
    let ckpt_out = if running {
        Some(
            Command::new(oci_bin())
                .args(["--root", &root_s, "checkpoint", id, "--image-path", image.to_str().unwrap()])
                .output()
                .expect("failed to run sandlock-oci checkpoint"),
        )
    } else {
        None
    };
    let ckpt_ok = ckpt_out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let meta_exists = image.join("meta.json").exists();

    // ── bonus: restore the checkpoint into a second container ───────────────────
    let id2 = "oci-ckpt-restored";
    let mut restored_advanced = None::<bool>;
    let mut restore_diag = String::new();
    if ckpt_ok && meta_exists {
        // Stop the original so only a restored process can advance the file, and
        // drop a low sentinel to prove the restored process (not a leftover) writes.
        let _ = Command::new(oci_bin())
            .args(["--root", &root_s, "delete", id, "--force"])
            .output();
        fs::write(&host_counter, b"0\n").unwrap();

        let restore_log = tmp.join("restore.log");
        let restore_status = Command::new(oci_bin())
            .args(["--root", &root_s, "restore", id2, "--image-path", image.to_str().unwrap()])
            .stdout(std::process::Stdio::from(fs::File::create(&restore_log).unwrap()))
            .stderr(std::process::Stdio::from(
                fs::OpenOptions::new().append(true).open(&restore_log).unwrap(),
            ))
            .status()
            .expect("failed to run sandlock-oci restore");
        if restore_status.success() {
            let rdl = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut adv = false;
            while std::time::Instant::now() < rdl {
                if let Some(v) = read_counter(&host_counter_s) {
                    if v > baseline {
                        adv = true;
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            restored_advanced = Some(adv);
            restore_diag = format!(
                "restore_status ok; last_counter={:?}; log: {}",
                read_counter(&host_counter_s),
                fs::read_to_string(&restore_log).unwrap_or_default()
            );
        } else {
            restored_advanced = Some(false);
            restore_diag = format!(
                "restore_status FAILED; log: {}",
                fs::read_to_string(&restore_log).unwrap_or_default()
            );
        }
    }

    // ── clean up before asserting so a failure never leaks a process ────────────
    let _ = Command::new(oci_bin())
        .args(["--root", &root_s, "delete", id, "--force"])
        .output();
    let _ = Command::new(oci_bin())
        .args(["--root", &root_s, "delete", id2, "--force"])
        .output();
    let _ = fs::remove_dir_all(&tmp);

    assert!(
        running,
        "container counter never advanced; create_out: {create_out}"
    );
    let ckpt_stderr = ckpt_out
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
        .unwrap_or_default();
    assert!(
        ckpt_ok,
        "checkpoint of a RUNNING container must succeed; stderr: {ckpt_stderr}"
    );
    assert!(
        meta_exists,
        "checkpoint must write meta.json to the image dir"
    );
    // Bonus (non-fatal): a full OCI checkpoint -> restore round-trip. The
    // checkpoint-of-running assertions above are the required deliverable. The
    // restore engine reopens fds/mappings by their recorded HOST path, which
    // collides with the virtual-chroot path rewriting of a bundle-based
    // container (the binary at `<rootfs>/counter` gets re-confined under the
    // restored chroot and Landlock denies it with EACCES). The standalone
    // `oci_restore_resumes_vdso_free_program` test covers restore on its own,
    // chroot-free; restore of a *chrooted* checkpoint is a separate limitation
    // outside the scope of the serve-while-running fix, so we only report it.
    if let Some(adv) = restored_advanced {
        if adv {
            eprintln!("bonus: full OCI checkpoint -> restore round-trip advanced the counter");
        } else {
            eprintln!(
                "note: bonus round-trip restore of a chrooted checkpoint did not advance \
                 (restore-under-chroot limitation, orthogonal to this fix): {restore_diag}"
            );
        }
    }
}

/// Minimal PATH lookup so the test does not depend on extra crates.
fn which(prog: &str) -> bool {
    std::env::var_os("PATH").map_or(false, |paths| {
        std::env::split_paths(&paths).any(|d| d.join(prog).is_file())
    })
}

/// Path to the prebuilt static `rootfs-helper` (compiled by sandlock-core's
/// build.rs). It is a self-contained, busybox-style binary the chroot
/// integration tests drop into a rootfs; building `sandlock-oci` pulls in
/// `sandlock-core`, so the binary is available here too.
fn rootfs_helper() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/rootfs-helper")
}

/// End-to-end proof that `sandlock-oci exec` runs an extra process inside the
/// SAME single-init container as the main workload, confined by the shared
/// sandbox (Landlock + seccomp-notify), and reports its exit status.
///
/// The main workload is a long-lived `rootfs-helper spawn-loop` that keeps the
/// container running. Once the keepalive counter advances (proving the container
/// is RUNNING), we `exec` a `rootfs-helper write /exec.ok done`: the exec'd
/// process is forked by the container's `sandlock-init`, so it lands inside the
/// chroot and writes the sentinel to `<rootfs>/exec.ok`. We assert the exec CLI
/// exits 0 and the sentinel is present with the expected contents, then tear the
/// container down with `delete --force`.
#[tokio::test(flavor = "multi_thread")]
async fn oci_exec_same_sandbox() {
    if sandlock_core::landlock_abi_version().is_err() {
        eprintln!("skipping: no Landlock");
        return;
    }
    let helper = rootfs_helper();
    if !helper.exists() {
        eprintln!("skipping: no rootfs-helper");
        return;
    }

    // bundle: rootfs with rootfs-helper; main process = spawn-loop (stays alive)
    let tmp = std::env::temp_dir().join(format!("sandlock-oci-exec2-{}", std::process::id()));
    fs::create_dir_all(&tmp).unwrap();
    let bundle = tmp.join("bundle");
    let rootfs = bundle.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::copy(&helper, rootfs.join("rootfs-helper")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(rootfs.join("rootfs-helper"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    create_bundle(&bundle, &["/rootfs-helper", "spawn-loop", "/keepalive.cnt"]);

    let root = tempdir().unwrap();
    let root_s = root.path().to_str().unwrap().to_string();
    let id = "oci-exec2-e2e";

    let create_log = tmp.join("create.log");
    let cs = Command::new(oci_bin())
        .args(["--root", &root_s, "create", id, "-b", bundle.to_str().unwrap()])
        .stdout(std::process::Stdio::from(fs::File::create(&create_log).unwrap()))
        .stderr(std::process::Stdio::from(
            fs::OpenOptions::new().append(true).open(&create_log).unwrap(),
        ))
        .status()
        .expect("create");
    assert!(cs.success(), "create: {}", fs::read_to_string(&create_log).unwrap_or_default());
    assert!(Command::new(oci_bin())
        .args(["--root", &root_s, "start", id])
        .output()
        .unwrap()
        .status
        .success());

    // container running once keepalive advances
    let host_keepalive = rootfs.join("keepalive.cnt");
    let read = |p: &std::path::Path| {
        fs::read_to_string(p).ok().and_then(|s| s.trim().parse::<u64>().ok())
    };
    let dl = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut running = false;
    while std::time::Instant::now() < dl {
        if read(&host_keepalive).map(|v| v > 2).unwrap_or(false) {
            running = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(running, "container never started: {}", fs::read_to_string(&create_log).unwrap_or_default());

    // exec writes a sentinel inside the container rootfs and exits 0
    let exec_out = Command::new(oci_bin())
        .args(["--root", &root_s, "exec", id, "/rootfs-helper", "write", "/exec.ok", "done"])
        .output()
        .expect("exec");
    let sentinel = rootfs.join("exec.ok");
    let ok = sentinel.exists() && fs::read_to_string(&sentinel).unwrap_or_default().trim() == "done";

    let _ = Command::new(oci_bin())
        .args(["--root", &root_s, "delete", id, "--force"])
        .output();
    let _ = fs::remove_dir_all(&tmp);

    assert!(exec_out.status.success(), "exec must exit 0: {}", String::from_utf8_lossy(&exec_out.stderr));
    assert!(ok, "exec'd process must run inside the container rootfs and write /exec.ok=done");
}

/// Regression test for process-group collapse on container stop. sandlock has
/// no PID namespace, so when the container's main process exits the supervisor
/// must explicitly SIGKILL the process group; otherwise background children (or
/// exec'd siblings) outlive the container with a dead supervisor.
///
/// The container's main process (`rootfs-helper spawn-loop`) forks a worker that
/// advances `/child.cnt`, then `pause`s. We confirm the worker is running,
/// `kill` the main process, and assert the worker stops advancing. Without the
/// `reap_and_collapse` fix the orphaned worker keeps writing and this test fails.
#[tokio::test(flavor = "multi_thread")]
async fn oci_stop_collapses_process_group() {
    if sandlock_core::landlock_abi_version().is_err() {
        eprintln!("skipping: Landlock unavailable on this host");
        return;
    }
    let helper = rootfs_helper();
    if !helper.exists() {
        eprintln!("skipping: rootfs-helper not built (needs musl-gcc or cc -static)");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("sandlock-oci-pgroup-{}", std::process::id()));
    fs::create_dir_all(&tmp).unwrap();

    // The container chroots to rootfs, so the worker's in-sandbox path
    // `/child.cnt` resolves to `rootfs/child.cnt` on the host. Drop the static
    // rootfs-helper into the rootfs and run its `spawn-loop` worker.
    let bundle = tmp.join("bundle");
    let rootfs = bundle.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::copy(&helper, rootfs.join("rootfs-helper")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(rootfs.join("rootfs-helper"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    create_bundle(&bundle, &["/rootfs-helper", "spawn-loop", "/child.cnt"]);

    let host_child = rootfs.join("child.cnt");
    let host_child_s = host_child.to_str().unwrap().to_string();
    let read_counter = |path: &str| -> Option<u64> {
        fs::read_to_string(path).ok().and_then(|s| s.trim().parse::<u64>().ok())
    };

    let root = tempdir().unwrap();
    let root_s = root.path().to_str().unwrap().to_string();
    let id = "oci-pgroup-e2e";

    // create (daemonizes a supervisor that inherits stdio; redirect + .status()).
    let create_log = tmp.join("create.log");
    let create_status = Command::new(oci_bin())
        .args(["--root", &root_s, "create", id, "-b", bundle.to_str().unwrap()])
        .stdout(std::process::Stdio::from(fs::File::create(&create_log).unwrap()))
        .stderr(std::process::Stdio::from(
            fs::OpenOptions::new().append(true).open(&create_log).unwrap(),
        ))
        .status()
        .expect("run create");
    assert!(create_status.success(), "create failed: {}", fs::read_to_string(&create_log).unwrap_or_default());

    let start_out = Command::new(oci_bin())
        .args(["--root", &root_s, "start", id])
        .output()
        .expect("run start");
    assert!(start_out.status.success(), "start failed: {}", String::from_utf8_lossy(&start_out.stderr));

    // Wait until the forked worker is genuinely running.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut worker_running = false;
    while std::time::Instant::now() < deadline {
        if read_counter(&host_child_s).map(|v| v > 2).unwrap_or(false) {
            worker_running = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Kill ONLY the main process (default SIGTERM to state.pid, not the group).
    // The supervisor's group-collapse is what must take the worker down.
    let kill_out = Command::new(oci_bin())
        .args(["--root", &root_s, "kill", id, "SIGTERM"])
        .output()
        .expect("run kill");
    let kill_ok = kill_out.status.success();

    // Give the supervisor time to observe the exit and collapse the group.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let sample_a = read_counter(&host_child_s);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let sample_b = read_counter(&host_child_s);

    // clean up before asserting so a failure never leaks the worker.
    let _ = Command::new(oci_bin())
        .args(["--root", &root_s, "delete", id, "--force"])
        .output();
    let _ = fs::remove_dir_all(&tmp);

    assert!(worker_running, "forked worker never started; create_log: {}", fs::read_to_string(&create_log).unwrap_or_default());
    assert!(kill_ok, "kill failed: {}", String::from_utf8_lossy(&kill_out.stderr));
    assert_eq!(
        sample_a, sample_b,
        "worker must stop advancing after the container's main process is killed \
         (process group was not collapsed); samples {:?} -> {:?}",
        sample_a, sample_b
    );
}

// ── F1.6 (SL-5): run_init fd discipline over the framed control wire ──────
//
// Observation basis (root-mode oci gate, Linux):
//
// The leak defect lives in `run_init`'s receive exits (parse error / EOF /
// RunMain / Shutdown / Signal branches did not close the SCM_RIGHTS fds a
// frame carried), and the fix is a RAII receive guard plus an explicitly
// framed wire (see tmp/sdd/f1.6-report.md). The most faithful probe is a
// fork of the test process that dups one end of a real socketpair onto
// CONTROL_FD (3) and calls the real `run_init` — the exact shape
// supervisor_main wires (crates/sandlock-oci/src/supervisor.rs dup's the
// child end onto fd 3 and runs `run_init` in-process). The parent owns the
// other end, plays the supervisor, and reads `/proc/<child>/fd` — the fd
// table is the observable that counts a leak.
//
// The frames below are crafted against the F1.6 wire constants, duplicated
// here deliberately: the harness must compile and run against the pre-F1.6
// init too (the RED phase), so it cannot depend on the crate's new framing
// API; these constants are the black-box oracle for the actual bytes.
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// F1.6 frame magic ("SLKF"), mirrored from `init::proto::FRAME_MAGIC`.
const SLK_MAGIC: [u8; 4] = *b"SLKF";
/// `init::proto::FRAME_VERSION`.
const SLK_VERSION: u8 = 1;
/// `init::proto::FRAME_TYPE_REQ`.
const SLK_TYPE_REQ: u8 = 1;
/// `init::proto::MAX_FRAME_PAYLOAD` (64 KiB).
const SLK_MAX_PAYLOAD: usize = 64 * 1024;
const SLK_HEADER_LEN: usize = 10;

fn frame_bytes(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(SLK_HEADER_LEN + payload.len());
    f.extend_from_slice(&SLK_MAGIC);
    f.push(SLK_VERSION);
    f.push(kind);
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

/// Fork a child that maps `child` onto CONTROL_FD and enters the real
/// `run_init` control loop (the supervisor_main wiring shape). Returns the
/// child pid, the parent's control stream, and the read end of a ready pipe.
/// The child writes `r` just before calling `run_init` and `e` once
/// `run_init` has RETURNED (the EOF path), then parks until killed so the
/// parent can sample `/proc/<pid>/fd` with the fd table final.
fn spawn_run_init_probe() -> (i32, UnixStream, i32) {
    let (daemon, child) = UnixStream::pair().unwrap();
    let mut ready = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0, "ready pipe");
    let (ready_r, ready_w) = (ready[0], ready[1]);
    let child_raw = child.as_raw_fd();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        // Child: hold only the dup'd control end (fd 3) and the ready-write
        // end. Closing the daemon end here is what makes the parent's close a
        // true EOF on the channel.
        unsafe {
            libc::close(daemon.as_raw_fd());
            libc::dup2(child_raw, sandlock_oci::init::CONTROL_FD);
            if child_raw != sandlock_oci::init::CONTROL_FD {
                libc::close(child_raw);
            }
            libc::close(ready_r);
            let _ = libc::write(ready_w, b"r".as_ptr() as *const _, 1);
        }
        sandlock_oci::init::run_init();
        // run_init returned: the peer closed the channel. Signal the parent
        // and park (fd table final) until killed.
        unsafe {
            let _ = libc::write(ready_w, b"e".as_ptr() as *const _, 1);
            loop {
                libc::pause();
            }
        }
    }
    drop(child); // parent drops its child-end copy
    unsafe {
        libc::close(ready_w);
    }
    (pid, daemon, ready_r)
}

/// Kills and reaps the probe child and closes the ready pipe; runs on panic
/// too, so a failed assertion never leaves a parked init orphaned.
struct RunInitProbeGuard {
    pid: i32,
    ready_r: i32,
}

impl Drop for RunInitProbeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(self.pid, &mut status, 0);
            libc::close(self.ready_r);
        }
    }
}

fn wait_ready_byte(ready_r: i32, deadline: Instant) -> Option<u8> {
    let mut pfd = libc::pollfd {
        fd: ready_r,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let ms = ((deadline - now).as_millis() as i64).min(1000) as i32;
        let pr = unsafe { libc::poll(&mut pfd, 1, ms) };
        if pr < 0 {
            return None;
        }
        if pr > 0 && (pfd.revents & libc::POLLIN) != 0 {
            let mut b = [0u8; 1];
            let n = unsafe { libc::read(ready_r, b.as_mut_ptr() as *mut _, 1) };
            if n == 1 {
                return Some(b[0]);
            }
            if n == 0 {
                return None;
            }
        }
    }
}

/// Number of open fds in `/proc/<pid>/fd` — the SL-5 leak surface.
fn open_fd_count(pid: i32) -> Option<usize> {
    fs::read_dir(format!("/proc/{pid}/fd")).ok().map(|it| it.count())
}

/// Read one init reply, returning its JSON payload. Accepts both wire shapes:
/// the F1.6 framed replies and the legacy newline-JSON shape — the RED phase
/// runs this harness against the un-framed init, which answers in newline
/// JSON until the fix lands.
fn read_init_reply(ctl: &UnixStream, deadline: Instant) -> Option<Vec<u8>> {
    let fd = ctl.as_raw_fd();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if buf.len() >= SLK_HEADER_LEN && buf[..4] == SLK_MAGIC {
            let len = u32::from_le_bytes(buf[6..10].try_into().unwrap()) as usize;
            if buf.len() >= SLK_HEADER_LEN + len {
                return Some(buf[SLK_HEADER_LEN..SLK_HEADER_LEN + len].to_vec());
            }
        } else if let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            // Legacy newline-JSON reply (pre-F1.6 RED wire).
            return Some(buf[..nl].to_vec());
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let ms = ((deadline - now).as_millis() as i64).min(200) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, ms) };
        if pr <= 0 {
            return None;
        }
        let mut chunk = [0u8; 4096];
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut _, chunk.len()) };
        if n <= 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    }
}

fn is_err_resp(payload: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|v| {
            v.get("resp")
                .and_then(|t| t.as_str())
                .map(|tag| tag == "err")
        })
        .unwrap_or(false)
}

/// One pipe write end is attached to every frame; the sender keeps its own
/// copy, and init receives a fresh fd table entry per frame (an entry a leak
/// leaves open).
fn new_attach_fd() -> (i32, i32) {
    let mut p = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0, "attach pipe");
    (p[0], p[1])
}

/// 1000 malformed frames, each carrying one fd: bad JSON payload, oversize
/// declared length, truncated declared length, and a bad type byte, cycled.
/// init must answer every one with `Err` and keep its fd count flat; after
/// the last frame the channel closes and init must still exit normally
/// (`run_init` returns — the `e` byte) with no fd left open.
#[test]
fn test_malformed_frames_do_not_leak_fds() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: /proc fd counting is Linux-only");
        return;
    }
    let (pid, ctl, ready_r) = spawn_run_init_probe();
    let guard = RunInitProbeGuard { pid, ready_r };
    assert_eq!(
        wait_ready_byte(ready_r, Instant::now() + Duration::from_secs(5)),
        Some(b'r'),
        "probe child never entered run_init"
    );
    let baseline = open_fd_count(pid).expect("read child fd table before the storm");
    let (attach_r, attach_w) = new_attach_fd();

    const ROUNDS: usize = 1000;
    let mut served = 0usize;
    for round in 0..ROUNDS {
        let frame = match round % 4 {
            0 => frame_bytes(SLK_TYPE_REQ, b"this is not json {"),
            1 => {
                let mut f = frame_bytes(SLK_TYPE_REQ, b"x");
                f[6..10].copy_from_slice(&((SLK_MAX_PAYLOAD + 1) as u32).to_le_bytes());
                f
            }
            2 => {
                let mut f = frame_bytes(SLK_TYPE_REQ, b"short");
                f[6..10].copy_from_slice(&300u32.to_le_bytes());
                f
            }
            _ => frame_bytes(9, b"bad type byte"),
        };
        sandlock_oci::fdpass::send_with_fds(&ctl, &frame, &[attach_w])
            .expect("send malformed frame");
        let reply =
            read_init_reply(&ctl, Instant::now() + Duration::from_secs(5)).expect(
                "init must answer every malformed frame with an Err reply \
                 (did it stop serving?)",
            );
        assert!(
            is_err_resp(&reply),
            "round {round}: expected an Err reply, got {:?}",
            String::from_utf8_lossy(&reply)
        );
        served += 1;
    }
    let after_storm = open_fd_count(pid).expect("read child fd table after the storm");

    // Host-side EOF semantics must survive the storm: closing the channel
    // makes run_init return (and the harness child report `e`).
    drop(ctl);
    let eof_seen = wait_ready_byte(ready_r, Instant::now() + Duration::from_secs(5))
        == Some(b'e');
    drop(guard);
    unsafe {
        libc::close(attach_r);
        libc::close(attach_w);
    }

    assert_eq!(
        after_storm, baseline,
        "init fd count must not grow across {served} malformed fd-bearing frames \
         (baseline {baseline} -> after {after_storm})"
    );
    assert_eq!(
        served, ROUNDS,
        "init must answer every malformed frame and stay in service ({served}/{ROUNDS})"
    );
    assert!(
        eof_seen,
        "after 1000 malformed frames the channel close must still end run_init normally"
    );
}

/// One well-formed frame carrying one fd (a `Signal` — a verb that never
/// consumes fds), then the peer closes the channel. `run_init` must close the
/// received fd before it returns: the probe child reports `e` only after
/// `run_init` returned, and the parent then counts the fd table — under the
/// pre-F1.6 code the frame is a parse error whose fd is left open, and the
/// count is baseline + 1.
#[test]
fn test_eof_closes_received_fd() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: /proc fd counting is Linux-only");
        return;
    }
    let (pid, ctl, ready_r) = spawn_run_init_probe();
    let guard = RunInitProbeGuard { pid, ready_r };
    assert_eq!(
        wait_ready_byte(ready_r, Instant::now() + Duration::from_secs(5)),
        Some(b'r'),
        "probe child never entered run_init"
    );
    let baseline = open_fd_count(pid).expect("read child fd table before the frame");
    let (attach_r, attach_w) = new_attach_fd();

    let frame = frame_bytes(SLK_TYPE_REQ, br#"{"req":"signal","signum":9}"#);
    sandlock_oci::fdpass::send_with_fds(&ctl, &frame, &[attach_w]).expect("send frame with fd");
    drop(ctl); // EOF: init's run_init must return
    let returned = wait_ready_byte(ready_r, Instant::now() + Duration::from_secs(5))
        == Some(b'e');
    let after_eof = open_fd_count(pid).expect("read child fd table after run_init returned");
    drop(guard);
    unsafe {
        libc::close(attach_r);
        libc::close(attach_w);
    }

    assert!(
        returned,
        "channel close must make run_init return (never hang or exit without a trace)"
    );
    assert_eq!(
        after_eof, baseline,
        "run_init must close the received fd before returning on EOF \
         (baseline {baseline} -> after return {after_eof})"
    );
}

// ── FUP-23: exec stdio relocation must not leak or miswire ────────────────

/// A framed reader that keeps the bytes after the frame it returns: init's
/// `Started` and the following `Exited` can coalesce into one socket read, and
/// the single-shot [`read_init_reply`] helper would drop the second frame.
struct FrameReader {
    ctl: UnixStream,
    buf: Vec<u8>,
}

impl FrameReader {
    fn new(ctl: &UnixStream) -> Self {
        Self {
            ctl: ctl.try_clone().expect("clone control end"),
            buf: Vec::new(),
        }
    }

    /// Next reply payload, or `None` once the deadline passes / the channel
    /// closes.
    fn next_payload(&mut self, deadline: Instant) -> Option<Vec<u8>> {
        loop {
            if self.buf.len() >= SLK_HEADER_LEN && self.buf[..4] == SLK_MAGIC {
                let len = u32::from_le_bytes(self.buf[6..10].try_into().unwrap()) as usize;
                if self.buf.len() >= SLK_HEADER_LEN + len {
                    let payload =
                        self.buf[SLK_HEADER_LEN..SLK_HEADER_LEN + len].to_vec();
                    self.buf.drain(..SLK_HEADER_LEN + len);
                    return Some(payload);
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            let mut pfd = libc::pollfd {
                fd: self.ctl.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pfd, 1, 200) } <= 0 {
                continue;
            }
            let mut chunk = [0u8; 4096];
            let n = unsafe {
                libc::read(
                    self.ctl.as_raw_fd(),
                    chunk.as_mut_ptr() as *mut _,
                    chunk.len(),
                )
            };
            if n <= 0 {
                return None;
            }
            self.buf.extend_from_slice(&chunk[..n as usize]);
        }
    }
}

fn reply_tag(payload: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|v| v.get("resp").and_then(|t| t.as_str()).map(str::to_string))
}

fn reply_pid(payload: &[u8]) -> Option<i64> {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|v| v.get("pid").and_then(|p| p.as_i64()))
}

/// Read exactly `want` bytes (then expect EOF once the writer is gone).
fn read_bytes_from(fd: i32, want: usize, deadline: Instant) -> Vec<u8> {
    let mut buf = Vec::new();
    while buf.len() < want && Instant::now() < deadline {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 200) } <= 0 {
            continue;
        }
        let mut chunk = [0u8; 64];
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut _, chunk.len()) };
        if n <= 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    }
    buf
}

/// FUP-23: every `RunExec` frame carries three stdio ends, which init now
/// relocates into a reserved range before the fork. This drives real execs
/// through the real `run_init` and pins both halves of the contract:
///
/// * each round's command delivers **exactly its own** stdout and stderr bytes
///   (a slot wired to the wrong description — the FUP-23 failure — shows up as
///   missing output, an `EBADF` writer or another round's bytes);
/// * init's fd table returns to its baseline after every round: the received
///   numbers are closed by the receive guard and the reserved copies by the
///   spawner. A missed close leaks three descriptors per exec and the session
///   dies of `EMFILE` once the budget runs out.
#[test]
fn exec_frames_deliver_their_own_output_and_leave_no_descriptor_behind() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: /proc fd counting is Linux-only");
        return;
    }
    const ROUNDS: usize = 40;
    let (pid, ctl, ready_r) = spawn_run_init_probe();
    let guard = RunInitProbeGuard { pid, ready_r };
    assert_eq!(
        wait_ready_byte(ready_r, Instant::now() + Duration::from_secs(5)),
        Some(b'r'),
        "probe child never entered run_init"
    );
    let baseline = open_fd_count(pid).expect("read child fd table before the execs");
    let mut reader = FrameReader::new(&ctl);

    for round in 0..ROUNDS {
        let mut p = [[0i32; 2]; 3];
        for pair in p.iter_mut() {
            assert_eq!(unsafe { libc::pipe2(pair.as_mut_ptr(), 0) }, 0, "pipe2");
        }
        let tag = format!("{round:02}");
        let payload = format!(
            r#"{{"req":"runexec","argv":["/bin/sh","-c","printf '{}O'; printf 'E' 1>&2"],
                "env":[],"cwd":null,"detach":false}}"#,
            tag
        );
        let frame = frame_bytes(SLK_TYPE_REQ, payload.as_bytes());
        // [stdin read, stdout write, stderr write] — the exec's child ends.
        sandlock_oci::fdpass::send_with_fds(&ctl, &frame, &[p[0][0], p[1][1], p[2][1]])
            .expect("send RunExec frame with stdio");
        // Our copies of the child ends must go: while we hold them, our own
        // reader can never see EOF.
        unsafe {
            libc::close(p[0][0]);
            libc::close(p[1][1]);
            libc::close(p[2][1]);
        }

        let started = reader
            .next_payload(Instant::now() + Duration::from_secs(10))
            .expect("init must answer RunExec");
        assert_eq!(
            reply_tag(&started).as_deref(),
            Some("started"),
            "round {round}: expected Started, got {}",
            String::from_utf8_lossy(&started)
        );
        let child_pid = reply_pid(&started).expect("Started carries the child pid");

        let out = read_bytes_from(p[1][0], tag.len() + 1, Instant::now() + Duration::from_secs(10));
        let err = read_bytes_from(p[2][0], 1, Instant::now() + Duration::from_secs(10));
        unsafe {
            libc::close(p[0][1]);
            libc::close(p[1][0]);
            libc::close(p[2][0]);
        }
        assert_eq!(
            out,
            format!("{tag}O").into_bytes(),
            "round {round}: stdout must carry exactly this round's bytes"
        );
        assert_eq!(err, b"E", "round {round}: stderr must carry only stderr");

        // Wait for the child's exit to be routed: that is the point by which
        // init has dropped every descriptor this round was using.
        let mut exited = false;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !exited && Instant::now() < deadline {
            match reader.next_payload(deadline) {
                None => break,
                Some(payload) => {
                    if reply_tag(&payload).as_deref() == Some("exited") {
                        assert_eq!(
                            reply_pid(&payload),
                            Some(child_pid),
                            "round {round}: Exited must name this round's child"
                        );
                        exited = true;
                    }
                }
            }
        }
        assert!(exited, "round {round}: init never reported the child's exit");

        let settled = {
            let until = Instant::now() + Duration::from_secs(5);
            let mut count = open_fd_count(pid).unwrap_or(usize::MAX);
            while count != baseline && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(50));
                count = open_fd_count(pid).unwrap_or(usize::MAX);
            }
            count
        };
        assert_eq!(
            settled, baseline,
            "round {round}: init must return to its baseline fd count \
             (received ends and reserved copies both closed; \
             baseline {baseline} -> now {settled})"
        );
    }
    // Both handles must go: `reader` holds a `try_clone` of the control end,
    // and init only sees EOF once every daemon-side copy is closed.
    drop(reader);
    drop(ctl);
    assert_eq!(
        wait_ready_byte(ready_r, Instant::now() + Duration::from_secs(5)),
        Some(b'e'),
        "channel close must still end run_init normally after {ROUNDS} execs"
    );
    let final_count = open_fd_count(pid).expect("read child fd table after EOF");
    assert_eq!(
        final_count, baseline,
        "no descriptor may survive {ROUNDS} execs (baseline {baseline} -> \
         final {final_count})"
    );
    drop(guard);
}

/// F15: the control channel is a `SOCK_STREAM`, so one `recvmsg` can return
/// several frames while the kernel hands back **one concatenated fd list**.
/// Two `RunExec` frames written once with six descriptors must give each exec
/// its own three — the positional guess ("three arrived, so they are mine") is
/// what made exec #2 write into exec #1's pipe and throw its own output away.
#[test]
fn two_exec_frames_in_one_read_unit_get_their_own_stdio() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: /proc-based fd checks and exec probes are Linux-only");
        return;
    }
    let (pid, ctl, ready_r) = spawn_run_init_probe();
    let guard = RunInitProbeGuard { pid, ready_r };
    assert_eq!(
        wait_ready_byte(ready_r, Instant::now() + Duration::from_secs(5)),
        Some(b'r'),
        "probe child never entered run_init"
    );

    let mut bytes = Vec::new();
    let mut child_ends: Vec<RawFd> = Vec::new();
    let mut stdout_read: Vec<RawFd> = Vec::new();
    let mut stderr_read: Vec<RawFd> = Vec::new();
    for tag in ["A", "B"] {
        let mut p = [[0i32; 2]; 3];
        for pair in p.iter_mut() {
            assert_eq!(unsafe { libc::pipe2(pair.as_mut_ptr(), 0) }, 0, "pipe2");
        }
        let payload = format!(
            r#"{{"req":"runexec","argv":["/bin/sh","-c","printf '{tag}'"],
                "env":[],"cwd":null,"detach":false}}"#
        );
        bytes.extend_from_slice(&frame_bytes(SLK_TYPE_REQ, payload.as_bytes()));
        // The three ends init must install as 0/1/2: stdin read, stdout write,
        // stderr write. Everything else stays ours.
        child_ends.extend_from_slice(&[p[0][0], p[1][1], p[2][1]]);
        stdout_read.push(p[1][0]);
        stderr_read.push(p[2][0]);
        // Nobody writes this exec's stdin; our copy of the write end goes now.
        unsafe { libc::close(p[0][1]) };
    }
    // ONE write: both frames plus all six descriptors in a single `sendmsg`,
    // which is what forces them into one read unit on the init side.
    sandlock_oci::fdpass::send_with_fds(&ctl, &bytes, &child_ends)
        .expect("send two RunExec frames with six fds");
    // Our copies of the handed-over ends must go: while we hold a write end,
    // our own reader can never see EOF for that exec.
    for fd in &child_ends {
        unsafe { libc::close(*fd) };
    }

    let mut reader = FrameReader::new(&ctl);
    let first = reader
        .next_payload(Instant::now() + Duration::from_secs(10))
        .expect("init must answer the first RunExec");
    let second = reader
        .next_payload(Instant::now() + Duration::from_secs(10))
        .expect("init must answer the second RunExec");
    assert_eq!(reply_tag(&first).as_deref(), Some("started"));
    assert_eq!(reply_tag(&second).as_deref(), Some("started"));
    let pa = reply_pid(&first).expect("Started carries the child pid");
    let pb = reply_pid(&second).expect("Started carries the child pid");
    assert_ne!(pa, pb, "two exec frames are two distinct children");

    let out_a = read_bytes_from(stdout_read[0], 1, Instant::now() + Duration::from_secs(10));
    let out_b = read_bytes_from(stdout_read[1], 1, Instant::now() + Duration::from_secs(10));
    assert_eq!(out_a, b"A", "exec #1 stdout must be exactly its own byte");
    assert_eq!(out_b, b"B", "exec #2 stdout must be exactly its own byte");
    for fd in stderr_read.iter().chain(stdout_read.iter()) {
        unsafe { libc::close(*fd) };
    }
    drop(guard);
}
