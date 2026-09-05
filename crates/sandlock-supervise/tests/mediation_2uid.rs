//! F6.1 (SL-1 / P1+P2) root-mode acceptance: B档 cross-uid hard evidence +
//! C档 fail-closed.
//!
//! This target runs only in the **root container phase**
//! (`scripts/test-all.sh --mediation-2uid`): constructing two genuine
//! non-root mediator processes at distinct host uids, and exercising the
//! root in-process C档 shape, both need root (`setpriv` + CAP_SETUID +
//! the privileged userns map).  There is deliberately NO soft skip: run
//! outside the root phase, the target fails loudly.
//!
//! Coverage (fork-plan F6.1 Steps 2–4):
//!
//! * `test_two_supervisors_distinct_uids_isolate_files` — B档.  Two
//!   `sandlock-supervise` processes at uid X and uid Y (via `setpriv`)
//!   both mediate workloads that write a shared 1777+sticky directory.
//!   The file X creates is owned by X (the on-behalf mediator == the
//!   sandbox host uid), X's own chmod takes effect, Y reads it, and Y's
//!   unlink/chmod are refused with EPERM by the kernel.  This is the only
//!   hard cross-uid evidence that SL-1's failure class is gone.
//! * `test_root_inprocess_mediation_is_refused` — C档.  A root in-process
//!   mediator remapping the sandbox to a non-zero host uid with path
//!   mediation active is refused under the default `caller` tier; the
//!   explicit `supervisor` tier builds, warns, and counts in `stats()`.
//! * `test_root_inprocess_mediation_with_caps_kept_would_leak` — the
//!   caps-kept control: under the explicit supervisor tier the mediator
//!   really runs as root (the sandbox's file is root-owned) and the same
//!   unlinkat B档 refuses succeeds through chroot mediation — proving the
//!   refusal of the default tier is load-bearing, not decorative.
//! * `test_cli_mediation_run_as_is_wired` — the CLI flag reaches the
//!   runtime builder: as root, the default tier refuses the C档 shape and
//!   `--mediation-run-as supervisor` accepts it with the warning.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sandlock_core::sandbox::MediationRunAs;
use sandlock_core::{Sandbox, SandlockError};

/// Route-B slot uids for the B档 pair: distinct non-root, non-reserved ids
/// (not 0, not the 1–999 system range, not 65534 = nobody/overflowuid).
const UID_X: u32 = 65531;
const UID_Y: u32 = 65532;

/// C档 sandbox host uids (root in-process remap targets).
const HOST_UID_A: u32 = 10000;
const HOST_UID_B: u32 = 10001;

fn supervise_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-supervise")
}

/// Container-local scratch root for tests whose assertions depend on REAL
/// kernel DAC file ownership.  The repo's bind mount (OrbStack file
/// sharing) collapses non-root container uids to 0 on the host side, so
/// ownership-sensitive evidence must live on the container's own fs
/// (`/tmp`), never on the mounted repo.
fn dac_tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandlock-med-2uid-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create container-local scratch");
    chmod_dir(&dir, 0o777);
    dir
}

fn cli_bin() -> PathBuf {
    // The root phase runs after the non-root cli suite, whose debug binary
    // lives in the shared target dir; the runner additionally builds it.
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/sandlock");
    assert!(
        bin.exists(),
        "sandlock CLI binary not found at {} — the root phase must run after \
         `cargo build -p sandlock-cli` (scripts/test-all.sh does this)",
        bin.display()
    );
    bin
}

fn rootfs_helper() -> PathBuf {
    let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/rootfs-helper");
    assert!(
        helper.exists(),
        "tests/rootfs-helper missing — build sandlock-core first (its build.rs \
         compiles the static chroot fixture)"
    );
    std::fs::canonicalize(&helper).expect("canonicalize rootfs-helper")
}

fn root_phase_env_check() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "the mediation_2uid target must run as root (scripts/test-all.sh \
         --mediation-2uid in the privileged container); a non-root run fails \
         loudly — there is no soft skip for the two-uid / C档 acceptance"
    );
    assert!(
        Command::new("setpriv")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
        "setpriv (util-linux) must be present in the root container phase"
    );
}

fn base_read_paths() -> Vec<String> {
    let mut paths = vec![
        "/usr".to_string(),
        "/lib".to_string(),
        "/bin".to_string(),
        "/etc".to_string(),
        "/proc".to_string(),
        "/dev".to_string(),
    ];
    if Path::new("/lib64").exists() {
        paths.push("/lib64".to_string());
    }
    paths
}

fn chmod_dir(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod dir");
}

fn write_shared(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write shared test file");
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
}

// ----------------------------------------------------------------
// Control-frame helpers (fd transport worker held by this test process)
// ----------------------------------------------------------------

fn read_control_response(worker: &mut std::os::unix::net::UnixStream) -> serde_json::Value {
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

fn roundtrip_frame(
    worker: &mut std::os::unix::net::UnixStream,
    body: &serde_json::Value,
) -> serde_json::Value {
    let bytes = serde_json::to_vec(body).expect("serialize frame");
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(&bytes);
    worker.write_all(&frame).expect("write control frame");
    read_control_response(worker)
}

/// Spawn `sandlock-supervise` at `uid` (via setpriv) with the fd-handoff
/// control channel and a launch-first program; returns the child and the
/// worker end.  The supervisor end of the socketpair survives both execs
/// (CLOEXEC cleared pre-exec).
fn spawn_supervise_at(
    uid: u32,
    policy: &Path,
    program: &Path,
    ctl_root: &Path,
) -> (Child, std::os::unix::net::UnixStream) {
    use std::os::unix::process::CommandExt;

    let (worker, server) = std::os::unix::net::UnixStream::pair().expect("control socketpair");
    let control_fd = server.as_raw_fd();
    let worker_fd = worker.as_raw_fd();
    let mut cmd = Command::new("setpriv");
    cmd.args([
        "--reuid",
        &uid.to_string(),
        "--regid",
        &uid.to_string(),
        "--clear-groups",
        "--",
        supervise_bin(),
        "--policy",
        policy.to_str().expect("policy path utf8"),
        "--uid",
        &uid.to_string(),
        "--control-fd",
        &control_fd.to_string(),
        "--program",
        program.to_str().expect("program path utf8"),
        "--serve",
    ])
    .env("SANDBOX_CTL_ROOT", ctl_root)
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(move || {
            for fd in [control_fd, worker_fd] {
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
    let child = cmd.spawn().expect("spawn setpriv supervise");
    drop(server);
    (child, worker)
}

/// Drive one supervise generation to a clean end: poll `stats` until the
/// instance reports `Exited` (the launch-first program's main exited), send
/// `shutdown`, and wait for the process.  Returns supervise's stderr.
fn run_generation_to_end(
    child: Child,
    mut worker: std::os::unix::net::UnixStream,
    what: &str,
) -> String {
    worker
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let deadline = Instant::now() + Duration::from_secs(60);
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
    assert!(
        exited,
        "{what}: instance never reached Exited after main exit"
    );

    let resp = roundtrip_frame(
        &mut worker,
        &serde_json::json!({ "v": 1, "verb": "shutdown", "args": {} }),
    );
    assert_eq!(
        resp["ok"],
        serde_json::Value::Bool(true),
        "shutdown: {resp:?}"
    );
    drop(worker);

    let out = child.wait_with_output().expect("wait supervise");
    assert!(
        out.status.success(),
        "{what}: supervise must end cleanly after shutdown; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ----------------------------------------------------------------
// B档: two supervisors at distinct uids, shared 1777+sticky directory
// ----------------------------------------------------------------

const X_WORKLOAD: &str = r#"
import json, os, sys
shared, ev = sys.argv[1], sys.argv[2]
path = os.path.join(shared, "x.txt")
# Mediated open (path mediation is active): the supervisor process
# (uid X) performs the create, so the file must end up owned by X.
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, b"XDATA\n")
os.close(fd)
# Self-chmod: only works when the file is owned by the sandbox host uid.
os.chmod(path, 0o644)
with open(os.path.join(ev, "x-done"), "w") as f:
    f.write("created\n")
"#;

const Y_WORKLOAD: &str = r#"
import json, os, sys
shared, ev = sys.argv[1], sys.argv[2]
path = os.path.join(shared, "x.txt")
out = {}
try:
    with open(path) as f:
        out["read"] = f.read()
except OSError as e:
    out["read_errno"] = e.errno
try:
    os.unlink(path)
    out["rm_errno"] = 0
except OSError as e:
    out["rm_errno"] = e.errno
try:
    os.chmod(path, 0o600)
    out["chmod_errno"] = 0
except OSError as e:
    out["chmod_errno"] = e.errno
out["exists"] = os.path.exists(path)
with open(os.path.join(ev, "y-report.json"), "w") as f:
    json.dump(out, f)
"#;

#[test]
fn test_two_supervisors_distinct_uids_isolate_files() {
    root_phase_env_check();
    let base = dac_tmp_dir("b");

    let ctl_root = base.join("ctl");
    std::fs::create_dir_all(&ctl_root).expect("create ctl root");
    chmod_dir(&ctl_root, 0o777);

    let shared = base.join("shared");
    std::fs::create_dir_all(&shared).expect("create shared dir");
    chmod_dir(&shared, 0o1777); // world-writable + sticky

    let evidence = base.join("evidence");
    std::fs::create_dir_all(&evidence).expect("create evidence dir");
    chmod_dir(&evidence, 0o1777);

    // Both supervisors allow writes to the SAME shared directory; path
    // mediation is active via a deny carve-out (Landlock cannot express a
    // denied leaf below a granted tree, so opens go on-behalf).
    let deny_leaf = shared.join("secret.txt");
    let policy_body = serde_json::json!({
        "fs_readable": base_read_paths(),
        "fs_writable": [shared.to_string_lossy(), evidence.to_string_lossy()],
        "fs_denied": [deny_leaf.to_string_lossy()],
    })
    .to_string();
    let policy_path = base.join("policy.json");
    write_shared(&policy_path, &policy_body);

    // ---- uid X creates and chmods its own file ----
    let prog_x = base.join("prog-x.json");
    write_shared(
        &prog_x,
        &serde_json::json!({
            "argv": [
                "python3", "-B", "-c", X_WORKLOAD,
                shared.to_string_lossy(), evidence.to_string_lossy(),
            ],
        })
        .to_string(),
    );
    let (sup_x, worker_x) = spawn_supervise_at(UID_X, &policy_path, &prog_x, &ctl_root);
    run_generation_to_end(sup_x, worker_x, "uid-X supervisor");

    let x_file = shared.join("x.txt");
    let meta = std::fs::metadata(&x_file).expect("host-side stat of X's mediated file");
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        meta.uid(),
        UID_X,
        "B档: the on-behalf create must run as supervisor uid X (the sandbox \
         host uid); got uid {}",
        meta.uid()
    );
    assert_eq!(
        meta.mode() & 0o7777,
        0o644,
        "B档: X's own chmod must take effect on its file"
    );
    assert_eq!(
        std::fs::read_to_string(evidence.join("x-done")).expect("read x-done"),
        "created\n"
    );

    // ---- uid Y reads X's file, then tries to delete / chmod it ----
    let prog_y = base.join("prog-y.json");
    write_shared(
        &prog_y,
        &serde_json::json!({
            "argv": [
                "python3", "-B", "-c", Y_WORKLOAD,
                shared.to_string_lossy(), evidence.to_string_lossy(),
            ],
        })
        .to_string(),
    );
    let (sup_y, worker_y) = spawn_supervise_at(UID_Y, &policy_path, &prog_y, &ctl_root);
    run_generation_to_end(sup_y, worker_y, "uid-Y supervisor");

    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(evidence.join("y-report.json")).expect("read Y report"),
    )
    .expect("Y report is JSON");
    assert_eq!(
        report["read"],
        serde_json::Value::String("XDATA\n".into()),
        "Y must be able to read X's 0644 file"
    );
    assert_eq!(
        report["rm_errno"],
        serde_json::Value::from(1),
        "Y's unlink of X's file in the sticky dir must be EPERM"
    );
    assert_eq!(
        report["chmod_errno"],
        serde_json::Value::from(1),
        "Y's chmod of X's file must be EPERM"
    );
    assert_eq!(report["exists"], serde_json::Value::Bool(true));

    let meta_after = std::fs::metadata(&x_file).expect("X's file survives Y");
    assert_eq!(
        meta_after.uid(),
        UID_X,
        "the file must still be owned by X after Y's refused operations"
    );
    assert_eq!(
        meta_after.mode() & 0o7777,
        0o644,
        "Y's refused chmod must not have changed X's file"
    );

    let _ = std::fs::remove_dir_all(&base);
}

// ----------------------------------------------------------------
// C档: root in-process mediation is refused under `caller`
// ----------------------------------------------------------------

fn refusal_msg(host_uid: u32) -> String {
    format!(
        "mediation_run_as=caller refused: in-process path mediation would run as euid 0 \
         while the sandbox's host uid is {host_uid}; on-behalf files would be owned by the \
         mediator, not the sandbox (SL-1). Run sandlock-supervise as uid {host_uid} (route B), \
         or pass mediation_run_as=supervisor to explicitly accept the downgrade"
    )
}

fn assert_run_refused(err: SandlockError, expected: &str) {
    match err {
        SandlockError::Runtime(sandlock_core::error::SandboxRuntimeError::Child(msg)) => {
            assert_eq!(msg, expected)
        }
        other => panic!("expected the mediation_run_as refusal, got: {other:?}"),
    }
}

fn c_tier_base(dir: &Path) -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(dir)
        .user(HOST_UID_A, HOST_UID_A)
}

#[tokio::test]
async fn test_root_inprocess_mediation_is_refused() {
    root_phase_env_check();
    let dir = dac_tmp_dir("c-refused");

    // Witness session (no path mediation) so the stats delta is exact
    // regardless of test order within this process.
    let mut witness = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(&dir)
        .user(HOST_UID_A, HOST_UID_A)
        .build()
        .expect("witness builds");
    let wr = witness.run(&["true"]).await.expect("witness runs");
    assert!(wr.success());
    let before = witness
        .stats()
        .await
        .expect("witness stats")
        .mediation_downgrades;

    // Default `caller` tier: the C档 shape (root + RunAs(10000) + mediation)
    // must be refused with the exact message before any fork.
    let mut sb = c_tier_base(&dir)
        .fs_deny(dir.join("secret.txt"))
        .build()
        .expect("caller-tier policy builds");
    let err = sb.run(&["true"]).await.expect_err("C档 must refuse");
    assert_run_refused(err, &refusal_msg(HOST_UID_A));

    // Explicit `supervisor` tier: allowed, warned, and counted in stats().
    let mut downgraded = c_tier_base(&dir)
        .fs_deny(dir.join("secret.txt"))
        .mediation_run_as(MediationRunAs::Supervisor)
        .build()
        .expect("supervisor-tier policy builds");
    let dr = downgraded
        .run(&["true"])
        .await
        .expect("supervisor tier runs");
    assert!(
        dr.success(),
        "the explicit supervisor tier must build the box"
    );
    let after = downgraded
        .stats()
        .await
        .expect("downgraded stats")
        .mediation_downgrades;
    assert_eq!(
        after,
        before + 1,
        "the supervisor-tier launch must be counted in stats() exactly once"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ----------------------------------------------------------------
// C档 control: caps-kept root mediator proves the downgrade is real
// ----------------------------------------------------------------

/// Minimal chroot rootfs with the static rootfs-helper and a sticky /tmp.
fn build_rootfs(base: &Path) -> PathBuf {
    let rootfs = base.join("rootfs");
    for dir in ["usr/bin", "usr/sbin", "etc", "proc", "dev", "tmp"] {
        std::fs::create_dir_all(rootfs.join(dir)).expect("create rootfs dir");
    }
    chmod_dir(&rootfs.join("tmp"), 0o1777);

    let helper = rootfs_helper();
    std::fs::hard_link(&helper, rootfs.join("usr/bin/rootfs-helper"))
        .or_else(|_| std::fs::copy(&helper, rootfs.join("usr/bin/rootfs-helper")).map(|_| ()))
        .expect("install rootfs-helper");
    for cmd in ["sh", "echo", "cat", "ls", "rm", "chmod", "true"] {
        let link = rootfs.join(format!("usr/bin/{cmd}"));
        std::os::unix::fs::symlink("rootfs-helper", &link).expect("create busybox symlink");
    }
    let _ = std::os::unix::fs::symlink("usr/bin", rootfs.join("bin"));
    let _ = std::os::unix::fs::symlink("usr/sbin", rootfs.join("sbin"));
    rootfs
}

#[tokio::test]
async fn test_root_inprocess_mediation_with_caps_kept_would_leak() {
    root_phase_env_check();
    let base = dac_tmp_dir("c-leak");
    let rootfs = build_rootfs(&base);

    // Sandbox A (host uid 10000) creates a file inside the chroot's sticky
    // /tmp through the root in-process mediator (explicit supervisor tier).
    // Chroot mediation performs the open supervisor-side: the file is owned
    // by uid 0, NOT by the sandbox's host uid — the downgrade is real.
    let chroot_policy = |host_uid: u32| {
        Sandbox::builder()
            .chroot(&rootfs)
            .fs_read("/usr")
            .fs_read("/bin")
            .fs_read("/etc")
            .fs_read("/proc")
            .fs_read("/dev")
            .fs_write("/tmp")
            .user(host_uid, host_uid)
            .mediation_run_as(MediationRunAs::Supervisor)
            .build()
            .expect("chroot supervisor-tier policy builds")
    };

    let mut a = chroot_policy(HOST_UID_A);
    let ra = a
        .run(&["rootfs-helper", "sh", "-c", "echo XDATA > /tmp/x.txt"])
        .await
        .expect("sandbox A runs");
    assert!(ra.success(), "A create failed: {:?}", ra.stderr_str());

    let host_file = rootfs.join("tmp/x.txt");
    let meta = std::fs::metadata(&host_file).expect("host-side stat of root-mediated file");
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        meta.uid(),
        0,
        "C档 control: the explicit supervisor tier must create the file as the \
         root mediator (owner 0), not as the sandbox's host uid {HOST_UID_A} — \
         proving the tier is a genuine downgrade"
    );

    // Sandbox B (host uid 10001) runs the SAME unlinkat the B档 test refuses
    // (Y deleting X's file in a sticky dir).  Through the caps-kept root
    // mediator it succeeds — the leak the caller-default refusal exists to
    // prevent.
    let mut b = chroot_policy(HOST_UID_B);
    let rb = b
        .run(&["rootfs-helper", "sh", "-c", "rm /tmp/x.txt && echo RM_OK"])
        .await
        .expect("sandbox B runs");
    assert!(rb.success(), "B run failed: {:?}", rb.stderr_str());
    assert_eq!(
        rb.stdout_str(),
        Some("RM_OK"),
        "caps-kept root mediation must delete the other-host-uid sandbox's file \
         (sticky bit bypassed by the mediator's root identity) — this is the leak \
         the default caller tier refuses"
    );
    assert!(
        !host_file.exists(),
        "the root-mediated unlink must have removed the file"
    );

    let _ = std::fs::remove_dir_all(&base);
}

// ----------------------------------------------------------------
// CLI wiring (root observable tier difference)
// ----------------------------------------------------------------

#[test]
fn test_cli_mediation_run_as_is_wired() {
    root_phase_env_check();
    let bin = cli_bin();
    let dir = dac_tmp_dir("cli-wire");
    let deny = dir.join("secret.txt");

    let mut base_args: Vec<String> = vec![
        "run".into(),
        "-r".into(),
        "/usr".into(),
        "-r".into(),
        "/lib".into(),
        "-r".into(),
        "/bin".into(),
        "-r".into(),
        "/etc".into(),
        "-r".into(),
        "/proc".into(),
        "-r".into(),
        "/dev".into(),
        "-w".into(),
        dir.to_string_lossy().into_owned(),
        "--fs-deny".into(),
        deny.to_string_lossy().into_owned(),
        "--user".into(),
        format!("{HOST_UID_A}:{HOST_UID_A}"),
    ];
    if Path::new("/lib64").exists() {
        base_args.push("-r".into());
        base_args.push("/lib64".into());
    }

    // Default tier (caller): the C档 shape must refuse with the exact message.
    let mut caller_args = base_args.clone();
    caller_args.push("--".into());
    caller_args.push("true".into());
    let caller = Command::new(&bin)
        .args(&caller_args)
        .output()
        .expect("run sandlock caller tier");
    assert!(
        !caller.status.success(),
        "the CLI default tier must refuse the root-remap shape"
    );
    let caller_err = String::from_utf8_lossy(&caller.stderr);
    let caller_line = caller_err.lines().next().unwrap_or_default();
    assert_eq!(
        caller_line.strip_prefix("Error: process error: child process error: "),
        Some(refusal_msg(HOST_UID_A).as_str()),
        "the CLI must surface the exact mediation_run_as refusal"
    );

    // Explicit supervisor tier: wired flag → box builds and runs, with the
    // downgrade warning on stderr.
    let mut sup_args = base_args.clone();
    sup_args.push("--mediation-run-as".into());
    sup_args.push("supervisor".into());
    sup_args.push("--".into());
    sup_args.push("true".into());
    let sup = Command::new(&bin)
        .args(&sup_args)
        .output()
        .expect("run sandlock supervisor tier");
    assert!(
        sup.status.success(),
        "--mediation-run-as supervisor must be wired to the runtime builder; \
         stderr: {}",
        String::from_utf8_lossy(&sup.stderr)
    );
    let sup_err = String::from_utf8_lossy(&sup.stderr);
    assert_eq!(
        sup_err.lines().next().unwrap_or_default(),
        format!(
            "sandlock: warning: mediation_run_as=supervisor: in-process path mediation runs \
             as euid 0 while the sandbox's host uid is {HOST_UID_A}; on-behalf files are \
             owned by the mediator, not the sandbox (SL-1 downgrade accepted explicitly)"
        ),
        "the explicit tier must warn on stderr (the downgrade is never silent)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
