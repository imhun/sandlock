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
//! * C档 fail-closed — a privileged in-process mediator (euid 0, or a
//!   non-root euid holding effective CAP_SETUID/CAP_SETGID) that would remap
//!   the sandbox to a *different* non-zero host uid with path mediation
//!   active is **refused before fork**, and the refusal's only remedy is
//!   route B (`Run sandlock-supervise as uid <host uid>`).  There is no
//!   downgrade tier left to accept it, so SL-1's owner/chmod/sticky failure
//!   class has no way back in through the in-process shape
//!   (`test_root_inprocess_mediation_is_refused`,
//!   `test_root_inprocess_mediation_refused_with_policy_fn_deny_shape`,
//!   `test_root_chroot_privileged_remap_is_refused_before_fork`,
//!   `test_nonroot_file_cap_launcher_is_refused_like_c_tier`,
//!   `test_cli_refuses_the_root_remap_shape`).
//! * The reverse regression — the refusal is *conditional* on
//!   `mediation_active`, never an unconditional same-identity demand, so the
//!   shapes that are legal today must keep working:
//!   `test_root_pure_per_uid_run_as_is_still_accepted` (privileged remap
//!   with **no** mediation: no chroot/COW/deny/policy_fn) and
//!   `test_root_chroot_uid0_instance_exec_only_restrictive_cache` (no remap
//!   at all).  The non-root same-uid chroot half of that pair lives in
//!   `crates/sandlock-core/tests/integration/test_instance_chroot.rs`.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sandlock_core::instance::{ExecStdio, SandboxInstance};
use sandlock_core::result::ExitStatus;
use sandlock_core::policy_fn::Verdict;
use sandlock_core::{Sandbox, SandlockError};

/// Route-B slot uids for the B档 pair: distinct non-root, non-reserved ids
/// (not 0, not the 1–999 system range, not 65534 = nobody/overflowuid).
const UID_X: u32 = 65531;
const UID_Y: u32 = 65532;
/// The route-B worker uid (the python client runs as this; slots allowlist it).
const UID_WORKER: u32 = 65534;

/// C档 sandbox host uid (the root in-process remap target).
const HOST_UID_A: u32 = 10000;

/// Non-root euid for the F14 file-cap launcher fixture (route-B ③ shape).
const CAPS_UID: u32 = 65533;

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
// F16 (Python client) B档: two distinct-uid registered slots driven by
// sandlock.supervise.SuperviseChannel over exec + wait_child + shutdown.
// The exec'd children run inside each slot's instance; the evidence and the
// host-side ownership assertions are the same B档 facts as above, now
// reached through the Python worker face envd (E2B) will use.
// ----------------------------------------------------------------

/// The Python client: exec `code_file` (python -c) in the slot, wait for its
/// exit, require exit code 0, then shut the generation down.
const F16_PY_CLIENT: &str = r#"
import os, sys
from sandlock.supervise import SuperviseChannel

path, token, code_file, shared, ev = sys.argv[1:6]
with open(code_file) as f:
    code = f.read()

with SuperviseChannel(path, token) as ch:
    dn = os.open("/dev/null", os.O_RDWR)
    try:
        fds = [dn, dn, dn]
        started = ch.request(
            "exec",
            {"argv": ["python3", "-B", "-c", code, shared, ev]},
            fds=fds,
        )
    finally:
        os.close(dn)
    status = ch.request("wait_child", {"child_id": started["child_id"]})
    if status.get("code") != 0:
        raise SystemExit("exec child failed: %r" % (status,))
    ch.request("shutdown")
"#;

/// Spawn a registered-path supervise slot at `uid` (via setpriv) with a
/// launch-first parking program so the instance exists for exec verbs.
fn spawn_supervise_registered(
    uid: u32,
    policy: &Path,
    program: &Path,
    ctl_root: &Path,
    name: &str,
    token: &str,
    peer_uids: &[u32],
) -> Child {
    let mut args: Vec<String> = vec![
        "--reuid".to_string(),
        uid.to_string(),
        "--regid".to_string(),
        uid.to_string(),
        "--clear-groups".to_string(),
        "--".to_string(),
        supervise_bin().to_string(),
        "--policy".to_string(),
        policy.to_string_lossy().into_owned(),
        "--uid".to_string(),
        uid.to_string(),
        "--serve-path".to_string(),
        name.to_string(),
        "--token".to_string(),
        token.to_string(),
    ];
    for u in peer_uids {
        args.push("--peer-uid".to_string());
        args.push(u.to_string());
    }
    args.push("--program".to_string());
    args.push(program.to_string_lossy().into_owned());
    Command::new("setpriv")
        .args(&args)
        .env("SANDBOX_CTL_ROOT", ctl_root)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn setpriv registered supervise")
}

/// Run the Python SuperviseChannel client as UID_WORKER (the route-B worker
/// uid), returning its exit status.  The fork's python package and the debug
/// cdylib live under the /src mount; the ffi c_smoke suite has already built
/// the cdylib in the non-root phase.
fn run_f16_client(
    script: &Path,
    args: &[&str],
) -> std::process::ExitStatus {
    let mut cmd = Command::new("setpriv");
    cmd.args([
        "--reuid",
        &UID_WORKER.to_string(),
        "--regid",
        &UID_WORKER.to_string(),
        "--clear-groups",
        "--",
        "python3",
        "-B",
        script.to_str().expect("client script utf8"),
    ])
    .args(args)
    .env(
        "PYTHONPATH",
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../python/src")
            .to_string_lossy()
            .into_owned(),
    )
    .env(
        "LD_LIBRARY_PATH",
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target-linux/debug")
            .to_string_lossy()
            .into_owned(),
    )
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn python client");
    let status = child.wait().expect("wait python client");
    if !status.success() {
        let mut err = String::new();
        if let Some(ref mut pipe) = child.stderr {
            let _ = std::io::Read::read_to_string(pipe, &mut err);
        }
        panic!("python client failed (status {status}); stderr: {err}");
    }
    status
}

fn wait_for_registered_socket(
    supervise: &mut Child,
    sock_path: &Path,
    what: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if sock_path.exists() {
            return;
        }
        if let Some(status) = supervise.try_wait().expect("try_wait supervise") {
            let mut err = String::new();
            if let Some(ref mut pipe) = supervise.stderr {
                let _ = std::io::Read::read_to_string(pipe, &mut err);
            }
            panic!(
                "{what}: supervise exited ({status}) before binding {sock_path:?}; stderr: {err}"
            );
        }
        assert!(
            Instant::now() < deadline,
            "{what}: timed out waiting for registered socket {sock_path:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Drive one F16 slot: write the parking program + workload code, spawn the
/// registered supervise at `uid`, run the Python client, and require both
/// processes to end cleanly.
fn run_f16_slot(
    uid: u32,
    base: &Path,
    shared: &Path,
    evidence: &Path,
    name: &str,
    token: &str,
    workload: &str,
) {
    // Each slot gets its own control root: the shared registry root is
    // per-uid by design (channel_registry_root defaults to
    // /tmp/sandlock-ctl-<uid>-registry), and two slots at different uids
    // must never chmod each other's registry root (sticky ownership).
    let ctl_root = base.join(format!("ctl-{name}"));
    std::fs::create_dir_all(&ctl_root).expect("create per-slot ctl root");
    chmod_dir(&ctl_root, 0o777);
    let policy_body = serde_json::json!({
        "fs_readable": base_read_paths(),
        "fs_writable": [shared.to_string_lossy(), evidence.to_string_lossy()],
        "fs_denied": [shared.join("secret.txt").to_string_lossy()],
    })
    .to_string();
    let policy_path = base.join(format!("policy-{name}.json"));
    write_shared(&policy_path, &policy_body);

    let program_path = base.join(format!("prog-{name}.json"));
    write_shared(
        &program_path,
        &serde_json::json!({
            "argv": ["python3", "-B", "-c", "import time; time.sleep(300)"],
        })
        .to_string(),
    );
    let code_path = base.join(format!("code-{name}.py"));
    write_shared(&code_path, workload);
    let client_path = base.join("f16-client.py");
    write_shared(&client_path, F16_PY_CLIENT);

    let mut supervise = spawn_supervise_registered(
        uid,
        &policy_path,
        &program_path,
        &ctl_root,
        name,
        token,
        &[UID_WORKER],
    );
    let sock_path = PathBuf::from(format!(
        "{}-registry/{}.d/control.sock",
        ctl_root.to_string_lossy().trim_end_matches('/'),
        sandlock_core::control::fnv1a_hex(name),
    ));
    wait_for_registered_socket(&mut supervise, &sock_path, name);

    run_f16_client(
        &client_path,
        &[
            sock_path.to_str().unwrap(),
            token,
            code_path.to_str().unwrap(),
            shared.to_str().unwrap(),
            evidence.to_str().unwrap(),
        ],
    );

    let status = supervise.wait().expect("wait supervise");
    assert!(
        status.success(),
        "{name}: supervise must exit 0 after the Python shutdown verb"
    );
}

#[test]
fn test_python_client_execs_distinct_uids_on_shared_sticky_dir() {
    root_phase_env_check();
    let base = dac_tmp_dir("b-py");

    let shared = base.join("shared");
    std::fs::create_dir_all(&shared).expect("create shared dir");
    chmod_dir(&shared, 0o1777);
    let evidence = base.join("evidence");
    std::fs::create_dir_all(&evidence).expect("create evidence dir");
    chmod_dir(&evidence, 0o1777);

    let tag = format!("f16-{}", std::process::id());
    let token_x = format!("{tag}-x");
    run_f16_slot(
        UID_X,
        &base,
        &shared,
        &evidence,
        &format!("{tag}-x"),
        &token_x,
        X_WORKLOAD,
    );

    let x_file = shared.join("x.txt");
    let meta = std::fs::metadata(&x_file).expect("host-side stat of X's mediated file");
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        meta.uid(),
        UID_X,
        "F16 python client: the exec'd create must run as supervisor uid X \
         (the sandbox host uid); got uid {}",
        meta.uid()
    );
    assert_eq!(
        meta.mode() & 0o7777,
        0o644,
        "F16 python client: X's own chmod must take effect on its file"
    );
    assert_eq!(
        std::fs::read_to_string(evidence.join("x-done")).expect("read x-done"),
        "created\n"
    );

    let token_y = format!("{tag}-y");
    run_f16_slot(
        UID_Y,
        &base,
        &shared,
        &evidence,
        &format!("{tag}-y"),
        &token_y,
        Y_WORKLOAD,
    );

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
// C档: privileged in-process mediation is refused (no downgrade tier)
// ----------------------------------------------------------------

fn refusal_msg(host_uid: u32) -> String {
    format!(
        "in-process path mediation refused: mediation would run as euid 0 while the sandbox's \
         host uid is {host_uid}; on-behalf files would be owned by the mediator, not the \
         sandbox (SL-1). Run sandlock-supervise as uid {host_uid} (route B)"
    )
}

/// F14: the non-root file-cap launcher shape is refused with a message that
/// names the capability (so deployment can tell "euid 0" from
/// "non-root effective CAP_SETUID/CAP_SETGID").
fn caps_refusal_msg(euid: u32, host_uid: u32) -> String {
    format!(
        "in-process path mediation refused: mediation would run as euid {euid} with effective \
         CAP_SETUID/CAP_SETGID while the sandbox's host uid is {host_uid}; on-behalf files \
         would be owned by the mediator, not the sandbox (SL-1). Run sandlock-supervise as \
         uid {host_uid} (route B)"
    )
}

fn assert_run_refused(err: SandlockError, expected: &str) {
    match err {
        SandlockError::Runtime(sandlock_core::error::SandboxRuntimeError::Child(msg)) => {
            assert_eq!(msg, expected)
        }
        other => panic!("expected the mediated-path identity refusal, got: {other:?}"),
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

    // The C档 shape (root + RunAs(10000) + path mediation) must be refused
    // with the exact message before any fork.  There is no tier left that
    // would accept it: the refusal names route B as the only remedy.
    let mut sb = c_tier_base(&dir)
        .fs_deny(dir.join("secret.txt"))
        .build()
        .expect("C档 policy builds");
    let err = sb.run(&["true"]).await.expect_err("C档 must refuse");
    assert_run_refused(err, &refusal_msg(HOST_UID_A));

    let _ = std::fs::remove_dir_all(&dir);
}

/// F14 (route-B ③ 前置): a non-root process whose executable carries
/// `cap_setuid,cap_setgid+eip` (the file-cap launcher shape) holds effective
/// CAP_SETUID/CAP_SETGID at a non-zero euid — the same privileged cross-uid
/// remap capability the C档 gate refuses for euid 0. The launcher shape must
/// fail closed at the gate with the capability-aware message
/// BEFORE any fork, instead of falling through to the late "unprivileged
/// supervisor cannot map" refusal (which assumes a caps-free caller and
/// would become an SL-1-class leak the moment the remap path honored caps).
#[test]
fn test_nonroot_file_cap_launcher_is_refused_like_c_tier() {
    root_phase_env_check();
    let dir = dac_tmp_dir("caps-c-tier");
    let deny = dir.join("secret.txt");
    std::fs::write(&deny, "secret\n").expect("write deny target");

    // Stamp the route-B ③ file-cap launcher capability set on a scratch copy
    // of the CLI (eip => effective CAP_SETUID/CAP_SETGID after exec).
    let capped = dir.join("sandlock-capable");
    std::fs::copy(cli_bin(), &capped).expect("copy CLI to scratch for file caps");
    let cap = Command::new("setcap")
        .args(["cap_setuid,cap_setgid+eip", capped.to_str().unwrap()])
        .output()
        .expect("run setcap");
    assert!(
        cap.status.success(),
        "setcap failed: {}",
        String::from_utf8_lossy(&cap.stderr)
    );

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
    base_args.push("--".into());
    base_args.push("true".into());

    let r = Command::new("setpriv")
        .arg("--reuid")
        .arg(CAPS_UID.to_string())
        .arg("--regid")
        .arg(CAPS_UID.to_string())
        .arg("--clear-groups")
        .arg(&capped)
        .args(&base_args)
        .output()
        .expect("run the file-cap launcher at a non-root euid");

    let err = String::from_utf8_lossy(&r.stderr);
    assert!(
        !r.status.success(),
        "the file-cap launcher shape must be refused under the default caller tier"
    );
    let line = err.lines().next().unwrap_or_default();
    assert_eq!(
        line.strip_prefix("Error: process error: child process error: "),
        Some(caps_refusal_msg(CAPS_UID, HOST_UID_A).as_str()),
        "the CLI must surface the capability-aware C档 refusal, got: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// I1 review fix (live shape): the on-behalf open gate is
/// `has_denied_paths()` on the shared DeniedSet, which also receives live
/// `policy_fn`-issued `deny_path()` calls.  A root in-process mediator with
/// `RunAs(non-zero)` and a path-denying policy_fn (no static
/// fs_denied/chroot/COW) must therefore be refused too: the refusal is about
/// the *capability*, not about whether a deny has fired yet.
#[tokio::test]
async fn test_root_inprocess_mediation_refused_with_policy_fn_deny_shape() {
    root_phase_env_check();
    let dir = dac_tmp_dir("c-policy-fn");
    let deny_target = dir.join("secret.txt").to_string_lossy().into_owned();

    // Refused even with no static fs_denied/chroot/COW — the deny_path
    // capability is a mediation trigger.
    let target = deny_target.clone();
    let mut sb = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(&dir)
        .user(HOST_UID_A, HOST_UID_A)
        .policy_fn(move |_ev, ctx| {
            // A live path-denying policy_fn: subsequent opens of the
            // target are mediated on-behalf by the supervisor.
            ctx.deny_path(&target);
            Verdict::Allow
        })
        .build()
        .expect("policy_fn policy builds");
    let err = sb
        .run(&["true"])
        .await
        .expect_err("the policy_fn deny shape must refuse");
    assert_run_refused(err, &refusal_msg(HOST_UID_A));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Minimal chroot rootfs with the static rootfs-helper and a sticky /tmp.
fn build_rootfs(base: &Path) -> PathBuf {
    let rootfs = base.join("rootfs");
    for dir in [
        "usr/bin",
        "usr/sbin",
        "etc",
        "proc",
        "dev",
        "tmp",
        "workspace",
        "home/user",
    ] {
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

// ----------------------------------------------------------------
// F10 shape, final state: chroot × privileged RunAs is refused before fork
// ----------------------------------------------------------------

/// The F10 shape is now a *refusal*, not a create/launch acceptance: root +
/// chroot (path mediation) + `RunAs(10000)` is exactly the privileged
/// mediator whose on-behalf opens would be owned by uid 0, and no downgrade
/// tier exists to accept it.  The refusal must fire before the child is
/// forked — before the chdir into the (root-owned 0700) cache, which is what
/// made the old acceptance hang on when it was *allowed*.  Message pinned
/// whole, with route B as the only remedy.
#[tokio::test]
async fn test_root_chroot_privileged_remap_is_refused_before_fork() {
    root_phase_env_check();
    let base = restrictive_tmp_dir("chroot-refused");
    let rootfs = build_rootfs(&base);
    let ws = base.join("ws");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");

    let mut sb = f10_chroot_policy(&rootfs, &ws, HOST_UID_A);
    let err = sb
        .run(&["rootfs-helper", "true"])
        .await
        .expect_err("the privileged in-process chroot shape must be refused");
    assert_run_refused(err, &refusal_msg(HOST_UID_A));

    // Nothing was created: the refusal precedes the fork, so the sticky /tmp
    // carve-out the mediator would have written remains empty.
    assert!(
        std::fs::read_dir(rootfs.join("tmp"))
            .expect("read the chroot's tmp")
            .next()
            .is_none(),
        "a refused spawn must not have performed any mediated write"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// Container-local scratch whose parent chain is NOT traversable by a
/// remapped non-zero sandbox uid — the E2B image-cache shape (root-owned
/// 0700).  The shapes below therefore still exercise the privileged
/// create/launch order (chdir + Landlock before the remap); the difference
/// is that a *non-zero* remap with chroot no longer reaches the fork at all.
fn restrictive_tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandlock-f10-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create container-local scratch");
    chmod_dir(&dir, 0o700);
    dir
}

/// Chroot policy with a chroot-visible workspace, mirroring the E2B M4
/// executor shape (rootfs + `/workspace`/`/home/user` mounts).
fn f10_chroot_policy(rootfs: &Path, ws: &Path, host_uid: u32) -> Sandbox {
    Sandbox::builder()
        .chroot(rootfs)
        .fs_read("/")
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_mount("/workspace", ws)
        .fs_mount("/home/user", ws)
        .fs_write("/workspace")
        .fs_write("/home/user")
        .cwd("/workspace")
        .user(host_uid, host_uid)
        .build()
        .expect("F10 chroot policy builds")
}

/// Reverse regression (the brief's "no误伤" case, root half): a
/// `RunAs(10000)` instance with **no** path mediation in play — no chroot,
/// no COW, no deny carve-out, no `policy_fn` — is a legal per-uid shape and
/// must still build and launch.  `mediation_active` is what gates the
/// identity refusal; a gate that demanded "the mediator must be the sandbox
/// uid" in all cases would break this (and, with it, the pooled per-sandbox
/// uid model E2B runs pure sandboxes on).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_root_pure_per_uid_run_as_is_still_accepted() {
    root_phase_env_check();
    let base = dac_tmp_dir("pure-per-uid");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(&ws)
        .user(HOST_UID_A, HOST_UID_A)
        .build()
        .expect("no mediation => no identity gate => the policy builds");
    let mut inst = SandboxInstance::launch_exec_only(policy)
        .await
        .expect("a pure per-uid instance must still launch");

    let h = inst
        .exec(&["/usr/bin/id", "-u"], ExecStdio::Piped)
        .await
        .expect("exec in the pure per-uid instance must succeed");
    let status = inst.wait_child(h.child_id).await.expect("wait child");
    assert_eq!(status, ExitStatus::Code(0), "exec child must exit 0");
    let stdout = h.stdout.expect("piped exec stdout");
    let mut out = Vec::new();
    std::fs::File::from(stdout)
        .read_to_end(&mut out)
        .expect("read exec stdout");
    assert_eq!(
        String::from_utf8_lossy(&out),
        "0\n",
        "the privileged remap maps the sandbox host uid to in-namespace 0"
    );
    inst.shutdown().await.expect("instance shutdown");

    let _ = std::fs::remove_dir_all(&base);
}

/// Acceptance 2 (root half, RunAs == holder == 0): uid 0 over the same
/// restrictive chroot must launch and serve `exec()` — `host_uid == 0`
/// needs no remap at all, so the identity gate must leave it alone
/// (regression pin for the instance exec-only create/launch order).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_root_chroot_uid0_instance_exec_only_restrictive_cache() {
    root_phase_env_check();
    let base = restrictive_tmp_dir("inst-u0");
    let rootfs = build_rootfs(&base);
    let ws = base.join("ws");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");
    chmod_dir(&ws, 0o777);

    let mut inst = SandboxInstance::launch_exec_only(f10_chroot_policy(&rootfs, &ws, 0))
        .await
        .expect("exec-only chroot instance must launch when the holder is uid 0");
    let h = inst
        .exec(
            &["rootfs-helper", "echo", "instance-chroot-u0-ok"],
            ExecStdio::Piped,
        )
        .await
        .expect("exec in the uid-0 chroot instance must succeed");
    let status = inst.wait_child(h.child_id).await.expect("wait child");
    assert_eq!(status, ExitStatus::Code(0), "exec child must exit 0");
    let stdout = h.stdout.expect("piped exec stdout");
    use std::io::Read;
    let mut out = Vec::new();
    std::fs::File::from(stdout)
        .read_to_end(&mut out)
        .expect("read exec stdout");
    assert_eq!(
        String::from_utf8_lossy(&out),
        "instance-chroot-u0-ok\n",
        "exec stdout must round-trip exactly"
    );
    inst.shutdown().await.expect("instance shutdown");

    let _ = std::fs::remove_dir_all(&base);
}

// ----------------------------------------------------------------
// CLI face of the refusal
// ----------------------------------------------------------------

#[test]
fn test_cli_refuses_the_root_remap_shape() {
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

    // The C档 shape (root + --user 10000 + --fs-deny) must refuse with the
    // exact message, wrapped by the CLI's error prologue.  The message is the
    // whole remedy an operator gets: route B, and nothing else.
    let mut args = base_args.clone();
    args.push("--".into());
    args.push("true".into());
    let caller = Command::new(&bin)
        .args(&args)
        .output()
        .expect("run sandlock");
    assert!(
        !caller.status.success(),
        "the CLI must refuse the root-remap shape"
    );
    let caller_err = String::from_utf8_lossy(&caller.stderr);
    let caller_line = caller_err.lines().next().unwrap_or_default();
    assert_eq!(
        caller_line.strip_prefix("Error: process error: child process error: "),
        Some(refusal_msg(HOST_UID_A).as_str()),
        "the CLI must surface the exact mediated-path identity refusal"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
