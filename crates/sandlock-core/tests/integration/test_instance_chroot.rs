//! Instance exec-only × chroot (fork-plan F10) — the non-root A档 half.
//!
//! The E2B M4 shape is a mainless `SandboxInstance` (launch_exec_only)
//! running over a real image rootfs with `mediation_run_as=supervisor` and a
//! chroot-visible workspace.  On the non-root gate the holder *is* the
//! sandbox's host uid (route A), so no userns remap happens and the initial
//! real chdir to the rootfs cwd succeeds with the caller's own credentials —
//! the same-uid contract the root-mode acceptance (`mediation_2uid` F10
//! cases) extends to a privileged remap.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sandlock_core::instance::{ExecStdio, SandboxInstance};
use sandlock_core::result::ExitStatus;
use sandlock_core::sandbox::MediationRunAs;
use sandlock_core::Sandbox;

/// Path to the static rootfs-helper binary (compiled by build.rs).
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found — build.rs should have compiled it")
}

fn temp_dir(name: &str) -> PathBuf {
    let base = option_env!("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("sandlock-test-inst-chroot-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Self-contained rootfs mirroring the `test_chroot` fixture, plus the
/// `/workspace` and `/home/user` mount points an image executor creates.
fn build_test_rootfs(name: &str) -> PathBuf {
    let rootfs = temp_dir(name);
    let helper = helper_binary();

    for dir in ["usr/bin", "usr/sbin", "etc", "proc", "dev", "tmp", "workspace", "home/user"] {
        let _ = std::fs::create_dir_all(rootfs.join(dir));
    }
    let _ = std::fs::set_permissions(rootfs.join("tmp"), std::fs::Permissions::from_mode(0o1777));

    let dest = rootfs.join("usr/bin/rootfs-helper");
    std::fs::hard_link(&helper, &dest)
        .or_else(|_| std::fs::copy(&helper, &dest).map(|_| ()))
        .expect("failed to install rootfs-helper into rootfs");

    for cmd in ["sh", "cat", "echo", "ls", "pwd", "readlink", "true", "write"] {
        let link = rootfs.join(format!("usr/bin/{cmd}"));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("rootfs-helper", &link)
            .expect("failed to create busybox symlink");
    }
    let _ = std::os::unix::fs::symlink("usr/bin", rootfs.join("bin"));
    let _ = std::os::unix::fs::symlink("usr/sbin", rootfs.join("sbin"));
    rootfs
}

fn cleanup(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

/// F10 acceptance 2 (non-root half): a mainless exec-only instance over a
/// chroot with the explicit `mediation_run_as=supervisor` tier launches and
/// serves an `exec()` — holder == sandbox host uid (route A), so the
/// supervisor-tier downgrade shape is the same one E2B runs per-sandbox.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_instance_exec_only_chroot_supervisor_same_uid_launch_and_exec() {
    let base = temp_dir("ws");
    let rootfs = build_test_rootfs("rootfs");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/")
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_mount("/workspace", &ws)
        .fs_mount("/home/user", &ws)
        .fs_write("/workspace")
        .fs_write("/home/user")
        .cwd("/workspace")
        .mediation_run_as(MediationRunAs::Supervisor)
        .build()
        .expect("instance chroot supervisor policy builds");

    let mut inst = SandboxInstance::launch_exec_only(policy)
        .await
        .expect("exec-only chroot instance must launch under the supervisor tier");
    let h = inst
        .exec(
            &["rootfs-helper", "echo", "instance-chroot-supervisor-ok"],
            ExecStdio::Piped,
        )
        .await
        .expect("exec in chroot instance must succeed");
    let status = inst
        .wait_child(h.child_id)
        .await
        .expect("wait exec child");
    assert_eq!(
        status,
        ExitStatus::Code(0),
        "chroot exec child must exit 0"
    );

    let stdout = h.stdout.expect("piped exec stdout");
    let mut out = Vec::new();
    std::fs::File::from(stdout)
        .read_to_end(&mut out)
        .expect("read exec stdout");
    assert_eq!(
        String::from_utf8_lossy(&out),
        "instance-chroot-supervisor-ok\n",
        "exec stdout must round-trip exactly"
    );

    inst.shutdown().await.expect("instance shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}
