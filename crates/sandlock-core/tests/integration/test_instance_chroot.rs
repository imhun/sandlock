//! Instance exec-only × chroot (fork-plan F10) — the non-root A档 half.
//!
//! The E2B M4 shape is a mainless `SandboxInstance` (launch_exec_only)
//! running over a real image rootfs with a chroot-visible workspace.  On the
//! non-root gate the holder *is* the sandbox's host uid (route A), so no
//! userns remap happens and the initial real chdir to the rootfs cwd succeeds
//! with the caller's own credentials.
//!
//! That shape is also the reverse regression for the mediated-path identity
//! gate: mediation is active (chroot) but the mediator's euid *is* the
//! sandbox's host uid, so the gate must leave it alone.  A gate that demanded
//! same-identity-in-all-cases instead of gating on `mediation_active` would
//! break exactly this case.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sandlock_core::instance::{ExecStdio, SandboxInstance};
use sandlock_core::result::ExitStatus;
use sandlock_core::Sandbox;

/// Monotonic suffix for scratch directory names; see `temp_dir`.
static SCRATCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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
    // The pid alone is not enough here: every case in this file asks for the
    // same scratch names (`rootfs`, and its own `ws`/`alias-*`), and libtest
    // runs them concurrently in one process, so two live cases would share a
    // directory — and one of them wiping it takes the other's rootfs away
    // mid-exec. A monotonic suffix keeps each case's scratch tree private.
    let seq = SCRATCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = base.join(format!(
        "sandlock-test-inst-chroot-{name}-{}-{}",
        std::process::id(),
        seq
    ));
    // `CARGO_TARGET_TMPDIR` is `target-linux/tmp`, which survives across
    // container runs while the pid baked into the name is reused there, and a
    // failing case never reaches `cleanup()`. A leftover rootfs from an
    // earlier run makes `build_test_rootfs`'s hard-link fall back to
    // `fs::copy` with a destination that is the *same inode* as the shared
    // `tests/rootfs-helper`; opening the destination for write truncates the
    // source too, zeroing that git-ignored artifact and turning every later
    // case in this file into `exit 127`. Start from a clean directory so the
    // fallback copy can never truncate the helper.
    let _ = std::fs::remove_dir_all(&dir);
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

/// Run one command in an instance and collect `(status, stdout, stderr)`.
///
/// Both pipes are read because a failure worth pinning is usually *named* on
/// stderr (`rootfs-helper` reports the errno there), and a bare `Code(1)` does
/// not say which of the two syscalls in that helper's command failed.
async fn exec_capture(
    inst: &mut SandboxInstance,
    args: &[&str],
) -> (ExitStatus, String, String) {
    let h = inst.exec(args, ExecStdio::Piped).await.expect("exec");
    let status = inst.wait_child(h.child_id).await.expect("wait");
    let read = |fd: Option<std::os::fd::OwnedFd>, what: &str| {
        let mut out = Vec::new();
        std::fs::File::from(fd.expect(what))
            .read_to_end(&mut out)
            .expect("read pipe");
        String::from_utf8_lossy(&out).into_owned()
    };
    let stdout = read(h.stdout, "piped stdout");
    let stderr = read(h.stderr, "piped stderr");
    (status, stdout, stderr)
}

/// F10 acceptance 2 (non-root half): a mainless exec-only instance over a
/// chroot launches and serves an `exec()` — holder == sandbox host uid
/// (route A), so the mediated-path identity gate must not fire even though
/// path mediation is active.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_instance_exec_only_chroot_same_uid_launch_and_exec() {
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
        .build()
        .expect("instance chroot policy builds");

    let mut inst = SandboxInstance::launch_exec_only(policy)
        .await
        .expect("exec-only chroot instance must launch (mediator euid == host uid)");
    let h = inst
        .exec(
            &["rootfs-helper", "echo", "instance-chroot-same-uid-ok"],
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
        "instance-chroot-same-uid-ok\n",
        "exec stdout must round-trip exactly"
    );

    inst.shutdown().await.expect("instance shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}

/// A host directory mounted at two virtual paths must not let the second
/// alias hide a sub-mount declared under the first one. Regression for the
/// E2B shared-volume shape: cwd-derived relative opens resolved against
/// `/home/user` (the alias `host_to_virtual` happened to pick) and missed
/// `/workspace/mnt/data` entirely -- EACCES on `cat mnt/data/x`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_relative_open_from_second_workspace_alias_resolves_the_submount() {
    let base = temp_dir("alias-mount");
    let rootfs = build_test_rootfs("rootfs");
    let ws = base.join("workspace");
    let vol = base.join("vol");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");
    std::fs::create_dir_all(&vol).expect("create volume host dir");
    std::fs::write(vol.join("data.txt"), "hello\n").expect("seed volume file");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/")
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/proc")
        .fs_mount("/workspace", &ws)
        .fs_mount("/workspace/mnt/data", &vol)
        .fs_mount("/home/user", &ws)
        .fs_write("/workspace")
        .fs_write("/workspace/mnt/data")
        .fs_write("/home/user")
        .cwd("/home/user")
        .build()
        .expect("alias + submount policy builds");

    let mut inst = SandboxInstance::launch_exec_only(policy)
        .await
        .expect("alias + submount instance must launch");
    let h = inst
        .exec(&["rootfs-helper", "cat", "mnt/data/data.txt"], ExecStdio::Piped)
        .await
        .expect("exec must succeed");
    let status = inst.wait_child(h.child_id).await.expect("wait child");
    let stdout = h.stdout.expect("piped stdout");
    let mut out = Vec::new();
    std::fs::File::from(stdout).read_to_end(&mut out).expect("read stdout");
    // The child's stderr rides along in every assertion message: a `Code(1)`
    // alone cannot be told apart from the fixture being broken (a zeroed
    // `rootfs-helper` exits 127 with an empty stdout), and the one line the
    // workload prints is what names the real failure.
    let mut err_out = Vec::new();
    std::fs::File::from(h.stderr.expect("piped stderr"))
        .read_to_end(&mut err_out)
        .expect("read stderr");
    assert_eq!(
        status,
        ExitStatus::Code(0),
        "relative cat must exit 0; stderr={:?}",
        String::from_utf8_lossy(&err_out)
    );
    assert_eq!(
        String::from_utf8_lossy(&out),
        "hello\n",
        "exact volume bytes; stderr={:?}",
        String::from_utf8_lossy(&err_out)
    );

    let w = inst
        .exec(&["rootfs-helper", "write", "mnt/data/new.txt", "bye"], ExecStdio::Piped)
        .await
        .expect("write exec must succeed");
    let wstatus = inst.wait_child(w.child_id).await.expect("wait write child");
    let mut werr = Vec::new();
    std::fs::File::from(w.stderr.expect("piped stderr"))
        .read_to_end(&mut werr)
        .expect("read write stderr");
    assert_eq!(
        wstatus,
        ExitStatus::Code(0),
        "relative write must exit 0; stderr={:?}",
        String::from_utf8_lossy(&werr)
    );
    assert_eq!(
        std::fs::read_to_string(vol.join("new.txt")).expect("volume must hold the write"),
        // `rootfs-helper write` always terminates its argument with a newline
        // (tests/rootfs-helper.c:174), so the exact bytes on disk are "bye\n".
        // The assertion itself is unchanged in substance: the relative write
        // must land in the volume, byte-for-byte.
        "bye\n",
        "relative write must land in the volume; stderr={:?}",
        String::from_utf8_lossy(&werr)
    );
    assert!(
        !ws.join("mnt/data/new.txt").exists(),
        "relative write must not land in the workspace copy; stderr={:?}",
        String::from_utf8_lossy(&werr)
    );

    inst.shutdown().await.expect("shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}

// ── FUP-26: a `..`-relative symlink lookup must not be a silent exit 127 ──

/// The exec path itself may be reached through a *relative* symlink whose
/// target has a `..` component -- the shape Debian/Ubuntu images ship as
/// `/lib64/ld-linux-x86-64.so.2 -> ../lib/x86_64-linux-gnu/...`, i.e. the
/// PT_INTERP every dynamically linked workload resolves first.
///
/// The kernel may refuse such a walk with the documented, *retryable*
/// `EAGAIN` ("could not ensure that a `..` component didn't escape ... due to
/// a race condition or potential attack. The caller may choose to retry"), so
/// the lookup has to be retried and, if it still fails, must surface as
/// `EAGAIN` rather than as a fabricated `ENOENT`. This case pins that the
/// shape resolves at all through the mediator (the fix's regression net; the
/// retry path itself is pinned deterministically by the `sys::fs` unit tests).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_exec_through_a_dotdot_relative_symlink_resolves() {
    let base = temp_dir("dotdot-exec");
    let rootfs = build_test_rootfs("rootfs");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");

    // <rootfs>/usr/lib64/echo -> ../bin/rootfs-helper: the final component is
    // a symlink whose target walks `..`, exactly like the image's ld-linux.
    std::fs::create_dir_all(rootfs.join("usr/lib64")).expect("create usr/lib64");
    std::os::unix::fs::symlink("../bin/rootfs-helper", rootfs.join("usr/lib64/echo"))
        .expect("create the ..-relative exec symlink");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/")
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_mount("/workspace", &ws)
        .fs_mount("/home/user", &ws)
        .fs_write("/workspace")
        .fs_write("/home/user")
        .cwd("/workspace")
        .build()
        .expect("dotdot exec policy builds");

    let mut inst = SandboxInstance::launch_exec_only(policy)
        .await
        .expect("exec-only chroot instance must launch");
    let h = inst
        .exec(&["/usr/lib64/echo", "dotdot-relative-exec-ok"], ExecStdio::Piped)
        .await
        .expect("exec through the ..-relative symlink must be served");
    let status = inst.wait_child(h.child_id).await.expect("wait exec child");
    let mut out = Vec::new();
    std::fs::File::from(h.stdout.expect("piped exec stdout"))
        .read_to_end(&mut out)
        .expect("read exec stdout");
    let mut err = Vec::new();
    std::fs::File::from(h.stderr.expect("piped exec stderr"))
        .read_to_end(&mut err)
        .expect("read exec stderr");
    assert_eq!(
        status,
        ExitStatus::Code(0),
        "the workload behind the ..-relative symlink must run; stderr={:?}",
        String::from_utf8_lossy(&err)
    );
    assert_eq!(
        String::from_utf8_lossy(&out),
        "dotdot-relative-exec-ok\n",
        "exact stdout through the ..-relative symlink; stderr={:?}",
        String::from_utf8_lossy(&err)
    );
    assert_eq!(
        String::from_utf8_lossy(&err),
        "",
        "a served exec emits nothing on stderr"
    );

    inst.shutdown().await.expect("instance shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}

/// A mediated exec failure the sandbox *hides* from the child must leave
/// evidence behind. Before FUP-26 every failure of the supervisor's own
/// `openat2(RESOLVE_IN_ROOT)` -- including the retryable `EAGAIN` -- was
/// reported to the child as `ENOENT`, so `execvp` failed, `sandlock-init`
/// exited 127 and the command produced no output at all: "127 with an empty
/// stderr" was indistinguishable from a genuinely missing binary.
///
/// Deterministic form: a symlink loop is `ELOOP` (40) at every attempt, on
/// every kernel version, for every uid -- the kernel's answer must reach the
/// child's stderr instead of being rewritten into "not found".
///
/// Measured 2026-09-23 (root-mode gate, `--privileged`): this test was the
/// regression reporter for a two-read errno bug -- `sandlock-init` read errno
/// again *after* `realroot::record_failure()` had tried to open the trace file,
/// so a denied open of `/tmp/sandlock-real-root-error` (the default path, and
/// the sandbox's ruleset grants no write to `/tmp`) replaced the exec's ELOOP
/// with the open's EACCES: `assert_eq` saw `errno 13` where the loop demands
/// `errno 40`. The shape matters: with `SANLOCK_REALROOT_TRACE` set, `note()`
/// opens the trace file just before `execvp` and the second read is never
/// reached, which is why the e2b lane (it sets that variable) hid this from
/// its own contract tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_exec_failure_names_the_kernel_errno_instead_of_exiting_127_silently() {
    let base = temp_dir("exec-errno");
    let rootfs = build_test_rootfs("rootfs");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");

    std::os::unix::fs::symlink("loop-b", rootfs.join("usr/bin/loop-a"))
        .expect("create loop-a");
    std::os::unix::fs::symlink("loop-a", rootfs.join("usr/bin/loop-b"))
        .expect("create loop-b");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/")
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_mount("/workspace", &ws)
        .fs_mount("/home/user", &ws)
        .fs_write("/workspace")
        .fs_write("/home/user")
        .cwd("/workspace")
        .build()
        .expect("errno-reporting policy builds");

    let mut inst = SandboxInstance::launch_exec_only(policy)
        .await
        .expect("exec-only chroot instance must launch");
    let h = inst
        .exec(&["/usr/bin/loop-a"], ExecStdio::Piped)
        .await
        .expect("the refused exec is the child's own exit status, not a driver error");
    let status = inst.wait_child(h.child_id).await.expect("wait exec child");
    let mut out = Vec::new();
    std::fs::File::from(h.stdout.expect("piped exec stdout"))
        .read_to_end(&mut out)
        .expect("read exec stdout");
    let mut err = Vec::new();
    std::fs::File::from(h.stderr.expect("piped exec stderr"))
        .read_to_end(&mut err)
        .expect("read exec stderr");

    assert_eq!(String::from_utf8_lossy(&out), "", "no stdout from a failed exec");
    assert_eq!(
        status,
        ExitStatus::Code(127),
        "127 stays the reserved exec-failure code; stderr={:?}",
        String::from_utf8_lossy(&err)
    );
    assert_eq!(
        String::from_utf8_lossy(&err),
        "sandlock-init: exec \"/usr/bin/loop-a\" failed (errno 40)\n",
        "the kernel's ELOOP must reach the operator, not a fabricated ENOENT"
    );

    // The genuinely-missing-binary shape keeps its stock, silent 127: ENOENT
    // is the POSIX "not found" answer every execvp caller already handles
    // (and the shape e2b's contract tests pin as "127 with no output").
    let m = inst
        .exec(&["/usr/bin/absent-binary"], ExecStdio::Piped)
        .await
        .expect("a missing binary is the child's exit status");
    let mstatus = inst.wait_child(m.child_id).await.expect("wait missing child");
    let mut merr = Vec::new();
    std::fs::File::from(m.stderr.expect("piped stderr"))
        .read_to_end(&mut merr)
        .expect("read stderr");
    assert_eq!(
        mstatus,
        ExitStatus::Code(127),
        "missing binary still exits 127; stderr={:?}",
        String::from_utf8_lossy(&merr)
    );
    assert_eq!(
        String::from_utf8_lossy(&merr),
        "",
        "ENOENT stays silent: 'command not found' is not a hidden failure"
    );

    inst.shutdown().await.expect("instance shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}

/// Guard, not a RED: this is the post-fix guarding assertion. The launch cwd
/// does not go through the mount tie-break — `context.rs` turns it into a real
/// `chdir` to the host path under the rootfs, which the chroot-root rule alone
/// maps back — so `.cwd("/home/user")` already passes today and must keep
/// passing after the fix. What it pins is the semantics: the alias the policy
/// declared is the alias `getcwd` reports.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_getcwd_reports_the_alias_the_policy_declared() {
    let base = temp_dir("alias-cwd");
    let rootfs = build_test_rootfs("rootfs");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/")
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_mount("/workspace", &ws)
        .fs_mount("/home/user", &ws)
        .fs_write("/workspace")
        .fs_write("/home/user")
        .cwd("/home/user")
        .build()
        .expect("alias policy builds");

    let mut inst = SandboxInstance::launch_exec_only(policy).await.expect("launch");
    let h = inst
        .exec(&["rootfs-helper", "pwd"], ExecStdio::Piped)
        .await
        .expect("pwd exec");
    let status = inst.wait_child(h.child_id).await.expect("wait");
    let stdout = h.stdout.expect("piped stdout");
    let mut out = Vec::new();
    std::fs::File::from(stdout).read_to_end(&mut out).expect("read");
    assert_eq!(status, ExitStatus::Code(0));
    assert_eq!(String::from_utf8_lossy(&out), "/home/user\n", "exact cwd string");

    inst.shutdown().await.expect("shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}

/// Whichever alias the request names is the one the sandbox must report — not
/// whatever a host->virtual reverse lookup happens to pick. The host directory
/// is mounted at both `/workspace` and `/home/user`, and `rootfs-helper chdir`
/// is serviced by `handle_chroot_chdir`: before the fix that handler records
/// where the kernel landed (`/proc/self/fd/N` read back as a host path) and
/// maps it with `host_to_virtual`, whose most-specific-prefix rule ties on two
/// mounts sharing one source and is won by the last one declared — so
/// `chdir("/workspace")` comes back as `OK /home/user`. That is precisely the
/// "cwd identity decided by a reverse lookup" defect this plan exists to fix;
/// RED until the recorded cwd is the alias the request named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_getcwd_reports_the_requested_alias_not_the_best_match() {
    let base = temp_dir("alias-cwd-requested");
    let rootfs = build_test_rootfs("rootfs");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/")
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_mount("/workspace", &ws)
        .fs_mount("/home/user", &ws)
        .fs_write("/workspace")
        .fs_write("/home/user")
        .cwd("/workspace")
        .build()
        .expect("alias policy builds");

    let mut inst = SandboxInstance::launch_exec_only(policy).await.expect("launch");
    let h = inst
        .exec(&["rootfs-helper", "chdir", "/workspace"], ExecStdio::Piped)
        .await
        .expect("chdir exec");
    let status = inst.wait_child(h.child_id).await.expect("wait");
    let stdout = h.stdout.expect("piped stdout");
    let mut out = Vec::new();
    std::fs::File::from(stdout).read_to_end(&mut out).expect("read");
    assert_eq!(status, ExitStatus::Code(0), "chdir must succeed");
    assert_eq!(
        String::from_utf8_lossy(&out),
        "OK /workspace\n",
        "the requested alias, not the reverse-lookup winner"
    );

    inst.shutdown().await.expect("shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}

/// S3 (`docs/n14-retire-the-emulation.md` §4.1): `getcwd` is the first handler
/// handed back to the kernel once the child has a real root, and this pins what
/// that *means* — not just that it works.
///
/// The emulated shape rewrites the child's buffer with the path the mediator
/// recorded, and that record is deliberately the spelling the caller asked for
/// (see `test_getcwd_reports_the_requested_alias_not_the_best_match` above).
/// Under a real root the kernel answers instead, and the kernel resolves
/// symlinks: a cwd entered through a symlink comes back canonical, exactly as
/// it would in a container. Both are legitimate spellings of one directory;
/// what this pins is *which* one the real-root shape produces. An edit that
/// puts the buffer rewrite back into the pivoted path answers `/alias` here and
/// is red.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_getcwd_under_a_real_root_is_the_kernels_answer() {
    let base = temp_dir("realroot-cwd");
    let rootfs = base.join("rootfs");
    let work = base.join("work");
    for dir in ["usr/bin", "work/sub", "etc", "proc"] {
        std::fs::create_dir_all(rootfs.join(dir)).expect("create rootfs dir");
    }
    // `/work` is the *host* directory bind-mounted over the rootfs's own
    // `/work`, so the subdirectory a case chdir's into has to exist on the host
    // side of the mount — the mount point inside the rootfs is just a stub.
    std::fs::create_dir_all(work.join("sub")).expect("create host work dir");
    // The helper is static (build.rs), so the rootfs needs nothing else to
    // exec it: no /lib, no interpreter, no /dev.
    let helper = helper_binary();
    let dest = rootfs.join("usr/bin/rootfs-helper");
    std::fs::hard_link(&helper, &dest)
        .or_else(|_| std::fs::copy(&helper, &dest).map(|_| ()))
        .expect("install rootfs-helper into rootfs");
    // Relative, so it means `/work` on both sides of the pivot.
    std::os::unix::fs::symlink("work", rootfs.join("alias")).expect("symlink /alias -> /work");

    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    let mut builder = Sandbox::builder()
        .chroot(&rootfs)
        .real_root(true)
        .user(euid, egid)
        .fs_read("/usr")
        .fs_mount("/work", &work)
        .fs_write("/work")
        .cwd("/work");
    builder.userns_self_map = true;
    let policy = builder.build().expect("real-root policy builds");

    let mut inst = SandboxInstance::launch_exec_only(policy).await.expect("launch");
    let (status, stdout, stderr) = exec_capture(&mut inst, &["rootfs-helper", "pwd"]).await;
    assert_eq!(status, ExitStatus::Code(0), "pwd failed: {stderr}");
    assert_eq!(
        stdout, "/work\n",
        "the policy's cwd, as the sandbox spells it"
    );

    let (status, stdout, stderr) =
        exec_capture(&mut inst, &["rootfs-helper", "chdir", "/work/sub"]).await;
    assert_eq!(status, ExitStatus::Code(0), "chdir failed: {stderr}");
    assert_eq!(
        stdout, "OK /work/sub\n",
        "a cwd with no symlink in it reads back as written"
    );

    let (status, stdout, stderr) =
        exec_capture(&mut inst, &["rootfs-helper", "chdir", "/alias"]).await;
    assert_eq!(status, ExitStatus::Code(0), "chdir failed: {stderr}");
    assert_eq!(
        stdout, "OK /work\n",
        "the kernel's answer: symlinks resolved, not the spelling the mediator recorded"
    );

    inst.shutdown().await.expect("shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}

/// Denying a sub-mount declared under one alias must cover the same host object
/// reached through the other alias. `/workspace` and `/home/user` are the same
/// host directory and the volume is mounted at `/workspace/mnt/data`, so
/// `fs_deny("/workspace/mnt/data")` has to catch `/home/user/mnt/data/...` too:
/// the alias-normalised mount walk reaches that very volume, and a deny that
/// only matched the spelling it was written with would be a way around itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_deny_declared_under_one_alias_covers_the_other_alias() {
    let base = temp_dir("alias-deny");
    let rootfs = build_test_rootfs("rootfs");
    let ws = base.join("workspace");
    let vol = base.join("vol");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");
    std::fs::create_dir_all(&vol).expect("create volume host dir");
    std::fs::write(vol.join("data.txt"), "hello\n").expect("seed volume file");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/")
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/proc")
        .fs_mount("/workspace", &ws)
        .fs_mount("/workspace/mnt/data", &vol)
        .fs_mount("/home/user", &ws)
        .fs_write("/workspace")
        .fs_write("/workspace/mnt/data")
        .fs_write("/home/user")
        .fs_deny("/workspace/mnt/data")
        .cwd("/home/user")
        .build()
        .expect("alias + submount + deny policy builds");

    let mut inst = SandboxInstance::launch_exec_only(policy)
        .await
        .expect("alias + deny instance must launch");
    let h = inst
        .exec(&["rootfs-helper", "cat", "mnt/data/data.txt"], ExecStdio::Piped)
        .await
        .expect("exec must succeed");
    let status = inst.wait_child(h.child_id).await.expect("wait child");
    let mut out = Vec::new();
    std::fs::File::from(h.stdout.expect("piped stdout"))
        .read_to_end(&mut out)
        .expect("read stdout");
    let mut err = Vec::new();
    std::fs::File::from(h.stderr.expect("piped stderr"))
        .read_to_end(&mut err)
        .expect("read stderr");
    let err = String::from_utf8_lossy(&err);

    assert_ne!(
        status,
        ExitStatus::Code(0),
        "the deny covers this alias: the read must not succeed (stdout={:?}, stderr={:?})",
        String::from_utf8_lossy(&out),
        err
    );
    assert_eq!(
        err,
        "cat: mnt/data/data.txt: Permission denied\n",
        "the deny fires on the requested path and reports EACCES exactly"
    );

    // Nothing served the file through the deny: the volume is untouched and the
    // denied read cannot have leaked its bytes.
    assert_eq!(
        std::fs::read_to_string(vol.join("data.txt")).expect("volume intact"),
        "hello\n"
    );

    inst.shutdown().await.expect("shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}

/// The read-only twin of the deny case: `fs_mount_ro("/workspace/mnt/data")`
/// must make the volume read-only through `/home/user/mnt/data` as well — reads
/// still work (the mount is readable), writes are refused. Without the
/// alias-aware check the relative write landed in the volume, which is exactly
/// the exposure the deny/RO folding exists to close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_only_declared_under_one_alias_covers_the_other_alias() {
    let base = temp_dir("alias-ro");
    let rootfs = build_test_rootfs("rootfs");
    let ws = base.join("workspace");
    let vol = base.join("vol");
    std::fs::create_dir_all(&ws).expect("create workspace host dir");
    std::fs::create_dir_all(&vol).expect("create volume host dir");
    std::fs::write(vol.join("data.txt"), "hello\n").expect("seed volume file");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/")
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/proc")
        .fs_mount("/workspace", &ws)
        .fs_mount_ro("/workspace/mnt/data", &vol)
        .fs_mount("/home/user", &ws)
        .fs_write("/workspace")
        .fs_write("/home/user")
        .cwd("/home/user")
        .build()
        .expect("alias + read-only submount policy builds");

    let mut inst = SandboxInstance::launch_exec_only(policy)
        .await
        .expect("alias + read-only instance must launch");

    // Read through the alias: allowed, byte-for-byte.
    let r = inst
        .exec(&["rootfs-helper", "cat", "mnt/data/data.txt"], ExecStdio::Piped)
        .await
        .expect("read exec must succeed");
    let rstatus = inst.wait_child(r.child_id).await.expect("wait read child");
    let mut rout = Vec::new();
    std::fs::File::from(r.stdout.expect("piped stdout"))
        .read_to_end(&mut rout)
        .expect("read stdout");
    let mut rerr = Vec::new();
    std::fs::File::from(r.stderr.expect("piped stderr"))
        .read_to_end(&mut rerr)
        .expect("read stderr");
    assert_eq!(
        rstatus,
        ExitStatus::Code(0),
        "a read-only mount stays readable; stderr={:?}",
        String::from_utf8_lossy(&rerr)
    );
    assert_eq!(
        String::from_utf8_lossy(&rout),
        "hello\n",
        "exact volume bytes through the alias; stderr={:?}",
        String::from_utf8_lossy(&rerr)
    );

    // Write through the alias: refused, and nothing reaches the volume.
    let w = inst
        .exec(&["rootfs-helper", "write", "mnt/data/new.txt", "bye"], ExecStdio::Piped)
        .await
        .expect("write exec must succeed");
    let wstatus = inst.wait_child(w.child_id).await.expect("wait write child");
    let mut werr = Vec::new();
    std::fs::File::from(w.stderr.expect("piped stderr"))
        .read_to_end(&mut werr)
        .expect("read stderr");
    let werr = String::from_utf8_lossy(&werr);
    assert_ne!(
        wstatus,
        ExitStatus::Code(0),
        "the read-only mount covers this alias: the write must not succeed (stderr={:?})",
        werr
    );
    assert_eq!(
        werr,
        "write: mnt/data/new.txt: Permission denied\n",
        "the read-only mount fires on the requested path and reports EACCES exactly"
    );
    assert!(
        !vol.join("new.txt").exists(),
        "the refused write must not land in the volume"
    );
    assert!(
        !ws.join("mnt/data/new.txt").exists(),
        "the refused write must not land in the workspace copy either"
    );

    inst.shutdown().await.expect("shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}

/// N16 (E2B `docs/superpowers/plans/2026-09-26-pure-shape-synthetic-rootfs.md`):
/// the pure shape's root is a *plain directory* the sandbox binds the host's
/// system directories into -- not an extracted image, and not a tmpfs (the
/// shipped worker profile refuses every `mount` whose fstype is not NULL).
///
/// The fork has no "image" concept on this path at all: `real_root` takes a root
/// path and a `(virtual, host)` mount list, so nothing here should need a
/// production change. The case exists to make that claim falsifiable -- each
/// assertion is one place an image assumption could have hidden.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_a_plain_directory_root_pivots_and_hides_the_host() {
    let base = temp_dir("synth-root");
    let rootfs = base.join("skeleton");
    let work = base.join("work");
    let host_only = base.join("host-only");
    std::fs::create_dir_all(&host_only).expect("create host-only dir");
    std::fs::write(host_only.join("SECRET"), b"secret\n").expect("write sentinel");
    // `work` is not decoration: it is the policy's `fs_mount` destination *and*
    // its cwd, and the engine refuses a root whose mount point is missing
    // (realroot.rs says so; the child's step-6 `chdir` into the host spelling of
    // the cwd fails first, with ENOENT, before the pivot). The E2B side creates
    // exactly this set next to the skeleton (`_ensure_chroot_mount_points`).
    for dir in ["usr/bin", "dev", "proc", "etc", "tmp", "work"] {
        std::fs::create_dir_all(rootfs.join(dir)).expect("create skeleton dir");
    }
    std::fs::create_dir_all(&work).expect("create host work dir");
    std::fs::write(work.join("hello.txt"), b"hello\n").expect("write workspace file");
    let helper = helper_binary();
    let dest = rootfs.join("usr/bin/rootfs-helper");
    std::fs::hard_link(&helper, &dest)
        .or_else(|_| std::fs::copy(&helper, &dest).map(|_| ()))
        .expect("install rootfs-helper into the skeleton");

    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    // `/` — the whole root — and not `/usr`. Under a chroot that spelling means
    // *this rootfs* (landlock.rs translates it to `root.join("")`; it is the
    // same grant the image shape carries), so it names the subject of the case
    // rather than a corner of it. With the narrower `/usr` the two anatomical
    // assertions become vacuous and pass for the wrong reason, both measured:
    // a path outside the allow-list is answered `EACCES` by policy before
    // anything looks at the root, so `/proc` read `Permission denied` *whether
    // or not the skeleton had a `proc` directory*, and the host-only path in ③
    // was refused by the allow-list instead of by the pivot. Granting the whole
    // root makes ③ and ④ measure what they claim: the policy permits every
    // path inside the root, so what is left hiding the host is the pivot, and
    // `ls /proc` is answered by the skeleton's own directory.
    let mut builder = Sandbox::builder()
        .chroot(&rootfs)
        .real_root(true)
        .user(euid, egid)
        .fs_read("/")
        .fs_mount("/work", &work)
        .fs_mount("/dev", "/dev")
        .fs_write("/work")
        .cwd("/work");
    builder.userns_self_map = true;
    let policy = builder.build().expect("synthetic-root policy builds");
    let mut inst = SandboxInstance::launch_exec_only(policy).await.expect("launch");

    // ① absolute exec through the bound host directory
    let (status, stdout, stderr) =
        exec_capture(&mut inst, &["/usr/bin/rootfs-helper", "pwd"]).await;
    assert_eq!(status, ExitStatus::Code(0), "absolute exec failed: {stderr}");
    assert_eq!(stdout, "/work\n");
    // ② relative exec -- the symptom of a self-bind taken in the wrong order
    let (status, stdout, stderr) =
        exec_capture(&mut inst, &["rootfs-helper", "cat", "hello.txt"]).await;
    assert_eq!(status, ExitStatus::Code(0), "relative exec failed: {stderr}");
    assert_eq!(stdout, "hello\n");
    // ③ the host-only path is gone: this is what the pivot bought
    let (status, _stdout, _stderr) = exec_capture(
        &mut inst,
        &["rootfs-helper", "stat", &host_only.display().to_string()],
    )
    .await;
    assert_eq!(
        status,
        ExitStatus::Code(1),
        "the host-only path is still reachable"
    );
    // ④ the skeleton's own /proc is an empty directory, not a missing one
    let (status, stdout, stderr) = exec_capture(&mut inst, &["rootfs-helper", "ls", "/proc"]).await;
    assert_eq!(status, ExitStatus::Code(0), "ls /proc failed: {stderr}");
    assert_eq!(stdout, "");

    inst.shutdown().await.expect("shutdown");
    cleanup(&rootfs);
    cleanup(&base);
}
