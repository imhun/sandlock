use sandlock_core::sandbox::BranchAction;
#[allow(unused_imports)]
use sandlock_core::{Sandbox};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Monotonic suffix for scratch directory names; see `temp_dir`.
static SCRATCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Path to the static rootfs-helper binary (compiled by build.rs).
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found — build.rs should have compiled it")
}

/// Minimal fs_readable set needed to run rootfs-helper under chroot.
///
/// N14 S5 (2026-10-04): the real root is the only chroot shape now (the
/// emulated one is refused at create), and an unprivileged mediator needs the
/// sandbox to have a user namespace of its own for the mount namespace the real
/// root builds -- that is what `userns_self_map` provides here, exactly as
/// `test_getcwd_under_a_real_root_is_the_kernels_answer` spells it.
fn minimal_exec_policy(rootfs: &PathBuf) -> sandlock_core::SandboxBuilder {
    let mut builder = Sandbox::builder()
        .chroot(rootfs)
        .real_root(true)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/proc")
        .fs_read("/dev");
    builder.userns_self_map = true;
    builder
}

fn temp_dir(name: &str) -> PathBuf {
    // Prefer cargo's per-test-binary tmp dir (under `target/`, the same
    // filesystem as the compiled rootfs-helper) so build_test_rootfs can
    // hard-link the helper into the rootfs instead of copying it. A
    // cross-filesystem temp such as /tmp (often tmpfs) forces the fs::copy
    // fallback, whose writable fd can be inherited by a concurrent fork+exec in
    // another parallel test and leave the helper briefly open for write, making
    // the eventual execve fail with ETXTBSY (Text file busy).
    //
    // The pid alone is NOT enough to name that scratch, for the reason
    // `test_instance_chroot.rs` records in full: `CARGO_TARGET_TMPDIR` is
    // `target-linux/tmp`, which survives across container runs while the pid
    // baked into the name is reused there, and a case that fails (or hangs)
    // never reaches `cleanup_rootfs`. A leftover rootfs then makes
    // `build_test_rootfs`'s hard link fail, and its `fs::copy` fallback writes
    // to a destination that is the SAME INODE as the shared
    // `tests/rootfs-helper` -- opening it for write truncates the source. The
    // git-ignored artifact goes to zero bytes and every later chroot case dies
    // with `execvp 'rootfs-helper': Exec format error` (measured 2026-09-22:
    // one leftover `magic-fd-link` fixture zeroed the helper and turned the
    // whole file red). A monotonic suffix plus a clean start removes the
    // fallback-copy path and the leftover it needs.
    let base = option_env!("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let seq = SCRATCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = base.join(format!(
        "sandlock-test-chroot-{}-{}-{}",
        name,
        std::process::id(),
        seq
    ));
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Build a self-contained rootfs with the static rootfs-helper binary.
///
/// Layout:
///   usr/bin/rootfs-helper   — the real binary
///   usr/bin/sh              — symlink -> rootfs-helper
///   usr/bin/cat             — symlink -> rootfs-helper
///   usr/bin/echo            — symlink -> rootfs-helper
///   usr/bin/ls              — symlink -> rootfs-helper
///   usr/bin/pwd             — symlink -> rootfs-helper
///   usr/bin/readlink        — symlink -> rootfs-helper
///   usr/bin/true            — symlink -> rootfs-helper
///   usr/bin/write           — symlink -> rootfs-helper
///   bin                     — symlink -> usr/bin  (merged /usr)
///   sbin                    — symlink -> usr/sbin (merged /usr)
///   etc/
///   proc/
///   dev/
///   tmp/                    — mode 1777
fn build_test_rootfs(name: &str) -> PathBuf {
    let rootfs = temp_dir(name);
    let helper = helper_binary();

    // Create real directories
    for dir in &["usr/bin", "usr/sbin", "etc", "proc", "dev", "tmp"] {
        let _ = fs::create_dir_all(rootfs.join(dir));
    }

    // Set /tmp sticky
    let _ = fs::set_permissions(rootfs.join("tmp"), fs::Permissions::from_mode(0o1777));

    // N14 S5: the real root binds the policy's `fs_mount` entries *inside* the
    // rootfs, and `realroot::build` refuses a target that does not exist there
    // ("mount point … does not exist inside the rootfs"). The emulated shape
    // never needed the mount points to exist (it translated paths in the
    // mediator), so the fixture has to materialize the ones the policies in
    // this file bind: `minimal_dev`'s six nodes and the `/tmp` write mount.
    for node in [
        "dev/ptmx",
        "dev/null",
        "dev/urandom",
        "dev/zero",
        "dev/tty",
    ] {
        let path = rootfs.join(node);
        if !path.exists() {
            fs::write(&path, b"").expect("materialize a /dev mount target");
        }
    }
    let _ = fs::create_dir_all(rootfs.join("dev/pts"));

    // Hard-link the helper binary (atomic, avoids ETXTBSY races from copy).
    let dest = rootfs.join("usr/bin/rootfs-helper");
    fs::hard_link(&helper, &dest)
        .or_else(|_| fs::copy(&helper, &dest).map(|_| ()))
        .expect("failed to install rootfs-helper into rootfs");

    // Create busybox-style symlinks (relative, within rootfs)
    for cmd in &["sh", "cat", "echo", "ls", "pwd", "readlink", "true", "write"] {
        let link = rootfs.join(format!("usr/bin/{}", cmd));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink("rootfs-helper", &link)
            .expect("failed to create busybox symlink");
    }

    // Merged /usr symlinks (like real distros)
    let _ = std::os::unix::fs::symlink("usr/bin", rootfs.join("bin"));
    let _ = std::os::unix::fs::symlink("usr/sbin", rootfs.join("sbin"));

    rootfs
}

fn cleanup_rootfs(rootfs: &PathBuf) {
    let _ = fs::remove_dir_all(rootfs);
}

/// List / inside chroot shows rootfs contents (should see "usr", "tmp", "bin", "etc")
#[tokio::test]
async fn test_chroot_ls_root() {
    let rootfs = build_test_rootfs("ls-root");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/tmp")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "ls", "/"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "ls / should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert!(stdout.contains("usr"), "should list usr, got: {}", stdout);
            assert!(stdout.contains("tmp"), "should list tmp, got: {}", stdout);
            assert!(stdout.contains("bin"), "should list bin, got: {}", stdout);
            assert!(stdout.contains("etc"), "should list etc, got: {}", stdout);
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// F6.1 (SL-1) chroot-form A档 assertion: chroot mediation performs the
/// workload's path operations supervisor-side (chroot dispatch), so the
/// mediator identity must be the owning process's own uid for the sandbox's
/// files to behave.  When the supervisor is the sandbox's host uid (route A
/// on the non-root gate), a file created through the mediated open is owned
/// by that uid and the workload's own `chmod` takes effect — the exact pair
/// SL-1's C档 shape (root supervisor + remap) gets wrong.
///
/// F6.2 (P5) coupling: `/dev` is provided by the `minimal_dev` single-node
/// bind-mount helper instead of an empty rootfs `/dev` dir or a whole-tree
/// host `/dev` mount, and the guest writes to `/dev/null` through it. No
/// `fs_denied` is dispatched anywhere in this policy — the minimal set has no
/// `/dev/shm` node to carve out, which is exactly the SL-1 trigger surface
/// single-node mounts eliminate.
#[tokio::test]
async fn test_chroot_mediated_create_is_owned_by_caller_and_self_chmod_works() {
    use std::os::unix::fs::MetadataExt;

    let rootfs = build_test_rootfs("mediation-owner");
    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .minimal_dev()
        .fs_write("/tmp")
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "echo chroot-mediated > /tmp/mediated.txt; chmod 0600 /tmp/mediated.txt; \
             echo discard > /dev/null",
        ])
        .await
        .expect("chroot-mediated run must succeed");
    assert!(
        result.success(),
        "chroot create + self-chmod + /dev/null write must succeed, stderr: {:?}",
        result.stderr_str()
    );

    let real_path = rootfs.join("tmp/mediated.txt");
    let meta = fs::metadata(&real_path).expect("host-side stat of chroot-mediated file");
    let euid = unsafe { libc::geteuid() };
    assert_eq!(
        meta.uid(),
        euid,
        "chroot-mediated create must run as the owning process's uid (mediator == \
         sandbox host uid in A/B档); got uid {}",
        meta.uid()
    );
    assert_eq!(
        meta.mode() & 0o7777,
        0o600,
        "the workload's own chmod must take effect on its chroot-mediated file"
    );
    assert_eq!(
        fs::read_to_string(&real_path).expect("read chroot-mediated file"),
        "chroot-mediated\n"
    );

    cleanup_rootfs(&rootfs);
}

/// N95: a *creating* path whose parent is not there yet must answer ENOENT,
/// not EACCES.
///
/// Node's `fs.mkdir(p, {recursive: true})`, Go's `os.MkdirAll` and every
/// `mkdir -p` walk up on ENOENT and give up on anything else, so answering
/// EACCES for "the parent is missing" is what made `npm install` die inside a
/// sandbox (`docs/n95-write-path-errno.md`). EACCES stays what it is: the
/// policy refusing a path it *did* resolve (the read-only leg below).
///
/// The `legacy-*` verbs print the raw errno (`ERR <n>`), which is what makes
/// the assertion exact rather than a `strerror` match.
#[tokio::test]
async fn test_chroot_create_paths_answer_the_kernels_errno() {
    let rootfs = build_test_rootfs("create-errno");
    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let run = |argv: [&'static str; 3]| {
        let mut policy = policy.clone();
        async move {
            policy
                .run(&["rootfs-helper", argv[0], argv[1], argv[2]])
                .await
                .expect("the chroot sandbox must be creatable")
        }
    };

    // The parent exists: a direct child of the writable root is created.
    let ok = run(["legacy-mkdir", "/tmp/n95", ""]).await;
    assert_eq!(
        ok.stdout_str().unwrap_or(""),
        "OK",
        "mkdir of a direct child must succeed; stderr: {:?}",
        ok.stderr_str()
    );

    // The parent is missing: ENOENT(2). This is the reading N95 is about --
    // before the fix every one of these answered EACCES(13).
    let deep = run(["legacy-mkdir", "/tmp/n95/deep/inner", ""]).await;
    assert_eq!(
        deep.stdout_str().unwrap_or(""),
        "ERR 2",
        "mkdir under a missing parent must answer ENOENT; stderr: {:?}",
        deep.stderr_str()
    );

    let link = run(["legacy-symlink", "/etc/hostname", "/tmp/n95/missing/link"]).await;
    assert_eq!(
        link.stdout_str().unwrap_or(""),
        "ERR 2",
        "symlink into a missing directory must answer ENOENT; stderr: {:?}",
        link.stderr_str()
    );

    let read = run(["legacy-readlink", "/tmp/n95/missing/link", ""]).await;
    assert_eq!(
        read.stdout_str().unwrap_or(""),
        "ERR 2",
        "readlink under a missing directory must answer ENOENT; stderr: {:?}",
        read.stderr_str()
    );

    // And the refusal that is *not* a missing parent keeps its own answer:
    // /etc is read-only here, so this is the policy, EACCES(13).
    let refused = run(["legacy-mkdir", "/etc/n95-nope", ""]).await;
    assert_eq!(
        refused.stdout_str().unwrap_or(""),
        "ERR 13",
        "a refused path must still answer EACCES; stderr: {:?}",
        refused.stderr_str()
    );

    cleanup_rootfs(&rootfs);
}

/// Path traversal via /../../ stays confined — reads a file unique to the chroot.
#[tokio::test]
async fn test_chroot_no_escape() {
    let rootfs = build_test_rootfs("no-escape");

    // Write a sentinel file only inside the chroot's /etc
    let sentinel = "sandlock-chroot-sentinel";
    fs::write(rootfs.join("etc/sentinel"), sentinel).unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    // Path traversal: /../../etc/sentinel should resolve to /etc/sentinel inside
    // the chroot (the sentinel file we created), not escape to the host.
    let result = policy.clone().run(&["rootfs-helper", "cat", "/../../etc/sentinel"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "cat should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert_eq!(
                stdout.trim(),
                sentinel,
                "should read chroot sentinel, got: {}",
                stdout
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// pwd returns / inside chroot
#[tokio::test]
async fn test_chroot_getcwd() {
    let rootfs = build_test_rootfs("getcwd");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "pwd"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "pwd should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert_eq!(stdout, "/", "pwd should return /, got: {}", stdout);
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// A short absolute path must be reachable (issue #178). The old handler
/// redirected the child through "/proc/self/fd/N", 16 bytes that cannot fit
/// the buffer behind a path as short as "/tmp", so every short mount point
/// failed with ENAMETOOLONG while ls and open on the same path worked.
#[tokio::test]
async fn test_chroot_chdir_short_path() {
    let rootfs = build_test_rootfs("chdir-short");

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy.clone().run(&["rootfs-helper", "chdir", "/tmp"]).await {
        Ok(r) => {
            assert!(
                r.success(),
                "chdir(/tmp) should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert_eq!(r.stdout_str().unwrap_or("").trim(), "OK /tmp");
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// The virtual root is the shortest path there is, and no redirect can ever
/// fit its two-byte buffer. `cd /` has to work without one.
#[tokio::test]
async fn test_chroot_chdir_virtual_root() {
    let rootfs = build_test_rootfs("chdir-root");

    let policy = minimal_exec_policy(&rootfs).build().unwrap();

    match policy.clone().run(&["rootfs-helper", "chdir", "/"]).await {
        Ok(r) => {
            assert!(
                r.success(),
                "chdir(/) should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert_eq!(r.stdout_str().unwrap_or("").trim(), "OK /");
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// A relative path opened after a chdir must resolve against the directory
/// the child moved to. The supervisor resolves the path itself, so this is
/// what proves its notion of the cwd actually followed the chdir.
#[tokio::test]
async fn test_chroot_relative_open_follows_chdir() {
    let rootfs = build_test_rootfs("chdir-relative");
    fs::write(rootfs.join("tmp/marker.txt"), "marker-body\n").unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "sh", "-c", "chdir /tmp && cat marker.txt"])
        .await
    {
        Ok(r) => {
            assert!(
                r.success(),
                "relative cat after chdir should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stdout_str().unwrap_or("").contains("marker-body"),
                "relative open should have read /tmp/marker.txt, got: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// fchdir carries a dirfd instead of a path, so a supervisor tracking the cwd
/// has to observe this spelling too. Chained after a chdir, which is where the
/// supervisor's own notion takes over: miss the fchdir and that notion goes
/// stale, sending the following relative open back to the chdir's directory.
///
/// N14 S5 (2026-10-04): under the real root the `open("/etc")` behind the
/// `fchdir` is answered with a *mediator-injected* descriptor, and that
/// descriptor lives on the mediator's mount rather than on the sandbox's own
/// root. The cwd it leaves behind therefore renders as a **host** path, and the
/// supervisor's bookkeeping has to map it back (N43's rule, applied to the cwd
/// rather than to a dirfd: map when it maps, and only take the report as the
/// sandbox's own spelling when there is nothing to map). Without that, the
/// tracked cwd became the rootfs's host path and every later relative open was
/// denied as "outside the grants" -- measured here, and the reason this case is
/// asserted through `;` rather than `&&`: the relative read has to be reached
/// even when an earlier step in the chain reports a failure.
#[tokio::test]
async fn test_chroot_relative_open_follows_fchdir() {
    let rootfs = build_test_rootfs("fchdir-relative");
    fs::write(rootfs.join("tmp/marker.txt"), "from-tmp\n").unwrap();
    fs::write(rootfs.join("etc/marker.txt"), "from-etc\n").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .fs_write("/tmp")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "chdir /tmp; fchdir /etc; cat marker.txt",
        ])
        .await
    {
        Ok(r) => {
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert!(
                stdout.contains("from-etc"),
                "relative open should have read /etc/marker.txt, got stdout: {:?} stderr: {:?}",
                stdout,
                r.stderr_str()
            );
            assert!(
                !stdout.contains("from-tmp"),
                "relative open resolved against the earlier chdir, got: {}",
                stdout
            );
            // The cwd the fchdir landed on must be named the way the sandbox
            // names it, not the way the mediator's mount does.
            assert!(
                stdout.contains("OK /etc"),
                "the cwd must come back as the sandbox's own spelling, got: {:?}",
                stdout
            );
            assert!(
                r.stderr_str().unwrap_or("").is_empty(),
                "the chain must run clean, got stdout: {:?} stderr: {:?}",
                stdout,
                r.stderr_str()
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// /proc/self/cwd is the kernel's own view of the cwd, and the kernel's view
/// is the one the supervisor stopped moving. It has to be answered from the
/// tracked cwd or it reports wherever exec left the child.
#[tokio::test]
async fn test_chroot_proc_self_cwd_link_follows_chdir() {
    let rootfs = build_test_rootfs("proc-self-cwd-link");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .fs_write("/tmp")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "sh", "-c", "chdir /tmp && readlink /proc/self/cwd"])
        .await
    {
        Ok(r) => {
            // Exact match on the readlink line (the chdir prints its own):
            // the test rootfs itself lives under a host path containing
            // "/tmp", so a substring check would pass on a leak.
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert_eq!(
                stdout.lines().last().unwrap_or("").trim(),
                "/tmp",
                "readlink /proc/self/cwd should report the sandbox cwd, full stdout: {}",
                stdout
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// Opening *through* /proc/self/cwd has to land in the same directory the
/// link reports, so the magic link needs rewriting on the resolution path
/// too, not just when it is read.
#[tokio::test]
async fn test_chroot_open_through_proc_self_cwd() {
    let rootfs = build_test_rootfs("proc-self-cwd-open");
    fs::write(rootfs.join("tmp/marker.txt"), "from-tmp\n").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .fs_write("/tmp")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "chdir /tmp && cat /proc/self/cwd/marker.txt",
        ])
        .await
    {
        Ok(r) => {
            assert!(
                r.success(),
                "open through /proc/self/cwd should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stdout_str().unwrap_or("").contains("from-tmp"),
                "should have read /tmp/marker.txt, got: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// A cwd the sandbox cannot name must never be answered with the host path
/// it happens to sit at. Without a `cwd` the child starts wherever sandlock
/// was launched, which is outside the virtual root entirely.
#[tokio::test]
async fn test_chroot_proc_self_cwd_never_leaks_a_host_path() {
    let rootfs = build_test_rootfs("proc-self-cwd-leak");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "readlink", "/proc/self/cwd"])
        .await
    {
        Ok(r) => {
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert!(
                !stdout.contains(rootfs.to_str().unwrap()),
                "cwd link leaked the rootfs's host path: {}",
                stdout
            );
            let launch_dir = std::env::current_dir().unwrap();
            assert!(
                !stdout.contains(launch_dir.to_str().unwrap()),
                "cwd link leaked the launch directory: {}",
                stdout
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// Removing a symlink must remove the link, not what it points at. The
/// chroot resolver follows the final component to find the file a path names,
/// which is right for open and wrong for unlink: it deleted the target and
/// left the dangling link behind.
#[tokio::test]
async fn test_chroot_unlink_removes_the_symlink_not_its_target() {
    let rootfs = build_test_rootfs("unlink-symlink");
    fs::write(rootfs.join("tmp/target.txt"), "target-body\n").unwrap();
    std::os::unix::fs::symlink("target.txt", rootfs.join("tmp/link.txt")).unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy.clone().run(&["rootfs-helper", "rm", "/tmp/link.txt"]).await {
        Ok(r) => {
            assert!(r.success(), "rm should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            assert!(
                rootfs.join("tmp/target.txt").exists(),
                "rm of a symlink deleted its target"
            );
            assert!(
                fs::symlink_metadata(rootfs.join("tmp/link.txt")).is_err(),
                "rm of a symlink left the link in place"
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// lstat must describe the link itself. Resolution for the policy check
/// follows the final component, so the no-follow spellings were being handed
/// an already-resolved path and reported the target's type and size.
#[tokio::test]
async fn test_chroot_lstat_describes_the_symlink() {
    let rootfs = build_test_rootfs("lstat-symlink");
    fs::write(rootfs.join("tmp/target.txt"), "target-body\n").unwrap();
    std::os::unix::fs::symlink("target.txt", rootfs.join("tmp/link.txt")).unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "legacy-lstat", "/tmp/link.txt"])
        .await
    {
        Ok(r) => {
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert!(
                stdout.contains("type=link"),
                "lstat should describe the link itself, got: {}",
                stdout
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// Renaming a symlink moves the link. Following the final component first
/// would rename whatever it points at, leaving the old name dangling.
#[tokio::test]
async fn test_chroot_rename_moves_the_symlink_not_its_target() {
    let rootfs = build_test_rootfs("rename-symlink");
    fs::write(rootfs.join("tmp/target.txt"), "target-body\n").unwrap();
    std::os::unix::fs::symlink("target.txt", rootfs.join("tmp/link.txt")).unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "mv", "/tmp/link.txt", "/tmp/moved.txt"])
        .await
    {
        Ok(r) => {
            assert!(r.success(), "mv should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            assert!(
                rootfs.join("tmp/target.txt").exists(),
                "rename of a symlink moved its target"
            );
            let moved = fs::symlink_metadata(rootfs.join("tmp/moved.txt"));
            assert!(
                moved.map(|m| m.file_type().is_symlink()).unwrap_or(false),
                "the moved entry should still be a symlink"
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// The /proc magic links are symlinks, and lstat has to say so even though
/// paths *through* them are rewritten to the directory they stand for.
#[tokio::test]
async fn test_chroot_lstat_of_proc_self_cwd_is_a_link() {
    let rootfs = build_test_rootfs("lstat-proc-cwd");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .fs_write("/tmp")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "legacy-lstat", "/proc/self/cwd"])
        .await
    {
        Ok(r) => {
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert!(
                stdout.contains("type=link"),
                "lstat of /proc/self/cwd should report a symlink, got: {}",
                stdout
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// Reading a magic link is a read of another process's state, so it needs the
/// same per-PID gate the /proc open path applies. Opening /proc/1/cwd was
/// already refused; readlinking it went straight to the supervisor's own view
/// of the host's process table.
#[tokio::test]
async fn test_chroot_readlink_of_a_foreign_pid_is_refused() {
    let rootfs = build_test_rootfs("readlink-foreign-pid");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "readlink", "/proc/1/cwd"])
        .await
    {
        Ok(r) => {
            assert!(
                !r.success(),
                "readlink of a non-sandbox pid should fail, stdout: {}",
                r.stdout_str().unwrap_or("")
            );
            assert!(
                !r.stdout_str().unwrap_or("").contains('/'),
                "readlink of a non-sandbox pid returned a path: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// An fd whose file the sandbox cannot name must not be described with the
/// host path behind it. /proc/<pid>/fd/N is a magic link, so the "target"
/// readlink hands back is a real host path the kernel synthesized, not link
/// text: an inherited stdio fd, or here a supervisor-opened /dev/null with
/// no /dev mount to map it into, would spell out where it lives on the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_chroot_fd_link_does_not_leak_a_host_path() {
    use sandlock_core::StdioMode;
    use std::fs::File;
    use std::io::Read;

    let rootfs = build_test_rootfs("fd-link-leak");

    let mut sb = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .build()
        .unwrap();

    match sb
        .popen(
            &["rootfs-helper", "readlink", "/proc/self/fd/0"],
            StdioMode::Null,
            StdioMode::Piped,
            StdioMode::Piped,
        )
        .await
    {
        Ok(mut child) => {
            let mut out = String::new();
            if let Some(stdout) = child.take_stdout() {
                let _ = File::from(stdout).read_to_string(&mut out);
            }
            let _ = child.wait().await;
            let link = out.trim().to_string();
            // N14 S5: under the real root the kernel names the file the fd
            // actually holds, spelled in the sandbox's own tree -- `/dev/null`
            // here, which is a path the sandbox may see. What must never appear
            // is the *host* path behind the mount (the fixture's rootfs, or any
            // mediator-side directory), because that is the leak this pins.
            let host_root = rootfs.to_string_lossy().to_string();
            assert!(
                !link.contains(&host_root),
                "fd link named the host path behind the mount: {}",
                link
            );
            if link.starts_with('/') {
                assert!(
                    link == "/dev/null",
                    "the only absolute target this probe's policy can name is its own \
                     /dev/null, got: {link}"
                );
            }
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// openat2 must be mediated like every other open spelling. It was trapped
/// for the deny check but never routed to the chroot handler, so an absolute
/// path reached the kernel as written and resolved against the host root
/// instead of the rootfs.
#[tokio::test]
async fn test_chroot_openat2_resolves_inside_the_rootfs() {
    let rootfs = build_test_rootfs("openat2-absolute");
    fs::write(rootfs.join("etc/marker.txt"), "from-rootfs\n").unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_read("/etc").build().unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "openat2", "/etc/marker.txt"])
        .await
    {
        Ok(r) => {
            assert!(
                r.success(),
                "openat2 of a rootfs path should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stdout_str().unwrap_or("").contains("from-rootfs"),
                "openat2 should have read the rootfs file, got: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// The same for a relative openat2 after a chdir: it resolves against the
/// supervisor's notion of the cwd, like every other relative path does.
#[tokio::test]
async fn test_chroot_openat2_relative_follows_chdir() {
    let rootfs = build_test_rootfs("openat2-relative");
    fs::write(rootfs.join("tmp/marker.txt"), "from-tmp\n").unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "sh", "-c", "chdir /tmp && openat2 marker.txt"])
        .await
    {
        Ok(r) => {
            assert!(
                r.success(),
                "relative openat2 after chdir should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stdout_str().unwrap_or("").contains("from-tmp"),
                "openat2 should have read /tmp/marker.txt, got: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// A RESOLVE_NO_SYMLINKS openat2 must still refuse a symlink once the
/// supervisor performs the open on its behalf. The child asked the kernel to
/// refuse it; servicing the open must not quietly grant what it declined.
#[tokio::test]
async fn test_chroot_openat2_honors_resolve_no_symlinks() {
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;

    let rootfs = build_test_rootfs("openat2-nosymlinks");
    fs::write(rootfs.join("etc/marker.txt"), "from-rootfs\n").unwrap();
    std::os::unix::fs::symlink("marker.txt", rootfs.join("etc/link.txt")).unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_read("/etc").build().unwrap();

    match policy
        .clone()
        .run(&[
            "rootfs-helper",
            "openat2",
            "/etc/link.txt",
            &RESOLVE_NO_SYMLINKS.to_string(),
        ])
        .await
    {
        Ok(r) => {
            assert!(
                !r.success(),
                "openat2 through a symlink with RESOLVE_NO_SYMLINKS should fail, stdout: {}",
                r.stdout_str().unwrap_or("")
            );
            assert!(
                r.stderr_str().unwrap_or("").contains("openat2"),
                "expected the helper's openat2 error, got: {}",
                r.stderr_str().unwrap_or("")
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// chdir into a same-path mount (/proc) from a READ-ONLY path buffer must
/// succeed. Regression for the busybox-`top` EFAULT: rewriting the child's
/// path argument to /proc/self/fd/N faults when the path lives in read-only
/// memory (a .rodata literal). The handler instead lets the kernel run the
/// original chdir unchanged when the on-behalf-resolved directory is identical
/// to the requested path, which holds for the /proc mount.
#[tokio::test]
async fn test_chroot_chdir_proc_readonly_buffer() {
    let rootfs = build_test_rootfs("chdir-proc-ro");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .build()
        .unwrap();

    let result = policy
        .clone()
        
        .run(&["rootfs-helper", "chdir", "/proc"])
        .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "chdir(/proc) from a read-only buffer should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            // cwd must be /proc (getcwd may render the mount root with a
            // trailing slash; the meaningful assertion is that we landed there).
            let cwd = r.stdout_str().unwrap_or("").trim().trim_end_matches('/').to_string();
            assert_eq!(cwd, "OK /proc", "cwd after chdir should be /proc");
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// chdir("/proc/self") must land on the CHILD's own /proc/<pid> dir, not the
/// supervisor's. sandlock services /proc via an on-behalf openat2 in the
/// supervisor task, so a literal "self" would resolve against the supervisor.
/// The chdir handler canonicalizes /proc/self to the child's numeric PID (same
/// as the open path), so getcwd() after the chdir renders the child's own
/// /proc/<pid> and its basename matches the child's getpid(). Before the fix the
/// cwd pointed at the supervisor's /proc/<pid> and the basename mismatched.
#[tokio::test]
async fn test_chroot_chdir_proc_self_resolves_to_child() {
    let rootfs = build_test_rootfs("chdir-proc-self");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .build()
        .unwrap();

    let result = policy
        .clone()
        
        .run(&["rootfs-helper", "chdir-self", "/proc/self"])
        .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "chdir(/proc/self) should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            // The helper checks getcwd()'s basename == its own getpid(); "OK"
            // means "self" resolved to the child's own /proc/<pid>, not the
            // supervisor's.
            let out = r.stdout_str().unwrap_or("").trim().to_string();
            assert!(
                out.starts_with("OK /proc/"),
                "self must resolve to the child's own /proc/<pid>, got: {:?}",
                out
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// A dirfd-relative /proc read under a chroot with NO /proc mount must still
/// hit the synthesis shim. Regression: resolve_open_target took the proc
/// dirfd's real symlink target (`<chroot>/proc`) as the base, so
/// `openat(open("/proc"), "meminfo")` normalized to `<chroot>/proc/meminfo` and
/// missed the `== "/proc/meminfo"` synthesis match, falling through to the
/// chroot handler which ENOENT'd on the empty rootfs procfs, while the absolute
/// spelling was synthesized. The resolver now maps the dirfd base back into the
/// virtual namespace so both spellings synthesize identically.
///
/// N43 (the other half of "translate the dirfd"): the descriptor a sandbox
/// holds is one the mediator opened on the *host* and injected (ADDFD), so the
/// kernel renders `/proc/<pid>/fd/N` as the host path of the directory. Under a
/// real root the translator read that report as "the child is pivoted, so it is
/// already virtual" and looked the *host* path up inside the rootfs -- ENOENT
/// for the following stat, EACCES for the nofollow / open / readlink family.
/// That is exactly the set `find` / `du` / `tar` use to walk a tree (they hold
/// the parent directory, never an absolute name), which is why those three
/// tools were dead in production sandboxes while every absolute spelling
/// worked.
///
/// N14 S5: the shape is asserted against the expected bytes on the only root
/// there is. This case used to compare three (the emulated root, the real root
/// and the pure shape's identity root) because only one of them was broken --
/// the emulated root mapped the host report back all along. The other two are
/// retired: the emulated root is refused at create, and the identity root is
/// the `E2B_PURE_ROOTFS=off` lever, refused by name at startup. The fixture is
/// also the shape the tools use, not just the syscalls: the descriptor is
/// opened on a directory that is a *mount point* and the name under it is a
/// symlink, so the mapped base has to survive the mount table and the link has
/// to be followed through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dirfd_relative_reads_resolve_under_the_real_root() {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    // `stdout_str` trims the trailing newline only; the four lines themselves
    // are compared whole.
    let expected = "stat size=3000\nlstat size=8\nopen bytes=3000\nreadlink seed.bin";

    let base = temp_dir("dirfd-relative");
    let rootfs = base.join("rootfs");
    let ws = base.join("workspace");
    for dir in ["usr/bin", "work", "etc"] {
        fs::create_dir_all(rootfs.join(dir)).expect("create rootfs dir");
    }
    fs::create_dir_all(&ws).expect("create the host workspace dir");
    let helper = helper_binary();
    for dest in [rootfs.join("usr/bin/rootfs-helper")] {
        fs::hard_link(&helper, &dest)
            .or_else(|_| fs::copy(&helper, &dest).map(|_| ()))
            .unwrap_or_else(|e| panic!("install rootfs-helper at {}: {e}", dest.display()));
    }
    fs::write(ws.join("seed.bin"), vec![b'x'; 3000]).expect("seed the workspace file");
    std::os::unix::fs::symlink("seed.bin", ws.join("link")).expect("seed the symlink");

    // `/work` is a *mount point* (declared below) whose host side is the
    // workspace, and it has to exist inside the rootfs before the pivot: the
    // real root installs the policy's own binds, and a missing mount point is
    // an error there rather than a silently absent path (`realroot.rs`).
    let mut builder = Sandbox::builder()
        .chroot(&rootfs)
        .user(euid, egid)
        .cwd("/work")
        .fs_read("/usr")
        .fs_mount("/work", &ws)
        .fs_write("/work");
    builder.userns_self_map = true;
    let policy = builder
        .build()
        .unwrap_or_else(|e| panic!("the real-root policy builds: {e}"));
    let r = policy
        .clone()
        .run(&["rootfs-helper", "dirfd-probe", "/work", "link"])
        .await
        .unwrap_or_else(|e| panic!("the probe must run: {e}"));
    assert_eq!(
        r.stdout_str().unwrap_or("<no stdout>"),
        expected,
        "a dirfd-relative name must resolve exactly like its absolute spelling \
         (stderr: {})",
        r.stderr_str().unwrap_or("")
    );
    assert_eq!(r.stderr_str().unwrap_or(""), "", "the probe must be silent");

    cleanup_rootfs(&rootfs);
}

#[tokio::test]
async fn test_chroot_proc_dirfd_relative_is_virtualized() {
    let rootfs = build_test_rootfs("proc-dirfd");

    // No fs_mount for /proc: it is the empty rootfs dir, so the file can only
    // come from synthesis. max_memory engages the /proc/meminfo shim.
    let policy = minimal_exec_policy(&rootfs)
        .max_memory(sandlock_core::sandbox::ByteSize::mib(256))
        .build()
        .unwrap();

    let result = policy
        .clone()
        
        .run(&["rootfs-helper", "proc-dirfd", "meminfo"])
        .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "dirfd-relative /proc/meminfo must be synthesized (not ENOENT), stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let out = r.stdout_str().unwrap_or("");
            assert!(out.contains("MemTotal"), "expected synthesized meminfo, got: {:?}", out);
            assert!(
                out.contains("262144"),
                "expected virtual 256MiB MemTotal (262144 kB), got: {:?}",
                out
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// A path that resolves (through symlinks) to a `/proc/self/fd/N` magic link
/// must open as a dup of the child's own fd, not fail. Regression: container
/// images wire logging through `error.log -> /dev/stderr -> /proc/self/fd/2`;
/// openat2(RESOLVE_IN_ROOT) refuses to traverse the magic link out of the
/// resolve root (EXDEV directly, or ENOENT when it points into another mount),
/// so the open handler must recognize the fd reference and hand back a dup of
/// the child's stderr. Before the fix this open failed and killed servers like
/// nginx at startup.
#[tokio::test]
async fn test_chroot_magic_fd_symlink_resolves_to_child_fd() {
    let rootfs = build_test_rootfs("magic-fd-link");
    std::os::unix::fs::symlink("/dev/stderr", rootfs.join("tmp/errlog")).unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .fs_mount("/dev", "/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let result = policy
        .clone()
        
        .run(&["rootfs-helper", "write-fd-link", "/tmp/errlog", "MAGIC_MARKER"])
        .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "open of errlog -> /dev/stderr -> /proc/self/fd/2 must succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            // The write lands on the child's own stderr via the magic link.
            assert!(
                r.stderr_str().unwrap_or("").contains("MAGIC_MARKER"),
                "marker must reach the child's stderr through the magic link, stderr: {:?}",
                r.stderr_str()
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// The magic-link write again, but bounded: a regression has to surface as a
/// red assertion, never as a hang.
///
/// The symlink chain lands on the sandbox's own `/proc/self/fd/2`, so the
/// descriptor the mediator resolves is that child's stderr **pipe** — a
/// descriptor with no size. The byte watch used to register it anyway *and keep
/// its own duplicate*, which held the capture pipe's write end open after the
/// child exited: `run()` then drained a pipe that could never reach EOF and
/// never returned (2026-09-22 — the unbounded case above hung the whole
/// `core_integ` suite from this). Every assertion here is reached only if the
/// run comes back.
#[tokio::test]
async fn a_magic_link_write_returns_instead_of_pinning_the_capture_pipe() {
    let rootfs = build_test_rootfs("magic-fd-bounded");
    std::os::unix::fs::symlink("/dev/stderr", rootfs.join("tmp/errlog")).unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .fs_mount("/dev", "/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let run = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        policy.clone().run(&[
            "rootfs-helper",
            "write-fd-link",
            "/tmp/errlog",
            "BOUNDED_MARKER",
        ]),
    )
    .await
    .expect("the run must return: a write to the sandbox's own stdio is not a file to watch")
    .expect("run");

    assert!(run.success(), "stderr: {}", run.stderr_str().unwrap_or(""));
    assert!(
        run.stderr_str().unwrap_or("").contains("BOUNDED_MARKER"),
        "marker must reach the child's stderr through the magic link, stderr: {:?}",
        run.stderr_str()
    );

    cleanup_rootfs(&rootfs);
}

/// echo hello > /tmp/test.txt && cat /tmp/test.txt works, file appears in rootfs/tmp
#[tokio::test]
async fn test_chroot_write_file() {
    let rootfs = build_test_rootfs("write-file");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "sh", "-c", "echo hello > /tmp/test.txt && cat /tmp/test.txt"],
    )
    .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert_eq!(stdout, "hello", "cat should output hello, got: {}", stdout);
            // File should appear in rootfs/tmp (since /tmp inside chroot maps to rootfs/tmp)
            let real_path = rootfs.join("tmp/test.txt");
            assert!(
                real_path.exists(),
                "test.txt should exist at {}",
                real_path.display()
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// Directory opens under chroot + COW must stay inside the chroot.
#[tokio::test]
async fn test_chroot_cow_directory_open_stays_in_rootfs() {
    let rootfs = build_test_rootfs("cow-dir-open");
    let tmp_dir = rootfs.join("tmp");

    fs::write(rootfs.join("tmp/rootfs-only.txt"), "rootfs").unwrap();

    let host_marker = std::env::temp_dir().join(format!(
        "sandlock-host-marker-{}",
        std::process::id()
    ));
    fs::write(&host_marker, "host").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "ls", "/tmp"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "ls /tmp should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert!(
                stdout.contains("rootfs-only.txt"),
                "expected to see rootfs file in /tmp, got: {}",
                stdout
            );
            assert!(
                !stdout.contains(host_marker.file_name().unwrap().to_string_lossy().as_ref()),
                "host /tmp leaked into chroot listing: {}",
                stdout
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    let _ = fs::remove_file(&host_marker);
    cleanup_rootfs(&rootfs);
}

/// chroot + COW with BranchAction::Abort discards writes
#[tokio::test]
async fn test_chroot_with_cow() {
    let rootfs = build_test_rootfs("cow");
    let tmp_dir = rootfs.join("tmp");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "sh", "-c", "echo cow-test > /tmp/cow.txt"],
    )
    .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            // With abort, file should NOT exist
            let cow_file = tmp_dir.join("cow.txt");
            assert!(
                !cow_file.exists(),
                "cow.txt should not exist after abort, but found at {}",
                cow_file.display()
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// A file deleted in the COW branch (a whiteout) must return ENOENT on a
/// read-open under CHROOT mode — the sync `handle_open` path. Before the fix,
/// `handle_open` returned `Ok(None)` for the whiteout and `chroot/dispatch.rs`
/// fell through to `openat2_in_root` on the still-present lower file, leaking the
/// pre-delete bytes. This is the chroot-mode sibling of the async
/// `test_seccomp_cow_read_deleted_file_is_enoent`, and it exercises the real
/// dispatch arm (not just the branch object): `cat` issues a bare
/// `open(O_RDONLY)` with no preceding `stat` (rootfs-helper.c), so it drives the
/// open path rather than short-circuiting on the (correct) stat ENOENT.
#[tokio::test]
async fn test_chroot_cow_read_deleted_file_is_enoent() {
    let rootfs = build_test_rootfs("cow-read-deleted");
    let tmp_dir = rootfs.join("tmp");
    // Seed the LOWER file with sentinel content that must never leak.
    fs::write(tmp_dir.join("secret.txt"), "PREDELETE").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // `rm` marks the file deleted in the branch (whiteout); `cat` then
    // bare-opens it in the same cage/branch. With the fix the open returns
    // ENOENT and nothing is printed; without it the untouched lower "PREDELETE"
    // bytes leak to stdout. (rootfs-helper's `sh -c` dispatches applets
    // in-process, so `rm` and `cat` share one COW branch.)
    let result = policy
        .clone()
        
        .run(&["rootfs-helper", "sh", "-c", "rm /tmp/secret.txt; cat /tmp/secret.txt"])
        .await;
    match result {
        Ok(r) => {
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert!(
                !stdout.contains("PREDELETE"),
                "pre-delete lower bytes leaked through the chroot read path (stdout: {:?})",
                stdout
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// readlink /proc/self/root returns /
#[tokio::test]
async fn test_chroot_proc_self_root() {
    let rootfs = build_test_rootfs("proc-self-root");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "readlink", "/proc/self/root"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "readlink should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert_eq!(
                stdout, "/",
                "readlink /proc/self/root should return /, got: {}",
                stdout
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// Writing to /tmp should fail when only fs_read is granted (no fs_write("/tmp"))
#[tokio::test]
async fn test_chroot_write_denied_without_fs_write() {
    let rootfs = build_test_rootfs("write-denied");

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .fs_read("/tmp")
        // Deliberately NO fs_write("/tmp")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "sh", "-c", "echo denied > /tmp/should-fail.txt"],
    )
    .await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "write should fail without fs_write, but got exit=0"
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// execve inside chroot with fs_readable=["/"] should work — regression test
/// for a bug where the seccomp path rewrite truncated /proc/self/fd/N when
/// the original path buffer was shorter than the replacement string.
#[tokio::test]
async fn test_chroot_exec_with_root_readable() {
    let rootfs = build_test_rootfs("exec-root-readable");

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .fs_read("/")
        .build()
        .unwrap();

    // Use /bin/rootfs-helper which goes through the bin -> usr/bin symlink
    let result = policy.clone().run(&["/bin/rootfs-helper", "echo", "chroot-exec-ok"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "/bin/rootfs-helper should succeed with fs_read(\"/\"), exit={:?} stderr: {} stdout: {}",
                r.code(), r.stderr_str().unwrap_or(""), r.stdout_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert!(
                stdout.contains("chroot-exec-ok"),
                "should print chroot-exec-ok, got: {}",
                stdout
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// fs_deny should override fs_read inside chroot using virtual paths.
#[tokio::test]
async fn test_chroot_fs_deny_blocks_virtual_path() {
    let rootfs = build_test_rootfs("fs-deny");

    fs::write(rootfs.join("etc/hostname"), "sandlock-test-host").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .fs_deny("/etc/hostname")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "cat", "/etc/hostname"]).await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "cat /etc/hostname should fail when fs_deny overrides fs_read, exit={:?} stdout={}",
                r.code(),
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// Reading /etc/hostname should fail when /etc is not in fs_readable
#[tokio::test]
async fn test_chroot_read_denied_without_fs_read() {
    let rootfs = build_test_rootfs("read-denied");

    // Create a hostname file in the rootfs
    fs::write(rootfs.join("etc/hostname"), "sandlock-test-host").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        // Deliberately NO fs_read("/etc")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "cat", "/etc/hostname"]).await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "cat /etc/hostname should fail without fs_read(\"/etc\"), exit={:?} stdout={}",
                r.code(),
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// fs_mount maps a host directory to a virtual path inside the chroot.
/// A file written to the host directory should be readable at the virtual path.
#[tokio::test]
async fn test_fs_mount_read_write() {
    let rootfs = build_test_rootfs("fs-mount-rw");

    // Create a /work directory inside the rootfs so the mount point exists
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let work_dir = temp_dir("fs-mount-work");

    // Write a test file in the host directory that will be mounted at /work
    fs::write(work_dir.join("input.txt"), "hello mount").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/tmp")
        .fs_write("/tmp")
        .fs_read("/work")
        .fs_write("/work")
        .fs_mount("/work", &work_dir)
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "cat", "/work/input.txt"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "cat /work/input.txt failed: exit={:?} stderr={}",
                r.code(),
                r.stderr_str().unwrap_or("")
            );
            assert_eq!(
                r.stdout_str().unwrap_or("").trim(),
                "hello mount",
                "expected 'hello mount', got: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("fs_mount test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&rootfs);
    let _ = fs::remove_dir_all(&work_dir);
}

/// When the chroot image ships its own `/etc/hosts`, the synthetic file
/// the sandbox sees should be seeded from the image's content (so any
/// private-registry / internal-service entries the image baked in
/// survive virtualization) — with loopback entries added only if the
/// image didn't already provide them.
#[tokio::test]
async fn test_chroot_etc_hosts_seeded_from_image() {
    let rootfs = build_test_rootfs("etc-hosts-image-seed");
    // Put a hosts file in the image that has its own entry but is
    // missing both loopback families on purpose.
    fs::write(
        rootfs.join("etc/hosts"),
        "10.0.0.5 internal.registry.local\n",
    )
    .unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "cat", "/etc/hosts"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "cat /etc/hosts should succeed inside chroot, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert!(
                stdout.contains("10.0.0.5 internal.registry.local"),
                "image's /etc/hosts entry missing: {stdout}"
            );
            assert!(
                stdout.contains("127.0.0.1 localhost"),
                "v4 loopback should be injected for the image: {stdout}"
            );
            assert!(
                stdout.contains("::1 localhost"),
                "v6 loopback should be injected for the image: {stdout}"
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// When the image already ships loopback entries, the synthesizer must
/// not duplicate them — the sandbox should see exactly the image's view
/// of localhost, not two copies of it.
#[tokio::test]
async fn test_chroot_etc_hosts_no_duplicate_loopback() {
    let rootfs = build_test_rootfs("etc-hosts-no-dup");
    fs::write(
        rootfs.join("etc/hosts"),
        "127.0.0.1 localhost\n::1 localhost\n10.0.0.5 svc.local\n",
    )
    .unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "cat", "/etc/hosts"]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "cat /etc/hosts should succeed");
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert_eq!(
                stdout.matches("127.0.0.1 localhost").count(),
                1,
                "v4 loopback duplicated: {stdout}"
            );
            assert_eq!(
                stdout.matches("::1 localhost").count(),
                1,
                "v6 loopback duplicated: {stdout}"
            );
            assert!(stdout.contains("10.0.0.5 svc.local"), "image entry missing: {stdout}");
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// `max_open_files` under `chroot`: the cap applies as usual, and the *startup
/// floor* the emulated shape had is gone with it.
///
/// N14 S5 (2026-10-04): under the emulated root the supervisor had to inject
/// the exec fd above the guest's own table, so a cap too low to hold that
/// injection answered `EIO` and exited 127 -- a floor the caller could not see
/// in the policy. The real root hands the exec to the kernel, so the only floor
/// left is the sandbox's own. Both halves are pinned here: a workable cap
/// changes nothing, and a cap of three descriptors no longer fails the exec.
#[tokio::test]
async fn test_max_open_files_chroot_has_no_injected_exec_fd_floor() {
    let rootfs = build_test_rootfs("max-open-files");

    // A workable cap changes nothing about the run.
    let ok = minimal_exec_policy(&rootfs)
        .max_open_files(64)
        .build()
        .unwrap()
        .run(&["rootfs-helper", "true"])
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the chroot sandbox must be creatable (N14 S5: the real root is \
                 the only shape): {e}"
            )
        });
    assert!(
        ok.success(),
        "a 64-descriptor cap should still run under chroot, stderr: {}",
        ok.stderr_str().unwrap_or("")
    );

    // Three descriptors: enough to exec through the kernel (the old shape
    // needed an injected fd above this, and answered EIO without one).
    let tiny = minimal_exec_policy(&rootfs)
        .max_open_files(3)
        .build()
        .unwrap()
        .run(&["rootfs-helper", "true"])
        .await
        .unwrap();
    assert_eq!(
        tiny.code(),
        Some(0),
        "the real root injects no exec fd, so a 3-descriptor cap must run, stderr: {}",
        tiny.stderr_str().unwrap_or("")
    );
    assert_eq!(tiny.stderr_str().unwrap_or(""), "", "nothing on stderr");

    cleanup_rootfs(&rootfs);
}

/// A dense parent fd table must not raise the chroot startup floor.
///
/// Regression test: `close_fds_above` used to enumerate `/proc/self/fd`, which
/// the already-installed confinement denies under chroot, so it silently closed
/// nothing and the child carried the parent's whole fd table into exec. The
/// injected exec fd then had to land above all of them, and a parent holding
/// descriptors past the cap (a busy parallel test run) turned the exec into
/// EMFILE-reported-as-EIO. The floor must depend on the sandbox, not on how
/// many files the embedding process happens to have open.
#[tokio::test]
async fn test_max_open_files_chroot_ignores_parent_fd_density() {
    let rootfs = build_test_rootfs("max-open-files-density");

    // Occupy fd numbers well past the cap for the duration of the spawn.
    let _hold: Vec<fs::File> = (0..80)
        .map(|_| fs::File::open("/dev/null").expect("open /dev/null"))
        .collect();

    let result = minimal_exec_policy(&rootfs)
        .max_open_files(64)
        .build()
        .unwrap()
        .run(&["rootfs-helper", "true"])
        .await;
    match result {
        Ok(r) => assert!(
            r.success(),
            "a 64-descriptor cap must not fail just because the parent holds \
             more fds than the cap, stderr: {}",
            r.stderr_str().unwrap_or("")
        ),
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// AT_SYMLINK_FOLLOW asks for the inode behind a symlink, and the supervisor
/// performs the link itself from outside the chroot. If the source is resolved
/// by walking its parent and appending the last component, a symlink whose
/// target does not exist inside the root comes back as the symlink itself, and
/// the host kernel then resolves it a second time against the real root: the
/// guest picks any host path it likes and gets a hard link to it inside the
/// sandbox, readable and writable.
#[tokio::test]
async fn test_chroot_hardlink_follow_cannot_reach_a_host_file() {
    use std::os::unix::fs::MetadataExt;

    let rootfs = build_test_rootfs("hardlink-follow-escape");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    // Outside the rootfs and outside every grant, but on the same filesystem,
    // so a hard link to it is physically possible and the refusal below is the
    // only thing standing in the way.
    let host_dir = temp_dir("hardlink-follow-host");
    let host_secret = host_dir.join("host-only.txt");
    fs::write(&host_secret, "HOST-ONLY").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/work")
        .fs_write("/work")
        .build()
        .unwrap();

    let bait = host_secret.to_string_lossy().to_string();
    let planted = match policy
        .clone()
        .run(&["rootfs-helper", "ln", "-s", &bait, "/work/bait"])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            cleanup_rootfs(&rootfs);
            let _ = fs::remove_dir_all(&host_dir);
            panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}");
        }
    };
    // A symlink is just a string, so planting it is allowed; the target is
    // meaningless inside the root. Without this the refusal below would prove
    // nothing.
    assert!(
        planted.success(),
        "planting the symlink should be allowed, exit={:?} stderr={}",
        planted.code(),
        planted.stderr_str().unwrap_or("")
    );

    let followed = policy
        .clone()
        .run(&["rootfs-helper", "linkat", "/work/bait", "/work/pwn", "follow"])
        .await
        .expect("second run should launch once the first did");
    assert!(
        !followed.success(),
        "following a symlink out of the root should be refused, exit={:?} stderr={}",
        followed.code(),
        followed.stderr_str().unwrap_or("")
    );
    // The sandbox says the same thing about a target that is missing and one
    // that lives outside the root: from inside, the outside does not exist.
    assert!(
        followed
            .stderr_str()
            .unwrap_or("")
            .contains("No such file or directory"),
        "the refusal should report the target as absent, stderr={}",
        followed.stderr_str().unwrap_or("")
    );
    assert_eq!(
        fs::metadata(&host_secret).unwrap().nlink(),
        1,
        "the host file gained a second name inside the sandbox"
    );

    let read_back = policy
        .clone()
        .run(&["rootfs-helper", "cat", "/work/pwn"])
        .await
        .expect("third run should launch once the first did");
    assert!(
        !read_back.stdout_str().unwrap_or("").contains("HOST-ONLY"),
        "host file contents were read from inside the sandbox: {}",
        read_back.stdout_str().unwrap_or("")
    );

    // The write side of the same escape: the destination name is writable by
    // policy, so this run succeeds either way. What it proves is which inode
    // that name refers to.
    let write_back = policy
        .clone()
        .run(&["rootfs-helper", "write", "/work/pwn", "OWNED"])
        .await
        .expect("fourth run should launch once the first did");
    assert!(
        write_back.success(),
        "writing the destination name should be allowed by policy, exit={:?} stderr={}",
        write_back.code(),
        write_back.stderr_str().unwrap_or("")
    );
    assert_eq!(
        fs::read_to_string(&host_secret).unwrap().trim(),
        "HOST-ONLY",
        "a write inside the sandbox reached the host file, so the link landed \
         on the host inode"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&host_dir);
}

/// The other side of the same branch: a symlink whose target does resolve
/// inside the root still links the target's inode, not the symlink. Pins that
/// the confined resolution above did not turn AT_SYMLINK_FOLLOW into a blanket
/// refusal, and that the flag is honoured rather than quietly dropped.
#[tokio::test]
async fn test_chroot_hardlink_follow_links_the_target_inode() {
    use std::os::unix::fs::MetadataExt;

    let rootfs = build_test_rootfs("hardlink-follow-target");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/work")
        .fs_write("/work")
        .build()
        .unwrap();

    let setup = match policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "write /work/orig.txt PAYLOAD && ln -s orig.txt /work/link",
        ])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            cleanup_rootfs(&rootfs);
            panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}");
        }
    };
    assert!(
        setup.success(),
        "creating the file and the symlink should succeed, exit={:?} stderr={}",
        setup.code(),
        setup.stderr_str().unwrap_or("")
    );

    let linked = policy
        .clone()
        .run(&["rootfs-helper", "linkat", "/work/link", "/work/alias.txt", "follow"])
        .await
        .expect("second run should launch once the first did");
    assert!(
        linked.success(),
        "following a symlink that resolves inside the root should be allowed, \
         exit={:?} stderr={}",
        linked.code(),
        linked.stderr_str().unwrap_or("")
    );

    let target = rootfs.join("work/orig.txt");
    let alias = rootfs.join("work/alias.txt");
    assert!(
        !fs::symlink_metadata(&alias).unwrap().file_type().is_symlink(),
        "the flag was dropped: the new name copied the symlink instead of \
         linking its target"
    );
    assert_eq!(
        fs::metadata(&target).unwrap().ino(),
        fs::metadata(&alias).unwrap().ino(),
        "the new name should be a second name for the target's inode"
    );

    cleanup_rootfs(&rootfs);
}

/// A hard link hands out a second name for an inode, so after link(2) the
/// authority over that inode is the union of the policy on both names. Under
/// chroot the supervisor performs the link itself, so nothing downstream can
/// re-check it: if only the destination is gated, a guest can name a file it
/// may read but not write under a writable prefix and then write to it there.
///
/// Read-only mount flavour: /ro is readable (so the source resolves) but never
/// writable, /rw is writable.
#[tokio::test]
async fn test_chroot_hardlink_cannot_escalate_read_only_mount() {
    let rootfs = build_test_rootfs("hardlink-ro-mount");
    fs::create_dir_all(rootfs.join("ro")).unwrap();
    fs::create_dir_all(rootfs.join("rw")).unwrap();

    // Both host directories sit under the same temp base and therefore on the
    // same filesystem. A cross-filesystem pair would fail with EXDEV and the
    // escalation could not be attempted at all, making the test vacuous.
    let ro_dir = temp_dir("hardlink-ro-src");
    let rw_dir = temp_dir("hardlink-ro-dst");
    let secret = ro_dir.join("secret.txt");
    fs::write(&secret, "SECRET").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/ro")
        .fs_read("/rw")
        .fs_write("/rw")
        .fs_mount_ro("/ro", &ro_dir)
        .fs_mount("/rw", &rw_dir)
        .build()
        .unwrap();

    let direct = match policy
        .clone()
        .run(&["rootfs-helper", "write", "/ro/secret.txt", "PWNED"])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            cleanup_rootfs(&rootfs);
            let _ = fs::remove_dir_all(&ro_dir);
            let _ = fs::remove_dir_all(&rw_dir);
            panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}");
        }
    };
    // Baseline: the policy grants no write on the source name. Without this
    // the link denial below would prove nothing.
    assert!(
        !direct.success(),
        "writing a read-only mount directly should fail, exit={:?}",
        direct.code()
    );

    let linked = policy
        .clone()
        .run(&["rootfs-helper", "ln", "/ro/secret.txt", "/rw/alias"])
        .await
        .expect("second run should launch once the first did");
    assert!(
        !linked.success(),
        "hard-linking a read-only mount into a writable mount should be \
         refused, exit={:?} stderr={}",
        linked.code(),
        linked.stderr_str().unwrap_or("")
    );

    // The consequence, spelled out: whatever now lives at the destination name
    // must not be the protected inode. Writing through it is allowed by policy
    // (/rw is writable), so this run must succeed on its own terms; if it ever
    // stops doing so, the host-side check below would hold for a reason that
    // has nothing to do with the escalation.
    let through_alias = policy
        .clone()
        .run(&["rootfs-helper", "write", "/rw/alias", "PWNED"])
        .await
        .expect("third run should launch once the first did");
    assert!(
        through_alias.success(),
        "the escalation attempt itself must run, exit={:?} stderr={}",
        through_alias.code(),
        through_alias.stderr_str().unwrap_or("")
    );
    assert_eq!(
        fs::read_to_string(&secret).unwrap().trim(),
        "SECRET",
        "a write to the destination name reached the read-only mount, so the \
         link aliased the protected inode"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&ro_dir);
    let _ = fs::remove_dir_all(&rw_dir);
}

/// fs_deny flavour of the same escalation: aliasing a denied file needs write
/// authority on the denied name, which fs_deny withholds, so the chain never
/// starts. Both the read and the write escalation are checked.
#[tokio::test]
async fn test_chroot_hardlink_cannot_alias_denied_path() {
    let rootfs = build_test_rootfs("hardlink-fs-deny");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let work_dir = temp_dir("hardlink-deny-work");
    let secret = work_dir.join("secret.txt");
    fs::write(&secret, "SECRET").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/work")
        .fs_write("/work")
        .fs_mount("/work", &work_dir)
        .fs_deny("/work/secret.txt")
        .build()
        .unwrap();

    let direct = match policy
        .clone()
        .run(&["rootfs-helper", "cat", "/work/secret.txt"])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            cleanup_rootfs(&rootfs);
            let _ = fs::remove_dir_all(&work_dir);
            panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}");
        }
    };
    // Baseline: fs_deny wins over the surrounding writable mount.
    assert!(
        !direct.success(),
        "fs_deny should block reading the file by its own name, exit={:?} stdout={}",
        direct.code(),
        direct.stdout_str().unwrap_or("")
    );

    let linked = policy
        .clone()
        .run(&["rootfs-helper", "ln", "/work/secret.txt", "/work/alias.txt"])
        .await
        .expect("second run should launch once the first did");
    assert!(
        !linked.success(),
        "hard-linking a denied path to an allowed name should be refused, \
         exit={:?} stderr={}",
        linked.code(),
        linked.stderr_str().unwrap_or("")
    );

    let via_alias = policy
        .clone()
        .run(&["rootfs-helper", "cat", "/work/alias.txt"])
        .await
        .expect("third run should launch once the first did");
    assert!(
        !via_alias.stdout_str().unwrap_or("").contains("SECRET"),
        "the denied file became readable under a second name: {}",
        via_alias.stdout_str().unwrap_or("")
    );

    // /work is writable, so this run must succeed whichever inode the second
    // name turns out to hold. Asserting that keeps the host-side check below
    // from passing because the write never happened.
    let through_alias = policy
        .clone()
        .run(&["rootfs-helper", "write", "/work/alias.txt", "PWNED"])
        .await
        .expect("fourth run should launch once the first did");
    assert!(
        through_alias.success(),
        "the escalation attempt itself must run, exit={:?} stderr={}",
        through_alias.code(),
        through_alias.stderr_str().unwrap_or("")
    );
    assert_eq!(
        fs::read_to_string(&secret).unwrap().trim(),
        "SECRET",
        "a write to the second name reached the denied inode"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&work_dir);
}

/// The other side of the predicate: when the policy grants writes on both
/// names the link must still go through. Uses linkat(2) directly so the *at
/// entry point is exercised alongside the legacy link(2) the other tests take.
#[tokio::test]
async fn test_chroot_hardlink_allowed_when_both_sides_writable() {
    use std::os::unix::fs::MetadataExt;

    let rootfs = build_test_rootfs("hardlink-allowed");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let work_dir = temp_dir("hardlink-allowed-work");
    fs::write(work_dir.join("orig.txt"), "payload").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/work")
        .fs_write("/work")
        .fs_mount("/work", &work_dir)
        .build()
        .unwrap();

    // A probe run carries the skip convention, so a host that cannot launch
    // the sandbox at all is the only thing it can hide. The run under test
    // then has to launch, or this test would be the one place where an
    // over-denying gate could ship unnoticed.
    if let Err(e) = policy.clone().run(&["rootfs-helper", "true"]).await {
        cleanup_rootfs(&rootfs);
        let _ = fs::remove_dir_all(&work_dir);
        panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}");
    }

    let linked = policy
        .clone()
        .run(&["rootfs-helper", "linkat", "/work/orig.txt", "/work/alias.txt"])
        .await
        .expect("second run should launch once the probe did");
    assert!(
        linked.success(),
        "linking within a writable mount should be allowed, exit={:?} stderr={}",
        linked.code(),
        linked.stderr_str().unwrap_or("")
    );
    let orig = fs::metadata(work_dir.join("orig.txt")).unwrap();
    let alias = fs::metadata(work_dir.join("alias.txt")).unwrap();
    assert_eq!(
        orig.ino(),
        alias.ino(),
        "the second name should be a hard link, not a copy"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&work_dir);
}

/// The gate has to judge the inode the link will name, which under a mount is
/// not the name the child spelled: the mount resolver reports the requested
/// path back, so a symlink to a denied file inside the mount would be checked
/// as the symlink's own (allowed) name. AT_SYMLINK_FOLLOW is the spelling that
/// reaches that branch, and it needs no knowledge of any host path: a relative
/// symlink next to the target is enough.
#[tokio::test]
async fn test_chroot_hardlink_follow_cannot_alias_a_denied_path_under_a_mount() {
    let rootfs = build_test_rootfs("hardlink-follow-deny");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let work_dir = temp_dir("hardlink-follow-deny-work");
    let secret = work_dir.join("secret.txt");
    fs::write(&secret, "SECRET").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/work")
        .fs_write("/work")
        .fs_mount("/work", &work_dir)
        .fs_deny("/work/secret.txt")
        .build()
        .unwrap();

    let planted = match policy
        .clone()
        .run(&["rootfs-helper", "ln", "-s", "secret.txt", "/work/s"])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            cleanup_rootfs(&rootfs);
            let _ = fs::remove_dir_all(&work_dir);
            panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}");
        }
    };
    // fs_deny covers the file, not the name of a symlink beside it, so
    // planting the bait is allowed and the refusal below is about the target.
    assert!(
        planted.success(),
        "planting the symlink should be allowed, exit={:?} stderr={}",
        planted.code(),
        planted.stderr_str().unwrap_or("")
    );

    let followed = policy
        .clone()
        .run(&["rootfs-helper", "linkat", "/work/s", "/work/alias.txt", "follow"])
        .await
        .expect("second run should launch once the first did");
    assert!(
        !followed.success(),
        "following a symlink to a denied file should be refused, exit={:?} stderr={}",
        followed.code(),
        followed.stderr_str().unwrap_or("")
    );

    let via_alias = policy
        .clone()
        .run(&["rootfs-helper", "cat", "/work/alias.txt"])
        .await
        .expect("third run should launch once the first did");
    assert!(
        !via_alias.stdout_str().unwrap_or("").contains("SECRET"),
        "the denied file became readable under a second name: {}",
        via_alias.stdout_str().unwrap_or("")
    );

    let through_alias = policy
        .clone()
        .run(&["rootfs-helper", "write", "/work/alias.txt", "PWNED"])
        .await
        .expect("fourth run should launch once the first did");
    assert!(
        through_alias.success(),
        "the escalation attempt itself must run, exit={:?} stderr={}",
        through_alias.code(),
        through_alias.stderr_str().unwrap_or("")
    );
    assert_eq!(
        fs::read_to_string(&secret).unwrap().trim(),
        "SECRET",
        "a write to the second name reached the denied inode"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&work_dir);
}

/// A copy-on-write branch stages writes in an upper layer and, under
/// BranchAction::Abort, throws them away. A hard link cannot be half staged:
/// with one name inside the workdir and the other below it, there is nothing
/// to stage, and performing the link for real would create the name in the
/// pristine workdir instead. EXDEV is the kernel's own word for a link that
/// cannot span two sides.
#[tokio::test]
async fn test_chroot_hardlink_into_a_branch_is_refused() {
    let rootfs = build_test_rootfs("hardlink-branch-in");
    let tmp_dir = rootfs.join("tmp");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/work")
        .fs_write("/work")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "write /work/a.txt LEAKED && ln /work/a.txt /tmp/pulled-in.txt",
        ])
        .await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "a hard link into the branch should be refused, exit={:?} stderr={}",
                r.code(),
                r.stderr_str().unwrap_or("")
            );
            // The helper prints `ln: <path>: <strerror(EXDEV)>`, and that text
            // is the libc's: glibc spells it "Invalid cross-device link", musl
            // spells it "Cross-device link". The aarch64 lane cross-builds the
            // helper statically with zigcc, which only offers a musl static
            // libc (zig refuses `-static` against glibc), so pin the phrase and
            // not one libc's wording.
            let stderr = r.stderr_str().unwrap_or_default();
            assert!(
                stderr.to_lowercase().contains("cross-device link"),
                "the refusal should read as a cross-device link, stderr={stderr}"
            );
            assert!(
                !tmp_dir.join("pulled-in.txt").exists(),
                "the branch was aborted, yet the link landed in the workdir itself"
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// The other direction, and the damaging one: a name taken out of the workdir
/// aliases the *lower* inode, so a write through it edits the very file the
/// branch promised to leave alone, and the edit outlives the abort.
#[tokio::test]
async fn test_chroot_hardlink_out_of_a_branch_is_refused() {
    let rootfs = build_test_rootfs("hardlink-branch-out");
    let tmp_dir = rootfs.join("tmp");
    fs::create_dir_all(rootfs.join("work")).unwrap();
    fs::write(tmp_dir.join("orig.txt"), "ORIGINAL").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/work")
        .fs_write("/work")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "ln /tmp/orig.txt /work/alias.txt && write /work/alias.txt OVERWRITTEN",
        ])
        .await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "a hard link out of the branch should be refused, exit={:?} stderr={}",
                r.code(),
                r.stderr_str().unwrap_or("")
            );
            assert!(
                !rootfs.join("work/alias.txt").exists(),
                "the second name was created outside the branch"
            );
            assert_eq!(
                fs::read_to_string(tmp_dir.join("orig.txt")).unwrap().trim(),
                "ORIGINAL",
                "the aborted branch still edited the file it was staging over"
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// Both names inside the workdir is the case the branch can stage, so it must
/// keep working, and it must stay in the branch: after an abort neither the
/// second name nor the copy of the first is left in the workdir.
#[tokio::test]
async fn test_chroot_hardlink_within_a_branch_stays_in_the_branch() {
    let rootfs = build_test_rootfs("hardlink-branch-within");
    let tmp_dir = rootfs.join("tmp");
    fs::write(tmp_dir.join("orig.txt"), "ORIGINAL").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "ln /tmp/orig.txt /tmp/alias.txt && cat /tmp/alias.txt",
        ])
        .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "a link between two names inside the workdir should be allowed, \
                 exit={:?} stderr={}",
                r.code(),
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stdout_str().unwrap_or("").contains("ORIGINAL"),
                "the second name should read as the file it links, stdout={}",
                r.stdout_str().unwrap_or("")
            );
            assert!(
                !tmp_dir.join("alias.txt").exists(),
                "the aborted branch left its second name in the workdir"
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// A file deleted in the branch is a whiteout: the lower entry is still on
/// disk with its pre-delete bytes. Linking it must answer ENOENT rather than
/// resurrect it, which is the same rule the read-open path already follows.
#[tokio::test]
async fn test_chroot_hardlink_to_a_file_deleted_in_the_branch_is_enoent() {
    let rootfs = build_test_rootfs("hardlink-branch-whiteout");
    let tmp_dir = rootfs.join("tmp");
    fs::write(tmp_dir.join("orig.txt"), "PREDELETE").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "rm /tmp/orig.txt && ln /tmp/orig.txt /tmp/alias.txt",
        ])
        .await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "linking a file the branch deleted should be refused, exit={:?} stderr={}",
                r.code(),
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stderr_str().unwrap_or("").contains("No such file or directory"),
                "the deleted file should read as absent, stderr={}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                !tmp_dir.join("alias.txt").exists(),
                "the pre-delete inode came back under a second name in the workdir"
            );
        }
        Err(e) => panic!("the chroot sandbox must be creatable (N14 S5: the real root is the only shape): {e}"),
    }

    cleanup_rootfs(&rootfs);
}

/// The invariant the writable-rootfs route rests on, at the write call site:
/// **a path the branch owns is served by the branch, never by a host operation
/// on the lower.**
///
/// `symlinkat` is where that broke. The branch declines a symlink with an
/// absolute (or `..`) target by design — its link text would name something
/// outside the branch's own view — and the handler used to treat "declined"
/// as "not COW's business" and fall through to `libc::symlink` on the resolved
/// host path. The lower here *is* the shared image rootfs, so the entry was
/// created there for real: a write into the cache every tenant shares.
///
/// The shape is the production one, minimally: the branch's workdir is the
/// whole rootfs and the policy grants **no** write at all, so both writes below
/// are admitted by the branch's grant alone (the policy would refuse them).
/// The stageable half is the control — the grant still serves what the branch
/// can stage — and both dispositions are `Keep` so the test can look inside the
/// upper afterwards: `Abort` deletes the only evidence of *where* the write
/// went, and the run ends on a refusal (`on_error`), so `on_exit` alone would
/// not keep it.
///
/// One cage, one branch: the read-back has to happen in the same run as the
/// write, since a second `run` would start a fresh branch with an empty upper.
#[tokio::test]
async fn test_chroot_cow_owned_writes_never_land_on_the_lower() {
    let rootfs = build_test_rootfs("cow-owned-lower");
    fs::create_dir_all(rootfs.join("usr/local")).unwrap();
    let storage = temp_dir("cow-owned-lower-upper");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .workdir(&rootfs)
        .fs_storage(&storage)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            // Stage a link the branch can serve, read it back, then ask for the
            // arm it declines (an absolute target) — all in one cage.
            "ln -s rel-target /usr/local/rel-link && \
             readlink /usr/local/rel-link && \
             ln -s /etc/os-release /usr/local/abs-link",
        ])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    // The staged half: the branch served it, so the name reads back through the
    // branch — and the lower has no such name, which is what makes the read a
    // read of the *upper*.
    assert_eq!(
        result.stdout_str().unwrap_or_default(),
        "rel-target",
        "the staged symlink must read back through the branch, stderr={:?}",
        result.stderr_str()
    );
    // The declined half: the mediator's own refusal (EPERM), and it is the last
    // command of the chain, so it is also the run's exit code.
    assert_eq!(
        result.code(),
        Some(1),
        "an owned path the branch declines must be refused, stderr={:?}",
        result.stderr_str()
    );

    let branch_dir = fs::read_dir(&storage)
        .expect("the kept branch's storage")
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .expect("the kept branch directory");
    let upper = branch_dir.join("upper");
    assert_eq!(
        fs::read_link(upper.join("usr/local/rel-link")).expect("the staged link lives in the upper"),
        PathBuf::from("rel-target"),
        "a write the branch serves lands in its upper"
    );
    assert!(
        !upper.join("usr/local/abs-link").exists(),
        "a refused symlink must not be staged either"
    );
    assert!(
        !rootfs.join("usr/local/rel-link").exists(),
        "the branch's lower is the shared rootfs and must gain no entry"
    );
    assert!(
        !rootfs.join("usr/local/abs-link").exists(),
        "a refused symlink must not be created on the lower"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&storage);
}

/// A **named** layer is adopted: the tree's carried layer is what the sandbox
/// sees.
///
/// The writable-rootfs route names its layer (`<ws>/.rootfs/layer`) so that a
/// tree restored from a snapshot — or migrated from another node — re-attaches
/// to the layer it already carries: the staged files *and* the whiteouts. The
/// failing behaviour was measured on the lane 2026-10-16: after
/// `Sandbox.create(A.create_snapshot())` the restored sandbox could not see the
/// file A wrote into the rootfs, saw `/etc/hostname` again, and its tree held
/// both the carried layer and a fresh empty one.
#[tokio::test]
async fn test_chroot_cow_a_named_layer_is_adopted_from_the_tree() {
    let rootfs = build_test_rootfs("cow-adopt");
    fs::create_dir_all(rootfs.join("usr/local")).unwrap();
    fs::write(rootfs.join("etc/hostname"), "from-the-image\n").unwrap();
    let storage = temp_dir("cow-adopt-layer");

    // What a previous sandbox left in the tree: one staged file, one whiteout.
    // (`deleted.log` is the fork's own format — one escaped path per line.)
    let layer = storage.join("layer");
    fs::create_dir_all(layer.join("upper/usr/local")).unwrap();
    fs::write(layer.join("upper/usr/local/staged"), "staged\n").unwrap();
    fs::write(layer.join("deleted.log"), "etc/hostname\n").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .workdir(&rootfs)
        .fs_storage(&storage)
        .cow_layer_name("layer")
        .cow_discard(true)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            // The staged file must read back (it lives in the adopted upper) and
            // the whiteouted one must be gone (`;`, so the second command runs
            // even though the first one fails).
            "cat /usr/local/staged ; cat /etc/hostname",
        ])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    assert_eq!(
        result.stdout_str().unwrap_or_default(),
        "staged",
        "the adopted upper is the sandbox's upper; stderr={:?}",
        result.stderr_str()
    );
    assert_eq!(
        result.stderr_str().unwrap_or_default().trim(),
        "cat: /etc/hostname: No such file or directory",
        "the adopted whiteout log is in effect"
    );
    assert_eq!(result.code(), Some(1), "the last command is the failed `cat`");
    // The layer the tree carried is still the only one: nothing was re-minted
    // beside it, and the lower was not touched.
    let entries: Vec<String> = fs::read_dir(&storage)
        .expect("the layer's storage")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec!["layer".to_string()], "one layer, adopted");
    assert_eq!(
        fs::read_to_string(rootfs.join("etc/hostname")).unwrap(),
        "from-the-image\n",
        "the lower keeps its bytes"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&storage);
}

/// The layer's budget is a **named** refusal all the way out to the child.
///
/// `max_disk` bounds what the branch stages, and the writable-rootfs route is
/// `cow_discard` (its lower is the shared image rootfs, so it must never merge).
/// Its layer used to be unbounded: the first thing to notice was the
/// filesystem, whose ENOSPC arrives *inside a copy-up* and surfaces as `EIO`
/// (`BranchError::Operation`), naming nothing. With the cap enforced on a
/// discard branch the child gets `ENOSPC` and the copy-up is refused before it
/// stages anything -- which matters here because a one-byte change to a lower
/// file stages the whole file.
#[tokio::test]
async fn test_chroot_cow_a_write_past_the_layers_budget_is_enospc() {
    let rootfs = build_test_rootfs("cow-quota");
    fs::create_dir_all(rootfs.join("usr/local")).unwrap();
    // 64 KiB in the *lower*: the copy-up is what the 1 KiB budget cannot afford.
    fs::write(rootfs.join("usr/local/big"), vec![0u8; 64 * 1024]).unwrap();
    let storage = temp_dir("cow-quota-upper");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .workdir(&rootfs)
        .fs_storage(&storage)
        .max_disk(sandlock_core::sandbox::ByteSize(1024))
        .cow_discard(true)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&["rootfs-helper", "sh", "-c", "echo x > /usr/local/big"])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    assert_eq!(
        result.stderr_str().unwrap_or_default().trim(),
        "sh: cannot open /usr/local/big: No space left on device",
        "the layer's budget must reach the child as ENOSPC; stdout={:?} code={:?}",
        result.stdout_str(),
        result.code()
    );
    assert_eq!(result.code(), Some(1));

    // The refusal is a reservation: nothing was staged, and the shared lower is
    // untouched.
    assert_eq!(
        fs::metadata(rootfs.join("usr/local/big")).unwrap().len(),
        64 * 1024,
        "the lower file must keep its bytes"
    );
    let branch_dir = fs::read_dir(&storage)
        .expect("the kept branch's storage")
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .expect("the kept branch directory");
    assert!(
        !branch_dir.join("upper/usr/local/big").exists(),
        "a refused copy-up must not be staged"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&storage);
}

#[tokio::test]
async fn test_chroot_cow_a_directory_created_in_the_rootfs_is_usable() {
    // `mkdir X && write into X` is the shape of every install that creates its
    // own directory (`pip install` -> `site-packages/<pkg>/`), and it is the
    // one shape the mediator's *resolve* could not serve: the parent exists
    // only in the branch's upper, while `resolve_in_root_nofollow` walks the
    // parent with `openat2_in_root(chroot_root, …)` -- the shared image rootfs.
    // Measured on the lane 2026-10-16: the write answered ENOENT while the
    // directory was demonstrably in the upper, and the shared lower had nothing.
    let rootfs = build_test_rootfs("cow-newdir");
    fs::create_dir_all(rootfs.join("usr/local")).unwrap();
    let storage = temp_dir("cow-newdir-upper");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .workdir(&rootfs)
        .fs_storage(&storage)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            // Create the directory, write into it, read it back, list it. All
            // four need the parent walked, and all four answered ENOENT before
            // this (the helper's `mkdir` has no `-p`, so the new directory's
            // parent is the lower's own `usr/local`).
            "mkdir /usr/local/cowdir && \
             echo hello > /usr/local/cowdir/f && \
             cat /usr/local/cowdir/f && \
             ls /usr/local/cowdir",
        ])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    assert_eq!(
        result.stdout_str().unwrap_or_default(),
        // "hello" is `cat`'s copy of the file, "f" is `ls`'s listing of the
        // directory the sandbox just created (the helper's `ls` emits no
        // trailing newline).
        "hello\nf",
        "a directory created in the sandbox must be writable, readable and listable; \
         stderr={:?} code={:?}",
        result.stderr_str(),
        result.code()
    );
    assert_eq!(result.code(), Some(0), "stderr={:?}", result.stderr_str());

    // The lower is the shared image rootfs: it gains nothing, and the branch
    // holds the new directory and its file.
    assert!(
        !rootfs.join("usr/local/cowdir").exists(),
        "a directory the sandbox created must not be written into the shared lower"
    );
    let branch_dir = fs::read_dir(&storage)
        .expect("the kept branch's storage")
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .expect("the kept branch directory");
    let upper = branch_dir.join("upper");
    assert!(
        upper.join("usr/local/cowdir").is_dir(),
        "the new directory lives in the branch's upper"
    );
    assert_eq!(
        fs::read_to_string(upper.join("usr/local/cowdir/f"))
            .expect("the file staged in the upper"),
        "hello\n"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&storage);
}

/// The alias is a **read-only** window onto the branch's upper.
///
/// Registering it as a mount is what lets an interpreter open a staged script
/// by path, and `ChrootCtx::can_write` treats "under any mount" as writable
/// unless the mount is declared read-only — so the alias has to be in
/// `fs_mount_ro` as well, or it becomes a second, *writable* spelling of the
/// upper (and an `fs_deny` written for `/sys` would be reachable as
/// `/.u/sys/…`). Measured on the lane 2026-10-16: without the `ro` half,
/// `echo evil > /.u/usr/local/cow-x` returned 0 through the mediator's own open.
#[tokio::test]
async fn test_chroot_cow_the_exec_alias_is_read_only() {
    let rootfs = build_test_rootfs("cow-alias-ro");
    fs::create_dir_all(rootfs.join("usr/local")).unwrap();
    fs::create_dir_all(rootfs.join(".u")).unwrap();
    let storage = temp_dir("cow-alias-ro-upper");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .workdir(&rootfs)
        .fs_storage(&storage)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            // `;` (not `&&`): the refused write must not stop the run, and the
            // last `cat` is what proves the file was left alone.
            "echo hello > /usr/local/cow-x ; \
             cat /.u/usr/local/cow-x ; \
             echo evil > /.u/usr/local/cow-x ; \
             cat /usr/local/cow-x",
        ])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    assert_eq!(
        result.stdout_str().unwrap_or_default(),
        "hello\nhello",
        "the alias reads the staged file and must not have changed it; stderr={:?}",
        result.stderr_str()
    );
    assert_eq!(
        result.stderr_str().unwrap_or_default().trim(),
        "sh: cannot open /.u/usr/local/cow-x: Permission denied",
        "a write through the alias must be refused"
    );
    assert_eq!(result.code(), Some(0), "stderr={:?}", result.stderr_str());
    assert!(
        !rootfs.join("usr/local/cow-x").exists(),
        "the staged file must not be written into the shared lower"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&storage);
}

/// A `#!` script the branch staged must run — which means the *interpreter*
/// must be able to open the script by path.
///
/// The kernel resolves the exec path itself (that is what the alias is for), but
/// a script makes the interpreter open the script **again**, and that open is
/// mediated. The mediator's own view of `/.u/…` is the rootfs's empty `.u`
/// directory, so it answered ENOENT (lane, 2026-10-16: `sh: 0: cannot open
/// /.u/usr/local/cow-s: No such file`). The alias is the fork's own read-only
/// bind of the branch's upper, so the mediator gets it as a **mount**: reads
/// come from the upper, and a write there is refused by the same gate that has
/// always kept the alias read-only (`can_write` is false for `/.u/…` and
/// `cow_owns(<upper>/<rel>)` is false, because the branch's key never names its
/// own storage).
#[tokio::test]
async fn test_chroot_cow_exec_runs_a_script_staged_in_the_upper() {
    let rootfs = build_test_rootfs("cow-script");
    fs::create_dir_all(rootfs.join("usr/local")).unwrap();
    // The alias's mount target: `realroot` binds the upper at `/.u` when it
    // exists, and the worker materializes it with the other mount targets.
    fs::create_dir_all(rootfs.join(".u")).unwrap();
    let storage = temp_dir("cow-script-upper");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .workdir(&rootfs)
        .fs_storage(&storage)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            // The shebang names the helper's own `cat`, so the "interpreter" is
            // a process that opens the script by path — what a real `#!` does,
            // without needing a real dash in this synthetic rootfs (`usr/bin/sh`
            // here is the helper, whose `sh` only takes `-c`).
            // The helper's tokenizer knows `"` (not `'`), so the shebang line
            // has to be quoted that way to land as one argument.
            "echo \"#!/usr/bin/rootfs-helper cat\" > /usr/local/cow-s && \
             chmod 755 /usr/local/cow-s && \
             exec /usr/local/cow-s",
        ])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    assert_eq!(
        result.stdout_str().unwrap_or_default(),
        // The script's one line, as `cat` printed it (`stdout_str` trims the
        // trailing newline the helper's `echo` wrote).
        "#!/usr/bin/rootfs-helper cat",
        "the interpreter must be able to open the staged script by path; \
         stderr={:?} code={:?}",
        result.stderr_str(),
        result.code()
    );
    assert_eq!(result.code(), Some(0), "stderr={:?}", result.stderr_str());
    assert!(
        !rootfs.join("usr/local/cow-s").exists(),
        "the staged script must not be written into the shared lower"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&storage);
}

/// A binary the branch staged into its upper must be executable.
///
/// The real-root shape hands `execve` back to the kernel, which resolves the
/// path in the **rootfs** -- and a file the sandbox wrote lives only in the
/// branch's upper, so `execve` answers ENOENT for a file `cat` reads back
/// (measured on the lane 2026-10-15: `cp` rc=0, `cat` 962920 bytes,
/// `/usr/local/bin/cow-elf: not found`).
///
/// The upper is inside the sandbox's own tree (`<workspace>/.rootfs/<uuid>/upper`
/// -- visible through the `/workspace` mount, which is what design D1 buys), so
/// the mediator can spell it the way the *child* can resolve it and let the
/// kernel exec the very same inode: no copy, no `/proc/self/fd` indirection,
/// and the file the kernel runs is the one the branch staged.
#[tokio::test]
async fn test_chroot_cow_exec_runs_a_binary_staged_in_the_upper() {
    let rootfs = build_test_rootfs("cow-exec-upper");
    fs::create_dir_all(rootfs.join("usr/local/bin")).unwrap();
    fs::create_dir_all(rootfs.join("workspace")).unwrap();
    // The alias the fork bind-mounts the upper at (`realroot::EXEC_ALIAS_DIR`);
    // the worker materializes it with the other mount targets in production.
    fs::create_dir_all(rootfs.join(".u")).unwrap();
    let ws = temp_dir("cow-exec-ws");
    let storage = ws.join(".rootfs");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/workspace")
        .fs_mount("/workspace", &ws)
        .workdir(&rootfs)
        .fs_storage(&storage)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            // Stage a copy of this very binary into the rootfs (the branch
            // keeps it in the upper), make it executable, then exec it. The
            // copy prints its usage on stderr and exits 1 -- which is the
            // proof that it ran, and which only the *kernel* can produce.
            "cat /usr/bin/rootfs-helper > /usr/local/bin/cow-elf && \
             chmod 755 /usr/local/bin/cow-elf && \
             exec /usr/local/bin/cow-elf",
        ])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    assert_eq!(
        result.stderr_str().unwrap_or_default(),
        "usage: rootfs-helper <command> [args...]",
        "the staged binary must be the thing that ran; stdout={:?} code={:?}",
        result.stdout_str(),
        result.code()
    );
    assert_eq!(result.code(), Some(1), "the staged binary's own exit code");

    // ...and it stayed in the branch: the lower is the shared image rootfs.
    assert!(
        !rootfs.join("usr/local/bin/cow-elf").exists(),
        "the staged binary must not be written into the shared lower"
    );
    let branch_dir = fs::read_dir(&storage)
        .expect("the kept branch's storage")
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .expect("the kept branch directory");
    assert!(
        branch_dir.join("upper/usr/local/bin/cow-elf").exists(),
        "the staged binary lives in the branch's upper"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&ws);
}

/// The metadata family has to be served out of the branch too.
///
/// The writable-rootfs route makes the branch's lower the **shared** image
/// rootfs, so the kernel's own answer for a rootfs path is the *lower* one: a
/// file the sandbox just wrote lives only in the upper, and a file it deleted
/// is masked by a whiteout. Measured on the lane (2026-10-15): `stat`/`ls -l`/
/// `test -e` answered ENOENT for a file the same shell had just written with
/// `echo`, while `cat` read it back — i.e. the branch served `open` but not
/// `stat`.
///
/// The chroot stat handlers already resolve through the branch (`cow_resolve`),
/// but N81 gates that whole family on `stat_metadata_mediated`, which is false
/// for a rootfs of the sandbox's own. With a branch that gate is wrong: the
/// kernel would answer for the lower, and the branch is the only thing that can
/// serve the upper. This pins the shape.
///
/// Every probe prints through the helper's buffered `echo`/`access` (`puts`), so
/// stdout's order is the script's; the `cat`s are redirected, and a failure
/// shows up as its own missing marker plus the helper's stderr line.
#[tokio::test]
async fn test_chroot_cow_stat_serves_the_upper_and_the_whiteout() {
    let rootfs = build_test_rootfs("cow-stat");
    fs::create_dir_all(rootfs.join("usr/local")).unwrap();
    fs::write(rootfs.join("etc/cow-victim"), b"victim\n").unwrap();
    let storage = temp_dir("cow-stat-upper");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .workdir(&rootfs)
        .fs_storage(&storage)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            // Write into the rootfs and ask for its metadata. `access` is the
            // probe because the helper's `stat` prints a mode the umask decides
            // and `sh` has no way to filter it; the *lane* reading
            // (`deploy/scripts/acceptance/probe_rootfs_cow.py` plus the manual
            // `stat`/`ls -l` diagnostics in Task 5's report) covers the rest of
            // the family. The helper's `sh` aborts the chain on the first `&&`
            // that fails, so a missing marker is the diagnosis.
            "echo probe > /usr/local/cow-stat && echo WROTE \
             && access /usr/local/cow-stat && echo ACCESS_OK",
        ])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    assert_eq!(
        result.stdout_str().unwrap_or_default(),
        "WROTE\nOK\nACCESS_OK",
        "a file the branch wrote must be visible to the metadata family; stderr={:?}",
        result.stderr_str()
    );
    assert_eq!(
        result.stderr_str().unwrap_or_default(),
        "",
        "no probe may fail"
    );
    assert!(
        !rootfs.join("usr/local/cow-stat").exists(),
        "the write must stay in the branch's upper, not the shared lower"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&storage);
}

/// A whiteout covers the name the sandbox deleted, symlink or not.
///
/// `cow_resolve` answers for the path it is handed, and the read handlers hand
/// it the **resolved** one: a symlink in the lower resolves to its target, so a
/// whiteout recorded against the *link's* name was never consulted and the
/// target stayed readable through it. Measured on the lane (2026-10-15):
/// `rm /etc/os-release; cat /etc/os-release` printed the target's contents
/// (that image's `/etc/os-release` is a symlink), while the same two steps on a
/// regular file answered ENOENT.
#[tokio::test]
async fn test_chroot_cow_whiteout_masks_the_deleted_symlink() {
    let rootfs = build_test_rootfs("cow-link-whiteout");
    fs::write(rootfs.join("etc/cow-target"), b"secret\n").unwrap();
    std::os::unix::fs::symlink("cow-target", rootfs.join("etc/cow-link")).unwrap();
    let storage = temp_dir("cow-link-whiteout-upper");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .workdir(&rootfs)
        .fs_storage(&storage)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            // Read through the link, delete the *link*, read again. The target
            // itself is never deleted, so anything but a whiteout on the name
            // leaves it readable.
            "cat /etc/cow-link && echo LINK_READ \
             && rm /etc/cow-link && echo RM_OK \
             && cat /etc/cow-link && echo LINK_STILL_READABLE",
        ])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    assert_eq!(
        result.stdout_str().unwrap_or_default(),
        "secret\nLINK_READ\nRM_OK",
        "deleting a symlink must mask the name, not just its target; stderr={:?}",
        result.stderr_str()
    );
    assert_eq!(
        result.stderr_str().unwrap_or_default(),
        "cat: /etc/cow-link: No such file or directory",
        "the second read is the one that must fail"
    );
    assert!(
        rootfs.join("etc/cow-link").exists(),
        "the link belongs to the shared lower and must not be deleted there"
    );
    assert_eq!(
        fs::read(rootfs.join("etc/cow-target")).unwrap(),
        b"secret\n",
        "the target is not what was deleted"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&storage);
}

/// A directory created by the branch, then another inside it, **in one
/// process**: `mkdir -p X/Y` is one process making two `mkdirat` calls, and it
/// is what `npm install -g` and every recursive installer does.
#[tokio::test]
async fn test_chroot_cow_mkdir_p_two_levels_in_one_process() {
    let rootfs = build_test_rootfs("cow-mkdirp");
    fs::create_dir_all(rootfs.join("usr/local")).unwrap();
    let storage = temp_dir("cow-mkdirp-layer");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .workdir(&rootfs)
        .fs_storage(&storage)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&["rootfs-helper", "sh", "-c", "mkdir /usr/local/zz1 && mkdir /usr/local/zz1/zz2"])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    assert_eq!(
        result.stderr_str().unwrap_or_default(),
        "",
        "a second mkdir inside a directory this branch just made must be allowed; code={:?}",
        result.code()
    );
    assert_eq!(result.code(), Some(0), "stderr={:?}", result.stderr_str());
    assert!(!rootfs.join("usr/local/zz1").exists(), "the lower gains nothing");
    let branch_dir = fs::read_dir(&storage)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .unwrap();
    assert!(branch_dir.join("upper/usr/local/zz1/zz2").is_dir());

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&storage);
}

/// A name created **relative to a descriptor the branch owns**.
///
/// `mkdir -p X/Y` and every recursive installer (`npm install -g` staging its
/// package tree, `pip` creating `site-packages/<pkg>/`) make the second level
/// *relative to a descriptor they opened on the first*, so the parent reaches
/// the mediator as `/proc/<pid>/fd/N` rather than as a path. Measured on the
/// lane 2026-10-16 on BytePlan's `sandbox-base` image: `mkdir /usr/local/r1`
/// returned 0 and the very next `mkdirat(dirfd_of_r1, "r2")` answered EACCES,
/// while the same two levels written path-by-path were fine.
#[tokio::test]
async fn test_chroot_cow_a_mkdirat_through_a_branch_owned_dirfd_is_staged() {
    let rootfs = build_test_rootfs("cow-mkdirat-dirfd");
    fs::create_dir_all(rootfs.join("usr/local")).unwrap();
    let storage = temp_dir("cow-mkdirat-dirfd-layer");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .workdir(&rootfs)
        .fs_storage(&storage)
        .on_exit(BranchAction::Keep)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "mkdir /usr/local/cowdir && mkdirat-dirfd /usr/local/cowdir inner",
        ])
        .await
        .expect("the chroot sandbox must be creatable (N14 S5: the real root is the only shape)");

    assert_eq!(
        result.stderr_str().unwrap_or_default(),
        "",
        "a name created relative to a descriptor on a directory this branch just made \
         must be allowed; code={:?}",
        result.code()
    );
    assert_eq!(result.code(), Some(0), "stderr={:?}", result.stderr_str());
    assert!(
        !rootfs.join("usr/local/cowdir").exists(),
        "the lower gains nothing"
    );
    let branch_dir = fs::read_dir(&storage)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .unwrap();
    assert!(branch_dir.join("upper/usr/local/cowdir/inner").is_dir());

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&storage);
}
