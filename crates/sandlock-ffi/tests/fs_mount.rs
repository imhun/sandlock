//! Integration tests for the C ABI filesystem-mount setters.
//!
//! `builder_*` tests drive the FFI symbols directly (no C compilation
//! step) and read back state through the public Rust `Sandbox` API.
//!
//! The `read_only_mount_*` test goes the whole way through the C ABI
//! (builder setters, `sandlock_sandbox_build`, `sandlock_run`) and runs a
//! real guest inside a chroot to check what the mount actually enforces:
//! reads succeed, writes are refused. A read-only mount is a policy
//! decision in the seccomp-notify chroot handlers (writes get EACCES),
//! not a kernel `MS_RDONLY` mount, and it only exists under `chroot`.

use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::{c_char, c_int, c_uint};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::ptr;

use sandlock_core::Sandbox;
use sandlock_ffi::{
    sandlock_result_exit_code, sandlock_result_free, sandlock_result_stderr,
    sandlock_result_stdout, sandlock_result_success, sandlock_run, sandlock_sandbox_build,
    sandlock_sandbox_builder_chroot, sandlock_sandbox_builder_fs_mount,
    sandlock_sandbox_builder_fs_mount_ro, sandlock_sandbox_builder_fs_read,
    sandlock_sandbox_builder_fs_write, sandlock_sandbox_builder_new, sandlock_sandbox_free,
    sandlock_sandbox_t, sandlock_string_free,
};

// ----------------------------------------------------------------
// Builder-level: what the setters record on the built Sandbox
// ----------------------------------------------------------------

/// Run `builder_new` + the supplied setter chain + `build()`, returning
/// the Sandbox so the caller can inspect `fs_mount` / `fs_mount_ro`.
fn build_via_ffi<F>(configure: F) -> Sandbox
where
    F: FnOnce(
        *mut sandlock_core::sandbox::SandboxBuilder,
    ) -> *mut sandlock_core::sandbox::SandboxBuilder,
{
    let b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");
    let b = configure(b);
    assert!(!b.is_null(), "configure returned null builder");
    // SAFETY: `b` is a valid Box pointer produced by builder_new and
    // possibly relocated through builder setters.
    let builder = unsafe { *Box::from_raw(b) };
    builder.build().expect("build failed")
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn builder_fs_mount_ro_registers_the_mount_and_marks_it_read_only() {
    let (vp, hp) = (cstr("/work"), cstr("/host/work"));
    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, vp.as_ptr(), hp.as_ptr())
    });

    // A read-only mount is still a mount: the pair must be in fs_mount,
    // otherwise nothing is visible at the virtual path at all.
    assert_eq!(
        sandbox.fs_mount,
        vec![(PathBuf::from("/work"), PathBuf::from("/host/work"))],
        "fs_mount_ro must also register the mount mapping",
    );
    // And the virtual path must be on the read-only side list, which is
    // what makes writes fail.
    assert_eq!(
        sandbox.fs_mount_ro,
        vec![PathBuf::from("/work")],
        "fs_mount_ro must mark the virtual path read-only",
    );
}

#[test]
fn builder_fs_mount_leaves_the_mount_writable() {
    let (vp, hp) = (cstr("/work"), cstr("/host/work"));
    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount(b, vp.as_ptr(), hp.as_ptr())
    });

    assert_eq!(
        sandbox.fs_mount,
        vec![(PathBuf::from("/work"), PathBuf::from("/host/work"))],
    );
    assert!(
        sandbox.fs_mount_ro.is_empty(),
        "plain fs_mount must not mark anything read-only, got {:?}",
        sandbox.fs_mount_ro,
    );
}

#[test]
fn builder_mount_setters_chain_and_stay_distinguishable() {
    let (ro_v, ro_h) = (cstr("/ro"), cstr("/host/ro"));
    let (rw_v, rw_h) = (cstr("/rw"), cstr("/host/rw"));
    let sandbox = build_via_ffi(|b| unsafe {
        let b = sandlock_sandbox_builder_fs_mount_ro(b, ro_v.as_ptr(), ro_h.as_ptr());
        sandlock_sandbox_builder_fs_mount(b, rw_v.as_ptr(), rw_h.as_ptr())
    });

    assert_eq!(
        sandbox.fs_mount,
        vec![
            (PathBuf::from("/ro"), PathBuf::from("/host/ro")),
            (PathBuf::from("/rw"), PathBuf::from("/host/rw")),
        ],
        "both mounts must survive the moved builder pointer",
    );
    assert_eq!(
        sandbox.fs_mount_ro,
        vec![PathBuf::from("/ro")],
        "only the read-only mount's virtual path may be marked read-only",
    );
}

#[test]
fn builder_fs_mount_ro_tolerates_null_arguments() {
    let (vp, hp) = (cstr("/work"), cstr("/host/work"));

    // Null in, builder out unchanged: the convention every other
    // `sandlock_sandbox_builder_*` setter follows.
    let out =
        unsafe { sandlock_sandbox_builder_fs_mount_ro(ptr::null_mut(), vp.as_ptr(), hp.as_ptr()) };
    assert!(out.is_null(), "fs_mount_ro(null, _, _) must return null");

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, ptr::null(), hp.as_ptr())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "a null virtual_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, vp.as_ptr(), ptr::null())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "a null host_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );
}

#[test]
fn builder_fs_mount_ro_refuses_empty_paths() {
    // An empty virtual path is a prefix of *every* path, so recording it
    // would mount the whole tree and make ChrootCtx::can_read return true
    // everywhere, and the read allowlist would be gone. Core's
    // parse_mount_spec rejects empty components for the same reason, so
    // the C ABI must not be the one door that accepts them.
    let (vp, hp) = (cstr("/work"), cstr("/host/work"));
    let empty = cstr("");

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, empty.as_ptr(), hp.as_ptr())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "an empty virtual_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, vp.as_ptr(), empty.as_ptr())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "an empty host_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );
}

#[test]
fn builder_fs_mount_ro_refuses_non_utf8_paths() {
    // A lossy conversion would have collapsed these to "", i.e. to the
    // tree-wide mount above; dropping the mount is the fail-closed choice
    // for a setter with no error channel.
    let (vp, hp) = (cstr("/work"), cstr("/host/work"));
    let bad = CString::new(vec![b'/', 0xff, b'x']).unwrap();

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, bad.as_ptr(), hp.as_ptr())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "a non-UTF-8 virtual_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, vp.as_ptr(), bad.as_ptr())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "a non-UTF-8 host_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );
}

#[test]
fn builder_fs_mount_refuses_unusable_paths_exactly_like_fs_mount_ro() {
    // The plain setter is the *more* dangerous door for the same input:
    // an empty virtual path there voids the write allowlist as well as the
    // read one (`ChrootCtx::can_write` short-circuits on `is_mounted`),
    // with no read-only marking left to hold writes closed. Both setters
    // must therefore drop the mount rather than degrade the path to "".
    // `sandlock_sandbox_builder_fs_mount` is what the Go binding
    // (go/sandlock_linux.go) and the Python `Sandbox` dataclass
    // (python/src/sandlock/_sdk.py) call, so this is the reachable one.
    let good = cstr("/work");
    let bad_utf8 = CString::new(vec![b'/', 0xff, b'x']).unwrap();
    let empty = cstr("");

    let cases: [(&str, &CString, &CString); 4] = [
        ("empty virtual_path", &empty, &good),
        ("empty host_path", &good, &empty),
        ("non-UTF-8 virtual_path", &bad_utf8, &good),
        ("non-UTF-8 host_path", &good, &bad_utf8),
    ];

    for (label, vp, hp) in cases {
        let sandbox = build_via_ffi(|b| unsafe {
            sandlock_sandbox_builder_fs_mount(b, vp.as_ptr(), hp.as_ptr())
        });
        assert!(
            sandbox.fs_mount.is_empty(),
            "fs_mount with {label} must add no mount, got {:?}",
            sandbox.fs_mount,
        );
        // Nothing marks it read-only either, so a recorded mount here would
        // be a tree-wide read-write mapping.
        assert!(sandbox.fs_mount_ro.is_empty());
    }
}

// ----------------------------------------------------------------
// End-to-end: what a read-only mount enforces on a real guest
// ----------------------------------------------------------------

/// Path to the static rootfs-helper binary (compiled by sandlock-core's
/// build.rs, which has already run because this crate depends on it).
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found; sandlock-core's build.rs should have compiled it")
}

fn temp_dir(name: &str) -> PathBuf {
    // Prefer cargo's per-test-binary tmp dir (same filesystem as the
    // compiled helper) so the rootfs can hard-link it instead of copying:
    // a copy's writable fd can leak into a concurrent fork+exec and make
    // the execve fail with ETXTBSY.
    let base = option_env!("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!(
        "sandlock-ffi-mount-{}-{}",
        name,
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("failed to create temp dir");
    dir
}

/// Minimal self-contained rootfs with the busybox-style rootfs-helper.
fn build_test_rootfs(name: &str) -> PathBuf {
    let rootfs = temp_dir(name);
    let helper = helper_binary();

    for dir in &["usr/bin", "etc", "proc", "dev", "tmp"] {
        fs::create_dir_all(rootfs.join(dir)).expect("failed to create rootfs dir");
    }
    let _ = fs::set_permissions(rootfs.join("tmp"), fs::Permissions::from_mode(0o1777));

    let dest = rootfs.join("usr/bin/rootfs-helper");
    fs::hard_link(&helper, &dest)
        .or_else(|_| fs::copy(&helper, &dest).map(|_| ()))
        .expect("failed to install rootfs-helper into rootfs");
    for cmd in &["cat", "write", "ls"] {
        let link = rootfs.join(format!("usr/bin/{}", cmd));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink("rootfs-helper", &link)
            .expect("failed to create busybox symlink");
    }
    let _ = std::os::unix::fs::symlink("usr/bin", rootfs.join("bin"));

    rootfs
}

/// Captured outcome of one guest command.
struct Run {
    success: bool,
    code: c_int,
    stdout: String,
    stderr: String,
}

/// Run `argv` under `policy` through the C ABI and collect the result.
fn run_in_sandbox(policy: *mut sandlock_sandbox_t, argv: &[&str]) -> Run {
    let owned: Vec<CString> = argv.iter().map(|s| cstr(s)).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    let r = unsafe { sandlock_run(policy, ptr::null(), ptrs.as_ptr(), ptrs.len() as c_uint) };
    assert!(!r.is_null(), "sandlock_run({:?}) returned null", argv);

    let read = |p: *mut c_char| -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: `p` is a malloc'd NUL-terminated string owned by us.
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        unsafe { sandlock_string_free(p) };
        s
    };
    let out = Run {
        success: unsafe { sandlock_result_success(r) },
        code: unsafe { sandlock_result_exit_code(r) },
        stdout: read(unsafe { sandlock_result_stdout(r) }),
        stderr: read(unsafe { sandlock_result_stderr(r) }),
    };
    unsafe { sandlock_result_free(r) };
    out
}

/// Build a chroot policy through the C ABI with one read-only mount at
/// `/ro` and one read-write mount at `/rw`.
fn build_mount_policy(rootfs: &Path, ro_host: &Path, rw_host: &Path) -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");

    let root = cstr(rootfs.to_str().unwrap());
    b = unsafe { sandlock_sandbox_builder_chroot(b, root.as_ptr()) };
    for p in ["/usr", "/bin", "/proc", "/dev"] {
        let c = cstr(p);
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    // Grant /ro read AND write explicitly: the read-only mount must win
    // over an explicit writable rule, which is the whole point of
    // checking mount_ro before the writable prefixes.
    for p in ["/ro", "/rw"] {
        let c = cstr(p);
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
        b = unsafe { sandlock_sandbox_builder_fs_write(b, c.as_ptr()) };
    }

    let (ro_v, ro_h) = (cstr("/ro"), cstr(ro_host.to_str().unwrap()));
    b = unsafe { sandlock_sandbox_builder_fs_mount_ro(b, ro_v.as_ptr(), ro_h.as_ptr()) };
    let (rw_v, rw_h) = (cstr("/rw"), cstr(rw_host.to_str().unwrap()));
    b = unsafe { sandlock_sandbox_builder_fs_mount(b, rw_v.as_ptr(), rw_h.as_ptr()) };

    let mut err: c_int = 0;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, &mut err_msg) };
    if err != 0 {
        let msg = if err_msg.is_null() {
            String::new()
        } else {
            let m = unsafe { CStr::from_ptr(err_msg) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandlock_string_free(err_msg) };
            m
        };
        panic!("sandbox_build failed: {}", msg);
    }
    assert!(!policy.is_null(), "sandbox_build returned null policy");
    policy
}

/// Build a chroot policy through the C ABI with a single node mounted at
/// `virtual_path` (a regular file or a character device node).
fn build_single_node_policy(
    rootfs: &Path,
    virtual_path: &str,
    host_path: &Path,
    read_only: bool,
    writable_prefixes: &[&str],
) -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");

    let root = cstr(rootfs.to_str().unwrap());
    b = unsafe { sandlock_sandbox_builder_chroot(b, root.as_ptr()) };
    // Execution grants for the static rootfs-helper; the mounted node needs
    // no fs_read grant of its own (mounts are readable by definition).
    for p in ["/usr", "/bin"] {
        let c = cstr(p);
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    // Optional write grants above the mount point (e.g. "/etc"): the
    // read-only marking must beat the writable prefix, and the EBUSY guard
    // must fire even when the prefix would otherwise allow the write family.
    for p in writable_prefixes {
        let c = cstr(p);
        b = unsafe { sandlock_sandbox_builder_fs_write(b, c.as_ptr()) };
    }

    let (vp, hp) = (cstr(virtual_path), cstr(host_path.to_str().unwrap()));
    b = unsafe {
        if read_only {
            sandlock_sandbox_builder_fs_mount_ro(b, vp.as_ptr(), hp.as_ptr())
        } else {
            sandlock_sandbox_builder_fs_mount(b, vp.as_ptr(), hp.as_ptr())
        }
    };

    let mut err: c_int = 0;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, &mut err_msg) };
    if err != 0 {
        let msg = if err_msg.is_null() {
            String::new()
        } else {
            let m = unsafe { CStr::from_ptr(err_msg) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandlock_string_free(err_msg) };
            m
        };
        panic!("sandbox_build failed: {}", msg);
    }
    assert!(!policy.is_null(), "sandbox_build returned null policy");
    policy
}

/// Bind-mounting a single regular file (the `/etc/resolv.conf` shape) must
/// expose the host file's content inside the chroot.
///
/// Regression (fork-plan F6.2 / P5): single-file mount points were treated
/// as resolution *roots*, so the mediator tried to `open(O_DIRECTORY)` the
/// host file and every access failed with `ENOTDIR`. A single-node bind
/// mount is a leaf: the object the child asked for *is* the configured host
/// source, so no interior resolution applies.
#[test]
fn test_mount_single_file_node() {
    let rootfs = build_test_rootfs("single-file-node");
    let host_dir = temp_dir("single-file-host");
    let host_file = host_dir.join("resolv.conf");
    let content = "nameserver 127.0.0.11\n";
    fs::write(&host_file, content).unwrap();

    // The rootfs deliberately has no resolv.conf of its own: the mount is
    // the only way the sandbox can see the name. Keep /etc clean so the
    // assertion cannot pass by falling through to a rootfs copy.
    assert!(
        !rootfs.join("etc/resolv.conf").exists(),
        "test rootfs must not shadow the mounted file"
    );

    let policy = build_single_node_policy(&rootfs, "/etc/resolv.conf", &host_file, false, &[]);

    let r = run_in_sandbox(policy, &["rootfs-helper", "cat", "/etc/resolv.conf"]);
    assert!(
        r.success,
        "cat of a single-file bind mount must succeed: exit={} stderr={}",
        r.code, r.stderr,
    );
    assert_eq!(
        r.stdout,
        content,
        "the sandbox must read the bound host file's exact content",
    );

    unsafe { sandlock_sandbox_free(policy) };

    // Read-only variant (ro kept): writes through the single-file mount are
    // refused and the host file stays byte-identical.
    // The /etc write prefix is granted so the refusal pins the read-only
    // mount winning over a writable prefix (mount_ro is checked before the
    // is_mounted allow), not merely the absence of a write grant.
    let ro_policy =
        build_single_node_policy(&rootfs, "/etc/resolv.conf", &host_file, true, &["/etc"]);
    let w = run_in_sandbox(ro_policy, &["rootfs-helper", "write", "/etc/resolv.conf", "clobber"]);
    assert!(
        !w.success,
        "writing through a read-only single-file mount must fail: stdout={} stderr={}",
        w.stdout, w.stderr,
    );
    assert_eq!(
        w.stderr,
        "write: /etc/resolv.conf: Permission denied\n",
        "the denied write must surface EACCES with the exact helper error",
    );
    assert_eq!(
        fs::read_to_string(&host_file).unwrap(),
        content,
        "the denied write must not reach the host file",
    );

    unsafe { sandlock_sandbox_free(ro_policy) };
    let _ = fs::remove_dir_all(&rootfs);
    let _ = fs::remove_dir_all(&host_dir);
}

/// Bind-mounting a character device node (`/dev/null`) must hand the guest a
/// real fd to the host chardev — the same inode — rather than failing with
/// `ENOTDIR` (fork-plan F6.2 / P5).
#[test]
fn test_mount_chardev_node() {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::FileTypeExt;

    let rootfs = build_test_rootfs("chardev-node");
    // The rootfs has an empty /dev dir; /dev/null only exists through the
    // single-node mount.
    let host_meta = fs::metadata("/dev/null").expect("host /dev/null must exist");
    let host_ino = host_meta.ino();
    assert_eq!(
        host_meta.file_type().is_char_device(),
        true,
        "test requires a real character device at /dev/null"
    );

    let policy = build_single_node_policy(&rootfs, "/dev/null", Path::new("/dev/null"), false, &[]);

    // open() + fstat on the injected fd: the inode must be the host chardev's
    // (a synthesized regular file would have a different inode).
    let r = run_in_sandbox(policy, &["rootfs-helper", "fstat-fd", "/dev/null"]);
    assert!(
        r.success,
        "open+fstat of a mounted chardev must succeed: exit={} stderr={}",
        r.code, r.stderr,
    );
    assert_eq!(
        r.stdout,
        format!("OK size=0 ino={}\n", host_ino),
        "the sandbox fd must be the real host /dev/null chardev",
    );

    // Raw openat2 spelling reaches the same node (the newest open ABI).
    let o = run_in_sandbox(policy, &["rootfs-helper", "openat2", "/dev/null"]);
    assert!(
        o.success,
        "openat2 on a mounted chardev must succeed: exit={} stderr={}",
        o.code, o.stderr,
    );
    assert_eq!(o.stdout, "", "reading /dev/null yields no bytes");

    // Writes to the chardev sink succeed (rw mount), proving the node is not
    // merely readable.
    let w = run_in_sandbox(policy, &["rootfs-helper", "write", "/dev/null", "discard"]);
    assert!(
        w.success,
        "writing to /dev/null through the mount must succeed: exit={} stderr={}",
        w.code, w.stderr,
    );

    unsafe { sandlock_sandbox_free(policy) };
    let _ = fs::remove_dir_all(&rootfs);
}

/// A single-node bind-mount point is a policy object, not a name the guest
/// owns: rm/mv of an rw single-file mount must fail with EBUSY and leave the
/// HOST file untouched (I1/P5 review). A read-only mount refuses the same
/// operations with EACCES first, even when a writable prefix above the mount
/// point (here `/etc`) would otherwise allow them.
#[test]
fn test_rw_mount_point_resists_unlink_and_rename() {
    let rootfs = build_test_rootfs("mount-point-mutation");
    let host_dir = temp_dir("mount-point-mutation-host");
    let host_file = host_dir.join("resolv.conf");
    let content = "nameserver 127.0.0.11\n";
    fs::write(&host_file, content).unwrap();

    // rw mount + writable /etc prefix: can_write passes, so EBUSY is the
    // guard that stops the guest from reaching the host source.
    let policy =
        build_single_node_policy(&rootfs, "/etc/resolv.conf", &host_file, false, &["/etc"]);

    let rm = run_in_sandbox(policy, &["rootfs-helper", "rm", "/etc/resolv.conf"]);
    assert!(
        !rm.success,
        "rm of an rw single-file mount point must fail: stdout={} stderr={}",
        rm.stdout, rm.stderr,
    );
    assert_eq!(
        rm.stderr,
        "rm: /etc/resolv.conf: Device or resource busy\n",
        "unlink at a mount point must surface EBUSY with the exact helper error",
    );
    assert_eq!(
        fs::read_to_string(&host_file).unwrap(),
        content,
        "rm must not delete the host file behind the mount",
    );

    let mv = run_in_sandbox(
        policy,
        &["rootfs-helper", "mv", "/etc/resolv.conf", "/etc/renamed.conf"],
    );
    assert!(
        !mv.success,
        "mv of an rw single-file mount point must fail: stdout={} stderr={}",
        mv.stdout, mv.stderr,
    );
    assert_eq!(
        mv.stderr,
        "mv: /etc/resolv.conf: Device or resource busy\n",
        "rename of a mount point must surface EBUSY with the exact helper error",
    );
    assert_eq!(
        fs::read_to_string(&host_file).unwrap(),
        content,
        "rename must not move the host file behind the mount",
    );
    assert!(
        !host_dir.join("renamed.conf").exists(),
        "rename must not create a host file under the moved name",
    );

    unsafe { sandlock_sandbox_free(policy) };

    // ro mount over the same writable prefix: EACCES wins (ro checked before
    // is_mounted), and the host file stays intact.
    let ro_policy =
        build_single_node_policy(&rootfs, "/etc/resolv.conf", &host_file, true, &["/etc"]);
    let ro_rm = run_in_sandbox(ro_policy, &["rootfs-helper", "rm", "/etc/resolv.conf"]);
    assert!(
        !ro_rm.success,
        "rm of a read-only single-file mount point must fail: stdout={} stderr={}",
        ro_rm.stdout, ro_rm.stderr,
    );
    assert_eq!(
        ro_rm.stderr,
        "rm: /etc/resolv.conf: Permission denied\n",
        "the read-only mount must beat the writable /etc prefix with EACCES",
    );
    assert_eq!(
        fs::read_to_string(&host_file).unwrap(),
        content,
        "the denied rm must not touch the host file",
    );

    unsafe { sandlock_sandbox_free(ro_policy) };
    let _ = fs::remove_dir_all(&rootfs);
    let _ = fs::remove_dir_all(&host_dir);
}

/// Hard-linking FROM a writable single-file mount point is refused with
/// EBUSY, exactly like unlink/rename at the same leaf (I1/P5 review, direct
/// pin): a hard link to the host source would give the sandbox a second name
/// for the HOST object behind the mount.
#[test]
fn test_rw_mount_point_resists_link() {
    let rootfs = build_test_rootfs("mount-point-link");
    let host_dir = temp_dir("mount-point-link-host");
    let host_file = host_dir.join("resolv.conf");
    let content = "nameserver 127.0.0.11\n";
    fs::write(&host_file, content).unwrap();

    // rw mount + writable /etc prefix: can_write passes on both sides, so
    // EBUSY is the guard that stops the guest from aliasing the host source.
    let policy =
        build_single_node_policy(&rootfs, "/etc/resolv.conf", &host_file, false, &["/etc"]);

    let ln = run_in_sandbox(
        policy,
        &["rootfs-helper", "ln", "/etc/resolv.conf", "/etc/resolv-link.conf"],
    );
    assert!(
        !ln.success,
        "hard-linking a mount point source must fail: stdout={} stderr={}",
        ln.stdout, ln.stderr,
    );
    assert_eq!(
        ln.stderr,
        "ln: /etc/resolv-link.conf: Device or resource busy\n",
        "link at a mount point must surface EBUSY with the exact helper error",
    );
    assert_eq!(
        fs::read_to_string(&host_file).unwrap(),
        content,
        "the refused link must not touch the host file",
    );
    assert!(
        !host_dir.join("resolv-link.conf").exists(),
        "the refused link must not create a host file under the new name",
    );

    unsafe { sandlock_sandbox_free(policy) };
    let _ = fs::remove_dir_all(&rootfs);
    let _ = fs::remove_dir_all(&host_dir);
}

/// rmdir of a *directory* bind-mount point must be refused with EBUSY like
/// a real kernel bind mount (F13 / FUP-05): the pre-F13 handler routed
/// rmdir (unlinkat AT_REMOVEDIR) straight to the host source, so an empty
/// host directory behind the mount could be deleted through the sandbox.
/// Regular directories *inside* the mount stay fully usable.
#[test]
fn test_directory_mount_point_rmdir_is_refused() {
    let rootfs = build_test_rootfs("dir-mount-rmdir");
    let host_dir = temp_dir("dir-mount-rmdir-host");
    let policy = build_single_node_policy(&rootfs, "/work", &host_dir, false, &[]);

    // Control: a regular directory inside the rw directory mount still
    // mkdir/rmdir normally — only the mount point itself is a policy object.
    let mk = run_in_sandbox(policy, &["rootfs-helper", "mkdir", "/work/inner"]);
    assert!(
        mk.success,
        "mkdir inside a rw directory mount must succeed: exit={} stderr={}",
        mk.code, mk.stderr,
    );
    assert!(
        host_dir.join("inner").is_dir(),
        "the sandbox mkdir must land in the host directory behind the mount",
    );
    let rm_inner = run_in_sandbox(policy, &["rootfs-helper", "rmdir", "/work/inner"]);
    assert!(
        rm_inner.success,
        "rmdir of a regular directory inside the mount must succeed: exit={} stderr={}",
        rm_inner.code, rm_inner.stderr,
    );
    assert!(
        !host_dir.join("inner").exists(),
        "the sandbox rmdir must remove the inner host directory",
    );

    // The mount point itself must resist rmdir, and the host directory (now
    // empty, so a host rmdir would otherwise succeed) must survive.
    let rm = run_in_sandbox(policy, &["rootfs-helper", "rmdir", "/work"]);
    assert!(
        !rm.success,
        "rmdir of a directory mount point must fail: stdout={} stderr={}",
        rm.stdout, rm.stderr,
    );
    assert_eq!(
        rm.stderr,
        "rmdir: /work: Device or resource busy\n",
        "rmdir at a directory mount point must surface EBUSY with the exact helper error",
    );
    assert!(
        host_dir.is_dir(),
        "rmdir must not delete the host directory behind the mount",
    );

    unsafe { sandlock_sandbox_free(policy) };
    let _ = fs::remove_dir_all(&rootfs);
    let _ = fs::remove_dir_all(&host_dir);
}

/// A single-file mount leaf resolves through the mount before the rootfs, so
/// a virtual parent chain missing from the rootfs does not block a direct
/// open of the mounted node (I2/P5 review pin: no parent precreate mechanism
/// exists or is needed for direct leaf opens).
#[test]
fn test_single_file_leaf_opens_without_rootfs_parents() {
    let rootfs = build_test_rootfs("absent-parent-leaf");
    // The rootfs has neither /opt nor /opt/app; only the mount provides the
    // name /opt/app/config.yaml.
    assert!(
        !rootfs.join("opt").exists(),
        "test rootfs must not pre-create the virtual parents"
    );

    let host_dir = temp_dir("absent-parent-leaf-host");
    let host_file = host_dir.join("config.yaml");
    let content = "leaf-without-parents: true\n";
    fs::write(&host_file, content).unwrap();

    let policy = build_single_node_policy(
        &rootfs,
        "/opt/app/config.yaml",
        &host_file,
        false,
        &[],
    );
    let r = run_in_sandbox(policy, &["rootfs-helper", "cat", "/opt/app/config.yaml"]);
    assert!(
        r.success,
        "direct open of a leaf mount without rootfs parents must succeed: exit={} stderr={}",
        r.code, r.stderr,
    );
    assert_eq!(
        r.stdout,
        content,
        "the sandbox must read the bound host file's exact content",
    );

    unsafe { sandlock_sandbox_free(policy) };
    let _ = fs::remove_dir_all(&rootfs);
    let _ = fs::remove_dir_all(&host_dir);
}

#[test]
fn read_only_mount_allows_reads_and_denies_writes() {
    let rootfs = build_test_rootfs("ro-enforced");
    fs::create_dir_all(rootfs.join("ro")).unwrap();
    fs::create_dir_all(rootfs.join("rw")).unwrap();

    let ro_host = temp_dir("ro-host");
    let rw_host = temp_dir("rw-host");
    fs::write(ro_host.join("input.txt"), "hello read-only mount\n").unwrap();
    fs::write(rw_host.join("input.txt"), "hello writable mount\n").unwrap();

    let policy = build_mount_policy(&rootfs, &ro_host, &rw_host);

    // 1. Reads go through the read-only mount, and they reach the host
    //    directory (not an empty rootfs dir of the same name).
    let r = run_in_sandbox(policy, &["rootfs-helper", "cat", "/ro/input.txt"]);
    assert!(
        r.success,
        "cat /ro/input.txt must succeed under a read-only mount: exit={} stderr={}",
        r.code, r.stderr,
    );
    assert_eq!(
        r.stdout.trim(),
        "hello read-only mount",
        "read-only mount must expose the host directory's content",
    );

    // 2. Creating a file under the read-only mount is refused, even
    //    though /ro was granted fs_write.
    let r = run_in_sandbox(
        policy,
        &["rootfs-helper", "write", "/ro/created.txt", "nope"],
    );
    assert!(
        !r.success,
        "creating /ro/created.txt must fail under a read-only mount: stdout={} stderr={}",
        r.stdout, r.stderr,
    );
    assert_eq!(
        r.stderr,
        "write: /ro/created.txt: Permission denied\n",
        "write to a read-only mount must be denied with EACCES and the exact helper error",
    );
    assert!(
        !ro_host.join("created.txt").exists(),
        "the denied write must not have reached the host directory",
    );

    // 3. Overwriting an existing file under the read-only mount is
    //    refused too, and the host content is untouched.
    let r = run_in_sandbox(
        policy,
        &["rootfs-helper", "write", "/ro/input.txt", "clobbered"],
    );
    assert!(
        !r.success,
        "overwriting /ro/input.txt must fail: stdout={} stderr={}",
        r.stdout, r.stderr,
    );
    assert_eq!(
        fs::read_to_string(ro_host.join("input.txt")).unwrap(),
        "hello read-only mount\n",
        "the host file must be byte-identical after the denied write",
    );

    // 4. Control: the very same policy, the very same guest command, on
    //    a mount registered with `fs_mount` instead: writes land. This
    //    is what pins the denial on the read-only marking rather than on
    //    a broken mount setup.
    let r = run_in_sandbox(
        policy,
        &["rootfs-helper", "write", "/rw/created.txt", "yes"],
    );
    assert!(
        r.success,
        "write to a read-write mount must succeed: exit={} stderr={}",
        r.code, r.stderr,
    );
    assert_eq!(
        fs::read_to_string(rw_host.join("created.txt")).unwrap(),
        "yes\n",
        "the allowed write must reach the host directory",
    );

    unsafe { sandlock_sandbox_free(policy) };
    let _ = fs::remove_dir_all(&rootfs);
    let _ = fs::remove_dir_all(&ro_host);
    let _ = fs::remove_dir_all(&rw_host);
}
