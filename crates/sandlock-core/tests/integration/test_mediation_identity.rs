//! Path-mediation identity (fork-plan F6.1 / SL-1) — A档 assertions.
//!
//! The seccomp-notify supervisor performs on-behalf path operations (open /
//! openat with O_CREAT under a deny carve-out, chroot resolution, COW
//! staging) inside the process that owns the instance, so the *mediator
//! identity is that process's euid*.  When the supervisor process is the
//! sandbox's own host uid (route A, and route B's supervise slots), the
//! kernel DAC checks on those on-behalf operations are exactly the checks
//! the sandboxed workload would get — files it creates are owned by its
//! host uid, its own `chmod` succeeds, and a carve-out deny still refuses.
//! SL-1's three symptoms (root-owned files, broken self-chmod, absent
//! cross-uid sticky protection) do not exist in this shape.
//!
//! The tests below pin that same-uid contract (A档) on the default
//! non-root gate.  They deliberately do NOT use `RunAs`: a `RunAs` remap
//! to a *different* host uid from a root supervisor is the C档 shape and is
//! refused / explicitly downgraded elsewhere (see the root-mode
//! `mediation_2uid` target and `mediation_run_as`).

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sandlock_core::Sandbox;

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn unique_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sandlock-test-mediation-{name}-{}",
        std::process::id()
    ))
}

fn cleanup(path: &PathBuf) {
    let _ = std::fs::remove_dir_all(path);
}

/// Base policy forcing the on-behalf open path: grants on the base system
/// dirs (so a real command can run), a writable scratch dir, and a deny
/// carve-out *inside* the scratch dir — a denied leaf below a granted tree
/// is exactly the shape Landlock cannot express, so every open is resolved
/// and (when not denied) executed on-behalf with a race-free pinned inode.
fn base(dir: &PathBuf) -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(dir)
        .fs_deny(dir.join("secret.txt"))
}

/// A档 hard assertion #1 (plan F6.1 Step 1): with path mediation active,
/// a file the workload creates in the sandbox is owned by the caller's own
/// host uid — the mediator's identity — and the workload's own `chmod`
/// takes effect.  Under the C档 (root in-process remap) both halves fail:
/// the file would be uid 0 and the workload's `chmod` would get EPERM.
#[tokio::test]
async fn test_nonroot_created_file_owned_by_self() {
    let dir = unique_dir("a-owner");
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let mut sb = base(&dir).build().expect("policy builds");

    let file = dir.join("created.txt");
    let cmd = format!(
        "umask 0; echo mediated > {}; chmod 0600 {}",
        file.display(),
        file.display()
    );
    let r = sb.run(&["sh", "-c", &cmd]).await.expect("sandboxed run");
    assert!(
        r.success(),
        "create + self-chmod must succeed, stderr: {:?}",
        r.stderr_str()
    );

    let meta = std::fs::metadata(&file).expect("host-side stat of mediated file");
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        meta.uid(),
        euid(),
        "on-behalf create must run as the owning process's uid (mediator == \
         sandbox host uid in A/B档); got uid {} for {}",
        meta.uid(),
        file.display()
    );
    assert_eq!(
        meta.mode() & 0o7777,
        0o600,
        "the workload's own chmod must take effect on its mediated file"
    );
    assert_eq!(
        std::fs::read_to_string(&file).expect("read mediated file"),
        "mediated\n",
        "content written through the mediated open must round-trip"
    );

    cleanup(&dir);
}

/// A档 hard assertion #2 (plan F6.1 Step 1): the deny carve-out is still
/// enforced while mediation is active — switching identities must never
/// have loosened the deny list (a denied leaf below a granted dir must
/// return EACCES, and a sibling allowed path must still work).
#[tokio::test]
async fn test_denied_path_still_denied() {
    let dir = unique_dir("a-deny");
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    std::fs::write(dir.join("secret.txt"), "top-secret").expect("seed denied file");

    let secret = dir.join("secret.txt");
    let cmd = format!("cat {}", secret.display());
    let mut denied_sb = base(&dir).build().expect("deny policy builds");
    let r = denied_sb
        .run(&["sh", "-c", &cmd])
        .await
        .expect("sandboxed run");
    assert!(
        !r.success(),
        "the denied carve-out must still be refused while mediation is active"
    );
    assert_eq!(
        r.stderr_str(),
        Some(format!("cat: {}: Permission denied", secret.display()).as_str()),
        "the carve-out refusal must be the exact EACCES cat reports"
    );

    // Same-grant sibling: still writable (the carve-out narrowed only the
    // leaf, not the whole granted tree).
    let allowed = dir.join("allowed.txt");
    let cmd = format!("echo ok > {}", allowed.display());
    let mut allowed_sb = base(&dir).build().expect("allow policy builds");
    let r = allowed_sb
        .run(&["sh", "-c", &cmd])
        .await
        .expect("sandboxed run");
    assert!(
        r.success(),
        "a sibling path under the same grant must remain usable, stderr: {:?}",
        r.stderr_str()
    );
    assert_eq!(
        std::fs::read_to_string(&allowed).expect("read allowed sibling"),
        "ok\n"
    );

    cleanup(&dir);
}
