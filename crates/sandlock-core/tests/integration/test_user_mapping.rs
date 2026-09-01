use sandlock_core::error::{SandboxRuntimeError, SandlockError};
use sandlock_core::Sandbox;

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Exact fail-closed refusal message `do_create_stdio` returns for an
/// unprivileged `RunAs` remap (see `sandbox.rs`); kept in lockstep with the
/// implementation.
fn run_as_refused_msg(uid: u32, gid: u32) -> String {
    format!(
        "RunAs({uid}, {gid}) refused: unprivileged supervisor (euid={}) cannot map an arbitrary \
         host uid (single-entry userns map can only cover the caller's own euid); \
         per-sandbox independent host uids require a privileged supervisor \
         (root/CAP_SETUID in the parent user namespace) or an equivalent mechanism",
        euid()
    )
}

fn assert_run_as_refused(err: SandlockError, expected: &str) {
    match err {
        SandlockError::Runtime(SandboxRuntimeError::Child(msg)) => assert_eq!(msg, expected),
        other => panic!("expected fail-closed RunAs refusal, got: {other:?}"),
    }
}

/// Check if user namespaces with uid mapping actually work in this environment.
/// Some CI environments (containers, restricted kernels) allow unshare but block
/// writing to /proc/self/uid_map.
fn userns_available() -> bool {
    // Fork a child that tries unshare(CLONE_NEWUSER) + uid_map write.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // Child: try unshare + write uid_map
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            unsafe { libc::_exit(1) };
        }
        let uid = unsafe { libc::getuid() };
        let map = format!("0 {} 1\n", uid);
        let ok = std::fs::write("/proc/self/setgroups", "deny\n").is_ok()
            && std::fs::write("/proc/self/uid_map", &map).is_ok()
            && std::fs::write("/proc/self/gid_map", &map).is_ok()
            && unsafe { libc::getuid() } == 0;
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    // Parent: wait and check exit status
    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// Test that --user 0:0 makes the child appear as uid 0 (privileged) or is
/// refused fail-closed (unprivileged supervisor cannot map a different host
/// uid).
#[tokio::test]
async fn test_uid_zero() {
    if euid() == 0 {
        if !userns_available() {
            eprintln!("Skipping: user namespaces not available in this environment");
            return;
        }

        let policy = Sandbox::builder()
            .fs_read("/usr")
            .fs_read("/lib")
            .fs_read_if_exists("/lib64")
            .fs_read("/bin")
            .fs_read("/etc")
            .fs_read("/proc")
            .user(0, 0)
            .build()
            .unwrap();

        let result = policy.clone().run(&["id", "-u"]).await.unwrap();
        assert!(result.success(), "id -u failed: {:?}", result.exit_status);
        let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
        assert_eq!(stdout.trim(), "0", "Expected uid 0, got: {:?}", stdout.trim());
    } else {
        let mut policy = Sandbox::builder()
            .fs_read("/usr")
            .fs_read("/lib")
            .fs_read_if_exists("/lib64")
            .fs_read("/bin")
            .fs_read("/etc")
            .fs_read("/proc")
            .user(0, 0)
            .build()
            .unwrap();
        let err = policy.run(&["id", "-u"]).await.unwrap_err();
        assert_run_as_refused(err, &run_as_refused_msg(0, 0));
    }
}

/// Test that --user 0:0 makes the child appear as gid 0 (privileged) or is
/// refused fail-closed (unprivileged).
#[tokio::test]
async fn test_uid_zero_gid_zero() {
    if euid() == 0 {
        if !userns_available() {
            eprintln!("Skipping: user namespaces not available in this environment");
            return;
        }

        let policy = Sandbox::builder()
            .fs_read("/usr")
            .fs_read("/lib")
            .fs_read_if_exists("/lib64")
            .fs_read("/bin")
            .fs_read("/etc")
            .fs_read("/proc")
            .user(0, 0)
            .build()
            .unwrap();

        let result = policy.clone().run(&["id", "-g"]).await.unwrap();
        assert!(result.success(), "id -g failed: {:?}", result.exit_status);
        let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
        assert_eq!(stdout.trim(), "0", "Expected gid 0, got: {:?}", stdout.trim());
    } else {
        let mut policy = Sandbox::builder()
            .fs_read("/usr")
            .fs_read("/lib")
            .fs_read_if_exists("/lib64")
            .fs_read("/bin")
            .fs_read("/etc")
            .fs_read("/proc")
            .user(0, 0)
            .build()
            .unwrap();
        let err = policy.run(&["id", "-g"]).await.unwrap_err();
        assert_run_as_refused(err, &run_as_refused_msg(0, 0));
    }
}

/// Test that without --user, uid is NOT 0 (assuming tests don't run as root).
#[tokio::test]
async fn test_no_uid_keeps_real_uid() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .build()
        .unwrap();

    let result = policy.clone().run(&["id", "-u"]).await.unwrap();
    assert!(result.success());
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // If running as root already, skip this check
    if unsafe { libc::getuid() } != 0 {
        assert_ne!(stdout.trim(), "0", "Without --user, uid should not be 0");
    }
}

/// Test that --user 0:0 doesn't break basic command execution (privileged) or
/// is refused fail-closed (unprivileged).
#[tokio::test]
async fn test_uid_zero_echo() {
    if euid() != 0 {
        let mut policy = Sandbox::builder()
            .fs_read("/usr")
            .fs_read("/lib")
            .fs_read_if_exists("/lib64")
            .fs_read("/bin")
            .fs_read("/etc")
            .user(0, 0)
            .build()
            .unwrap();
        let err = policy.run(&["echo", "hello"]).await.unwrap_err();
        assert_run_as_refused(err, &run_as_refused_msg(0, 0));
        return;
    }

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .user(0, 0)
        .build()
        .unwrap();

    let result = policy.clone().run(&["echo", "hello"]).await.unwrap();
    assert!(result.success());
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "hello");
}

/// Test that --user 1000:1000 maps to the expected UID inside the namespace.
///
/// Semantics depend on the supervisor's privilege (task S1.2):
/// * privileged (root): `RunAs` is the HOST identity — inside the namespace
///   the process is uid 0 (single-entry map `0 -> host_uid`);
/// * unprivileged: a different host uid cannot be mapped (single-entry map
///   only covers the caller's own euid), so the request is **refused** at
///   spawn (fail-closed) instead of silently running with the caller's uid.
#[tokio::test]
async fn test_uid_custom() {
    if euid() == 0 {
        if !userns_available() {
            eprintln!("Skipping: user namespaces not available in this environment");
            return;
        }

        let policy = Sandbox::builder()
            .fs_read("/usr")
            .fs_read("/lib")
            .fs_read_if_exists("/lib64")
            .fs_read("/bin")
            .fs_read("/etc")
            .fs_read("/proc")
            .user(1000, 1000)
            .build()
            .unwrap();

        let result = policy.clone().run(&["id", "-u"]).await.unwrap();
        assert!(result.success(), "id -u failed: {:?}", result.exit_status);
        let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
        assert_eq!(
            stdout.trim(),
            "0",
            "privileged: inside uid must be 0 (host identity 1000), got: {:?}",
            stdout.trim()
        );
    } else {
        let mut policy = Sandbox::builder()
            .fs_read("/usr")
            .fs_read("/lib")
            .fs_read_if_exists("/lib64")
            .fs_read("/bin")
            .fs_read("/etc")
            .fs_read("/proc")
            .user(1000, 1000)
            .build()
            .unwrap();
        let err = policy.run(&["id", "-u"]).await.unwrap_err();
        assert_run_as_refused(err, &run_as_refused_msg(1000, 1000));
    }
}

/// Requesting the identity the process already has must NOT create a user
/// namespace — so it works even where unprivileged userns is unavailable.
/// (No `userns_available()` guard on purpose: this exercises the skip path.)
#[tokio::test]
async fn test_user_matching_runtime_skips_userns() {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .user(uid, gid)
        .build()
        .unwrap();

    let result = policy.clone().run(&["echo", "hi"]).await.unwrap();
    assert!(
        result.success(),
        "matching-identity user() should skip the userns and run cleanly: {:?}",
        result.exit_status
    );
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "hi");
}
