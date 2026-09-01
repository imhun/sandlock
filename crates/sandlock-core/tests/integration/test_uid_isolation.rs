//! Per-sandbox host-uid isolation (task S1.2) integration tests.
//!
//! `RunAs` (`--user UID:GID`) is applied through a single-entry user-namespace
//! map.  When the supervisor is privileged (root in its user namespace) the
//! map is `0 -> host_uid`, so the sandbox runs as uid 0 *inside* the
//! namespace while the *host* sees the requested `RunAs` uid/gid — two
//! sandboxes with different `RunAs` uids then get kernel-enforced file and
//! unix-socket isolation (0700 owner-only + distinct host uid).  An
//! unprivileged supervisor can only map its own euid (single-entry rule), so
//! it falls back to the historical contract: the requested uid is visible
//! inside the sandbox and the host uid stays the caller's — the tests below
//! pin both contracts and gate the isolation assertions on the privileged
//! path where they are actually enforceable.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sandlock_core::{Sandbox, StdioMode};

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn unique_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sandlock-test-uid-{name}-{}", std::process::id()))
}

fn make_shared_dir(path: &Path) {
    std::fs::create_dir_all(path).expect("create shared dir");
    // World-writable so every mapped host uid can create files in it; the
    // isolation under test is the per-file/per-socket owner check, not the
    // directory.  The parent (test) cleans up afterwards as root/owner.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))
        .expect("chmod shared dir");
}

fn cleanup(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
}

fn base(dir: &Path) -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(dir)
}

/// Host (parent-namespace) real uid of a running sandboxed process, read from
/// `/proc/<pid>/status` by the test process.
async fn host_uid_of(sb: &mut Sandbox) -> u32 {
    let child = sb
        .popen(
            &["sleep", "30"],
            StdioMode::Inherit,
            StdioMode::Inherit,
            StdioMode::Inherit,
        )
        .await
        .expect("popen");
    // Dropping the Process handle leaves the child running under the Sandbox
    // (which owns it until kill/drop) and releases the &mut borrow so the
    // pid can be read.
    drop(child);
    let pid = sb.pid().expect("sandbox pid");
    let mut host = None;
    for _ in 0..100 {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            if let Some(line) = status.lines().find(|l| l.starts_with("Uid:")) {
                host = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
                if host.is_some() {
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    sb.kill().expect("kill");
    host.expect("host uid readable while sandbox runs")
}

/// Arbitrary `RunAs` uids (e.g. 10000/10001) must be representable through the
/// single-entry userns map, with both sides of the contract pinned:
///
/// * privileged supervisor: inside sees uid 0 (fake root), host sees the
///   requested uid — `RunAs` is the *host* identity;
/// * unprivileged supervisor: inside sees the requested uid, host sees the
///   caller's own uid (single-entry map can only cover the caller's euid).
#[tokio::test]
async fn test_run_as_arbitrary_uid_mapping() {
    let dir = unique_dir("map");
    make_shared_dir(&dir);

    let inside = |uid: u32, gid: u32| {
        let mut sb = base(&dir).user(uid, gid).build().unwrap();
        async move {
            let r = sb.run(&["id", "-u"]).await.unwrap();
            assert!(r.success(), "id -u failed: {:?}", r.exit_status);
            r.stdout_str().expect("stdout").to_string()
        }
    };
    let in_a = inside(10000, 10000).await;
    let in_b = inside(10001, 10001).await;

    let mut host_a = base(&dir).user(10000, 10000).build().unwrap();
    let mut host_b = base(&dir).user(10001, 10001).build().unwrap();
    let host_uid_a = host_uid_of(&mut host_a).await;
    let host_uid_b = host_uid_of(&mut host_b).await;

    if euid() == 0 {
        // Privileged path: host identity is RunAs, inside is fake root.
        assert_eq!(
            in_a, "0",
            "privileged: inside uid must be 0 (mapped), got {in_a:?}"
        );
        assert_eq!(
            in_b, "0",
            "privileged: inside uid must be 0 (mapped), got {in_b:?}"
        );
        assert_eq!(host_uid_a, 10000, "privileged: host uid must be RunAs uid");
        assert_eq!(host_uid_b, 10001, "privileged: host uid must be RunAs uid");
        assert_ne!(
            host_uid_a, host_uid_b,
            "privileged: distinct RunAs uids must yield distinct host uids"
        );
    } else {
        // Unprivileged fallback: inside sees RunAs, host stays the caller.
        assert_eq!(
            in_a, "10000",
            "unprivileged: inside uid must be RunAs uid, got {in_a:?}"
        );
        assert_eq!(
            in_b, "10001",
            "unprivileged: inside uid must be RunAs uid, got {in_b:?}"
        );
        assert_eq!(host_uid_a, euid(), "unprivileged: host uid must stay the caller's");
        assert_eq!(host_uid_b, euid(), "unprivileged: host uid must stay the caller's");
    }

    cleanup(&dir);
}

/// The PID-namespace path creates the user namespace in the *intermediate*
/// process (parent-written maps when privileged), so the same `RunAs`
/// contracts must hold there: privileged → inside uid 0 / host uid = RunAs,
/// unprivileged → inside uid = RunAs / host uid = caller's.
#[tokio::test]
async fn test_run_as_arbitrary_uid_with_pid_ns() {
    let dir = unique_dir("pidns");
    make_shared_dir(&dir);

    let inside = |uid: u32, gid: u32| {
        let mut sb = base(&dir).pid_ns(true).user(uid, gid).build().unwrap();
        async move {
            let r = sb.run(&["id", "-u"]).await.unwrap();
            assert!(r.success(), "pid-ns id -u failed: {:?}", r.exit_status);
            r.stdout_str().expect("stdout").to_string()
        }
    };
    let in_a = inside(10000, 10000).await;
    let in_b = inside(10001, 10001).await;

    if euid() == 0 {
        assert_eq!(
            in_a, "0",
            "privileged pid-ns: inside uid must be 0, got {in_a:?}"
        );
        assert_eq!(
            in_b, "0",
            "privileged pid-ns: inside uid must be 0, got {in_b:?}"
        );
    } else {
        assert_eq!(
            in_a, "10000",
            "unprivileged pid-ns: inside uid must be RunAs uid, got {in_a:?}"
        );
        assert_eq!(
            in_b, "10001",
            "unprivileged pid-ns: inside uid must be RunAs uid, got {in_b:?}"
        );
    }

    cleanup(&dir);
}

/// Two sandboxes with different `RunAs` host uids must not read each other's
/// same-path 0700 files: the kernel's owner check (not just Landlock) is the
/// isolation boundary.  The cross-sandbox assertions only hold on the
/// privileged path (distinct host uids are impossible from an unprivileged
/// supervisor, whose single-entry map can only cover its own euid).
#[tokio::test]
async fn test_run_as_distinct_host_uids_isolate_same_path_files() {
    if euid() != 0 {
        eprintln!(
            "skipping privileged isolation assertions as uid {}: an unprivileged \
             supervisor cannot give sandboxes distinct host uids",
            euid()
        );
        return;
    }

    let dir = unique_dir("files");
    make_shared_dir(&dir);
    let secret = dir.join("secret.txt");
    let secret_str = secret.display().to_string();

    // Sandbox A (host uid 10000) writes an owner-only file at the shared path.
    let write_cmd = format!("printf A-secret > {secret_str}; chmod 700 {secret_str}");
    let mut a = base(&dir).user(10000, 10000).build().unwrap();
    let wa = a.run(&["sh", "-c", &write_cmd]).await.unwrap();
    assert!(wa.success(), "sandbox A write failed: {:?}", wa.exit_status);

    // Control: a same-RunAs sandbox (host uid 10000) can read its own file.
    let mut ctrl = base(&dir).user(10000, 10000).build().unwrap();
    let rc = ctrl.run(&["cat", &secret_str]).await.unwrap();
    assert!(rc.success(), "same-uid control read failed: {:?}", rc.exit_status);
    assert_eq!(rc.stdout_str(), Some("A-secret"));

    // Sandbox B (host uid 10001) must get EACCES on the same path.
    let mut b = base(&dir).user(10001, 10001).build().unwrap();
    let rb = b.run(&["cat", &secret_str]).await.unwrap();
    assert!(!rb.success(), "cross-uid read must fail, got {:?}", rb.exit_status);
    assert_eq!(
        rb.stderr_str(),
        Some(format!("cat: {secret_str}: Permission denied").as_str()),
        "cross-uid read must be refused by the kernel owner check"
    );

    cleanup(&dir);
}

/// A unix socket bound by one sandbox must not be connectable from a sandbox
/// with a different `RunAs` host uid: the socket inode's owner check (mode
/// 0700) isolates it per uid, independently of Landlock.
#[tokio::test]
async fn test_run_as_distinct_host_uids_isolate_unix_sockets() {
    if euid() != 0 {
        eprintln!(
            "skipping privileged isolation assertions as uid {}: an unprivileged \
             supervisor cannot give sandboxes distinct host uids",
            euid()
        );
        return;
    }

    let dir = unique_dir("sock");
    make_shared_dir(&dir);
    let sock = dir.join("a.sock");
    let sock_str = sock.display().to_string();

    // Sandbox A (host uid 10000) binds an owner-only listening socket and
    // stays alive until the test kills it.
    let listen = format!(
        "import socket, os, time\n\
         s = socket.socket(socket.AF_UNIX)\n\
         s.bind('{sock_str}')\n\
         os.chmod('{sock_str}', 0o700)\n\
         s.listen(1)\n\
         time.sleep(30)\n"
    );
    let mut a = base(&dir).user(10000, 10000).build().unwrap();
    let mut listener = a
        .popen(
            &["python3", "-B", "-c", &listen],
            StdioMode::Inherit,
            StdioMode::Inherit,
            StdioMode::Inherit,
        )
        .await
        .expect("listener popen");

    // Wait for the socket node to appear (bind happens after the sandbox boots).
    let mut seen = false;
    for _ in 0..200 {
        if sock.exists() {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(seen, "listener socket node never appeared");

    // Sandbox B (host uid 10001) must fail to connect with EACCES (13).
    let probe = format!(
        "import socket\n\
         s = socket.socket(socket.AF_UNIX)\n\
         try:\n\
         \x20 s.connect('{sock_str}')\n\
         \x20 print('CONNECT_OK')\n\
         except OSError as e:\n\
         \x20 print('CONNECT_ERR', e.errno)\n"
    );
    let mut b = base(&dir).user(10001, 10001).build().unwrap();
    let rb = b.run(&["python3", "-B", "-c", &probe]).await.unwrap();
    assert_eq!(rb.stdout_str(), Some("CONNECT_ERR 13"), "cross-uid connect must get EACCES");

    // Control: a same-RunAs sandbox (host uid 10000) can connect to the socket.
    let mut ctrl = base(&dir).user(10000, 10000).build().unwrap();
    let rc = ctrl.run(&["python3", "-B", "-c", &probe]).await.unwrap();
    assert_eq!(rc.stdout_str(), Some("CONNECT_OK"), "same-uid connect must succeed");

    listener.kill().expect("kill listener");
    let _ = listener.wait().await;
    cleanup(&dir);
}
