//! Integration tests for the per-sandbox control socket (RFC #68).
//!
//! These tests exercise the control-socket wire protocol by starting a real
//! sandbox via the CLI binary and querying its `config` verb, verifying that
//! the effective policy returned matches the sandbox's configured policy.

use std::ffi::CString;
use std::process::Command;
use std::time::Duration;

/// Locate the sandlock binary.  We're in sandlock-core's tests, so
/// CARGO_BIN_EXE_sandlock is not available; find it relative to the
/// current executable's location.
fn sandlock_bin() -> Command {
    // Point every CLI child at the per-process control root so subprocess and
    // in-process lookups agree.
    isolate_ctl_root();
    // The test binary is in target/release/deps/; go up two levels to
    // the workspace root, then into target/release/sandlock.
    let exe = std::env::current_exe().expect("current_exe");
    let deps_dir = exe.parent().expect("parent of test binary");
    let target_dir = deps_dir.parent().expect("parent of deps dir");
    let sandlock_path = target_dir.join("sandlock");
    if sandlock_path.exists() {
        return Command::new(&sandlock_path);
    }
    // Fallback: assume workspace root is grandparent of target_dir.
    let workspace_root = target_dir.parent().expect("parent of target dir");
    let alt_path = workspace_root.join("target/release/sandlock");
    if alt_path.exists() {
        return Command::new(&alt_path);
    }
    Command::new("sandlock")
}

/// Start a sandbox running `sleep 30`, wait for it to appear in `ps`,
/// return the name. The caller should kill it.
fn start_sleep_sandbox(name: &str) -> std::process::Child {
    let has_lib64 = std::path::Path::new("/lib64").exists();
    let mut args: Vec<String> = vec![
        "run".into(), "--name".into(), name.into(),
        "-r".into(), "/usr".into(), "-r".into(), "/lib".into(),
        "-r".into(), "/bin".into(), "-r".into(), "/etc".into(),
        "-r".into(), "/proc".into(), "-r".into(), "/dev".into(),
        "--".into(), "/bin/sleep".into(), "30".into(),
    ];
    if has_lib64 {
        // Insert -r /lib64 before -r /bin.  Find the -r before /bin.
        let pos = args.iter().position(|s| s == "/bin").unwrap();
        // pos points to "/bin"; the "-r" is at pos-1.
        args.insert(pos - 1, "/lib64".into());
        args.insert(pos - 1, "-r".into());
    }
    sandlock_bin()
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sandlock")
}

/// Read stderr from a child process (if available).
fn child_stderr(child: &mut std::process::Child) -> String {
    use std::io::Read;
    let mut s = String::new();
    if let Some(ref mut stderr) = child.stderr {
        let _ = stderr.read_to_string(&mut s);
    }
    s
}

/// Poll `sandlock ps` until `name` appears, or timeout.
fn wait_for_sandbox(name: &str) -> Result<(), String> {
    for _ in 0..20 {
        let out = sandlock_bin()
            .args(["ps"])
            .output()
            .expect("sandlock ps");
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains(name) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!("sandbox '{}' did not appear in ps", name))
}

#[test]
fn test_control_list_sandboxes_via_cli() {
    let name = format!("test-ctrl-list-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin()
                .args(["ps"])
                .output()
                .expect("sandlock ps");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains(&name),
                "ps should contain sandbox name '{}':\n{}",
                name, stdout
            );
            assert!(
                stdout.contains("NAME") && stdout.contains("PID") && stdout.contains("UPTIME"),
                "ps should have column headers: {}",
                stdout
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_control_inspect_returns_policy_via_cli() {
    let name = format!("test-ctrl-config-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin()
                .args(["inspect", &name])
                .output()
                .expect("sandlock inspect");
            assert!(
                out.status.success(),
                "inspect should succeed: stderr={}",
                String::from_utf8_lossy(&out.stderr)
            );
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains("filesystem"),
                "inspect JSON should contain 'filesystem': {}",
                stdout
            );
            assert!(
                stdout.contains("/usr"),
                "inspect JSON should contain /usr: {}",
                stdout
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_control_inspect_nonexistent_sandbox() {
    let out = sandlock_bin()
        .args(["inspect", "nonexistent-sandbox-xyz-99999"])
        .output()
        .expect("sandlock inspect");
    assert!(!out.status.success(), "inspect for nonexistent sandbox should fail");
}

#[test]
fn test_control_unknown_verb() {
    // We can't test unknown verbs via the CLI (it only sends "config"),
    // so test via the core API directly.
    let result = sandlock_core::control::send_control_request(
        "nonexistent-sandbox-xyz-99999",
        "nonexistent_verb",
        serde_json::Value::Object(Default::default()),
    );
    // Should fail because the sandbox doesn't exist (not because of the verb).
    assert!(result.is_err(), "should error for nonexistent sandbox");
}

#[test]
fn test_control_prunes_stale_dirs_via_cli() {
    let name = format!("test-ctrl-prune-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let dir = sandlock_core::control::sandbox_dir(&name);
            assert!(dir.exists(), "runtime dir should exist: {:?}", dir);

            // Read the child PID from the pid file (first line only; the file
            // is child_pid\nsupervisor_pid\nstarttime\n — the extra identity
            // line is ignored here).
            let pid_file = sandlock_core::control::pid_path(&dir);
            let child_pid: i32 = std::fs::read_to_string(&pid_file)
                .unwrap()
                .lines()
                .next()
                .and_then(|l| l.trim().parse().ok())
                .expect("first line of pid file should be child PID");

            // Kill the supervisor process (SIGKILL — no Drop cleanup).
            child.kill().expect("kill supervisor");
            child.wait().expect("wait supervisor");

            // Also kill the sandboxed child (sleep), otherwise kill(pid,0)
            // still sees it as alive.
            unsafe { libc::kill(child_pid, libc::SIGKILL) };

            // Wait a moment for the child to die.
            std::thread::sleep(std::time::Duration::from_millis(500));

            // The stale dir may or may not still exist (depends on whether
            // the supervisor's Drop ran before SIGKILL was delivered).
            // Either way, list_live_sandboxes should not list this sandbox
            // and the dir should be gone after pruning.
            let sandboxes = sandlock_core::control::list_live_sandboxes().unwrap();
            assert!(
                !sandboxes.iter().any(|(n, _)| n == &name),
                "sandbox should not be listed after kill (pruned): {:?}",
                sandboxes
            );

            // The stale dir should be gone after pruning.
            assert!(!dir.exists(), "stale dir should be pruned: {:?}", dir);
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }
}

#[test]
fn test_control_runtime_dir_paths() {
    isolate_ctl_root();
    let dir = sandlock_core::control::sandbox_dir("test-xyz");
    let s = dir.to_string_lossy();
    // SL-7: the dir name is the name's FNV-1a hash, never the raw name, and
    // the whole tree lives under the per-uid control root (not /dev/shm).
    assert!(
        !s.contains("test-xyz"),
        "hashed dir must not contain the raw name: {}",
        s
    );
    let other = sandlock_core::control::sandbox_dir("another");
    let root = other.parent().unwrap();
    assert_eq!(dir.parent(), Some(root), "dir must live under the state root");
    let file_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    assert!(file_name.ends_with(".d"), "dir should end in .d: {}", file_name);
    let stem = file_name.trim_end_matches(".d");
    assert_eq!(stem.len(), 16, "hash stem should be 16 hex chars: {}", stem);
    assert!(
        stem.chars().all(|c| c.is_ascii_hexdigit()),
        "hash stem should be hex: {}",
        stem
    );

    let pid_file = sandlock_core::control::pid_path(&dir);
    assert_eq!(pid_file.file_name().unwrap(), "pid");

    let token_file = dir.join("token");
    assert_eq!(token_file.file_name().unwrap(), "token");

    let name_file = dir.join("name");
    assert_eq!(name_file.file_name().unwrap(), "name");

    let sock = sandlock_core::control::sock_path(&dir);
    assert_eq!(sock.file_name().unwrap(), "control.sock");
}

#[test]
fn test_control_sandbox_to_profile() {
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_write("/tmp")
        .fs_deny("/etc/shadow")
        .build()
        .unwrap();

    let profile = sandlock_core::profile::sandbox_to_profile(&sb, &[]);

    let read = &profile.filesystem.read;
    assert!(read.contains(&std::path::PathBuf::from("/usr")));
    assert!(read.contains(&std::path::PathBuf::from("/bin")));

    let write = &profile.filesystem.write;
    assert!(write.contains(&std::path::PathBuf::from("/tmp")));

    let deny = &profile.filesystem.deny;
    assert!(deny.contains(&std::path::PathBuf::from("/etc/shadow")));
}

#[test]
fn test_control_mode_stays_out_of_profile() {
    // The mode marker is ps metadata, not policy: inspect output (a
    // ProfileInput) must not carry it.
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .mode("learn")
        .build()
        .unwrap();

    let toml_str = sandlock_core::profile::sandbox_to_toml(&sb, &[]).unwrap();
    assert!(!toml_str.contains("mode"), "mode leaked into profile: {toml_str}");
}

#[test]
fn test_control_sandbox_mode_absent_for_plain_runs() {
    assert_eq!(sandlock_core::control::sandbox_mode("no-such-sandbox-mode"), None);
}

#[test]
fn test_control_sandbox_to_profile_dedups_net_rules() {
    // "*" expands to tcp://* + udp://* at parse time, so the explicit
    // udp://* renders as a duplicate spec.
    let sb = sandlock_core::Sandbox::builder()
        .net_allow("*")
        .net_allow("udp://*")
        .net_allow("icmp://*")
        .build()
        .unwrap();

    let profile = sandlock_core::profile::sandbox_to_profile(&sb, &[]);
    let allow = &profile.network.allow;
    let unique: std::collections::HashSet<&String> = allow.iter().collect();
    assert_eq!(allow.len(), unique.len(), "duplicate net rules in {allow:?}");
    assert!(allow.contains(&"udp://*".to_string()));
    assert!(allow.contains(&"icmp://*".to_string()));
}

#[test]
fn test_control_sandbox_to_profile_merges_dynamic_denies() {
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_deny("/etc/shadow")
        .build()
        .unwrap();

    let extra = vec!["/etc/passwd".to_string(), "/tmp/secret".to_string()];
    let profile = sandlock_core::profile::sandbox_to_profile(&sb, &extra);

    let deny = &profile.filesystem.deny;
    assert!(deny.contains(&std::path::PathBuf::from("/etc/shadow")));
    assert!(deny.contains(&std::path::PathBuf::from("/etc/passwd")));
    assert!(deny.contains(&std::path::PathBuf::from("/tmp/secret")));
}

#[test]
fn test_control_sandbox_to_toml_roundtrip() {
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let toml_str = sandlock_core::profile::sandbox_to_toml(&sb, &[]).unwrap();
    assert!(!toml_str.is_empty(), "TOML output should not be empty");
    assert!(toml_str.contains("[filesystem]"), "TOML should have [filesystem] section");
    assert!(toml_str.contains("/usr"), "TOML should contain /usr");

    let reparsed: sandlock_core::ProfileInput = toml::from_str(&toml_str)
        .expect("TOML should re-parse");
    assert!(
        reparsed.filesystem.read.contains(&std::path::PathBuf::from("/usr")),
        "re-parsed profile should contain /usr in read"
    );
}

#[test]
fn test_control_sandbox_to_json() {
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let json_str = sandlock_core::profile::sandbox_to_json(&sb, &[]).unwrap();
    assert!(!json_str.is_empty(), "JSON output should not be empty");

    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .expect("JSON should parse");
    let fs = parsed.get("filesystem").expect("should have filesystem");
    let read = fs.get("read").and_then(|r| r.as_array())
        .expect("filesystem.read should be an array");
    assert!(
        read.iter().any(|v| v.as_str() == Some("/usr")),
        "filesystem.read should contain /usr"
    );
}

// ============================================================
// Name collision, --no-supervisor, control_socket=false, ports
// ============================================================

#[test]
fn test_control_name_collision() {
    let name = format!("test-ctrl-collision-{}", std::process::id());
    let mut first = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin()
                .args([
                    "run", "--name", &name,
                    "-r", "/usr", "-r", "/bin", "-r", "/etc",
                    "-r", "/proc", "-r", "/dev",
                    "--", "/bin/sleep", "5",
                ])
                .output()
                .expect("sandlock run (collision)");
            assert!(
                !out.status.success(),
                "second sandbox with same name must fail"
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("already running"),
                "error should indicate name collision: {}",
                stderr
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut first);
            let _ = first.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = first.kill();
    let _ = first.wait();
}

#[test]
fn test_control_name_collision_no_supervisor() {
    // The no_supervisor path shares setup_runtime_dir_no_socket and must
    // hard-fail on a live-name collision just like the supervisor path;
    // continuing would leave a second sandbox running invisible to ps.
    let name = format!("test-ctrl-collision-nosup-{}", std::process::id());
    let mut first = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin()
                .args([
                    "run", "--name", &name, "--no-supervisor",
                    "-r", "/usr", "-r", "/bin", "-r", "/etc",
                    "-r", "/proc", "-r", "/dev",
                    "--", "/bin/sleep", "5",
                ])
                .output()
                .expect("sandlock run --no-supervisor (collision)");
            assert!(
                !out.status.success(),
                "no_supervisor sandbox with a live name must fail"
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("already running"),
                "error should indicate name collision: {}",
                stderr
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut first);
            let _ = first.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = first.kill();
    let _ = first.wait();
}

#[test]
fn test_control_no_supervisor() {
    let name = format!("test-ctrl-nosup-{}", std::process::id());
    let has_lib64 = std::path::Path::new("/lib64").exists();
    let mut args: Vec<&str> = vec![
        "run", "--name", &name, "--no-supervisor",
        "-r", "/usr", "-r", "/bin", "-r", "/lib",
        "-r", "/etc", "-r", "/proc", "-r", "/dev",
    ];
    if has_lib64 {
        args.push("-r");
        args.push("/lib64");
    }
    args.push("--");
    args.push("/bin/sleep");
    args.push("30");

    let mut child = sandlock_bin()
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sandlock --no-supervisor");

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin().args(["ps"]).output().expect("sandlock ps");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains(&name),
                "ps should list --no-supervisor sandbox: {}",
                stdout
            );
            assert!(
                stdout.contains("PORTS"),
                "ps should have PORTS column: {}",
                stdout
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_control_socket_disabled() {
    // control_socket = false is a builder field, not a CLI flag.
    // The sandbox runs without binding the control socket — the pid file
    // is still written (via setup_runtime_dir_no_socket) so ps still sees
    // it, but config/ports/kill via the socket fail gracefully.
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .control_socket(false)
        .build()
        .unwrap();
    assert!(
        !sb.control_socket,
        "control_socket should be false"
    );

    // Also test the default (true).
    let sb2 = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .build()
        .unwrap();
    assert!(
        sb2.control_socket,
        "control_socket should default to true"
    );
}

#[test]
fn test_control_ports_verb() {
    let name = format!("test-ctrl-ports-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let resp = sandlock_core::control::send_control_request(
                &name,
                "ports",
                serde_json::Value::Object(Default::default()),
            );
            match resp {
                Ok(r) => {
                    assert!(r.ok, "ports verb should succeed: {:?}", r.err);
                    // With no port forwarding configured, the map should be empty.
                    if let Some(data) = r.data {
                        let map: std::collections::HashMap<u16, u16> =
                            serde_json::from_value(data).unwrap_or_default();
                        assert!(
                            map.is_empty(),
                            "ports map should be empty when no port forwarding configured"
                        );
                    }
                }
                Err(e) => {
                    panic!("ports verb failed: {}", e);
                }
            }
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_control_ps_ports_column() {
    let name = format!("test-ctrl-psports-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin().args(["ps"]).output().expect("sandlock ps");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains("PORTS"),
                "ps header should contain PORTS column: {}",
                stdout
            );
            assert!(
                stdout.contains(&name),
                "ps should list sandbox: {}",
                stdout
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn test_control_invalid_names() {
    isolate_ctl_root();
    // Names that are not clean single tokens must be rejected at spawn time
    // (sandbox_resolve_name → sandbox_validate_name): the name is the
    // uid-wide key that hashes to a state-dir slot and is displayed verbatim
    // by `sandlock ps`.
    for bad in &["/", "..", ".", "a/b", "../etc"] {
        let result = sandlock_core::Sandbox::builder()
            .fs_read("/usr")
            .fs_read("/bin")
            .fs_read("/lib")
            .fs_read_if_exists("/lib64")
            .fs_read("/proc")
            .build()
            .unwrap()
            .with_name(*bad)
            .run(&["true"])
            .await;
        assert!(
            result.is_err(),
            "sandbox name {:?} should be rejected", bad
        );
    }

    // sandbox_dir maps any name through the hash, so even an unvalidated
    // ".." cannot escape the state root; validation still matters for the
    // name-key/metadata contract, but path safety no longer depends on it.
    let dir = sandlock_core::control::sandbox_dir("..");
    let dir_str = dir.to_string_lossy();
    assert!(
        !dir_str.ends_with(".."),
        "sandbox_dir('..') must hash the name, never append it: {}",
        dir_str
    );
    assert!(
        dir_str.ends_with(".d"),
        "sandbox_dir('..') must still map to a hashed dir: {}",
        dir_str
    );
}

// ============================================================
// CLI kill / config input validation
// ============================================================

#[test]
fn test_control_cli_kill_rejects_bad_names() {
    for bad in &["..", ".", "a/b", "/dev/shm"] {
        let out = sandlock_bin()
            .args(["kill", bad])
            .output()
            .expect("sandlock kill");
        assert!(
            !out.status.success(),
            "sandlock kill {:?} should fail", bad
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("must not"),
            "kill {:?} should produce a validation error, got: {}",
            bad, stderr
        );
    }
}

#[test]
fn test_control_cli_inspect_rejects_bad_names() {
    for bad in &["..", ".", "a/b"] {
        let out = sandlock_bin()
            .args(["inspect", bad])
            .output()
            .expect("sandlock inspect");
        assert!(
            !out.status.success(),
            "sandlock inspect {:?} should fail", bad
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("must not"),
            "inspect {:?} should produce a validation error, got: {}",
            bad, stderr
        );
    }
}

#[test]
fn test_control_cli_kill_nonexistent() {
    let out = sandlock_bin()
        .args(["kill", "nonexistent-sandbox-xyz-99999"])
        .output()
        .expect("sandlock kill");
    assert!(
        !out.status.success(),
        "kill nonexistent sandbox should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no sandbox named") || stderr.contains("not running"),
        "kill nonexistent should say 'no sandbox named', got: {}",
        stderr
    );
}

// ============================================================
// pid file format — three lines (child/supervisor/starttime); single-line
// leftovers are pruned
// ============================================================

#[test]
fn test_control_single_line_pid_file_is_pruned() {
    isolate_ctl_root();
    let dir = sandlock_core::control::sandbox_dir("test-single-line-pid");
    std::fs::create_dir_all(&dir).expect("create test dir");

    // Write a pid file with only one line — the format that never shipped.
    let pid_path = sandlock_core::control::pid_path(&dir);
    std::fs::write(&pid_path, "12345\n").expect("write single-line pid file");

    // Set the dir mtime to >2s ago so the recency check allows pruning.
    // list_live_sandboxes won't prune dirs modified less than 2s ago
    // (concurrent setup protection).
    let old_time = libc::timespec {
        tv_sec: 1000, // Unix epoch + 1000s — ancient
        tv_nsec: 0,
    };
    let times = [old_time, old_time];
    let dir_cstr = CString::new(dir.to_str().unwrap()).expect("valid C string");
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            dir_cstr.as_ptr(),
            times.as_ptr(),
            0,
        )
    };
    assert_eq!(rc, 0, "utimensat failed on {:?}", dir);

    // list_live_sandboxes must prune this dir (supervisor_pid parse fails
    // and the mtime is old).
    let sandboxes = sandlock_core::control::list_live_sandboxes()
        .expect("list_live_sandboxes");
    assert!(
        !sandboxes.iter().any(|(n, _)| n == "test-single-line-pid"),
        "single-line pid dir should not be listed, got: {:?}",
        sandboxes
    );
    assert!(
        !dir.exists(),
        "single-line pid dir should be pruned"
    );
}

// ============================================================
// SL-7 (fork-plan-2026-09 F1.3): control-channel auth + identity
// ============================================================
//
// The control state root is per-uid, owner-only, and hashed per sandbox
// name.  These tests pin the F1.3 contract:
//
//  * `config`/`ports` (sensitive verbs) are refused without a token match
//    and the connection is closed after the refusal;
//  * a sibling sandbox can neither enumerate the control root nor read
//    another sandbox's policy (EACCES/ECONNREFUSED/ENOENT everywhere);
//  * a same-name create refuses to preempt a live (but pid-file-less)
//    sandbox's directory.
//
// `SANDBOX_CTL_ROOT` points every process (this test binary and the CLI
// children it spawns) at a per-process root under /tmp, so these tests never
// collide with other suites sharing the container.  Today's /dev/shm root is
// also probed so the sibling test stays red against the pre-fix layout.
fn isolate_ctl_root() -> std::path::PathBuf {
    static SET: std::sync::Once = std::sync::Once::new();
    let root = std::path::PathBuf::from(format!(
        "/tmp/sandlock-ctl-test-{}",
        std::process::id()
    ));
    SET.call_once(|| {
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var("SANDBOX_CTL_ROOT", root.as_os_str());
    });
    root
}

/// Connect a raw (framework-less) client to a sandbox's control socket so a
/// test can send requests the way an attacker would — including requests
/// without the identity token.
fn raw_connect(name: &str) -> Result<std::os::unix::net::UnixStream, String> {
    let dir = sandlock_core::control::sandbox_dir(name);
    let sp = sandlock_core::control::sock_path(&dir);
    let stream = std::os::unix::net::UnixStream::connect(&sp)
        .map_err(|e| format!("connect to {:?}: {}", sp, e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("set_write_timeout: {}", e))?;
    Ok(stream)
}

/// Send one raw length-prefixed JSON request with an optional `token` field
/// and return the parsed response.
fn raw_send(
    stream: &mut std::os::unix::net::UnixStream,
    verb: &str,
    token: Option<&str>,
) -> Result<sandlock_core::control::ControlResponse, String> {
    use std::io::{Read, Write};

    let mut obj = serde_json::Map::new();
    obj.insert("v".into(), serde_json::Value::from(1));
    obj.insert("verb".into(), serde_json::Value::from(verb));
    obj.insert("args".into(), serde_json::Value::Object(Default::default()));
    if let Some(t) = token {
        obj.insert("token".into(), serde_json::Value::from(t));
    }
    let body = serde_json::to_vec(&serde_json::Value::Object(obj))
        .map_err(|e| format!("serialize request: {}", e))?;

    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(|e| format!("write len: {}", e))?;
    stream.write_all(&body).map_err(|e| format!("write body: {}", e))?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| format!("read len: {}", e))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 65536 {
        return Err("response too large".to_string());
    }
    let mut resp_body = vec![0u8; resp_len];
    stream.read_exact(&mut resp_body).map_err(|e| format!("read body: {}", e))?;
    serde_json::from_slice(&resp_body).map_err(|e| format!("parse response: {}", e))
}

/// `config` and `ports` are sensitive verbs: a peer that presents no token
/// (or the wrong one) must be refused explicitly, not served the sandbox's
/// full policy.
#[test]
fn test_verb_without_token_rejected() {
    isolate_ctl_root();
    let name = format!("test-ctrl-notoken-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let mut stream = raw_connect(&name).expect("connect to control socket");
            let resp = raw_send(&mut stream, "config", None).expect("send config request");
            assert!(
                !resp.ok,
                "config without token must be rejected, got: {:?}",
                resp
            );
            let err = resp.err.as_deref().unwrap_or_default();
            assert!(
                err.contains("token"),
                "config denial must name the token requirement, got: {}",
                err
            );

            let mut stream = raw_connect(&name).expect("connect to control socket (ports)");
            let resp = raw_send(&mut stream, "ports", None).expect("send ports request");
            assert!(
                !resp.ok,
                "ports without token must be rejected, got: {:?}",
                resp
            );
            let err = resp.err.as_deref().unwrap_or_default();
            assert!(
                err.contains("token"),
                "ports denial must name the token requirement, got: {}",
                err
            );

            // Positive control: the same verbs succeed when the client
            // presents the token from the sandbox's runtime dir — proving the
            // rejection is token-based and not a broken socket.
            match sandlock_core::control::send_control_request(
                &name,
                "ports",
                serde_json::Value::Object(Default::default()),
            ) {
                Ok(r) => {
                    assert!(
                        r.ok,
                        "token-authenticated ports must succeed: {:?}",
                        r.err
                    );
                }
                Err(e) => panic!("token-authenticated ports request failed: {}", e),
            }
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

/// Peer-uid mismatch must close the connection rather than eprintln-and-serve.
///
/// Degraded form (documented in the F1.3 report): a true cross-uid peer
/// cannot be constructed inside the non-root gate — an unprivileged
/// supervisor's single-entry user-namespace map can only cover its own euid,
/// so no sandbox or child can present a different uid to SO_PEERCRED.  This
/// test pins the strongest expressible shape instead: the runtime dir and
/// token file are owner-only (0700/0600, so any other uid is stopped by the
/// kernel before the socket), and a peer that reaches the socket without the
/// matching token is refused with the connection closed afterwards.
#[test]
fn test_peer_uid_mismatch_closes() {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    isolate_ctl_root();
    let name = format!("test-ctrl-peerauth-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let dir = sandlock_core::control::sandbox_dir(&name);
            let my_uid = unsafe { libc::getuid() };

            let dir_meta = std::fs::metadata(&dir).expect("runtime dir metadata");
            assert_eq!(
                dir_meta.uid(),
                my_uid,
                "runtime dir must be owned by the sandbox's uid: {:?}",
                dir
            );
            assert_eq!(
                dir_meta.mode() & 0o777,
                0o700,
                "runtime dir must be owner-only (0700): {:?}",
                dir
            );

            let token_file = dir.join("token");
            let token_meta =
                std::fs::metadata(&token_file).expect("token file metadata");
            assert_eq!(
                token_meta.uid(),
                my_uid,
                "token file must be owned by the sandbox's uid: {:?}",
                token_file
            );
            assert_eq!(
                token_meta.mode() & 0o777,
                0o600,
                "token file must be owner-only (0600): {:?}",
                token_file
            );
            let token = std::fs::read_to_string(&token_file)
                .expect("read token file")
                .trim()
                .to_string();
            assert!(!token.is_empty(), "token must not be empty");

            // Wrong token: explicitly refused, then the connection is closed
            // (the next read sees EOF).
            let wrong = "0".repeat(token.len());
            let mut stream = raw_connect(&name).expect("connect with wrong token");
            let resp = raw_send(&mut stream, "config", Some(&wrong))
                .expect("send config with wrong token");
            assert!(
                !resp.ok,
                "config with a wrong token must be rejected, got: {:?}",
                resp
            );
            let err = resp.err.as_deref().unwrap_or_default();
            assert!(
                err.contains("token"),
                "wrong-token denial must name the token requirement, got: {}",
                err
            );
            let mut buf = [0u8; 4];
            let n = stream.read(&mut buf).expect("read after denial");
            assert_eq!(
                n, 0,
                "server must close the connection after a token mismatch"
            );

            // Missing token on the protected verb: same refusal.
            let mut stream = raw_connect(&name).expect("connect without token");
            let resp = raw_send(&mut stream, "ports", None).expect("send ports without token");
            assert!(
                !resp.ok,
                "ports without token must be rejected, got: {:?}",
                resp
            );
            assert!(
                resp.err.as_deref().unwrap_or_default().contains("token"),
                "no-token denial must name the token requirement, got: {:?}",
                resp.err
            );

            // Matching token (positive control): the same uid owner is served.
            match sandlock_core::control::send_control_request(
                &name,
                "config",
                serde_json::Value::Object(Default::default()),
            ) {
                Ok(r) => {
                    assert!(
                        r.ok,
                        "token-authenticated config must succeed: {:?}",
                        r.err
                    );
                }
                Err(e) => panic!("token-authenticated config request failed: {}", e),
            }
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

/// Two sandboxes coexist: a sibling sandbox (A) must not be able to read the
/// other sandbox's (B's) control socket/policy.  A grants itself write access
/// to /dev/shm (the E2B rootfs shape that makes today's /dev/shm control root
/// reachable — a plain read-only /dev grant already fails connect() on the
/// socket inode, so it cannot demonstrate the leak).  A probes both the F1.3
/// state root and the pre-fix /dev/shm root so the test is red against
/// today's layout and stays meaningful after the move.  Any enumeration or
/// successful connect that yields `ok:true` from `config` is a policy leak
/// and fails the probe.
#[test]
fn test_sibling_sandbox_cannot_read_other_policy() {
    isolate_ctl_root();
    let name_b = format!("test-ctrl-sibling-b-{}", std::process::id());
    let mut child_b = start_sleep_sandbox(&name_b);

    match wait_for_sandbox(&name_b) {
        Ok(()) => {
            let dir_b = sandlock_core::control::sandbox_dir(&name_b);
            assert!(dir_b.exists(), "sibling B runtime dir should exist: {:?}", dir_b);

            let root = isolate_ctl_root();
            let name_a = format!("test-ctrl-sibling-a-{}", std::process::id());
            let script = r#"import os, socket, struct, sys

def fnv1a_hex(name):
    h = 0xcbf29ce484222325
    for b in name.encode():
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return "%016x" % h

name = sys.argv[2]
roots = [sys.argv[1], "/dev/shm/sandlock-%d" % os.getuid()]
for root in roots:
    try:
        names = os.listdir(root)
    except PermissionError:
        print("ENUM %s EACCES" % root)
        continue
    except FileNotFoundError:
        print("ENUM %s ENOENT" % root)
        continue
    except OSError as e:
        print("ENUM %s %r" % (root, e))
        sys.exit(9)
    print("ENUM %s OK %r" % (root, names))
    candidates = [
        os.path.join(root, name, "control.sock"),
        os.path.join(root, fnv1a_hex(name) + ".d", "control.sock"),
    ]
    for sock in candidates:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.settimeout(2)
            s.connect(sock)
        except PermissionError:
            print("CONNECT %s EACCES" % sock)
            continue
        except ConnectionRefusedError:
            print("CONNECT %s ECONNREFUSED" % sock)
            continue
        except FileNotFoundError:
            print("CONNECT %s ENOENT" % sock)
            continue
        except OSError as e:
            print("CONNECT %s %r" % (sock, e))
            sys.exit(10)
        print("CONNECT %s OK" % sock)
        req = b'{"v":1,"verb":"config","args":{}}'
        try:
            s.sendall(struct.pack(">I", len(req)) + req)
            lb = s.recv(4)
            if len(lb) != 4:
                print("CONFIG %s CLOSED %r" % (sock, lb))
                continue
            (n,) = struct.unpack(">I", lb)
            resp = b""
            while len(resp) < n:
                chunk = s.recv(n - len(resp))
                if not chunk:
                    break
                resp += chunk
            print("CONFIG %s %r" % (sock, resp[:160]))
            if b'"ok":true' in resp:
                print("POLICY LEAK %s" % sock)
                sys.exit(11)
        except OSError as e:
            print("CONFIG %s %r" % (sock, e))
print("PROBE PASS")
sys.exit(0)
"#
            .to_string();

            let has_lib64 = std::path::Path::new("/lib64").exists();
            let mut args: Vec<String> = vec![
                "run".into(),
                "--name".into(),
                name_a.clone(),
                "-r".into(),
                "/usr".into(),
            ];
            if has_lib64 {
                args.push("-r".into());
                args.push("/lib64".into());
            }
            args.extend([
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
                "/dev/shm".into(),
                "--".into(),
                "python3".into(),
                "-B".into(),
                "-c".into(),
                script,
                root.display().to_string(),
                name_b.clone(),
            ]);

            let out = sandlock_bin()
                .args(&args)
                .output()
                .expect("run sibling probe sandbox");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                out.status.success(),
                "sibling probe must exit 0 (no policy leak); stdout:\n{}\nstderr:\n{}",
                stdout, stderr
            );
            assert!(
                stdout.contains("PROBE PASS"),
                "sibling probe must complete cleanly; stdout:\n{}\nstderr:\n{}",
                stdout, stderr
            );

            // Positive control: B itself is unaffected and still serves its
            // own uid's token-authenticated requests.
            match sandlock_core::control::send_control_request(
                &name_b,
                "ports",
                serde_json::Value::Object(Default::default()),
            ) {
                Ok(r) => {
                    assert!(
                        r.ok,
                        "sandbox B must still serve its owner after the sibling probe: {:?}",
                        r.err
                    );
                }
                Err(e) => panic!("sandbox B control request after probe failed: {}", e),
            }
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child_b);
            let _ = child_b.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child_b.kill();
    let _ = child_b.wait();
}

/// Spawn a same-name sandbox and require it to exit quickly with a refusal
/// (rather than starting after preempting the live dir).
fn spawn_and_expect_refused(name: &str) {
    let mut second = start_sleep_sandbox(name);
    let mut exited = None;
    for _ in 0..40 {
        if let Some(status) = second.try_wait().expect("try_wait on second sandbox") {
            exited = Some(status);
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    let status = match exited {
        Some(status) => status,
        None => {
            let _ = second.kill();
            let _ = second.wait();
            panic!(
                "second create with the same name preempted the live sandbox \
                 instead of refusing (it is still running)"
            );
        }
    };
    assert!(
        !status.success(),
        "second sandbox with the same name must fail"
    );
    let stderr = child_stderr(&mut second);
    assert!(
        stderr.contains("already running"),
        "refusal should say 'already running': {}",
        stderr
    );
}

/// Assert the first sandbox's runtime dir survived a refused same-name create
/// and its token-authenticated control socket still serves.
fn assert_first_sandbox_intact(name: &str, dir: &std::path::Path) {
    assert!(dir.exists(), "first sandbox dir must survive: {:?}", dir);
    let sock = sandlock_core::control::sock_path(dir);
    assert!(sock.exists(), "first sandbox socket must survive: {:?}", sock);
    match sandlock_core::control::send_control_request(
        name,
        "config",
        serde_json::Value::Object(Default::default()),
    ) {
        Ok(r) => {
            assert!(
                r.ok,
                "first sandbox must still serve config after the refused create: {:?}",
                r.err
            );
        }
        Err(e) => {
            panic!(
                "first sandbox control request after refused create failed: {}",
                e
            );
        }
    }
}

/// A second create with a live sandbox's name must refuse — never preempt.
/// The preemption trigger is a live sandbox whose pid file is unreadable (a
/// torn write / lost file): today's code treats that as dead and
/// `remove_dir_all`s the live dir; the fix must refuse because the dir cannot
/// be proven stale, and the first sandbox's directory must survive intact.
///
/// Both pid-less dir ages are pinned: freshly modified (<2s, the recency
/// window) and backdated past it (>2s — the classifier must not reclaim a
/// pid-less dir at create time just because it looks old; only `sandlock ps`
/// pruning may reclaim such debris).
#[test]
fn test_name_conflict_refuses_preempt() {
    isolate_ctl_root();
    let name = format!("test-ctrl-nopreempt-{}", std::process::id());
    let mut first = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let dir = sandlock_core::control::sandbox_dir(&name);
            let pid_file = sandlock_core::control::pid_path(&dir);
            let original_pid = std::fs::read_to_string(&pid_file)
                .expect("read first sandbox pid file");
            let child_pid: i32 = original_pid
                .lines()
                .next()
                .and_then(|l| l.trim().parse().ok())
                .expect("first line of pid file should be child PID");
            // Simulate the unreadable-pid-file condition while the supervisor
            // is demonstrably still alive (it serves control requests below).
            std::fs::remove_file(&pid_file).expect("remove first sandbox pid file");

            // Variant 1: pid-less dir freshly modified (inside the 2s recency
            // window).  Same-name create must refuse and the live dir must
            // survive.
            spawn_and_expect_refused(&name);
            assert_first_sandbox_intact(&name, &dir);

            // Variant 2: pid-less dir backdated ~5s — past the recency
            // window.  Create time must STILL refuse (create never reclaims a
            // pid-less dir, no matter its age); only the explicit ps pruning
            // path reclaims dead pid-less debris.
            let now = std::time::SystemTime::now();
            let old_secs = now
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_secs() as libc::time_t
                - 5;
            let old_time = libc::timespec {
                tv_sec: old_secs,
                tv_nsec: 0,
            };
            let times = [old_time, old_time];
            let dir_cstr = CString::new(dir.to_str().unwrap()).expect("valid C string");
            let rc = unsafe {
                libc::utimensat(libc::AT_FDCWD, dir_cstr.as_ptr(), times.as_ptr(), 0)
            };
            assert_eq!(rc, 0, "utimensat failed on {:?}", dir);
            let backdated = std::fs::metadata(&dir)
                .expect("dir metadata after backdate")
                .modified()
                .expect("dir mtime");
            let age = now.duration_since(backdated).expect("backdated mtime");
            assert!(
                age.as_secs() >= 4,
                "dir should be backdated past the recency window, age: {:?}",
                age
            );

            spawn_and_expect_refused(&name);
            assert_first_sandbox_intact(&name, &dir);

            // Restore the pid file (the test removed it; the supervisor never
            // rewrites it) so the sandbox stays listed and cleanly killable.
            std::fs::write(&pid_file, &original_pid).expect("restore first sandbox pid file");
            let live = sandlock_core::control::list_live_sandboxes()
                .expect("list_live_sandboxes after refused create");
            let matches: Vec<&(String, i32)> =
                live.iter().filter(|(n, _)| n == &name).collect();
            assert_eq!(
                matches.len(),
                1,
                "exactly one live sandbox named '{}' should remain, got: {:?}",
                name, live
            );
            assert_eq!(
                matches[0].1, child_pid,
                "the surviving sandbox must still be the first one (child PID {}), got: {:?}",
                child_pid, live
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut first);
            let _ = first.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = first.kill();
    let _ = first.wait();
}
