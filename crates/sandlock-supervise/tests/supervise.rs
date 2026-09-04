//! End-to-end `sandlock-supervise` binary tests (fork-plan F2b.1).
//!
//! These live in the new crate's own integration target because
//! `CARGO_BIN_EXE_sandlock-supervise` is only available there (the plan's
//! `integration/test_supervise.rs` path belongs to the core suite, which
//! cannot see this crate's binary env var).

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-supervise")
}

fn repo_tmp_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest.join("../../tmp");
    std::fs::create_dir_all(&dir).expect("create repo tmp dir");
    dir
}

fn write_policy(name: &str, body: &str) -> PathBuf {
    let path = repo_tmp_dir().join(format!("supervise-{name}-{}.json", std::process::id()));
    std::fs::write(&path, body).expect("write policy file");
    path
}

fn write_secret(name: &str) -> PathBuf {
    let path = repo_tmp_dir().join(format!("supervise-{name}-{}.secret", std::process::id()));
    std::fs::write(&path, "s3cret\n").expect("write test secret");
    path
}

fn spawn(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("spawn sandlock-supervise")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Current euid of the test process (the gate runs this suite as uid 65534).
fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

#[test]
fn test_supervise_refuses_wrong_uid() {
    // A valid (minimal) policy is provided so the refusal is attributable to
    // the uid self-check, which must run before the policy is even read.
    let policy = write_policy("wrong-uid", "{}");
    let wrong_uid = euid().wrapping_add(1);
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &wrong_uid.to_string(),
        "--control-fd",
        "2",
    ]);
    assert!(
        !out.status.success(),
        "supervise must refuse to start when euid != --uid"
    );
    let err = stderr(&out);
    assert!(
        err.contains("refusing to start") && err.contains("--uid"),
        "stderr must explain the refusal, got: {err}"
    );
    assert!(
        err.contains(&euid().to_string()) && err.contains(&wrong_uid.to_string()),
        "stderr must name both uids, got: {err}"
    );
}

#[test]
fn test_policy_roundtrip_covers_every_field() {
    // Full-field policy through the real binary: every union field is
    // provided with a distinctive value; startup must succeed only if each
    // one parsed, applied, and read back equal. Any missing/un-landed field
    // makes the binary fail and name the field.
    let secret = write_secret("roundtrip");
    let body = sandlock_supervise::policy::example_policy_json(&secret);
    let policy = write_policy("roundtrip", &body);
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        "--control-fd",
        "2",
    ]);
    let err = stderr(&out);
    assert!(
        out.status.success(),
        "full-field policy must start cleanly; stderr: {err}"
    );
    assert!(
        err.is_empty(),
        "successful startup must not write to stderr, got: {err}"
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&secret);
}

#[test]
fn test_supervise_rejects_unknown_policy_field_by_name() {
    let policy = write_policy(
        "unknown-field",
        r#"{"fs_readable": ["/usr"], "not_a_real_field": 1}"#,
    );
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        "--control-fd",
        "2",
    ]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("`not_a_real_field`"),
        "unknown field must be named, got: {err}"
    );
    let _ = std::fs::remove_file(&policy);
}

#[test]
fn test_supervise_rejects_closed_control_fd() {
    let policy = write_policy("closed-control-fd", "{}");
    // 999 is not open in a fresh test process.
    let out = spawn(&[
        "--policy",
        policy.to_str().unwrap(),
        "--uid",
        &euid().to_string(),
        "--control-fd",
        "999",
    ]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("control fd 999") && err.contains("not open"),
        "closed control fd must be refused by name, got: {err}"
    );
    let _ = std::fs::remove_file(&policy);
}
