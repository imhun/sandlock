//! F3.3 FFI surface for the exec-capable `SandboxInstance`:
//! `sandlock_instance_launch` / `_exec` / `_wait_child` / `_kill_child` /
//! `_resize_child` / `_free`.
//!
//! These drive the FFI symbols directly (no C compilation step; the pure-C
//! smoke in `c_smoke.rs` compiles the regenerated header against the cdylib)
//! and read the returned pipe fds exactly like `popen.rs` does.

use std::ffi::CString;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::os::raw::{c_char, c_int};
use std::ptr;

use sandlock_ffi::{
    sandlock_instance_exec, sandlock_instance_exec_result_t, sandlock_instance_free,
    sandlock_instance_kill_child, sandlock_instance_launch, sandlock_instance_wait_child,
    sandlock_result_exit_code, sandlock_result_free, sandlock_sandbox_build,
    sandlock_sandbox_builder_fs_read, sandlock_sandbox_builder_new, sandlock_sandbox_free,
    sandlock_sandbox_t,
};

const PIPED: u32 = 1;

/// Build a policy that can exec the usual coreutils in a minimal rootfs.
fn build_policy() -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    for p in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"] {
        if p == "/lib64" && !std::path::Path::new("/lib64").exists() {
            continue;
        }
        let c = CString::new(p).unwrap();
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    let mut err: c_int = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert_eq!(err, 0, "policy build failed");
    assert!(!policy.is_null());
    policy
}

fn argv(cmd: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
    let owned: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    (owned, ptrs)
}

/// F3.3 acceptance: an exec-capable session launched from a policy runs an
/// additional command with piped stdio, returns its own child id, and
/// `wait_child` reaps it by id — no borrowing of the originating sandbox.
#[test]
fn instance_exec_streams_stdio_and_waits_by_child_id() {
    let policy = build_policy();
    let inst = unsafe { sandlock_instance_launch(policy, ptr::null()) };
    assert!(!inst.is_null(), "instance launch returned null");

    let (_owned, av) = argv(&["/bin/sh", "-c", "printf ffi-exec"]);
    let mut out = sandlock_instance_exec_result_t {
        child_id: 0,
        pid: 0,
        stdin_fd: -1,
        stdout_fd: -1,
        stderr_fd: -1,
        pty_fd: -1,
    };
    let rc = unsafe {
        sandlock_instance_exec(inst, av.as_ptr(), av.len() as u32, PIPED, &mut out)
    };
    assert_eq!(rc, sandlock_ffi::SANDLOCK_INSTANCE_OK, "exec must succeed");
    assert!(out.child_id > 0, "exec returns a fresh child id");
    assert!(out.pid > 0, "exec returns the child pid");
    assert!(out.stdin_fd >= 0, "piped stdin fd");
    assert!(out.stdout_fd >= 0, "piped stdout fd");
    assert!(out.stderr_fd >= 0, "piped stderr fd");
    assert_eq!(out.pty_fd, -1, "no pty in piped mode");

    let mut bytes = String::new();
    unsafe { std::fs::File::from_raw_fd(out.stdout_fd) }
        .read_to_string(&mut bytes)
        .expect("read exec stdout");
    assert_eq!(bytes, "ffi-exec");

    let res = unsafe { sandlock_instance_wait_child(inst, out.child_id, 0) };
    assert!(!res.is_null(), "wait_child returned null");
    assert_eq!(unsafe { sandlock_result_exit_code(res) }, 0);

    unsafe {
        sandlock_result_free(res);
        sandlock_instance_free(inst);
        sandlock_sandbox_free(policy);
    }
}

/// An invalid stdio mode is refused with the stable child/protocol error code
/// before any child is created.
#[test]
fn instance_exec_rejects_unknown_stdio_mode() {
    let policy = build_policy();
    let inst = unsafe { sandlock_instance_launch(policy, ptr::null()) };
    assert!(!inst.is_null());

    let (_owned, av) = argv(&["true"]);
    let mut out = sandlock_instance_exec_result_t {
        child_id: 0,
        pid: 0,
        stdin_fd: -1,
        stdout_fd: -1,
        stderr_fd: -1,
        pty_fd: -1,
    };
    let rc = unsafe {
        sandlock_instance_exec(inst, av.as_ptr(), av.len() as u32, 99, &mut out)
    };
    assert_eq!(
        rc,
        sandlock_ffi::SANDLOCK_INSTANCE_ERR_CHILD,
        "unknown stdio mode must fail with the child/protocol code"
    );

    unsafe {
        sandlock_instance_free(inst);
        sandlock_sandbox_free(policy);
    }
}

/// `kill_child` by registered child id is idempotent for an already-reaped
/// child, and a wait then still returns the original exit status.
#[test]
fn instance_kill_after_reap_is_idempotent() {
    let policy = build_policy();
    let inst = unsafe { sandlock_instance_launch(policy, ptr::null()) };
    assert!(!inst.is_null());

    let (_owned, av) = argv(&["/bin/sh", "-c", "exit 3"]);
    let mut out = sandlock_instance_exec_result_t {
        child_id: 0,
        pid: 0,
        stdin_fd: -1,
        stdout_fd: -1,
        stderr_fd: -1,
        pty_fd: -1,
    };
    let rc = unsafe {
        sandlock_instance_exec(inst, av.as_ptr(), av.len() as u32, PIPED, &mut out)
    };
    assert_eq!(rc, sandlock_ffi::SANDLOCK_INSTANCE_OK);
    let res = unsafe { sandlock_instance_wait_child(inst, out.child_id, 0) };
    assert!(!res.is_null());
    assert_eq!(unsafe { sandlock_result_exit_code(res) }, 3);
    unsafe { sandlock_result_free(res) };

    let krc = unsafe { sandlock_instance_kill_child(inst, out.child_id, 9) };
    assert_eq!(
        krc,
        sandlock_ffi::SANDLOCK_INSTANCE_OK,
        "kill after reap is an idempotent no-op"
    );

    unsafe {
        sandlock_instance_free(inst);
        sandlock_sandbox_free(policy);
    }
}
