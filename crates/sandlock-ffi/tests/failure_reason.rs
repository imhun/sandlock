//! SL-12 (Task B1): `sandlock_create` / `sandlock_instance_launch` failures
//! must carry the core's own reason across the C ABI.
//!
//! Before this task the FFI returned a bare NULL and the SDK face could only
//! say ``sandlock_create failed`` — a fail-closed refusal's remedy (name the
//! route-B supervisor, or accept the downgrade explicitly) was lost at the
//! boundary.  The `*_with_err` symbols publish that text through the same
//! `err`/`err_msg` out-parameter contract the supervise exports use; these
//! tests pin the *whole* string, not a fragment.
//!
//! The refusal under test is chosen by privilege so the target runs in both
//! phases with no soft skip:
//!
//! * unprivileged (the gate's uid 65534 phase): a `RunAs` to a uid the
//!   single-entry user-namespace map cannot cover is refused before fork;
//! * root: the C档 shape (default `mediation_run_as=caller` + path mediation
//!   + non-zero host uid) is refused with the route-B remedy.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

use sandlock_ffi::{
    sandlock_create, sandlock_create_with_err, sandlock_handle_free, sandlock_instance_free,
    sandlock_instance_launch, sandlock_instance_launch_with_err, sandlock_sandbox_build,
    sandlock_sandbox_builder_fs_deny, sandlock_sandbox_builder_fs_read,
    sandlock_sandbox_builder_new, sandlock_sandbox_builder_user, sandlock_sandbox_free,
    sandlock_sandbox_t, sandlock_string_free, SANDLOCK_INSTANCE_ERR_CHILD,
};

/// The sandbox host uid/gid every refusal fixture requests: far from any real
/// caller and from 0.
const TARGET_UID: u32 = 4242;
const TARGET_GID: u32 = 4242;

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// The refusal's `SandlockError` Display text, verbatim (kept in lockstep
/// with `sandlock-core`'s spawn-time refusals, like the core-side helpers in
/// `tests/integration/test_uid_isolation.rs` and
/// `sandlock-supervise/tests/mediation_2uid.rs`).
fn expected_refusal() -> String {
    if euid() == 0 {
        // C档: root in-process remap with path mediation under `caller`.
        format!(
            "process error: child process error: mediation_run_as=caller refused: \
             in-process path mediation would run as euid 0 while the sandbox's host uid is \
             {TARGET_UID}; on-behalf files would be owned by the mediator, not the sandbox \
             (SL-1). Run sandlock-supervise as uid {TARGET_UID} (route B), or pass \
             mediation_run_as=supervisor to explicitly accept the downgrade"
        )
    } else {
        format!(
            "process error: child process error: RunAs({TARGET_UID}, {TARGET_GID}) refused: \
             unprivileged supervisor (euid={}) cannot map an arbitrary host uid (single-entry \
             userns map can only cover the caller's own euid); per-sandbox independent host \
             uids require a privileged supervisor (root/CAP_SETUID in the parent user \
             namespace) or an equivalent mechanism",
            unsafe { libc::getuid() }
        )
    }
}

/// Build a policy whose *spawn* is refused (no child is forked).  As root the
/// deny rule switches path mediation on, which makes the same `RunAs` the C档
/// shape; unprivileged, the `RunAs` alone is the refusal.
fn refused_policy() -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");
    if euid() == 0 {
        let denied = CString::new("/sandlock-sl12-refused").unwrap();
        b = unsafe { sandlock_sandbox_builder_fs_deny(b, denied.as_ptr()) };
    }
    b = unsafe { sandlock_sandbox_builder_user(b, TARGET_UID, TARGET_GID) };
    let mut err: c_int = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert_eq!(err, 0, "policy build failed");
    assert!(!policy.is_null(), "policy build returned null");
    policy
}

/// Build a policy that can actually fork: the usual coreutils roots.
fn launchable_policy() -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");
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
    assert!(!policy.is_null(), "policy build returned null");
    policy
}

fn argv(cmd: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
    let owned: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    (owned, ptrs)
}

/// Take the heap message out of an `err_msg` out-param (and free it), so the
/// assertion compares owned bytes rather than a dangling pointer.
unsafe fn take(msg: *mut c_char) -> String {
    assert!(!msg.is_null(), "the FFI published no reason");
    let text = CStr::from_ptr(msg).to_str().expect("not UTF-8").to_string();
    sandlock_string_free(msg);
    text
}

/// `sandlock_create_with_err` reports the refusal text verbatim and leaves
/// `*err` at -1 with a null handle.
#[test]
fn create_with_err_publishes_the_core_refusal() {
    let policy = refused_policy();
    let (_owned, av) = argv(&["true"]);
    let mut err: c_int = 0;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let handle = unsafe {
        sandlock_create_with_err(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as u32,
            &mut err,
            &mut err_msg,
        )
    };
    assert!(
        handle.is_null(),
        "a refused create must not return a handle"
    );
    assert_eq!(err, -1, "a refused create must set *err to -1");
    let text = unsafe { take(err_msg) };
    assert_eq!(text, expected_refusal());
    unsafe { sandlock_sandbox_free(policy) };
}

/// `sandlock_instance_launch_with_err` publishes the same reason for the
/// exec-capable session entry point.
#[test]
fn instance_launch_with_err_publishes_the_core_refusal() {
    let policy = refused_policy();
    let mut err: c_int = 0;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let instance =
        unsafe { sandlock_instance_launch_with_err(policy, ptr::null(), &mut err, &mut err_msg) };
    assert!(
        instance.is_null(),
        "a refused launch must not return a handle"
    );
    // The instance family reports the *stable* code rather than a bare -1, so
    // callers classify by code (closed=1 / dead=6) instead of parsing the
    // reason text (B1 review, minor-3).
    assert_eq!(
        err, SANDLOCK_INSTANCE_ERR_CHILD,
        "a spawn refusal is classified as a child failure"
    );
    let text = unsafe { take(err_msg) };
    assert_eq!(text, expected_refusal());
    unsafe { sandlock_sandbox_free(policy) };
}

/// The success path sets `*err` to 0 and clears the reason slot instead of
/// leaving a stale message behind (a caller reusing the slot must not read an
/// old failure).
#[test]
fn with_err_symbols_clear_the_reason_on_success() {
    let policy = launchable_policy();
    let (_owned, av) = argv(&["true"]);
    let stale = CString::new("stale reason").unwrap().into_raw();
    let mut err: c_int = -1;
    let mut err_msg: *mut c_char = stale;
    let handle = unsafe {
        sandlock_create_with_err(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as u32,
            &mut err,
            &mut err_msg,
        )
    };
    assert!(
        !handle.is_null(),
        "a launchable policy must create a handle"
    );
    assert_eq!(err, 0, "success must set *err to 0");
    assert!(err_msg.is_null(), "success must clear the reason slot");
    unsafe {
        sandlock_handle_free(handle);
        sandlock_string_free(stale);
    }

    let stale = CString::new("stale reason").unwrap().into_raw();
    let mut err: c_int = -1;
    let mut err_msg: *mut c_char = stale;
    let instance =
        unsafe { sandlock_instance_launch_with_err(policy, ptr::null(), &mut err, &mut err_msg) };
    assert!(!instance.is_null(), "a launchable policy must launch");
    assert_eq!(err, 0, "success must set *err to 0");
    assert!(err_msg.is_null(), "success must clear the reason slot");
    unsafe {
        sandlock_instance_free(instance);
        sandlock_string_free(stale);
        sandlock_sandbox_free(policy);
    }
}

/// The original 4-argument `sandlock_create` and 2-argument
/// `sandlock_instance_launch` keep their ABI (existing C/Go consumers): same
/// null on failure, no out-parameters to pass.
#[test]
fn legacy_symbols_keep_their_abi() {
    let policy = refused_policy();
    let (_owned, av) = argv(&["true"]);
    let handle = unsafe { sandlock_create(policy, ptr::null(), av.as_ptr(), av.len() as u32) };
    assert!(handle.is_null(), "the legacy create must still return null");
    let instance = unsafe { sandlock_instance_launch(policy, ptr::null()) };
    assert!(
        instance.is_null(),
        "the legacy launch must still return null"
    );
    unsafe { sandlock_sandbox_free(policy) };
}
