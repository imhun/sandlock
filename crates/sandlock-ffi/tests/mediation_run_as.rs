//! F6.1 (SL-1): FFI setter for the mediation identity tier
//! (`mediation_run_as` = caller | supervisor).
//!
//! The setter must land on the built `Sandbox` so a caller using the C ABI
//! can explicitly declare the supervisor downgrade tier; the default stays
//! `caller` (fail-closed for root in-process remaps).

use sandlock_core::sandbox::MediationRunAs;
use sandlock_core::Sandbox;
use sandlock_ffi::{sandlock_sandbox_builder_mediation_run_as, sandlock_sandbox_builder_new};

fn build_via_ffi(tier: u8) -> Sandbox {
    let b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");
    // SAFETY: `b` is a valid Box pointer produced by builder_new; the setter
    // uses move semantics and returns the (possibly relocated) pointer.
    let b = unsafe { sandlock_sandbox_builder_mediation_run_as(b, tier) };
    assert!(!b.is_null(), "mediation setter returned null builder");
    let builder = unsafe { *Box::from_raw(b) };
    builder.build().expect("build failed")
}

#[test]
fn builder_mediation_run_as_supervisor_lands_on_policy() {
    let sandbox = build_via_ffi(1);
    assert_eq!(
        sandbox.mediation_run_as,
        MediationRunAs::Supervisor,
        "tier 1 (supervisor) must land on the built policy"
    );
}

#[test]
fn builder_mediation_run_as_defaults_to_caller_and_invalid_stays_closed() {
    let default = build_via_ffi(0);
    assert_eq!(default.mediation_run_as, MediationRunAs::Caller);
    // An out-of-range discriminant must not secretly select a tier: the
    // default (caller, fail-closed for root remaps) is kept.
    let invalid = build_via_ffi(7);
    assert_eq!(invalid.mediation_run_as, MediationRunAs::Caller);
}
