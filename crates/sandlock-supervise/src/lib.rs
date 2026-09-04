//! `sandlock-supervise` policy transport (fork-plan F2b.1).
//!
//! The binary entry point ([`crate::main`](main) in `src/main.rs`) is a thin
//! shell around this crate: uid self-check, policy source read, then
//! [`policy::validate`], then the control-fd liveness check. Keeping the
//! policy machinery in a library makes the full-field round-trip directly
//! testable and gives F2b.2+ (serve loop) one import to reuse.

#![recursion_limit = "256"]

pub mod policy;
pub mod serve;
