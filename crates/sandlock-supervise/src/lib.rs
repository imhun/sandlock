//! `sandlock-supervise` policy transport (fork-plan F2b.1).
//!
//! The binary entry point ([`crate::main`](main) in `src/main.rs`) is a thin
//! shell around this crate: uid self-check, policy source read, then
//! [`policy::validate`], then the control-fd liveness check. Keeping the
//! policy machinery in a library makes the full-field round-trip directly
//! testable and gives F2b.2+ (serve loop) one import to reuse.
//!
//! # Identity boundary (fork-plan F2b.3, route B)
//!
//! The fork provides and tests exactly this capability: *a supervisor
//! process running as any non-root host uid is fully functional* (Landlock /
//! seccomp-notif mediation, DNS gateway, inbound port mapping, instance
//! lifecycle), gated by the `--uid` self-check in the binary entry.
//!
//! **The fork does not install privileges.** "How the process becomes uid X"
//! lives outside this crate — a deployer root launcher holding
//! `CAP_SETUID/CAP_SETGID/CAP_CHOWN`, a file-cap launcher, or a pooled slot
//! started directly as uid X (deployment option ①).  This crate ships no
//! setuid binary, contains no `CAP_SETUID`/`setuid`/`setfsuid` code, and has
//! no runtime path that maps a live generation's mediator to a *new* host
//! uid.  That last path is the route-B C-grade revival and is pinned as
//! forbidden here and in `docs/supervise-identity-handoff.md`: the mediator
//! **is** this process, its host uid is fixed at exec by the launcher, and a
//! sandbox's uid inside its own user namespace maps only to this process's
//! own uid (single-entry map).  Any code change that would re-map the
//! mediator to another host uid at runtime violates the route-B hard
//! invariants and must be rejected in review.

#![recursion_limit = "256"]

pub mod policy;
pub mod serve;
pub mod events;

/// Route-B hard invariant, pinned at the crate root (fork-plan F2b.3):
/// supervise never re-maps its mediator (itself) to a new host uid at
/// runtime.  The forbidden alternative — one uid-W slot serving sandboxes by
/// giving each a *different* host uid via a multi-entry map — would leave the
/// mediator running as W (C-grade revival, SL-1 returns).  Kept as a named
/// constant so the invariant is greppable and testable, not just a comment.
pub const FORBIDDEN_RUNTIME_MEDIATOR_REMAP: &str =
    "supervise never maps a live generation's mediator to a new host uid; \
     the mediator host uid is fixed at exec (--uid self-check) and the \
     sandbox's userns maps only the supervisor's own uid";
