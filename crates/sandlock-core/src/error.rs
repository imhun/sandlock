use thiserror::Error;

/// Root error type for all sandlock operations.
#[derive(Debug, Error)]
pub enum SandlockError {
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    #[error("process error: {0}")]
    Runtime(#[from] SandboxRuntimeError),

    #[error("memory protection error: {0}")]
    MemoryProtect(String),

    #[error("handler error: {0}")]
    Handler(#[from] crate::seccomp::dispatch::HandlerError),
}

/// Errors from sandbox configuration validation and building.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("invalid sandbox: {0}")]
    Invalid(String),

    #[error("max_cpu must be 1-100, got {0}")]
    InvalidCpuPercent(u8),

    #[error("confine() only accepts Landlock filesystem policy; unsupported fields: {0}")]
    UnsupportedForConfine(String),

    #[error("chroot path {path} does not exist or is inaccessible: {source}")]
    ChrootNotFound {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Errors from the sandbox process runtime (fork, confinement, child, etc.).
#[derive(Debug, Error)]
pub enum SandboxRuntimeError {
    #[error("fork failed: {0}")]
    Fork(#[source] std::io::Error),

    #[error("confinement failed: {0}")]
    Confinement(#[from] ConfinementError),

    #[error("child process error: {0}")]
    Child(String),

    #[error("branch error: {0}")]
    Branch(#[from] BranchError),

    #[error("sandbox not running")]
    NotRunning,

    /// The session is closed and cannot take new work: `shutdown` completed,
    /// the init channel closed after the main-exit container collapse, or the
    /// session was never exec-capable. Every later
    /// `exec`/`wait_child`/`kill_child` on this instance fails with this same
    /// variant — the F5.4 S5 unified closed-instance code. A machinery
    /// failure (request deadline, unexpected init termination) is the
    /// distinct [`SandboxRuntimeError::InstanceDead`] code instead. The
    /// instance is never silently re-launched.
    #[error(
        "instance is closed (shut down, or the init channel closed after the \
         main-exit container end); no new work is accepted"
    )]
    InstanceClosed,

    /// F5.4 (M3 S5): the session's machinery died — the exec control link
    /// exceeded a request deadline, `sandlock-init` terminated unexpectedly
    /// (no Shutdown frame, no main-exit collapse), or the link reader hit a
    /// fatal channel error. The instance is `InstancePhase::Dead`; every
    /// later `exec`/`wait_child`/`kill_child`/`resize_child` returns this
    /// same code, and the instance is never silently relaunched. Callers
    /// distinguish it from [`SandboxRuntimeError::InstanceClosed`] (a clean
    /// shutdown / main-exit container end) and rebuild the box.
    #[error(
        "instance is dead (listener/reaper/control-channel failure); every verb returns \
         this code and the instance is never silently relaunched"
    )]
    InstanceDead,

    /// A per-child verb named a child id that was never registered by this
    /// session's executor (F1.2 announced-registry checking). The id is
    /// reported exactly so callers can distinguish a stale handle from a
    /// wrong id.
    #[error("instance has no child with id {0}")]
    UnknownChild(u64),

    /// `resize_child` addressed a registered child that has no pty (it was
    /// not exec'd with `ExecStdio::Pty`).
    #[error("child {0} has no pty master (exec without ExecStdio::Pty)")]
    NoPtyMaster(u64),

    /// F4.2 (S9): an exec request carried a per-exec parameter wider than the
    /// instance-time policy ceiling (an `extra_writable` path outside the
    /// writable grants, a `cwd` outside every fs grant, a `bind_ports` port
    /// outside `net_allow_bind`, or a path the instance `fs_deny`'d). The
    /// ceiling is fixed at instance creation; a wider request is refused with
    /// this EPERM-class error naming the field and the offending value, never
    /// silently granted (the on-behalf fd-injection entry point enforces the
    /// same check).
    #[error("exec params exceed the instance policy ceiling: {field} {value} is outside the allowed set (EPERM)")]
    PolicyTooWide {
        /// Which per-exec parameter dimension went out of bounds.
        field: &'static str,
        /// The offending value (path string or port number), so the error is
        /// log-visible and machine-comparable.
        value: String,
    },

    /// F5.2 (M3 S3): `checkpoint()` on an exec session that currently has
    /// more than one live child. A checkpoint image captures **one** address
    /// space; silently snapshotting a single command while its siblings keep
    /// running would let a restore claim the whole box was captured. The
    /// refusal is explicit and names the live count so callers can wait for
    /// children before retrying.
    #[error(
        "cannot checkpoint an exec session with {live} live children: a checkpoint \
         image captures one address space; wait for all but one child first"
    )]
    CheckpointMultipleChildren {
        /// Number of live (not yet reaped) registered children.
        live: u32,
    },

    /// F5.2: `checkpoint()` on an exec session with no live child to capture.
    #[error("cannot checkpoint an exec session with no live child to capture")]
    CheckpointNoLiveChild,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Stable, machine-readable *why* a verb was refused by a session
/// (route-B F19 / SL-13).
///
/// A refusal has always carried its prose (`SandboxRuntimeError`'s message,
/// unchanged); the code is the same fact in a form a host may branch on
/// without parsing that prose. It exists because a route-B slot is a
/// *separate process*: `sandlock-supervise` answers a refused verb over the
/// control channel, where the native error type cannot survive, so before
/// this code the worker had to ask the slot what state its generation was in
/// and reverse-infer "rebuild or not" from `stats`. The code removes that
/// inference.
///
/// The string values are part of the wire contract with the E2B worker
/// (`envd_service/executors/sandlock.py`, `envd_service/route_b.py`) and with
/// `sandlock.exceptions`; the fork-side test
/// `refusal_codes_are_the_stable_wire_strings` pins them.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    /// The session is closed: `shutdown` completed, or the init channel
    /// closed after the main-exit container collapse. The session is never
    /// silently relaunched; a host's recovery is a fresh one.
    GenerationClosed,
    /// The session machinery failed (request deadline, unexpected
    /// `sandlock-init` termination, fatal channel error). Distinct from
    /// [`RefusalCode::GenerationClosed`] (a *clean* end) exactly like the
    /// two error variants; a host's recovery is again a fresh session.
    GenerationDead,
    /// A **Live** session refused the verb for its own reason: the request
    /// was wider than the instance-time policy ceiling (EPERM). The session
    /// is healthy; no recovery applies and the refusal must reach the caller
    /// unchanged.
    PolicyDenied,
    /// A **Live** session refused the verb for a reason that is neither a
    /// gone generation nor a policy ceiling (an unknown child id, a child
    /// with no pty, a malformed verb payload, a verb this generation cannot
    /// serve). Same treatment as [`RefusalCode::PolicyDenied`].
    VerbRefused,
}

impl RefusalCode {
    /// The stable wire string (see the enum doc for the contract).
    pub const fn as_str(self) -> &'static str {
        match self {
            RefusalCode::GenerationClosed => "generation_closed",
            RefusalCode::GenerationDead => "generation_dead",
            RefusalCode::PolicyDenied => "policy_denied",
            RefusalCode::VerbRefused => "verb_refused",
        }
    }
}

impl std::fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SandboxRuntimeError {
    /// The refusal code this failure maps to, or `None` when it is not a
    /// verb refusal at all (a build/fork/confinement failure, an io error).
    ///
    /// `None` is deliberately not [`RefusalCode::VerbRefused`]: the caller
    /// that answers a *served* verb knows it is answering a refusal and picks
    /// the catch-all itself, while a failure that never reached a session has
    /// no refusal to describe.
    pub fn refusal_code(&self) -> Option<RefusalCode> {
        match self {
            SandboxRuntimeError::InstanceClosed => Some(RefusalCode::GenerationClosed),
            SandboxRuntimeError::InstanceDead => Some(RefusalCode::GenerationDead),
            SandboxRuntimeError::PolicyTooWide { .. } => Some(RefusalCode::PolicyDenied),
            _ => None,
        }
    }
}

/// The refusal code of a top-level sandlock error, or `None` when the error
/// is not a session verb refusal (see
/// [`SandboxRuntimeError::refusal_code`]).
pub fn refusal_code(err: &SandlockError) -> Option<RefusalCode> {
    match err {
        SandlockError::Runtime(runtime) => runtime.refusal_code(),
        _ => None,
    }
}

#[derive(Debug, Error)]
pub enum ConfinementError {
    #[error("landlock unavailable: {0}")]
    LandlockUnavailable(String),

    /// A `Protection` in `ProtectionState::Strict` is unavailable
    /// because the host kernel's Landlock ABI is below the
    /// protection's `min_abi()`. Build (or `confine`) refuses to
    /// proceed; the caller can resolve by setting that protection to
    /// `Degradable` or `Disabled`, or by running on a kernel that
    /// supports it.
    #[error("required protection {protection:?} is not available: host Landlock ABI is v{host_abi}, requires v{required_abi}")]
    ProtectionUnavailable {
        protection: crate::protection::Protection,
        required_abi: u32,
        host_abi: u32,
    },

    #[error("landlock error: {0}")]
    Landlock(String),

    #[error("seccomp error: {0}")]
    Seccomp(#[from] SeccompError),
}

#[derive(Debug, Error)]
pub enum SeccompError {
    #[error("seccomp filter installation failed: {0}")]
    FilterInstall(String),

    #[error("notification error: {0}")]
    Notif(#[from] NotifError),
}

#[derive(Debug, Error)]
pub enum NotifError {
    #[error("notification supervisor error: {0}")]
    Supervisor(String),

    #[error("child memory read failed: {0}")]
    ChildMemoryRead(#[source] std::io::Error),

    #[error("child memory write failed: {0}")]
    ChildMemoryWrite(#[source] std::io::Error),

    #[error("notification ioctl failed: {0}")]
    Ioctl(#[source] std::io::Error),
}

#[derive(Debug, Error)]
pub enum BranchError {
    #[error("branch operation failed: {0}")]
    Operation(String),

    #[error("branch conflict: {0}")]
    Conflict(String),

    #[error("disk quota exceeded")]
    QuotaExceeded,

    #[error("operation denied by policy")]
    Denied,

    #[error("file already exists")]
    Exists,

    /// The path was deleted in this branch (a whiteout). The lower file still
    /// physically exists with its pre-delete bytes, so the open call site must
    /// return `ENOENT` instead of falling through to it. Sync mirror of the
    /// async `CowOpenPlan::Deleted`.
    #[error("file was deleted in this branch")]
    Deleted,
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, SandlockError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal-code strings are a wire contract with the E2B worker
    /// (``envd_service/executors/sandlock.py`` branches on them) and with
    /// ``sandlock.exceptions``. Pinned verbatim so a rename cannot land
    /// silently; the serde form must be the same string.
    #[test]
    fn refusal_codes_are_the_stable_wire_strings() {
        assert_eq!(RefusalCode::GenerationClosed.as_str(), "generation_closed");
        assert_eq!(RefusalCode::GenerationDead.as_str(), "generation_dead");
        assert_eq!(RefusalCode::PolicyDenied.as_str(), "policy_denied");
        assert_eq!(RefusalCode::VerbRefused.as_str(), "verb_refused");
        assert_eq!(
            serde_json::to_string(&RefusalCode::GenerationClosed).expect("serialize code"),
            "\"generation_closed\""
        );
        assert_eq!(
            serde_json::from_str::<RefusalCode>("\"generation_dead\"").expect("parse code"),
            RefusalCode::GenerationDead
        );
    }

    /// The three session-gone / policy classes map to their code; every other
    /// failure (a build, a fork, an io error, an unknown child id) maps to
    /// ``None`` so the caller picks the catch-all only where it *is* answering
    /// a refused verb.
    #[test]
    fn only_the_classified_runtime_errors_carry_a_refusal_code() {
        assert_eq!(
            SandboxRuntimeError::InstanceClosed.refusal_code(),
            Some(RefusalCode::GenerationClosed)
        );
        assert_eq!(
            SandboxRuntimeError::InstanceDead.refusal_code(),
            Some(RefusalCode::GenerationDead)
        );
        assert_eq!(
            SandboxRuntimeError::PolicyTooWide {
                field: "bind_ports",
                value: "65000".to_string(),
            }
            .refusal_code(),
            Some(RefusalCode::PolicyDenied)
        );
        assert_eq!(SandboxRuntimeError::NotRunning.refusal_code(), None);
        assert_eq!(SandboxRuntimeError::UnknownChild(7).refusal_code(), None);
        assert_eq!(SandboxRuntimeError::NoPtyMaster(7).refusal_code(), None);
        assert_eq!(
            refusal_code(&SandlockError::Runtime(SandboxRuntimeError::InstanceClosed)),
            Some(RefusalCode::GenerationClosed)
        );
        assert_eq!(
            refusal_code(&SandlockError::MemoryProtect("nope".to_string())),
            None
        );
    }
}
