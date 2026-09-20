//! Per-exec parameter surface and S9 subset validation (fork-plan F4.1/F4.2).
//!
//! [`ExecParams`] are the per-command differences E2B passes with each
//! `exec`: a chdir target (`cwd`), environment handling (`env` + per-exec
//! `clean_env`), extra writable paths (`extra_writable`) and TCP bind ports
//! (`bind_ports`). The instance ceiling is fixed at session creation from the
//! `Sandbox` policy ([`ExecCeiling::from_policy`]); an exec request is never
//! wider than that ceiling ([`ExecCeiling::validate`], S9):
//!
//! * `extra_writable` paths must be absolute, at or under a writable grant of
//!   the ceiling, and never at or under an instance `fs_deny`;
//! * `cwd` must be absolute and inside at least one fs grant (readable or
//!   writable), so a per-exec chdir cannot be used to reach a path the
//!   instance never granted;
//! * `bind_ports` must be inside the instance `net_allow_bind` allowlist (or
//!   not denied by `net_deny_bind`, which is default-allow);
//! * `env`/`clean_env` are always in scope: environment is process-local and
//!   per-exec by construction, and this fork's `Sandbox` policy has no
//!   "env forbidden" ceiling field, so there is no wider-than-ceiling env
//!   request to refuse. (Documented here so the asymmetry is deliberate, not
//!   accidental.)
//!
//! The validation is a single choke point shared by the in-process exec path
//! and the on-behalf fd-injection path (`exec_with_fds[_params]`, the
//! cross-process holder shape): whichever route a request arrives through, an
//! out-of-ceiling grant is refused with the named EPERM-class
//! [`SandboxRuntimeError::PolicyTooWide`] error before any fd or frame is
//! consumed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::{SandboxRuntimeError, SandlockError};
use crate::sandbox::BindPorts;

/// Per-exec parameters carried by one `exec` request (F4.1).
///
/// `cwd`/`env`/`clean_env` are applied by `sandlock-init` at execve (chdir,
/// then environment construction). `extra_writable`/`bind_ports` are
/// per-child grants inside the instance ceiling: validated host-side and
/// recorded per child; init itself does not consume them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecParams {
    /// Optional chdir target, applied before execve. Must be absolute and
    /// inside an instance fs grant (readable or writable).
    pub cwd: Option<PathBuf>,
    /// Environment entries applied in the child before execve. Additive
    /// overrides over the inherited session environment unless `clean_env`
    /// is set, in which case they are the child's complete environment.
    pub env: Vec<(String, String)>,
    /// When true, the child starts from an empty environment and only `env`
    /// is applied (per-exec `clean_env`, independent of the policy-level
    /// `Sandbox.clean_env` that shaped init itself).
    pub clean_env: bool,
    /// Extra writable paths for this child (absolute). Must be a subset of
    /// the instance's writable grants and never `fs_deny`'d.
    pub extra_writable: Vec<PathBuf>,
    /// TCP ports this child may bind. Must be a subset of the instance's
    /// `net_allow_bind` ceiling.
    pub bind_ports: Vec<u16>,
    /// N25/C: tighten `RLIMIT_FSIZE` for this child to this many bytes.
    ///
    /// A per-exec *tightening* only: the instance ceiling is the policy's
    /// `max_file_size` (or "no bound"), and a request above it is refused as
    /// wider-than-ceiling. Lowering your own limit is always permitted, so
    /// init applies it in the forked child before execve -- and that is the
    /// only place it can go: limits are per-process, so applying it in init
    /// itself would cap every later exec as well.
    ///
    /// This is what makes the disk ceiling *dynamic* without a per-write
    /// mediator: a caller that knows how much of a budget is left can hand
    /// each command the remaining amount, and a write past it fails with
    /// EFBIG instead of being noticed afterwards.
    pub max_file_size: Option<u64>,
}

impl ExecParams {
    /// Whether the request carries no per-exec change (the pre-F4
    /// `exec(argv, stdio)` shape).
    pub fn is_default(&self) -> bool {
        *self == ExecParams::default()
    }
}

/// The immutable per-exec ceiling of one exec-capable session (S9).
///
/// Captured from the `Sandbox` policy before the session is spawned; exec
/// requests are validated against it and can never widen it.
#[derive(Debug, Clone)]
pub(crate) struct ExecCeiling {
    fs_readable: Vec<PathBuf>,
    fs_writable: Vec<PathBuf>,
    fs_denied: Vec<PathBuf>,
    /// Writable mount destinations: `fs_mount` targets whose host path is
    /// not listed in `fs_mount_ro`.
    writable_mounts: Vec<PathBuf>,
    bind_allow: BindPorts,
    bind_deny: HashSet<u16>,
    /// N25/C: the instance's `RLIMIT_FSIZE`, in bytes, or `None` for "no
    /// bound". A per-exec `max_file_size` may only tighten it.
    max_file_size: Option<u64>,
}

impl ExecCeiling {
    pub(crate) fn from_policy(policy: &crate::sandbox::Sandbox) -> Self {
        let ro: HashSet<&PathBuf> = policy.fs_mount_ro.iter().collect();
        let writable_mounts = policy
            .fs_mount
            .iter()
            .filter(|(_, host)| !ro.contains(host))
            .map(|(_, host)| host.clone())
            .collect();
        ExecCeiling {
            fs_readable: policy.fs_readable.clone(),
            fs_writable: policy.fs_writable.clone(),
            fs_denied: policy.fs_denied.clone(),
            writable_mounts,
            bind_allow: policy.net_allow_bind.clone(),
            bind_deny: policy.net_deny_bind.iter().copied().collect(),
            max_file_size: policy.max_file_size.map(|b| b.0),
        }
    }

    /// S9 subset check: refuse any per-exec grant wider than the ceiling.
    /// Single choke point for the in-process and on-behalf exec routes.
    pub(crate) fn validate(&self, params: &ExecParams) -> Result<(), SandlockError> {
        if let Some(requested) = params.max_file_size {
            // A *tightening* is always in scope; an above-ceiling request is
            // not. Zero is a tightening like any other, and it is the one the
            // product asks for: a sandbox over its disk budget may not write,
            // and everything else (reads, deletes, exec) keeps working, so the
            // owner can get back inside. It is not a freeze.
            let fits = self
                .max_file_size
                .map(|ceiling| requested <= ceiling)
                .unwrap_or(true);
            if !fits {
                return Err(Self::too_wide("max_file_size", requested.to_string()));
            }
        }
        for path in &params.extra_writable {
            let value = path.to_string_lossy().to_string();
            if !path.is_absolute() {
                return Err(Self::too_wide("extra_writable", value));
            }
            if path_under_any(path, &self.fs_denied) {
                return Err(Self::too_wide("extra_writable", value));
            }
            let mut writable = self.fs_writable.clone();
            writable.extend(self.writable_mounts.iter().cloned());
            if !path_under_any(path, &writable) {
                return Err(Self::too_wide("extra_writable", value));
            }
        }
        if let Some(cwd) = params.cwd.as_ref() {
            let value = cwd.to_string_lossy().to_string();
            if !cwd.is_absolute() {
                return Err(Self::too_wide("cwd", value));
            }
            if path_under_any(cwd, &self.fs_denied) {
                return Err(Self::too_wide("cwd", value));
            }
            let mut granted = self.fs_readable.clone();
            granted.extend(self.fs_writable.iter().cloned());
            granted.extend(self.writable_mounts.iter().cloned());
            if !path_under_any(cwd, &granted) {
                return Err(Self::too_wide("cwd", value));
            }
        }
        for port in &params.bind_ports {
            let allowed = match &self.bind_allow {
                BindPorts::All => true,
                BindPorts::Ports(ports) => ports.contains(port),
            };
            if !allowed || self.bind_deny.contains(port) {
                return Err(Self::too_wide("bind_ports", port.to_string()));
            }
        }
        // env/clean_env: always in scope (see module docs).
        Ok(())
    }

    fn too_wide(field: &'static str, value: String) -> SandlockError {
        SandboxRuntimeError::PolicyTooWide { field, value }.into()
    }
}

/// Lexical `path.starts_with(any root)`. Grant roots are treated as prefix
/// dirs (a writable `/tmp` grant covers `/tmp/anything`), matching the
/// Landlock prefix semantics the rest of the crate relies on.
fn path_under_any(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sandbox;

    fn ceiling() -> ExecCeiling {
        let policy = Sandbox::builder()
            .fs_read("/usr")
            .fs_write("/tmp")
            .fs_deny("/tmp/denied")
            .net_allow_bind_port(8080)
            .build()
            .unwrap();
        ExecCeiling::from_policy(&policy)
    }

    #[test]
    fn in_ceiling_params_validate() {
        let c = ceiling();
        let p = ExecParams {
            cwd: Some(PathBuf::from("/tmp/work")),
            env: vec![("A".into(), "1".into())],
            extra_writable: vec![PathBuf::from("/tmp/scratch")],
            bind_ports: vec![8080],
            ..Default::default()
        };
        c.validate(&p).expect("in-ceiling params must validate");
    }

    #[test]
    fn wider_extra_writable_is_refused() {
        let c = ceiling();
        let p = ExecParams {
            extra_writable: vec![PathBuf::from("/etc")],
            ..Default::default()
        };
        let err = c.validate(&p).unwrap_err();
        match err {
            crate::SandlockError::Runtime(SandboxRuntimeError::PolicyTooWide { field, value }) => {
                assert_eq!(field, "extra_writable");
                assert_eq!(value, "/etc");
            }
            other => panic!("expected PolicyTooWide, got {other:?}"),
        }
    }

    #[test]
    fn fs_denied_extra_writable_is_refused() {
        let c = ceiling();
        let p = ExecParams {
            extra_writable: vec![PathBuf::from("/tmp/denied/x")],
            ..Default::default()
        };
        assert!(c.validate(&p).is_err(), "fs_deny must never be overridable");
    }

    #[test]
    fn fs_denied_cwd_is_refused() {
        let c = ceiling();
        let p = ExecParams {
            cwd: Some(PathBuf::from("/tmp/denied")),
            ..Default::default()
        };
        let err = c.validate(&p).unwrap_err();
        assert!(matches!(
            err,
            crate::SandlockError::Runtime(SandboxRuntimeError::PolicyTooWide {
                field: "cwd",
                value,
            }) if value == "/tmp/denied"
        ));
    }

    #[test]
    fn out_of_ceiling_cwd_and_ports_are_refused() {
        let c = ceiling();
        let p = ExecParams {
            cwd: Some(PathBuf::from("/root")),
            ..Default::default()
        };
        let err = c.validate(&p).unwrap_err();
        assert!(matches!(
            err,
            crate::SandlockError::Runtime(SandboxRuntimeError::PolicyTooWide { field: "cwd", .. })
        ));

        let p = ExecParams {
            bind_ports: vec![9090],
            ..Default::default()
        };
        let err = c.validate(&p).unwrap_err();
        assert!(matches!(
            err,
            crate::SandlockError::Runtime(SandboxRuntimeError::PolicyTooWide {
                field: "bind_ports",
                value,
            }) if value == "9090"
        ));
    }
}
