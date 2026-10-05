use crate::sandbox::Sandbox;

/// Internal normalized view of a sandbox configuration.
///
/// `Sandbox` is the public configuration surface. `ResolvedSandbox` is the
/// private shape used by runtime setup after defaults and feature activation
/// have been reduced to named facts.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedSandbox {
    pub(crate) features: SandboxFeatures,
}

impl ResolvedSandbox {
    pub(crate) fn from_sandbox(
        sandbox: &Sandbox,
        sandbox_name: Option<&str>,
        handler_syscalls: &[i64],
    ) -> Self {
        Self {
            features: SandboxFeatures::from_sandbox(sandbox, sandbox_name, handler_syscalls),
        }
    }
}

/// Boolean feature gates derived from a sandbox configuration.
///
/// These are deliberately named around runtime behavior instead of raw option
/// names. That keeps syscall planning and supervisor setup from re-encoding
/// the same `Option`/empty-list checks in several places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SandboxFeatures {
    pub(crate) memory_limit: bool,
    /// A host-maintained disk accounting file is configured, so `statfs(2)`
    /// must be trapped and answered from it.
    pub(crate) disk_stats: bool,
    pub(crate) network_supervision: bool,
    pub(crate) network_destination_policy: bool,
    pub(crate) bind_denylist: bool,
    pub(crate) unix_fs_gate: bool,
    pub(crate) random_seed: bool,
    pub(crate) time_start: bool,
    pub(crate) virtual_cpu_count: bool,
    pub(crate) virtual_hostname: bool,
    pub(crate) cow: bool,
    pub(crate) chroot: bool,
    /// The stat family's metadata half still has to reach the mediator (N81).
    pub(crate) stat_metadata_mediated: bool,
    pub(crate) fs_denies: bool,
    pub(crate) policy_fn: bool,
    pub(crate) port_remap: bool,
    pub(crate) fd_inject_connect: bool,
    pub(crate) net_isolation: bool,
    pub(crate) inbound_port_map: bool,
    pub(crate) net_bind_inject: bool,
    pub(crate) http_acl: bool,
    pub(crate) argv_safety_required: bool,
    pub(crate) sysv_ipc_allowed: bool,
    pub(crate) net_allow_present: bool,
    pub(crate) net_deny: bool,
    pub(crate) pid_ns: bool,
}

/// Whether the stat family's metadata half still has to reach the mediator.
///
/// That half is a gate, not a translation. `stat` is metadata, Landlock has no
/// access right for it, and so a call on a path outside the readable set would
/// otherwise reach the host filesystem. The gate is unnecessary exactly when
/// the kernel can only answer for the sandbox's own tree: a root of its own
/// whose `/proc` is an ordinary directory of that same root.
///
/// Measured 2026-10-06 (`deploy/scripts/acceptance/probe_n81_proc_stat_shape.py`):
/// with a rootfs of its own, `stat /proc` and `stat /` share a `st_dev`, and
/// `/proc/uptime` answers ENOENT *from the kernel* -- there is no host pid
/// space behind it to collide with.
///
/// Keep the gate whenever that premise fails:
///
/// * no `chroot` at all -- the sandbox's `/proc` is then the container's
///   procfs, where the numeric-pid collision is real;
/// * `<root>/proc` sits on another filesystem -- a mount (the identity shape's
///   `/`) or a bind of something that is not this root;
/// * a policy mount at or under `/proc`: the child makes those mounts *after*
///   this check, so only the policy can tell us about them.
///
/// The metadata follows symlinks, exactly as the sandbox's own open would.
fn stat_metadata_mediated(sandbox: &Sandbox) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    let Some(root) = sandbox.chroot.as_ref() else {
        return true;
    };
    if sandbox
        .fs_mount
        .iter()
        .any(|(vp, _)| vp == Path::new("/proc") || vp.starts_with("/proc/"))
    {
        return true;
    }
    let Ok(root_md) = std::fs::metadata(root) else {
        // The root is not there (yet): we cannot tell, so keep the gate.
        return true;
    };
    match std::fs::metadata(root.join("proc")) {
        Ok(proc_md) => !(proc_md.is_dir() && proc_md.dev() == root_md.dev()),
        // No `/proc` at all: the kernel has nothing there to answer with.
        Err(_) => false,
    }
}

impl SandboxFeatures {
    fn from_sandbox(
        sandbox: &Sandbox,
        sandbox_name: Option<&str>,
        handler_syscalls: &[i64],
    ) -> Self {
        let http_acl = !sandbox.http_allow.is_empty() || !sandbox.http_deny.is_empty();
        let network_destination_policy = !sandbox.net_allow.is_empty()
            || !sandbox.net_deny.is_empty()
            || sandbox.policy_fn.is_some()
            || http_acl;
        let bind_denylist = !sandbox.net_deny_bind.is_empty();
        let exec_handler = handler_syscalls
            .iter()
            .any(|&nr| nr == libc::SYS_execve || nr == libc::SYS_execveat);

        Self {
            memory_limit: sandbox.max_memory.is_some(),
            disk_stats: sandbox.disk_stats_path.is_some(),
            network_supervision: network_destination_policy || bind_denylist,
            network_destination_policy,
            bind_denylist,
            unix_fs_gate: sandbox.has_unix_fs_gate(),
            random_seed: sandbox.random_seed.is_some(),
            time_start: sandbox.time_start.is_some(),
            virtual_cpu_count: sandbox.num_cpus.is_some(),
            virtual_hostname: sandbox_name.is_some(),
            cow: sandbox.workdir.is_some(),
            chroot: sandbox.chroot.is_some(),
            stat_metadata_mediated: stat_metadata_mediated(sandbox),
            fs_denies: !sandbox.fs_denied.is_empty(),
            policy_fn: sandbox.policy_fn.is_some(),
            port_remap: sandbox.port_remap,
            fd_inject_connect: sandbox.fd_inject_connect,
            net_isolation: sandbox.net_isolation,
            inbound_port_map: !sandbox.net_bind_map.is_empty(),
            net_bind_inject: sandbox.net_bind_inject,
            http_acl,
            // F5.1 (M3 S1): an in-child-main control session (the confined
            // `sandlock-init` of an exec-capable `SandboxInstance`, and every
            // other `create_with_in_child_main` entry) forks workloads whose
            // exits are reaped with WNOHANG by the control loop — the wait4
            // path lazy mode relies on never fires. Fork-tracking/birth
            // registration makes the pidfd watcher the authoritative
            // `proc_count` releaser, which is what makes whole-box
            // `max_processes` honest across exec children and their
            // descendants (F1.4's argv-safety mechanism; same shape as the
            // E2B/OCI handler mode).
            argv_safety_required: sandbox.policy_fn.is_some()
                || exec_handler
                || sandbox.in_child_main.is_some(),
            sysv_ipc_allowed: sandbox.allows_sysv_ipc(),
            net_allow_present: !sandbox.net_allow.is_empty(),
            net_deny: !sandbox.net_deny.is_empty(),
            pid_ns: sandbox.pid_ns,
        }
    }
}
