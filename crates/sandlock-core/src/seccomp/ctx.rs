use std::os::unix::io::RawFd;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::notif::NotifPolicy;
use super::state::{
    ChrootState, CowState, NetworkState, PolicyFnState, ProcessIndex, ProcfsState, ResourceState,
    TimeRandomState,
};

/// Holds all supervisor state and policy. Passed to every handler.
pub struct SupervisorCtx {
    /// Resource-limit state (memory, processes, checkpoint).
    pub resource: Arc<Mutex<ResourceState>>,
    /// Copy-on-write filesystem state.
    pub cow: Arc<Mutex<CowState>>,
    /// /proc virtualization state.
    pub procfs: Arc<Mutex<ProcfsState>>,
    /// Network policy and port remapping state.
    pub network: Arc<Mutex<NetworkState>>,
    /// Deterministic time/random state.
    pub time_random: Arc<Mutex<TimeRandomState>>,
    /// Dynamic policy callback state.
    pub policy_fn: Arc<Mutex<PolicyFnState>>,
    /// Chroot-specific runtime state.
    pub chroot: Arc<Mutex<ChrootState>>,
    /// N25/L2c: directories this sandbox has written to since the last drain.
    /// Filled by the chroot path handlers (the only component that sees every
    /// write) and drained by whoever does the disk accounting.
    pub dirty: Arc<crate::dirty::DirtyDirs>,
    /// N25: descriptors this sandbox has open **for writing**, with the size
    /// each file had when the mediator opened it. Filled by the `openat`
    /// handler from the kernel's ADDFD reply, and read by the append watch
    /// (`crate::append_watch`), which can see a running writer's true size
    /// through those descriptors while a path-based `stat` cannot.
    pub write_fds: Arc<crate::dirty::WriteFds>,
    /// NETLINK_ROUTE virtualization state.
    pub netlink: Arc<crate::netlink::NetlinkState>,
    /// Per-process registry: pid → PidKey. This anchors unified
    /// per-process state cleanup. With policy_fn active, fork-like
    /// syscalls populate it at child creation time before user code can
    /// run; otherwise it is populated lazily from notifications. Wraps
    /// an internal RwLock, so handlers can query it synchronously
    /// without `.await`.
    pub processes: Arc<ProcessIndex>,
    /// Immutable policy — no lock needed.
    pub policy: Arc<NotifPolicy>,
    /// pidfd for the child process (immutable after spawn).
    pub child_pidfd: Option<RawFd>,
    /// Seccomp notification fd (for on-behalf operations).
    pub notif_fd: RawFd,
}
