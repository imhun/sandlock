//! Seccomp syscall and argument-filter planning.
//!
//! This module turns the normalized sandbox feature view into the concrete
//! syscall notification lists, blocklists, and BPF argument filters installed
//! by the child-side confinement path.

use syscalls::{Sysno, SysnoSet};

use crate::arch;
use crate::resolved::ResolvedSandbox;
use crate::sandbox::Sandbox;
use crate::seccomp::bpf::{jump, stmt};
use crate::sys::structs::{
    AF_INET, AF_INET6, BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K,
    BPF_LD, BPF_RET, BPF_W, CLONE_NS_FLAGS, DEFAULT_BLOCKLIST_SYSCALLS, EPERM, FIBMAP,
    FIGETBSZ, FS_IOC_FIEMAP, OFFSET_ARGS0_LO, OFFSET_ARGS1_LO, OFFSET_ARGS2_LO, OFFSET_ARGS3_LO,
    OFFSET_NR, PR_SET_DUMPABLE, PR_SET_PTRACER, PR_SET_SECUREBITS, SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO, SIOCETHTOOL, SIOCGIFADDR, SIOCGIFBRDADDR, SIOCGIFCONF,
    SIOCGIFDSTADDR, SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFINDEX, SIOCGIFNAME,
    SIOCGIFNETMASK, SIOCSIFADDR, SIOCSIFBRDADDR, SIOCSIFHWADDR, SIOCSIFNETMASK, SIOCSIFFLAGS,
    SOCK_DGRAM, SOCK_RAW, SOCK_TYPE_MASK, SYSV_IPC_BLOCKLIST_SYSCALLS,
    TIOCLINUX, TIOCSTI, SockFilter,
};

// ============================================================
// Sandbox -> syscall lists
// ============================================================

#[derive(Default)]
struct SyscallList {
    nrs: Vec<u32>,
}

impl SyscallList {
    fn with(syscalls: &[i64]) -> Self {
        let mut list = Self::default();
        list.extend(syscalls);
        list
    }

    fn push(&mut self, nr: i64) {
        self.nrs.push(nr as u32);
    }

    fn extend(&mut self, syscalls: &[i64]) {
        self.nrs.extend(syscalls.iter().map(|&nr| nr as u32));
    }

    fn push_optional(&mut self, nr: Option<i64>) {
        if let Some(nr) = nr {
            self.push(nr);
        }
    }

    fn finish(mut self) -> Vec<u32> {
        self.nrs.sort_unstable();
        self.nrs.dedup();
        self.nrs
    }
}

const BASE_NOTIF_SYSCALLS: &[i64] = &[
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_wait4,
    libc::SYS_waitid,
];

// The address-space accounting family: the syscalls the mediator traps so its
// own byte ledger can follow a sandbox's memory (`resource::handle_memory`).
//
// N83 phase 2 (D7): a deployment whose **kernel** enforces the memory budget
// (a cgroup v2 `memory.high`/`memory.max` on the sandbox's own `sbx_<id>`)
// retires exactly this family -- it is the ledger, not an enforcement point.
// See `Sandbox::kernel_enforced_limits` and `notif_syscalls_resolved`.
//
// `shmget` is the SysV spelling of the same allocation and travels with them,
// but it joins the table only where `sysv_ipc` is *allowed* (below): outside
// that it is answered by the kernel blocklist, and notifying on a blocklisted
// syscall would bypass that deny.
const ADDRESS_SPACE_ACCOUNTING_SYSCALLS: &[i64] = &[
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_brk,
    libc::SYS_mremap,
];

// exec destroys the address space and the kernel picks a fresh randomized brk
// base, so brk accounting must observe it to drop the old image's base;
// otherwise the new image's first brk is charged the ASLR distance between the
// two heaps.
//
// These two stay on the table even where the ledger is retired: every deployed
// shape carries them anyway for the chroot/COW/deny/policy_fn mediators, and
// they are cold next to `mmap`, so retiring them would buy nothing while
// putting a hole in whichever of those shapes does *not* add them back.
const EXEC_ADDRESS_SPACE_RESET_SYSCALLS: &[i64] = &[libc::SYS_execve, libc::SYS_execveat];

const NETWORK_POLICY_SYSCALLS: &[i64] = &[
    libc::SYS_connect,
    libc::SYS_sendto,
    libc::SYS_sendmsg,
    libc::SYS_sendmmsg,
    libc::SYS_bind,
];

// Also intercept openat so the supervisor can re-patch vDSO after exec.
const RANDOM_NOTIF_SYSCALLS: &[i64] = &[libc::SYS_getrandom, libc::SYS_openat];

// Also intercept openat so the supervisor gets a notification after exec
// and can re-patch the vDSO (exec replaces vDSO with a fresh copy).
const TIME_NOTIF_SYSCALLS: &[i64] = &[
    libc::SYS_clock_nanosleep,
    libc::SYS_timerfd_settime,
    libc::SYS_timer_settime,
    libc::SYS_openat,
];

// /proc virtualization + /etc/hosts virtualization (always on).
//
// `openat` carries the simple `(AT_FDCWD, "/proc/...")` and
// `(AT_FDCWD, "/etc/hosts")` spellings; `openat2` is the same shape
// on newer libcs; legacy `open(path, ...)` is the same path without a
// dirfd. The handlers normalize all three into a single absolute path
// check, so we have to put every variant on the notif list -- otherwise
// a caller that picks `open` or `openat2` slips past virtualization
// and reads the real on-disk file.
fn procfs_hosts_notif_syscalls() -> Vec<i64> {
    let mut v = vec![libc::SYS_openat, arch::SYS_OPENAT2, libc::SYS_getdents64];
    v.extend([arch::sys_open(), arch::sys_getdents()].into_iter().flatten());
    v
}

/// The metadata ("stat") family: the syscalls that only *read* a path's or a
/// file's metadata.
///
/// `readlinkat` and the legacy `readlink` are not metadata in the mediator's
/// sense -- they are *served* on the child's behalf -- but they share the
/// argument shape and the `/proc` gate, so they travel in this list and
/// `build_notif_list` decides who gets it.
///
/// Since N81 this list is a **gate**, not a translation: it reaches the notify
/// table only when `stat_metadata_mediated` says the kernel would otherwise
/// answer for something that is not the sandbox's own (no root of its own, or
/// a `/proc` that is a separate mount). The shape that originally needed it --
/// a PID-namespace sandbox whose `/proc` was the host's, so `/proc/<n>` hit
/// host pid `n` -- is exactly what that predicate still detects and keeps the
/// gate for; it is simply no longer a shape the deployed roots have.
pub(crate) fn stat_family_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_faccessat,
        arch::SYS_FACCESSAT2,
        libc::SYS_readlinkat,
    ];
    v.extend(
        [
            arch::sys_stat(),
            arch::sys_lstat(),
            arch::sys_access(),
            arch::sys_readlink(),
        ]
        .into_iter()
        .flatten(),
    );
    v
}

// Netlink virtualization (always on):
//   socket, bind, getsockname -- swap in a unix socketpair for AF_NETLINK
//   recvfrom, recvmsg         -- zero msg_name so glibc accepts the reply
//                                (kernel only writes sun_family on unix
//                                 recvmsg, leaving nl_pid uninitialized)
//   close                     -- unregister (pid, fd) so reuse doesn't
//                                collide with the cookie set
// Send traffic flows through the real socketpair untouched.
const NETLINK_NOTIF_SYSCALLS: &[i64] = &[
    libc::SYS_socket,
    libc::SYS_bind,
    libc::SYS_getsockname,
    libc::SYS_recvfrom,
    libc::SYS_recvmsg,
];

fn cow_path_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_openat,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        libc::SYS_renameat2,
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_fchmodat,
        // `fchmodat2` is mediated rather than blocklisted: glibc uses it to
        // implement `chmod`/`fchmodat` with `AT_SYMLINK_NOFOLLOW` semantics, and a
        // seccomp refusal is `EPERM`, which glibc does not fall back from --
        // blocklisting it would break `chmod` inside the sandbox.
        arch::SYS_FCHMODAT2,
        libc::SYS_fchownat,
        libc::SYS_truncate,
        libc::SYS_utimensat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_faccessat,
        arch::SYS_FACCESSAT2,
        libc::SYS_readlinkat,
        libc::SYS_getdents64,
        libc::SYS_chdir,
        libc::SYS_getcwd,
    ];
    v.extend(
        [
            arch::sys_open(),
            arch::sys_unlink(),
            arch::sys_rmdir(),
            arch::sys_mkdir(),
            arch::sys_mknod(),
            arch::sys_rename(),
            arch::sys_symlink(),
            arch::sys_link(),
            arch::sys_chmod(),
            arch::sys_chown(),
            arch::sys_lchown(),
            arch::sys_stat(),
            arch::sys_lstat(),
            arch::sys_access(),
            arch::sys_readlink(),
            arch::sys_getdents(),
        ]
        .into_iter()
        .flatten(),
    );
    v
}

/// The file-size-limit syscalls, mediated so a sandbox process may only
/// *lower* its `RLIMIT_FSIZE` (N25).
///
/// The ceilings this deployment runs on are `RLIMIT_FSIZE` values: the
/// sandbox's budget at launch (the hard limit, which a sandbox process cannot
/// raise -- measured in a sandbox, `setrlimit((1<<40, 1<<40))` answers
/// `ValueError: not allowed to raise maximum limit`), a per-exec allowance, and
/// the worker's live tightening. The *soft* limit, however, may always be
/// raised back up to the hard one by the process itself, with no privilege:
/// that is the kernel's rule and it is enough for a workload to undo a soft
/// tightening. So the platform moved the hard limit down instead -- which is
/// one-way, and left a sandbox that made room for itself unable to ever write
/// again (§22.5.9).
///
/// The way out is to keep the hard limit where the launch put it and let only
/// the platform move the soft one, with these two syscalls gated so the guest
/// can only lower it. The init path is exempt: it applies each command's
/// per-exec allowance in the fork before `execve`, and it is identifiable as
/// the supervisor binary, which lives outside the image the sandbox can exec.
pub(crate) fn file_size_limit_syscalls() -> Vec<i64> {
    vec![libc::SYS_setrlimit, libc::SYS_prlimit64]
}

pub(crate) fn chroot_path_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_openat,
        // openat2 resolves paths like openat and must be mediated the same
        // way: left to the kernel, an absolute path resolves against the
        // host root rather than the rootfs.
        arch::SYS_OPENAT2,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_renameat2,
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_fchmodat,
        // `fchmodat2` is mediated rather than blocklisted: glibc uses it to
        // implement `chmod`/`fchmodat` with `AT_SYMLINK_NOFOLLOW` semantics, and a
        // seccomp refusal is `EPERM`, which glibc does not fall back from --
        // blocklisting it would break `chmod` inside the sandbox.
        arch::SYS_FCHMODAT2,
        libc::SYS_fchownat,
        libc::SYS_truncate,
        // N81: the *metadata* half of the stat family is deliberately absent
        // here. It is a gate, not a translation: with a root of the sandbox's
        // own the kernel resolves the same path inside the sandbox's own tree,
        // and Landlock already refuses the opens that path could lead to. See
        // `stat_metadata_mediated` -- the gate comes back for the shapes where
        // that premise fails (no root at all, or `/proc` as a separate mount),
        // and it is re-added to this list by `build_notif_list` there.
        //
        // `readlinkat` stays: it is a *serving* path (the mediator reads
        // `/proc/self/exe`, `/proc/self/fd/N` and friends on the child's
        // behalf from the host procfs, gated per pid), not a deny.
        libc::SYS_readlinkat,
        libc::SYS_getdents64,
        libc::SYS_chdir,
        // fchdir carries no path, but it still moves the cwd that every
        // later relative path resolves against, so the supervisor has to
        // see it to keep its own notion in step.
        libc::SYS_fchdir,
        // inotify_add_watch carries a path and no dirfd. Landlock has no
        // access right for it, so left unmediated the kernel resolves the
        // child's string against the host root and the sandbox can watch
        // host directories (see handle_chroot_inotify_add_watch).
        libc::SYS_inotify_add_watch,
        libc::SYS_getcwd,
        libc::SYS_statfs,
        libc::SYS_utimensat,
        // xattr family (path-based): must be mediated so that paths under an
        // fs_mount/chroot resolve to the real backing file rather than the
        // empty mount point (issue #84). The fd-based f*xattr variants need
        // no mediation; their fd already points at the resolved file.
        libc::SYS_getxattr,
        libc::SYS_lgetxattr,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_listxattr,
        libc::SYS_llistxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
    ];
    v.extend(
        [
            arch::sys_open(),
            arch::sys_readlink(),
            arch::sys_getdents(),
            arch::sys_unlink(),
            arch::sys_rmdir(),
            arch::sys_mkdir(),
            arch::sys_rename(),
            // Where the ABI has no plain rename(2), libc's rename() compiles
            // to renameat, so leaving it out left rename unmediated on
            // aarch64: an absolute path went to the kernel and resolved
            // against the host root instead of the rootfs.
            arch::sys_renameat(),
            arch::sys_symlink(),
            arch::sys_link(),
            arch::sys_chmod(),
            arch::sys_chown(),
            arch::sys_lchown(),
        ]
        .into_iter()
        .flatten(),
    );
    v
}

/// Syscalls gated by the deny-path precheck in `handle_notification`.
///
/// This is the single source of truth for deny-path enforcement scope: it
/// decides both which syscalls enter the notif BPF list when deny paths are
/// configured and which notifications run `is_path_denied_for_notif`.
///
/// symlinkat/symlink and mkdirat/mkdir are intentionally absent: creating a
/// symlink does not access its target, and mkdir cannot touch existing
/// content, so there is nothing to deny at creation time. A later open
/// through the created name resolves to the real target and is denied
/// race-free on the open path (issue #111).
pub(crate) fn fs_denied_path_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_openat,
        arch::SYS_OPENAT2,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_linkat,
        libc::SYS_renameat2,
        // A denied file must not be destroyed either: truncate(2) wipes its
        // content and unlinkat(2) (incl. AT_REMOVEDIR) deletes it, and both
        // take a path so the fd-based open deny never sees them.
        libc::SYS_truncate,
        libc::SYS_unlinkat,
    ];
    v.extend(
        [
            arch::sys_open(),
            arch::sys_link(),
            arch::sys_rename(),
            arch::sys_renameat(),
            arch::sys_unlink(),
            arch::sys_rmdir(),
        ]
        .into_iter()
        .flatten(),
    );
    v
}

/// Syscalls intercepted for policy_fn event emission.
///
/// Must match what `emit_policy_event` can decode into a `SyscallEvent`, so
/// every field documented there fires for a policy_fn-only sandbox instead of
/// depending on COW, chroot, or network supervision happening to intercept
/// the syscall.
fn policy_event_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_openat,
        arch::SYS_OPENAT2,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_bind,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        libc::SYS_unlinkat,
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_renameat2,
        libc::SYS_truncate,
    ];
    v.extend(
        [
            arch::sys_open(),
            arch::sys_mkdir(),
            arch::sys_mknod(),
            arch::sys_rmdir(),
            arch::sys_unlink(),
            arch::sys_symlink(),
            arch::sys_link(),
            arch::sys_rename(),
            arch::sys_renameat(),
        ]
        .into_iter()
        .flatten(),
    );
    v
}

const PORT_REMAP_SYSCALLS: &[i64] = &[
    libc::SYS_bind,
    libc::SYS_getsockname,
];

/// S2.5 inbound port mapping: `listen` triggers host-listener creation for a
/// mapped sandbox port, and `accept4` (plus legacy `accept` where the ABI has
/// it) is served from that host listener with the accepted fd injected into
/// the sandbox. `close` is already on the notif list via the netlink block,
/// so the close handler chain can drop the mapping when the listener closes.
// E7.1: besides listen/accept, event-loop servers (uvicorn/asyncio, Node,
// Go) need poll/epoll readiness synthesis so a host-side queued connection
// wakes their accept(); `epoll_ctl` tracking tells `epoll_wait` which fds
// are mapped listeners. `poll`/`epoll_wait` exist only on the legacy ABI
// (x86_64); the generic ABI (aarch64/riscv64) has only `ppoll`/
// `epoll_pwait`, which glibc's `poll()`/`epoll_wait()` wrappers call — so
// intercepting the generic pair covers both. All are trapped only when the
// feature is on — the default path never notifies on them.
const INBOUND_MAPPING_SYSCALLS: &[i64] = &[
    libc::SYS_listen,
    libc::SYS_accept4,
    libc::SYS_ppoll,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
];

/// Determine which syscalls need `SECCOMP_RET_USER_NOTIF`.
pub(crate) fn notif_syscalls(policy: &Sandbox, sandbox_name: Option<&str>) -> Vec<u32> {
    let resolved = ResolvedSandbox::from_sandbox(policy, sandbox_name, &[]);
    notif_syscalls_resolved(&resolved)
}

/// Determine which syscalls need `SECCOMP_RET_USER_NOTIF` from the resolved
/// internal feature view.
pub(crate) fn notif_syscalls_resolved(resolved: &ResolvedSandbox) -> Vec<u32> {
    let features = &resolved.features;
    let mut nrs = SyscallList::with(BASE_NOTIF_SYSCALLS);
    nrs.push_optional(arch::sys_vfork());

    // Bare fork(2) carries none of the namespace/process-limit risk of
    // clone/clone3 and was historically left out of the BPF filter so
    // hot fork-loops (COW map-reduce) bypass the supervisor entirely.
    // It only needs interception when argv safety is required, so the
    // supervisor can register the new child via ptrace fork events before
    // user code can mutate argv observed by policy_fn or exec handlers.
    if features.argv_safety_required {
        nrs.push_optional(arch::sys_fork());
    }

    if features.memory_limit {
        // N83 phase 2 (D7): where the kernel enforces the memory budget, the
        // address-space accounting family leaves the table -- the ledger it
        // feeds is exactly what the kernel's `memory.max` replaced, so every
        // notification it buys is pure cost (one round trip per `mmap`/
        // `munmap`/`brk`, and N82 measured the hot ones sharing the 5000/s
        // notification budget at ~2600 op/s). The **clone** family stays
        // either way: `handle_fork` is the only enforcement point for
        // `clone3`'s namespace-creation ban and the checkpoint fork hold, so
        // retiring it would trade a security control for latency (Task 4's
        // ruling; see `Sandbox::kernel_enforced_limits`).
        if !features.kernel_enforced_limits {
            nrs.extend(ADDRESS_SPACE_ACCOUNTING_SYSCALLS);
        }
        // shmget is in notif only when SysV IPC is allowed. The BPF
        // layout puts notif JEQs before deny JEQs, so a syscall on
        // both lists would notify (RET_USER_NOTIF) and silently
        // bypass the kernel-level deny. When extra_allow_syscalls does not contain "sysv_ipc",
        // shmget belongs only on the blocklist.
        if features.sysv_ipc_allowed && !features.kernel_enforced_limits {
            nrs.push(libc::SYS_shmget);
        }
        nrs.extend(EXEC_ADDRESS_SPACE_RESET_SYSCALLS);
    }

    if features.network_supervision {
        nrs.extend(NETWORK_POLICY_SYSCALLS);
    } else if features.unix_fs_gate {
        // Named-unix gate: trap connect() (stream) and sendto()/sendmsg()/
        // sendmmsg() (datagram) so reaching a unix socket outside the fs-write
        // grants is denied, even when no IP network rules are present. Landlock
        // cannot gate this. Handlers bail cheaply on addr-less (connected) sends.
        nrs.push(libc::SYS_connect);
        nrs.push(libc::SYS_sendto);
        nrs.push(libc::SYS_sendmsg);
        nrs.push(libc::SYS_sendmmsg);
    }

    if features.random_seed {
        nrs.extend(RANDOM_NOTIF_SYSCALLS);
    }

    if features.time_start {
        nrs.extend(TIME_NOTIF_SYSCALLS);
    }

    nrs.extend(&procfs_hosts_notif_syscalls());
    nrs.extend(NETLINK_NOTIF_SYSCALLS);

    // Virtualize sched_getaffinity so nproc/sysconf agree with /proc/cpuinfo
    if features.virtual_cpu_count {
        nrs.push(libc::SYS_sched_getaffinity);
        nrs.push(libc::SYS_getcpu);
    }
    // Virtualize the raw syscall behind /proc/meminfo: sysinfo(2) is not
    // namespaced, so it would otherwise hand out the host's memory totals,
    // load average, process count and uptime.
    if features.memory_limit {
        nrs.push(libc::SYS_sysinfo);
    }
    // `statfs(2)` answers with the host volume's capacity; trap it when the
    // host maintains the sandbox's own accounting file. `fstatfs(2)` is the
    // fd-based sibling of the same question (`os.fstatvfs`, anything that
    // stats an open handle) -- leaving it out reports the node's volume on
    // exactly the calls a path-based trap does not cover.
    if features.disk_stats {
        nrs.push(libc::SYS_statfs);
        nrs.push(libc::SYS_fstatfs);
    }
    if features.virtual_hostname {
        nrs.extend(&[libc::SYS_uname, libc::SYS_openat]);
    }

    // COW filesystem interception (seccomp-based, unprivileged)
    if features.cow {
        nrs.extend(&cow_path_syscalls());
    }

    // Chroot path interception
    if features.chroot {
        nrs.extend(&chroot_path_syscalls());
        // N25: the file-size ceilings are the platform's. A sandbox process may
        // only *lower* them (see `file_size_limit_syscalls`).
        nrs.extend(&file_size_limit_syscalls());
    }

    // N81: the stat family is a *gate*, not a translation, so it only needs to
    // be on the notify table where the kernel would answer for something that
    // is not the sandbox's own. `stat_metadata_mediated` is that predicate.
    // Where it is false these syscalls leave the table entirely and the kernel
    // answers (see the N81 plan; measured by
    // `deploy/scripts/acceptance/probe_n81_proc_stat_shape.py`).
    if features.stat_metadata_mediated && (features.chroot || features.pid_ns) {
        nrs.extend(&stat_family_syscalls());
    }

    // Explicit deny-paths need path-bearing syscalls intercepted.
    if features.fs_denies {
        nrs.extend(&fs_denied_path_syscalls());
    }

    // Dynamic policy callback: intercept every syscall the event emitter
    // can decode.
    if features.policy_fn {
        nrs.extend(&policy_event_syscalls());
    }

    // Port remapping
    if features.port_remap {
        nrs.extend(PORT_REMAP_SYSCALLS);
    }

    // Inbound port mapping (S2.5)
    if features.inbound_port_map {
        nrs.extend(INBOUND_MAPPING_SYSCALLS);
        nrs.push_optional(arch::sys_poll());
        nrs.push_optional(arch::sys_epoll_wait());
        nrs.push_optional(arch::sys_accept());
    }

    nrs.finish()
}

/// Resolve `base` syscall names plus policy extras (and SysV IPC syscalls when
/// `policy.allows_sysv_ipc()` is false) to a deduplicated, ascending list of
/// numbers for the current architecture. Extras naming a syscall group
/// expand to the group's members.
///
/// A `SysnoSet` accumulates the membership: it dedups inherently (so SysV IPC
/// folds in with a plain `insert`) and iterates in ascending syscall order.
/// Names that do not exist on this architecture resolve to nothing and are
/// skipped, so the result stays arch-correct.
fn resolve_blocklist(base: &[&str], policy: &Sandbox) -> Vec<u32> {
    let extra_denies = policy.extra_deny_syscalls.iter().flat_map(|name| {
        match crate::sys::structs::syscall_group(name) {
            Some(members) => members.iter().copied().collect::<Vec<_>>(),
            None => vec![name.as_str()],
        }
    });
    let mut set: SysnoSet = base
        .iter()
        .copied()
        .chain(extra_denies)
        .filter_map(|n| n.parse::<Sysno>().ok())
        .collect();
    if !policy.allows_sysv_ipc() {
        for name in SYSV_IPC_BLOCKLIST_SYSCALLS {
            if let Ok(sysno) = name.parse::<Sysno>() {
                set.insert(sysno);
            }
        }
    }
    set.iter().map(|s| s.id() as u32).collect()
}

/// Resolve `NO_SUPERVISOR_BLOCKLIST_SYSCALLS` names to numbers, plus
/// SysV IPC syscalls when `policy.allows_sysv_ipc()` is false.
pub(crate) fn no_supervisor_blocklist_syscall_numbers(policy: &Sandbox) -> Vec<u32> {
    use crate::sys::structs::NO_SUPERVISOR_BLOCKLIST_SYSCALLS;
    resolve_blocklist(NO_SUPERVISOR_BLOCKLIST_SYSCALLS, policy)
}

/// Resolve the default syscall blocklist plus policy extras to numbers.
///
/// SysV IPC syscalls are appended to the resolved blocklist when
/// `policy.allows_sysv_ipc()` is false.
pub(crate) fn blocklist_syscall_numbers(policy: &Sandbox) -> Vec<u32> {
    resolve_blocklist(DEFAULT_BLOCKLIST_SYSCALLS, policy)
}

/// Build argument-level seccomp filter instructions matching the Python
/// `_build_arg_filters()` exactly.
///
/// Returns a `Vec<SockFilter>` containing self-contained BPF blocks for:
///   - clone: block namespace creation flags
///   - ioctl: block TIOCSTI, TIOCLINUX, SIOCGIF*, SIOCSIF*, SIOCETHTOOL,
///     FS_IOC_FIEMAP, FIBMAP, FIGETBSZ
///   - prctl: block PR_SET_DUMPABLE, PR_SET_SECUREBITS, PR_SET_PTRACER
///   - socket: block SOCK_RAW/SOCK_DGRAM on AF_INET/AF_INET6 (with type mask)
pub(crate) fn arg_filters(policy: &Sandbox) -> Vec<SockFilter> {
    let resolved = ResolvedSandbox::from_sandbox(policy, None, &[]);
    arg_filters_resolved(&resolved)
}

pub(crate) fn arg_filters_resolved(resolved: &ResolvedSandbox) -> Vec<SockFilter> {
    let features = &resolved.features;
    let ret_errno = SECCOMP_RET_ERRNO | EPERM as u32;
    let nr_clone = libc::SYS_clone as u32;
    let nr_ioctl = libc::SYS_ioctl as u32;
    let nr_prctl = libc::SYS_prctl as u32;
    let nr_socket = libc::SYS_socket as u32;

    let mut insns: Vec<SockFilter> = Vec::new();

    // --- clone: block namespace creation flags ---
    // 5 instructions:
    //   LD NR
    //   JEQ clone -> +0, skip 3
    //   LD arg0
    //   JSET NS_FLAGS -> +0, skip 1
    //   RET ERRNO
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
    insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_clone, 0, 3));
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO));
    insns.push(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NS_FLAGS as u32, 0, 1));
    insns.push(stmt(BPF_RET | BPF_K, ret_errno));

    // --- mknod / mknodat: block *device* nodes, keep FIFOs ---
    // Inside its own user namespace the sandbox holds CAP_MKNOD (F18 makes the
    // in-guest identity match a privileged supervisor's), so it could create a
    // block/char node in a writable directory and open it -- raw device access
    // that in practice is stopped only by the runtime's device cgroup, which a
    // plain process has no reason to have configured. `mkfifo()` is the *same*
    // syscall with S_IFIFO and workloads genuinely need it, so filter on the
    // file-type bits instead of the syscall name.
    // Layout per call (mode arg): LD NR, JEQ ->+0/skip 6, LD mode, AND S_IFMT,
    //   JEQ S_IFBLK ->+0/skip 1, RET ERRNO, JEQ S_IFCHR ->+0/skip 1, RET ERRNO.
    // The legacy `mknod` entry exists on x86_64 but not on aarch64, and its
    // mode is arg1 there; `mknodat` is the one glibc actually calls.
    let mut mknod_arms: Vec<(u32, u32)> = Vec::new();
    if let Some(nr) = arch::sys_mknod() {
        mknod_arms.push((nr as u32, OFFSET_ARGS1_LO));
    }
    mknod_arms.push((libc::SYS_mknodat as u32, OFFSET_ARGS2_LO));
    for (nr_mknod, mode_offset) in mknod_arms {
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_mknod, 0, 6));
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, mode_offset));
        insns.push(stmt(BPF_ALU | BPF_AND | BPF_K, libc::S_IFMT as u32));
        insns.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::S_IFBLK as u32,
            0,
            1,
        ));
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
        // A still holds the masked file type, so the second test needs no reload.
        insns.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::S_IFCHR as u32,
            0,
            1,
        ));
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
    }

    // --- ioctl: block dangerous commands ---
    // Block terminal injection (TIOCSTI, TIOCLINUX), network interface
    // enumeration and manipulation ioctls (SIOCGIF*/SIOCSIF*/SIOCETHTOOL) to
    // complement NETLINK_ROUTE virtualization, and the filesystem-layout
    // ioctls (FS_IOC_FIEMAP, FIBMAP, FIGETBSZ).
    //
    // What is deliberately NOT here is the terminal *write* family --
    // TCSETS/TCSETSW/TCSETSF, their TCSETS2/TCSETSW2/TCSETSF2 counterparts,
    // TIOCSWINSZ, TIOCSETD, TIOCSIG, TCXONC, TCFLSH. Those were candidates
    // and were dropped after measurement, because their safety does not come
    // from this list:
    //
    //  * `openpty`/`posix_openpt` and every raw-mode program depend on
    //    TCSETS/TCSETSW -- tmux, vim, ssh, less and `stty raw` all break
    //    without them. This list is also load-bearing for the platform's own
    //    PTY endpoint, which sets winsize via TIOCSWINSZ.
    //  * What they could attack is not reachable. Measured 2026-10-04 in a
    //    live sandbox: `/dev/pts` is a per-sandbox devpts instance (a
    //    freshly allocated sandbox lists only `ptmx`; the first openpty adds
    //    only its own `0`), so no other sandbox's ptys are in scope, and
    //    `/dev/tty` cannot be opened at all (ENXIO), so there is no
    //    controlling terminal to retarget. Every process in the sandbox is
    //    the same uid, so reconfigureing a sibling's terminal is already
    //    achievable with kill().
    //
    // TIOCSTI/TIOCLINUX are in this list for the opposite reason: they write
    // into a terminal's *input* queue, so their reach is the terminal a
    // descriptor names rather than the caller's own state.
    //
    // The per-sandbox devpts instance and the unopenable `/dev/tty` are the
    // two load-bearing preconditions for leaving the write family allowed.
    // Both are asserted by the parent repository's live-sandbox invariant
    // test; if either stops holding, this list needs the write family back.
    //
    // Layout: LD NR, JEQ ioctl (skip 1 + N*2), LD arg1, [JEQ cmd, RET ERRNO] * N
    let dangerous_ioctls: &[u32] = &[
        TIOCSTI as u32,
        TIOCLINUX as u32,
        SIOCGIFNAME as u32,
        SIOCGIFCONF as u32,
        SIOCGIFFLAGS as u32,
        SIOCSIFFLAGS as u32,
        SIOCSIFADDR as u32,
        SIOCGIFADDR as u32,
        SIOCSIFBRDADDR as u32,
        SIOCGIFDSTADDR as u32,
        SIOCGIFBRDADDR as u32,
        SIOCSIFNETMASK as u32,
        SIOCGIFNETMASK as u32,
        SIOCSIFHWADDR as u32,
        SIOCGIFHWADDR as u32,
        SIOCGIFINDEX as u32,
        SIOCETHTOOL as u32,
        FS_IOC_FIEMAP as u32,
        FIBMAP as u32,
        FIGETBSZ as u32,
    ];
    let n_ioctls = dangerous_ioctls.len();
    // The JEQ skip field is 8 bits wide, so the whole chain must stay under
    // 255 instructions. Asserted rather than assumed: a longer list would
    // truncate to a wrapped count and quietly stop matching codes late in the
    // chain instead of failing to build.
    assert!(
        (1 + n_ioctls * 2) <= u8::MAX as usize,
        "ioctl deny list too long for the 8-bit JEQ skip field: {} entries",
        n_ioctls
    );
    let skip_count = (1 + n_ioctls * 2) as u8;
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
    insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_ioctl, 0, skip_count));
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS1_LO));
    for &cmd in dangerous_ioctls {
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, cmd, 0, 1));
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
    }

    // --- prctl: block dangerous options ---
    // Layout: LD NR, JEQ prctl (skip 1 + N*2), LD arg0, [JEQ op, RET ERRNO] * N
    let dangerous_prctl_ops: &[u32] = &[PR_SET_DUMPABLE, PR_SET_SECUREBITS, PR_SET_PTRACER];
    let n_ops = dangerous_prctl_ops.len();
    let skip_count = (1 + n_ops * 2) as u8;
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
    insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_prctl, 0, skip_count));
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO));
    for &op in dangerous_prctl_ops {
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, op, 0, 1));
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
    }

    // --- socket: block SOCK_RAW and/or SOCK_DGRAM on AF_INET/AF_INET6 ---
    //
    // SOCK_RAW is unconditionally denied. Sandlock does not expose
    // raw ICMP: packet-crafting capabilities aren't part of the XOA
    // threat model, and destination filtering at `sendto` can't be
    // honestly enforced for raw sockets (the agent controls the IP
    // header). Workloads that need ping should use the kernel ping
    // socket (SOCK_DGRAM + IPPROTO_ICMP) via an `icmp://...` rule.
    //
    // SOCK_DGRAM is denied only when no net rule exists at all. Once any
    // `--net-allow`/`--net-deny` rule is present, connect/sendto/sendmsg/
    // sendmmsg are trapped and destination-checked per protocol, and a
    // protocol with no rule resolves to an empty allowlist that denies
    // every destination — so creation itself is harmless and must be
    // permitted: glibc's getaddrinfo creates UDP sockets for its RFC 3484
    // address-sorting probes (connect, never send), and blocking those
    // breaks name resolution for TCP-only rule sets. Gating stays at
    // socket() only for the no-rules sandbox, where nothing traps sends.
    // This must NOT widen to HTTP-ACL-only or policy_fn-only configs:
    // their empty net_allow resolves the UDP policy to Unrestricted, so
    // creation would mean unrestricted UDP egress.
    let mut blocked_types: Vec<u32> = Vec::new();
    blocked_types.push(SOCK_RAW);
    if !features.net_allow_present && !features.net_deny {
        blocked_types.push(SOCK_DGRAM);
    }

    if !blocked_types.is_empty() {
        let n = blocked_types.len();
        // Instructions after domain checks: 2 (load+AND) + N (JEQs) + 1 (RET)
        let after_domain = 2 + n + 1;
        // Total after NR check: 3 (load domain + 2 JEQs) + after_domain
        let skip_all = (3 + after_domain) as u8;

        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_socket, 0, skip_all));
        // Load domain (arg0)
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO));
        // AF_INET -> skip to type check (jump over AF_INET6 check)
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 1, 0));
        // AF_INET6 -> type check; else skip everything remaining
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, after_domain as u8));
        // Load type (arg1) and mask off SOCK_NONBLOCK|SOCK_CLOEXEC
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS1_LO));
        insns.push(stmt(BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK));
        // Check each blocked type
        for (i, &sock_type) in blocked_types.iter().enumerate() {
            let remaining = n - i - 1;
            // Match -> jump to RET ERRNO (skip 'remaining' JEQs ahead)
            // No match on last type -> skip past RET ERRNO (jf=1)
            // No match on non-last -> check next type (jf=0)
            let jf: u8 = if remaining == 0 { 1 } else { 0 };
            insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, sock_type, remaining as u8, jf));
        }
        // Deny return (reached by any matching JEQ)
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
    }

    // (raw ICMP carve-out removed: SOCK_RAW is unconditionally denied
    // by the blocked_types block above. Sandlock does not expose raw
    // sockets; ping uses the SOCK_DGRAM kernel ping socket via an
    // `icmp://...` rule, gated by host `ping_group_range`.)

    // --- wait4: skip notification for WNOHANG/WNOWAIT (non-blocking) ---
    // wait4(pid, status, options, rusage): options is arg2
    // 5 instructions:
    //   LD NR
    //   JEQ wait4 -> +0, skip 3
    //   LD arg2
    //   JSET (WNOHANG|WNOWAIT) -> +0, skip 1
    //   RET ALLOW
    {
        let nr_wait4 = libc::SYS_wait4 as u32;
        let wnohang_or_wnowait = (libc::WNOHANG | 0x0100_0000/* WNOWAIT */) as u32;
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_wait4, 0, 3));
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS2_LO));
        insns.push(jump(BPF_JMP | BPF_JSET | BPF_K, wnohang_or_wnowait, 0, 1));
        insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    // --- waitid: skip notification for WNOHANG/WNOWAIT (non-blocking) ---
    // waitid(idtype, id, infop, options, rusage): options is arg3
    {
        let nr_waitid = libc::SYS_waitid as u32;
        let wnohang_or_wnowait = (libc::WNOHANG | 0x0100_0000/* WNOWAIT */) as u32;
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_waitid, 0, 3));
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS3_LO));
        insns.push(jump(BPF_JMP | BPF_JSET | BPF_K, wnohang_or_wnowait, 0, 1));
        insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    insns
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    /// Is the stat family's metadata half on the notify list for this policy?
    fn metadata_gated(policy: &Sandbox) -> bool {
        let family: BTreeSet<u32> = stat_family_syscalls()
            .into_iter()
            .map(|n| n as u32)
            .collect();
        let planned: BTreeSet<u32> = notif_syscalls(policy, None).into_iter().collect();
        family.is_subset(&planned)
    }

    fn own_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("sandlock-n81-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("proc")).unwrap();
        root
    }

    /// N81: a root of the sandbox's own, whose `/proc` is a plain directory of
    /// that same root, is the shape where the kernel answers for the sandbox's
    /// own tree -- so the stat gate leaves the notify table (that is the whole
    /// point: 26 us -> the bare kernel cost).
    #[test]
    fn an_own_root_with_a_plain_proc_drops_the_stat_gate() {
        let root = own_root("plain");
        let policy = Sandbox::builder()
            .chroot(root.clone())
            .pid_ns(true)
            .build()
            .unwrap();
        assert!(!metadata_gated(&policy), "gate should be gone for {root:?}");
    }

    /// The identity root (`chroot("/")`) is the shape the gate exists for: its
    /// `/proc` is a real mount, so a numeric path would reach the host table.
    #[test]
    fn the_identity_root_keeps_the_stat_gate() {
        let policy = Sandbox::builder()
            .chroot("/")
            .pid_ns(true)
            .build()
            .unwrap();
        assert!(metadata_gated(&policy));
    }

    /// No root at all: the sandbox's `/proc` is the container's procfs. This is
    /// the E5.1 / library shape, and it keeps today's interception.
    #[test]
    fn no_root_at_all_keeps_the_stat_gate() {
        let policy = Sandbox::builder().pid_ns(true).build().unwrap();
        assert!(metadata_gated(&policy));
    }

    /// A policy mount at or under `/proc` is made by the child *after* the
    /// filesystem check, so the policy alone can keep the gate.
    #[test]
    fn a_policy_mount_at_proc_keeps_the_stat_gate() {
        let root = own_root("mount");
        let policy = Sandbox::builder()
            .chroot(root)
            .pid_ns(true)
            .fs_mount("/proc", "/etc")
            .build()
            .unwrap();
        assert!(metadata_gated(&policy));
    }

    /// The predicate is evaluated in two processes -- the launcher (host path
    /// visible) and the confined child (already pivoted, so the root is `/`) --
    /// and both have to walk the same code and reach the same answer. A
    /// disagreement puts the family on the notify list while the supervisor has
    /// no handler for it: measured on the cluster (2026-10-06) as a 5000/s
    /// ceiling with ~940 ms stalls and *nothing* behind the round trip.
    #[test]
    fn both_views_of_the_root_agree() {
        let root = own_root("views");
        let policy = Sandbox::builder()
            .chroot(root.clone())
            .pid_ns(true)
            .build()
            .unwrap();
        // The launcher's view: the root at its host path.
        assert!(!metadata_gated(&policy), "host-path view should drop the gate");
        // The same root, spelled as the confined child would spell it (the
        // child's `/` is this directory). Same answer required.
        assert!(
            !crate::resolved::stat_metadata_mediated_at(&policy, &root),
            "an explicit view of the same root must agree with the host path"
        );
    }

    // ------------------------------------------------------- N83 phase 2 / T4

    /// The **address-space accounting** family: the syscalls whose only reason
    /// to be on the notify table is the mediator's own byte ledger of a
    /// sandbox's memory (`resource::handle_memory`). `shmget` travels with
    /// them -- it is the SysV spelling of the same allocation, on the table
    /// for the same ledger.
    fn address_space_family() -> Vec<u32> {
        let mut nrs: Vec<u32> = [
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_brk,
            libc::SYS_mremap,
            libc::SYS_shmget,
        ]
        .iter()
        .map(|&n| n as u32)
        .collect();
        nrs.sort_unstable();
        nrs
    }

    /// A memory-limited sandbox with SysV IPC allowed -- so `shmget` is a real
    /// member of the family -- and the kernel lane switched either way.
    /// `sysv_ipc` goes in `extra_allow_syscalls` because outside it `shmget` is
    /// on the blocklist and never reaches the notify table at all.
    fn accounting_lane(kernel_enforced: bool) -> Sandbox {
        Sandbox::builder()
            .max_memory(crate::sandbox::ByteSize::mib(256))
            .extra_allow_syscalls(vec!["sysv_ipc".into()])
            .kernel_enforced_limits(kernel_enforced)
            .build()
            .unwrap()
    }

    fn traced(policy: &Sandbox) -> BTreeSet<u32> {
        notif_syscalls(policy, None).into_iter().collect()
    }

    /// N83 phase 2 (Task 4, D7): where the kernel enforces the memory budget,
    /// the address-space accounting family leaves the table -- **exactly** it,
    /// and nothing else. Both directions are asserted, so a future change that
    /// quietly drops a fifth syscall (or takes one of its neighbours with it)
    /// fails here by name.
    #[test]
    fn the_kernel_lane_retires_exactly_the_address_space_accounting_family() {
        let off = traced(&accounting_lane(false));
        let on = traced(&accounting_lane(true));

        let retired: Vec<u32> = off.difference(&on).copied().collect();
        assert_eq!(
            retired,
            address_space_family(),
            "the kernel lane must retire the address-space accounting family \
             and nothing else"
        );
        let added: Vec<u32> = on.difference(&off).copied().collect();
        assert!(
            added.is_empty(),
            "the kernel lane must not add notify-table members: {added:?}"
        );
    }

    /// The other half of the ruling: the **clone family stays**, kernel lane or
    /// not. `resource::handle_fork` is this fork's only enforcement point for
    /// the namespace-creation ban on `clone3` -- the cBPF arg filter can read
    /// `clone`'s `args[0]`, but `clone_args` sits behind a user pointer cBPF
    /// cannot follow, and `clone3` is not on the default blocklist -- and it is
    /// also what parks forks (`hold_forks`) across a checkpoint. Retiring those
    /// entries would trade a security control for latency.
    #[test]
    fn the_kernel_lane_keeps_the_whole_clone_family() {
        let on = traced(&accounting_lane(true));
        for nr in arch::fork_like_syscalls() {
            // Bare `fork(2)` is the one exception, and it has nothing to do
            // with the ledger: it reaches the table only when argv safety is
            // required (see `notif_syscalls`), which this policy does not ask
            // for.
            if Some(nr) == arch::sys_fork() {
                continue;
            }
            assert!(
                on.contains(&(nr as u32)),
                "fork-class syscall {nr} must stay on the notify table: \
                 handle_fork is the only clone3 namespace-creation ban"
            );
        }
        for nr in [libc::SYS_wait4, libc::SYS_waitid] {
            assert!(
                on.contains(&(nr as u32)),
                "wait-family syscall {nr} must stay: proc_count's release path \
                 is lazy without argv safety"
            );
        }
    }

    /// `off` is byte-for-byte today: a policy that never mentions the field at
    /// all and the same policy spelling it `false` plan the **same** table,
    /// with the whole accounting family on it. The field's absence has to mean
    /// the old behaviour -- that is what every deployment which has not
    /// switched lanes looks like.
    #[test]
    fn the_default_lane_keeps_todays_table() {
        let unspecified = Sandbox::builder()
            .max_memory(crate::sandbox::ByteSize::mib(256))
            .extra_allow_syscalls(vec!["sysv_ipc".into()])
            .build()
            .unwrap();
        let explicit_off = traced(&accounting_lane(false));
        assert_eq!(
            traced(&unspecified),
            explicit_off,
            "an unset field must plan exactly what an explicit `false` plans"
        );
        for nr in address_space_family() {
            assert!(
                explicit_off.contains(&nr),
                "syscall {nr} belongs on the default lane's notify table"
            );
        }
    }
}
