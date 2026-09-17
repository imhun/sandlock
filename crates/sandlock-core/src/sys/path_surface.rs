//! The path surface: every syscall that can name a filesystem object outside
//! the sandbox's virtual root, and what confines it.
//!
//! # Why this file exists
//!
//! The chroot (image-rootfs) shape has **no kernel-level root**: the confined
//! child's kernel root is still the host root, and the supervisor manufactures
//! the rootfs view by intercepting path syscalls and resolving them through
//! `chroot_root` (`chroot/dispatch.rs`). `landlock.rs` relies on that being
//! airtight -- "*only chroot-translated paths are added -- host paths are NOT
//! added, so any seccomp fallthrough is blocked by Landlock (fail-closed)*" --
//! which makes "the interception list is complete" a **security invariant the
//! code never checked**. `chroot(2)` was a live counter-example: absent from
//! `chroot_path_syscalls()` and from the blocklist, so the kernel executed it
//! against the host root and a sandbox could chroot into a host-only directory
//! (E2B audit 2026-09-17, OBS-1; fixed by blocklisting it).
//!
//! This ledger turns that prose invariant into a checked one. The tests below
//! fail when:
//!
//! 1. `chroot_path_syscalls()` gains or loses a member the ledger does not
//!    record ([`tests::mediated_set_matches_the_ledger`]) -- the interception
//!    list cannot drift unreviewed;
//! 2. a `Blocked` entry is not actually resolved into the seccomp blocklist
//!    ([`tests::blocked_entries_are_actually_refused`]);
//! 3. a ledger name does not resolve on this architecture
//!    ([`tests::every_ledger_name_resolves_on_this_arch`]) -- a typo cannot
//!    silently pass;
//! 4. **any syscall the `syscalls` crate knows is unclassified**
//!    ([`tests::every_arch_syscall_is_classified`]) -- so a kernel/crate that
//!    adds a syscall turns this red instead of silently widening the
//!    fallthrough set.
//!
//! # How entries were classified
//!
//! Not from memory: every non-`Mediated` entry below was probed from inside a
//! real sandbox on the audit kernel (Linux 7.0.14-orbstack, Landlock ABI 8) in
//! the mediated (image-rootfs) shape, and the measured result is what the
//! reason string records. Runbook and raw output: `docs/security-audit/`
//! (`OBS-2`, plus `tmp/sec-pathsb*-probe.py` in the E2B tree).
//!
//! `Disposition::Open` is the honest bucket: unmediated, no gate demonstrated
//! on the audit kernel, **needs a decision**. An entry that cannot be closed by
//! mediation or a gate belongs there rather than in a comfortable `Gated`.

use crate::seccomp::syscall::syscall_name_to_nr;

/// What stands between a syscall and the host filesystem in the confined child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Refused by the seccomp blocklist (`DEFAULT_BLOCKLIST_SYSCALLS`).
    Blocked,
    /// Not intercepted, but a gate the syscall cannot pass confines it. The
    /// reason names the gate *and* the measurement behind the claim.
    Gated(&'static str),
    /// Unmediated and no gate demonstrated: the fallthrough set this ledger
    /// exists to keep empty. Needs a decision (mediate it, block it, or prove
    /// the gate).
    Open(&'static str),
}

/// The syscalls `chroot_path_syscalls()` is expected to intercept, by name.
///
/// Kept as names (not numbers) so an accidental edit to the plan's list is a
/// visible diff here rather than a silent hole; `mediated_set_matches_the_ledger`
/// compares it against the resolved list both ways.
pub(crate) const MEDIATED_PATH_SYSCALLS: &[&str] = &[
    "openat",
    "openat2",
    "execve",
    "execveat",
    "unlinkat",
    "mkdirat",
    "renameat2",
    "symlinkat",
    "linkat",
    "fchmodat",
    "fchownat",
    "truncate",
    "newfstatat",
    "statx",
    "faccessat",
    "faccessat2",
    "readlinkat",
    "getdents64",
    "chdir",
    "fchdir",
    "inotify_add_watch",
    "getcwd",
    "statfs",
    "utimensat",
    "getxattr",
    "lgetxattr",
    "setxattr",
    "lsetxattr",
    "listxattr",
    "llistxattr",
    "removexattr",
    "lremovexattr",
    "open",
    "stat",
    "lstat",
    "access",
    "readlink",
    "getdents",
    "unlink",
    "rmdir",
    "mkdir",
    "rename",
    "renameat",
    "symlink",
    "link",
    "chmod",
    "chown",
    "lchown",
];

/// Syscalls that name a filesystem object and are **not** mediated.
///
/// Every one of these either has a gate the sandbox cannot pass, or is an open
/// item. The list is the reviewable half of the invariant; the other half is
/// [`NON_PATH_SYSCALLS`], whose job is to make the classification total.
pub(crate) const UNMEDIATED_PATH_TAKING: &[(&str, Disposition)] = &[
    // ---- open items: unmediated, no demonstrated gate ---------------------
    (
        "open_tree",
        Disposition::Open(
            "mount API without OPEN_TREE_CLONE is an O_PATH open; MEASURED to return an fd \
             for a host directory. Traversal through that fd was refused (openat -> EACCES, \
             the mediator will not resolve a dirfd outside the virtual root) and \
             getdents64 -> EBADF, so no content leak was demonstrated -- but the path was \
             resolved by the kernel against the host root, which is the property this \
             ledger tracks.",
        ),
    ),
    (
        "fchmodat2",
        Disposition::Open("at-style chmod; ENOSYS on the audit kernel, live on kernels >= 6.6"),
    ),
    (
        "getxattrat",
        Disposition::Open("at-style xattr read; ENOSYS on the audit kernel, live on kernels >= 6.13"),
    ),
    (
        "setxattrat",
        Disposition::Open("at-style xattr write; ENOSYS on the audit kernel, live on kernels >= 6.13"),
    ),
    (
        "listxattrat",
        Disposition::Open("at-style xattr list; ENOSYS on the audit kernel, live on kernels >= 6.13"),
    ),
    (
        "removexattrat",
        Disposition::Open("at-style xattr remove; ENOSYS on the audit kernel, live on kernels >= 6.13"),
    ),
    (
        "open_tree_attr",
        Disposition::Open("same family as open_tree; ENOSYS on the audit kernel"),
    ),
    (
        "statmount",
        Disposition::Open(
            "takes a mount id, not a path, but returns host mount metadata \
             (root/mountpoint strings): an information-disclosure surface rather than a \
             path-resolution one. ENOSYS on the audit kernel.",
        ),
    ),
    (
        "listmount",
        Disposition::Open("mount enumeration by id; same disclosure class as statmount; ENOSYS on the audit kernel"),
    ),
    (
        "file_getattr",
        Disposition::Open("kernel 6.13+; signature not verified on the audit kernel (ENOSYS). Review before enabling"),
    ),
    (
        "file_setattr",
        Disposition::Open("kernel 6.13+; signature not verified on the audit kernel (ENOSYS). Review before enabling"),
    ),
    // ---- gated: measured --------------------------------------------------
    (
        "creat",
        Disposition::Gated(
            "Landlock: MEASURED EACCES when truncating an existing host-readable file \
             outside fs_writable",
        ),
    ),
    (
        "mknod",
        Disposition::Gated(
            "Landlock gates the create; device types are additionally refused by the \
             seccomp arg filter (FIFOs are allowed on purpose)",
        ),
    ),
    (
        "mknodat",
        Disposition::Gated("same as mknod; not path-mediated, Landlock + the arg filter bound it"),
    ),
    (
        "utime",
        Disposition::Gated("Landlock denies the write; MEASURED EACCES on a host directory"),
    ),
    (
        "utimes",
        Disposition::Gated("same as utime (utimensat is the mediated spelling)"),
    ),
    (
        "futimesat",
        Disposition::Gated("same as utime (utimensat is the mediated spelling)"),
    ),
    (
        "fanotify_mark",
        Disposition::Gated("fanotify_init needs CAP_SYS_ADMIN; MEASURED EPERM, so no mark can be established"),
    ),
    (
        "move_mount",
        Disposition::Gated("CAP_SYS_ADMIN in the mount namespace's userns; MEASURED EPERM"),
    ),
    (
        "fspick",
        Disposition::Gated("mount API; CAP_SYS_ADMIN-gated like move_mount (fsopen measured EPERM)"),
    ),
    (
        "mount_setattr",
        Disposition::Gated("CAP_SYS_ADMIN-gated mount API; the attribute argument was rejected (EINVAL) before any path effect"),
    ),
    (
        "uselib",
        Disposition::Gated("obsolete: ENOSYS on every supported kernel"),
    ),
    (
        "mq_open",
        Disposition::Gated("resolves in the mqueue filesystem, which the worker does not mount"),
    ),
    (
        "mq_unlink",
        Disposition::Gated(
            "resolves in the mqueue filesystem like mq_open, which the worker does not mount",
        ),
    ),
    // ---- blocked ----------------------------------------------------------
    // The OBS-1 fallthrough: unmediated, resolved against the host root, so a
    // sandbox could chroot into a host-only directory. Blocklisted 2026-09-17;
    // recorded here because it is the reason this ledger exists.
    ("chroot", Disposition::Blocked),
];

/// What confines a path-taking syscall in the **pure** (no-chroot) shape.
///
/// The pure shape has no rootfs and *no mediator at all*: the sandbox's view is
/// the host's and Landlock is the only barrier. Landlock's access rights are a
/// closed set (execute / read_file / read_dir / write_file / remove_file /
/// remove_dir / make_* / refer / truncate / ioctl_dev), so a path-taking
/// syscall outside that set is **ungated** there even though the chroot shape
/// mediates it. Measured on the audit kernel against a host directory the
/// sandbox may traverse (`/obs6_hostdir`, 0755) and a host file (0644):
/// `statx` -> OK, `faccessat` -> OK, `readlinkat` -> resolved (EINVAL, not a
/// link), `listxattr` -> OK, `getxattr` -> reached the inode (ENODATA), and
/// from the unmediated list `inotify_add_watch` -> watched and delivered host
/// file names, `open_tree` -> returned an fd.
///
/// The three lists below partition the path surface *by pure-shape verdict*
/// and `pure_shape_classifies_every_path_taking_syscall` keeps that partition
/// exact, so the ungated set is the worklist for the pure shape rather than
/// something to re-derive by probing.

/// Landlock refuses the operation itself.
pub(crate) const PURE_LANDLOCK_GATED: &[&str] = &[
    // read / write / execute
    "open", "openat", "openat2", "execve", "execveat",
    // directory enumeration
    "getdents", "getdents64",
    // creation
    "mkdir", "mkdirat", "mknod", "mknodat", "creat",
    // removal
    "unlink", "unlinkat", "rmdir",
    // refer (rename/link) and symlink creation
    "rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat",
    // truncate
    "truncate",
];

/// Not Landlock, but a kernel-side gate the sandbox cannot pass: a capability
/// held only in the initial user namespace, an obsolete syscall, or the
/// seccomp blocklist every shape installs (reason strings say which).
pub(crate) const PURE_GATED_ELSEWHERE: &[(&str, &str)] = &[
    ("chroot", "blocklisted in every shape (OBS-1)"),
    ("chown", "ownership/DAC only, no Landlock right: the sandbox owns nothing outside its workspace"),
    ("lchown", "ownership/DAC only, see chown"),
    ("fchownat", "ownership/DAC only, see chown"),
    ("fanotify_mark", "fanotify_init needs CAP_SYS_ADMIN in the initial userns (measured EPERM)"),
    ("move_mount", "CAP_SYS_ADMIN in the mount namespace's userns (measured EPERM)"),
    ("fspick", "mount API, CAP_SYS_ADMIN-gated like move_mount"),
    ("mount_setattr", "mount API, CAP_SYS_ADMIN-gated"),
    ("open_tree_attr", "same family as open_tree; ENOSYS on the audit kernel"),
    ("file_getattr", "kernel 6.13+; ENOSYS on the audit kernel, signature unverified"),
    ("file_setattr", "kernel 6.13+; ENOSYS on the audit kernel, signature unverified"),
    ("statmount", "takes a mount id, not a path; ENOSYS on the audit kernel. Would disclose mount metadata when it lands"),
    ("listmount", "mount enumeration by id, see statmount; ENOSYS on the audit kernel"),
    ("uselib", "obsolete, ENOSYS"),
    ("mq_open", "resolves in the mqueue filesystem, which the worker does not mount"),
    ("mq_unlink", "same as mq_open"),
];

/// **Ungated in the pure shape**: no Landlock access right covers it and no
/// other kernel-side gate was found, so the call reaches the host object. In
/// the chroot shape these are mediated (the first column of
/// [`MEDIATED_PATH_SYSCALLS`]) or already recorded as open above.
///
/// Read as a leak list rather than an exploit list: what it exposes is host
/// **metadata** (existence, size, timestamps, inode, symlink targets, xattr
/// names and values) plus directory-change events -- information about files
/// the sandbox cannot read. That is the pure shape's actual confinement
/// boundary, and the reason the pure shape is not a security boundary for
/// tenants that must not learn about each other.
pub(crate) const PURE_UNGATED: &[(&str, &str)] = &[
    ("stat", "metadata: existence, size, timestamps, inode (measured OK)"),
    ("lstat", "metadata, see stat"),
    ("newfstatat", "metadata, see stat"),
    ("statx", "metadata, see stat (measured OK)"),
    ("statfs", "filesystem metadata (size/free/type)"),
    ("access", "existence + permission probe (measured OK via faccessat)"),
    ("faccessat", "existence + permission probe (measured OK)"),
    ("faccessat2", "existence + permission probe, see faccessat"),
    ("readlink", "symlink target (measured: path resolved)"),
    ("readlinkat", "symlink target, see readlink"),
    ("chdir", "moves the cwd; no Landlock right covers it"),
    ("fchdir", "see chdir"),
    ("getcwd", "see chdir"),
    ("chmod", "mode change is ownership-gated (DAC), not Landlock-gated"),
    ("fchmodat", "see chmod"),
    ("utimensat", "timestamps are DAC-gated only, not Landlock-gated"),
    ("utime", "see utimensat"),
    ("utimes", "see utimensat"),
    ("futimesat", "see utimensat"),
    ("getxattr", "attribute value (measured: reached the inode)"),
    ("lgetxattr", "attribute value, see getxattr"),
    ("setxattr", "attribute write, DAC-gated only"),
    ("lsetxattr", "see setxattr"),
    ("listxattr", "attribute names (measured OK)"),
    ("llistxattr", "attribute names, see listxattr"),
    ("removexattr", "attribute removal, DAC-gated only"),
    ("lremovexattr", "see removexattr"),
    ("inotify_add_watch", "directory events + host file names (measured leak, OBS-2)"),
    ("open_tree", "O_PATH fd for a host object (measured); traversal refused by the mediator only in the chroot shape"),
    ("fchmodat2", "at-style chmod; ENOSYS on the audit kernel, live on kernels >= 6.6"),
    ("getxattrat", "at-style xattr read; ENOSYS on the audit kernel, live on kernels >= 6.13"),
    ("setxattrat", "at-style xattr write; ENOSYS on the audit kernel"),
    ("listxattrat", "at-style xattr list; ENOSYS on the audit kernel"),
    ("removexattrat", "at-style xattr remove; ENOSYS on the audit kernel"),
];

/// Every syscall this architecture knows that is neither mediated nor in the
/// path-taking ledger above -- i.e. the reviewed claim "this syscall cannot
/// name a filesystem object outside the virtual root".
///
/// Generated by enumerating the `syscalls` crate's table and subtracting the
/// interception list, the resolved blocklist, and [`UNMEDIATED_PATH_TAKING`];
/// then reviewed by name. It is deliberately exhaustive rather than a curated
/// subset: that is what makes [`tests::every_arch_syscall_is_classified`] total,
/// so a new syscall cannot quietly join the fallthrough set.
pub(crate) const NON_PATH_SYSCALLS: &[&str] = &[
    "read", "write", "close", "fstat",
    "poll", "lseek", "mmap", "mprotect",
    "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
    "rt_sigreturn", "ioctl", "pread64", "pwrite64",
    "readv", "writev", "pipe", "select",
    "sched_yield", "mremap", "msync", "mincore",
    "madvise", "dup", "dup2", "pause",
    "nanosleep", "getitimer", "alarm", "setitimer",
    "getpid", "sendfile", "socket", "connect",
    "accept", "sendto", "recvfrom", "sendmsg",
    "recvmsg", "shutdown", "bind", "listen",
    "getsockname", "getpeername", "socketpair", "setsockopt",
    "getsockopt", "clone", "fork", "vfork",
    "exit", "wait4", "kill", "uname",
    "fcntl", "flock", "fsync", "fdatasync",
    "ftruncate", "fchmod", "fchown", "umask",
    "gettimeofday", "getrlimit", "getrusage", "sysinfo",
    "times", "getuid", "syslog", "getgid",
    "setuid", "setgid", "geteuid", "getegid",
    "setpgid", "getppid", "getpgrp", "setsid",
    "setreuid", "setregid", "getgroups", "setgroups",
    "setresuid", "getresuid", "setresgid", "getresgid",
    "getpgid", "setfsuid", "setfsgid", "getsid",
    "capget", "capset", "rt_sigpending", "rt_sigtimedwait",
    "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "ustat",
    "fstatfs", "sysfs", "getpriority", "setpriority",
    "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
    "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock",
    "munlock", "mlockall", "munlockall", "vhangup",
    "modify_ldt", "_sysctl", "prctl", "arch_prctl",
    "adjtimex", "setrlimit", "sync", "settimeofday",
    "create_module", "get_kernel_syms", "query_module", "getpmsg",
    "putpmsg", "afs_syscall", "tuxcall", "security",
    "gettid", "readahead", "fsetxattr", "fgetxattr",
    "flistxattr", "fremovexattr", "tkill", "time",
    "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
    "io_setup", "io_destroy", "io_getevents", "io_submit",
    "io_cancel", "get_thread_area", "epoll_create", "epoll_ctl_old",
    "epoll_wait_old", "remap_file_pages", "set_tid_address", "restart_syscall",
    "fadvise64", "timer_create", "timer_settime", "timer_gettime",
    "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime",
    "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait",
    "epoll_ctl", "tgkill", "vserver", "mbind",
    "set_mempolicy", "get_mempolicy", "mq_timedsend", "mq_timedreceive",
    "mq_notify", "mq_getsetattr", "waitid", "ioprio_set",
    "ioprio_get", "inotify_init", "inotify_rm_watch", "migrate_pages",
    "pselect6", "ppoll", "set_robust_list", "get_robust_list",
    "splice", "tee", "sync_file_range", "vmsplice",
    "move_pages", "epoll_pwait", "signalfd", "timerfd_create",
    "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime",
    "accept4", "signalfd4", "eventfd2", "epoll_create1",
    "dup3", "pipe2", "inotify_init1", "preadv",
    "pwritev", "rt_tgsigqueueinfo", "recvmmsg", "fanotify_init",
    "prlimit64", "clock_adjtime", "syncfs", "sendmmsg",
    "getcpu", "kcmp", "sched_setattr", "sched_getattr",
    "seccomp", "getrandom", "memfd_create", "kexec_file_load",
    "membarrier", "mlock2", "copy_file_range", "preadv2",
    "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free",
    "io_pgetevents", "rseq", "uretprobe", "uprobe",
    "pidfd_send_signal", "fsopen", "fsconfig", "fsmount",
    "pidfd_open", "clone3", "close_range", "pidfd_getfd",
    "process_madvise", "epoll_pwait2", "quotactl_fd", "landlock_create_ruleset",
    "landlock_add_rule", "landlock_restrict_self", "memfd_secret", "process_mrelease",
    "futex_waitv", "set_mempolicy_home_node", "cachestat", "map_shadow_stack",
    "futex_wake", "futex_wait", "futex_requeue", "lsm_get_self_attr",
    "lsm_set_self_attr", "lsm_list_modules", "mseal",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp_plan::{blocklist_syscall_numbers, chroot_path_syscalls};
    use std::collections::BTreeSet;

    fn arch_syscalls() -> Vec<String> {
        (0usize..600)
            .filter_map(syscalls::Sysno::new)
            .map(|s| s.to_string())
            .collect()
    }

    fn mediated_names() -> BTreeSet<String> {
        chroot_path_syscalls()
            .into_iter()
            .map(|n| syscalls::Sysno::new(n as usize).unwrap().to_string())
            .collect()
    }

    /// The interception list and the ledger must describe the same set: a
    /// member added to the plan without a ledger row (or removed from the plan
    /// while the ledger still claims mediation) is exactly the drift that let
    /// `chroot` through.
    #[test]
    fn mediated_set_matches_the_ledger() {
        let mediated = mediated_names();
        let ledger: BTreeSet<String> =
            MEDIATED_PATH_SYSCALLS.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            mediated, ledger,
            "chroot_path_syscalls() and MEDIATED_PATH_SYSCALLS disagree"
        );
    }

    #[test]
    fn every_ledger_name_resolves_on_this_arch() {
        for name in MEDIATED_PATH_SYSCALLS {
            assert!(
                syscall_name_to_nr(name).is_some(),
                "mediated ledger name {name} does not resolve on this architecture"
            );
        }
        for (name, _) in UNMEDIATED_PATH_TAKING {
            assert!(
                syscall_name_to_nr(name).is_some(),
                "path-surface entry {name} does not resolve on this architecture"
            );
        }
    }

    /// `Blocked` is a claim about the *resolved* filter, not about a string in
    /// a list: a name that fails to resolve would be silently dropped.
    #[test]
    fn blocked_entries_are_actually_refused() {
        let policy = crate::sandbox::Sandbox::builder().build().unwrap();
        let resolved: BTreeSet<u32> = blocklist_syscall_numbers(&policy).into_iter().collect();
        for (name, disposition) in UNMEDIATED_PATH_TAKING {
            if *disposition != Disposition::Blocked {
                continue;
            }
            let nr = syscall_name_to_nr(name).expect("resolves");
            assert!(
                resolved.contains(&nr),
                "{name} is recorded as Blocked but is not in the resolved blocklist"
            );
        }
    }

    /// Open items must say why, and the set of them must not grow by accident:
    /// this is the bucket a reviewer is expected to empty.
    #[test]
    fn open_items_are_enumerated_and_reasoned() {
        let open: Vec<&str> = UNMEDIATED_PATH_TAKING
            .iter()
            .filter(|(_, d)| matches!(d, Disposition::Open(_)))
            .map(|(n, _)| *n)
            .collect();
        for (name, disposition) in UNMEDIATED_PATH_TAKING {
            if let Disposition::Open(reason) | Disposition::Gated(reason) = disposition {
                assert!(
                    reason.len() > 40,
                    "{name} carries a disposition without a real reason"
                );
            }
        }
        assert_eq!(
            open,
            vec![
                "open_tree",
                "fchmodat2",
                "getxattrat",
                "setxattrat",
                "listxattrat",
                "removexattrat",
                "open_tree_attr",
                "statmount",
                "listmount",
                "file_getattr",
                "file_setattr",
            ],
            "the open (needs-a-decision) set changed: update the ledger and this pin together"
        );
    }

    /// The pure-shape verdicts must cover exactly the path surface: every
    /// mediated syscall and every unmediated path-taking entry needs one, and
    /// nothing else may appear. Adding a path-taking syscall to either side
    /// without a pure verdict fails here.
    #[test]
    fn pure_shape_classifies_every_path_taking_syscall() {
        let mut expected: BTreeSet<String> = MEDIATED_PATH_SYSCALLS
            .iter()
            .map(|s| s.to_string())
            .collect();
        for (name, _) in UNMEDIATED_PATH_TAKING {
            expected.insert((*name).to_string());
        }
        let mut got: BTreeSet<String> = PURE_LANDLOCK_GATED.iter().map(|s| s.to_string()).collect();
        for (name, _) in PURE_GATED_ELSEWHERE {
            assert!(got.insert((*name).to_string()), "{name} listed twice");
        }
        for (name, _) in PURE_UNGATED {
            assert!(got.insert((*name).to_string()), "{name} listed twice");
        }
        assert_eq!(
            got, expected,
            "the pure-shape verdicts and the path surface disagree"
        );
    }

    /// Pin the pure shape's ungated set: it is the worklist for that shape, so
    /// shrinking it should be a deliberate diff, not a silent one.
    #[test]
    fn pure_shape_ungated_set_is_pinned() {
        let names: Vec<&str> = PURE_UNGATED.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec![
                "stat", "lstat", "newfstatat", "statx", "statfs",
                "access", "faccessat", "faccessat2",
                "readlink", "readlinkat",
                "chdir", "fchdir", "getcwd",
                "chmod", "fchmodat",
                "utimensat", "utime", "utimes", "futimesat",
                "getxattr", "lgetxattr", "setxattr", "lsetxattr",
                "listxattr", "llistxattr", "removexattr", "lremovexattr",
                "inotify_add_watch", "open_tree",
                "fchmodat2", "getxattrat", "setxattrat", "listxattrat", "removexattrat",
            ]
        );
    }

    /// Totality: every syscall the arch knows is classified exactly once. This
    /// is what turns "the fallthrough set is empty" from prose into a check.
    #[test]
    fn every_arch_syscall_is_classified() {
        let mediated = mediated_names();
        let policy = crate::sandbox::Sandbox::builder().build().unwrap();
        let blocked: BTreeSet<String> = blocklist_syscall_numbers(&policy)
            .into_iter()
            .map(|n| syscalls::Sysno::new(n as usize).unwrap().to_string())
            .collect();
        let ledger: BTreeSet<String> = UNMEDIATED_PATH_TAKING
            .iter()
            .map(|(n, _)| n.to_string())
            .collect();
        let non_path: BTreeSet<String> = NON_PATH_SYSCALLS.iter().map(|s| s.to_string()).collect();

        let mut unclassified = Vec::new();
        for name in arch_syscalls() {
            let known = mediated.contains(&name)
                || blocked.contains(&name)
                || ledger.contains(&name)
                || non_path.contains(&name);
            if !known {
                unclassified.push(name);
            }
        }
        assert!(
            unclassified.is_empty(),
            "new/unclassified syscalls: {unclassified:?} -- classify them in \
             sys/path_surface.rs (mediated, blocked, gated with a reason, or no-path)"
        );

        // ...and the buckets must not overlap.
        for name in &ledger {
            assert!(
                !mediated.contains(name),
                "{name} is both mediated and listed as unmediated"
            );
        }
        for name in &non_path {
            assert!(
                !ledger.contains(name) && !mediated.contains(name),
                "{name} is listed twice in the ledger"
            );
        }
    }
}
