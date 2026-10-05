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
    "fchmodat2",
    "fchownat",
    "truncate",
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

/// The mediated rows whose *existence* is per-ABI, each with the
/// [`crate::arch`] helper `chroot_path_syscalls()` reaches it through.
///
/// The names above are the union across the ABIs Sandlock targets; this table
/// says which of them an individual ABI may not have at all. On x86_64 every
/// helper resolves; on the generic-ABI arches (aarch64, riscv64) the legacy
/// pre-`*at` forms answer `None` and the ABI has no such syscall, while
/// `renameat` survives on aarch64 and not on riscv64. The pair is checked
/// against the name resolver in
/// [`tests::every_ledger_name_resolves_on_this_arch`], so a row that drifts
/// out of the plan or is spelled wrong fails on the ABI it belongs to.
pub(crate) const MEDIATED_PATH_SYSCALLS_PER_ABI: &[(&str, fn() -> Option<i64>)] = &[
    ("open", crate::arch::sys_open),
    ("readlink", crate::arch::sys_readlink),
    ("getdents", crate::arch::sys_getdents),
    ("unlink", crate::arch::sys_unlink),
    ("rmdir", crate::arch::sys_rmdir),
    ("mkdir", crate::arch::sys_mkdir),
    ("rename", crate::arch::sys_rename),
    ("renameat", crate::arch::sys_renameat),
    ("symlink", crate::arch::sys_symlink),
    ("link", crate::arch::sys_link),
    ("chmod", crate::arch::sys_chmod),
    ("chown", crate::arch::sys_chown),
    ("lchown", crate::arch::sys_lchown),
];

/// Syscalls that name a filesystem object and are **not** mediated.
///
/// Every one of these either has a gate the sandbox cannot pass, or is an open
/// item. The list is the reviewable half of the invariant; the other half is
/// [`NON_PATH_SYSCALLS`], whose job is to make the classification total.
pub(crate) const UNMEDIATED_PATH_TAKING: &[(&str, Disposition)] = &[
    // ---- open items: unmediated, no demonstrated gate ---------------------
    // The new mount API, refused in every shape (see the blocklist):
    // `open_tree` without OPEN_TREE_CLONE measured to hand the sandbox an
    // O_PATH fd for a host directory, and the CLONE form is CAP_SYS_ADMIN.
    ("open_tree", Disposition::Blocked),
    // The 6.13 "*at" metadata calls (E2B audit STATIC-2, 2026-10-04). These were
    // the ledger's last `Open` rows: ENOSYS on the deployed kernel, so nothing
    // measured, and the note claimed the shipped worker seccomp profile refused
    // them. The rehearsal on a 7.0 kernel showed that claim was carrying the
    // whole defence -- `seccomp=unconfined` let all of them through, and
    // Docker/OCI's default profile does not block `fchmodat2`. Blocked rather
    // than mediated because no workload uses them and glibc does not call them
    // yet. `fchmodat2` left this table instead: glibc *does* use it, so it is
    // mediated (see MEDIATED_PATH_SYSCALLS and seccomp_plan.rs).
    ("getxattrat", Disposition::Blocked),
    ("setxattrat", Disposition::Blocked),
    ("listxattrat", Disposition::Blocked),
    ("removexattrat", Disposition::Blocked),
    ("open_tree_attr", Disposition::Blocked),
    // `statmount`/`listmount` used to be `Open` (kernel 457/458, refused only
    // by the shipped worker profile, which is a host-dependent gate): they
    // return host mount metadata (root/mountpoint strings, options) and no
    // sandbox workload reads it. Blocked 2026-09-30 after the k0s probe showed
    // a sandbox process reaching the kernel for the sibling mount-API calls.
    ("statmount", Disposition::Blocked),
    ("listmount", Disposition::Blocked),
    ("file_getattr", Disposition::Blocked),
    ("file_setattr", Disposition::Blocked),
    // These five were classified `NON_PATH_SYSCALLS`, which claimed they cannot
    // name a filesystem object. That was wrong for `cachestat` and
    // `lsm_get_self_attr` (both take a path) and contradicted a Blocked verdict
    // for all five, so they were reclassified on 2026-10-04. Blocked rather
    // than left merely ungated: none answers on the deployed 6.12 kernel
    // (ENOSYS -- they arrived in 6.5 and 6.10), and listing them makes the
    // refusal a property of the policy instead of a property of the kernel the
    // node happens to run. Rationale per syscall is on the blocklist entry.
    ("cachestat", Disposition::Blocked),
    ("lsm_get_self_attr", Disposition::Blocked),
    ("lsm_set_self_attr", Disposition::Blocked),
    ("lsm_list_modules", Disposition::Blocked),
    ("mseal", Disposition::Blocked),
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
    // The mount API's companions were `Gated` (CAP_SYS_ADMIN in the mount
    // namespace's userns) until 2026-09-30. That gate is a property of the
    // *host profile and capability set*, not of the sandbox: the k0s probe
    // measured them reaching the kernel from inside a real sandbox, and no
    // Landlock right covers them. They are blocklisted in every shape now, the
    // same as `open_tree`.
    ("move_mount", Disposition::Blocked),
    ("fspick", Disposition::Blocked),
    ("mount_setattr", Disposition::Blocked),
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
    // ---- the stat family's metadata half (N81, 2026-10-06) ----------------
    // It was mediated for one reason: `stat` is metadata, Landlock has no
    // access right for it, and the mediator's answer was the only thing that
    // could refuse a path outside the readable set. With a root of the
    // sandbox's own whose `/proc` is a plain directory of that root (every
    // deployed shape since N14 S5) there is nothing left to refuse: the kernel
    // resolves inside the sandbox's own tree, `/proc/<host pid>` collides with
    // nothing, and Landlock still gates the opens that tree leads to.
    //
    // Measured 2026-10-06 (`deploy/scripts/acceptance/probe_n81_proc_stat_shape.py`):
    // `stat /proc` and `stat /` share a `st_dev`, and `/proc/uptime`,
    // `/proc/version`, `/proc/meminfo`, `/proc/cpuinfo` answer ENOENT *from the
    // kernel* (they are non-numeric, so the mediator already `Continue`d them --
    // that answer is the kernel's, and it proves the kernel sees an empty
    // directory). Where the premise fails the family goes straight back on the
    // notify list: `resolved::stat_metadata_mediated` is the predicate, and
    // `seccomp_plan`'s tests pin all four shapes (own root / identity root /
    // no root / a policy mount at `/proc`).
    //
    // `readlinkat` deliberately stays mediated: it *serves* `/proc/self/exe`
    // and `/proc/self/fd/N` from the host procfs on the child's behalf.
    (
        "newfstatat",
        Disposition::Gated(
            "the sandbox's own rootfs: the kernel answers for its own tree; N81 gate predicate + probe_n81_proc_stat_shape.py",
        ),
    ),
    (
        "statx",
        Disposition::Gated(
            "metadata, same gate as newfstatat (N81): the sandbox's own rootfs answers it",
        ),
    ),
    (
        "faccessat",
        Disposition::Gated(
            "existence probe, same gate as newfstatat (N81): the kernel's own answer",
        ),
    ),
    (
        "faccessat2",
        Disposition::Gated(
            "existence probe, same gate as newfstatat (N81): the kernel's own answer",
        ),
    ),
    (
        "stat",
        Disposition::Gated(
            "metadata, same gate as newfstatat (N81): the sandbox's own rootfs answers it",
        ),
    ),
    (
        "lstat",
        Disposition::Gated(
            "metadata, same gate as newfstatat (N81): the sandbox's own rootfs answers it",
        ),
    ),
    (
        "access",
        Disposition::Gated(
            "existence probe, same gate as newfstatat (N81): the kernel's own answer",
        ),
    ),
    // ---- blocked ----------------------------------------------------------
    // The OBS-1 fallthrough: unmediated, resolved against the host root, so a
    // sandbox could chroot into a host-only directory. Blocklisted 2026-09-17;
    // recorded here because it is the reason this ledger exists.
    ("chroot", Disposition::Blocked),
];

/// Unmediated rows the generic-ABI architectures (aarch64, riscv64) do not
/// have at all: the pre-`*at` legacy forms plus `uselib` (x86-only). The table
/// above is the union across the ABIs Sandlock targets, so what each of these
/// rows records is an x86_64 statement; on an ABI that has no such syscall
/// there is nothing for the kernel to resolve a path through.
/// [`tests::every_ledger_name_resolves_on_this_arch`] requires every row
/// *outside* this list to resolve on the architecture under test, so a typo in
/// the ledger still fails -- on the ABI that does have the syscall.
pub(crate) const UNMEDIATED_PATH_TAKING_ABI_SPECIFIC: &[&str] =
    &[
        "creat",
        "mknod",
        "utime",
        "utimes",
        "futimesat",
        "uselib",
        // The legacy stat spellings: x86_64 has them, the generic-ABI arches
        // (aarch64, riscv64) do not -- they only have the `*at` forms.
        "stat",
        "lstat",
        "access",
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
    ("open_tree", "blocklisted in every shape: the new mount API, no Landlock right covers it"),
    ("open_tree_attr", "blocklisted in every shape, see open_tree"),
    ("chown", "ownership/DAC only, no Landlock right: the sandbox owns nothing outside its workspace"),
    ("lchown", "ownership/DAC only, see chown"),
    ("fchownat", "ownership/DAC only, see chown"),
    ("fanotify_mark", "fanotify_init needs CAP_SYS_ADMIN in the initial userns (measured EPERM)"),
    ("move_mount", "blocklisted in every shape (2026-09-30); no Landlock right covers it"),
    ("fspick", "blocklisted in every shape (2026-09-30), see move_mount"),
    ("mount_setattr", "blocklisted in every shape (2026-09-30), see move_mount"),
    ("file_getattr", "kernel 6.13+; ENOSYS on the audit kernel, signature unverified"),
    ("file_setattr", "kernel 6.13+; ENOSYS on the audit kernel, signature unverified"),
    ("statmount", "blocklisted in every shape (2026-09-30): host mount metadata, no workload use"),
    ("listmount", "blocklisted in every shape (2026-09-30), see statmount"),
    ("cachestat", "blocklisted in every shape (2026-10-04): page-cache residency side channel, ENOSYS on 6.12"),
    ("lsm_get_self_attr", "blocklisted in every shape (2026-10-04): reports the host LSM stack, ENOSYS on 6.12"),
    ("lsm_set_self_attr", "blocklisted in every shape (2026-10-04), see lsm_get_self_attr"),
    ("lsm_list_modules", "blocklisted in every shape (2026-10-04), see lsm_get_self_attr"),
    ("mseal", "blocklisted in every shape (2026-10-04): seals mappings incl. file-backed, ENOSYS on 6.12"),
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
    ("fchmodat2", "at-style chmod; refused by the shipped worker seccomp profile, reachable on a wider-profile host"),
    ("getxattrat", "at-style xattr read; refused by the shipped profile, reachable on a wider-profile host"),
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
    "futex_waitv", "set_mempolicy_home_node", "map_shadow_stack",
    "futex_wake", "futex_wait", "futex_requeue",
    // The 32-bit time64 group. The `syscalls` crate's aarch64 table carries
    // these at 403..422, where the kernel implements nothing (they exist for
    // 32-bit ABIs, which have the 2038 problem for `struct timespec`); none of
    // them takes a path, in either spelling. Classified here so the totality
    // check reads the same on aarch64 as it does on x86_64 instead of
    // reporting the crate's leftovers as "new syscalls".
    "clock_gettime64", "clock_settime64", "clock_adjtime64", "clock_getres_time64",
    "clock_nanosleep_time64", "timer_gettime64", "timer_settime64",
    "timerfd_gettime64", "timerfd_settime64", "utimensat_time64",
    "pselect6_time64", "ppoll_time64", "io_pgetevents_time64",
    "recvmmsg_time64", "mq_timedsend_time64", "mq_timedreceive_time64",
    "semtimedop_time64", "rt_sigtimedwait_time64", "futex_time64",
    "sched_rr_get_interval_time64",
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
    ///
    /// Compared as *numbers*, because that is what the plan actually is: the
    /// ledger is the union across ABIs (see
    /// [`MEDIATED_PATH_SYSCALLS_PER_ABI`]) and a name has to go through the
    /// same alias table the engine uses to land on this ABI's number. On
    /// aarch64 the legacy non-`*at` rows resolve to nothing and drop out, while
    /// `newfstatat` resolves to the number the plan calls 79.
    #[test]
    fn mediated_set_matches_the_ledger() {
        let mediated: BTreeSet<u32> =
            chroot_path_syscalls().into_iter().map(|n| n as u32).collect();
        let ledger: BTreeSet<u32> = MEDIATED_PATH_SYSCALLS
            .iter()
            .filter_map(|name| syscall_name_to_nr(name))
            .collect();
        assert_eq!(
            mediated, ledger,
            "chroot_path_syscalls() and MEDIATED_PATH_SYSCALLS disagree on this ABI"
        );
    }

    /// Every ledger row is either a syscall this ABI has, or a documented
    /// per-ABI row whose arch helper agrees that this ABI has none. The two
    /// halves are cross-checked against each other, so a typo in either the
    /// ledger or the per-ABI table fails here instead of shrinking the plan
    /// silently.
    #[test]
    fn every_ledger_name_resolves_on_this_arch() {
        for name in MEDIATED_PATH_SYSCALLS {
            if syscall_name_to_nr(name).is_some() {
                continue;
            }
            let helper = MEDIATED_PATH_SYSCALLS_PER_ABI
                .iter()
                .find(|(n, _)| n == name)
                .unwrap_or_else(|| {
                    panic!("mediated ledger name {name} does not resolve on this architecture")
                })
                .1;
            assert!(
                helper().is_none(),
                "{name} is listed as ABI-specific, but the arch helper resolved it"
            );
        }
        for (name, helper) in MEDIATED_PATH_SYSCALLS_PER_ABI {
            assert!(
                MEDIATED_PATH_SYSCALLS.contains(name),
                "per-ABI row {name} is missing from MEDIATED_PATH_SYSCALLS"
            );
            assert_eq!(
                helper().map(|n| n as u32),
                syscall_name_to_nr(name),
                "arch helper and name resolver disagree about {name}"
            );
        }
        for (name, _) in UNMEDIATED_PATH_TAKING {
            if syscall_name_to_nr(name).is_some() {
                continue;
            }
            assert!(
                UNMEDIATED_PATH_TAKING_ABI_SPECIFIC.contains(name),
                "path-surface entry {name} does not resolve on this architecture"
            );
        }
        for name in UNMEDIATED_PATH_TAKING_ABI_SPECIFIC {
            assert!(
                UNMEDIATED_PATH_TAKING.iter().any(|(n, _)| n == name),
                "{name} is listed as ABI-specific but is not in UNMEDIATED_PATH_TAKING"
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
        // Empty as of 2026-10-04 (E2B audit STATIC-2): the seven "*at" metadata
        // calls were the last `Open` rows. Six are blocked and `fchmodat2` is
        // mediated. This is the bucket a reviewer empties, and it is empty --
        // if a new `Open` row appears it must come with a measurement.
        assert_eq!(
            open,
            Vec::<&str>::new(),
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
                "inotify_add_watch",
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
