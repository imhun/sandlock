// Kernel struct definitions matching ABI exactly for x86_64

// ============================================================
// Landlock structs
// ============================================================

/// Ruleset attributes for landlock_create_ruleset (24 bytes)
#[repr(C)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub scoped: u64,
}

/// Path beneath attribute for landlock_add_rule (12 bytes, packed)
#[repr(C, packed)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

/// Network port attribute for landlock_add_rule (16 bytes)
#[repr(C)]
pub struct LandlockNetPortAttr {
    pub allowed_access: u64,
    pub port: u64,
}

// ============================================================
// Seccomp structs
// ============================================================

/// Seccomp BPF data passed to filters (64 bytes)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// Seccomp user notification (80 bytes)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// Seccomp user notification response (24 bytes)
#[repr(C)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// Seccomp add file descriptor (24 bytes)
#[repr(C)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

/// BPF filter instruction
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// BPF filter program
#[repr(C)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

// SAFETY: SockFprog is only used in single-threaded syscall context
unsafe impl Send for SockFprog {}
unsafe impl Sync for SockFprog {}

// ============================================================
// Landlock syscall numbers
// ============================================================

pub const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
pub const SYS_LANDLOCK_ADD_RULE: i64 = 445;
pub const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

// ============================================================
// Landlock FS access flags (bits 0-15)
// ============================================================

pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
pub const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

// ============================================================
// Landlock net access flags
// ============================================================

pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

// ============================================================
// Landlock rule types
// ============================================================

pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
pub const LANDLOCK_RULE_NET_PORT: u32 = 2;

// ============================================================
// Landlock scope flags
// ============================================================

pub const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
pub const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

// ============================================================
// Seccomp constants
// ============================================================

pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 1 << 3;
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u64 = 1 << 5;
pub const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7FC0_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
pub const SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP: u32 = 1;
/// Install the new fd at the requested `newfd` number instead of the lowest
/// available one.
pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1 << 0;
/// Atomically install the fd and respond to the syscall (Linux 5.14+).
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;

// ============================================================
// Seccomp ioctl commands
// ============================================================

pub const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0xc050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xc018_2101;
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = 0x4008_2102;
pub const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = 0xc018_2103;
pub const SECCOMP_IOCTL_NOTIF_SET_FLAGS: u64 = 0x4008_2104;

// ============================================================
// BPF opcodes
// ============================================================

pub const BPF_LD: u16 = 0x00;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;
pub const BPF_RET: u16 = 0x06;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_AND: u16 = 0x50;

// ============================================================
// seccomp_data field offsets
// ============================================================

pub const OFFSET_NR: u32 = 0;
pub const OFFSET_ARCH: u32 = 4;
pub const OFFSET_ARGS0_LO: u32 = 16;
pub const OFFSET_ARGS1_LO: u32 = 24;
pub const OFFSET_ARGS2_LO: u32 = 32;
pub const OFFSET_ARGS3_LO: u32 = 40;

// ============================================================
// Clone namespace flags
// ============================================================

pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;

pub const CLONE_NS_FLAGS: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID;

// ============================================================
// Dangerous ioctls
// ============================================================

pub const TIOCSTI: u64 = 0x5412;
pub const TIOCLINUX: u64 = 0x541C;

// Network interface ioctls (linux/sockios.h)
pub const SIOCGIFNAME: u64 = 0x8910;
pub const SIOCGIFCONF: u64 = 0x8912;
pub const SIOCGIFFLAGS: u64 = 0x8913;
pub const SIOCSIFFLAGS: u64 = 0x8914;
pub const SIOCGIFADDR: u64 = 0x8915;
pub const SIOCGIFDSTADDR: u64 = 0x8917;
pub const SIOCGIFBRDADDR: u64 = 0x8919;
pub const SIOCGIFNETMASK: u64 = 0x891B;
pub const SIOCGIFHWADDR: u64 = 0x8927;
pub const SIOCGIFINDEX: u64 = 0x8933;
pub const SIOCETHTOOL: u64 = 0x8946;

// The set half of the network-interface family, mirroring the SIOCGIF* get
// family above. Every one of these is CAP_NET_ADMIN-gated in the kernel, so
// none of them can be reached today -- measured inside a live sandbox
// 2026-10-04, `socket()` itself answers EPERM, so there is no fd to issue an
// ioctl on. They are listed because the get half is: refusing to enumerate an
// interface while leaving the fd settable would be a half-measure, and these
// cost two BPF instructions each. Unverified at runtime for that reason -- they
// are transcribed from uapi `linux/sockios.h`, where they are plain hex and
// share the numbering of the entries above.
pub const SIOCSIFADDR: u64 = 0x8916;
pub const SIOCSIFBRDADDR: u64 = 0x891A;
pub const SIOCSIFNETMASK: u64 = 0x891C;
pub const SIOCSIFHWADDR: u64 = 0x8924;

// Filesystem-layout ioctls (uapi `linux/fs.h`).
//
// These answer "where does this file physically live". Landlock's
// `LANDLOCK_ACCESS_FS_IOCTL_DEV` is defined over *device* files, so nothing in
// the Landlock ruleset bounds ioctl on a regular file, and nothing else in the
// filter looked at it either. Measured inside a live sandbox 2026-10-04 on a
// 1 MiB workspace file: `FS_IOC_FIEMAP` is implemented and answers EINVAL (the
// workspace filesystem does not serve it), while the two block-device ioctls
// answer ENOTTY because a regular file is not a block device -- so only FIEMAP
// is demonstrably reachable on the file types a workload actually holds.
//
// A wrong request code here is not a partial gap but a silent no-op: the JEQ
// simply never matches, so the entry would read like a control while being
// inert. Three of the values tried from memory during that audit were wrong in
// exactly that way (all three answered ENOTTY), so these are transcribed from
// the header and every reachable one was confirmed against a running kernel.
pub const FIBMAP: u64 = 0x0000_0001; // _IO(0x00, 1)
pub const FIGETBSZ: u64 = 0x0000_0002; // _IO(0x00, 2)
pub const FS_IOC_FIEMAP: u64 = 0xC020_660B; // _IOWR('f', 11, struct fiemap)

// ============================================================
// Dangerous prctl options
// ============================================================

pub const PR_SET_DUMPABLE: u32 = 4;
pub const PR_SET_SECUREBITS: u32 = 28;
pub const PR_SET_PTRACER: u32 = 0x5961_6d61;

// ============================================================
// Socket constants
// ============================================================

pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_TYPE_MASK: u32 = 0xFF;

// ============================================================
// Errno values
// ============================================================

pub const EPERM: i32 = 1;
pub const EACCES: i32 = 13;
pub const ENOMEM: i32 = 12;
pub const EAGAIN: i32 = 11;
pub const ECONNREFUSED: i32 = 111;

// ============================================================
// Default blocklisted syscall list
// ============================================================

/// SysV IPC syscalls. Appended to the kernel-level blocklist when
/// `policy.allows_sysv_ipc()` is false. Sandlock does not use an IPC
/// namespace, so without these denials two sandboxes on the same host
/// share a SysV keyspace and can rendezvous via a well-known key.
///
/// POSIX shared memory (`shm_open`) is intentionally not here — it is
/// just `open("/dev/shm/<name>")`, gated by Landlock filesystem rules.
/// POSIX message queues (`mq_open` and friends) are also out of scope
/// for this flag.
pub const SYSV_IPC_BLOCKLIST_SYSCALLS: &[&str] = &[
    "shmget",
    "shmat",
    "shmdt",
    "shmctl",
    "msgget",
    "msgsnd",
    "msgrcv",
    "msgctl",
    "semget",
    "semop",
    "semctl",
    "semtimedop",
];

/// Named syscall groups shared by `--extra-deny-syscall` and
/// `--extra-allow-syscall`. Deny accepts a group name (expanded to its
/// members) or an individual syscall name; allow accepts group names only,
/// because re-allowing arbitrary single syscalls from the default blocklist
/// could punch holes in the mediation boundary (e.g. io_uring bypasses
/// per-syscall seccomp entirely).
pub const SYSCALL_GROUPS: &[(&str, &[&str])] = &[("sysv_ipc", SYSV_IPC_BLOCKLIST_SYSCALLS)];

/// Look up a syscall group by name.
pub fn syscall_group(name: &str) -> Option<&'static [&'static str]> {
    SYSCALL_GROUPS
        .iter()
        .find(|(group, _)| *group == name)
        .map(|(_, members)| *members)
}

pub const DEFAULT_BLOCKLIST_SYSCALLS: &[&str] = &[
    "mount",
    "umount2",
    "pivot_root",
    // The new mount API is the same capability through a newer interface.
    // `mount`/`umount2`/`pivot_root` are already refused above, a container
    // runtime is what uses these rather than a workload, and no Landlock
    // access right covers them -- `open_tree` without OPEN_TREE_CLONE is an
    // O_PATH open, measured to hand a sandbox an fd for a *host* directory
    // (E2B audit 2026-09-17, path-surface ledger). With OPEN_TREE_CLONE it is
    // CAP_SYS_ADMIN in the initial userns, which the sandbox does not have.
    "open_tree",
    "open_tree_attr",
    // `chroot` is *not* mediated: it is absent from `chroot_path_syscalls()`,
    // and in the emulated-chroot shape the confined child's kernel root is
    // still the host root (the supervisor translates every path syscall to
    // `<chroot_root>/<virtual>`; `context.rs` chdirs into the *host* path
    // under the rootfs precisely because no real chroot happens). So a
    // sandboxed `chroot(2)` executes against the host filesystem as the
    // id-0-in-userns child and succeeds on any host directory -- a genuine
    // hole in the seccomp fallthrough set that `landlock.rs` relies on being
    // empty ("any seccomp fallthrough is blocked by Landlock, fail-closed").
    // It grants nothing by itself today (every later path syscall is either
    // mediated against the static root or denied by Landlock), but it is
    // exactly the class of syscall that turns a future fallthrough into an
    // escape, and a sandbox has no legitimate use for it.
    "chroot",
    "swapon",
    "swapoff",
    "reboot",
    "sethostname",
    "setdomainname",
    "kexec_load",
    "init_module",
    "finit_module",
    "delete_module",
    "unshare",
    "setns",
    "perf_event_open",
    "bpf",
    "userfaultfd",
    "keyctl",
    "add_key",
    "request_key",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    // The same capability as `ptrace` through a newer interface: it duplicates
    // a file descriptor out of another process. The supervisor needs it -- that
    // is how it picks up the child's seccomp-notification fd
    // (`sandbox.rs::dup_child_fd`) -- but it runs *outside* this filter, so
    // blocking it here only takes it away from sandbox code, which has no
    // legitimate use for it. Measured 2026-09-30 on the k0s cluster: without
    // this entry a sandbox process could `pidfd_open` + `pidfd_getfd` its own
    // sandbox's processes and duplicate their descriptors (it could not name or
    // reach anything outside its own sandbox, but `ptrace` is blocked for
    // exactly this class). `--no-supervisor` mode keeps it allowed via
    // NO_SUPERVISOR_BLOCKLIST_SYSCALLS, because an inner supervisor may run
    // there.
    "pidfd_getfd",
    "open_by_handle_at",
    "name_to_handle_at",
    "ioperm",
    "iopl",
    "quotactl",
    // `quotactl_fd` is the fd spelling of the same quota interface. A sandbox
    // has no use for it: the platform's quota work runs in the worker
    // (`envd_service/xfs_quota.py` calls `quotactl_fd` through ctypes), which
    // is outside this filter. Measured 2026-09-30 on the k0s cluster (arm64,
    // worker pod, no effective capabilities): inside a real sandbox the call
    // reaches the kernel (EBADF for a deliberately-bad fd), i.e. nothing but
    // the missing capability was in the way.
    "quotactl_fd",
    "acct",
    "lookup_dcookie",
    "nfsservctl",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    // The legacy POSIX AIO interface is the generation before io_uring: the
    // same class of "batch I/O submitted through one syscall", with no
    // per-request interception point. Nothing in a sandbox needs it (glibc's
    // `aio_*` is the only consumer), and `io_uring`'s own entry above is the
    // precedent. Measured on the same cluster run: `io_setup` and `io_submit`
    // both reached the kernel from inside the sandbox (EFAULT/EINVAL).
    "io_setup",
    "io_submit",
    "io_cancel",
    "io_getevents",
    "io_pgetevents",
    "personality",
    // ---- the ptrace class, newer interfaces ------------------------------
    // `pidfd_getfd` above is one member; these are the rest of the family.
    // `process_madvise`/`process_mrelease` act on another process's memory
    // through a pidfd and are gated by the same `PTRACE_MODE_ATTACH` check
    // `process_vm_readv/writev` carry -- and which this blocklist already
    // refuses. `kcmp` compares two processes' descriptors/memory and was
    // historically the same-side-channel primitive. A workload has no use for
    // any of them; measured inside a real sandbox on the k0s cluster
    // (2026-09-30): all three reached the kernel (EBADF/ESRCH for bad
    // arguments).
    "process_madvise",
    "process_mrelease",
    "kcmp",
    // ---- kernel code / kexec ---------------------------------------------
    // `kexec_load` is refused above; this is the file-based spelling of the
    // same capability. Measured inside a sandbox: EPERM, i.e. the call was
    // reaching the kernel and stopping only at the missing `CAP_SYS_BOOT`.
    "kexec_file_load",
    // ---- the new mount API ------------------------------------------------
    // `mount`/`umount2`/`pivot_root`/`open_tree` are refused above; these are
    // the remaining entry points to the same capability. They matter more than
    // the rest of this list because **no Landlock access right covers them**
    // (the ledger in `sys/path_surface.rs` records each one), so the seccomp
    // filter is the only barrier that survives a host whose outer profile is
    // wider than the shipped worker profile. Measured 2026-09-30 inside a real
    // sandbox on the k0s cluster: every one of them reached the kernel from
    // sandbox code (`fsconfig`/`mount_setattr` answered EINVAL, proving the
    // argument parse ran; the others stopped at the capability check). The
    // deployment's own rule for these -- written when the real-root shape was
    // designed -- is "allow `mount` + `pivot_root` in the worker, and never
    // hand the companions to a workload" (docs/task-backlog.md, N14).
    "fsopen",
    "fsconfig",
    "fsmount",
    "move_mount",
    "fspick",
    "mount_setattr",
    // `statmount`/`listmount` take a mount id rather than a path, but return
    // host mount metadata (root/mountpoint strings, mount options) -- a
    // disclosure surface with no workload use. Both were `Open` (unmediated,
    // no gate) in the path-surface ledger.
    "statmount",
    "listmount",
    // ---- the 6.13 "*at" metadata calls nothing here uses --------------------
    // Measured 2026-10-04 (E2B audit STATIC-2): on the deployed 6.12 kernel all
    // of these return ENOSYS, so the file cap's own comment about "refused by
    // the shipped worker seccomp profile" described a *second* line of defence.
    // The rehearsal on a 7.0 kernel showed what that second line is worth: with
    // the outer profile widened (`seccomp=unconfined`) every one of them reached
    // the kernel with no EPERM in sight, `fchmodat2` returned 0 and changed a
    // file's mode, and `file_getattr` returned 0. Docker's and OCI's *default*
    // profiles do not block `fchmodat2` either -- so "we ship a restrictive
    // profile" was the only thing between this ledger and a live primitive.
    //
    // They are blocked rather than mediated because no sandbox workload needs
    // them and glibc does not call them yet, so there is nothing to keep
    // working. (`fchmodat2` is the exception and is mediated instead: glibc
    // *does* use it for `chmod`, and a seccomp `EPERM` is not something glibc
    // falls back from.)
    //
    // What a bypass would buy: Landlock has no xattr right and no chmod right, so
    // an unmediated `setxattrat`/`fchmodat2` is a metadata *write* against any
    // path the sandbox can traverse, which for a path the sandbox cannot read is
    // still a blind write primitive. Blocking removes the dependence on the
    // container profile entirely, which is the point.
    "setxattrat",
    "getxattrat",
    "listxattrat",
    "removexattrat",
    "file_getattr",
    "file_setattr",
    // ---- host/device surfaces with no sandbox use -------------------------
    // `memfd_secret` allocates pages the kernel itself cannot read back; it is
    // a hardening primitive for secrets handling, never something a sandboxed
    // workload needs, and measured inside the sandbox it *succeeded*
    // (returned a real fd). `memfd_create` is deliberately left allowed --
    // runtimes and JITs use it.
    "memfd_secret",
    // x86-only and absent on the deployed arm64 ABI (the name resolves to
    // nothing there, so the entry is inert on arm64). Only emulators that
    // build 16-bit segments need it.
    "modify_ldt",
    // ---- NUMA policy ------------------------------------------------------
    // No sandbox workload needs to set or read the host's memory policy, and
    // `get_mempolicy` reports the host topology, which is exactly the kind of
    // host fact a sandbox is not supposed to learn. Measured inside a real
    // sandbox (k0s, 2026-09-30): `get_mempolicy` and `set_mempolicy` *succeeded*
    // there -- these are not capability-gated.
    "get_mempolicy",
    "set_mempolicy",
    "mbind",
    "move_pages",
    "migrate_pages",
    "set_mempolicy_home_node",
    // ---- LSM introspection and mapping sealing (kernel 6.5-6.10) ----------
    // None of these exists on the deployed kernel: they were added in 6.5
    // (`cachestat`, `lsm_*`) and 6.10 (`mseal`), and the audit kernel is 6.12,
    // where all five answer ENOSYS. They are listed so the blocklist is a
    // property of the policy rather than of the kernel it happens to run on:
    // a node upgraded into their range must not silently start answering.
    //
    // `cachestat` reports page-cache residency for a path, which is a
    // side-channel about the host's memory pressure and a timing oracle on
    // shared cache. `lsm_get_self_attr` and `lsm_list_modules` report the
    // host's LSM stack -- which modules are loaded, and under what labels --
    // and `lsm_set_self_attr` writes that state. `mseal` seals or unmaps
    // memory mappings, including file-backed ones.
    //
    // No sandboxed workload has a use for any of them: they exist for
    // LSM implementors, a memory allocator's hardening path, and
    // cache-monitoring tools. Note the fork already refuses `process_madvise`
    // and `process_mrelease`, so leaving the per-self mapping and security-
    // attribute syscalls allowed was the inconsistency, not the design.
    "cachestat",
    "lsm_get_self_attr",
    "lsm_set_self_attr",
    "lsm_list_modules",
    "mseal",
];

/// Deny list for --no-supervisor mode.
///
/// More relaxed than DEFAULT_BLOCKLIST_SYSCALLS because a full sandbox supervisor
/// may run inside the outer no-supervisor sandbox and needs syscalls like
/// ptrace, process_vm_readv/writev, unshare, mount, and setns.
///
/// Only blocks syscalls that could damage the host or escape all containment.
pub const NO_SUPERVISOR_BLOCKLIST_SYSCALLS: &[&str] = &[
    // Swap / reboot / shutdown — host-wide damage
    "swapon",
    "swapoff",
    "reboot",
    "kexec_load",
    // Kernel modules — arbitrary kernel code execution
    "init_module",
    "finit_module",
    "delete_module",
    // Kernel introspection / attack surface
    "perf_event_open",
    "bpf",
    // Direct hardware access
    "ioperm",
    "iopl",
    // io_uring bypasses seccomp for I/O operations
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];
