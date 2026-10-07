// /proc file virtualization and PID filtering via seccomp notification.
//
// Intercepts openat syscalls that target sensitive /proc paths or virtual
// files (/proc/cpuinfo, /proc/meminfo). For virtual files, creates a memfd
// with fake content and injects it into the child's fd table.
//
// Continue safety (issue #27):
//   - Sensitive-path denials use Errno(EACCES) — TOCTOU-safe: the seccomp
//     response *is* the answer; the kernel does not re-read user memory.
//   - Virtualized paths (cpuinfo, meminfo, mounts, /proc/net/*, hostname,
//     etc.) use InjectFdSend with a sealed memfd — the child's fd table
//     ends up with our memfd, and the kernel never re-resolves the path
//     string after injection.
//   - Continue is reserved for fall-through cases: read_path failed (kernel
//     will re-read and EFAULT identically), the path doesn't match any
//     virtualized entry, or supervisor-side I/O on /proc/<pid>/fd/<n>
//     read_link returned an error. None of these cases involve the
//     supervisor approving a syscall based on user-controlled string
//     contents, so the seccomp_unotify TOCTOU class doesn't apply.

use std::collections::{HashMap, HashSet};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::seccomp::notif::{content_memfd, read_child_cstr, write_child_mem, NotifAction, NotifPolicy};
use crate::seccomp::state::{NetworkState, ProcessIndex};
use crate::sys::structs::{SeccompNotif, EACCES};

// ============================================================
// PID namespace translation (CLONE_NEWPID)
// ============================================================

/// How far up a parent chain the PID-namespace fallback looks.
const MAX_ANCESTOR_HOPS: usize = 64;

/// The parent of `pid`, from `/proc/<pid>/stat` (world-readable, so this works
/// even where reading a namespace link is refused).
fn parent_pid_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` is parenthesised and may contain spaces and parens, so the fields
    // after it are counted from its *last* `)`.
    let (_, rest) = stat.rsplit_once(')')?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

/// Maps the PID namespace of one sandbox (`Sandbox::pid_ns`) to the host
/// PID namespace the supervisor lives in.
///
/// This map is *not* used to translate `SeccompNotif.pid`: the kernel fills
/// that field with the pid relative to the reader's namespace
/// (`task_pid_vnr`), and the supervisor reads notifications from the host
/// namespace, so notifications already carry host pids. The map exists for
/// the sandbox's own `/proc` view: the shared host `/proc` mount lists host
/// pids, but inside the sandbox's namespace the same processes must appear
/// as their namespace pids (1, 2, …). It translates ns pid ↔ host pid for
/// that renumbering and for `/proc/<ns_pid>/…` opens.
///
/// The leader's host pid is known at spawn time (it is the value `clone3`
/// returned to the spawner; its ns pid is always 1). Every other
/// process is discovered by scanning `/proc` for tasks whose PID namespace
/// inode matches the sandbox's and reading the last `NSpid:` entry (the pid
/// in the task's own namespace). Entries are re-verified against
/// `/proc/<host>/status` + the namespace inode on every use, so a recycled
/// host pid can never be mistaken for a live sandbox process.
pub(crate) struct PidNsMap {
    /// The sandbox's PID namespace identity: `readlink /proc/<leader>/ns/pid`
    /// (e.g. `pid:[4026532444]`). Only processes in this namespace can be
    /// translated.
    ns_inode: Option<String>,
    /// The sandbox leader's host pid, kept so the identity above can be
    /// re-read when the first attempt failed.
    ///
    /// It is not a formality. The read happens while the leader is *starting*:
    /// it has just moved into its own user namespace, and a process that has
    /// done that is no longer dumpable, so a reader that is not privileged in
    /// that namespace can be refused. The failure is silent (`.ok()`), and an
    /// empty map is not a local problem: measured on the cluster it hides
    /// every numeric entry from the sandbox's own `/proc` (`/proc/self`
    /// included) *and* leaves the append watch unable to translate a single
    /// notification, which is why the push channel was dead for its whole
    /// life (§22.5.7). Keeping the pid lets a later refresh recover.
    leader_host_pid: i32,
    /// ns pid (as reported by seccomp notifications) → host pid.
    map: HashMap<u32, i32>,
}

impl PidNsMap {
    /// Create the map for a sandbox whose leader (ns pid 1) has host pid
    /// `leader_host_pid`.
    pub(crate) fn new(leader_host_pid: i32) -> Self {
        let mut map = HashMap::new();
        map.insert(1, leader_host_pid);
        let mut myself = Self {
            leader_host_pid,
            ns_inode: None,
            map,
        };
        myself.ns_inode = myself.read_ns_inode();
        myself
    }

    /// The sandbox's PID namespace inode, from the leader's own `/proc` entry.
    fn read_ns_inode(&self) -> Option<String> {
        std::fs::read_link(format!("/proc/{}/ns/pid", self.leader_host_pid))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// Translate a sandbox-namespace pid to its host pid, scanning `/proc`
    /// for a fresh entry when the cache misses. Returns `None` when the pid
    /// cannot be resolved to a live process of this sandbox's namespace.
    pub(crate) fn host_pid(&mut self, ns_pid: u32) -> Option<i32> {
        if let Some(&host) = self.map.get(&ns_pid) {
            if self.verify(host, ns_pid) {
                return Some(host);
            }
        }
        self.refresh();
        self.map.get(&ns_pid).copied().filter(|&host| self.verify(host, ns_pid))
    }

    /// The sandbox-namespace pid of a tracked host pid, if known.
    pub(crate) fn ns_pid_of(&self, host_pid: i32) -> Option<u32> {
        self.map.iter().find_map(|(&ns, &host)| (host == host_pid).then_some(ns))
    }

    /// Highest sandbox-namespace pid currently known, for `/proc/loadavg`.
    pub(crate) fn max_ns_pid(&self) -> Option<i32> {
        self.map.keys().copied().map(|p| p as i32).max()
    }

    /// Whether nothing has been resolved yet (a diagnostic).
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Rebuild the map from a full `/proc` scan. Every process whose PID
    /// namespace inode matches the sandbox's is added under its own-namespace
    /// pid (the last `NSpid:` entry), and every thread of a sandbox process
    /// is added under its namespace tid so `/proc/<ns_tid>/…` opens resolve
    /// too (a multi-threaded workload addresses threads by number). The
    /// leader's entry (ns pid 1) is always re-seeded — its ns pid is fixed
    /// by construction.
    fn refresh(&mut self) {
        let mut fresh = HashMap::new();
        // A reader that was refused once may be allowed a moment later (see
        // `leader_host_pid`): without this retry the whole map stays empty for
        // the life of the sandbox, which hides every `/proc/<pid>` entry from
        // the sandbox itself and leaves the append watch unable to translate
        // a single notification.
        if self.ns_inode.is_none() {
            self.ns_inode = self.read_ns_inode();
        }
        {
            if let Ok(dir) = std::fs::read_dir("/proc") {
                for entry in dir.flatten() {
                    let Ok(host) = entry.file_name().to_string_lossy().parse::<i32>() else {
                        continue;
                    };
                    if host <= 0 {
                        continue;
                    }
                    if !self.in_sandbox_ns(host) {
                        continue;
                    }
                    if let Some(ns) = self.ns_pid_of_host(host) {
                        fresh.insert(ns, host);
                    }
                    // Threads of a sandbox process: the sandbox sees their
                    // namespace tids as `/proc/<ns_tid>/…` and can open them
                    // by number, so the map must resolve those as well.
                    if let Ok(task_dir) = std::fs::read_dir(format!("/proc/{}/task", host)) {
                        for task in task_dir.flatten() {
                            let Ok(tid) = task.file_name().to_string_lossy().parse::<i32>() else {
                                continue;
                            };
                            if tid <= 0 || tid == host {
                                continue;
                            }
                            if !self.in_sandbox_ns(tid) {
                                continue;
                            }
                            if let Some(ns) = self.ns_pid_of_host(tid) {
                                fresh.insert(ns, tid);
                            }
                        }
                    }
                }
            }
        }
        if let Some(&host) = self.map.get(&1) {
            fresh.insert(1, host);
        }
        if fresh.is_empty() {
            // Never silent. An empty map hides every numeric entry from the
            // sandbox's own `/proc` and leaves the append watch with nothing
            // to translate, and from outside both look exactly like "the
            // sandbox has no processes".
            static EMPTY_LOGS: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let n = EMPTY_LOGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n < 3 {
                eprintln!(
                    "sandlock-supervise: pid-ns map is empty for leader {} \
                     (namespace inode {})",
                    self.leader_host_pid,
                    match self.ns_inode {
                        Some(ref inode) => inode.as_str(),
                        None => "unreadable",
                    }
                );
            }
        }
        self.map = fresh;
    }

    /// True when `host` lives in the sandbox's PID namespace.
    ///
    /// The namespace inode is the precise answer and is used whenever it is
    /// known. It is not always known: the leader is read while it is moving
    /// into its own user namespace (see `leader_host_pid`), and a reader that
    /// is not privileged there can be refused. The fallback is the sandbox's
    /// *process tree*, which needs nothing but the world-readable
    /// `/proc/<pid>/stat`: everything a sandbox runs descends from its leader,
    /// and a process that changed PID namespace inherits that namespace for
    /// its descendants. Narrower than the inode (a workload that daemonises
    /// and reparents is missed), and only used when the exact answer is
    /// unavailable -- an empty map is not an acceptable alternative, because
    /// it hides every `/proc` entry from the sandbox itself and leaves the
    /// append watch with nothing to translate (§22.5.7).
    fn in_sandbox_ns(&self, host: i32) -> bool {
        match self.ns_inode {
            Some(ref inode) => std::fs::read_link(format!("/proc/{}/ns/pid", host))
                .map(|p| p.to_string_lossy() == inode.as_str())
                .unwrap_or(false),
            None => self.descends_from_leader(host),
        }
    }

    /// Whether `host`'s parent chain reaches the sandbox leader, from
    /// `/proc/<pid>/stat` alone. Bounded: sandboxes are shallow, and a cycle
    /// (or a pid namespace's pid 1) must not become an infinite walk.
    fn descends_from_leader(&self, host: i32) -> bool {
        if host == self.leader_host_pid {
            return true;
        }
        let mut current = host;
        for _ in 0..MAX_ANCESTOR_HOPS {
            let Some(parent) = parent_pid_of(current) else {
                return false;
            };
            if parent == self.leader_host_pid {
                return true;
            }
            if parent <= 1 {
                return false;
            }
            current = parent;
        }
        false
    }

    /// The pid of `host` inside its own (innermost) PID namespace: the last
    /// field of the `NSpid:` line in `/proc/<host>/status`.
    fn ns_pid_of_host(&self, host: i32) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{}/status", host)).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("NSpid:") {
                return rest.split_whitespace().last()?.parse().ok();
            }
        }
        None
    }

    /// Re-check a cached (ns_pid, host_pid) pair against live `/proc` state
    /// so a recycled host pid (or an exited process) is never used.
    fn verify(&self, host: i32, ns_pid: u32) -> bool {
        self.in_sandbox_ns(host) && self.ns_pid_of_host(host) == Some(ns_pid)
    }
}

// ============================================================
// Sensitive path detection
// ============================================================

/// Paths that should be denied with EACCES.
const SENSITIVE_PATHS: &[&str] = &[
    "/proc/kcore",
    "/proc/kmsg",
    "/proc/kallsyms",
    "/proc/keys",
    "/proc/key-users",
    "/proc/sysrq-trigger",
    "/sys/class/net",
    "/sys/firmware",
    "/sys/kernel/security",
];

/// Single-component metadata files under `/proc/<pid>/` that a
/// PID-namespace sandbox may open *on its behalf* (the supervisor opens
/// the translated host path and injects the fd).
///
/// Every entry is a plain, read-only procfs file. Deliberately excluded:
/// magic links (`root`, `cwd`, `exe`, `fd/N`, `map_files/…`, `net/…`),
/// memory exposure (`mem`, `environ`, `smaps`, `pagemap`, …), symlinked
/// aliases that resolve through `/proc/self` (`mounts`, `mountinfo`,
/// `mountstats`), and everything that needs a path component of its own.
/// An on-behalf open with the supervisor's credentials would otherwise
/// bypass the sandbox's own Landlock deny list and ptrace restrictions,
/// so the safe surface is exactly these read-only task-metadata files.
const ON_BEHALF_READABLE_METADATA: &[&str] = &[
    "status",
    "stat",
    "statm",
    "cmdline",
    "comm",
    "limits",
    "cgroup",
    "cpuset",
    "sched",
    "schedstat",
    "io",
    "oom_score",
    "oom_score_adj",
    "oom_adj",
    "loginuid",
    "sessionid",
    "uid_map",
    "gid_map",
    "projid_map",
    "setgroups",
    "coredump_filter",
    "timerslack_ns",
];

/// Returns true for paths that should be denied access.
pub(crate) fn is_sensitive_proc(path: &str) -> bool {
    SENSITIVE_PATHS
        .iter()
        .any(|&sensitive| path == sensitive || path.starts_with(&format!("{}/", sensitive)))
}

/// Extract a numeric PID from a `/proc/{pid}/...` path.
///
/// Returns `None` for non-numeric components like `/proc/self/...`,
/// `/proc/cpuinfo`, etc.  Those are handled elsewhere or are safe.
pub(crate) fn extract_proc_pid(path: &str) -> Option<i32> {
    let rest = path.strip_prefix("/proc/")?;
    // Take the next path component (up to '/' or end of string).
    let component = rest.split('/').next()?;
    component.parse::<i32>().ok()
}

// ============================================================
// /proc/cpuinfo generator
// ============================================================

/// Generate a minimal /proc/cpuinfo with N processor entries.
pub(crate) fn generate_cpuinfo(num_cpus: u32) -> Vec<u8> {
    let mut buf = String::new();
    for i in 0..num_cpus {
        if i > 0 {
            buf.push('\n');
        }
        buf.push_str(&format!(
            "processor\t: {}\nmodel name\t: Virtual CPU\ncpu MHz\t\t: 2400.000\n",
            i
        ));
    }
    buf.into_bytes()
}

// ============================================================
// /proc/uptime generator

/// Generate /proc/uptime showing virtual uptime since sandbox start.
/// Format: "<uptime_secs> <idle_secs>\n"
/// When time_start is set, uptime starts at 0 and ticks forward from sandbox creation.
pub(crate) fn generate_uptime(elapsed_secs: f64) -> Vec<u8> {
    // idle time is reported as 0 — the sandbox has no meaningful idle metric.
    format!("{:.2} 0.00\n", elapsed_secs.max(0.0)).into_bytes()
}

// ============================================================
// /proc/loadavg generator + EWMA tracker
// ============================================================

/// Exponential weighted moving average load tracker, matching the Linux kernel's
/// algorithm (kernel/sched/loadavg.c). Sampled every 5 seconds.
#[derive(Debug, Clone)]
pub struct LoadAvg {
    pub avg_1: f64,
    pub avg_5: f64,
    pub avg_15: f64,
}

// Decay factors: e^(-5/60), e^(-5/300), e^(-5/900)
const EXP_1: f64 = 0.9200444146293232; // e^(-1/12)
const EXP_5: f64 = 0.9834714538216174; // e^(-1/60)
const EXP_15: f64 = 0.9944598480048967; // e^(-1/180)

impl LoadAvg {
    pub fn new() -> Self {
        Self { avg_1: 0.0, avg_5: 0.0, avg_15: 0.0 }
    }

    /// Update averages with current runnable process count.
    /// Called every 5 seconds by the sampling task.
    pub fn sample(&mut self, running: u32) {
        let r = running as f64;
        self.avg_1 = self.avg_1 * EXP_1 + r * (1.0 - EXP_1);
        self.avg_5 = self.avg_5 * EXP_5 + r * (1.0 - EXP_5);
        self.avg_15 = self.avg_15 * EXP_15 + r * (1.0 - EXP_15);
    }
}

/// Generate /proc/loadavg from tracked EWMA values.
/// Format: "avg1 avg5 avg15 running/total last_pid\n"
pub(crate) fn generate_loadavg(load: &LoadAvg, running: u32, total: u32, last_pid: i32) -> Vec<u8> {
    format!(
        "{:.2} {:.2} {:.2} {}/{} {}\n",
        load.avg_1, load.avg_5, load.avg_15,
        running.max(1).min(total), total,
        last_pid.max(0),
    )
    .into_bytes()
}

// /proc/meminfo generator
// ============================================================

/// Generate /proc/meminfo showing virtual memory limits.
pub(crate) fn generate_meminfo(total_bytes: u64, used_bytes: u64) -> Vec<u8> {
    let total_kb = total_bytes / 1024;
    let used_kb = used_bytes.min(total_bytes) / 1024;
    let free_kb = total_kb.saturating_sub(used_kb);
    // Available is typically slightly more than free (includes reclaimable)
    let avail_kb = free_kb;

    format!(
        "MemTotal:       {} kB\n\
         MemFree:        {} kB\n\
         MemAvailable:   {} kB\n",
        total_kb, free_kb, avail_kb,
    )
    .into_bytes()
}

// ============================================================
// /proc/mounts and /proc/self/mountinfo virtualization
// ============================================================

/// Detect the filesystem type of a host path via statfs(2).
fn detect_fstype(path: &std::path::Path) -> &'static str {
    let c_path = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
        Ok(p) => p,
        Err(_) => return "unknown",
    };
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut buf) } != 0 {
        return "unknown";
    }
    // Map f_type magic to filesystem name.
    // Values from linux/magic.h and statfs(2).
    match buf.f_type {
        0xEF53 => "ext4",            // EXT2/3/4_SUPER_MAGIC
        0x9123683E => "btrfs",        // BTRFS_SUPER_MAGIC
        0x58465342 => "xfs",          // XFS_SUPER_MAGIC
        0x01021994 => "tmpfs",        // TMPFS_MAGIC
        0x6969 => "nfs",              // NFS_SUPER_MAGIC
        0x5346544E => "ntfs",         // NTFS_SB_MAGIC
        0x65735546 => "fuse",         // FUSE_SUPER_MAGIC
        0x28cd3d45 => "cramfs",       // CRAMFS_MAGIC
        0x3153464A => "jfs",          // JFS_SUPER_MAGIC
        0x52654973 => "reiserfs",     // REISERFS_SUPER_MAGIC
        0xF2F52010 => "f2fs",         // F2FS_SUPER_MAGIC
        0x4244 => "hfs",              // HFS_SUPER_MAGIC
        0x482B => "hfsplus",          // HFSPLUS_SUPER_MAGIC
        0x1021997 => "v9fs",          // V9FS_MAGIC
        0xFF534D42 => "cifs",         // CIFS_SUPER_MAGIC
        0x73717368 => "squashfs",     // SQUASHFS_MAGIC
        0x62656572 => "sysfs",        // SYSFS_MAGIC
        0x9FA0 => "proc",            // PROC_SUPER_MAGIC
        0x61756673 => "aufs",         // AUFS_SUPER_MAGIC
        0x794C7630 => "overlayfs",    // OVERLAYFS_SUPER_MAGIC
        0x01161970 => "gfs2",         // GFS2_MAGIC
        0x5A4F4653 => "zonefs",       // ZONEFS_MAGIC
        0xCAFE001 => "bcachefs",      // BCACHEFS_SUPER_MAGIC (approximation)
        _ => "unknown",
    }
}

/// Whether the chroot rootfs should be reported read-only in the synthesized
/// mount tables. Only meaningful under a chroot, where the rootfs is presented
/// as its own mount: it is read-only unless `/` was granted write (a read-write
/// OCI rootfs or `--fs-write /`). Without a chroot, the root is the host's real
/// (read-write) `/`, restricted by Landlock rather than a read-only mount.
fn root_is_read_only(policy: &NotifPolicy) -> bool {
    policy.chroot_root.is_some()
        && !policy
            .chroot_writable
            .iter()
            .any(|p| p.as_path() == std::path::Path::new("/"))
}

/// Generate a virtual /proc/mounts showing only the sandbox's own mounts.
///
/// Produces standard `/proc/mounts` format: `device mountpoint type options dump pass`
/// Shows the root entry and each fs_mount entry. Filesystem types are detected
/// from the actual host paths via statfs(2).
pub(crate) fn generate_proc_mounts(
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    chroot_mount_ro: &[std::path::PathBuf],
    root_ro: bool,
) -> Vec<u8> {
    let mut buf = String::new();

    if let Some(root) = chroot_root {
        let fstype = detect_fstype(root);
        let opts = if root_ro { "ro,relatime" } else { "rw,relatime" };
        buf.push_str(&format!("sandlock / {} {} 0 0\n", fstype, opts));
    } else {
        buf.push_str(&format!("rootfs / rootfs {} 0 0\n", if root_ro { "ro" } else { "rw" }));
    }

    for (virtual_path, host_path) in chroot_mounts {
        let vp = virtual_path.to_string_lossy();
        let fstype = detect_fstype(host_path);
        let opts = if chroot_mount_ro.iter().any(|d| d == virtual_path) {
            "ro,relatime"
        } else {
            "rw,relatime"
        };
        buf.push_str(&format!("sandlock {} {} {} 0 0\n", vp, fstype, opts));
    }

    buf.into_bytes()
}

/// Generate a virtual /proc/self/mountinfo showing only the sandbox's own mounts.
///
/// Format (per mount_namespaces(7)):
/// `mount_id parent_id major:minor root mount_point options optional_fields - fs_type source super_options`
pub(crate) fn generate_proc_mountinfo(
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    chroot_mount_ro: &[std::path::PathBuf],
    root_ro: bool,
) -> Vec<u8> {
    let mut buf = String::new();
    let mut mount_id: u32 = 20;
    let (root_opts, root_super) = if root_ro { ("ro,relatime", "ro") } else { ("rw,relatime", "rw") };

    if let Some(root) = chroot_root {
        let fstype = detect_fstype(root);
        buf.push_str(&format!(
            "{} 1 8:1 / / {} - {} sandlock {}\n", mount_id, root_opts, fstype, root_super
        ));
    } else {
        buf.push_str(&format!(
            "{} 1 0:1 / / {} - rootfs rootfs {}\n", mount_id, root_super, root_super
        ));
    }
    mount_id += 1;

    for (virtual_path, host_path) in chroot_mounts {
        let vp = virtual_path.to_string_lossy();
        let fstype = detect_fstype(host_path);
        let (opts, sup) = if chroot_mount_ro.iter().any(|d| d == virtual_path) {
            ("ro,relatime", "ro")
        } else {
            ("rw,relatime", "rw")
        };
        buf.push_str(&format!(
            "{} 20 8:1 / {} {} - {} sandlock {}\n", mount_id, vp, opts, fstype, sup
        ));
        mount_id += 1;
    }

    buf.into_bytes()
}

// ============================================================
// /proc/net/dev and /proc/net/if_inet6 virtualization
// ============================================================

/// Generate a synthetic /proc/net/dev showing only the loopback interface.
pub(crate) fn generate_proc_net_dev() -> Vec<u8> {
    concat!(
        "Inter-|   Receive                                                |  Transmit\n",
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
        "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n",
    ).as_bytes().to_vec()
}

/// Generate a synthetic /proc/net/if_inet6 showing only loopback (::1).
pub(crate) fn generate_proc_net_if_inet6() -> Vec<u8> {
    // Format: address ifindex prefix_len scope flags ifname
    b"00000000000000000000000000000001 01 80 10 80       lo\n".to_vec()
}

// ============================================================
// /proc/net/tcp filtering
// ============================================================

/// Generate a filtered /proc/net/tcp (or tcp6) showing only the sandbox's own ports.
///
/// Reads the real /proc/net/tcp, parses each line's local port, and keeps only
/// lines whose port is in `bound_ports`. The header line is always included.
pub(crate) fn generate_proc_net_tcp(bound_ports: &HashSet<u16>, is_v6: bool) -> Vec<u8> {
    let path = if is_v6 { "/proc/net/tcp6" } else { "/proc/net/tcp" };
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut result = String::new();
    for (i, line) in content.lines().enumerate() {
        if i == 0 {
            // Header line — always include
            result.push_str(line);
            result.push('\n');
            continue;
        }
        // Each line looks like:
        //   sl  local_address rem_address   st ...
        //    0: 0100007F:1F90 00000000:0000 0A ...
        // The local port is the hex after the colon in field 1 (0-indexed).
        if let Some(local_port) = parse_proc_net_tcp_port(line) {
            if bound_ports.contains(&local_port) {
                result.push_str(line);
                result.push('\n');
            }
        }
    }
    result.into_bytes()
}

/// Parse the local port from a /proc/net/tcp line.
/// Format: "  sl  local_addr:PORT remote_addr:PORT ..."
fn parse_proc_net_tcp_port(line: &str) -> Option<u16> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 2 {
        return None;
    }
    // fields[1] is "ADDR:PORT" in hex
    let local = fields[1];
    let colon = local.rfind(':')?;
    let port_hex = &local[colon + 1..];
    u16::from_str_radix(port_hex, 16).ok()
}

// ============================================================
// memfd injection
// ============================================================

/// Create a sealed memfd of `content` and inject it as the child's openat
/// result. The memfd is created in the supervisor, sealed read-only, and
/// handed to the child via NOTIF_ADDFD, so the kernel never re-resolves the
/// virtualized /proc path string after injection.
///
/// On memfd allocation failure we fall through to `Continue` (let the real
/// open proceed) rather than `Errno`, preserving this module's long-standing
/// behavior: a failure to synthesise /proc content is not a denial.
/// Rewrite the pid numbers of an on-behalf `status`/`stat` read into the
/// **sandbox's** numbering (N85).
///
/// Those two files are the only whitelisted metadata whose *content* carries
/// pids, and hiding the host numbering is the whole point of the pid namespace:
/// served by an on-behalf fd they hand the child its host pid (`Pid:`/`Tgid:`/
/// `PPid:`/`NSpid:` in `status`, the first and third fields of `stat`) -- the
/// class of leak N79/N81 kept out of `/proc` by denying the stat family. Both
/// files are small, so their content goes through a memfd (`inject_memfd`)
/// instead of being forwarded.
///
/// A host pid that is not in this sandbox's map (a parent outside the
/// namespace, the host's own init) is written as `0` -- which is what the
/// kernel shows a process whose parent lives outside its namespace.
fn rewrite_pid_numbers(
    content: &str,
    component: &str,
    ns_of: &dyn Fn(i32) -> Option<u32>,
) -> String {
    if component == "stat" {
        rewrite_stat_pids(content, ns_of)
    } else {
        rewrite_status_pids(content, ns_of)
    }
}

fn rewrite_status_pids(content: &str, ns_of: &dyn Fn(i32) -> Option<u32>) -> String {
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        match line.split_once(':') {
            Some((key @ ("Pid" | "Tgid" | "PPid"), value)) => {
                let host = value.trim().parse::<i32>().unwrap_or(0);
                out.push_str(&format!("{}:\t{}", key, ns_of(host).unwrap_or(0)));
            }
            Some(("NSpid", value)) => {
                // The reader is *inside* the sandbox, so exactly one level of
                // the namespace stack is visible to it.
                let inner = value.split_whitespace().last().unwrap_or("0");
                out.push_str(&format!("NSpid:\t{}", inner));
            }
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

fn rewrite_stat_pids(content: &str, ns_of: &dyn Fn(i32) -> Option<u32>) -> String {
    // "1234 (comm) S 5678 ..." -- `comm` may contain spaces and parentheses, so
    // the pid is what precedes the first '(' and the remaining fields start
    // after the *last* ')'.
    let (Some(open), Some(close)) = (content.find('('), content.rfind(')')) else {
        return content.to_string();
    };
    let pid = content[..open].trim().parse::<i32>().unwrap_or(0);
    let comm = &content[open + 1..close];
    let fields: Vec<&str> = content[close + 1..].split_whitespace().collect();
    // After the comm: fields[0] is the state, then ppid, pgrp, session, tty_nr,
    // tpgid. Every one of those that carries a pid carries the *host's* pid, so
    // they all get the same treatment as PPid -- and a value that is not a
    // positive pid (0, or tpgid's -1 for "no tty") is left exactly as it is.
    const PID_FIELDS: [usize; 4] = [1, 2, 3, 5];
    if fields.get(1).is_none() {
        return content.to_string();
    }
    let mut out = format!("{} ({})", ns_of(pid).unwrap_or(0), comm);
    for (index, field) in fields.iter().enumerate() {
        out.push(' ');
        let host = PID_FIELDS
            .contains(&index)
            .then(|| field.parse::<i32>().ok())
            .flatten()
            .filter(|value| *value > 0);
        match host {
            Some(value) => out.push_str(&ns_of(value).unwrap_or(0).to_string()),
            None => out.push_str(field),
        }
    }
    out.push('\n');
    out
}

fn inject_memfd(content: &[u8]) -> NotifAction {
    match content_memfd(content, true) {
        Ok(fd) => NotifAction::InjectFdSend { srcfd: fd, newfd_flags: libc::O_CLOEXEC as u32 },
        Err(_) => NotifAction::Continue, // fallback: let real open proceed
    }
}

// ============================================================
// Read path from child memory
// ============================================================

/// Read a NUL-terminated path string from child memory.
fn read_path(notif: &SeccompNotif, addr: u64, notif_fd: RawFd) -> Option<String> {
    read_child_cstr(notif_fd, notif.id, notif.pid, addr, 4096)
}

// ============================================================
// handle_proc_open — intercept openat for /proc virtualization
// ============================================================

/// Handle openat syscalls targeting /proc files.
///
/// - Denies access to sensitive kernel files.
/// - Virtualizes /proc/cpuinfo and /proc/meminfo with fake content.
/// - Lets everything else through.
pub(crate) async fn handle_proc_open(
    notif: &SeccompNotif,
    processes: &Arc<ProcessIndex>,
    resource: &Arc<Mutex<crate::seccomp::state::ResourceState>>,
    network: &Arc<Mutex<NetworkState>>,
    policy: &NotifPolicy,
    notif_fd: RawFd,
) -> NotifAction {
    // Resolve open/openat/openat2 to a normalized absolute path so the
    // sensitive-path deny, the per-PID filter, and the virtualization
    // string-matches below all see the same canonical form regardless of
    // how the caller spelled it (dirfd-relative, `..`-laden, etc.).
    let resolved = match resolve_open_target(
        notif,
        notif_fd,
        policy.chroot_root.as_deref(),
        &policy.chroot_mounts,
        processes,
    ) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    let path = match resolved.to_str() {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    // Block sensitive paths.
    if is_sensitive_proc(path) {
        return NotifAction::Errno(EACCES);
    }

    // Block access to /proc/{pid}/ entries for PIDs outside the sandbox.
    // This complements the getdents64 PID filtering — directory listings
    // already hide non-sandbox PIDs, but without this check a process
    // could still open /proc/{ppid}/cmdline (or any guessed PID) directly.
    if let Some(pid) = extract_proc_pid(path) {
        // With a PID namespace the numeric pid in the path is the
        // *sandbox-namespace* pid (the shared host /proc mount lists host
        // pids, but the sandbox only ever learns ns pids from its filtered
        // directory listings). Translate to the host pid before deciding,
        // and service the open on the supervisor's behalf against the host
        // path — the kernel would otherwise resolve `/proc/<ns_pid>`
        // against an unrelated host process.
        if let Some(ref map) = policy.pid_ns {
            // PID-namespace sandbox: the numeric pid is a *sandbox-
            // namespace* pid. Resolve it to the host pid and require it to
            // belong to this sandbox's namespace.
            //
            // The open is then serviced on the supervisor's behalf against
            // the host path — but only for a strict whitelist of read-only
            // task-metadata files, and never with a write intent. Opening
            // `/proc/<pid>/root|mem|fd/N|...` with the supervisor's
            // credentials would bypass the sandbox's own Landlock deny list
            // and ptrace restrictions (e.g. `open("/proc/1/root/etc/passwd")`
            // would hand the child a fd to the host `/etc/passwd` the
            // sandbox is denied, and `open("/proc/1/mem")` would re-grant
            // what the process_vm_*/ptrace deny list takes away). Magic-link
            // and multi-component paths (the lexical folding above collapses
            // `.`/`..` but never resolves symlinks) are refused, and
            // O_WRONLY/O_RDWR requests are denied outright — the injected fd
            // is always opened O_RDONLY, so no write-capable descriptor ever
            // crosses the supervisor boundary.
            let open_args = crate::seccomp::notif::decode_open_args(notif, notif_fd);
            let raw_flags = open_args.map(|a| a.flags as i64).unwrap_or(libc::O_RDONLY as i64);
            const WRITE_INTENT: i64 = (libc::O_WRONLY
                | libc::O_RDWR
                | libc::O_APPEND
                | libc::O_TRUNC
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_TMPFILE) as i64;
            if (raw_flags & WRITE_INTENT) != 0 {
                return NotifAction::Errno(EACCES);
            }

            let mut map = map.write().expect("pid-ns map lock poisoned");
            let Some(host_pid) = map.host_pid(pid as u32).map(|h| h as i32) else {
                return NotifAction::Errno(EACCES);
            };
            // F5.3 (M3 S4): the on-behalf whitelist is narrowed to the
            // caller's own process group. Every confined process is its own
            // process-group leader or stays in its command's group (F1.7
            // per-child groups; the one-shot leader's descendants share its
            // group), so same-group == same command subtree in the fork's
            // per-child topology: the caller (identified by its PidKey /
            // notif pid) may read metadata of itself and in-group
            // descendants, never of a sibling command or of
            // `sandlock-init`. Group scope is the subtree approximation —
            // a descendant that `setsid()`s into its own group is denied
            // too (fail closed; documented PidKey limitation). Without the
            // check a sibling's `cmdline`/`status` would leak through the
            // supervisor's on-behalf open.
            let caller_pgid = unsafe { libc::getpgid(notif.pid as i32) };
            let target_pgid = unsafe { libc::getpgid(host_pid) };
            if caller_pgid <= 0 || target_pgid <= 0 || caller_pgid != target_pgid {
                return NotifAction::Errno(EACCES);
            }
            let prefix = format!("/proc/{}", pid);
            let rest = path.strip_prefix(&prefix).unwrap_or("");
            // `strip_prefix` leaves the leading `/` ("/proc/1/status" →
            // "/status"); the whitelist holds bare component names.
            let component = rest.strip_prefix('/').unwrap_or(rest);
            if rest.is_empty() || !ON_BEHALF_READABLE_METADATA.contains(&component) {
                return NotifAction::Errno(EACCES);
            }
            // `status`/`stat` carry this process's pids *as the host sees
            // them*; rewrite them into the sandbox's numbering instead of
            // forwarding the host file (N85). An unreadable file is left to
            // the kernel's answer for the sandbox-namespace path rather than
            // forwarded as-is -- the one outcome that must not happen is
            // handing the child host numbering.
            if component == "status" || component == "stat" {
                let host_path = format!("/proc/{}{}", host_pid, rest);
                let Ok(raw) = std::fs::read_to_string(&host_path) else {
                    return NotifAction::Continue;
                };
                let rewritten = rewrite_pid_numbers(&raw, component, &|host| map.ns_pid_of(host));
                return inject_memfd(rewritten.as_bytes());
            }
            let host_path = format!("/proc/{}{}", host_pid, rest);
            let c_path = match std::ffi::CString::new(host_path) {
                Ok(c) => c,
                Err(_) => return NotifAction::Errno(libc::EINVAL),
            };
            // Open strictly read-only: the caller's write flags are stripped
            // here (write-intent requests were already refused above), and
            // O_CLOEXEC is the only flag carried into the injected fd.
            let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY, 0) };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return NotifAction::Errno(err.raw_os_error().unwrap_or(libc::EIO));
            }
            let newfd_flags = (raw_flags as u32) & (libc::O_CLOEXEC as u32);
            // SAFETY: fd is a fresh O_RDONLY open owned by the supervisor.
            let owned = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) };
            return NotifAction::InjectFdSend { srcfd: owned, newfd_flags };
        } else if !processes.contains(pid) {
            return NotifAction::Errno(EACCES);
        }
    }

    // Virtualize /proc/cpuinfo.
    if path == "/proc/cpuinfo" {
        if let Some(num_cpus) = policy.num_cpus {
            let content = generate_cpuinfo(num_cpus);
            return inject_memfd(&content);
        }
    }

    // Virtualize /proc/meminfo.
    if path == "/proc/meminfo" && policy.max_memory_bytes > 0 {
        let rs = resource.lock().await;
        let content = generate_meminfo(policy.max_memory_bytes, rs.mem_used);
        return inject_memfd(&content);
    }

    // Virtualize /proc/uptime when time_start is set.
    if path == "/proc/uptime" && policy.has_time_start {
        let rs = resource.lock().await;
        let elapsed = rs.start_instant.elapsed().as_secs_f64();
        let content = generate_uptime(elapsed);
        return inject_memfd(&content);
    }

    // Virtualize /proc/loadavg when proc virtualization is active.
    if path == "/proc/loadavg" {
        let total = processes.len() as u32;
        let last_pid = match policy.pid_ns {
            Some(ref map) => map.read().expect("pid-ns map lock poisoned").max_ns_pid().unwrap_or(0),
            None => processes.max_pid().unwrap_or(0),
        };
        let rs = resource.lock().await;
        let running = rs.proc_count;
        let content = generate_loadavg(&rs.load_avg, running, total, last_pid);
        return inject_memfd(&content);
    }

    // Virtualize /proc/net/dev and /proc/net/if_inet6 — show loopback only.
    if path == "/proc/net/dev" {
        return inject_memfd(&generate_proc_net_dev());
    }
    if path == "/proc/net/if_inet6" {
        return inject_memfd(&generate_proc_net_if_inet6());
    }

    // Virtualize /proc/net/tcp and /proc/net/tcp6 when port_remap is active.
    if policy.port_remap && (path == "/proc/net/tcp" || path == "/proc/net/tcp6") {
        let is_v6 = path.ends_with('6');
        let ns = network.lock().await;
        let content = generate_proc_net_tcp(&ns.port_map.bound_ports, is_v6);
        return inject_memfd(&content);
    }

    // Virtualize /proc/mounts and /proc/self/mounts.
    if path == "/proc/mounts" || path == "/proc/self/mounts" {
        let content = generate_proc_mounts(
            policy.chroot_root.as_deref(),
            &policy.chroot_mounts,
            &policy.chroot_mount_ro,
            root_is_read_only(policy),
        );
        return inject_memfd(&content);
    }

    // Virtualize /proc/self/mountinfo.
    if path == "/proc/self/mountinfo" {
        let content = generate_proc_mountinfo(
            policy.chroot_root.as_deref(),
            &policy.chroot_mounts,
            &policy.chroot_mount_ro,
            root_is_read_only(policy),
        );
        return inject_memfd(&content);
    }

    NotifAction::Continue
}

// ============================================================
// PID-namespace stat-family gate
// ============================================================

/// Gate the stat family (`newfstatat`/`statx`/`access`/`readlink` and
/// their legacy variants) for PID-namespace sandboxes.
///
/// In a PID-namespace sandbox a numeric `/proc/<n>/…` path must be read as
/// a *sandbox-namespace* pid, but the shared host `/proc` mount would
/// resolve `/proc/<n>/…` against host pid `n` — a direct cross-namespace
/// metadata leak (host pids 1..N all exist, so every number the sandbox can
/// guess maps to a real host process). The open and getdents64 families are
/// virtualized (translated / renumbered); the stat family is denied
/// outright so the kernel never resolves a sandbox-ns pid against the host
/// table. `open()` remains the supported way to read task metadata (it is
/// translated to the host pid and serves only the whitelisted read-only
/// files above).
///
/// Registered only for the shapes where the kernel would answer for something
/// that is not the sandbox's own tree (`resolved::stat_metadata_mediated`):
/// no root of its own, or a `/proc` that is a separate mount. The syscalls are
/// added to the BPF notif list by
/// [`crate::seccomp_plan::stat_family_syscalls`] under the same predicate.
pub(crate) async fn handle_proc_stat_family(
    notif: &SeccompNotif,
    processes: &Arc<ProcessIndex>,
    policy: &NotifPolicy,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let (dirfd, path_ptr): (i64, u64) = if nr == libc::SYS_newfstatat
        || nr == libc::SYS_statx
        || nr == libc::SYS_faccessat
        || nr == crate::arch::SYS_FACCESSAT2
        || nr == libc::SYS_readlinkat
    {
        // All *at variants share the (dirfd, path) argument slots.
        (notif.data.args[0] as i64, notif.data.args[1])
    } else if Some(nr) == crate::arch::sys_stat()
        || Some(nr) == crate::arch::sys_lstat()
        || Some(nr) == crate::arch::sys_access()
        || Some(nr) == crate::arch::sys_readlink()
    {
        // Legacy syscalls take the path as the first argument.
        (libc::AT_FDCWD as i64, notif.data.args[0])
    } else {
        return NotifAction::Continue;
    };

    let path = match read_path(notif, path_ptr, notif_fd) {
        // Empty path (e.g. `fstatat(fd, "", AT_EMPTY_PATH)`) stats the fd
        // itself, not a path: let the kernel handle it.
        Some(p) if !p.is_empty() => p,
        _ => return NotifAction::Continue,
    };
    let resolved = match resolve_to_normalized_absolute(
        notif.pid,
        dirfd,
        &path,
        policy.chroot_root.as_deref(),
        &policy.chroot_mounts,
        processes,
    ) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    let path = match resolved.to_str() {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    if extract_proc_pid(path).is_some() {
        return NotifAction::Errno(EACCES);
    }
    NotifAction::Continue
}

// ============================================================
// sched_getaffinity virtualization
// ============================================================

/// Handle sched_getaffinity(pid, cpusetsize, mask) — return a fake mask
/// with only `num_cpus` bits set, so nproc/sysconf report the virtual count
/// without actually pinning the process to specific cores.
pub(crate) fn handle_sched_getaffinity(
    notif: &SeccompNotif,
    num_cpus: u32,
    notif_fd: RawFd,
) -> NotifAction {
    let cpusetsize = notif.data.args[1] as usize;
    let mask_addr = notif.data.args[2];

    if mask_addr == 0 || cpusetsize == 0 {
        return NotifAction::Continue;
    }

    // Build a cpu_set with the first N bits set.
    let mut mask = vec![0u8; cpusetsize];
    for i in 0..num_cpus as usize {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < mask.len() {
            mask[byte_idx] |= 1 << bit_idx;
        }
    }

    match write_child_mem(notif_fd, notif.id, notif.pid, mask_addr, &mask) {
        Ok(()) => NotifAction::ReturnValue(cpusetsize as i64),
        Err(_) => NotifAction::Continue,
    }
}

// ============================================================
// uname virtualization
// ============================================================

/// Handle uname() — override the nodename (hostname) field.
///
/// uname(buf) writes a `struct utsname` to buf. We call the real uname()
/// in the supervisor, patch the nodename field, and write the result to
/// the child's buffer.
pub(crate) fn handle_uname(
    notif: &SeccompNotif,
    hostname: &str,
    notif_fd: RawFd,
) -> NotifAction {
    let buf_addr = notif.data.args[0];
    if buf_addr == 0 {
        return NotifAction::Continue;
    }

    // Call real uname() in the supervisor to get current kernel info.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return NotifAction::Continue;
    }

    // Overwrite nodename with the virtual hostname.
    let name_bytes = hostname.as_bytes();
    let len = name_bytes.len().min(uts.nodename.len() - 1);
    for (i, &b) in name_bytes[..len].iter().enumerate() {
        uts.nodename[i] = b as libc::c_char;
    }
    uts.nodename[len] = 0;

    // Write the patched utsname to child memory.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &uts as *const _ as *const u8,
            std::mem::size_of::<libc::utsname>(),
        )
    };

    match write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, bytes) {
        Ok(()) => NotifAction::ReturnValue(0),
        Err(_) => NotifAction::Continue,
    }
}

// ============================================================
// sysinfo / getcpu virtualization
// ============================================================

/// Handle `sysinfo(2)` -- report the sandbox's own memory budget.
///
/// `sysinfo` is not namespaced: it answers with the **host's** total and free
/// RAM, 1/5/15-minute load average, process count and uptime. The mediated
/// `/proc/meminfo` already reports the sandbox's budget, so without this the
/// two views disagree by an order of magnitude (measured: `/proc` said 1 GiB /
/// load 0.00 / 4 procs while the raw syscall said 7.5 GiB / load 0.31 /
/// 685 procs), and the host's free-RAM figure is a cross-tenant side channel:
/// a neighbour's allocations move it.
///
/// The values mirror [`generate_meminfo`] -- same total (the sandbox's budget),
/// same free (budget minus the usage the resource ledger tracks) -- and
/// everything the platform does not model is zero rather than the host's real
/// number. `mem_unit` is 1, so the byte fields are in bytes.
pub(crate) fn handle_sysinfo(
    notif: &SeccompNotif,
    total_bytes: u64,
    used_bytes: u64,
    notif_fd: RawFd,
) -> NotifAction {
    let buf_addr = notif.data.args[0];
    if buf_addr == 0 {
        return NotifAction::Continue;
    }

    let used = used_bytes.min(total_bytes);
    let free = total_bytes.saturating_sub(used);
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    info.mem_unit = 1;
    // Uptime/load/process count are host-wide facts the sandbox has no view
    // of; the platform does not model them, so they are zero (not the host's).
    info.uptime = 0;
    info.loads = [0, 0, 0];
    info.procs = 0;
    info.totalram = total_bytes as _;
    info.freeram = free as _;
    info.sharedram = 0;
    info.bufferram = 0;
    info.totalswap = 0;
    info.freeswap = 0;
    info.totalhigh = 0;
    info.freehigh = 0;

    let bytes = unsafe {
        std::slice::from_raw_parts(
            &info as *const _ as *const u8,
            std::mem::size_of::<libc::sysinfo>(),
        )
    };
    match write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, bytes) {
        Ok(()) => NotifAction::ReturnValue(0),
        Err(_) => NotifAction::Continue,
    }
}

/// Handle `getcpu(2)` -- report CPU 0 instead of the host CPU the sandbox
/// happens to be scheduled on. Either pointer may be NULL (both are optional
/// in the kernel's contract).
pub(crate) fn handle_getcpu(notif: &SeccompNotif, notif_fd: RawFd) -> NotifAction {
    for arg in [notif.data.args[0], notif.data.args[1]] {
        if arg == 0 {
            continue;
        }
        let zero: u32 = 0;
        let bytes = unsafe {
            std::slice::from_raw_parts(&zero as *const _ as *const u8, std::mem::size_of::<u32>())
        };
        if write_child_mem(notif_fd, notif.id, notif.pid, arg, bytes).is_err() {
            return NotifAction::Continue;
        }
    }
    NotifAction::ReturnValue(0)
}

/// Handle `statfs(2)` from the host-maintained disk accounting file.
///
/// `statfs` is not namespaced either: it reports the *host* filesystem's
/// capacity and free space, so `df` / `shutil.disk_usage` inside a sandbox see
/// the node's whole volume (measured: 99.7 GiB with 31.6% used on `/`, and a
/// 10 PiB NAS figure for `/workspace`). The sandbox's own story is its quota
/// and what is left of it, and only the host knows both -- it sold the quota
/// and it measures the tree -- so the host writes them into a file and this
/// handler reports them:
///
/// ```text
/// <total_bytes> <used_bytes>
/// ```
///
/// Read on every call, so the numbers are as fresh as the host's own refresh.
/// A missing or malformed file falls through to the kernel: that is the
/// pre-option behaviour, and refusing a valid `statfs` would be worse than
/// answering it with the host's numbers.
///
/// `f_type`/`f_namelen` keep the real values (they describe the tree the
/// sandbox is actually on, and tools use them to reason about the path);
/// block counts are the accounting, at a 4 KiB block size.
pub(crate) fn handle_statfs(
    notif: &SeccompNotif,
    stats_path: &std::path::Path,
    notif_fd: RawFd,
) -> NotifAction {
    let mut seed: libc::statfs = unsafe { std::mem::zeroed() };
    // Seed from the kernel so f_type/f_namelen describe the real tree. The
    // numbers reported below do not depend on the path, so a path the
    // supervisor cannot read is not a reason to fall through.
    let path_addr = notif.data.args[0];
    if path_addr != 0 {
        if let Some(text) = read_child_cstr(notif_fd, notif.id, notif.pid, path_addr, 4096) {
            if let Ok(c_path) = std::ffi::CString::new(text) {
                unsafe { libc::statfs(c_path.as_ptr(), &mut seed) };
            }
        }
    }
    answer_disk_stats(notif, stats_path, notif_fd, seed)
}

/// `fstatfs(2)`: the fd-based spelling of the same question.
///
/// `os.fstatvfs(fd)` -- and anything that stats an already-open handle instead
/// of a path -- takes this syscall, so leaving it out reports the node's volume
/// even while `statfs` reports the ledger (measured 2026-10-01: `statvfs("/")`
/// answered 2621440 blocks while `fstatvfs(fd)` answered 72335360).
///
/// The seed comes from the child's own fd (duplicated out of it, exactly like
/// every other on-behalf fd op) so `f_type`/`f_namelen` describe the object the
/// handle really points at; a handle the supervisor cannot duplicate is not a
/// reason to fall through -- the accounting does not depend on it.
pub(crate) fn handle_fstatfs(
    notif: &SeccompNotif,
    stats_path: &std::path::Path,
    notif_fd: RawFd,
) -> NotifAction {
    let mut seed: libc::statfs = unsafe { std::mem::zeroed() };
    let fd = notif.data.args[0] as i32;
    if fd >= 0 {
        if let Ok(dup) = crate::seccomp::notif::dup_fd_from_pid(notif.pid, fd) {
            unsafe { libc::fstatfs(dup.as_raw_fd(), &mut seed) };
        }
    }
    answer_disk_stats(notif, stats_path, notif_fd, seed)
}

/// Write the accounting answer for a `statfs`/`fstatfs` notification.
///
/// Both syscalls put the buffer in `args[1]` (the path/fd is `args[0]`), so the
/// only difference between them is how `seed` was obtained. A missing or
/// malformed accounting file falls through to the kernel -- which is the
/// pre-option behaviour, and refusing a valid `statfs` would be worse than
/// answering it with the host's numbers.
fn answer_disk_stats(
    notif: &SeccompNotif,
    stats_path: &std::path::Path,
    notif_fd: RawFd,
    seed: libc::statfs,
) -> NotifAction {
    let buf_addr = notif.data.args[1];
    if buf_addr == 0 {
        return NotifAction::Continue;
    }
    let Some((total, used)) = read_disk_stats(stats_path) else {
        return NotifAction::Continue;
    };

    let mut buf = seed;

    const BLOCK: u64 = 4096;
    let used = used.min(total);
    let total_blocks = total / BLOCK;
    let free_blocks = (total - used) / BLOCK;
    buf.f_bsize = BLOCK as _;
    buf.f_frsize = BLOCK as _;
    buf.f_blocks = total_blocks as _;
    buf.f_bfree = free_blocks as _;
    buf.f_bavail = free_blocks as _;
    // Inode counts are not modelled separately; scale them like the block
    // counts so `df -i` stays self-consistent.
    buf.f_files = total_blocks as _;
    buf.f_ffree = free_blocks as _;

    let bytes = unsafe {
        std::slice::from_raw_parts(
            &buf as *const _ as *const u8,
            std::mem::size_of::<libc::statfs>(),
        )
    };
    match write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, bytes) {
        Ok(()) => NotifAction::ReturnValue(0),
        Err(_) => NotifAction::Continue,
    }
}

/// Parse the host's ``<total_bytes> <used_bytes>`` accounting file.
fn read_disk_stats(path: &std::path::Path) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut parts = text.split_whitespace();
    let total: u64 = parts.next()?.parse().ok()?;
    let used: u64 = parts.next().unwrap_or("0").parse().ok()?;
    Some((total, used))
}

/// Handle open/openat/openat2 targeting /etc/hostname — return a memfd
/// with the virtual hostname. Path is resolved and lexically normalized
/// via [`resolve_open_target`] so dirfd-relative and non-canonical
/// spellings all hit the shim.
pub(crate) fn handle_hostname_open(
    notif: &SeccompNotif,
    hostname: &str,
    notif_fd: RawFd,
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    processes: &ProcessIndex,
) -> Option<NotifAction> {
    let resolved = resolve_open_target(notif, notif_fd, chroot_root, chroot_mounts, processes)?;
    if resolved != std::path::Path::new("/etc/hostname") {
        return None;
    }
    let content = format!("{}\n", hostname);
    Some(inject_memfd(content.as_bytes()))
}

/// Intercept any `open`/`openat`/`openat2` of `/etc/hosts` and return a memfd
/// with virtual content.
///
/// Every sandbox gets a fixed loopback view (`127.0.0.1 localhost` /
/// `::1 localhost`) plus any concrete hostnames pre-resolved from
/// `net_allow`, so the host's on-disk `/etc/hosts` never leaks in and
/// glibc's `files` NSS backend resolves allowed hostnames without DNS.
pub(crate) fn handle_etc_hosts_open(
    notif: &SeccompNotif,
    etc_hosts_content: &str,
    notif_fd: RawFd,
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    processes: &ProcessIndex,
) -> Option<NotifAction> {
    handle_virtual_file_open(
        notif,
        std::path::Path::new("/etc/hosts"),
        etc_hosts_content,
        notif_fd,
        chroot_root,
        chroot_mounts,
        processes,
    )
}

/// Intercept any `open`/`openat`/`openat2` of `/etc/resolv.conf` and return
/// a memfd pointing at the sandbox's DNS gateway. Only active in per-sandbox
/// netns mode, so wildcard-domain lookups reach the supervisor's gateway
/// instead of the host resolver.
pub(crate) fn handle_resolv_conf_open(
    notif: &SeccompNotif,
    resolv_conf_content: &str,
    notif_fd: RawFd,
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    processes: &ProcessIndex,
) -> Option<NotifAction> {
    handle_virtual_file_open(
        notif,
        std::path::Path::new("/etc/resolv.conf"),
        resolv_conf_content,
        notif_fd,
        chroot_root,
        chroot_mounts,
        processes,
    )
}

/// Shared implementation: if the open target resolves to `virtual_path`,
/// return a memfd with `content`; otherwise fall through.
fn handle_virtual_file_open(
    notif: &SeccompNotif,
    virtual_path: &std::path::Path,
    content: &str,
    notif_fd: RawFd,
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    processes: &ProcessIndex,
) -> Option<NotifAction> {
    let resolved = resolve_open_target(notif, notif_fd, chroot_root, chroot_mounts, processes)?;
    if resolved != virtual_path {
        return None;
    }
    Some(inject_memfd(content.as_bytes()))
}

/// Resolve the path argument of an open-family syscall (`open`, `openat`,
/// or `openat2`) to a lexically-normalized absolute host-side path.
///
/// Used by every `openat`-shaped handler so the security and
/// virtualization checks operate on the same canonical form regardless
/// of how the caller spelled the path. The literal-string compare used
/// before this helper missed four bypass shapes: legacy `open`,
/// `openat2`, dirfd-relative spellings like `openat(open("/etc"),
/// "hosts", ...)`, and non-canonical absolutes like `/etc/../etc/hosts`
/// or `//etc/hosts`.
///
/// Returns `None` if the notif isn't an open variant, the path can't be
/// read from child memory, the dirfd can't be resolved, or the path
/// walks above `/`. Callers treat `None` as "fall through to the kernel"
/// (`NotifAction::Continue`).
pub(crate) fn resolve_open_target(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    processes: &ProcessIndex,
) -> Option<std::path::PathBuf> {
    let nr = notif.data.nr as i64;
    let (dirfd, path_ptr): (i64, u64) = if Some(nr) == crate::arch::sys_open() {
        // open(path, flags, mode) — no dirfd, behaves as AT_FDCWD.
        (libc::AT_FDCWD as i64, notif.data.args[0])
    } else if nr == libc::SYS_openat || nr == crate::arch::SYS_OPENAT2 {
        // openat(dirfd, path, ...) and openat2(dirfd, path, ...) share
        // the same first two argument slots.
        (notif.data.args[0] as i64, notif.data.args[1])
    } else {
        return None;
    };
    let path = read_path(notif, path_ptr, notif_fd)?;
    resolve_to_normalized_absolute(notif.pid, dirfd, &path, chroot_root, chroot_mounts, processes)
}

/// Lexical normalization of `(pid, dirfd, path)`:
///
/// - Absolute `path`: used as-is.
/// - Relative `path` with `dirfd == AT_FDCWD`: prefixed with the child's
///   cwd from `/proc/<pid>/cwd`.
/// - Relative `path` with explicit `dirfd`: prefixed with the symlink
///   target of `/proc/<pid>/fd/<dirfd>` (the host kernel's view of the
///   directory the dirfd points to).
///
/// Then collapses `.`, `..`, and redundant `/` components. Returns
/// `None` if the dirfd cannot be resolved or the path walks above `/`.
fn resolve_to_normalized_absolute(
    pid: u32,
    dirfd: i64,
    path: &str,
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    processes: &ProcessIndex,
) -> Option<std::path::PathBuf> {
    use std::path::{Component, Path, PathBuf};

    // The dirfd/cwd symlink target is the *real* host directory. Under
    // chroot, sandlock services /proc, /etc and /dev via on-behalf opens,
    // so that target is e.g. `<chroot>/proc` while the child's absolute
    // spelling of the same file is `/proc/...`. Map the base back into the
    // sandbox's virtual namespace so relative and absolute spellings
    // resolve identically and the open-family shims (proc synthesis,
    // /etc/hosts, /etc/hostname, random seed, CA inject) match either way.
    let to_virtual = |host: PathBuf| match chroot_root {
        Some(root) => {
            crate::chroot::resolve::host_to_virtual(root, chroot_mounts, &host).unwrap_or(host)
        }
        None => host,
    };

    let joined: PathBuf = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else if dirfd as i32 == libc::AT_FDCWD {
        // Under chroot the supervisor services chdir itself and the child's
        // real cwd never moves, so its own notion is the only current one,
        // and it is already virtual. Falling back to the kernel's is right
        // only for a task that has never moved, which is when nothing is
        // tracked.
        let base = match i32::try_from(pid).ok().and_then(|p| processes.virtual_cwd(p)) {
            Some(tracked) => tracked,
            None => to_virtual(std::fs::read_link(format!("/proc/{}/cwd", pid)).ok()?),
        };
        base.join(path)
    } else {
        let base = std::fs::read_link(format!("/proc/{}/fd/{}", pid, dirfd as i32)).ok()?;
        to_virtual(base).join(path)
    };

    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                // pop the last regular component; refuse to walk above
                // the root (out becomes empty after popping "/").
                if !out.pop() {
                    return None;
                }
                if out.as_os_str().is_empty() {
                    return None;
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    Some(out)
}

// ============================================================
// Deterministic directory listing
// ============================================================

/// Handle getdents64/getdents for deterministic directory listing.
///
/// Reads the directory entries via `/proc/{pid}/fd/{fd}`, sorts them
/// lexicographically by name, and returns them to the child in sorted order.
/// This ensures `readdir()`, `ls`, `glob()` etc. produce the same order
/// regardless of filesystem internals.
pub(crate) async fn handle_sorted_getdents(
    notif: &SeccompNotif,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let pid = notif.pid;
    let child_fd = (notif.data.args[0] & 0xFFFF_FFFF) as u32;
    let buf_addr = notif.data.args[1];
    let buf_size = (notif.data.args[2] & 0xFFFF_FFFF) as usize;

    let link_path = format!("/proc/{}/fd/{}", pid, child_fd);
    let dir_path = match std::fs::read_link(&link_path) {
        Ok(t) => t,
        Err(_) => return NotifAction::Continue,
    };

    let entry = match processes.entry_for(pid as i32) {
        Some(e) => e,
        None => return NotifAction::Continue,
    };
    let cache_key = (child_fd, dir_path.to_string_lossy().into_owned());
    let mut perproc = entry.1.lock().await;

    // Build and cache sorted entries on first call for this open directory.
    // Remove an empty cache on EOF so later fd reuse can rebuild entries.
    if !perproc.procfs_dir_cache.contains_key(&cache_key) {
        let dir = match std::fs::read_dir(&dir_path) {
            Ok(d) => d,
            Err(_) => return NotifAction::Continue,
        };

        let mut names: Vec<_> = Vec::new();
        {
            use std::os::unix::fs::MetadataExt;
            let dot_ino = std::fs::symlink_metadata(&dir_path).map(|m| m.ino()).unwrap_or(0);
            let dotdot_ino = dir_path
                .parent()
                .and_then(|p| std::fs::symlink_metadata(p).ok())
                .map(|m| m.ino())
                .unwrap_or(dot_ino);
            names.push((".".to_string(), DT_DIR, dot_ino));
            names.push(("..".to_string(), DT_DIR, dotdot_ino));
        }

        names.extend(dir
            .filter_map(|e| e.ok())
            .map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let d_type = match e.file_type() {
                    Ok(ft) if ft.is_dir() => DT_DIR,
                    Ok(ft) if ft.is_symlink() => DT_LNK,
                    _ => DT_REG,
                };
                let d_ino = {
                    use std::os::linux::fs::MetadataExt;
                    e.metadata().map(|m| m.st_ino()).unwrap_or(0)
                };
                (name, d_type, d_ino)
            }));

        names.sort_by(|a, b| a.0.cmp(&b.0));

        let entries: Vec<Vec<u8>> = names
            .iter()
            .enumerate()
            .filter_map(|(i, (name, d_type, d_ino))| {
                build_dirent64(*d_ino, (i + 1) as i64, *d_type, name)
            })
            .collect();

        perproc.procfs_dir_cache.insert(cache_key.clone(), entries);
    }

    let entries = match perproc.procfs_dir_cache.get_mut(&cache_key) {
        Some(e) => e,
        None => return NotifAction::Continue,
    };

    // Empty cache = already fully drained on a prior call → return 0 (EOF).
    if entries.is_empty() {
        perproc.procfs_dir_cache.remove(&cache_key);
        return NotifAction::ReturnValue(0);
    }

    // Pack as many entries as fit into the child's buffer.
    let mut result = Vec::new();
    let mut consumed = 0;
    for entry in entries.iter() {
        if result.len() + entry.len() > buf_size {
            break;
        }
        result.extend_from_slice(entry);
        consumed += 1;
    }

    if consumed > 0 {
        entries.drain(..consumed);
    }

    drop(perproc);

    if !result.is_empty() {
        if write_child_mem(notif_fd, notif.id, pid, buf_addr, &result).is_err() {
            return NotifAction::Continue;
        }
    }

    NotifAction::ReturnValue(result.len() as i64)
}

// ============================================================
// dirent64 construction helpers
// ============================================================

pub(crate) const DT_DIR: u8 = 4;
pub(crate) const DT_REG: u8 = 8;
pub(crate) const DT_LNK: u8 = 10;

/// Build a single linux_dirent64 entry.
/// struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }
/// d_reclen is 8-byte aligned.
///
/// Returns `None` if `name` exceeds the Linux NAME_MAX limit (255 bytes) —
/// such names can't appear in a real dirent stream, and accepting them would
/// produce a record whose `d_reclen` overflows the u16 field.
pub(crate) fn build_dirent64(d_ino: u64, d_off: i64, d_type: u8, name: &str) -> Option<Vec<u8>> {
    const NAME_MAX: usize = 255;
    let name_bytes = name.as_bytes();
    if name_bytes.len() > NAME_MAX {
        return None;
    }
    let reclen = ((19 + name_bytes.len() + 1) + 7) & !7; // +1 NUL, align to 8
    let mut buf = vec![0u8; reclen];
    buf[0..8].copy_from_slice(&d_ino.to_ne_bytes());
    buf[8..16].copy_from_slice(&d_off.to_ne_bytes());
    buf[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
    buf[18] = d_type;
    buf[19..19 + name_bytes.len()].copy_from_slice(name_bytes);
    Some(buf)
}

/// Build a filtered list of dirent64 entries for /proc, hiding PIDs not in the sandbox.
fn build_filtered_dirents(sandbox_pids: &HashSet<i32>) -> Vec<Vec<u8>> {
    let mut entries = Vec::new();
    let mut d_off: i64 = 0;

    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return entries,
    };

    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Filter out foreign PID directories.
        if let Ok(pid) = name_str.parse::<i32>() {
            if !sandbox_pids.contains(&pid) {
                continue;
            }
        }

        d_off += 1;

        let d_type = match entry.file_type() {
            Ok(ft) if ft.is_dir() => DT_DIR,
            Ok(ft) if ft.is_symlink() => DT_LNK,
            _ => DT_REG,
        };

        let d_ino = {
            use std::os::linux::fs::MetadataExt;
            entry.metadata().map(|m| m.st_ino()).unwrap_or(0)
        };

        if let Some(rec) = build_dirent64(d_ino, d_off, d_type, &name_str) {
            entries.push(rec);
        }
    }
    entries
}

/// Like [`build_filtered_dirents`], but for a PID-namespace sandbox: the
/// entries are renamed to the pid each process has *inside* the sandbox's
/// namespace (`/proc` there shows 1, 2, … — never host pids). Membership is
/// decided by the namespace map (which covers every process of the sandbox's
/// PID namespace, whether or not the supervisor has registered it yet), not
/// by the supervisor's tracking set.
fn build_filtered_dirents_ns(map: &PidNsMap) -> Vec<Vec<u8>> {
    let mut entries = Vec::new();
    let mut d_off: i64 = 0;

    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return entries,
    };

    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Keep only the sandbox's own processes, renamed to their ns pid.
        if let Ok(host_pid) = name_str.parse::<i32>() {
            let Some(ns_pid) = map.ns_pid_of(host_pid) else {
                // Not a process of this sandbox's PID namespace: hide it.
                continue;
            };
            d_off += 1;
            let d_type = match entry.file_type() {
                Ok(ft) if ft.is_dir() => DT_DIR,
                Ok(ft) if ft.is_symlink() => DT_LNK,
                _ => DT_REG,
            };
            let d_ino = {
                use std::os::linux::fs::MetadataExt;
                entry.metadata().map(|m| m.st_ino()).unwrap_or(0)
            };
            if let Some(rec) = build_dirent64(d_ino, d_off, d_type, &ns_pid.to_string()) {
                entries.push(rec);
            }
            continue;
        }

        d_off += 1;
        let d_type = match entry.file_type() {
            Ok(ft) if ft.is_dir() => DT_DIR,
            Ok(ft) if ft.is_symlink() => DT_LNK,
            _ => DT_REG,
        };
        let d_ino = {
            use std::os::linux::fs::MetadataExt;
            entry.metadata().map(|m| m.st_ino()).unwrap_or(0)
        };
        if let Some(rec) = build_dirent64(d_ino, d_off, d_type, &name_str) {
            entries.push(rec);
        }
    }
    entries
}

// ============================================================
// handle_getdents — PID filtering
// ============================================================

/// Handle getdents64 for PID filtering when `isolate_pids` is true.
///
/// Intercepts getdents64 calls on /proc directory fds and returns a filtered
/// set of entries that hides PIDs not belonging to the sandbox.
pub(crate) async fn handle_getdents(
    notif: &SeccompNotif,
    processes: &Arc<ProcessIndex>,
    policy: &NotifPolicy,
    notif_fd: RawFd,
) -> NotifAction {
    let pid = notif.pid; // u32
    let child_fd = (notif.data.args[0] & 0xFFFF_FFFF) as u32;
    let buf_addr = notif.data.args[1];
    let buf_size = (notif.data.args[2] & 0xFFFF_FFFF) as usize;

    // Check if the child's fd points to /proc.
    let link_path = format!("/proc/{}/fd/{}", pid, child_fd);
    let target = match std::fs::read_link(&link_path) {
        Ok(t) => t,
        Err(_) => return NotifAction::Continue,
    };
    if target.to_str() != Some("/proc") {
        return NotifAction::Continue;
    }

    let entry = match processes.entry_for(pid as i32) {
        Some(e) => e,
        None => return NotifAction::Continue,
    };
    let cache_key = (child_fd, target.to_string_lossy().into_owned());
    let mut perproc = entry.1.lock().await;

    // Build and cache entries on first call for this (fd, target) pair.
    if !perproc.procfs_dir_cache.contains_key(&cache_key) {
        // Snapshot sandbox PIDs without holding the per-process lock
        // any longer than needed — pids_snapshot only takes the
        // ProcessIndex read lock briefly.
        let snapshot = processes.pids_snapshot();
        let entries = match policy.pid_ns {
            // PID-namespace sandbox: list the sandbox's own processes under
            // their namespace pids (1, 2, …) so /proc matches what the
            // kernel's pid namespace would show.
            Some(ref map) => {
                let mut map = map.write().expect("pid-ns map lock poisoned");
                // Refresh so processes created since the last scan (and any
                // not yet registered with the supervisor) appear; the
                // getdents cache makes this once per directory fd.
                map.refresh();
                build_filtered_dirents_ns(&map)
            }
            None => build_filtered_dirents(&snapshot),
        };
        perproc.procfs_dir_cache.insert(cache_key.clone(), entries);
    }

    let entries = match perproc.procfs_dir_cache.get_mut(&cache_key) {
        Some(e) => e,
        None => return NotifAction::Continue,
    };

    // Pack as many entries as fit into the child's buffer.
    let mut result = Vec::new();
    let mut consumed = 0;
    for entry in entries.iter() {
        if result.len() + entry.len() > buf_size {
            break;
        }
        result.extend_from_slice(entry);
        consumed += 1;
    }

    // Empty cache = already fully drained on a prior call → return 0 (EOF).
    if entries.is_empty() {
        perproc.procfs_dir_cache.remove(&cache_key);
        return NotifAction::ReturnValue(0);
    }

    if consumed > 0 {
        entries.drain(..consumed);
    }

    drop(perproc);

    // Write the result into the child's buffer and return the byte count.
    if !result.is_empty() {
        if write_child_mem(notif_fd, notif.id, pid, buf_addr, &result).is_err() {
            return NotifAction::Continue;
        }
    }

    NotifAction::ReturnValue(result.len() as i64)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// N85: the two whitelisted metadata files whose content carries pids are
    /// rewritten into the sandbox's numbering. The host pids here are the ones
    /// the on-behalf read really produced on the local lane (`Pid: 46`,
    /// `PPid: 42`, `NSpid: 46 3` for a process the sandbox knows as pid 3).
    #[test]
    fn status_pid_fields_are_rewritten_into_the_sandbox_numbering() {
        let raw = concat!(
            "Name:\tpython3\n",
            "Pid:\t46\n",
            "PPid:\t42\n",
            "Tgid:\t46\n",
            "NSpid:\t46\t3\n",
            "Uid:\t10000\t10000\t10000\t10000\n",
        );
        let ns_of = |host: i32| match host {
            46 => Some(3),
            42 => Some(1),
            _ => None,
        };
        assert_eq!(
            rewrite_pid_numbers(raw, "status", &ns_of),
            concat!(
                "Name:\tpython3\n",
                "Pid:\t3\n",
                "PPid:\t1\n",
                "Tgid:\t3\n",
                "NSpid:\t3\n",
                "Uid:\t10000\t10000\t10000\t10000\n",
            )
        );
    }

    /// A parent outside the namespace reads as 0, which is the kernel's own
    /// answer for that shape.
    #[test]
    fn a_pid_outside_the_sandbox_is_rewritten_to_zero() {
        let raw = "Pid:\t46\nPPid:\t1\n";
        let ns_of = |host: i32| (host == 46).then_some(3);
        assert_eq!(rewrite_pid_numbers(raw, "status", &ns_of), "Pid:\t3\nPPid:\t0\n");
    }

    /// `stat` is one line, and `comm` may contain spaces and parentheses -- the
    /// rewrite must not be confused by them.
    #[test]
    fn stat_pid_and_ppid_are_rewritten_with_a_hostile_comm() {
        let raw = "46 (py ) thing) S 42 46 46 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0\n";
        let ns_of = |host: i32| match host {
            46 => Some(3),
            42 => Some(1),
            _ => None,
        };
        assert_eq!(
            rewrite_pid_numbers(raw, "stat", &ns_of),
            "3 (py ) thing) S 1 3 3 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0\n"
        );
    }

    /// Kernel-behavior probe backing `Sandbox::pid_ns`: after
    /// `unshare(CLONE_NEWUSER)` (required for unprivileged PID namespace
    /// creation) + `unshare(CLONE_NEWPID)` + a final fork, the first
    /// process of the new namespace cannot `kill(pid, 0)` a process from
    /// the host namespace — the probe must fail with ESRCH. The integration
    /// suite relies on exactly this property for cross-sandbox signal
    /// isolation; this lib test pins it without the full sandbox stack.
    #[test]
    fn pid_ns_kill_host_pid_is_esrch() {
        let host_pid = std::process::id() as i32;
        let a = unsafe { libc::fork() };
        assert!(a >= 0, "fork failed");
        if a == 0 {
            if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
                unsafe { libc::_exit(10) };
            }
            if unsafe { libc::unshare(crate::sys::structs::CLONE_NEWPID as libc::c_int) } != 0 {
                unsafe { libc::_exit(11) };
            }
            let b = unsafe { libc::fork() };
            if b < 0 {
                unsafe { libc::_exit(12) };
            }
            if b == 0 {
                let r = unsafe { libc::kill(host_pid, 0) };
                let errno = if r == 0 {
                    0
                } else {
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
                };
                unsafe { libc::_exit(errno) }; // exit code = errno; ESRCH == 3
            }
            let mut st = 0;
            unsafe { libc::waitpid(b, &mut st, 0) };
            if libc::WIFEXITED(st) {
                unsafe { libc::_exit(libc::WEXITSTATUS(st)) };
            }
            unsafe { libc::_exit(13) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(a, &mut st, 0) };
        assert!(
            libc::WIFEXITED(st),
            "intermediate exited abnormally: status {:#x}",
            st
        );
        assert_eq!(
            libc::WEXITSTATUS(st),
            3,
            "kill(host_pid, 0) must be ESRCH inside a fresh PID namespace"
        );
    }

    #[test]
    fn test_is_sensitive_proc() {
        assert!(is_sensitive_proc("/proc/kcore"));
        assert!(is_sensitive_proc("/proc/kmsg"));
        assert!(is_sensitive_proc("/proc/kallsyms"));
        assert!(is_sensitive_proc("/proc/keys"));
        assert!(is_sensitive_proc("/proc/key-users"));
        assert!(is_sensitive_proc("/proc/sysrq-trigger"));
        assert!(is_sensitive_proc("/sys/firmware"));
        assert!(is_sensitive_proc("/sys/firmware/efi"));
        assert!(is_sensitive_proc("/sys/kernel/security"));
        assert!(is_sensitive_proc("/sys/kernel/security/apparmor"));

        assert!(!is_sensitive_proc("/proc/cpuinfo"));
        assert!(!is_sensitive_proc("/proc/meminfo"));
        assert!(!is_sensitive_proc("/proc/1/status"));
        assert!(is_sensitive_proc("/sys/class/net"));
        assert!(is_sensitive_proc("/sys/class/net/eth0"));
    }

    #[test]
    fn test_extract_proc_pid() {
        assert_eq!(extract_proc_pid("/proc/123/cmdline"), Some(123));
        assert_eq!(extract_proc_pid("/proc/1/status"), Some(1));
        assert_eq!(extract_proc_pid("/proc/99999/fd"), Some(99999));
        assert_eq!(extract_proc_pid("/proc/self/status"), None);
        assert_eq!(extract_proc_pid("/proc/cpuinfo"), None);
        assert_eq!(extract_proc_pid("/proc/meminfo"), None);
        assert_eq!(extract_proc_pid("/proc/net/tcp"), None);
        assert_eq!(extract_proc_pid("/etc/group"), None);
        assert_eq!(extract_proc_pid("/proc/"), None);
    }

    #[test]
    fn test_generate_cpuinfo_single() {
        let info = generate_cpuinfo(1);
        let text = String::from_utf8(info).unwrap();
        assert!(text.contains("processor\t: 0"));
        assert!(text.contains("model name\t: Virtual CPU"));
        assert!(text.contains("cpu MHz\t\t: 2400.000"));
        assert!(!text.contains("processor\t: 1"));
    }

    #[test]
    fn test_generate_cpuinfo_multiple() {
        let info = generate_cpuinfo(4);
        let text = String::from_utf8(info).unwrap();
        assert!(text.contains("processor\t: 0"));
        assert!(text.contains("processor\t: 1"));
        assert!(text.contains("processor\t: 2"));
        assert!(text.contains("processor\t: 3"));
        assert!(!text.contains("processor\t: 4"));
    }

    #[test]
    fn test_generate_meminfo() {
        // 1 GiB total, 256 MiB used
        let total = 1024 * 1024 * 1024u64;
        let used = 256 * 1024 * 1024u64;
        let info = generate_meminfo(total, used);
        let text = String::from_utf8(info).unwrap();

        let total_kb = total / 1024;
        let used_kb = used / 1024;
        let free_kb = total_kb - used_kb;

        assert!(text.contains(&format!("MemTotal:       {} kB", total_kb)));
        assert!(text.contains(&format!("MemFree:        {} kB", free_kb)));
        assert!(text.contains(&format!("MemAvailable:   {} kB", free_kb)));
    }

    #[test]
    fn test_generate_meminfo_zero_used() {
        let total = 512 * 1024 * 1024u64;
        let info = generate_meminfo(total, 0);
        let text = String::from_utf8(info).unwrap();
        let total_kb = total / 1024;
        assert!(text.contains(&format!("MemTotal:       {} kB", total_kb)));
        assert!(text.contains(&format!("MemFree:        {} kB", total_kb)));
    }

    #[test]
    fn test_generate_meminfo_over_used() {
        // used > total should clamp
        let total = 100 * 1024u64;
        let used = 200 * 1024u64;
        let info = generate_meminfo(total, used);
        let text = String::from_utf8(info).unwrap();
        // Free should be 0 (saturating sub)
        assert!(text.contains("MemFree:        0 kB"));
    }

    #[test]
    fn test_generate_uptime() {
        let info = generate_uptime(123.456);
        let text = String::from_utf8(info).unwrap();
        assert!(text.starts_with("123.46"));
        assert!(text.contains("0.00"));
    }

    #[test]
    fn test_generate_uptime_zero() {
        let info = generate_uptime(0.0);
        let text = String::from_utf8(info).unwrap();
        assert!(text.starts_with("0.00"));
    }

    #[test]
    fn test_generate_uptime_negative_clamped() {
        let info = generate_uptime(-5.0);
        let text = String::from_utf8(info).unwrap();
        assert!(text.starts_with("0.00"));
    }

    #[test]
    fn test_loadavg_ewma() {
        let mut la = LoadAvg::new();
        assert_eq!(la.avg_1, 0.0);
        assert_eq!(la.avg_5, 0.0);
        assert_eq!(la.avg_15, 0.0);

        // After sampling with 4 running processes, averages should rise
        for _ in 0..12 {
            la.sample(4);
        }
        // 1-min average should converge faster than 5 and 15
        assert!(la.avg_1 > la.avg_5);
        assert!(la.avg_5 > la.avg_15);
        assert!(la.avg_1 > 2.0); // should be well above 0 after 60s of load=4
    }

    #[test]
    fn test_loadavg_ewma_decay() {
        let mut la = LoadAvg::new();
        // Load up
        for _ in 0..60 {
            la.sample(10);
        }
        let peak = la.avg_1;
        // Load drops to 0
        for _ in 0..60 {
            la.sample(0);
        }
        assert!(la.avg_1 < peak * 0.1, "1-min avg should decay quickly");
    }

    #[test]
    fn test_generate_loadavg() {
        let la = LoadAvg { avg_1: 1.23, avg_5: 0.45, avg_15: 0.12 };
        let info = generate_loadavg(&la, 3, 10, 42);
        let text = String::from_utf8(info).unwrap();
        assert!(text.contains("1.23"));
        assert!(text.contains("0.45"));
        assert!(text.contains("0.12"));
        assert!(text.contains("3/10"));
        assert!(text.contains("42"));
    }

    #[test]
    fn test_generate_loadavg_zero_procs() {
        let la = LoadAvg::new();
        let info = generate_loadavg(&la, 0, 0, 0);
        let text = String::from_utf8(info).unwrap();
        // running should be clamped: max(0,1).min(0) = 0
        assert!(text.contains("0/0"));
    }

    #[test]
    fn test_detect_fstype_root() {
        // / should always return a known fstype
        let fstype = detect_fstype(std::path::Path::new("/"));
        assert_ne!(fstype, "unknown", "root fs should have a known type");
    }

    #[test]
    fn test_detect_fstype_nonexistent() {
        let fstype = detect_fstype(std::path::Path::new("/no/such/path"));
        assert_eq!(fstype, "unknown");
    }

    #[test]
    fn test_generate_proc_mounts_chroot() {
        // Use real paths so detect_fstype works
        let tmp = std::env::temp_dir();
        let mounts = vec![
            (std::path::PathBuf::from("/work"), tmp.clone()),
            (std::path::PathBuf::from("/data"), tmp.clone()),
        ];
        let ro = vec![std::path::PathBuf::from("/data")];
        let content = generate_proc_mounts(Some(tmp.as_path()), &mounts, &ro, false);
        let text = String::from_utf8(content).unwrap();
        // Root entry with detected fstype (not hardcoded ext4)
        assert!(text.starts_with("sandlock / "), "Should start with root entry, got: {}", text);
        assert!(text.contains("sandlock /work "));
        assert!(text.contains("sandlock /data "));
        // Should NOT contain host paths
        assert!(!text.contains(tmp.to_str().unwrap()));
        // Fstype should be detected, not "unknown" (tmp is on a real fs)
        let root_line = text.lines().next().unwrap();
        assert!(!root_line.contains("unknown"), "root fstype should be detected, got: {}", root_line);
        // Options reflect read-only: /data is ro, /work and root are rw.
        assert!(text.lines().any(|l| l.starts_with("sandlock / ") && l.contains(" rw,relatime ")));
        assert!(text.lines().any(|l| l.starts_with("sandlock /work ") && l.contains(" rw,relatime ")));
        assert!(text.lines().any(|l| l.starts_with("sandlock /data ") && l.contains(" ro,relatime ")));
    }

    #[test]
    fn test_generate_proc_mounts_read_only_root() {
        let tmp = std::env::temp_dir();
        let content = generate_proc_mounts(Some(tmp.as_path()), &[], &[], true);
        let text = String::from_utf8(content).unwrap();
        assert!(text.lines().next().unwrap().contains(" ro,relatime "), "got: {}", text);
    }

    #[test]
    fn test_generate_proc_mounts_no_chroot() {
        let mounts: Vec<(std::path::PathBuf, std::path::PathBuf)> = vec![];
        let content = generate_proc_mounts(None, &mounts, &[], false);
        let text = String::from_utf8(content).unwrap();
        assert!(text.contains("rootfs / rootfs rw 0 0"));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn test_generate_proc_mountinfo_chroot() {
        let tmp = std::env::temp_dir();
        let mounts = vec![
            (std::path::PathBuf::from("/work"), tmp.clone()),
        ];
        let content = generate_proc_mountinfo(Some(tmp.as_path()), &mounts, &[], false);
        let text = String::from_utf8(content).unwrap();
        assert!(text.contains("/ / rw,relatime -"));
        assert!(text.contains("/ /work rw,relatime -"));
        assert!(!text.contains(tmp.to_str().unwrap()));
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn test_generate_proc_mountinfo_no_chroot() {
        let mounts: Vec<(std::path::PathBuf, std::path::PathBuf)> = vec![];
        let content = generate_proc_mountinfo(None, &mounts, &[], false);
        let text = String::from_utf8(content).unwrap();
        assert!(text.contains("/ / rw - rootfs rootfs rw"));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn test_build_dirent64() {
        let entry = build_dirent64(12345, 1, DT_DIR, "1234").unwrap();
        assert_eq!(entry.len(), 24); // 19 + 5 = 24, already aligned
        let d_ino = u64::from_ne_bytes(entry[0..8].try_into().unwrap());
        assert_eq!(d_ino, 12345);
        let d_reclen = u16::from_ne_bytes(entry[16..18].try_into().unwrap());
        assert_eq!(d_reclen, 24);
        assert_eq!(entry[18], DT_DIR);
        assert_eq!(&entry[19..23], b"1234");
        assert_eq!(entry[23], 0);
    }

    #[test]
    fn test_build_dirent64_alignment() {
        let entry = build_dirent64(1, 1, DT_REG, "ab").unwrap();
        // 19 + 3 = 22, padded to 24
        assert_eq!(entry.len(), 24);
    }

    #[test]
    fn test_build_dirent64_rejects_oversize_name() {
        let name = "x".repeat(256);
        assert!(build_dirent64(1, 1, DT_REG, &name).is_none());
    }

    #[test]
    fn test_build_filtered_dirents() {
        use std::collections::HashSet;
        let mut sandbox_pids = HashSet::new();
        sandbox_pids.insert(1_i32);
        let entries = build_filtered_dirents(&sandbox_pids);
        assert!(!entries.is_empty());
    }
}
