// Domain-specific state structs — each domain is locked independently so
// handlers only contend on the state they actually need. Per-process
// state is bundled into a single `PerProcessState` owned by
// `ProcessIndex`; cleanup on exit is just dropping the entry's `Arc`.

use std::collections::{HashMap, HashSet};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

/// Resource-limit runtime state shared across notification handlers.
pub struct ResourceState {
    /// Live concurrent process count — incremented on fork, decremented on wait.
    pub proc_count: u32,
    /// Peak concurrent process count observed since sandbox start.
    pub peak_proc_count: u32,
    /// Maximum allowed concurrent processes.
    pub max_processes: u32,
    /// True when the per-child pidfd watcher is the authoritative `proc_count`
    /// releaser: every counted fork child is birth-registered (argv-safety
    /// mode), its exit releases the slot exactly once, and blocking wait4
    /// notifications must NOT decrement (`handle_wait` is an idempotent
    /// no-op). False in lazy mode, where watcher coverage is incomplete and a
    /// reaping wait4 remains the only release for watcher-less children.
    pub pidfd_release_authoritative: bool,
    /// Estimated anonymous memory usage (bytes).
    pub mem_used: u64,
    /// Peak anonymous memory usage observed since sandbox start (bytes).
    pub peak_mem_used: u64,
    /// Maximum allowed anonymous memory (bytes).
    pub max_memory_bytes: u64,
    /// Whether fork notifications should be held (checkpoint/freeze).
    pub hold_forks: bool,
    /// Notification IDs held during a checkpoint freeze.
    ///
    /// `NotifAction::Hold` deliberately does not answer the notification, so
    /// the sandboxed `fork()` stays parked in the kernel. Whoever ends the
    /// freeze therefore has to *answer* these ids (see
    /// [`crate::resource::release_held_forks`]) -- dropping the list instead
    /// leaves each of those processes blocked in `fork()` forever, with no
    /// error anywhere.
    pub held_notif_ids: Vec<u64>,
    /// The supervisor's seccomp notification fd, published by the notify loop
    /// so the held ids can be answered from outside it. `-1` until then.
    pub notif_fd: RawFd,
    /// Exponentially-weighted load average.
    pub load_avg: crate::procfs::LoadAvg,
    /// Instant when the supervisor started (for uptime reporting).
    pub start_instant: std::time::Instant,
}

impl ResourceState {
    /// Create a new resource state with the given limits.
    pub fn new(max_memory_bytes: u64, max_processes: u32) -> Self {
        Self {
            proc_count: 0,
            peak_proc_count: 1, // root process always exists; handle_fork counts children only
            max_processes,
            pidfd_release_authoritative: false,
            mem_used: 0,
            peak_mem_used: 0,
            max_memory_bytes,
            hold_forks: false,
            held_notif_ids: Vec::new(),
            notif_fd: -1,
            load_avg: crate::procfs::LoadAvg::new(),
            start_instant: std::time::Instant::now(),
        }
    }
}

// ============================================================
// ProcfsState — /proc virtualization state
// ============================================================

/// /proc virtualization runtime state. Per-notification process state
/// lives in `ProcessIndex`; per-process getdents caches live in
/// `PerProcessState::procfs_dir_cache`. This struct only holds truly
/// global virtualization state.
pub struct ProcfsState {
    /// Base address of the last vDSO we patched (0 = not yet patched).
    pub vdso_patched_addr: u64,
}

impl ProcfsState {
    pub fn new() -> Self {
        Self {
            vdso_patched_addr: 0,
        }
    }
}

// ============================================================
// PidKey — stable per-process identity
// ============================================================

/// Stable process identity. Numeric pid plus the start_time that
/// distinguishes a specific process instance from any future recycle
/// of the same pid slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PidKey {
    /// Numeric PID observed by seccomp notification.
    pub pid: i32,
    /// Process start time from /proc/<pid>/stat field 22.
    pub start_time: u64,
}

/// Read the thread-group leader pid (TGID) containing `tid` from
/// `/proc/<tid>/status`. `None` when the task is gone or /proc is
/// unreadable; callers decide what that means for them.
pub(crate) fn read_tgid_of_tid(tid: i32) -> Option<i32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", tid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Read the parent pid (field 4 of `/proc/<pid>/stat`) for `pid`.
/// `None` when the task is gone or /proc is unreadable.
pub(crate) fn read_ppid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Skip past "pid (comm)": comm may contain spaces and parens, but the
    // last ") " in the line ends it. The first token after it is the state,
    // and the parent pid follows.
    let rest = stat.rsplit_once(") ")?.1;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Read the process start time (field 22 of /proc/<pid>/stat) for `pid`.
/// Returns None if the process is gone or /proc is not readable.
pub(crate) fn read_pid_start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Skip past "pid (comm)" — comm may contain spaces and parens, but the
    // last ") " in the line ends the comm field.
    let rest = stat.rsplit_once(") ")?.1;
    // The first token after "(comm) " is field 3; field 22 is therefore nth(19).
    rest.split_whitespace().nth(19)?.parse().ok()
}

// ============================================================
// PerProcessState — bundled per-process supervisor state
// ============================================================

/// All per-process supervisor state for one tracked child. One
/// instance lives per `PidKey`, owned by `ProcessIndex` behind an
/// `Arc<AsyncMutex<…>>`. Cleanup on process exit is one operation:
/// `ProcessIndex::unregister` drops the index's `Arc`, and the
/// supervisor's per-handler clones drop along with their tasks.
#[derive(Default)]
pub struct PerProcessState {
    /// Logical cwd while the process is chdir'd into a COW-only
    /// directory. None means "use kernel-reported cwd".
    pub virtual_cwd: Option<String>,
    /// Recorded brk base for memory accounting. None until first brk.
    pub brk_base: Option<u64>,
    /// Anonymous memory (bytes) charged to this address space and not
    /// yet credited back. Only the thread-group leader's entry carries a
    /// charge: threads share one address space, so all accounting for a
    /// task is routed to its leader via [`ProcessIndex::addr_space_state`].
    /// Credited back to the global total when the address space goes away
    /// (exec replaces it, or the process exits).
    pub mem_charged: u64,
    /// COW directory dirent cache. Keyed by child's fd; value is
    /// (host target path, sorted dirent bytes left to return).
    /// Entries are invalidated when the fd is reused for a different
    /// directory.
    pub cow_dir_cache: HashMap<u32, (String, Vec<Vec<u8>>)>,
    /// /proc directory dirent cache. Keyed by (child fd, target
    /// path); same drain-on-EOF semantics as cow_dir_cache.
    pub procfs_dir_cache: HashMap<(u32, String), Vec<Vec<u8>>>,
}

// ============================================================
// ProcessIndex — tracked processes + per-process state
// ============================================================

/// Registry for tracked sandbox processes plus their per-process
/// supervisor state.
///
/// In the default supervisor this is populated lazily from seccomp
/// notifications. When `policy_fn` is active, fork-like syscalls are
/// additionally traced for one ptrace creation event so children are
/// inserted here before they can run user code; this makes the index
/// complete for argv-safety freezes.
///
/// The runtime keeps **one entry per thread group (TGID)**, keyed by the
/// thread-group leader's pid (F12): a notification from any thread resolves
/// to its leader's key and state via [`ProcessIndex::key_for`] /
/// [`ProcessIndex::entry_for`] / [`ProcessIndex::addr_space_state`] /
/// [`ProcessIndex::contains`], so the raw key set is also the raw TGID set.
/// There are no per-tid entries, no per-thread watchers, and every
/// enumeration point (`pids_snapshot`, `dead_keys`, `len`) counts process
/// groups rather than threads. (`register` still accepts a tid when a caller
/// deliberately constructs a defensive shape — e.g. freeze's duplicate-key
/// unit test — but the notification path never does.)
///
/// Maps the kernel's numeric `pid` (the value that arrives in seccomp
/// notifications) to the canonical `PidKey` plus an
/// `Arc<AsyncMutex<PerProcessState>>` holding everything per-process.
/// Held behind an internal `std::sync::RwLock` so the read-mostly hot
/// paths (`key_for`, `contains`, `entry_for`, `/proc` virtualization)
/// avoid an async mutex on every notification, and so `ProcessIndex`
/// doesn't need its own outer wrapper in `SupervisorCtx`. Lock guards
/// are `!Send` and the compiler will reject holding one across an
/// `.await`, which keeps callers honest.
///
/// Ownership of each child's pidfd lives with the per-child watcher
/// task, not with this index. That keeps the kernel fd alive for as
/// long as the `AsyncFd` registration in the tokio IO driver does,
/// and avoids a race where dropping the fd from the index could
/// deregister a recycled fd from epoll.
pub struct ProcessIndex {
    inner: std::sync::RwLock<HashMap<i32, ProcessEntry>>,
}

/// A task's current directory as the sandbox believes it to be: the
/// path `getcwd` should report, in whatever namespace the child sees
/// (the virtual path under chroot, the real path otherwise).
///
/// `None` means the task has never moved, so the kernel's own cwd is
/// still authoritative. Shared behind an `Arc` the way the kernel
/// shares `fs_struct`, so a chdir in one thread is seen by its
/// siblings. Kept outside `PerProcessState` (and behind a std mutex)
/// because path resolution reads it from synchronous helpers.
pub type SharedCwd = Arc<std::sync::Mutex<Option<PathBuf>>>;

#[derive(Clone)]
struct ProcessEntry {
    key: PidKey,
    /// Thread-group leader of this task; equals `key.pid` for a
    /// single-threaded process. Read once at registration and kept
    /// outside the async mutex so address-space lookups need only the
    /// index's read lock.
    tgid: i32,
    /// Exit-release bookkeeping for this process slot (see `ProcessRelease`).
    release: Arc<ProcessRelease>,
    state: Arc<AsyncMutex<PerProcessState>>,
    cwd: SharedCwd,
}

/// Per-entry bookkeeping for the exactly-once `proc_count` release.
///
/// In argv-safety mode every counted fork child is registered (and given a
/// pidfd watcher) at birth, before it can run user code. The watcher's exit
/// cleanup owns that child's release: `counted` records that the slot was
/// fork-counted, and `released` is the one-shot latch that keeps duplicate
/// exit observations (watcher + periodic GC, watcher + a stale duplicate
/// readiness event, or a re-registration race) from releasing the same child
/// twice.
#[derive(Default)]
pub(crate) struct ProcessRelease {
    /// True when this entry was birth-registered as a fork-counted child, so
    /// its pidfd watcher owns the `proc_count` release on exit.
    pub counted: bool,
    /// One-shot latch: set by whichever cleanup first performs the release.
    pub released: std::sync::atomic::AtomicBool,
}

/// Resolve the registry entry for a raw notification pid.
///
/// A pid that is itself a key always wins (defensive shapes can still
/// register a tid directly). Otherwise a non-leader thread resolves to its
/// thread-group leader's entry — the runtime registers one entry per TGID
/// under the leader's pid (F12) — so every lookup from any thread of a
/// tracked process lands on the same key/state. Returns `None` for a
/// completely unknown pid or an unreadable `/proc/<pid>/status`.
fn entry_for_raw(map: &HashMap<i32, ProcessEntry>, pid: i32) -> Option<&ProcessEntry> {
    if let Some(entry) = map.get(&pid) {
        return Some(entry);
    }
    let tgid = read_tgid_of_tid(pid)?;
    if tgid == pid {
        return None;
    }
    map.get(&tgid)
}

impl ProcessIndex {
    pub fn new() -> Self {
        Self {
            inner: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Register a process with a non-counted slot (root and lazy
    /// registrations; the release, if any, happens on the wait4 side).
    ///
    /// The runtime notification path (`register_pid_if_new`) only ever
    /// passes thread-group leaders here (F12); the generic form remains for
    /// defensive/unit-test shapes that register a tid directly.
    pub fn register(&self, pid: i32) -> Option<PidKey> {
        self.register_with(pid, false)
    }

    /// Register a birth-tracked, fork-counted child whose pidfd watcher owns
    /// the exactly-once `proc_count` release on exit. Used by the argv-safety
    /// ptrace fork-event path, where every counted child (always a new TGID
    /// leader — `CLONE_THREAD` births are never counted) is registered
    /// before it can run user code.
    pub(crate) fn register_counted(&self, pid: i32) -> Option<PidKey> {
        self.register_with(pid, true)
    }

    /// Register a process by reading its start_time once and allocating its
    /// `PerProcessState`. Returns the canonical key, or None if the process is
    /// already gone. The caller is responsible for keeping the pidfd alive —
    /// the per-child watcher task does this via `AsyncFd<OwnedFd>`.
    fn register_with(&self, pid: i32, counted: bool) -> Option<PidKey> {
        let start_time = read_pid_start_time(pid)?;
        let key = PidKey { pid, start_time };
        let tgid = read_tgid_of_tid(pid).unwrap_or(pid);
        let entry = ProcessEntry {
            key,
            tgid,
            release: Arc::new(ProcessRelease {
                counted,
                released: std::sync::atomic::AtomicBool::new(false),
            }),
            state: Arc::new(AsyncMutex::new(PerProcessState::default())),
            cwd: self.inherited_cwd(pid, tgid),
        };
        self.inner.write().ok()?.insert(pid, entry);
        Some(key)
    }

    /// The cwd cell a task starts life with.
    ///
    /// A thread joins its leader's cell, because the kernel hands
    /// pthreads a shared `fs_struct` and one thread's chdir moves its
    /// siblings. Anything else copies the parent's current value, which
    /// is what `fork(2)` does. Thread-group membership stands in for
    /// `CLONE_FS` here, the same approximation `addr_space_state` makes
    /// for `CLONE_VM`: a bare `clone(CLONE_FS)` without `CLONE_THREAD`
    /// gets a private copy instead of sharing. An untracked parent
    /// leaves the child at None, which falls back to the kernel's cwd.
    fn inherited_cwd(&self, pid: i32, tgid: i32) -> SharedCwd {
        let ppid = if tgid == pid { read_ppid(pid) } else { None };
        let Ok(guard) = self.inner.read() else {
            return SharedCwd::default();
        };
        if tgid != pid {
            if let Some(leader) = guard.get(&tgid) {
                return Arc::clone(&leader.cwd);
            }
        }
        let parent_cwd = ppid
            .and_then(|p| guard.get(&p))
            .and_then(|e| e.cwd.lock().ok().and_then(|c| c.clone()));
        Arc::new(std::sync::Mutex::new(parent_cwd))
    }

    /// The cwd cell to read or write for `pid`.
    ///
    /// A task without an entry of its own falls back to its
    /// thread-group leader: the runtime registers one entry per TGID under
    /// the leader's pid, so a thread's tid is never a key of its own (F12).
    /// Since threads share one `fs_struct`, the leader's cell is the correct
    /// answer for them, not an approximation. Only that miss pays for the
    /// extra /proc read.
    fn cwd_cell(&self, pid: i32) -> Option<SharedCwd> {
        if let Ok(guard) = self.inner.read() {
            if let Some(entry) = guard.get(&pid) {
                return Some(Arc::clone(&entry.cwd));
            }
        }
        let tgid = read_tgid_of_tid(pid)?;
        if tgid == pid {
            return None;
        }
        let guard = self.inner.read().ok()?;
        guard.get(&tgid).map(|e| Arc::clone(&e.cwd))
    }

    /// The cwd this task believes it is in, or None when the task is
    /// untracked or has never moved.
    pub fn virtual_cwd(&self, pid: i32) -> Option<PathBuf> {
        let cell = self.cwd_cell(pid)?;
        let cwd = cell.lock().ok()?.clone();
        cwd
    }

    /// Record where this task now believes it is. Silently does nothing
    /// for an untracked pid: the fallback is the kernel's own cwd.
    ///
    /// Every caller writes a path the *request* named, never a host path
    /// mapped back through the mount table: one host directory can be mounted
    /// at several virtual paths (E2B's `/workspace` and `/home/user` are the
    /// same directory), so a reverse lookup has no single right answer and
    /// picking one makes every later relative path resolve against the wrong
    /// alias. The seeded callers are `handle_chroot_chdir` (the chdir the
    /// child asked for) and the exec announcement in
    /// `SandboxInstance::exec_with_fds_inner` (the request's `cwd`), which
    /// exists because a child that never re-derives its cwd must not depend on
    /// the kernel's `/proc/<pid>/cwd` — that one still points at the launch
    /// directory, since the supervisor services chdir by recording it.
    pub fn set_virtual_cwd(&self, pid: i32, cwd: PathBuf) {
        if let Some(cell) = self.cwd_cell(pid) {
            if let Ok(mut slot) = cell.lock() {
                *slot = Some(cwd);
            }
        }
    }

    /// Look up the canonical PidKey for a notification's raw pid.
    /// An unregistered non-leader thread resolves to its thread-group
    /// leader's key (F12). Returns None only for a pid whose thread group
    /// was never registered — callers should fall back to a no-op.
    pub fn key_for(&self, pid: i32) -> Option<PidKey> {
        let guard = self.inner.read().ok()?;
        entry_for_raw(&guard, pid).map(|e| e.key)
    }

    /// Look up both the PidKey and the per-process state handle for
    /// `pid`. An unregistered non-leader thread resolves to its thread-group
    /// leader's entry (F12), so threads share one state handle with the
    /// leader. Returns None if the pid's thread group isn't tracked. The
    /// caller locks the returned `Arc<AsyncMutex<…>>` to read or mutate.
    pub fn entry_for(&self, pid: i32) -> Option<(PidKey, Arc<AsyncMutex<PerProcessState>>)> {
        let guard = self.inner.read().ok()?;
        entry_for_raw(&guard, pid).map(|e| (e.key, Arc::clone(&e.state)))
    }

    /// Per-process state plus the exit-release slot, for the pidfd-watcher /
    /// GC cleanup path. Returns None if the pid isn't tracked.
    ///
    /// Cleanup always runs against an exact map key (the leader's pid in the
    /// runtime shape), so this deliberately does **not** resolve threads to
    /// leaders: a watcher key and the entry it cleans up must be the same
    /// key, or a recycled-pid guard could release the wrong slot.
    pub(crate) fn entry_for_cleanup(
        &self,
        pid: i32,
    ) -> Option<(
        PidKey,
        Arc<AsyncMutex<PerProcessState>>,
        Arc<ProcessRelease>,
    )> {
        self.inner
            .read()
            .ok()?
            .get(&pid)
            .map(|e| (e.key, Arc::clone(&e.state), Arc::clone(&e.release)))
    }

    /// Per-address-space state for `pid`: the thread-group leader's
    /// entry when `pid` is a thread, otherwise its own. Memory
    /// accounting keys off this because threads share one address
    /// space — charging each thread separately would let every thread's
    /// first brk go free and would credit a live heap back when one
    /// thread exits. Falls back to the task's own entry when the leader
    /// is untracked. With the runtime's leader-only registration (F12), an
    /// unregistered tid resolves through `/proc/<tid>/status` to its
    /// leader's entry; the task's own entry fallback only applies to
    /// defensive shapes that register a tid directly.
    pub fn addr_space_state(&self, pid: i32) -> Option<Arc<AsyncMutex<PerProcessState>>> {
        let guard = self.inner.read().ok()?;
        match guard.get(&pid) {
            Some(entry) => {
                if entry.tgid != pid {
                    if let Some(leader) = guard.get(&entry.tgid) {
                        return Some(Arc::clone(&leader.state));
                    }
                }
                Some(Arc::clone(&entry.state))
            }
            None => {
                let tgid = read_tgid_of_tid(pid)?;
                if tgid == pid {
                    return None;
                }
                guard.get(&tgid).map(|e| Arc::clone(&e.state))
            }
        }
    }

    /// Tracked-process test — used by /proc virtualization to gate access
    /// to `/proc/<pid>/...` paths and by getdents filtering.
    ///
    /// A non-leader thread of a tracked TGID counts as tracked (it resolves
    /// to its leader), so a sandbox process's threads stay visible and
    /// readable in its virtualized `/proc` exactly like on kernels where
    /// threads could never be registered (F12). Only a pid whose whole
    /// thread group is untracked (or unreadable /proc) returns false.
    pub fn contains(&self, pid: i32) -> bool {
        self.inner
            .read()
            .map(|g| entry_for_raw(&g, pid).is_some())
            .unwrap_or(false)
    }

    /// Number of tracked processes (for /proc/loadavg total).
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Largest tracked pid (for /proc/loadavg last_pid).
    pub fn max_pid(&self) -> Option<i32> {
        self.inner.read().ok()?.keys().copied().max()
    }

    /// Snapshot the set of tracked pids. Used by getdents filtering
    /// where the caller needs O(1) lookups inside a loop and would
    /// otherwise have to re-acquire the read lock per entry.
    pub fn pids_snapshot(&self) -> HashSet<i32> {
        self.inner
            .read()
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Remove a process from the index. The per-process state's
    /// `Arc` reference held by the index drops here; remaining clones
    /// (e.g. a handler that's mid-execution for that pid) will drop
    /// when they go out of scope, and the inner `PerProcessState`
    /// frees automatically.
    pub fn unregister(&self, key: PidKey) {
        if let Ok(mut g) = self.inner.write() {
            // Only clear if the entry still points at this key. A PID
            // recycled with a fresh start_time may already have
            // overwritten the entry via register(); we must not stomp it.
            if g.get(&key.pid).map(|e| e.key) == Some(key) {
                g.remove(&key.pid);
            }
        }
    }

    /// Defensive sweep: drop entries whose process is gone (or whose
    /// start_time has changed). Called from a low-frequency backstop
    /// task in case a pidfd watcher failed to spawn or the kernel
    /// didn't deliver the readability event.
    pub fn prune_dead(&self) {
        for key in self.dead_keys() {
            self.unregister(key);
        }
    }

    /// Snapshot the keys whose process is gone (or whose start_time has
    /// changed, i.e. the pid was recycled). The backstop task runs the full
    /// `cleanup_pid` on each so the exactly-once release latch still fires for
    /// counted children whose watcher missed the exit.
    pub(crate) fn dead_keys(&self) -> Vec<PidKey> {
        let candidates: Vec<(i32, PidKey)> = match self.inner.read() {
            Ok(g) => g.iter().map(|(p, e)| (*p, e.key)).collect(),
            Err(_) => return Vec::new(),
        };
        let mut dead = Vec::new();
        for (pid, key) in candidates {
            match read_pid_start_time(pid) {
                Some(st) if st == key.start_time => continue,
                _ => dead.push(key),
            }
        }
        dead
    }
}

impl Default for ProcessIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// CowState — copy-on-write filesystem state (global only)
// ============================================================

/// Global COW state. Per-process COW state (virtual cwd, dir cache)
/// lives in `PerProcessState`.
pub struct CowState {
    /// Seccomp-based COW branch (None if COW disabled).
    pub branch: Option<crate::cow::seccomp::SeccompCowBranch>,
}

impl CowState {
    pub fn new() -> Self {
        Self { branch: None }
    }
}

// ============================================================
// NetworkState — network policy and port remapping state
// ============================================================

/// Network policy and port-remapping state. Holds one
/// `NetworkPolicy` per L4 protocol — the on-behalf handler picks the
/// matching one based on the dup'd fd's `SO_PROTOCOL`.
pub struct NetworkState {
    /// Allowlist for TCP destinations (`tcp://...` and bare-form rules;
    /// bare specs expand to a TCP + UDP pair at parse time).
    pub tcp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Allowlist for UDP destinations (`udp://...` and bare-form rules).
    pub udp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Allowlist for ICMP destinations (`icmp://...` rules). ICMP rules
    /// carry no ports, so every entry uses `PortAllow::Any` and the
    /// effective check is IP-only.
    pub icmp_policy: crate::seccomp::notif::NetworkPolicy,
    /// The sandbox's live policy handle — the instance-wide narrowing channel
    /// (end-state B). It is shared with [`crate::seccomp::state::PolicyFnState`]
    /// when a `policy_fn` callback is configured, so there is exactly one
    /// handle: the session `update_network` verb writes
    /// [`crate::policy_fn::LivePolicy::narrowed_ips`] into it (effective for
    /// every process at once), and the callback writes `allowed_ips` through
    /// its own [`crate::policy_fn::PolicyContext`]. A bare `NetworkState`
    /// (tests) owns an unseeded handle: no narrowing, no replacement set.
    pub live_policy: std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>,
    /// Port binding and remapping tracker.
    pub port_map: crate::port_remap::PortMap,
    /// `--net-deny-bind`: TCP ports the sandbox may NOT bind (default-allow
    /// denylist). The on-behalf `bind()` handler rejects a TCP bind to any
    /// port in this set with `EACCES`; empty = no bind denylist.
    pub bind_deny_ports: HashSet<u16>,
    /// Per-PID network overrides from policy_fn (IP-only via the legacy
    /// `restrict_network(ips)` API; any port is permitted to listed IPs).
    pub pid_ip_overrides: std::sync::Arc<std::sync::RwLock<HashMap<u32, HashSet<std::net::IpAddr>>>>,
    /// HTTP ACL proxy address (None if HTTP ACL not active).
    pub http_acl_addr: Option<std::net::SocketAddr>,
    /// TCP ports to intercept and redirect to the HTTP ACL proxy.
    pub http_acl_ports: HashSet<u16>,
    /// Shared map for recording original destination IPs on proxy redirect.
    pub http_acl_orig_dest: Option<crate::transparent_proxy::OrigDestMap>,
    /// Hostname ↔ synthetic-IP mapping for wildcard-domain rules. Populated
    /// by the sandbox's DNS path; the connect handler reverse-looks a
    /// synthetic destination here before matching wildcard rules.
    pub synthetic_dns: crate::network::dns_synth::SyntheticDns,
    /// The sandbox's DNS gateway endpoint (`<gateway>:53`) — a per-sandbox
    /// `127.0.1.x` loopback address. The send/connect verdicts exempt exactly
    /// this endpoint so the sandbox can resolve names through its own
    /// gateway without opening the rest of loopback.
    pub dns_gateway_addr: Option<std::net::SocketAddr>,
    /// SOCKS5 egress proxy (Block C): when set, every TCP connect that passes
    /// the destination filter is tunneled through this upstream instead of
    /// being dialed directly. UDP/ICMP are not tunneled. The endpoint itself
    /// is dialed by the supervisor and is never added to the sandbox's
    /// allowlist, so the sandbox cannot reach the proxy directly.
    pub egress_proxy: Option<crate::network::egress::EgressProxy>,
    /// S2.5 configured inbound port mapping: `sandbox_port -> host_port`
    /// (from `net_bind_map(host_port, sandbox_port)`). The host listener for
    /// a mapped sandbox port is created when the sandbox `listen()`s on it.
    pub inbound_map: HashMap<u16, u16>,
    /// S2.5 live host-side inbound listeners, keyed by the sandbox listening
    /// socket's inode (stable across fork/dup of the listening fd). Dropping
    /// an entry closes the host listener, which happens on sandbox teardown
    /// (`NetworkState` drop) or when a later socket listens on the same mapped
    /// port and replaces it (N88 ②(a); `close` no longer tears it down, so
    /// every use re-validates the entry against the live socket — see
    /// `network::inbound`).
    pub inbound: HashMap<u64, crate::network::inbound::InboundListener>,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            tcp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            udp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            icmp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            live_policy: std::sync::Arc::new(std::sync::RwLock::new(
                crate::policy_fn::LivePolicy {
                    allowed_ips: HashSet::new(),
                    narrowed_ips: None,
                    max_memory_bytes: 0,
                    max_processes: 0,
                },
            )),
            port_map: crate::port_remap::PortMap::new(),
            bind_deny_ports: HashSet::new(),
            pid_ip_overrides: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            http_acl_addr: None,
            http_acl_ports: HashSet::new(),
            http_acl_orig_dest: None,
            synthetic_dns: crate::network::dns_synth::SyntheticDns::new(),
            dns_gateway_addr: None,
            egress_proxy: None,
            inbound_map: HashMap::new(),
            inbound: HashMap::new(),
        }
    }

    /// True when `(ip, port)` is this sandbox's own DNS gateway endpoint,
    /// which must be reachable regardless of the network allowlist so the
    /// sandbox can resolve names through the gateway.
    pub fn is_dns_gateway_dest(&self, ip: std::net::IpAddr, port: Option<u16>) -> bool {
        match self.dns_gateway_addr {
            Some(a) => a.ip() == ip && port == Some(a.port()),
            None => false,
        }
    }

    /// Get the effective network policy for a PID and protocol.
    ///
    /// The verdict depends only on the sandbox's **current** network policy —
    /// never on which exec session a process belongs to (end-state B: no
    /// per-pid / per-pgid / ancestor attribution exists). Priority:
    ///
    /// 1. a per-PID override registered for `pid` (`policy_fn`'s legacy
    ///    `restrict_pid_network`) — IP-only, any port, across all protocols,
    ///    unchanged by this round;
    /// 2. the instance-wide narrowing (`update_network`), composed with the
    ///    per-protocol static ceiling so it can never widen;
    /// 3. the live replacement set of an active `policy_fn` callback, else
    ///    the static per-protocol policy.
    ///
    /// `live_policy` is the caller's handle on the sandbox's live policy
    /// (`None` = use this state's own handle, which is the same object in a
    /// running sandbox — see [`NetworkState::live_policy`]).
    pub fn effective_network_policy(
        &self,
        pid: u32,
        protocol: crate::sandbox::Protocol,
        live_policy: Option<&std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    ) -> crate::seccomp::notif::NetworkPolicy {
        if let Ok(overrides) = self.pid_ip_overrides.read() {
            if let Some(ips) = overrides.get(&pid) {
                return ip_only_allow_policy(ips);
            }
        }
        let live_policy = live_policy.unwrap_or(&self.live_policy);
        let narrowing = live_policy
            .read()
            .ok()
            .and_then(|live| live.narrowed_ips.clone());
        self.apply_live_tightening(
            narrowing.map(|ips| ip_only_allow_policy(&ips)),
            protocol,
            Some(live_policy),
        )
    }

    /// Apply the instance-wide narrowing and the policy-fn live replacement
    /// on top of the static per-protocol policy: the effective allow set is
    /// the intersection (deny wins).
    ///
    /// `binding` is the session `update_network` narrowing as an IP-any-port
    /// allowlist (or `None` when the sandbox is not narrowed). It is composed
    /// with the protocol's static ceiling ([`intersect_ceiling_grant`]), so a
    /// narrowing can never widen a protocol — a request naming an IP the
    /// ceiling does not grant leaves that protocol denying it. The policy-fn
    /// live set (when non-empty) narrows the result further, and `live_policy`
    /// is seeded from the instance ceiling and can only shrink at runtime, so
    /// this never widens the instance policy either.
    fn apply_live_tightening(
        &self,
        binding: Option<crate::seccomp::notif::NetworkPolicy>,
        protocol: crate::sandbox::Protocol,
        live_policy: Option<&std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    ) -> crate::seccomp::notif::NetworkPolicy {
        let Some(bound) = binding else {
            // Not narrowed: the shared live/static instance policy applies.
            return self.live_or_static(protocol, live_policy);
        };
        let Some(lp) = live_policy else {
            return intersect_ceiling_grant(&bound, &self.protocol_ceiling(protocol));
        };
        let Ok(live) = lp.read() else {
            return intersect_ceiling_grant(&bound, &self.protocol_ceiling(protocol));
        };
        let within = intersect_ceiling_grant(&bound, &self.protocol_ceiling(protocol));
        if live.allowed_ips.is_empty() {
            return within;
        }
        let bound_ips = allowlist_any_port_ips(&within);
        let effective: HashSet<std::net::IpAddr> = live
            .allowed_ips
            .iter()
            .copied()
            .filter(|ip| bound_ips.contains(ip))
            .collect();
        ip_only_allow_policy(&effective)
    }

    fn protocol_ceiling(&self, protocol: crate::sandbox::Protocol) -> &crate::seccomp::notif::NetworkPolicy {
        match protocol {
            crate::sandbox::Protocol::Tcp => &self.tcp_policy,
            crate::sandbox::Protocol::Udp => &self.udp_policy,
            crate::sandbox::Protocol::Icmp => &self.icmp_policy,
        }
    }

    /// Live policy (when restricting) over the instance per-protocol static
    /// policy — the un-narrowed default path (no session `update_network`
    /// narrowing in force).
    fn live_or_static(
        &self,
        protocol: crate::sandbox::Protocol,
        live_policy: Option<&std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    ) -> crate::seccomp::notif::NetworkPolicy {
        if let Some(lp) = live_policy {
            if let Ok(live) = lp.read() {
                if !live.allowed_ips.is_empty() {
                    return ip_only_allow_policy(&live.allowed_ips);
                }
            }
        }
        match protocol {
            crate::sandbox::Protocol::Tcp => self.tcp_policy.clone(),
            crate::sandbox::Protocol::Udp => self.udp_policy.clone(),
            crate::sandbox::Protocol::Icmp => self.icmp_policy.clone(),
        }
    }

}

/// Build the legacy IP-only allowlist policy (any port to each listed IP)
/// used by per-PID overrides and live-policy snapshots.
fn ip_only_allow_policy(
    ips: &HashSet<std::net::IpAddr>,
) -> crate::seccomp::notif::NetworkPolicy {
    use crate::seccomp::notif::{NetworkPolicy, PortAllow};
    let per_ip = ips.iter().map(|&ip| (ip, PortAllow::Any)).collect();
    NetworkPolicy::AllowList {
        per_ip,
        cidrs: Vec::new(),
        any_ip_ports: HashSet::new(),
        wildcard_domains: Vec::new(),
        denied: Default::default(),
    }
}

/// The deny-all allowlist (no destination matches). Used where a composition
/// provably grants nothing — [`intersect_ceiling_grant`] against a ceiling
/// that cannot express the requested subset, and the session narrowing set
/// written empty by `update_network` (deny all outbound).
fn deny_all_policy() -> crate::seccomp::notif::NetworkPolicy {
    ip_only_allow_policy(&HashSet::new())
}

/// The IPs an ip-only allowlist policy grants at any-port granularity.
/// Update bindings are built this way, so only the `per_ip` entries matter.
fn allowlist_any_port_ips(policy: &crate::seccomp::notif::NetworkPolicy) -> HashSet<std::net::IpAddr> {
    use crate::seccomp::notif::NetworkPolicy;
    match policy {
        NetworkPolicy::AllowList { per_ip, .. } => per_ip
            .iter()
            .filter(|(_, allow)| matches!(allow, crate::seccomp::notif::PortAllow::Any))
            .map(|(ip, _)| *ip)
            .collect(),
        // An Unrestricted bound policy grants every IP; the live set then
        // supplies the restriction (caller never reaches here with one).
        _ => HashSet::new(),
    }
}

/// S9 ceiling check for an `update_network` request (reviewer I1): does the
/// static per-protocol ceiling **explicitly deny** this destination? A
/// DenyList rule covering the IP (any deny entry, an any-IP port deny, or a
/// deny-all) refuses the request — the binding must never override an
/// explicit instance deny. Grant-based AllowList ceilings never refuse here:
/// the bound policy is intersected with the ceiling per protocol at verdict
/// time (see [`intersect_ceiling_grant`]), so a protocol that does not grant
/// the IP simply keeps denying it instead of being widened.
pub(crate) fn update_network_denied_by_ceiling(
    ceiling: &crate::seccomp::notif::NetworkPolicy,
    ip: std::net::IpAddr,
) -> bool {
    use crate::seccomp::notif::NetworkPolicy;
    match ceiling {
        NetworkPolicy::Unrestricted => false,
        NetworkPolicy::DenyList {
            cidrs,
            any_ip_ports,
            deny_all,
        } => {
            if *deny_all {
                return true;
            }
            if !any_ip_ports.is_empty() {
                return true;
            }
            cidrs.iter().any(|(net, _)| net.contains(ip))
        }
        NetworkPolicy::AllowList { .. } => false,
    }
}

/// Intersect an update binding (an IP-any-port allowlist) with one protocol's
/// static ceiling, so the bound child's effective policy for that protocol is
/// never wider than the ceiling:
///
/// * `Unrestricted` ceilings keep the binding;
/// * `DenyList` ceilings keep the binding (a requested IP the ceiling
///   explicitly denies was already refused at update time, and the binding
///   only narrows the default-allow remainder);
/// * `AllowList` ceilings keep only the requested IPs the ceiling grants at
///   any-port granularity (per-IP or covering CIDR `PortAllow::Any`); a
///   port-scoped grant or an any-IP-port rule cannot express an IP-any-port
///   subset, so the binding contributes nothing for that protocol and the
///   static policy (typically deny-all) governs — never a widened one.
pub(crate) fn intersect_ceiling_grant(
    binding: &crate::seccomp::notif::NetworkPolicy,
    ceiling: &crate::seccomp::notif::NetworkPolicy,
) -> crate::seccomp::notif::NetworkPolicy {
    use crate::seccomp::notif::{NetworkPolicy, PortAllow};
    match ceiling {
        NetworkPolicy::Unrestricted | NetworkPolicy::DenyList { .. } => binding.clone(),
        NetworkPolicy::AllowList {
            per_ip,
            cidrs,
            any_ip_ports,
            ..
        } => {
            if !any_ip_ports.is_empty() {
                return deny_all_policy();
            }
            let allowed: HashSet<std::net::IpAddr> = allowlist_any_port_ips(binding)
                .into_iter()
                .filter(|ip| {
                    matches!(per_ip.get(&ip.to_canonical()), Some(PortAllow::Any))
                        || cidrs.iter().any(|(net, allow)| {
                            net.contains(*ip) && matches!(allow, PortAllow::Any)
                        })
                })
                .collect();
            ip_only_allow_policy(&allowed)
        }
    }
}

// ============================================================
// TimeRandomState — deterministic time/random state
// ============================================================

/// Time offset and deterministic random state.
pub struct TimeRandomState {
    /// Clock offset for time virtualization.
    pub time_offset: Option<i64>,
    /// Deterministic PRNG state (seeded from policy).
    pub random_state: Option<rand_chacha::ChaCha8Rng>,
}

impl TimeRandomState {
    pub fn new(time_offset: Option<i64>, random_state: Option<rand_chacha::ChaCha8Rng>) -> Self {
        Self { time_offset, random_state }
    }
}

// ============================================================
// DeniedSet — denied paths plus captured file identities
// ============================================================

/// The filesystem deny set: path prefixes plus the file-handle identities
/// captured when each path was denied.
///
/// The path set is the primary, race-free boundary enforced at `open`. The
/// identity set makes the deny robust against namespace games (hardlinks,
/// renames, and pre-existing aliases): a [`FileId`] is the kernel file handle,
/// which encodes the inode and a generation number, so it travels with the
/// file's identity rather than the name used to reach it and is immune to
/// inode reuse. An open is denied if the opened file's identity matches, no
/// matter which path led to it. With `AT_HANDLE_FID` the kernel encodes an
/// identity FID for essentially every filesystem (generic inode FID where
/// NFS-export ops are absent); the rare path that still fails captures no
/// identity and relies on the always-on path prefix.
#[derive(Default)]
pub struct DeniedSet {
    paths: std::sync::RwLock<HashSet<String>>,
    ids: std::sync::RwLock<HashSet<FileId>>,
}

/// A file's stable identity: its kernel file handle, keyed by the superblock
/// device so identical handles from different filesystems cannot collide.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct FileId {
    dev: u64,
    handle_type: i32,
    handle: Vec<u8>,
}

/// Identity of a path, following symlinks (the open will resolve to the same
/// target). `None` if it cannot be resolved or no handle can be encoded. The
/// `(handle_type, handle)` FID comes from [`crate::sys::fs::file_handle`]; it is
/// keyed by the superblock `dev` so handles from different filesystems cannot
/// collide.
pub(crate) fn file_id_of_path(path: &str) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    let dev = std::fs::metadata(path).ok()?.dev();
    let c = std::ffi::CString::new(path).ok()?;
    let (handle_type, handle) =
        crate::sys::fs::file_handle(libc::AT_FDCWD, &c, libc::AT_SYMLINK_FOLLOW)?;
    Some(FileId { dev, handle_type, handle })
}

/// Identity of an open fd.
pub(crate) fn file_id_of_fd(fd: std::os::unix::io::RawFd) -> Option<FileId> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    let empty = std::ffi::CString::new("").ok()?;
    let (handle_type, handle) = crate::sys::fs::file_handle(fd, &empty, libc::AT_EMPTY_PATH)?;
    Some(FileId { dev: st.st_dev as u64, handle_type, handle })
}

impl DeniedSet {
    /// Deny `path` (and its subtree, by prefix). Also captures the file's
    /// handle identity if it exists now, so the deny still applies after the
    /// file is hardlinked or renamed to a non-denied name.
    pub fn deny(&self, path: &str) {
        if let Ok(mut p) = self.paths.write() {
            p.insert(path.to_string());
        }
        if let Some(id) = file_id_of_path(path) {
            if let Ok(mut i) = self.ids.write() {
                i.insert(id);
            }
        }
    }

    /// Stop denying `path`, dropping its captured identity too (best-effort:
    /// only if the path still resolves). A leftover identity would only ever
    /// over-deny, which is fail-safe.
    pub fn allow(&self, path: &str) {
        if let Ok(mut p) = self.paths.write() {
            p.remove(path);
        }
        if let Some(id) = file_id_of_path(path) {
            if let Ok(mut i) = self.ids.write() {
                i.remove(&id);
            }
        }
    }

    /// True if `path` is at or beneath a denied path (lexical prefix).
    pub fn is_path_denied(&self, path: &str) -> bool {
        self.paths.read().map_or(false, |denied| {
            let path = std::path::Path::new(path);
            denied
                .iter()
                .any(|d| path.starts_with(std::path::Path::new(d)))
        })
    }

    /// True if `id` is a denied file identity (catches hardlinks, renames, and
    /// pre-existing aliases regardless of the path used).
    pub(crate) fn is_id_denied(&self, id: &FileId) -> bool {
        self.ids.read().map_or(false, |s| s.contains(id))
    }

    /// Whether any deny rule is in effect.
    pub fn is_empty(&self) -> bool {
        self.paths.read().map_or(true, |p| p.is_empty())
            && self.ids.read().map_or(true, |i| i.is_empty())
    }

    /// Snapshot of the currently-denied path prefixes (sorted, deduped).
    /// Used by the control-socket `config` verb to reflect dynamic
    /// `policy_fn`-issued `deny_path()` calls in the effective policy.
    pub fn denied_paths(&self) -> Vec<String> {
        self.paths.read().map_or(Vec::new(), |p| {
            let mut v: Vec<String> = p.iter().cloned().collect();
            v.sort();
            v.dedup();
            v
        })
    }
}

// ============================================================
// PolicyFnState — dynamic policy callback state
// ============================================================

/// Dynamic policy callback state.
pub struct PolicyFnState {
    /// Event sender for dynamic policy callback (None if no policy_fn).
    pub event_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::policy_fn::PolicyMsg>>,
    /// Shared live policy for dynamic updates (None if no policy_fn).
    pub live_policy: Option<std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    /// Dynamically denied paths and inode identities from policy_fn / fs_deny.
    pub denied: std::sync::Arc<DeniedSet>,
}

impl PolicyFnState {
    pub fn new() -> Self {
        Self {
            event_tx: None,
            live_policy: None,
            denied: std::sync::Arc::new(DeniedSet::default()),
        }
    }

    /// Check if a path is at or beneath a denied path.
    pub fn is_path_denied(&self, path: &str) -> bool {
        self.denied.is_path_denied(path)
    }

    /// Check if an opened file's handle identity is denied.
    pub(crate) fn is_id_denied(&self, id: &FileId) -> bool {
        self.denied.is_id_denied(id)
    }

    /// Whether any deny rule is currently in effect. Cheap gate for the
    /// race-free on-behalf open path: with no denies there is no carve-out
    /// to protect and opens are left to the kernel and Landlock.
    pub fn has_denied_paths(&self) -> bool {
        !self.denied.is_empty()
    }
}

// ============================================================
// ChrootState — chroot-specific runtime state
// ============================================================

/// Chroot-specific runtime state.
pub struct ChrootState {
    /// Virtual exe path for chroot (set by handle_chroot_exec when memfd patching
    /// rewrites PT_INTERP, since /proc/self/exe would otherwise show the memfd path).
    pub chroot_exe: Option<std::path::PathBuf>,
}

impl ChrootState {
    pub fn new() -> Self {
        Self { chroot_exe: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_index_register_lookup_unregister() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx
            .register(self_pid)
            .expect("register should succeed for live pid");
        assert_eq!(key.pid, self_pid);

        assert_eq!(idx.key_for(self_pid), Some(key));
        assert!(idx.contains(self_pid));
        assert_eq!(idx.key_for(self_pid + 999_999), None);
        assert!(!idx.contains(self_pid + 999_999));
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.max_pid(), Some(self_pid));

        idx.unregister(key);
        assert_eq!(idx.key_for(self_pid), None);
        assert!(!idx.contains(self_pid));
        assert_eq!(idx.len(), 0);
        assert_eq!(idx.max_pid(), None);
    }

    #[test]
    fn threads_of_one_process_share_one_cwd() {
        // The kernel gives pthreads a shared fs_struct, so a chdir in one
        // thread moves its siblings. Registering a tid must join the leader's
        // cwd rather than start a private one.
        let leader = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        idx.register(leader).expect("leader registers");

        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            tid_tx.send(tid).unwrap();
            // Stay alive: register() reads /proc/<tid>/stat.
            let _ = stop_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        idx.register(tid).expect("thread registers");

        idx.set_virtual_cwd(tid, PathBuf::from("/workspace"));
        assert_eq!(idx.virtual_cwd(leader), Some(PathBuf::from("/workspace")));

        let _ = stop_tx.send(());
        thread.join().unwrap();
    }

    #[test]
    fn a_thread_without_its_own_key_uses_its_leader_cwd() {
        // F12: the runtime never registers a non-leader thread under its own
        // tid — one TGID has exactly one ProcessIndex entry (the leader's).
        // A thread still shares the leader's fs_struct, so its chdir must
        // land in the leader's cell, and its tid must count as tracked via
        // the leader.
        let leader = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        idx.register(leader).expect("leader registers");

        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            tid_tx.send(tid).unwrap();
            let _ = stop_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        // Deliberately not registered under its own tid.
        assert_eq!(idx.len(), 1, "a thread of a tracked leader has no key of its own");
        assert!(
            idx.contains(tid),
            "a thread must count as tracked through its thread-group leader"
        );

        idx.set_virtual_cwd(tid, PathBuf::from("/workspace"));
        assert_eq!(idx.virtual_cwd(tid), Some(PathBuf::from("/workspace")));
        assert_eq!(idx.virtual_cwd(leader), Some(PathBuf::from("/workspace")));

        let _ = stop_tx.send(());
        thread.join().unwrap();
    }

    #[test]
    fn thread_of_tracked_leader_resolves_to_leaders_entry() {
        // F12: one index entry per thread group. A non-leader thread is never
        // registered under its own tid by the runtime; every lookup on its
        // tid must resolve to the leader's entry (same key, same state Arc,
        // same address-space accounting target).
        let leader = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let leader_key = idx.register(leader).expect("leader registers");

        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            tid_tx.send(tid).unwrap();
            let _ = stop_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        assert_ne!(tid, leader, "helper must be a real non-leader thread");

        // Deliberately not registered under its own tid.
        assert_eq!(idx.len(), 1, "no tid key may exist for the helper thread");

        assert!(
            idx.contains(tid),
            "a thread of a tracked TGID must count as tracked via its leader"
        );
        assert_eq!(
            idx.key_for(tid),
            Some(leader_key),
            "key lookup on a thread tid must return the leader's PidKey"
        );
        let (tid_key, tid_state) = idx.entry_for(tid).expect("entry_for resolves via leader");
        assert_eq!(tid_key, leader_key);
        let (_, leader_state) = idx.entry_for(leader).expect("leader entry present");
        assert!(
            Arc::ptr_eq(&tid_state, &leader_state),
            "thread and leader must share one PerProcessState"
        );
        assert!(
            Arc::ptr_eq(
                &idx
                    .addr_space_state(tid)
                    .expect("addr_space_state resolves via leader"),
                &leader_state
            ),
            "memory accounting for a thread must target the leader's state"
        );

        let _ = stop_tx.send(());
        thread.join().unwrap();
    }

    #[test]
    fn a_child_copies_the_parent_cwd_instead_of_sharing_it() {
        // fork(2) copies fs_struct: the child starts where the parent stood,
        // and its later chdir must not move the parent.
        let parent = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        idx.register(parent).expect("parent registers");
        idx.set_virtual_cwd(parent, PathBuf::from("/workspace"));

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            // Async-signal-safe only: sleep, then leave without unwinding.
            let ts = libc::timespec { tv_sec: 30, tv_nsec: 0 };
            unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
            unsafe { libc::_exit(0) };
        }

        idx.register(child).expect("child registers");
        assert_eq!(idx.virtual_cwd(child), Some(PathBuf::from("/workspace")));

        idx.set_virtual_cwd(child, PathBuf::from("/tmp"));
        assert_eq!(idx.virtual_cwd(parent), Some(PathBuf::from("/workspace")));

        unsafe { libc::kill(child, libc::SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0) };
    }

    #[test]
    fn process_index_register_overwrites_stale_entry_for_recycled_pid() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        // Forge a stale entry by direct insertion under the lock.
        {
            let stale_key = PidKey { pid: self_pid, start_time: 0 };
            let stale = ProcessEntry {
                key: stale_key,
                tgid: self_pid,
                release: Arc::new(ProcessRelease::default()),
                state: Arc::new(AsyncMutex::new(PerProcessState::default())),
                cwd: SharedCwd::default(),
            };
            idx.inner.write().unwrap().insert(self_pid, stale);
        }

        let new_key = idx.register(self_pid).unwrap();
        assert_ne!(new_key.start_time, 0);
        assert_eq!(idx.key_for(self_pid), Some(new_key));

        // Unregistering by the stale key must NOT clobber the fresh
        // registration; only an exact-match unregister wins.
        let stale_key = PidKey { pid: self_pid, start_time: 0 };
        idx.unregister(stale_key);
        assert_eq!(idx.key_for(self_pid), Some(new_key));
    }

    #[tokio::test]
    async fn process_index_entry_for_returns_shared_handle() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx.register(self_pid).unwrap();

        let (k1, s1) = idx.entry_for(self_pid).unwrap();
        let (k2, s2) = idx.entry_for(self_pid).unwrap();
        assert_eq!(k1, key);
        assert_eq!(k2, key);

        // Two clones of the same Arc — writes through one are visible
        // through the other.
        s1.lock().await.brk_base = Some(0xdead_beef);
        assert_eq!(s2.lock().await.brk_base, Some(0xdead_beef));

        // After unregister, entry_for returns None but existing Arc
        // clones stay valid (kept alive by callers).
        idx.unregister(key);
        assert!(idx.entry_for(self_pid).is_none());
        assert_eq!(s1.lock().await.brk_base, Some(0xdead_beef));
    }

    #[test]
    fn process_index_pids_snapshot_is_independent() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx.register(self_pid).unwrap();
        let snap = idx.pids_snapshot();
        idx.unregister(key);
        assert!(snap.contains(&self_pid));
        assert!(!idx.contains(self_pid));
    }

    #[test]
    fn process_index_prune_dead_drops_recycled_entries() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        // Insert a stale entry for self with a wrong start_time.
        let stale_key = PidKey { pid: self_pid, start_time: 0 };
        let stale = ProcessEntry {
            key: stale_key,
            tgid: self_pid,
            release: Arc::new(ProcessRelease::default()),
            state: Arc::new(AsyncMutex::new(PerProcessState::default())),
            cwd: SharedCwd::default(),
        };
        idx.inner.write().unwrap().insert(self_pid, stale);

        idx.prune_dead();
        assert!(!idx.contains(self_pid));
    }

    #[test]
    fn process_index_prune_dead_keeps_live_entries() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx.register(self_pid).unwrap();
        idx.prune_dead();
        assert_eq!(idx.key_for(self_pid), Some(key));
    }

    // ============================================================
    // Instance-wide egress policy (end-state B): the verdict depends on the
    // sandbox's current policy, never on which exec a process belongs to.
    // ============================================================

    fn tcp_allow(ips: &[&str]) -> crate::seccomp::notif::NetworkPolicy {
        use crate::seccomp::notif::{NetworkPolicy, PortAllow};
        let per_ip = ips
            .iter()
            .map(|s| (s.parse().unwrap(), PortAllow::Any))
            .collect();
        NetworkPolicy::AllowList {
            per_ip,
            cidrs: Vec::new(),
            any_ip_ports: HashSet::new(),
            wildcard_domains: Vec::new(),
            denied: Default::default(),
        }
    }

    #[test]
    fn effective_policy_is_identical_for_every_pid() {
        let mut ns = NetworkState::new();
        ns.tcp_policy = tcp_allow(&["10.0.0.1", "10.0.0.2"]);
        ns.live_policy
            .write()
            .unwrap()
            .narrowed_ips = Some(HashSet::from(["10.0.0.1".parse().unwrap()]));

        // Two unrelated pids (an exec child and a stranger) read the same
        // verdict: process identity is not part of the judgement any more.
        let child = ns.effective_network_policy(4242, crate::sandbox::Protocol::Tcp, None);
        let stranger = ns.effective_network_policy(999_999, crate::sandbox::Protocol::Tcp, None);
        assert_eq!(
            child.allows("10.0.0.1".parse().unwrap(), 443),
            stranger.allows("10.0.0.1".parse().unwrap(), 443)
        );
        assert_eq!(
            child.allows("10.0.0.2".parse().unwrap(), 443),
            stranger.allows("10.0.0.2".parse().unwrap(), 443)
        );
        assert!(child.allows("10.0.0.1".parse().unwrap(), 443));
        assert!(!child.allows("10.0.0.2".parse().unwrap(), 443));
    }

    #[test]
    fn instance_narrowing_composes_with_the_protocol_ceiling() {
        let mut ns = NetworkState::new();
        // The narrowing names an IP the TCP ceiling does not grant: the
        // composition keeps it denied instead of widening the protocol.
        ns.tcp_policy = tcp_allow(&["10.0.0.1"]);
        ns.live_policy.write().unwrap().narrowed_ips = Some(HashSet::from([
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        ]));

        let tcp = ns.effective_network_policy(4242, crate::sandbox::Protocol::Tcp, None);
        assert!(tcp.allows("10.0.0.1".parse().unwrap(), 443));
        assert!(
            !tcp.allows("10.0.0.2".parse().unwrap(), 443),
            "an IP outside the protocol ceiling must stay denied"
        );

        // An empty narrowing is deny-all, not "unrestricted".
        ns.live_policy.write().unwrap().narrowed_ips = Some(HashSet::new());
        assert!(
            ns.effective_network_policy(4242, crate::sandbox::Protocol::Tcp, None)
                .denies_everything(),
            "an empty narrowing set must deny every outbound destination"
        );
    }

    #[test]
    fn pid_override_is_unchanged_by_the_instance_narrowing() {
        let mut ns = NetworkState::new();
        ns.tcp_policy = tcp_allow(&["10.0.0.1", "10.0.0.2"]);
        ns.live_policy
            .write()
            .unwrap()
            .narrowed_ips = Some(HashSet::from(["10.0.0.1".parse().unwrap()]));
        // The legacy per-PID channel keeps its own set (unchanged semantics).
        ns.pid_ip_overrides
            .write()
            .unwrap()
            .insert(4242, HashSet::from(["10.0.0.2".parse().unwrap()]));

        let overridden = ns.effective_network_policy(4242, crate::sandbox::Protocol::Tcp, None);
        assert!(overridden.allows("10.0.0.2".parse().unwrap(), 443));
        let other = ns.effective_network_policy(4243, crate::sandbox::Protocol::Tcp, None);
        assert!(!other.allows("10.0.0.2".parse().unwrap(), 443));
    }

    // ============================================================
    // F4 follow-up I1: update_network ceiling checks honor deny
    // semantics and per-protocol composition never widens
    // ============================================================

    fn deny_list(cidrs: Vec<(crate::network::IpCidr, crate::seccomp::notif::PortAllow)>) -> crate::seccomp::notif::NetworkPolicy {
        crate::seccomp::notif::NetworkPolicy::DenyList {
            cidrs,
            any_ip_ports: HashSet::new(),
            deny_all: false,
        }
    }

    #[test]
    fn update_ceiling_denylist_refuses_ip_covered_by_static_deny() {
        use crate::seccomp::notif::PortAllow;
        let ceiling = deny_list(vec![(
            crate::network::IpCidr::parse("10.0.0.0/8").unwrap(),
            PortAllow::Any,
        )]);
        assert!(
            update_network_denied_by_ceiling(&ceiling, "10.1.2.3".parse().unwrap()),
            "an IP the static DenyList denies must not be grantable any-port"
        );
        assert!(
            !update_network_denied_by_ceiling(&ceiling, "8.8.8.8".parse().unwrap()),
            "an IP outside the static denies stays grantable"
        );
    }

    #[test]
    fn update_ceiling_deny_all_refuses_every_request() {
        use crate::seccomp::notif::NetworkPolicy;
        let ceiling = NetworkPolicy::DenyList {
            cidrs: Vec::new(),
            any_ip_ports: HashSet::new(),
            deny_all: true,
        };
        assert!(
            update_network_denied_by_ceiling(&ceiling, "127.0.0.1".parse().unwrap()),
            "deny-all instance must refuse every non-empty update"
        );
    }

    #[test]
    fn update_binding_never_widens_a_deny_all_protocol_ceiling() {
        // UDP ceiling that grants nothing (deny-all AllowList): a TCP-scoped
        // update request must not widen UDP — the per-protocol composition
        // keeps UDP denying the requested IP.
        let udp_deny_all = crate::seccomp::notif::NetworkPolicy::AllowList {
            per_ip: HashMap::new(),
            cidrs: Vec::new(),
            any_ip_ports: HashSet::new(),
            wildcard_domains: Vec::new(),
            denied: Default::default(),
        };
        let binding = tcp_allow(&["10.0.0.1"]);
        assert!(
            !intersect_ceiling_grant(&binding, &udp_deny_all)
                .allows("10.0.0.1".parse().unwrap(), 53),
            "a deny-all UDP ceiling must never be widened by a TCP-bound update"
        );

        // Port-scoped TCP grant: the same request must not widen ports either
        // (the binding contributes nothing to that protocol).
        let tcp_port_scoped = crate::seccomp::notif::NetworkPolicy::AllowList {
            per_ip: HashMap::from([(
                "10.0.0.1".parse().unwrap(),
                crate::seccomp::notif::PortAllow::Specific(HashSet::from([443])),
            )]),
            cidrs: Vec::new(),
            any_ip_ports: HashSet::new(),
            wildcard_domains: Vec::new(),
            denied: Default::default(),
        };
        let narrowed = intersect_ceiling_grant(&binding, &tcp_port_scoped);
        assert!(
            !narrowed.allows("10.0.0.1".parse().unwrap(), 444),
            "port-scoped ceilings cannot be widened to any-port"
        );

        // Grant-based TCP ceiling: the binding applies for the granted IPs
        // only (narrowing, never widening past the ceiling).
        let tcp_ceiling = tcp_allow(&["10.0.0.1", "10.0.0.2"]);
        let narrowed = intersect_ceiling_grant(
            &tcp_allow(&["10.0.0.1", "10.0.0.2", "10.0.0.3"]),
            &tcp_ceiling,
        );
        assert!(narrowed.allows("10.0.0.1".parse().unwrap(), 443));
        assert!(narrowed.allows("10.0.0.2".parse().unwrap(), 443));
        assert!(
            !narrowed.allows("10.0.0.3".parse().unwrap(), 443),
            "an IP outside the ceiling must stay denied for that protocol"
        );
    }

}
