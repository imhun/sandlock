//! Which directories a sandbox has written to (N25/L2c).

//! The disk accounting that runs outside the sandbox needs "what changed since
//! the last look" to avoid re-walking a whole tree, and the only component
//! that sees every write is the mediator that already resolves every write's
//! path. This module is that ledger: a small, capped set of *parent
//! directories* of write-intent operations, drained by whoever does the
//! accounting.
//!
//! Three properties are deliberate:
//!
//! * **No new traps.** The marks are taken inside handlers that are already
//!   registered for those syscalls, at the point where the path has already
//!   been resolved — zero added syscalls, zero added notifications, and no
//!   change to the seccomp plan (so the sandbox's trap surface is unchanged).
//! * **Parent directories, not files.** The consumer re-walks a directory and
//!   reads the sizes that exist *then*; a file's size at mark time is already
//!   stale by the time anyone looks.
//! * **A cap with an explicit overflow.** One `cp -r` can touch tens of
//!   thousands of directories; past [`MAX_DIRTY_DIRS`] the set is dropped and
//!   [`DirtyDirs::drain`] reports `overflow`, which tells the consumer to fall
//!   back to one whole-tree walk instead of trusting a set that stopped
//!   recording.
//!
//! What it cannot see is a write that never names a path: a process that holds
//! a file descriptor open and keeps appending (a log file) issues no path
//! syscall. That is by design — covering it would mean a notification per
//! `write` — and the reconciliation walk is what catches it. A consumer can
//! close most of the gap cheaply by keeping a directory marked while its
//! re-walk keeps finding it *larger* (see `docs/disk-accounting-dirty-dirs.md`
//! §4.2): the first growth is marked by the `open` that preceded it.

use std::collections::HashSet;
use std::collections::HashMap;
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// How many distinct directories may be remembered before the set is declared
/// overflowed. 4096 host paths is ~0.3 MiB per sandbox, and a sandbox that
/// touches more than that in one round is exactly the shape a whole-tree walk
/// is cheaper for.
pub const MAX_DIRTY_DIRS: usize = 4096;

#[derive(Debug, Default)]
struct Inner {
    dirs: HashSet<PathBuf>,
    overflow: bool,
}

/// The per-sandbox set of written-to directories.
///
/// Interior mutability rather than a `Mutex<DirtyDirs>` at the call site: the
/// marking happens inline in synchronous code inside the notification
/// handlers, which must not become an `await` point.
#[derive(Debug)]
pub struct DirtyDirs {
    inner: Mutex<Inner>,
}

impl Default for DirtyDirs {
    fn default() -> Self {
        Self::new()
    }
}

impl DirtyDirs {
    pub fn new() -> Self {
        DirtyDirs {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Record the parent directory of `host_path`.
    ///
    /// Callers pass the *resolved host* path of the operation (the same path
    /// the handler is about to act on), so no further resolution happens here.
    /// A path with no parent (the filesystem root) is ignored: nothing outside
    /// a granted tree can be reached in the first place, and a consumer that
    /// re-walks `/` is not something this ledger should be able to ask for.
    pub fn mark(&self, host_path: &Path) {
        let Some(parent) = host_path.parent() else {
            return;
        };
        if parent.as_os_str().is_empty() {
            return;
        }
        let mut inner = self.lock();
        if inner.overflow || inner.dirs.contains(parent) {
            return;
        }
        if inner.dirs.len() >= MAX_DIRTY_DIRS {
            // Over the cap the set stops being a shortcut and starts being a
            // lie: clear it and let the consumer do one full walk. The flag
            // clears on drain, so a burst costs exactly one walk.
            inner.dirs.clear();
            inner.overflow = true;
            return;
        }
        inner.dirs.insert(parent.to_path_buf());
    }

    /// Take everything marked since the last drain: `(dirs, overflow)`.
    ///
    /// Draining clears the overflow flag with the set, because the consumer
    /// that receives it walks the whole tree and comes back with a baseline
    /// that no longer needs the flag.
    pub fn drain(&self) -> (Vec<PathBuf>, bool) {
        let mut inner = self.lock();
        let overflow = inner.overflow;
        inner.overflow = false;
        let dirs = inner.dirs.drain().collect();
        (dirs, overflow)
    }

    /// Whether anything is currently marked (no drain, for diagnostics).
    pub fn is_empty(&self) -> bool {
        let inner = self.lock();
        inner.dirs.is_empty() && !inner.overflow
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock means a marking thread panicked while holding it.
        // The set is a hint used to avoid work, so the honest recovery is to
        // keep using what is there rather than to propagate a panic into the
        // sandbox's syscall path.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// How many open write descriptors one sandbox may have watched at a time.
///
/// Past this the registry refuses new entries rather than evicting: the
/// consumer of this ledger watches for *a runaway writer*, and a sandbox
/// holding four thousand files open for writing is not that shape. Refusing
/// (instead of clearing, as [`DirtyDirs`] does) keeps the entries that are
/// already worth watching.
pub const MAX_WRITE_FDS: usize = 4096;

/// Which of a sandbox's open descriptors are **for writing**, and to what.
///
/// The mediator already opens every file the sandbox opens -- it is the
/// process that performs the `openat` and injects the resulting descriptor --
/// so it can learn `(pid, fd) -> host path` for free, from the kernel's
/// ADDFD reply, and it holds a descriptor that names exactly the inode the
/// sandbox will write through. That matters on a network filesystem: reading
/// the file's size *through that inode* is live (it is the page cache the
/// writer is filling), while reading it by path from another mount of the
/// same export is not -- measured on the cluster, a fast writer's file is
/// invisible by path from the worker for seconds, and reported at its final
/// size the instant it appears, while the writer's own view has the true size
/// from the first write.
///
/// This is a *watch list*, not a ledger: it records where to look, and the
/// consumer (`crate::append_watch`) reads sizes itself. Entries are dropped
/// when the descriptor is gone -- the reader notices, because reading the
/// descriptor's own metadata starts failing.
#[derive(Debug, Default)]
pub struct WriteFds {
    inner: Mutex<HashMap<(i32, i32), WriteFd>>,
    /// Everything the watch has attributed to writes since this generation
    /// started, summed incrementally (`observe` adds each step, so a
    /// descriptor that closes keeps its contribution).
    ///
    /// This is how much of the last budget the sandbox has *spent*, which is
    /// what turns "the remaining budget as of the last round" into "the
    /// remaining budget now" for an `open` that happens in between.
    spent: std::sync::atomic::AtomicU64,
    /// The last budget the worker sent, with the `spent` reading it arrived
    /// at: `bytes - (spent_now - spent_then)` is what is left *now*.
    budget: Mutex<Option<Budget>>,
    /// Bytes the mediator has watched the sandbox *free* since the generation
    /// started (an `unlink`, an `rmdir`, a shrinking truncate).
    ///
    /// Deleting is how a sandbox gets back inside its budget, and on this
    /// storage that only becomes true when the last descriptor lets go -- but
    /// the *decision* that matters is the mediator's own: its "may the tree
    /// grow?" refusal and the soft limit it hands out are computed from
    /// `remaining()`, and a command that deletes and then writes has to see
    /// the space come back *within the same command*, not on the next
    /// accounting round (§22.5.9).
    freed: std::sync::atomic::AtomicU64,
}

/// One `update_file_size_limit` from the worker, as a baseline.
#[derive(Debug, Clone, Copy)]
struct Budget {
    bytes: u64,
    spent_at: u64,
    freed_at: u64,
}

/// The offset of a descriptor the mediator holds, from `/proc/self/fdinfo`.
fn held_offset(held: &std::os::fd::OwnedFd) -> Option<u64> {
    use std::os::fd::AsRawFd;
    let fd = held.as_raw_fd();
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("pos:"))
        .and_then(|value| value.trim().parse::<u64>().ok())
}

/// One watched descriptor: what it names and where it started.
#[derive(Debug, Clone)]
pub struct WriteFd {
    pub path: PathBuf,
    /// The file's size at the instant the mediator opened it (`lseek(SEEK_END)`
    /// on the descriptor it is about to inject, so O_TRUNC is already
    /// applied). Growth is measured from here, which is what makes a
    /// short-lived writer -- one that opens, writes and closes inside a single
    /// sampling interval -- still countable: the interval only has to catch
    /// the descriptor once.
    pub baseline: u64,
    /// The largest offset the watch has read for this descriptor.
    ///
    /// Kept here rather than in the watch so that a *tightening* can ask the
    /// same question the accounting asks -- "how much has this descriptor
    /// grown since it was opened" -- without a second reader. That number is
    /// what stops a per-file limit from eating the file it is limiting: the
    /// bytes a file has already written are part of the worker's "used", so
    /// the ceiling it implies must be added back to them.
    pub observed: u64,
    /// The mediator's own descriptor for the same open file description.
    ///
    /// The kernel's fd injection *dups* the listener's descriptor into the
    /// sandbox, so both name one `struct file` and therefore one offset. The
    /// sandbox is free to move its copy -- measured: `exec 9>>file` dups the
    /// injected descriptor onto 9 and closes the original -- and a reader that
    /// only knows the sandbox's copy loses the file at that instant. This one
    /// cannot move, and reading it needs no pid translation and no permission
    /// on another process's `/proc` entry.
    pub held: Option<Arc<std::os::fd::OwnedFd>>,
    /// The absolute file size this descriptor was granted when it was opened
    /// (`baseline + what was left of the budget then`).
    ///
    /// Kept so a later `open` by the same process cannot lower the ceiling of
    /// a file it is still writing: the process-wide limit is the largest of
    /// the grants its live descriptors hold.
    pub cap: u64,
}

impl PartialEq for WriteFd {
    /// Everything that decides an entry's *accounting*. The held descriptor is
    /// the same file by construction, so it is left out of the comparison.
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.baseline == other.baseline
            && self.observed == other.observed
            && self.cap == other.cap
    }
}

impl Eq for WriteFd {}

impl WriteFds {
    pub fn new() -> Self {
        WriteFds {
            inner: Mutex::new(HashMap::new()),
            spent: std::sync::atomic::AtomicU64::new(0),
            budget: Mutex::new(None),
            freed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record bytes the sandbox just freed (`unlink`, `rmdir`, a shrinking
    /// truncate).
    ///
    /// They go straight back into what is left, so the very next `open` in the
    /// same command is judged against the space its own `rm` just returned.
    pub fn credit_freed(&self, bytes: u64) {
        if bytes > 0 {
            self.freed
                .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Record that `pid` holds `fd` open for writing on `host_path`.
    ///
    /// Called from the inject callback, i.e. *after* the kernel has answered
    /// with the child-side descriptor number, so the entry lands before the
    /// sandbox's `open` returns and no write can happen off the books.
    pub fn register(
        &self,
        pid: i32,
        fd: i32,
        host_path: &Path,
        baseline: u64,
        held: Option<Arc<std::os::fd::OwnedFd>>,
        cap: u64,
    ) {
        let mut inner = self.lock();
        if inner.len() >= MAX_WRITE_FDS && !inner.contains_key(&(pid, fd)) {
            return;
        }
        inner.insert(
            (pid, fd),
            WriteFd {
                path: host_path.to_path_buf(),
                baseline,
                observed: baseline,
                held,
                cap,
            },
        );
    }

    /// Record where a descriptor's offset is now (called by the watch).
    pub fn observe(&self, pid: i32, fd: i32, offset: u64) {
        let mut inner = self.lock();
        if let Some(entry) = inner.get_mut(&(pid, fd)) {
            // Monotone: a rewind (pwrite) must not shrink what the file is
            // allowed to be, or a tightening could refuse a legal file.
            let next = entry.observed.max(offset);
            let step = next.saturating_sub(entry.observed);
            entry.observed = next;
            self.spent
                .fetch_add(step, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Record the budget the worker just sent, with the spend it arrived at.
    pub fn note_budget(&self, bytes: u64) {
        let spent_at = self.spent.load(std::sync::atomic::Ordering::Relaxed);
        let freed_at = self.freed.load(std::sync::atomic::Ordering::Relaxed);
        *self
            .budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(Budget {
                bytes,
                spent_at,
                freed_at,
            });
    }

    /// What is left of the last budget, counting everything the watch has seen
    /// the sandbox append since that budget was computed.
    ///
    /// `None` when the worker has not sent a budget yet: an `open` then has no
    /// number to hand out and leaves the ceiling alone.
    pub fn remaining(&self) -> Option<u64> {
        let guard = self
            .budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let budget = (*guard)?;
        let spent_now = self.spent.load(std::sync::atomic::Ordering::Relaxed);
        let freed_now = self.freed.load(std::sync::atomic::Ordering::Relaxed);
        Some(
            budget
                .bytes
                .saturating_add(freed_now.saturating_sub(budget.freed_at))
                .saturating_sub(spent_now.saturating_sub(budget.spent_at)),
        )
    }

    /// Whether the sandbox has spent its whole budget: nothing may grow.
    ///
    /// The product semantic is "over the limit means you cannot write, but
    /// everything else still works" -- a freeze takes the whole sandbox away
    /// from its owner, including the deletes that would bring it back inside.
    /// So the enforcement is a *zero ceiling* plus, for the operations a
    /// ceiling cannot reach, a refusal at the mediator: `RLIMIT_FSIZE = 0`
    /// stops every write to a regular file, and creating *new* tree entries
    /// (`O_CREAT`, `mkdir`, `symlink`, `link`) is refused with `ENOSPC`,
    /// because those grow the tree without writing a byte.
    ///
    /// `false` until the worker has sent a budget: "no number yet" is not
    /// "no space".
    pub fn is_exhausted(&self) -> bool {
        self.remaining() == Some(0)
    }

    /// The largest file-size grant any of `pid`'s live descriptors holds.
    pub fn max_cap_for_pid(&self, pid: i32) -> u64 {
        self.lock()
            .iter()
            .filter(|((entry_pid, _fd), _entry)| *entry_pid == pid)
            .map(|(_key, entry)| entry.cap)
            .max()
            .unwrap_or(0)
    }

    /// How much `pid`'s watched descriptors have grown since they were opened.
    pub fn max_grown_for_pid(&self, pid: i32) -> u64 {
        self.max_grown_for_pids(&[pid])
    }

    /// Read every held descriptor of `pid` *now*, before answering a
    /// tightening.
    ///
    /// The watch samples on its own interval, and a tightening reasons about
    /// the same instant the worker's number came from: measured on the cluster,
    /// a file at 113 MiB was handed `bytes + grown` with `grown` still at the
    /// watch's previous sample (54 MiB), so the cap came out 59 MiB short and a
    /// legal file stopped at 263 MiB with 324 MiB of budget left
    /// (`probe_exec_limit.py`, step 1). The held descriptor is always
    /// readable, so the size at *this* instant is one small read away.
    ///
    /// Returns the largest growth seen, for callers that only want the number.
    pub fn refresh_held(&self, pid: i32) -> u64 {
        let held: Vec<(i32, i32, Arc<std::os::fd::OwnedFd>)> = self
            .lock()
            .iter()
            .filter(|((entry_pid, _fd), _entry)| *entry_pid == pid)
            .filter_map(|((entry_pid, fd), entry)| {
                entry.held.clone().map(|held| (*entry_pid, *fd, held))
            })
            .collect();
        let mut best = 0;
        for (entry_pid, fd, held) in held {
            if let Some(offset) = held_offset(&held) {
                self.observe(entry_pid, fd, offset);
                best = best.max(offset);
            }
        }
        best
    }

    /// The same, for a whole process group (N25).
    ///
    /// The group is the unit the tightening already works in, and for the
    /// same reason: the descriptor that is growing usually belongs to the
    /// *parent* -- `sh -c '... > file'` opens it and its child writes through
    /// the inherited descriptor -- so asking per pid would give the writer a
    /// ceiling that ignores the bytes it is already writing.
    pub fn max_grown_for_pids(&self, pids: &[i32]) -> u64 {
        self.lock()
            .iter()
            .filter(|((entry_pid, _fd), _entry)| pids.contains(entry_pid))
            .map(|(_key, entry)| entry.observed.saturating_sub(entry.baseline))
            .max()
            .unwrap_or(0)
    }

    /// Forget one descriptor (the consumer noticed it is gone).
    pub fn forget(&self, pid: i32, fd: i32) {
        self.lock().remove(&(pid, fd));
    }

    /// Every watched descriptor, as `((pid, fd), host path)`.
    pub fn snapshot(&self) -> Vec<((i32, i32), WriteFd)> {
        self.lock()
            .iter()
            .map(|(key, entry)| (*key, entry.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(i32, i32), WriteFd>> {
        // Same recovery as `DirtyDirs`: a poisoned lock means a marking thread
        // panicked, and this is a hint used to decide whether to do extra
        // work -- propagating the panic into a syscall path would be worse.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_the_parent_directory() {
        let dirty = DirtyDirs::new();
        dirty.mark(Path::new("/tree/a/b/c.txt"));
        let (dirs, overflow) = dirty.drain();
        assert_eq!(dirs, vec![PathBuf::from("/tree/a/b")]);
        assert!(!overflow);
    }

    #[test]
    fn draining_clears_the_set() {
        let dirty = DirtyDirs::new();
        dirty.mark(Path::new("/tree/a.txt"));
        assert!(!dirty.is_empty());
        let _ = dirty.drain();
        assert!(dirty.is_empty());
        assert_eq!(dirty.drain().0, Vec::<PathBuf>::new());
    }

    #[test]
    fn the_same_directory_is_recorded_once() {
        let dirty = DirtyDirs::new();
        dirty.mark(Path::new("/tree/d/f1"));
        dirty.mark(Path::new("/tree/d/f2"));
        assert_eq!(dirty.drain().0, vec![PathBuf::from("/tree/d")]);
    }

    #[test]
    fn a_path_without_a_parent_is_ignored() {
        let dirty = DirtyDirs::new();
        dirty.mark(Path::new("/"));
        assert!(dirty.is_empty());
    }

    #[test]
    fn the_cap_drops_the_set_and_reports_overflow() {
        let dirty = DirtyDirs::new();
        for i in 0..MAX_DIRTY_DIRS {
            dirty.mark(Path::new(&format!("/tree/d{i}/f")));
        }
        // One past the cap: the set is cleared and the flag raised.
        dirty.mark(Path::new("/tree/overflow/f"));
        let (dirs, overflow) = dirty.drain();
        assert!(overflow);
        assert!(dirs.is_empty());
        assert!(!dirty.drain().1, "the flag clears with the drain");
    }

    #[test]
    fn marking_after_overflow_is_a_no_op_until_the_drain() {
        let dirty = DirtyDirs::new();
        for i in 0..=MAX_DIRTY_DIRS {
            dirty.mark(Path::new(&format!("/tree/d{i}/f")));
        }
        dirty.mark(Path::new("/tree/after/f"));
        let (dirs, overflow) = dirty.drain();
        assert!(overflow);
        assert!(dirs.is_empty());

        dirty.mark(Path::new("/tree/real/f"));
        let (dirs, overflow) = dirty.drain();
        assert!(!overflow);
        assert_eq!(dirs, vec![PathBuf::from("/tree/real")]);
    }

    #[test]
    fn a_watched_descriptor_keeps_its_path_and_baseline() {
        let watch = WriteFds::new();
        watch.register(11, 5, Path::new("/tree/blob.bin"), 4096, None, 0);
        let entries = watch.snapshot();
        assert_eq!(entries.len(), 1);
        let (key, entry) = &entries[0];
        assert_eq!(*key, (11, 5));
        assert_eq!(entry.path, PathBuf::from("/tree/blob.bin"));
        assert_eq!(entry.baseline, 4096);
    }

    #[test]
    fn forgetting_a_descriptor_removes_it() {
        let watch = WriteFds::new();
        watch.register(11, 5, Path::new("/tree/a"), 0, None, 0);
        watch.register(11, 6, Path::new("/tree/b"), 0, None, 0);
        watch.forget(11, 5);
        let entries = watch.snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, (11, 6));
    }

    #[test]
    fn a_reopened_descriptor_replaces_its_baseline() {
        // Same slot, new file: the old baseline must not survive, or growth
        // would be measured against the wrong starting point.
        let watch = WriteFds::new();
        watch.register(11, 5, Path::new("/tree/first"), 10_000, None, 0);
        watch.register(11, 5, Path::new("/tree/second"), 0, None, 0);
        let entries = watch.snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.path, PathBuf::from("/tree/second"));
        assert_eq!(entries[0].1.baseline, 0);
    }

    #[test]
    fn an_observed_offset_reports_what_a_descriptor_has_grown_by() {
        let watch = WriteFds::new();
        watch.register(11, 5, Path::new("/tree/f"), 4096, None, 0);
        assert_eq!(watch.max_grown_for_pid(11), 0);
        watch.observe(11, 5, 4096 + 900);
        assert_eq!(watch.max_grown_for_pid(11), 900);
        // Another process's descriptors are not this process's allowance.
        assert_eq!(watch.max_grown_for_pid(12), 0);
    }

    #[test]
    fn an_observed_offset_is_monotone() {
        // A `pwrite` back at offset 0 must not shrink what the file may be:
        // the limit derived from it would then refuse writes that are legal.
        let watch = WriteFds::new();
        watch.register(11, 5, Path::new("/tree/f"), 0, None, 0);
        watch.observe(11, 5, 10_000);
        watch.observe(11, 5, 8);
        assert_eq!(watch.max_grown_for_pid(11), 10_000);
    }

    #[test]
    fn the_allowance_is_the_largest_of_a_processs_descriptors() {
        let watch = WriteFds::new();
        watch.register(11, 5, Path::new("/tree/a"), 0, None, 0);
        watch.register(11, 6, Path::new("/tree/b"), 0, None, 0);
        watch.observe(11, 5, 700);
        watch.observe(11, 6, 900);
        assert_eq!(watch.max_grown_for_pid(11), 900);
    }

    #[test]
    fn observing_a_descriptor_that_is_gone_is_a_no_op() {
        let watch = WriteFds::new();
        watch.observe(11, 5, 1234);
        assert_eq!(watch.max_grown_for_pid(11), 0);
    }

    #[test]
    fn refresh_held_reads_the_descriptor_now() {
        // The watch samples on its own interval, and a tightening reasons
        // about the instant the worker's number came from: measured on the
        // cluster, a file at 113 MiB was handed `bytes + grown` with `grown`
        // still at the previous sample (54 MiB), which stopped a legal file
        // 59 MiB early. The held descriptor makes the size at *this* instant
        // one small read away.
        use std::io::Write;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
        std::fs::create_dir_all(&dir).expect("create test tmp");
        let path = dir.join(format!("refresh-held-{}.bin", std::process::id()));
        let mut file = std::fs::File::create(&path).expect("create file");
        file.write_all(&[0u8; 4096]).expect("write");
        let held = std::sync::Arc::new(std::os::fd::OwnedFd::from(file));

        let watch = WriteFds::new();
        watch.register(11, 5, &path, 0, Some(held), 1024);
        // Nothing has sampled this descriptor yet.
        assert_eq!(watch.max_grown_for_pid(11), 0);
        // A tightening asks for the size now.
        assert_eq!(watch.refresh_held(11), 4096);
        assert_eq!(watch.max_grown_for_pid(11), 4096);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_remaining_budget_is_the_last_number_minus_what_was_spent_since() {
        // N25/B: an `open` between two rounds has to know what the last round
        // did *not* know yet. `spent` is that, summed as the watch observes.
        let watch = WriteFds::new();
        watch.register(11, 5, Path::new("/tree/a.bin"), 0, None, 0);
        watch.note_budget(1024 * 1024);
        assert_eq!(watch.remaining(), Some(1024 * 1024));

        watch.observe(11, 5, 600 * 1024);
        assert_eq!(watch.remaining(), Some(424 * 1024));

        // A descriptor that closes keeps what it spent: the pool is a spend
        // counter, not a sum over live descriptors.
        watch.forget(11, 5);
        assert_eq!(watch.remaining(), Some(424 * 1024));

        watch.register(11, 9, Path::new("/tree/b.bin"), 0, None, 0);
        watch.observe(11, 9, 424 * 1024);
        assert_eq!(watch.remaining(), Some(0));
    }

    #[test]
    fn a_new_budget_rebaselines_the_spend() {
        let watch = WriteFds::new();
        watch.register(11, 5, Path::new("/tree/a.bin"), 0, None, 0);
        watch.observe(11, 5, 700);
        watch.note_budget(400);
        assert_eq!(watch.remaining(), Some(400));
        watch.observe(11, 5, 900);
        assert_eq!(watch.remaining(), Some(200));
    }

    #[test]
    fn the_largest_grant_of_a_processes_descriptors_wins() {
        // A later `open` by a process that is still writing must not lower the
        // ceiling under that file: the process-wide limit is the largest grant
        // its live descriptors hold.
        let watch = WriteFds::new();
        watch.register(11, 5, Path::new("/tree/first.bin"), 0, None, 900 * 1024 * 1024);
        assert_eq!(watch.max_cap_for_pid(11), 900 * 1024 * 1024);
        watch.register(11, 9, Path::new("/tree/second.bin"), 0, None, 1024 * 1024);
        assert_eq!(watch.max_cap_for_pid(11), 900 * 1024 * 1024);
        assert_eq!(watch.max_cap_for_pid(12), 0);
    }

    #[test]
    fn the_cap_refuses_new_descriptors_but_keeps_the_ones_it_has() {
        let watch = WriteFds::new();
        for fd in 0..MAX_WRITE_FDS as i32 {
            watch.register(11, fd, Path::new("/tree/f"), 0, None, 0);
        }
        assert_eq!(watch.len(), MAX_WRITE_FDS);
        watch.register(11, MAX_WRITE_FDS as i32, Path::new("/tree/one-too-many"), 0, None, 0);
        assert_eq!(watch.len(), MAX_WRITE_FDS);
        assert!(!watch
            .snapshot()
            .iter()
            .any(|(_, e)| e.path == PathBuf::from("/tree/one-too-many")));
        // An update to a descriptor already watched is still accepted.
        watch.register(11, 0, Path::new("/tree/f"), 7, None, 0);
        let first = watch
            .snapshot()
            .into_iter()
            .find(|(k, _)| *k == (11, 0))
            .expect("watched");
        assert_eq!(first.1.baseline, 7);
    }
}
