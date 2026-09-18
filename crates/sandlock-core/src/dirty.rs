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
}
