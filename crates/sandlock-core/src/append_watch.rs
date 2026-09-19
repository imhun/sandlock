//! How much a sandbox has appended, read from its own open descriptors (N25).

//! The disk accounting outside the sandbox measures a tree, and on this
//! deployment the tree lives on NFS. That makes the *size* of a file a
//! question with surprising properties: measured on the cluster, a worker
//! asking by path about a file a sandbox is writing at speed sees the file
//! not at all for seconds and then at its final size, because what it can see
//! is what the server has committed (and a `stat` that forces the flush
//! answers only once the write is over).
//!
//! The mediator is not in that position. It is the process that performed the
//! sandbox's `openat` -- it opens the file itself and injects the descriptor
//! -- so it holds a descriptor naming exactly the inode the sandbox writes
//! through, and that inode's size is the writer's own view. Measured the same
//! way (inside the sandbox, holding such an fd): the size jumps to the final
//! value within one sampling interval, while the writer is still blocked on
//! writeback for seconds.
//!
//! So this module turns "which descriptors were opened for writing"
//! ([`crate::dirty::WriteFds`], filled by the open handler for free) into a
//! monotone count of *appended bytes*, by reading each descriptor's current
//! offset. It deliberately reports a **lower bound**:
//!
//! * offsets only move forward while we watch, so an overwrite in place counts
//!   zero rather than negative;
//! * two descriptors on one file count once (the larger of the two), because
//!   either one can only report the file's own end;
//! * a descriptor we never sampled counts nothing -- the file's size still
//!   reaches the accounting through the ordinary walk, just later.
//!
//! A lower bound is the useful direction for a quota: a consumer may act on
//! "the tree has grown by at least this much", because growth that is real
//! cannot be smaller than a bound taken from the writes themselves.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::dirty::WriteFds;

/// Where a descriptor's current offset comes from; injectable so the counting
/// rules can be tested without a live sandbox.
pub trait OffsetReader {
    /// The descriptor's current offset, or `None` when it no longer exists.
    fn read_offset(&self, pid: i32, fd: i32) -> Option<u64>;
}

/// Reads `/proc/<pid>/fdinfo/<fd>` and parses its `pos:` line.
///
/// The offset is the one the kernel keeps for the open file description, so
/// for the shapes that matter here -- create-and-fill (`dd`, a download, an
/// extractor) and append (`>>`, a log) -- it *is* the file's size, and it is
/// available with no round trip to the server and no wait for the data.
pub struct ProcOffsetReader;

impl OffsetReader for ProcOffsetReader {
    fn read_offset(&self, pid: i32, fd: i32) -> Option<u64> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).ok()?;
        parse_pos(&text)
    }
}

/// Pull `pos:` out of one `fdinfo` document.
pub fn parse_pos(fdinfo: &str) -> Option<u64> {
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("pos:"))
        .and_then(|value| value.trim().parse::<u64>().ok())
}

/// What one tick of the watch found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Appended {
    /// Bytes appended since the previous tick (never negative).
    pub bytes: u64,
    /// Descriptors currently watched.
    pub watching: usize,
    /// Descriptors dropped this tick because they are gone.
    pub dropped: usize,
}

/// The running "how much has been appended" view of one sandbox.
///
/// Stateful across ticks, and only across ticks: the consumer is expected to
/// call [`Self::tick`] on a fixed interval and to treat each `bytes` value as
/// an increment.
#[derive(Debug, Default)]
pub struct AppendWatch {
    /// Highest growth seen per descriptor, so a descriptor that rewinds (or a
    /// file that is truncated underneath us) cannot lower the count.
    grown: HashMap<(i32, i32), u64>,
}

impl AppendWatch {
    pub fn new() -> Self {
        AppendWatch::default()
    }

    /// Read every watched descriptor and report what grew since the last tick.
    pub fn tick<R: OffsetReader>(&mut self, watch: &WriteFds, reader: &R) -> Appended {
        let entries = watch.snapshot();
        let considered = entries.len();
        let mut result = Appended::default();
        // A descriptor that is gone is dropped from both sides, so the map
        // cannot grow for the life of a sandbox.
        let mut present: HashMap<(i32, i32), u64> = HashMap::with_capacity(entries.len());
        // Two descriptors on the same file each see that file's end, so the
        // per-file number is the larger of them, not their sum; comparing it
        // against the same fold over the previous tick is what makes a
        // descriptor that closed take its contribution away *without* reading
        // as a negative delta on the file that is still growing.
        let mut now_by_path: HashMap<PathBuf, u64> = HashMap::new();
        let mut before_by_path: HashMap<PathBuf, u64> = HashMap::new();

        for (key, entry) in entries {
            let Some(offset) = reader.read_offset(key.0, key.1) else {
                watch.forget(key.0, key.1);
                result.dropped += 1;
                continue;
            };
            // Publish where this descriptor is, so a tightening can add back
            // what this file has already written (see `WriteFd::observed`).
            watch.observe(key.0, key.1, offset);
            let grown_now = offset.saturating_sub(entry.baseline);
            let previous = self.grown.get(&key).copied().unwrap_or(0);
            let best = grown_now.max(previous);
            present.insert(key, best);
            let slot = now_by_path.entry(entry.path.clone()).or_insert(0);
            *slot = (*slot).max(best);
            let slot = before_by_path.entry(entry.path).or_insert(0);
            *slot = (*slot).max(previous);
        }

        for (path, now) in now_by_path {
            let before = before_by_path.get(&path).copied().unwrap_or(0);
            result.bytes = result
                .bytes
                .saturating_add(now.saturating_sub(before));
        }

        self.grown = present;
        // "Watching" is what is left after this tick's drops, not what the
        // tick started with: the consumer is being told where the watch
        // stands, and a descriptor that just closed is not part of that.
        result.watching = considered.saturating_sub(result.dropped);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dirty::WriteFds;
    use std::collections::HashMap as Map;
    use std::sync::Mutex;

    /// A scripted reader: `(pid, fd) -> offset`, `None` meaning "gone".
    #[derive(Default)]
    struct Fake {
        offsets: Mutex<Map<(i32, i32), Option<u64>>>,
    }

    impl Fake {
        fn set(&self, pid: i32, fd: i32, offset: Option<u64>) {
            self.offsets.lock().unwrap().insert((pid, fd), offset);
        }
    }

    impl OffsetReader for Fake {
        fn read_offset(&self, pid: i32, fd: i32) -> Option<u64> {
            self.offsets.lock().unwrap().get(&(pid, fd)).copied().flatten()
        }
    }

    fn watch_with(entries: &[(i32, i32, &str, u64)]) -> WriteFds {
        let watch = WriteFds::new();
        for (pid, fd, path, baseline) in entries {
            watch.register(*pid, *fd, std::path::Path::new(path), *baseline);
        }
        watch
    }

    #[test]
    fn parses_the_pos_line() {
        let text = "pos:\t1048576\nflags:\t0100002\nmnt_id:\t30\nino:\t42\n";
        assert_eq!(parse_pos(text), Some(1048576));
    }

    #[test]
    fn a_missing_pos_is_not_a_size() {
        assert_eq!(parse_pos("flags:\t0100002\n"), None);
        assert_eq!(parse_pos("pos:\tnot-a-number\n"), None);
    }

    #[test]
    fn counts_growth_from_the_baseline_on_first_sight() {
        // The shape a single sample cannot otherwise see: a short-lived
        // writer that opened, wrote and is about to close.
        let watch = watch_with(&[(7, 3, "/tree/a.bin", 0)]);
        let fake = Fake::default();
        fake.set(7, 3, Some(900 * 1024 * 1024));
        let mut watcher = AppendWatch::new();
        let sample = watcher.tick(&watch, &fake);
        assert_eq!(sample.bytes, 900 * 1024 * 1024);
        assert_eq!(sample.watching, 1);
        assert_eq!(sample.dropped, 0);
    }

    #[test]
    fn counts_only_the_increment_on_later_ticks() {
        let watch = watch_with(&[(7, 3, "/tree/a.bin", 0)]);
        let fake = Fake::default();
        let mut watcher = AppendWatch::new();

        fake.set(7, 3, Some(1000));
        assert_eq!(watcher.tick(&watch, &fake).bytes, 1000);
        fake.set(7, 3, Some(1500));
        assert_eq!(watcher.tick(&watch, &fake).bytes, 500);
        fake.set(7, 3, Some(1500));
        assert_eq!(watcher.tick(&watch, &fake).bytes, 0);
    }

    #[test]
    fn an_append_starts_from_the_size_at_open() {
        // A file that already held 4 MiB, opened for append, then grown.
        let watch = watch_with(&[(7, 3, "/tree/log", 4 * 1024 * 1024)]);
        let fake = Fake::default();
        fake.set(7, 3, Some(6 * 1024 * 1024));
        let mut watcher = AppendWatch::new();
        assert_eq!(watcher.tick(&watch, &fake).bytes, 2 * 1024 * 1024);
    }

    #[test]
    fn a_rewind_never_counts_negative() {
        let watch = watch_with(&[(7, 3, "/tree/a.bin", 0)]);
        let fake = Fake::default();
        let mut watcher = AppendWatch::new();
        fake.set(7, 3, Some(4096));
        assert_eq!(watcher.tick(&watch, &fake).bytes, 4096);
        // pwrite back at offset 0: the file did not grow.
        fake.set(7, 3, Some(8));
        assert_eq!(watcher.tick(&watch, &fake).bytes, 0);
        // ...and growth after that is measured from the high-water mark.
        fake.set(7, 3, Some(5000));
        assert_eq!(watcher.tick(&watch, &fake).bytes, 904);
    }

    #[test]
    fn two_descriptors_on_one_file_count_once() {
        let watch = watch_with(&[(7, 3, "/tree/a.bin", 0), (7, 4, "/tree/a.bin", 0)]);
        let fake = Fake::default();
        fake.set(7, 3, Some(1_000_000));
        fake.set(7, 4, Some(1_000_000));
        let mut watcher = AppendWatch::new();
        assert_eq!(watcher.tick(&watch, &fake).bytes, 1_000_000);
    }

    #[test]
    fn a_closed_descriptor_drops_its_contribution_without_a_negative_delta() {
        let watch = watch_with(&[(7, 3, "/tree/a.bin", 0), (7, 4, "/tree/b.bin", 0)]);
        let fake = Fake::default();
        fake.set(7, 3, Some(1000));
        fake.set(7, 4, Some(0));
        let mut watcher = AppendWatch::new();
        assert_eq!(watcher.tick(&watch, &fake).bytes, 1000);

        // a.bin is closed: its 1000 bytes stay counted, and b.bin's later
        // growth is still an increment.
        fake.set(7, 3, None);
        fake.set(7, 4, Some(400));
        let sample = watcher.tick(&watch, &fake);
        assert_eq!(sample.dropped, 1);
        assert_eq!(sample.bytes, 400);
        assert_eq!(sample.watching, 1);
    }

    #[test]
    fn a_new_descriptor_after_a_close_is_counted_from_its_own_baseline() {
        // The loop shape: each iteration opens the next file. A tick that
        // catches iteration N's descriptor after iteration N-1's closed must
        // still count it, which is what the baseline buys.
        let watch = watch_with(&[(7, 3, "/tree/part1", 0)]);
        let fake = Fake::default();
        fake.set(7, 3, Some(900));
        let mut watcher = AppendWatch::new();
        assert_eq!(watcher.tick(&watch, &fake).bytes, 900);

        fake.set(7, 3, None);
        assert_eq!(watcher.tick(&watch, &fake).bytes, 0);

        watch.register(7, 9, std::path::Path::new("/tree/part2"), 0);
        fake.set(7, 9, Some(700));
        assert_eq!(watcher.tick(&watch, &fake).bytes, 700);
    }
}
