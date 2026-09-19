//! Pushing events from the slot to the worker (N25).

//! Route B's control channel is request/response: the worker asks, the slot
//! answers. Accounting is the one thing that runs the other way -- a sandbox
//! starts writing and the platform should hear about it *then*, not at its
//! next poll -- so this is a second, one-way descriptor the launcher hands
//! over (`--events-fd N`) and the slot writes to whenever there is something
//! to say.
//!
//! Two decisions worth naming:
//!
//! * **A separate descriptor, not extra frames on the control stream.** The
//!   control stream is request/response and every response is read by code
//!   that expects one reply per request; interleaving unprompted frames would
//!   make "the next frame" ambiguous and force every reader (including the
//!   older ones) to grow a dispatch table. A second fd keeps both protocols
//!   simple, and lets the worker block on events in its own thread without
//!   ever delaying an `exec` or a `wait_child`.
//! * **NDJSON, not length-prefixed frames.** Events are small, one object per
//!   line, and the reader on the other side is Python: `readline()` plus
//!   `json.loads` needs no framing code to get wrong, and a partial read
//!   cannot desynchronise a stream that is only ever read to a newline.
//!
//! The watch itself is deliberately dumb about *what* grew: it reports bytes
//! appended through descriptors the sandbox holds open for writing, which is
//! a lower bound on how much the workspace grew (see
//! [`sandlock_core::append_watch`]). Nothing is reported when nothing grew,
//! so an idle sandbox costs the worker nothing but the descriptor.

use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sandlock_core::append_watch::{AppendWatch, ProcOffsetReader};
use sandlock_core::dirty::WriteFds;

/// How often the watch looks at the sandbox's open write descriptors.
///
/// This is the resolution of the append signal, and it is the only knob that
/// bounds how far a runaway writer can overshoot before the platform hears
/// about it. 100 ms is well under the ~1 s a polling scan round costs, and
/// the work per tick is one `read` of `/proc/<pid>/fdinfo/<fd>` per open
/// write descriptor -- tens of microseconds for the shapes that matter.
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

/// Environment override for [`DEFAULT_INTERVAL`], in milliseconds.
pub const INTERVAL_ENV: &str = "SANLOCK_APPEND_INTERVAL_MS";

/// A running event publisher. Dropping it stops the thread.
pub struct Appender {
    stop: Arc<AtomicBool>,
}

impl Appender {
    /// Start publishing append events for `watch` on the handed-over fd.
    ///
    /// The thread is deliberately not joined on drop: its exit condition is
    /// the generation ending, and a thread blocked writing to a worker that
    /// has stopped reading must not be able to hold the process open. It
    /// owns its end of the socketpair, so the fd closes when it exits.
    ///
    /// Fails when the descriptor cannot be written at all: a slot whose
    /// channel is dead must say so, because the consumer cannot tell "nothing
    /// was written" from "the channel was never wired" -- it sees an
    /// immediately-closed descriptor in both cases, which is how a dead push
    /// channel stayed invisible on the cluster (§22.5.7).
    pub fn spawn(events_fd: RawFd, watch: Arc<WriteFds>) -> Result<Appender, String> {
        let interval = interval_from_env();
        let trace = std::env::var("SANLOCK_EVENT_TRACE")
            .map(|value| value.trim() == "1")
            .unwrap_or(false);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let mut stream = unsafe { UnixStream::from_raw_fd(events_fd) };
        // SL-4 class: the sandbox must never inherit this descriptor, or a
        // confined process would hold the pipe the worker reads events from.
        // The launcher clears FD_CLOEXEC for the hand-over; it is restored
        // here, before anything else in the generation can run.
        unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };

        // Prove the channel before the generation starts serving: one greeting
        // line, so "the worker never saw a byte" is a refusal here rather than
        // silence later.
        let hello = serde_json::json!({"v": 1, "event": "hello", "fd": events_fd});
        let mut greeting = hello.to_string();
        greeting.push('\n');
        stream
            .write_all(greeting.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|e| format!("events descriptor {events_fd} is not writable: {e}"))?;

        std::thread::Builder::new()
            .name("sandlock-events".to_string())
            .spawn(move || {
                let mut state = AppendWatch::new();
                let reader = ProcOffsetReader;
                let mut seq: u64 = 0;
                while !thread_stop.load(Ordering::Relaxed) {
                    let sample = state.tick(&watch, &reader);
                    if trace {
                        // Off by default. The question it answers -- "is the
                        // watch empty, or are the reads failing?" -- is the
                        // one the two look identical for from outside, and it
                        // is what found the namespace-pid bug.
                        let debug = serde_json::json!({
                            "v": 1,
                            "event": "tick",
                            "watching": sample.watching,
                            "dropped": sample.dropped,
                            "bytes": sample.bytes,
                        });
                        let mut line = debug.to_string();
                        line.push('\n');
                        let _ = stream.write_all(line.as_bytes());
                    }
                    if sample.bytes > 0 {
                        let event = serde_json::json!({
                            "v": 1,
                            "event": "append",
                            "seq": seq,
                            "bytes": sample.bytes,
                            "watching": sample.watching,
                            "dropped": sample.dropped,
                        });
                        let mut line = event.to_string();
                        line.push('\n');
                        if let Err(e) = stream.write_all(line.as_bytes()) {
                            // Loud on purpose: a publisher that stops without
                            // saying so looks exactly like a sandbox that
                            // stopped writing, and the worker cannot tell the
                            // two apart -- it just sees the channel close.
                            eprintln!(
                                "sandlock-supervise: events publisher stopped: write to \
                                 the events descriptor failed: {e}"
                            );
                            return;
                        }
                        let _ = stream.flush();
                        seq += 1;
                    }
                    std::thread::sleep(interval);
                }
            })
            .map_err(|e| format!("cannot start the events publisher thread: {e}"))?;
        Ok(Appender { stop })
    }
}

impl Drop for Appender {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// The publish interval, from the environment when it is set to a sane value.
pub fn interval_from_env() -> Duration {
    match std::env::var(INTERVAL_ENV) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(ms) if ms > 0 && ms <= 60_000 => Duration::from_millis(ms),
            _ => DEFAULT_INTERVAL,
        },
        Err(_) => DEFAULT_INTERVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_event_line_is_one_json_object_per_line() {
        let event = serde_json::json!({"v": 1, "event": "append", "seq": 0, "bytes": 4096});
        let mut line = event.to_string();
        line.push('\n');
        assert_eq!(line.matches('\n').count(), 1);
        let parsed: serde_json::Value =
            serde_json::from_str(line.trim_end()).expect("one object");
        assert_eq!(parsed["event"], "append");
        assert_eq!(parsed["bytes"], 4096);
    }
}
