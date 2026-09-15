//! FUP-24: `kill --all`'s daemon-gone fallback must fire only when the request
//! never reached the daemon.
//!
//! `cmd_kill --all` delivered the instance signal through the supervisor and
//! answered **any** `send_command` error with a direct
//! `killpg(state.pid, signum)` ("the daemon never got it"). A request the
//! supervisor *did* read, relay to `sandlock-init` and answer — whose reply was
//! then lost on the way back — lands in that same arm, so the instance signal
//! was delivered a **second** time, breaking the F1.7/SECE-6 exactly-once
//! contract. (The f1oci flake was this arm firing on an `EPIPE` raised *after*
//! the payload had already been acted on; that path is gone, the over-broad
//! criterion was not — this suite pins the narrowed one.)
//!
//! Each test drives the real `sandlock-oci kill --all` CLI against a state root
//! and a stand-in supervisor socket it owns, and observes the delivery count on
//! a victim process group:
//!
//! 1. frame delivered, reply lost        -> exactly one delivery, error reported
//! 2. socket unreachable (ENOENT / refused) -> fallback still delivers, once
//! 3. normal round trip                  -> exactly one delivery, exit 0
//!
//! The victim (`sigwatch`) is a static C probe built the same way
//! `test_process_groups.rs` builds `/pgprobe`. It puts itself in its **own**
//! process group (so the CLI's `killpg(state.pid, …)` fallback can only reach
//! it), traps a realtime signal — realtime signals are queued, so every
//! injection is observable instead of coalescing — and reports how many
//! deliveries it saw after a fixed window.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

use sandlock_oci::supervisor::{socket_path_in, SupervisorCmd};

/// The victim probe. `sigwatch <info> <count> <signum> <window-ms>`:
///
/// - `setpgid(0, 0)` so it leads its own group;
/// - traps `<signum>` with a counter (realtime signals queue, so N injections
///   are N handler runs);
/// - writes `pid=<pid> pgid=<pgid>` to `<info>` as soon as it is armed;
/// - sleeps `<window-ms>` (resuming through deliveries) and writes the number
///   of deliveries to `<count>`.
const SIGWATCH_C: &str = r##"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t deliveries = 0;

static void on_signal(int sig) {
    (void)sig;
    deliveries++;
}

static void put(const char *path, const char *s) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) _exit(3);
    size_t n = strlen(s);
    while (n > 0) {
        ssize_t w = write(fd, s, n);
        if (w <= 0) _exit(4);
        s += w;
        n -= (size_t)w;
    }
    close(fd);
}

int main(int argc, char **argv) {
    if (argc != 5) return 100;
    const char *info = argv[1];
    const char *count = argv[2];
    int sig = atoi(argv[3]);
    long window_ms = atol(argv[4]);

    /* Own process group: the CLI's degraded direct killpg must reach this
     * process and nothing else. */
    if (setpgid(0, 0) != 0) return 5;

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(sig, &sa, NULL) != 0) return 6;

    char buf[128];
    snprintf(buf, sizeof buf, "pid=%d pgid=%d\n", (int)getpid(), (int)getpgrp());
    put(info, buf);

    struct timespec t = { window_ms / 1000, (window_ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) != 0 && errno == EINTR) { }

    snprintf(buf, sizeof buf, "%d\n", (int)deliveries);
    put(count, buf);
    return 0;
}
"##;

/// How long the victim keeps counting after it is armed. Long enough to cover
/// the CLI process spawn plus both delivery paths, short enough to keep the
/// suite quick.
const WINDOW_MS: u64 = 1500;

fn oci_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-oci")
}

/// Compile the victim probe into `dir` (same toolchain pattern as the
/// process-group suite: a static C binary via the first of cc/gcc).
fn build_sigwatch(dir: &Path) -> PathBuf {
    let src = dir.join("sigwatch.c");
    let bin = dir.join("sigwatch");
    fs::write(&src, SIGWATCH_C).unwrap();
    let cc = ["cc", "gcc"]
        .into_iter()
        .find(|c| {
            std::env::var_os("PATH").map_or(false, |paths| {
                std::env::split_paths(&paths).any(|d| d.join(c).is_file())
            })
        })
        .expect("no C compiler (cc/gcc) available to build the signal-counting victim");
    let out = Command::new(cc)
        .args(["-static", "-O0", "-o"])
        .arg(&bin)
        .arg(&src)
        .output()
        .unwrap_or_else(|e| panic!("spawn {cc}: {e}"));
    assert!(
        out.status.success(),
        "sigwatch build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

/// Write the minimal `state.json` `cmd_kill` loads: it only ever reads `pid`
/// (and the surrounding struct must parse).
fn write_state(root: &Path, id: &str, pid: i32) {
    let dir = root.join(id);
    fs::create_dir_all(&dir).unwrap();
    let state = serde_json::json!({
        "ociVersion": "1.0.2",
        "id": id,
        "status": "running",
        "pid": pid,
        "bundle": "/",
        "created": 0,
    });
    fs::write(
        dir.join("state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

/// What the stand-in supervisor does after it has read a complete frame (and,
/// like the daemon, relayed the signal to the victim group).
#[derive(Clone, Copy)]
enum Peer {
    /// Close without a reply: the daemon acted, the reply was lost.
    VanishAfterDelivering,
    /// Answer `{"result":"ok"}`: the healthy round trip.
    AckAfterDelivering,
}

/// Bind `<root>/<fnv16(id)>.sock` and serve exactly one control connection:
/// read to the frame's `\n`, parse it, deliver `signum` to `victim_pgid`
/// exactly as `sandlock-init` would, then behave per `peer`.
///
/// Returns the raw frame it received, so the caller can assert the CLI's wire
/// form byte-for-byte.
fn spawn_stand_in_supervisor(sock: &Path, victim_pgid: i32, peer: Peer) -> std::thread::JoinHandle<String> {
    let listener = UnixListener::bind(sock).expect("bind stand-in supervisor socket");
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("stand-in accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut frame = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).expect("stand-in read");
            assert_ne!(
                n, 0,
                "the client closed before its request's newline delimiter arrived"
            );
            frame.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        let text = String::from_utf8(frame).expect("control frame is UTF-8");
        let cmd: SupervisorCmd =
            serde_json::from_str(text.trim()).expect("stand-in parses the client's control frame");
        match cmd {
            SupervisorCmd::Signal { signum } => {
                let rc = unsafe { libc::killpg(victim_pgid, signum) };
                assert_eq!(
                    rc, 0,
                    "stand-in daemon delivery to pgrp {victim_pgid} failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            other => panic!("expected a signal frame, got {other:?}"),
        }
        if let Peer::AckAfterDelivering = peer {
            stream.write_all(b"{\"result\":\"ok\"}\n").unwrap();
            stream.flush().unwrap();
        }
        text
    })
}

/// A running `sigwatch` process, plus the files it reports through.
struct Victim {
    pid: i32,
    child: Child,
    count_file: PathBuf,
}

fn parse_pid_pgid(s: &str) -> Option<(i32, i32)> {
    let mut pid = None;
    let mut pgid = None;
    for tok in s.split_whitespace() {
        if let Some(v) = tok.strip_prefix("pid=") {
            pid = v.parse().ok();
        } else if let Some(v) = tok.strip_prefix("pgid=") {
            pgid = v.parse().ok();
        }
    }
    Some((pid?, pgid?))
}

/// Arm a victim for `signum` and wait until it has published its pid/pgid.
fn start_victim(dir: &Path, tag: &str, signum: i32) -> Victim {
    let bin = build_sigwatch(dir);
    let info = dir.join(format!("victim-{tag}.info"));
    let count = dir.join(format!("victim-{tag}.count"));
    let child = Command::new(&bin)
        .arg(&info)
        .arg(&count)
        .arg(signum.to_string())
        .arg(WINDOW_MS.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sigwatch");
    let deadline = Instant::now() + Duration::from_secs(10);
    let (pid, pgid) = loop {
        if let Some(ids) = fs::read_to_string(&info).ok().as_deref().and_then(parse_pid_pgid) {
            break ids;
        }
        assert!(
            Instant::now() < deadline,
            "victim never reported its pid/pgid"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        pgid, pid,
        "victim must lead its own process group (pgid {pgid} != pid {pid}); the \
         CLI's killpg(state.pid) fallback would otherwise miss it"
    );
    Victim {
        pid,
        child,
        count_file: count,
    }
}

impl Victim {
    /// Wait out the counting window and return the delivery count.
    fn deliveries(mut self) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match self.child.try_wait().expect("wait for the victim") {
                Some(status) => {
                    assert!(status.success(), "sigwatch exited {status:?}");
                    return fs::read_to_string(&self.count_file)
                        .expect("victim never wrote its delivery count");
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "victim p {} never finished its counting window",
                        self.pid
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
}

/// `sandlock-oci --root <root> kill <id> --all <signal>`; returns the exit code
/// and the captured stderr.
fn kill_all(root: &Path, id: &str, signal: &str) -> (Option<i32>, String) {
    let out = Command::new(oci_bin())
        .arg("--root")
        .arg(root)
        .args(["kill", id, "--all", signal])
        .output()
        .expect("run sandlock-oci kill --all");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A fresh state root plus a fresh victim inside one temp dir.
fn fixture(tmp: &TempDir) -> (PathBuf, PathBuf) {
    let root = tmp.path().join("root");
    let scratch = tmp.path().join("scratch");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&scratch).unwrap();
    (root, scratch)
}

/// 1. The daemon read the frame, relayed the signal and vanished without a
/// reply. The signal must be delivered **once**: the lost reply is a reply
/// failure, not a request failure, so the CLI must not deliver a second time —
/// and must report the error instead of papering over it.
#[test]
fn lost_reply_after_a_delivered_frame_is_not_redelivered() {
    let tmp = TempDir::new().unwrap();
    let (root, scratch) = fixture(&tmp);
    let id = "fup24-lost-reply";
    let rt = libc::SIGRTMIN();

    let victim = start_victim(&scratch, "lost-reply", rt);
    write_state(&root, id, victim.pid);
    let sock = socket_path_in(&root, id);
    let peer = spawn_stand_in_supervisor(&sock, victim.pid, Peer::VanishAfterDelivering);

    let (code, stderr) = kill_all(&root, id, &rt.to_string());
    let frame = peer.join().expect("stand-in supervisor thread");
    let count = victim.deliveries();

    assert_eq!(
        frame,
        format!("{{\"cmd\":\"signal\",\"signum\":{rt}}}\n"),
        "the CLI must send the payload and its newline delimiter as one complete frame"
    );
    assert_eq!(
        count.trim(),
        "1",
        "instance signal {rt} must be delivered exactly once when the daemon acted \
         but its reply was lost; got {count:?} deliveries, i.e. `kill --all` \
         re-delivered a signal the daemon had already relayed (F1.7/SECE-6)"
    );
    assert_eq!(
        code,
        Some(1),
        "a lost reply must be reported to the caller, not swallowed (exit {code:?}, \
         stderr {stderr:?})"
    );
    assert_eq!(
        stderr,
        "Error: the supervisor received the request but the reply was lost: parse \
         supervisor reply: EOF while parsing a value at line 1 column 0\n",
        "the caller must get the send failure verbatim"
    );
}

/// 2. The socket is unreachable, so the daemon cannot have received the
/// request: the degraded direct `killpg` fallback must still run, or
/// `kill --all` would silently do nothing exactly when the daemon is gone.
/// Both shapes of "unreachable" are covered — the socket file is absent
/// (ENOENT) and the socket file is stale with no listener (ECONNREFUSED, what
/// a SIGKILLed supervisor leaves behind).
#[test]
fn unreachable_socket_still_falls_back_to_a_direct_group_delivery() {
    let tmp = TempDir::new().unwrap();
    let (root, scratch) = fixture(&tmp);
    let rt = libc::SIGRTMIN();

    for (id, stale_socket) in [
        ("fup24-no-socket-file", false),
        ("fup24-refused", true),
    ] {
        let victim = start_victim(&scratch, id, rt);
        write_state(&root, id, victim.pid);
        let sock = socket_path_in(&root, id);
        if stale_socket {
            // A supervisor that was SIGKILLed leaves its socket file behind.
            let listener = UnixListener::bind(&sock).unwrap();
            drop(listener);
        }

        let (code, stderr) = kill_all(&root, id, &rt.to_string());
        let count = victim.deliveries();

        assert_eq!(
            count.trim(),
            "1",
            "with no reachable daemon (id {id}, stale socket: {stale_socket}) a \
             `kill --all` must still deliver the signal through the direct killpg \
             fallback; got {count:?} deliveries. The fallback is the only path that \
             keeps `kill --all` from silently doing nothing once the daemon is gone"
        );
        assert_eq!(
            code,
            Some(0),
            "the degraded fallback is still a delivered signal (exit {code:?}, \
             stderr {stderr:?})"
        );
        assert_eq!(
            stderr, "",
            "the fallback path must not report an error (id {id})"
        );
    }
}

/// 3. The healthy round trip is unchanged: one frame, one delivery, exit 0.
#[test]
fn normal_round_trip_delivers_exactly_once() {
    let tmp = TempDir::new().unwrap();
    let (root, scratch) = fixture(&tmp);
    let id = "fup24-ok";
    let rt = libc::SIGRTMIN();

    let victim = start_victim(&scratch, "ok", rt);
    write_state(&root, id, victim.pid);
    let sock = socket_path_in(&root, id);
    let peer = spawn_stand_in_supervisor(&sock, victim.pid, Peer::AckAfterDelivering);

    let (code, stderr) = kill_all(&root, id, &rt.to_string());
    let frame = peer.join().expect("stand-in supervisor thread");
    let count = victim.deliveries();

    assert_eq!(
        frame,
        format!("{{\"cmd\":\"signal\",\"signum\":{rt}}}\n"),
        "the CLI's healthy control frame is unchanged"
    );
    assert_eq!(
        count.trim(),
        "1",
        "a replied instance signal is delivered exactly once; got {count:?}"
    );
    assert_eq!(
        code,
        Some(0),
        "an answered `kill --all` must exit 0 (stderr {stderr:?})"
    );
    assert_eq!(stderr, "", "the healthy path must not write to stderr");
}
