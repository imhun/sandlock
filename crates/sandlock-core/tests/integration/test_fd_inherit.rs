//! SL-4 (fork-plan-2026-09 F1.1): control fds mapped onto a confined child
//! must be close-on-exec so user processes the child execs (the OCI workload
//! under `sandlock-init`) never inherit the control channel, while stdio
//! (0/1/2) stays inheritable.
//!
//! The core integration crate cannot run sandlock-oci's real init loop, so the
//! OCI shape is expressed with the same wiring the OCI supervisor uses
//! (`crates/sandlock-oci/src/supervisor.rs:340-370`):
//! `create_with_in_child_main` maps the child end of a socketpair onto fd 3
//! (`CONTROL_FD`) and an in-process entrypoint plays init's role — fork+exec
//! the probe workload, then relay the verdict over a result pipe mapped onto
//! fd 4.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;

use sandlock_core::{Sandbox, StdioMode};

/// Control-socket fd inside the confined child (mirrors oci `CONTROL_FD = 3`).
const CONTROL_FD: i32 = 3;
/// Result-pipe write end mapped into the confined child.
const RESULT_FD: i32 = 4;

fn base_policy() -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap()
}

/// Duplicate `fd` onto the first free number >= `min` with `F_DUPFD` (the copy
/// has no `FD_CLOEXEC`). This keeps the extra-fd *source* away from the fixed
/// 3/4 targets so `dup2`/`dup3` never degrade into an `oldfd == newfd`
/// no-op, which would silently preserve the source's CLOEXEC state.
fn relocate_above(fd: i32, min: i32) -> i32 {
    let hi = unsafe { libc::fcntl(fd, libc::F_DUPFD, min) };
    assert!(hi >= 0, "F_DUPFD failed: {}", std::io::Error::last_os_error());
    hi
}

/// In-process confined entrypoint (init role): write `bytes` to the result
/// pipe and exit the confined child.
fn report(bytes: &[u8]) -> ! {
    unsafe {
        libc::write(RESULT_FD, bytes.as_ptr() as *const libc::c_void, bytes.len());
        libc::_exit(0);
    }
}

/// Init-role entry for the leak test: fork + exec a probe workload that
/// answers "can a user process still readlink `/proc/self/fd/3`?" and relay
/// the verdict. The probe exits 0 when fd 3 survived the exec (today's leak)
/// and 1 when it did not.
fn exec_probe_entry() {
    // No /dev/null redirect: Landlock grants the sandbox only read on /dev, so
    // a write redirect would fail before readlink ever ran and would fake the
    // "absent" verdict. Capture the output instead — the assignment's exit
    // status is readlink's own (0 when fd 3 survived the exec, 1 when it did
    // not), and the captured text never reaches the test log.
    let probe = "if l=$(readlink /proc/self/fd/3 2>&1); then exit 0; else exit 1; fi";
    let sh = CString::new("sh").unwrap();
    let flag = CString::new("-c").unwrap();
    let script = CString::new(probe).unwrap();
    let argv = [sh.as_ptr(), flag.as_ptr(), script.as_ptr(), std::ptr::null()];
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            report(b"probe_failed=fork\n");
        } else if pid == 0 {
            // User workload: sh is exec'd with the confined child's fd table,
            // so it sees the control socket exactly when FD_CLOEXEC is absent.
            libc::execvp(argv[0], argv.as_ptr());
            libc::_exit(127);
        }
        let mut status = 0i32;
        if libc::waitpid(pid, &mut status, 0) < 0 {
            report(b"probe_failed=wait\n");
        }
        if libc::WIFEXITED(status) {
            match libc::WEXITSTATUS(status) {
                0 => report(b"fd3_visible=yes\n"),
                1 => report(b"fd3_visible=no\n"),
                127 => report(b"probe_failed=exec\n"),
                _ => report(b"probe_failed=other\n"),
            }
        }
        report(b"probe_failed=signal\n");
    }
}

/// Init-role entry for the CLOEXEC-flag test: report whether fd 3 carries
/// `FD_CLOEXEC` inside the confined child itself (`fcntl(F_GETFD)` — the
/// pre-exec equivalent of `fdinfo` no longer listing inheritable flags).
fn check_cloexec_entry() {
    unsafe {
        let flags = libc::fcntl(CONTROL_FD, libc::F_GETFD);
        if flags >= 0 && (flags & libc::FD_CLOEXEC) != 0 {
            report(b"fd3_cloexec=yes\n");
        } else {
            report(b"fd3_cloexec=no\n");
        }
    }
}

/// Run `entry` as the confined in-process PID-1 with the child end of a
/// socketpair mapped onto [`CONTROL_FD`] and a result-pipe write end mapped
/// onto [`RESULT_FD`]. Returns the daemon socket end (kept open for the
/// sandbox's lifetime), the entrypoint's report, and the sandbox.
async fn spawn_control_sandbox(entry: fn(), name: &str) -> (UnixStream, String, Sandbox) {
    let (daemon_ctl, child_ctl) = UnixStream::pair().unwrap();
    let child_ctl_src = relocate_above(child_ctl.as_raw_fd(), 10);
    drop(child_ctl);
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let res_w = relocate_above(fds[1], 10);
    unsafe {
        libc::close(fds[1]);
    }
    let res_r = fds[0];

    let mut sb = base_policy().with_name(name);
    sb.create_with_in_child_main(
        name,
        vec![(CONTROL_FD, child_ctl_src), (RESULT_FD, res_w)],
        entry,
    )
    .await
    .unwrap();
    // The confined child holds its own dup'd copies; close ours so EOF on the
    // result pipe tracks the entrypoint exiting.
    unsafe {
        libc::close(child_ctl_src);
        libc::close(res_w);
    }
    sb.start().unwrap();
    let out = tokio::task::spawn_blocking(move || {
        let mut buf = String::new();
        let mut f = unsafe { File::from_raw_fd(res_r) };
        f.read_to_string(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();
    (daemon_ctl, out, sb)
}

/// A control socket mapped onto fd 3 of the confined child must not survive
/// the exec of a user process: the exec'd probe's `readlink /proc/self/fd/3`
/// has to fail (probe exits 1 → `fd3_visible=no`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_control_socket_not_inherited_by_user_process() {
    let (_daemon_ctl, out, mut sb) =
        spawn_control_sandbox(exec_probe_entry, "fd-inherit-control").await;
    assert_eq!(out, "fd3_visible=no\n");
    let result = sb.wait().await.unwrap();
    assert_eq!(result.code(), Some(0), "confined entrypoint must exit cleanly");
}

/// The mapped extra fd must carry `FD_CLOEXEC` inside the confined child, so
/// the control socket is never handed to anything the child execs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_extra_fds_are_cloexec() {
    let (_daemon_ctl, out, mut sb) =
        spawn_control_sandbox(check_cloexec_entry, "fd-inherit-cloexec").await;
    assert_eq!(out, "fd3_cloexec=yes\n");
    let result = sb.wait().await.unwrap();
    assert_eq!(result.code(), Some(0), "confined entrypoint must exit cleanly");
}

/// Stdio guard: the SL-4 fix (CLOEXEC on extra-fd targets >= 3 plus the
/// init-side belt on the control fd) must not over-close the exec'd user
/// process's stdin/stdout/stderr — all three stay usable across the exec.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stdio_still_inheritable() {
    let mut sb = base_policy().with_name("fd-inherit-stdio");
    let mut child = sb
        .popen(
            &[
                "sh",
                "-c",
                "IFS= read -r line; printf 'in:%s\\n' \"$line\"; printf 'err-ok\\n' >&2",
            ],
            StdioMode::Piped,
            StdioMode::Piped,
            StdioMode::Piped,
        )
        .await
        .unwrap();
    let mut stdin = File::from(child.take_stdin().expect("stdin pipe"));
    let mut stdout = File::from(child.take_stdout().expect("stdout pipe"));
    let mut stderr = File::from(child.take_stderr().expect("stderr pipe"));
    stdin.write_all(b"ping\n").unwrap();
    drop(stdin); // EOF on stdin
    let mut out = String::new();
    stdout.read_to_string(&mut out).unwrap();
    let mut err = String::new();
    stderr.read_to_string(&mut err).unwrap();
    assert_eq!(out, "in:ping\n");
    assert_eq!(err, "err-ok\n");
    let res = child.wait().await.unwrap();
    assert_eq!(res.code(), Some(0));
}
