//! PID namespace (`SandboxBuilder::pid_ns`) integration tests.
//!
//! The sandbox's first process must become PID 1 inside its own namespace:
//! `kill(pid, 0)` probes of host / other-sandbox processes return `ESRCH`,
//! in-namespace signaling still works, `/proc` lists only the sandbox's own
//! processes under their namespace pids, the stat family never resolves a
//! sandbox-ns pid against the host table, and the leader-group operations
//! (pause/resume/checkpoint/throttle/tty) keep working.

use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use sandlock_core::instance::{ExecStdio, InstancePhase, SandboxInstance};
use sandlock_core::Sandbox;

fn exec_base_policy() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .pid_ns(true)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
}

fn defunct_children_of(parent: i32) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_string_lossy().parse::<i32>().ok() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some(after) = stat.rsplit_once(") ") else {
            continue;
        };
        let mut fields = after.1.split_whitespace();
        let state = fields.next();
        let ppid = fields.next().and_then(|v| v.parse::<i32>().ok());
        if state == Some("Z") && ppid == Some(parent) {
            out.push(pid);
        }
    }
    out
}

fn poll_until_async(mut cond: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// F5.3 (M3 S4): pid_ns + exec-instance coexistence — the confined
/// `sandlock-init` is namespace PID 1 (the S4 "internal reaper"). A
/// workload's exit is reaped by PID 1 and must **not** take the instance
/// tree: the session stays Live, adopted orphans (backgrounded descendants
/// of an exited child) are reaped by PID 1 without defunct accumulation,
/// new execs keep working, and only `shutdown` ends the box.
///
/// The instance-facing child pids must be the children's **host** pids
/// (each child's `/proc/<pid>/stat` ppid is the init host pid), so the
/// host-side registry/pidfd/killpg machinery — which lives outside the
/// namespace — can address them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_init_reaps_ns_pid_1_exit() {
    let seq = std::process::id() as u64 * 1000 + 9;
    let marker_a = format!("/tmp/sandlock-f5-reap-a-{seq}");
    let marker_g = format!("/tmp/sandlock-f5-reap-g-{seq}");

    let mut inst = SandboxInstance::launch_exec_only(
        exec_base_policy().build().unwrap().with_name("f5-init-reaps"),
    )
    .await
    .expect("launch pid-ns exec-only session");

    // A is the session's first workload (in a legacy per-command pid-ns
    // sandbox it would have been ns PID 1 and its exit would have taken the
    // tree down). It records its namespace pid, then exits after 2 s.
    let a = inst
        .exec(
            &[
                "sh",
                "-c",
                &format!("echo $$ > {marker_a}; exec sleep 2"),
            ],
            ExecStdio::Piped,
        )
        .await
        .expect("exec A (first workload)");

    let init_pid = inst
        .control_pid()
        .expect("exec session exposes the confined init host pid");
    assert!(
        poll_until_async(|| std::path::Path::new(&marker_a).exists(), Duration::from_secs(10)),
        "A must record its namespace pid"
    );
    // The announced pid must be a live host process whose parent is init —
    // host-side pids, not namespace pids (RED before F5.3 translation).
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", a.pid)).expect(
        "the exec handle must carry a live host pid (namespace pids are not \
         addressable from the host)",
    );
    let after = stat.rsplit_once(") ").expect("stat format").1;
    let ppid: i32 = after
        .split_whitespace()
        .nth(1)
        .expect("ppid field")
        .parse()
        .expect("ppid numeric");
    assert_eq!(
        ppid, init_pid,
        "A's host pid must be a direct child of the confined init (ns PID 1)"
    );
    assert_eq!(inst.phase(), InstancePhase::Live);

    // B: exits immediately, leaving a backgrounded grandchild behind — the
    // kernel reparents it to ns PID 1 (init), which must reap it.
    let b = inst
        .exec(
            &["sh", "-c", &format!("sleep 2 & echo $! > {marker_g}; exit 0")],
            ExecStdio::Piped,
        )
        .await
        .expect("exec B (leaves an adopted orphan)");

    let a_status = inst.wait_child(a.child_id).await.expect("wait A");
    assert_eq!(a_status, sandlock_core::result::ExitStatus::Code(0));
    let b_status = inst.wait_child(b.child_id).await.expect("wait B");
    assert_eq!(b_status, sandlock_core::result::ExitStatus::Code(0));

    // A and B are reaped by init: no defunct may remain under ns PID 1 once
    // their exits settle, and the backgrounded grandchild is adopted and
    // reaped the same way (bounded by the grandchild's own 2 s lifetime).
    assert!(
        poll_until_async(
            || defunct_children_of(init_pid).is_empty(),
            Duration::from_secs(10),
        ),
        "init (ns PID 1) must reap every exited child; defuncts under it: {:?}",
        defunct_children_of(init_pid)
    );
    let _ = std::fs::read_to_string(&marker_g); // grandchild ns pid observed by B

    // The tree survives both exits: the session is Live, a new exec works,
    // and only shutdown ends the box.
    assert_eq!(inst.phase(), InstancePhase::Live);
    let c = inst
        .exec(&["sh", "-c", "exit 0"], ExecStdio::Piped)
        .await
        .expect("exec C after A and B exited (tree not taken)");
    let c_status = inst.wait_child(c.child_id).await.expect("wait C");
    assert_eq!(c_status, sandlock_core::result::ExitStatus::Code(0));

    inst.shutdown().await.expect("shutdown");
    assert_eq!(inst.phase(), InstancePhase::ShutDown);
    let _ = std::fs::remove_file(&marker_a);
    let _ = std::fs::remove_file(&marker_g);
}

/// Runs inside the sandbox after confinement. `PROBE_HOST_PID` names a host
/// process outside the sandbox (the test process or another sandbox's
/// leader). Writes one result line per probe to fd 3.
fn pid_ns_probe() {
    let host_pid: i32 = match std::env::var("PROBE_HOST_PID") {
        Ok(v) => v.parse().unwrap_or(0),
        Err(_) => 0,
    };
    let mut out = unsafe { std::fs::File::from_raw_fd(3) };
    let mut line = String::new();

    let kill_errno = |pid: i32| {
        let r = unsafe { libc::kill(pid, 0) };
        if r == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        }
    };

    // Never probe pid <= 0 (kill(-1, 0) would signal every process).
    if host_pid > 0 {
        line.push_str(&format!("kill_host_errno={}\n", kill_errno(host_pid)));
    } else {
        line.push_str("kill_host_errno=probe_misconfigured\n");
    }

    // A child inside the sandbox: signaling it (and the leader, ns pid 1)
    // must still work — the namespace isolates pids, not own processes.
    let child = unsafe { libc::fork() };
    if child < 0 {
        line.push_str(&format!(
            "fork_errno={}\n",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        ));
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
        unsafe { libc::_exit(1) };
    }
    if child == 0 {
        loop {
            unsafe { libc::pause() };
        }
    }
    line.push_str(&format!("kill_child_errno={}\n", kill_errno(child)));
    line.push_str(&format!("kill_leader_errno={}\n", kill_errno(1)));

    // /proc must show the sandbox's own processes under namespace pids
    // (1 and the child) and nothing else — in particular no host pids.
    let mut proc_pids: Vec<i32> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() {
                proc_pids.push(p);
            }
        }
    }
    proc_pids.sort_unstable();
    line.push_str(&format!("proc_pids={:?}\n", proc_pids));
    line.push_str(&format!(
        "proc_has_host_pid={}\n",
        host_pid > 0 && proc_pids.contains(&host_pid)
    ));

    // /proc/1/status must resolve to the sandbox leader (translated to its
    // host pid by the supervisor), not to host pid 1. The translation is
    // proven by exact fields: `Pid:` must equal the leader's host pid (the
    // supervisor reads /proc/<host_pid>/status) and `Name:` must be the
    // in-process entry's comm — any other process (host pid 1 included)
    // would fail one of the two.
    let status = std::fs::read_to_string("/proc/1/status").unwrap_or_default();
    let mut status_pid = String::new();
    let mut status_name = String::new();
    for l in status.lines() {
        if let Some(v) = l.strip_prefix("Pid:") {
            status_pid = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("Name:") {
            status_name = v.trim().to_string();
        }
    }
    line.push_str(&format!("proc1_status_pid={}\n", status_pid));
    line.push_str(&format!("proc1_status_name={}\n", status_name));

    unsafe { libc::kill(child, libc::SIGKILL) };
    let mut st = 0;
    unsafe { libc::waitpid(child, &mut st, 0) };

    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
    unsafe { libc::_exit(0) };
}

/// Runs inside the sandbox: the stat family must never resolve a numeric
/// `/proc/<ns_pid>/…` path against the host table (EACCES), while non-numeric
/// `/proc` paths (the directory itself, `/proc/self/…`) keep working.
fn stat_family_probe() {
    let mut out = unsafe { std::fs::File::from_raw_fd(3) };
    let mut line = String::new();
    let proc1_status = b"/proc/1/status\0";
    let proc2_status = b"/proc/2/status\0";
    let proc1_exe = b"/proc/1/exe\0";
    let proc_dir = b"/proc\0";
    let self_status = b"/proc/self/status\0";

    let errno_of = |r: libc::c_int| -> i32 {
        if r == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        }
    };

    // newfstatat via libc::stat — the common spelling.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    line.push_str(&format!(
        "stat_proc1_status_errno={}\n",
        errno_of(unsafe { libc::stat(proc1_status.as_ptr() as *const libc::c_char, &mut st) })
    ));
    line.push_str(&format!(
        "stat_proc2_status_errno={}\n",
        errno_of(unsafe { libc::stat(proc2_status.as_ptr() as *const libc::c_char, &mut st) })
    ));
    line.push_str(&format!(
        "lstat_proc1_status_errno={}\n",
        errno_of(unsafe { libc::lstat(proc1_status.as_ptr() as *const libc::c_char, &mut st) })
    ));

    // statx (raw syscall: libc::statx is not exposed on every libc).
    let mut stx = [0u8; 256];
    let stx_ret = unsafe {
        libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            proc1_status.as_ptr() as *const libc::c_char,
            0,
            libc::STATX_BASIC_STATS,
            stx.as_mut_ptr(),
        )
    };
    line.push_str(&format!(
        "statx_proc1_status_errno={}\n",
        errno_of(stx_ret as libc::c_int)
    ));

    // access / faccessat / faccessat2.
    line.push_str(&format!(
        "access_proc1_status_errno={}\n",
        errno_of(unsafe { libc::access(proc1_status.as_ptr() as *const libc::c_char, libc::R_OK) })
    ));
    let fac_ret = unsafe {
        libc::syscall(
            libc::SYS_faccessat,
            libc::AT_FDCWD,
            proc1_status.as_ptr() as *const libc::c_char,
            libc::R_OK,
            0,
        )
    };
    line.push_str(&format!(
        "faccessat_proc1_status_errno={}\n",
        errno_of(fac_ret as libc::c_int)
    ));
    let fac2_ret = unsafe {
        libc::syscall(
            439, // SYS_faccessat2 (same number on x86_64/aarch64/riscv64)
            libc::AT_FDCWD,
            proc1_status.as_ptr() as *const libc::c_char,
            libc::R_OK,
            0,
        )
    };
    line.push_str(&format!(
        "faccessat2_proc1_status_errno={}\n",
        errno_of(fac2_ret as libc::c_int)
    ));

    // readlink of a magic link must be denied too.
    let mut buf = [0u8; 256];
    line.push_str(&format!(
        "readlink_proc1_exe_errno={}\n",
        errno_of(
            unsafe {
                libc::readlink(proc1_exe.as_ptr() as *const libc::c_char, buf.as_mut_ptr() as *mut libc::c_char, buf.len())
            } as libc::c_int
        )
    ));

    // Controls: non-numeric /proc paths are not gated and keep working.
    line.push_str(&format!(
        "stat_proc_dir_errno={}\n",
        errno_of(unsafe { libc::stat(proc_dir.as_ptr() as *const libc::c_char, &mut st) })
    ));
    line.push_str(&format!(
        "stat_self_status_errno={}\n",
        errno_of(unsafe { libc::stat(self_status.as_ptr() as *const libc::c_char, &mut st) })
    ));

    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
    unsafe { libc::_exit(0) };
}

/// Runs inside the sandbox: spawns a thread, then opens `/proc/<ns_tid>/…`
/// by the thread's namespace tid. The on-behalf translation must resolve the
/// thread (exact `Name:`), and the thread tid must not appear in the
/// top-level `/proc` listing (only tgids do).
fn thread_probe() {
    static THREAD_NS_TID: AtomicI32 = AtomicI32::new(0);
    let mut out = unsafe { std::fs::File::from_raw_fd(3) };
    let mut line = String::new();
    let thread_name: &'static [u8] = b"pidns-thread\0";

    std::thread::spawn(|| {
        unsafe {
            libc::prctl(libc::PR_SET_NAME, thread_name.as_ptr() as libc::c_ulong, 0, 0, 0);
        }
        THREAD_NS_TID.store(unsafe { libc::gettid() }, Ordering::Release);
        loop {
            unsafe { libc::pause() };
        }
    });

    // Wait for the thread's namespace tid.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ns_tid = 0i32;
    while Instant::now() < deadline {
        let t = THREAD_NS_TID.load(Ordering::Acquire);
        if t > 0 {
            ns_tid = t;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if ns_tid <= 0 {
        let _ = out.write_all(b"thread_ns_tid=timeout\n");
        let _ = out.flush();
        unsafe { libc::_exit(1) };
    }
    line.push_str(&format!("thread_ns_tid={}\n", ns_tid));

    let status = std::fs::read_to_string(format!("/proc/{}/status", ns_tid)).unwrap_or_default();
    let mut status_name = String::new();
    let mut status_pid = String::new();
    for l in status.lines() {
        if let Some(v) = l.strip_prefix("Name:") {
            status_name = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("Pid:") {
            status_pid = v.trim().to_string();
        }
    }
    line.push_str(&format!("thread_status_name={}\n", status_name));
    line.push_str(&format!("thread_status_pid={}\n", status_pid));

    // A bogus ns pid must not translate: EACCES, never a host process.
    let bogus = std::fs::read_to_string("/proc/99999/status");
    line.push_str(&format!(
        "bogus_pid_open_errno={}\n",
        match bogus {
            Ok(_) => 0,
            Err(e) => e.raw_os_error().unwrap_or(-1),
        }
    ));

    // Top-level /proc listing: only the leader's tgid (1); thread tids are
    // not top-level entries.
    let mut proc_pids: Vec<i32> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() {
                proc_pids.push(p);
            }
        }
    }
    proc_pids.sort_unstable();
    line.push_str(&format!("proc_pids={:?}\n", proc_pids));

    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
    unsafe { libc::_exit(0) };
}

/// Runs inside the sandbox: CPU-bound spin for a fixed iteration count.
/// `THROTTLE_SPIN_ITERS` is set by the test; elapsed wall time is reported
/// so the throttle (SIGSTOP/SIGCONT on the leader's group) measurably slows
/// the in-namespace leader.
fn throttle_spin_probe() {
    let iters: u64 = std::env::var("THROTTLE_SPIN_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000_000);
    let start = Instant::now();
    let mut x: u64 = 0;
    for _ in 0..iters {
        x = x.wrapping_add(1);
    }
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let mut out = unsafe { std::fs::File::from_raw_fd(3) };
    let _ = writeln!(out, "spin_elapsed_ms={}", elapsed_ms);
    let _ = writeln!(out, "spin_checksum={}", x);
    let _ = out.flush();
    unsafe { libc::_exit(0) };
}

/// Runs inside a default (pid_ns=false) sandbox: host pids stay visible and
/// directly addressable — `kill(host_pid, 0)` must NOT return ESRCH, and
/// `/proc/<own host pid>/status` must be openable under the host pid.
fn default_off_probe() {
    let host_pid = std::process::id() as i32;
    // The test process's pid, passed from outside — the kill probe target.
    let probe_host_pid: i32 = std::env::var("PROBE_HOST_PID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut out = unsafe { std::fs::File::from_raw_fd(3) };
    let mut line = String::new();
    line.push_str(&format!("own_pid={}\n", host_pid));

    let kill_errno = |pid: i32| {
        let r = unsafe { libc::kill(pid, 0) };
        if r == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        }
    };
    // The host test process lives in the same (shared) PID namespace, so
    // probing it must succeed (0) or hit EPERM — never ESRCH.
    if probe_host_pid > 0 {
        line.push_str(&format!("kill_host_errno={}\n", kill_errno(probe_host_pid)));
    } else {
        line.push_str("kill_host_errno=probe_misconfigured\n");
    }

    // The first notified syscall registers this process with the supervisor;
    // opening /proc/<own host pid>/status proves host-pid addressing works
    // when the PID namespace is off. Emit the exact `Pid:` field so the test
    // can assert it equals the host pid.
    let status = std::fs::read_to_string(format!("/proc/{}/status", host_pid));
    let own_status_pid = status
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Pid:").map(|v| v.trim().to_string()))
        })
        .unwrap_or_default();
    line.push_str(&format!("own_status_pid={}\n", own_status_pid));

    let mut proc_pids: Vec<i32> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Ok(p) = e.file_name().to_string_lossy().parse::<i32>() {
                proc_pids.push(p);
            }
        }
    }
    proc_pids.sort_unstable();
    line.push_str(&format!("proc_pids={:?}\n", proc_pids));
    line.push_str(&format!(
        "proc_has_own={}\n",
        proc_pids.contains(&host_pid)
    ));

    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
    unsafe { libc::_exit(0) };
}

/// Build a sandbox running `entry` in-process with a result pipe on fd 3,
/// start it, and read everything the probe wrote. Returns (output, sandbox).
async fn run_probe(
    entry: fn(),
    name: &str,
    env: &[(&str, &str)],
    pid_ns: bool,
    fs_read: &[&str],
) -> (String, Sandbox) {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let (r, w) = (fds[0], fds[1]);
    let mut b = Sandbox::builder().pid_ns(pid_ns);
    for (k, v) in env {
        b = b.env_var(*k, *v);
    }
    for p in fs_read {
        b = b.fs_read(*p);
    }
    let mut sb = b.build().unwrap();
    sb.create_with_in_child_main(name, vec![(3, w)], entry)
        .await
        .unwrap();
    // The child got its own dup of `w` at fd 3; close ours so the read end
    // sees EOF when the probe exits.
    unsafe { libc::close(w) };
    sb.start().unwrap();
    // Read the probe's output off the runtime: a synchronous pipe read here
    // would starve the single-threaded tokio executor that pumps the seccomp
    // supervisors (the sandbox's own popen docs warn about exactly this).
    let buf = tokio::task::spawn_blocking(move || {
        let mut buf = String::new();
        let mut f = unsafe { std::fs::File::from_raw_fd(r) };
        f.read_to_string(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();
    (buf, sb)
}

/// The sandbox's own process tree must be invisible to `kill(pid, 0)`
/// probes from outside its PID namespace... and, conversely, the host must
/// be invisible from inside: `kill(host_pid, 0)` must return ESRCH.
#[tokio::test]
async fn pid_ns_kill_host_pid_is_esrch() {
    let host_pid = std::process::id() as i32;
    let (output, mut sb) = run_probe(
        pid_ns_probe,
        "pidns-probe",
        &[("PROBE_HOST_PID", &host_pid.to_string())],
        true,
        &["/proc"],
    )
    .await;
    let result = sb.wait().await.unwrap();
    assert!(result.success(), "sandbox failed: {:?}\nprobe output:\n{}", result.exit_status, output);

    let mut kill_host = None;
    let mut kill_child = None;
    let mut kill_leader = None;
    for l in output.lines() {
        if let Some(v) = l.strip_prefix("kill_host_errno=") {
            kill_host = Some(v);
        } else if let Some(v) = l.strip_prefix("kill_child_errno=") {
            kill_child = Some(v);
        } else if let Some(v) = l.strip_prefix("kill_leader_errno=") {
            kill_leader = Some(v);
        }
    }
    assert_eq!(kill_host, Some("3"), "kill(host_pid, 0) must be ESRCH, got {:?}:\n{}", kill_host, output);
    assert_eq!(kill_child, Some("0"), "kill(own child, 0) must succeed, got {:?}:\n{}", kill_child, output);
    assert_eq!(kill_leader, Some("0"), "kill(own leader pid 1, 0) must succeed, got {:?}:\n{}", kill_leader, output);
}

/// `/proc` in the sandbox lists only the sandbox's own processes, renamed
/// to their namespace pids — host pids are not enumerable, and `/proc/1`
/// resolves to the sandbox leader (proven by the exact `Pid:`/`Name:`
/// fields of its status, not a substring match).
#[tokio::test]
async fn pid_ns_procfs_view_is_renumbered() {
    let host_pid = std::process::id() as i32;
    let (output, mut sb) = run_probe(
        pid_ns_probe,
        "pidns-probe",
        &[("PROBE_HOST_PID", &host_pid.to_string())],
        true,
        &["/proc"],
    )
    .await;
    let result = sb.wait().await.unwrap();
    assert!(result.success(), "sandbox failed: {:?}\nprobe output:\n{}", result.exit_status, output);

    let mut proc_pids = None;
    let mut proc_has_host_pid = None;
    let mut proc1_status_pid = None;
    let mut proc1_status_name = None;
    for l in output.lines() {
        if let Some(v) = l.strip_prefix("proc_pids=") {
            proc_pids = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("proc_has_host_pid=") {
            proc_has_host_pid = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("proc1_status_pid=") {
            proc1_status_pid = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("proc1_status_name=") {
            proc1_status_name = Some(v.to_string());
        }
    }
    // Leader (1) + the fork child (2). Any additional numeric entry would
    // be a host pid leaking through the filter.
    assert_eq!(
        proc_pids.as_deref(),
        Some("[1, 2]"),
        "unexpected /proc pid set:\n{}",
        output
    );
    assert_eq!(proc_has_host_pid.as_deref(), Some("false"));
    // The translated /proc/1/status must be the leader's: its Pid: equals
    // the leader's host pid and its Name: is the in-process entry's comm.
    let leader_str = sb.pid().expect("leader pid").to_string();
    assert_eq!(
        proc1_status_pid.as_deref(),
        Some(leader_str.as_str()),
        "status Pid: must equal the sandbox leader's host pid:\n{}",
        output
    );
    assert_eq!(
        proc1_status_name.as_deref(),
        Some("pidns-probe"),
        "status Name: must be the probe's comm:\n{}",
        output
    );
}

/// The stat family must never resolve a numeric `/proc/<ns_pid>/…` path
/// against the host table: `stat`/`statx`/`access`/`readlink` all return
/// EACCES, while non-numeric `/proc` paths (the directory, `/proc/self/…`)
/// keep working. This closes the host-pid collision leak that a direct
/// kernel resolution would create (host pids 1..N all exist).
#[tokio::test]
async fn pid_ns_stat_family_denied() {
    let (output, mut sb) = run_probe(stat_family_probe, "pidns-stat-probe", &[], true, &["/proc"]).await;
    let result = sb.wait().await.unwrap();
    assert!(result.success(), "sandbox failed: {:?}\nprobe output:\n{}", result.exit_status, output);

    let mut got = std::collections::HashMap::new();
    for l in output.lines() {
        if let Some((k, v)) = l.split_once('=') {
            got.insert(k.to_string(), v.to_string());
        }
    }
    for key in [
        "stat_proc1_status_errno",
        "stat_proc2_status_errno",
        "lstat_proc1_status_errno",
        "statx_proc1_status_errno",
        "access_proc1_status_errno",
        "faccessat_proc1_status_errno",
        "faccessat2_proc1_status_errno",
        "readlink_proc1_exe_errno",
    ] {
        assert_eq!(
            got.get(key).map(String::as_str),
            Some("13"),
            "{key} must be EACCES (13):\n{}",
            output
        );
    }
    assert_eq!(
        got.get("stat_proc_dir_errno").map(String::as_str),
        Some("0"),
        "stat(/proc) must still work:\n{}",
        output
    );
    assert_eq!(
        got.get("stat_self_status_errno").map(String::as_str),
        Some("0"),
        "stat(/proc/self/status) must still work:\n{}",
        output
    );
}

/// A multi-threaded workload addresses its threads by namespace tid
/// (`/proc/<ns_tid>/…`); the on-behalf translation must resolve threads too,
/// and thread tids must not appear in the top-level `/proc` listing.
#[tokio::test]
async fn pid_ns_thread_tid_open() {
    let (output, mut sb) = run_probe(thread_probe, "pidns-thread-probe", &[], true, &["/proc"]).await;
    let result = sb.wait().await.unwrap();
    assert!(result.success(), "sandbox failed: {:?}\nprobe output:\n{}", result.exit_status, output);

    let mut thread_ns_tid = None;
    let mut thread_status_name = None;
    let mut thread_status_pid = None;
    let mut bogus_errno = None;
    let mut proc_pids = None;
    for l in output.lines() {
        if let Some(v) = l.strip_prefix("thread_ns_tid=") {
            thread_ns_tid = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("thread_status_name=") {
            thread_status_name = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("thread_status_pid=") {
            thread_status_pid = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("bogus_pid_open_errno=") {
            bogus_errno = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("proc_pids=") {
            proc_pids = Some(v.to_string());
        }
    }
    let ns_tid: i32 = thread_ns_tid
        .as_deref()
        .and_then(|v| v.parse().ok())
        .expect("thread ns tid missing");
    assert!(ns_tid > 1, "thread must have a namespace tid above the leader:\n{output}");
    assert_eq!(
        thread_status_name.as_deref(),
        Some("pidns-thread"),
        "translated /proc/<ns_tid>/status must be the thread's own:\n{}",
        output
    );
    let thread_host_pid: i32 = thread_status_pid
        .as_deref()
        .and_then(|v| v.parse().ok())
        .expect("thread status Pid: missing");
    assert!(
        thread_host_pid > 0 && thread_host_pid != sb.pid().expect("leader pid"),
        "thread host pid must differ from the leader's:\n{}",
        output
    );
    // Unknown ns pids must not translate to a host process.
    assert_eq!(bogus_errno.as_deref(), Some("13"), "bogus ns pid open must be EACCES:\n{output}");
    // Only the leader's tgid appears at /proc top level.
    assert_eq!(proc_pids.as_deref(), Some("[1]"), "thread tids must not appear at /proc top level:\n{output}");
}

/// Signal isolation between two pid-namespace sandboxes: a process in one
/// sandbox cannot even detect a process in another (`kill(pid, 0)` →
/// ESRCH), while the same-sandbox probes stay healthy (covered by
/// [`pid_ns_kill_host_pid_is_esrch`]).
#[tokio::test]
async fn pid_ns_cross_sandbox_signal_isolation() {
    // Sandbox B: a live workload whose leader host pid we can hand to A.
    let mut sb_b = Sandbox::builder()
        .pid_ns(true)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/proc")
        .build()
        .unwrap();
    sb_b.create(&["sleep", "30"]).await.unwrap();
    sb_b.start().unwrap();
    let b_leader = sb_b.pid().expect("sandbox B leader pid");

    let (output, mut sb_a) = run_probe(
        pid_ns_probe,
        "pidns-probe",
        &[("PROBE_HOST_PID", &b_leader.to_string())],
        true,
        &["/proc"],
    )
    .await;
    let result = sb_a.wait().await.unwrap();
    assert!(result.success(), "sandbox A failed: {:?}\nprobe output:\n{}", result.exit_status, output);

    let mut kill_host = None;
    for l in output.lines() {
        if let Some(v) = l.strip_prefix("kill_host_errno=") {
            kill_host = Some(v);
        }
    }
    assert_eq!(
        kill_host,
        Some("3"),
        "kill(other sandbox leader, 0) must be ESRCH, got {:?}:\n{}",
        kill_host,
        output
    );

    sb_b.kill().unwrap();
    let result_b = sb_b.wait().await.unwrap();
    assert!(!result_b.success());
}

/// Leader-group lifecycle under pid_ns: `pause`/`resume` must reach the
/// namespace leader (its /proc state flips T ↔ S), and `checkpoint` must
/// capture the leader (ptrace-seized by host pid) rather than the
/// intermediate relay process.
#[tokio::test]
async fn pid_ns_pause_resume_checkpoint() {
    let mut sb = Sandbox::builder()
        .pid_ns(true)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .build()
        .unwrap();
    sb.create(&["sleep", "60"]).await.unwrap();
    sb.start().unwrap();
    let leader = sb.pid().expect("leader pid");

    sb.pause().unwrap();
    let state = wait_for_proc_state(leader, 'T').await;
    assert_eq!(state, Some('T'), "pause must SIGSTOP the pid-ns leader (host pid {leader})");

    sb.resume().unwrap();
    let state = wait_for_proc_state(leader, 'S').await;
    assert_eq!(state, Some('S'), "resume must SIGCONT the pid-ns leader (host pid {leader})");

    let cp = sb.checkpoint().await.expect("checkpoint of a pid-ns sandbox must succeed");
    assert_eq!(cp.process_state.pid, leader, "checkpoint must capture the leader's host pid");
    assert!(!cp.process_state.memory_maps.is_empty(), "checkpoint must capture memory maps");
    assert!(!cp.process_state.regs.is_empty(), "checkpoint must capture registers");
    assert!(!cp.fd_table.is_empty(), "checkpoint must capture fd table");

    sb.kill().unwrap();
    let result = sb.wait().await.unwrap();
    assert!(!result.success());
}

/// Poll `/proc/<pid>/stat` until the state char equals `want` (or timeout).
async fn wait_for_proc_state(pid: i32, want: char) -> Option<char> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = proc_stat_state(pid);
        if state == Some(want) {
            return state;
        }
        if Instant::now() >= deadline {
            return state;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The state character (field 3) of `/proc/<pid>/stat`, read from the host
/// side (the test process shares the host PID namespace).
fn proc_stat_state(pid: i32) -> Option<char> {
    let s = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let after = s.rsplit(')').next()?;
    after.split_whitespace().next()?.chars().next()
}

/// `max_cpu` throttling must SIGSTOP/SIGCONT the pid-ns *leader's* group:
/// a CPU-bound in-process probe (which is the leader) measurably slows down.
#[tokio::test]
async fn pid_ns_throttle_slows_cpu_work() {
    const ITERS: &str = "300_000_000";

    let (baseline_out, mut baseline) = run_probe(
        throttle_spin_probe,
        "pidns-throttle-baseline",
        &[("THROTTLE_SPIN_ITERS", ITERS)],
        true,
        &["/proc"],
    )
    .await;
    let baseline_result = baseline.wait().await.unwrap();
    assert!(baseline_result.success(), "baseline sandbox failed: {:?}\n{}", baseline_result.exit_status, baseline_out);
    let baseline_ms = parse_spin_elapsed(&baseline_out);

    let mut b = Sandbox::builder()
        .pid_ns(true)
        .max_cpu(25)
        .env_var("THROTTLE_SPIN_ITERS", ITERS);
    for p in ["/proc"] {
        b = b.fs_read(p);
    }
    let mut throttled = b.build().unwrap();
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let (r, w) = (fds[0], fds[1]);
    throttled
        .create_with_in_child_main("pidns-throttle", vec![(3, w)], throttle_spin_probe)
        .await
        .unwrap();
    unsafe { libc::close(w) };
    throttled.start().unwrap();
    let throttled_out = tokio::task::spawn_blocking(move || {
        let mut buf = String::new();
        let mut f = unsafe { std::fs::File::from_raw_fd(r) };
        f.read_to_string(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();
    let throttled_result = throttled.wait().await.unwrap();
    assert!(throttled_result.success(), "throttled sandbox failed: {:?}\n{}", throttled_result.exit_status, throttled_out);
    let throttled_ms = parse_spin_elapsed(&throttled_out);

    assert!(
        throttled_ms >= baseline_ms * 2,
        "max_cpu(25) must measurably slow the pid-ns leader: baseline={baseline_ms}ms throttled={throttled_ms}ms\n{}",
        throttled_out
    );
}

fn parse_spin_elapsed(out: &str) -> u64 {
    out.lines()
        .find_map(|l| l.strip_prefix("spin_elapsed_ms="))
        .and_then(|v| v.parse().ok())
        .expect("spin_elapsed_ms missing from probe output")
}

/// Default `pid_ns=false`: the shared host PID namespace stays in effect —
/// the sandbox sees host pids (`/proc/<own host pid>/status` opens under the
/// host pid, its own host pid appears in `/proc`), and `kill(host_pid, 0)`
/// returns 0/EPERM, never ESRCH.
#[tokio::test]
async fn pid_ns_default_off_keeps_host_pid_view() {
    let host_pid = std::process::id() as i32;
    let (output, mut sb) = run_probe(
        default_off_probe,
        "pidns-off-probe",
        &[("PROBE_HOST_PID", &host_pid.to_string())],
        false,
        &["/proc"],
    )
    .await;
    let result = sb.wait().await.unwrap();
    assert!(result.success(), "sandbox failed: {:?}\nprobe output:\n{}", result.exit_status, output);

    let mut own_pid = None;
    let mut kill_host = None;
    let mut own_status_pid = None;
    let mut proc_pids = None;
    let mut proc_has_own = None;
    for l in output.lines() {
        if let Some(v) = l.strip_prefix("own_pid=") {
            own_pid = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("kill_host_errno=") {
            kill_host = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("own_status_pid=") {
            own_status_pid = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("proc_pids=") {
            proc_pids = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("proc_has_own=") {
            proc_has_own = Some(v.to_string());
        }
    }
    assert!(
        matches!(kill_host.as_deref(), Some("0") | Some("1")),
        "kill(host test pid, 0) must be detectable (0 or EPERM), never ESRCH, got {:?}:\n{}",
        kill_host,
        output
    );
    let sb_pid_str = sb.pid().expect("sandbox pid").to_string();
    assert_eq!(own_pid.as_deref(), Some(sb_pid_str.as_str()), "probe getpid() must match the supervisor's view of the sandbox pid:\n{output}");
    let own_pid_str = own_pid.expect("own_pid missing");
    assert_eq!(
        own_status_pid.as_deref(),
        Some(own_pid_str.as_str()),
        "/proc/<own host pid>/status must open by host pid and report it:\n{output}"
    );
    assert_eq!(proc_has_own.as_deref(), Some("true"), "own host pid must appear in /proc:\n{output}");
    let expected_pids = format!("[{own_pid_str}]");
    assert_eq!(
        proc_pids.as_deref(),
        Some(expected_pids.as_str()),
        "default sandbox /proc lists its own process under its host pid:\n{output}"
    );
}
