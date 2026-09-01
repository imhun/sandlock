//! PID namespace (`SandboxBuilder::pid_ns`) integration tests.
//!
//! The sandbox's first process must become PID 1 inside its own namespace:
//! `kill(pid, 0)` probes of host / other-sandbox processes return `ESRCH`,
//! in-namespace signaling still works, and `/proc` lists only the sandbox's
//! own processes under their namespace pids.

use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;

use sandlock_core::Sandbox;

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
    // host pid by the supervisor), not to host pid 1.
    let status = std::fs::read_to_string("/proc/1/status").unwrap_or_default();
    line.push_str(&format!(
        "proc1_status_readable={}\n",
        status.contains("Name:")
    ));

    unsafe { libc::kill(child, libc::SIGKILL) };
    let mut st = 0;
    unsafe { libc::waitpid(child, &mut st, 0) };

    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
    unsafe { libc::_exit(0) };
}

async fn probe_sandbox(host_pid: i32) -> (String, Sandbox) {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let (r, w) = (fds[0], fds[1]);
    let mut sb = Sandbox::builder()
        .pid_ns(true)
        .fs_read("/proc")
        .env_var("PROBE_HOST_PID", host_pid.to_string())
        .build()
        .unwrap();
    sb.create_with_in_child_main("pidns-probe", vec![(3, w)], pid_ns_probe)
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
    let (output, mut sb) = probe_sandbox(host_pid).await;
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
/// resolves to the sandbox leader.
#[tokio::test]
async fn pid_ns_procfs_view_is_renumbered() {
    let host_pid = std::process::id() as i32;
    let (output, mut sb) = probe_sandbox(host_pid).await;
    let result = sb.wait().await.unwrap();
    assert!(result.success(), "sandbox failed: {:?}\nprobe output:\n{}", result.exit_status, output);

    let mut proc_pids = None;
    let mut proc_has_host_pid = None;
    let mut proc1_readable = None;
    for l in output.lines() {
        if let Some(v) = l.strip_prefix("proc_pids=") {
            proc_pids = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("proc_has_host_pid=") {
            proc_has_host_pid = Some(v.to_string());
        } else if let Some(v) = l.strip_prefix("proc1_status_readable=") {
            proc1_readable = Some(v.to_string());
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
    assert_eq!(proc1_readable.as_deref(), Some("true"));
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

    let (output, mut sb_a) = probe_sandbox(b_leader).await;
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
