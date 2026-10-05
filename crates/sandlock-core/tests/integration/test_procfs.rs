use sandlock_core::sandbox::ByteSize;
use sandlock_core::{Sandbox};

/// Test that num_cpus virtualizes both /proc/cpuinfo and sched_getaffinity.
#[tokio::test]
async fn test_num_cpus_virtualization() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(2)
        .build()
        .unwrap();

    // Verify /proc/cpuinfo shows 2 processors.
    let result = policy.clone().run(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"]).await.unwrap();
    assert!(result.success(), "grep /proc/cpuinfo should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "2", "/proc/cpuinfo should show 2 processors, got: {:?}", stdout.trim());

    // Verify nproc (sched_getaffinity) also reports 2.
    let result = policy.clone().run(&["nproc"]).await.unwrap();
    assert!(result.success(), "nproc should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "2", "nproc should report 2 CPUs, got: {:?}", stdout.trim());
}

/// Test that max_memory virtualizes /proc/meminfo.
#[tokio::test]
async fn test_meminfo_virtualization() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .max_memory(ByteSize::mib(256))
        .build()
        .unwrap();

    // Read meminfo — should show virtualized values
    let result = policy.clone().run(&["cat", "/proc/meminfo"]).await.unwrap();
    assert!(result.success(), "cat /proc/meminfo should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // 256 MiB = 262144 kB
    assert!(
        stdout.contains("MemTotal:       262144 kB"),
        "Expected MemTotal of 262144 kB (256 MiB), got: {:?}", stdout
    );
}

/// `sysinfo(2)` reports the sandbox's own memory budget, not the host's.
///
/// The syscall is not namespaced, so without mediation it answers with the
/// host's totals, load average, process count and uptime -- contradicting the
/// mediated `/proc/meminfo` and exposing the node (the host's `freeram` moves
/// with a neighbour's allocations, which makes it a cross-tenant channel).
#[tokio::test]
async fn test_sysinfo_virtualization() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(2)
        .max_memory(ByteSize::mib(256))
        .build()
        .unwrap();

    let script = format!(
        r#"
import ctypes, json
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long
class Sysinfo(ctypes.Structure):
    _fields_ = [("uptime", ctypes.c_long), ("loads", ctypes.c_ulong * 3),
        ("totalram", ctypes.c_ulong), ("freeram", ctypes.c_ulong),
        ("sharedram", ctypes.c_ulong), ("bufferram", ctypes.c_ulong),
        ("totalswap", ctypes.c_ulong), ("freeswap", ctypes.c_ulong),
        ("procs", ctypes.c_ushort), ("pad", ctypes.c_ushort),
        ("totalhigh", ctypes.c_ulong), ("freehigh", ctypes.c_ulong),
        ("mem_unit", ctypes.c_uint)]
si = Sysinfo()
cpu = ctypes.c_uint(99); node = ctypes.c_uint(99)
rc = libc.syscall({nr}, ctypes.byref(si))
rc_cpu = libc.syscall({cpu_nr}, ctypes.byref(cpu), ctypes.byref(node), None)
print(json.dumps({{"rc": rc, "total": si.totalram * si.mem_unit,
                   "load1": si.loads[0], "procs": si.procs,
                   "uptime": si.uptime, "rc_cpu": rc_cpu, "cpu": cpu.value}}))
"#,
        nr = libc::SYS_sysinfo,
        cpu_nr = libc::SYS_getcpu
    );
    let result = policy.clone().run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "sysinfo should succeed: {:?}", result);
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).into_owned();
    assert_eq!(
        stdout.trim(),
        r#"{"rc": 0, "total": 268435456, "load1": 0, "procs": 0, "uptime": 0, "rc_cpu": 0, "cpu": 0}"#,
        "sysinfo must report the sandbox budget (256 MiB) and no host-wide state; \
         getcpu must not name the host CPU"
    );
}

/// `statfs(2)` reports the host's accounting for this sandbox -- its quota and
/// what is left of it -- instead of the node's whole volume.
///
/// `df` and `shutil.disk_usage` go through `statfs`, which is not namespaced:
/// without this the sandbox sees the host XFS (99.7 GiB on `/`) and the NAS
/// aggregate for `/workspace`.
#[tokio::test]
async fn test_statfs_reports_the_hosts_disk_accounting() {
    let dir = tempfile::tempdir().unwrap();
    let stats = dir.path().join("disk-stats");
    // 10 GiB sold, 4 GiB used -> 6 GiB free. `df` style numbers are these
    // divided by the 4 KiB block size the handler reports.
    std::fs::write(&stats, "10737418240 4294967296\n").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .disk_stats_path(&stats)
        .build()
        .unwrap();

    let script = "import os\n\
         s = os.statvfs('/')\n\
         fd = os.open('/etc', os.O_RDONLY)\n\
         f = os.fstatvfs(fd)\n\
         print(s.f_frsize, s.f_blocks, s.f_bfree, s.f_bavail)\n\
         print(f.f_frsize, f.f_blocks, f.f_bfree, f.f_bavail)\n";
    let result = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    assert!(result.success(), "statvfs should succeed: {:?}", result);
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).into_owned();
    assert_eq!(
        stdout.trim(),
        "4096 2621440 1572864 1572864\n4096 2621440 1572864 1572864",
        "statfs and its fd-based sibling fstatfs must both report the sold \
         quota (10 GiB) and its remainder (6 GiB)"
    );

    // The host keeps the numbers fresh by rewriting the file; the next call
    // must reflect the new value without restarting the sandbox.
    std::fs::write(&stats, "10737418240 9663676416\n").unwrap();
    let result = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).into_owned();
    assert_eq!(
        stdout.trim(),
        "4096 2621440 262144 262144\n4096 2621440 262144 262144",
        "a refreshed accounting file must be observed by the next statfs"
    );
}

/// SEC-K0S-007 correction: the accounting must win in the **mediated** shapes
/// too, not only in the bare one above.
///
/// Measured 2026-10-01 on the deployed route-B shape: the payload's `statfs`
/// *was* notified (and every other notif-mediated handler -- `uname`,
/// `/proc` synthesis, `inotify_add_watch` -- answered for it), yet the ledger
/// was ignored and the node's numbers came back. The cause is handler
/// precedence, not the seccomp filter: a chain stops at the first
/// non-`Continue` result, and `register_chroot_handlers` used to register
/// `SYS_statfs` *before* the accounting handler, so `handle_chroot_statfs`
/// answered every call. Every deployment shape has a chroot root (the pure /
/// synthesized root, an image rootfs, or the real root), which is why the
/// feature was dead in production while the non-chroot case above stayed
/// green.
///
/// The accounting is deliberately path-insensitive (`handle_statfs`), so it is
/// the right answer for every `statfs` the sandbox makes once a ledger is
/// configured -- including this one, whose path resolves through the chroot.
#[tokio::test]
async fn test_statfs_accounting_wins_over_the_chroot_handler() {
    let dir = tempfile::tempdir().unwrap();
    let stats = dir.path().join("disk-stats");
    // 10 GiB sold, 4 GiB used -> 6 GiB free, in the handler's 4 KiB blocks.
    std::fs::write(&stats, "10737418240 4294967296\n").unwrap();

    // N14 S5 (2026-10-04): the pure shape's *identity* root -- `chroot("/")`,
    // the mediator's root being the host's -- is retired (the `E2B_PURE_ROOTFS=
    // off` lever, refused by name at startup), and the real root cannot pivot
    // into `/` at all (S2 measured EBUSY). The surviving pure shape is the
    // synthesized one: a skeleton root with the host's system directories bound
    // into it, which is what the deployment builds and what this case now
    // uses. The subject is unchanged -- the chroot handler used to shadow the
    // accounting one, and the ledger has to win in *every* mediated shape.
    let rootfs = dir.path().join("rootfs");
    for sub in ["usr", "lib", "bin", "etc", "proc", "tmp", "dev"] {
        std::fs::create_dir_all(rootfs.join(sub)).expect("create the skeleton dir");
    }
    let mut builder = Sandbox::builder()
        .chroot(&rootfs)
        // The mounts make the host's system directories *exist* inside the real
        // root; the read grants are what carry the EXECUTE right the workload
        // needs to run `python3` out of them.
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_mount_ro("/usr", "/usr")
        .fs_mount_ro("/lib", "/lib")
        .fs_mount_ro("/bin", "/bin")
        .fs_mount_ro("/etc", "/etc")
        .fs_mount_ro("/proc", "/proc")
        .disk_stats_path(&stats);
    if std::path::Path::new("/lib64").exists() {
        std::fs::create_dir_all(rootfs.join("lib64")).expect("create lib64");
        builder = builder.fs_mount_ro("/lib64", "/lib64");
    }
    let policy = builder.build().unwrap();

    let script = "import os\n\
         s = os.statvfs('/')\n\
         fd = os.open('/etc', os.O_RDONLY)\n\
         f = os.fstatvfs(fd)\n\
         print(s.f_frsize, s.f_blocks, s.f_bfree, s.f_bavail)\n\
         print(f.f_frsize, f.f_blocks, f.f_bfree, f.f_bavail)\n";
    let result = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    assert!(result.success(), "statvfs should succeed: {:?}", result);
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).into_owned();
    assert_eq!(
        stdout.trim(),
        "4096 2621440 1572864 1572864\n4096 2621440 1572864 1572864",
        "the ledger must win over the chroot statfs handler: the chroot handler \
         would report the node's volume instead, and the fd-based sibling must \
         answer it too"
    );

    // The host keeps the numbers fresh by rewriting the file; the next call
    // must reflect the new value through the same (mediated) path.
    std::fs::write(&stats, "10737418240 9663676416\n").unwrap();
    let result = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).into_owned();
    assert_eq!(
        stdout.trim(),
        "4096 2621440 262144 262144\n4096 2621440 262144 262144",
        "a refreshed accounting file must be observed by the next statfs in the \
         chroot shape too"
    );
}

/// Test that sensitive /proc paths are blocked.
#[tokio::test]
async fn test_sensitive_proc_blocked() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(1) // activate proc virtualization
        .build()
        .unwrap();

    // /proc/kcore should be denied
    let result = policy.clone().run(&["cat", "/proc/kcore"]).await.unwrap();
    assert!(!result.success(), "/proc/kcore should be denied");
}

/// The sensitive-path deny used to do a literal `path == "/proc/kcore"`
/// (and `starts_with("/proc/kcore/")`) match, which any non-canonical or
/// dirfd-relative spelling sidestepped. Exercise each known bypass shape
/// and assert the deny still fires.
#[tokio::test]
async fn test_sensitive_proc_resists_bypasses() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(1)
        .build()
        .unwrap();

    // EACCES (errno 13) is what the handler returns for sensitive paths.
    // Each branch prints OK if the open was denied, FAIL otherwise.
    let script = concat!(
        "import os, errno\n",
        "results = []\n",
        "def must_deny(label, fn):\n",
        "  try:\n",
        "    fd = fn()\n",
        "    os.close(fd)\n",
        "    results.append(f'{label}:LEAKED')\n",
        "  except OSError as e:\n",
        "    results.append(f'{label}:DENIED' if e.errno == errno.EACCES else f'{label}:errno={e.errno}')\n",
        // 1. dirfd-relative: open(/proc), then open 'kcore' relative to it
        "procfd = os.open('/proc', os.O_DIRECTORY | os.O_RDONLY)\n",
        "must_deny('dirfd', lambda: os.open('kcore', os.O_RDONLY, dir_fd=procfd))\n",
        "os.close(procfd)\n",
        // 2. non-canonical absolutes
        "must_deny('dotdot', lambda: os.open('/proc/../proc/kcore', os.O_RDONLY))\n",
        "must_deny('curdir', lambda: os.open('/proc/./kcore', os.O_RDONLY))\n",
        "must_deny('slash2', lambda: os.open('//proc/kcore', os.O_RDONLY))\n",
        "print('|'.join(results))\n",
    );

    let result = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    for label in ["dirfd", "dotdot", "curdir", "slash2"] {
        let needle = format!("{label}:DENIED");
        assert!(
            stdout.contains(&needle),
            "{label}: /proc/kcore leaked via this spelling. stdout: {stdout}"
        );
    }
}

/// The /proc/cpuinfo virtualization used to do a literal
/// `path == "/proc/cpuinfo"` match, so non-canonical and dirfd-relative
/// spellings fell through to the host's real cpuinfo and leaked the host's
/// real CPU count.
#[tokio::test]
async fn test_proc_virt_resists_bypasses() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(2)
        .build()
        .unwrap();

    // Every spelling must see exactly 2 `^processor` lines, matching the
    // synthetic cpuinfo. A leak to the host file would show this host's
    // real CPU count (almost certainly != 2).
    let script = concat!(
        "import os\n",
        "results = {}\n",
        "procfd = os.open('/proc', os.O_DIRECTORY | os.O_RDONLY)\n",
        "fd = os.open('cpuinfo', os.O_RDONLY, dir_fd=procfd)\n",
        "results['dirfd']  = os.read(fd, 4096).decode().count('processor\\t')\n",
        "os.close(fd); os.close(procfd)\n",
        "results['dotdot'] = open('/proc/../proc/cpuinfo').read().count('processor\\t')\n",
        "results['curdir'] = open('/proc/./cpuinfo').read().count('processor\\t')\n",
        "results['slash2'] = open('//proc/cpuinfo').read().count('processor\\t')\n",
        "print(results)\n",
    );

    let result = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    for label in ["dirfd", "dotdot", "curdir", "slash2"] {
        let needle = format!("'{label}': 2");
        assert!(
            stdout.contains(&needle),
            "{label}: host cpuinfo leaked (expected 2 processors, virtualized). stdout: {stdout}"
        );
    }
}

/// Test basic sandbox still works without /proc virtualization.
#[tokio::test]
async fn test_no_proc_virt_still_works() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .build()
        .unwrap();

    let result = policy.clone().run(&["cat", "/proc/version"]).await.unwrap();
    assert!(result.success(), "Should work without proc virtualization");
}

/// Test that /proc/net/tcp is filtered with port_remap — only shows sandbox's own ports.
#[tokio::test]
async fn test_proc_net_tcp_filtered() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procnet-{}",
        std::process::id()
    ));

    // Pick a free port to avoid conflicts with parallel tests.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .net_allow_bind_port(port)
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "s.bind(('127.0.0.1', {port}))\n",
        "s.listen(1)\n",
        "with open('/proc/net/tcp') as f:\n",
        "  lines = f.readlines()\n",
        "s.close()\n",
        "ports = []\n",
        "for line in lines[1:]:\n",
        "  parts = line.split()\n",
        "  if len(parts) >= 2:\n",
        "    port_hex = parts[1].split(':')[1]\n",
        "    ports.append(int(port_hex, 16))\n",
        "open('{out}', 'w').write(str(len(ports)))\n",
    ), port = port, out = out.display());

    let result = policy.clone().run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let count: usize = content.parse().unwrap_or(999);
    assert!(count <= 2, "/proc/net/tcp should be filtered, got {} entries", count);

    let _ = std::fs::remove_file(&out);
}

/// Test that /proc/mounts is virtualized and only shows sandbox mounts.
#[tokio::test]
async fn test_proc_mounts_virtualized() {
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .build()
        .unwrap();

    let result = policy.clone().run(&["cat", "/proc/mounts"]).await.unwrap();
    assert!(result.success(), "cat /proc/mounts should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // Should contain the root entry (no chroot → rootfs)
    assert!(stdout.contains("rootfs / rootfs rw 0 0"), "Should show root mount, got: {}", stdout);
    // Should NOT leak host mounts (e.g. /home, /boot, real device paths)
    assert!(!stdout.contains("/home"), "Should not leak host /home mount");
    assert!(!stdout.contains("nvme"), "Should not leak host disk device names");
}

/// Test that /proc/self/mountinfo is virtualized.
#[tokio::test]
async fn test_proc_self_mountinfo_virtualized() {
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .build()
        .unwrap();

    let result = policy.clone().run(&["cat", "/proc/self/mountinfo"]).await.unwrap();
    assert!(result.success(), "cat /proc/self/mountinfo should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // Should contain root entry in mountinfo format
    assert!(stdout.contains("/ / rw - rootfs rootfs rw"), "Should show root in mountinfo, got: {}", stdout);
    assert!(!stdout.contains("/home"), "Should not leak host /home mount in mountinfo");
}

/// Test that /proc/{ppid}/ is blocked (non-sandbox PID isolation).
#[tokio::test]
async fn test_proc_parent_pid_blocked() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procparent-{}",
        std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let script = format!(concat!(
        "import os\n",
        "ppid = os.getppid()\n",
        "results = []\n",
        "for entry in ['cmdline', 'status']:\n",
        "  try:\n",
        "    open(f'/proc/{{ppid}}/{{entry}}').read()\n",
        "    results.append('LEAKED')\n",
        "  except PermissionError:\n",
        "    results.append('BLOCKED')\n",
        "  except Exception as e:\n",
        "    results.append(f'ERR:{{e}}')\n",
        "# Verify /proc/self still works\n",
        "try:\n",
        "  open('/proc/self/status').read()\n",
        "  results.append('SELF_OK')\n",
        "except Exception:\n",
        "  results.append('SELF_FAIL')\n",
        "open('{out}', 'w').write(','.join(results))\n",
    ), out = out.display());

    let result = policy.clone().run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "script should exit 0");
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let parts: Vec<&str> = content.split(',').collect();
    assert_eq!(parts.get(0), Some(&"BLOCKED"), "/proc/ppid/cmdline should be blocked, got: {}", content);
    assert_eq!(parts.get(1), Some(&"BLOCKED"), "/proc/ppid/status should be blocked, got: {}", content);
    assert_eq!(parts.get(2), Some(&"SELF_OK"), "/proc/self/status should still work, got: {}", content);
}

/// Test that /proc/net/tcp hides host ports when sandbox has no bindings.
#[tokio::test]
async fn test_proc_net_tcp_hides_host_ports() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procnet-hide-{}",
        std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(concat!(
        "with open('/proc/net/tcp') as f:\n",
        "  lines = f.readlines()\n",
        "ports = []\n",
        "for line in lines[1:]:\n",
        "  parts = line.split()\n",
        "  if len(parts) >= 2:\n",
        "    port_hex = parts[1].split(':')[1]\n",
        "    ports.append(int(port_hex, 16))\n",
        "open('{out}', 'w').write(str(len(ports)))\n",
    ), out = out.display());

    let result = policy.clone().run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let count: usize = content.parse().unwrap_or(999);
    assert_eq!(count, 0, "/proc/net/tcp should show 0 entries when sandbox has no bindings");

    let _ = std::fs::remove_file(&out);
}
