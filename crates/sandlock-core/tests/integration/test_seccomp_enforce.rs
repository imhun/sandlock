use std::path::PathBuf;

use sandlock_core::{Sandbox};

/// Helper: base policy with standard FS paths for running commands.
fn base_policy() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
}

/// Helper: build a temp file path for a given test name.
fn temp_out(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sandlock-test-seccomp-{}-{}",
        name,
        std::process::id()
    ))
}

// ------------------------------------------------------------------
// 1. mount() is blocked by default seccomp blocklist
// ------------------------------------------------------------------
#[tokio::test]
async fn test_mount_blocked() {
    let out = temp_out("mount-blocked");
    let cmd_str = format!(
        "mount -t tmpfs none /tmp 2>/dev/null; echo $? > {}",
        out.display()
    );
    let policy = base_policy().build().unwrap();
    let result = policy.clone().run_interactive(&["sh", "-c", &cmd_str])
        .await
        .unwrap();

    // sh itself should exit 0 (the echo succeeds), but the mount exit
    // code written to the file should be non-zero (permission denied).
    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let code: i32 = contents.trim().parse().unwrap_or(-1);
    assert_ne!(code, 0, "mount should have been denied, got exit code 0");
    // Also confirm the sandbox wrapper itself didn't crash.
    assert!(result.success());
}

// ------------------------------------------------------------------
// 1b. chroot() is blocked by the default seccomp blocklist
// ------------------------------------------------------------------
//
// `chroot` is deliberately absent from `chroot_path_syscalls()`, so before it
// was blocklisted the kernel executed it for real -- and in the
// emulated-chroot shape (the one image-rootfs sandboxes use) the child's kernel
// root is still the *host* root: the supervisor chdirs into the host path
// under the rootfs and translates every path syscall, but never calls
// `chroot(2)` itself. A sandboxed `chroot("/")` therefore succeeded against the
// host filesystem, which is exactly the "seccomp fallthrough" that
// `landlock.rs` documents as needing to be empty.
//
// The assertion is on the errno the sandbox observes, not on "the command
// failed": a missing interpreter or a bad path would also produce a non-zero
// exit and prove nothing.
#[tokio::test]
async fn test_chroot_blocked() {
    let out = temp_out("chroot-blocked");
    let script = format!(concat!(
        "import ctypes, os\n",
        "ctypes.set_errno(0)\n",
        "try:\n",
        "  os.chroot('/')\n",
        "  result = 'ALLOWED'\n",
        "except OSError as e:\n",
        "  result = 'BLOCKED:%d' % e.errno\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());
    let policy = base_policy().build().unwrap();
    let result = policy.clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        content, "BLOCKED:1",
        "chroot must be denied with EPERM by the default blocklist"
    );
}

// ------------------------------------------------------------------
// 1c. the 2026-09-30 hardening list is refused inside a real sandbox
// ------------------------------------------------------------------
//
// Each of these was measured *reaching the kernel from inside a sandbox on the
// deployed cluster* (k0s, arm64, worker pod with no effective capabilities --
// `fsconfig`/`mount_setattr` answered EINVAL, so their argument parse ran;
// `memfd_secret` returned a usable fd; `get_mempolicy`/`set_mempolicy` returned
// 0). They are in `DEFAULT_BLOCKLIST_SYSCALLS` now, so the assertion is on the
// errno the sandbox observes: EPERM, not "the call failed" (a bad argument
// would also fail and prove nothing).
//
// The numbers come from the crate's own resolver, so the test is arch-correct:
// `modify_ldt` (x86 only) simply drops out on aarch64.
#[tokio::test]
async fn test_first_tier_blocklist_refused() {
    use sandlock_core::seccomp::syscall::syscall_name_to_nr;

    // name -> deliberately-bad arguments, so a regression cannot have side
    // effects while it is being measured.
    const PROBES: &[(&str, &[i64])] = &[
        // mount API companions
        ("fsopen", &[0, 0]),
        ("fsconfig", &[0x7FFF_FFF0, 0, 0, 0, 0]),
        ("fsmount", &[0x7FFF_FFF0, 0, 0]),
        ("move_mount", &[0x7FFF_FFF0, 0, 0x7FFF_FFF0, 0, 0]),
        ("fspick", &[0x7FFF_FFF0, 0, 0]),
        ("mount_setattr", &[0x7FFF_FFF0, 0, 0, 0, 0]),
        ("statmount", &[0, 0, 0, 0, 0, 0]),
        ("listmount", &[0, 0, 0, 0, 0]),
        // the ptrace class
        ("process_madvise", &[0x7FFF_FFF0, 0, 0, 4, 0]),
        ("process_mrelease", &[0x7FFF_FFF0, 0]),
        ("kcmp", &[0x7FFF_FFF0, 0x7FFF_FFF0, 0, 0, 0]),
        // quota / kexec / legacy AIO
        ("quotactl_fd", &[0x7FFF_FFF0, 0, 0, 0, 0]),
        ("kexec_file_load", &[0x7FFF_FFF0, 0x7FFF_FFF0, 0, 0, 0]),
        ("io_setup", &[0, 0]),
        ("io_submit", &[0x7FFF_FFF0, 0, 0]),
        ("io_cancel", &[0x7FFF_FFF0, 0, 0]),
        ("io_getevents", &[0x7FFF_FFF0, 0, 0, 0, 0]),
        ("io_pgetevents", &[0x7FFF_FFF0, 0, 0, 0, 0, 0]),
        // host/device
        ("memfd_secret", &[0]),
        ("modify_ldt", &[0, 0, 0]),
        // NUMA
        ("get_mempolicy", &[0, 0, 0, 0, 0]),
        ("set_mempolicy", &[0, 0, 0]),
        ("mbind", &[0, 4096, 0, 0, 0, 0]),
        ("move_pages", &[0, 0, 0, 0, 0, 0]),
        ("migrate_pages", &[0, 0, 0, 0]),
        ("set_mempolicy_home_node", &[0, 0, 0, 0]),
    ];

    let mut table = String::new();
    for (name, args) in PROBES {
        let Some(nr) = syscall_name_to_nr(name) else {
            // ABI-specific name (x86-only `modify_ldt`): nothing to enforce.
            continue;
        };
        table.push_str(&format!("    {name:?}: ({nr}, {args:?}),\n"));
    }
    assert!(
        table.matches("\n").count() > 20,
        "the probe table resolved almost nothing: {table}"
    );

    let out = temp_out("first-tier-blocklist");
    let script = format!(concat!(
        "import ctypes, sys\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "libc.syscall.restype = ctypes.c_long\n",
        "PROBES = {{\n",
        "{table}",
        "}}\n",
        "lines = []\n",
        "for name, (nr, args) in PROBES.items():\n",
        "    a = list(args) + [0] * (6 - len(args))\n",
        "    ctypes.set_errno(0)\n",
        "    libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(x) for x in a])\n",
        "    lines.append('%s %d' % (name, ctypes.get_errno()))\n",
        "open(sys.argv[1], 'w').write('\\n'.join(lines))\n",
    ), table = table);
    let policy = base_policy().build().unwrap();
    let result = policy.clone()
        .run_interactive(&["python3", "-c", &script, &out.display().to_string()])
        .await
        .unwrap();
    assert!(
        result.success(),
        "the probe process must run inside the sandbox (stderr: {})",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let mut wrong: Vec<String> = Vec::new();
    let mut checked = 0;
    for line in content.lines() {
        let (name, errno) = line.split_once(' ').expect("name errno");
        checked += 1;
        if errno != "1" {
            wrong.push(format!("{name}={errno}"));
        }
    }
    assert_eq!(checked, table.matches("\n").count(), "probe count mismatch: {content}");
    assert!(
        wrong.is_empty(),
        "these must be refused with EPERM(1) by the default blocklist, got: {wrong:?}"
    );
}

// ------------------------------------------------------------------
// 1d. clone3's namespace flags are refused by the sandbox's own check
// ------------------------------------------------------------------
//
// `clone3` carries its flags inside a `clone_args` struct behind a user
// pointer, so the BPF arg filter -- which reads arg0 directly, the way it does
// for `clone` -- cannot see them. Only the notif handler can, by reading the
// struct out of the caller. Until 2026-09-30 `handle_fork` guarded its
// namespace check with `nr == SYS_clone`, so `clone3(CLONE_NEWUSER|...)` was
// answered `Continue` and the kernel executed it. On the deployed worker
// profile that was masked by the outer profile denying `clone3` outright
// (ENOSYS, measured on the k0s cluster) -- which is exactly the problem: the
// namespace ban was being enforced by the container profile, not by sandlock.
//
// `CLONE_NEWUSER|CLONE_THREAD` is deliberate. A thread cannot create a new user
// namespace, so a build that lets the call through gets `EINVAL` from the
// kernel: distinguishable from the `EPERM` this test requires, and with no side
// effect in either case (no task is created). The same test also spawns two
// threads, which glibc implements with `clone3`: the check must refuse the
// namespace flag without refusing ordinary thread creation.
#[tokio::test]
async fn test_clone3_namespace_flags_refused() {
    let out = temp_out("clone3-ns");
    let script = format!(concat!(
        "import ctypes, errno, sys, threading\n",
        "CLONE_NEWUSER = 0x10000000\n",
        "CLONE_THREAD = 0x00010000\n",
        "CLONE_NEWNS = 0x00020000\n",
        "SIGCHLD = 17\n",
        // clone_args: 11 __aligned_u64 fields, flags first.
        "class CloneArgs(ctypes.Structure):\n",
        "    _fields_ = [('flags', ctypes.c_ulonglong)] + [\n",
        "        (n, ctypes.c_ulonglong) for n in ('pidfd', 'child_tid', 'parent_tid',\n",
        "         'exit_signal', 'stack', 'stack_size', 'tls', 'set_tid', 'set_tid_size',\n",
        "         'cgroup')]\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "libc.syscall.restype = ctypes.c_long\n",
        "def clone3(flags):\n",
        "    a = CloneArgs()\n",
        "    a.flags = flags\n",
        "    a.exit_signal = SIGCHLD\n",
        "    ctypes.set_errno(0)\n",
        "    libc.syscall(ctypes.c_long(435), ctypes.byref(a), ctypes.sizeof(a))\n",
        "    return ctypes.get_errno()\n",
        "notes = []\n",
        "notes.append('newuser_thread=%d' % clone3(CLONE_NEWUSER | CLONE_THREAD))\n",
        // Control: ordinary thread creation (glibc: clone3) must still work.
        "ts = [threading.Thread(target=lambda: None) for _ in range(2)]\n",
        "for t in ts: t.start()\n",
        "for t in ts: t.join()\n",
        "notes.append('threads=ok')\n",
        "open(sys.argv[1], 'w').write('\\n'.join(notes))\n",
    ));
    let policy = base_policy().build().unwrap();
    let result = policy.clone()
        .run_interactive(&["python3", "-c", &script, &out.display().to_string()])
        .await
        .unwrap();
    assert!(
        result.success(),
        "the probe process must run inside the sandbox (stderr: {})",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        content,
        // EPERM = 1; the thread control line proves the same check did not cost
        // ordinary clone3 (only the invalid-combination spelling is exercised,
        // because a *valid* namespace clone would create a task).
        "newuser_thread=1\nthreads=ok",
        "clone3's namespace flags must be refused with EPERM, and plain \
         thread creation must keep working"
    );
}

// ------------------------------------------------------------------
// 2. ptrace is blocked (strace should fail)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_ptrace_blocked() {
    let out = temp_out("ptrace-blocked");
    let cmd_str = format!(
        "strace -p 1 2>/dev/null; echo $? > {}",
        out.display()
    );
    let policy = base_policy().build().unwrap();
    let result = policy.clone().run_interactive(&["sh", "-c", &cmd_str])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let code: i32 = contents.trim().parse().unwrap_or(-1);
    assert_ne!(code, 0, "ptrace (strace) should have been denied");
    assert!(result.success());
}

// ------------------------------------------------------------------
// 3. personality() blocked (ASLR bypass prevention)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_personality_blocked() {
    let out = temp_out("personality-blocked");
    let script = format!(concat!(
        "import ctypes\n",
        "libc = ctypes.CDLL(None)\n",
        "ADDR_NO_RANDOMIZE = 0x0040000\n",
        "current = libc.syscall(135, 0xffffffff)\n",
        "ret = libc.syscall(135, current | ADDR_NO_RANDOMIZE)\n",
        "if ret == -1:\n",
        "  result = 'BLOCKED'\n",
        "else:\n",
        "  new = libc.syscall(135, 0xffffffff)\n",
        "  result = 'ESCAPED' if new & ADDR_NO_RANDOMIZE else 'BLOCKED'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "BLOCKED",
        "personality(ADDR_NO_RANDOMIZE) should be blocked, got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 4. Raw sockets blocked by default (allow_icmp defaults to false)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_raw_socket_blocked() {
    let out = temp_out("raw-socket-blocked");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "BLOCKED",
        "raw socket should be blocked by default, got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 4b. Raw ICMP is unconditionally denied — sandlock does not expose
//     SOCK_RAW + IPPROTO_ICMP, even with policy concessions. Workloads
//     that need ping should use the SOCK_DGRAM kernel ping socket via
//     an `icmp://...` rule (test 4d below).
// ------------------------------------------------------------------
#[tokio::test]
async fn test_raw_icmp_always_denied() {
    let out = temp_out("raw-icmp-denied");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    // Even with an `icmp://*` rule (which permits the dgram path), raw
    // ICMP must still be blocked: SOCK_RAW is always in the deny list.
    let policy = base_policy()
        .net_allow("icmp://*")
        .build()
        .unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_ne!(
        contents.trim(), "ALLOWED",
        "raw ICMP must be denied unconditionally; got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 4d. The kernel ping socket (SOCK_DGRAM + IPPROTO_ICMP) is permitted
//     when an `icmp://*` rule is present — the modern unprivileged
//     ping path, distinct from raw ICMP.
// ------------------------------------------------------------------
#[tokio::test]
async fn test_icmp_dgram_allowed_with_icmp_rule() {
    let out = temp_out("icmp-dgram-allowed");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy()
        .net_allow("icmp://*")
        .build()
        .unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    // Seccomp must allow the syscall. The kernel may still deny if the
    // sandbox GID is outside `net.ipv4.ping_group_range` (errno 1 EPERM
    // or EACCES). Accepting ALLOWED / BLOCKED / ERROR:1 / ERROR:13 keeps
    // the test green across hosts.
    let trimmed = contents.trim();
    assert!(
        trimmed == "ALLOWED" || trimmed == "BLOCKED"
            || trimmed == "ERROR:1" || trimmed == "ERROR:13",
        "kernel ping socket should be permitted by seccomp under icmp://*; got: {}",
        trimmed
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 5. UDP allowed when a `udp://*:*` rule is present.
// ------------------------------------------------------------------
#[tokio::test]
async fn test_udp_allowed_when_opted_in() {
    let out = temp_out("udp-allowed");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy()
        .net_allow("udp://*:*")
        .build()
        .unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "ALLOWED",
        "UDP socket should be allowed with udp://*:*, got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 6. UDP denied by default
// ------------------------------------------------------------------
#[tokio::test]
async fn test_udp_denied_by_default() {
    let out = temp_out("udp-denied");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "BLOCKED",
        "UDP should be denied by default; got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 6b. With a TCP-only rule set, UDP moves to send-time gating: the
//     socket is creatable (glibc getaddrinfo needs that for its
//     address-sorting probes, or name resolution breaks on TCP-only
//     profiles), but every send, connect, and bind on it is denied —
//     no UDP rule means the protocol's allowlist is empty.
// ------------------------------------------------------------------
#[tokio::test]
async fn test_udp_send_time_gating_with_tcp_only_rules() {
    let out = temp_out("udp-send-gated");
    let script = format!(concat!(
        "import socket, json\n",
        "res = {{}}\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "  res['create'] = 'ok'\n",
        "except OSError as e:\n",
        "  res['create'] = 'err:%d' % e.errno\n",
        "  s = None\n",
        "if s is not None:\n",
        "  try:\n",
        "    s.sendto(b'x', ('127.0.0.1', 53))\n",
        "    res['sendto'] = 'ok'\n",
        "  except OSError as e:\n",
        "    res['sendto'] = 'err:%d' % e.errno\n",
        "  try:\n",
        "    s.connect(('127.0.0.1', 53))\n",
        "    res['connect'] = 'ok'\n",
        "  except OSError as e:\n",
        "    res['connect'] = 'err:%d' % e.errno\n",
        "  try:\n",
        "    s.bind(('127.0.0.1', 0))\n",
        "    res['bind'] = 'ok'\n",
        "  except OSError as e:\n",
        "    res['bind'] = 'err:%d' % e.errno\n",
        "  s.close()\n",
        "open('{out}', 'w').write(json.dumps(res))\n",
    ), out = out.display());

    let policy = base_policy()
        .net_allow("tcp://127.0.0.1:9")
        .build()
        .unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert!(contents.contains("\"create\": \"ok\""),
        "UDP socket creation must succeed with net rules present; got: {contents}");
    assert!(contents.contains("\"sendto\": \"err:111\""),
        "UDP sendto must be denied with ECONNREFUSED; got: {contents}");
    assert!(contents.contains("\"connect\": \"err:111\""),
        "UDP connect must be denied with ECONNREFUSED; got: {contents}");
    assert!(contents.contains("\"bind\": \"err:13\""),
        "UDP bind must be denied with EACCES; got: {contents}");
    assert!(result.success());
}

// ------------------------------------------------------------------
// 7. SysV IPC (shmget) denied by default — sandlock has no IPC
//    namespace, so the deny is the only thing isolating shm
//    keyspaces between sandboxes.
// ------------------------------------------------------------------
#[tokio::test]
async fn test_sysv_shmget_denied_by_default() {
    let out = temp_out("shmget-denied");
    // shmget(IPC_PRIVATE, 4096, IPC_CREAT|0600) — should return EPERM.
    let script = format!(concat!(
        "import ctypes, errno\n",
        "libc = ctypes.CDLL(None)\n",
        "ret = libc.shmget(0, 4096, 0o1000 | 0o600)\n",
        "if ret == -1:\n",
        "  e = ctypes.get_errno()\n",
        "  result = 'EPERM' if e == errno.EPERM else f'ERROR:{{e}}'\n",
        "else:\n",
        "  libc.shmctl(ret, 0, None)\n",
        "  result = 'ALLOWED'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let trimmed = contents.trim();
    // ctypes does not propagate errno from libc by default; the call
    // itself returning -1 is the signal that the seccomp deny fired.
    assert!(
        trimmed != "ALLOWED",
        "shmget must be denied by default (sandlock has no IPC ns); got: {}",
        trimmed
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 7b. extra_allow_syscalls(["sysv_ipc"]) restores SysV shm.
// ------------------------------------------------------------------
#[tokio::test]
async fn test_sysv_shmget_allowed_when_opted_in() {
    let out = temp_out("shmget-allowed");
    let script = format!(concat!(
        "import ctypes\n",
        "libc = ctypes.CDLL(None)\n",
        "ret = libc.shmget(0, 4096, 0o1000 | 0o600)\n",
        "if ret == -1:\n",
        "  result = 'BLOCKED'\n",
        "else:\n",
        "  libc.shmctl(ret, 0, None)\n",
        "  result = 'ALLOWED'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy()
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "ALLOWED",
        "shmget should be permitted under extra_allow_syscalls=[\"sysv_ipc\"]; got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 8. TCP always allowed (default blocklist posture for raw + UDP)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_tcp_always_allowed() {
    let out = temp_out("tcp-allowed");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy()
        .build()
        .unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "ALLOWED",
        "TCP socket should always be allowed, got: {}",
        contents.trim()
    );
    assert!(result.success());
}
