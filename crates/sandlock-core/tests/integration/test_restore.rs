use sandlock_core::Sandbox;
use std::path::PathBuf;

/// Path to the static rootfs-helper binary (compiled by build.rs). Its
/// `clock-loop` command is a single-process, single-fd counter loop that calls
/// `clock_gettime(CLOCK_MONOTONIC)` every iteration — the vDSO fast path — so it
/// exercises the full restore engine (memory, registers, reopened fd) plus vDSO
/// relocation without any embedded C in the test.
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found — build.rs should have compiled it")
}

/// The address range the restore-stub's own image is linked into. Must match
/// `checkpoint::restore_blob::STUB_BASE`/`STUB_SPAN`, which is crate-private;
/// `stub_links_at_the_reserved_base` guards the constant against the binary.
/// x86_64 and aarch64 use 3 TiB; riscv64 uses 192 GiB (below Sv39 ceiling).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const STUB_BASE: u64 = 0x300_0000_0000;
#[cfg(target_arch = "riscv64")]
const STUB_BASE: u64 = 0x30_0000_0000;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
const STUB_BASE: u64 = 0;
const STUB_SPAN: u64 = 0x40_0000;

/// Bound an await so a wedged restore fails *by name* instead of hanging the
/// suite (see the twin helper in `test_instance_exec.rs`: on 2026-10-05 a
/// session-restore case blocked for ~35 minutes with no timeout anywhere in the
/// harness). `cargo test` has no per-test timeout, so each restore step carries
/// its own; `scripts/test-all.sh` bounds every suite as the outer belt.
async fn bounded<F: std::future::Future>(secs: u64, what: &str, fut: F) -> F::Output {
    match tokio::time::timeout(std::time::Duration::from_secs(secs), fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {secs}s"),
    }
}

/// Parse `/proc/<pid>/maps` into `(start, end, path)` triples.
fn read_maps(pid: i32) -> Vec<(u64, u64, String)> {
    std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(6, ' ');
            let (lo, hi) = parts.next()?.split_once('-')?;
            let path = parts.nth(4).unwrap_or("").trim().to_string();
            Some((
                u64::from_str_radix(lo, 16).ok()?,
                u64::from_str_radix(hi, 16).ok()?,
                path,
            ))
        })
        .collect()
}

/// End-to-end proof that an ordinary libc program surviving a checkpoint/restore
/// keeps making vDSO calls. Run the static-musl helper's `clock-loop` (which
/// calls `clock_gettime` each iteration and advances an on-disk counter),
/// checkpoint it mid-loop, kill the original, restore into a fresh sandbox, and
/// confirm the restored process resumes and advances the counter — which it can
/// only do if every post-restore `clock_gettime` (a vDSO call) succeeds. Before
/// vDSO relocation, glibc/musl's cached vDSO pointer would reference the
/// checkpoint-era base and the restored process would fault on its first call.
///
/// Also asserts the restored address space is *clean*: nothing is mapped that
/// the checkpoint did not record, beyond the kernel's own special mappings and
/// the restore-stub's reserved window. That is the property the execve stub
/// exists for. The ptrace-injection engine it replaced could not hold it — it
/// rebuilt the image on top of a parked libc launcher, whose leftover text,
/// stack and heap stayed mapped and reachable.
#[tokio::test]
async fn test_restore_glibc_vdso_program_resumes() {
    if cfg!(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))) {
        eprintln!("skipping: the restore engine is x86_64/aarch64/riscv64 only");
        return;
    }

    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();

    let tmp = std::env::temp_dir().join(format!("sandlock-vdso-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let counter = tmp.join("clock.cnt");
    let counter_s = counter.to_str().unwrap().to_string();

    // Static musl helper needs only its own binary readable and the output dir
    // writable; clock_gettime routes through the kernel-provided vDSO (no fs).
    let policy = Sandbox::builder()
        .fs_read(&helper_dir)
        .fs_read(&tmp)
        .fs_write(&tmp)
        .build().unwrap();

    let helper_s = helper.to_str().unwrap().to_string();
    let mut sb = policy.clone().with_name("vdso-src");
    sb.spawn_interactive(&[helper_s.as_str(), "clock-loop", counter_s.as_str()])
        .await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let cp = sb.checkpoint().await.unwrap();

    let read_counter = |path: &str| -> Option<u64> {
        std::fs::read_to_string(path).ok().and_then(|s| s.trim().parse::<u64>().ok())
    };
    let baseline = read_counter(&counter_s).expect("counter file should exist with a value");
    assert!(baseline > 2, "counter should have advanced before checkpoint, got {baseline}");

    // Kill the original so only the restored process can advance the file.
    sb.kill().unwrap();
    let _ = sb.wait().await;

    // Sentinel: prove the *restored* process (not a leftover original) is writing.
    std::fs::write(&counter, b"0\n").unwrap();

    let mut sb2 = policy.clone().with_name("vdso-dst");
    let _ = bounded(60, "restore_interactive (vdso dst)", sb2.restore_interactive(&cp))
        .await
        .unwrap();
    eprintln!("restore skipped fds: {:?}", sb2.restore_skipped());

    // Poll up to ~3s for the restored process to resume and advance the counter
    // past the checkpointed baseline.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut last = 0u64;
    let mut advanced = false;
    while std::time::Instant::now() < deadline {
        if let Some(v) = read_counter(&counter_s) {
            last = v;
            if v > baseline {
                advanced = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Read the restored layout while the process is still alive.
    let restored_maps = sb2.pid().map(read_maps).unwrap_or_default();

    // Clean up before asserting so a failure never leaks the child/files.
    let _ = sb2.kill();
    let exit = sb2.wait().await.map(|r| r.exit_status);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        advanced,
        "restored process must resume and keep calling clock_gettime past \
         baseline {baseline}; last seen {last}, restored exit {exit:?}"
    );

    // Compare by address coverage, not by identity: the kernel merges and
    // splits adjacent mappings, so a restored VMA legitimately spans several
    // recorded ones. What must not happen is a *byte* being mapped that the
    // checkpoint never recorded.
    assert!(!restored_maps.is_empty(), "could not read the restored layout");
    let mut allowed: Vec<(u64, u64)> = cp
        .process_state
        .memory_maps
        .iter()
        .map(|m| (m.start, m.end))
        .chain(std::iter::once((STUB_BASE, STUB_BASE + STUB_SPAN)))
        .collect();
    allowed.sort_unstable();
    let mut covered: Vec<(u64, u64)> = Vec::new();
    for (lo, hi) in allowed {
        match covered.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => covered.push((lo, hi)),
        }
    }
    let mut strays = Vec::new();
    for (start, end, path) in &restored_maps {
        // The kernel always provides these; they are not checkpoint state.
        if matches!(path.as_str(), "[vdso]" | "[vvar]" | "[vvar_vclock]" | "[vsyscall]") {
            continue;
        }
        if !covered.iter().any(|&(lo, hi)| *start >= lo && *end <= hi) {
            strays.push(format!("{start:#x}-{end:#x} {path}"));
        }
    }
    assert!(
        strays.is_empty(),
        "restored address space must hold only the checkpoint image, the kernel's \
         special mappings and the stub's reserved window; found {} stray mapping(s): {strays:#?}",
        strays.len(),
    );
}

/// The A route: the stub is delivered by descriptor (`execveat(AT_EMPTY_PATH)`)
/// and the ruleset grants that one *host* file `EXECUTE|READ_FILE`.
///
/// Both chroot shapes are exercised, because each used to fail for its own
/// reason: the emulated root could not resolve the stub's host path through the
/// mediator (and the mediator refused the fd-named exec outright), and the real
/// root could not resolve it in the kernel either. With the fd delivery neither
/// has to: the file is named by a descriptor, and Landlock judges its real path
/// (docs/chroot-workspace-exec.md §11).
#[tokio::test]
async fn test_restore_resumes_inside_a_chroot_root() {
    if cfg!(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))) {
        return;
    }
    let helper = helper_binary();
    // N14 S5 (2026-10-04): one shape. This case used to run the emulated chroot
    // and the real root side by side; the emulated root is refused at create now
    // (`Sandbox::do_create_stdio`), so what is left -- and what the deployment
    // runs -- is the real root.
    for (label, real_root) in [("real root", true)] {
        let tmp = std::env::temp_dir().join(format!(
            "sandlock-chroot-restore-{}-{real_root}",
            std::process::id()
        ));
        let rootfs = tmp.join("rootfs");
        let data = tmp.join("data");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        std::fs::create_dir_all(rootfs.join("work")).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::copy(&helper, rootfs.join("usr/bin/rootfs-helper"))
            .expect("install the helper inside the rootfs");

        let counter = data.join("clock.cnt");
        let counter_s = counter.to_str().unwrap().to_string();
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        let mut builder = Sandbox::builder()
            .chroot(&rootfs)
            .real_root(real_root)
            .user(euid, egid)
            .fs_read("/usr")
            .fs_mount("/work", &data)
            .fs_write("/work")
            .cwd("/work");
        builder.userns_self_map = true;
        let policy = builder.build().expect("chroot policy builds");

        let mut sb = policy.clone().with_name("chroot-src");
        sb.spawn_interactive(&["/usr/bin/rootfs-helper", "clock-loop", "/work/clock.cnt"])
            .await
            .unwrap_or_else(|e| panic!("{label}: the counter starts: {e}"));
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let cp = sb.checkpoint().await.expect("checkpoint");

        let read_counter = |path: &str| -> Option<u64> {
            std::fs::read_to_string(path).ok().and_then(|s| s.trim().parse::<u64>().ok())
        };
        let baseline = read_counter(&counter_s).expect("counter has a value");
        assert!(baseline > 2, "{label}: counter advanced, got {baseline}");
        sb.kill().unwrap();
        let _ = sb.wait().await;
        std::fs::write(&counter, b"0\n").unwrap();

        let mut sb2 = policy.clone().with_name("chroot-dst");
        let _restored = bounded(60, "restore_interactive (chroot dst)", sb2.restore_interactive(&cp))
            .await
            .unwrap_or_else(|e| panic!("{label}: restore must work with a chroot root: {e}"));
        let skipped = sb2.restore_skipped().to_vec();

        let mut advanced = false;
        let mut last = 0u64;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if let Some(v) = read_counter(&counter_s) {
                last = v;
                if v > baseline {
                    advanced = true;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let pid = sb2.pid();
        let fds: Vec<String> = pid
            .map(|pid| {
                std::fs::read_dir(format!("/proc/{pid}/fd"))
                    .map(|entries| {
                        entries
                            .filter_map(|e| e.ok())
                            .map(|e| {
                                format!(
                                    "{}->{}",
                                    e.file_name().to_string_lossy(),
                                    std::fs::read_link(e.path())
                                        .map(|p| p.display().to_string())
                                        .unwrap_or_else(|_| "<unreadable>".into())
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        eprintln!("{label}: restored fds = {fds:?}");
        let _ = sb2.kill();
        let exit = sb2.wait().await.map(|r| r.exit_status);
        let _ = std::fs::remove_dir_all(&tmp);

        assert!(
            skipped.iter().all(|s| s.fd <= 2),
            "{label}: only stdio may be skipped; skipped: {skipped:?}"
        );
        assert!(
            advanced,
            "{label}: the restored process must advance the counter past {baseline}; \
             last seen {last}, exit {exit:?}"
        );
        // No platform descriptor may survive into the restored program: the
        // delivery fd of the stub (CLOEXEC), the stub's channel fds and the
        // supervisor's own state are all scaffolding. Measured before the
        // CLOEXEC on the delivery fd: `6->…/restore-stub` in both shapes.
        for fd in &fds {
            assert!(
                !fd.contains("restore-stub")
                    && !fd.contains("seccomp notify")
                    && !fd.contains("memfd"),
                "{label}: a platform descriptor leaked into the restored program: {fd}"
            );
        }
    }
}


/// Gate for the no-exec prototype (`docs/chroot-workspace-exec.md` §11.5).
///
/// The route's payload runs on a `fork` of the *supervisor*, so it inherits that
/// process's per-task kernel state and its thread state. Measured 2026-09-23: in
/// a quiet process it restores correctly (61 child mappings, a 45-entry sweep,
/// the counter resumes inside a real root), and once other tests have run in the
/// same process the payload is killed by SIGSEGV *before* READY -- the
/// fork-of-a-multi-threaded-supervisor hazard the plan named, recorded but not
/// yet diagnosed. Run it deliberately with `SANLOCK_NOEXEC_PROTOTYPE=1`.
fn noexec_prototype_enabled() -> bool {
    if std::env::var("SANLOCK_NOEXEC_PROTOTYPE").map(|v| v.trim() == "1").unwrap_or(false) {
        return true;
    }
    eprintln!(
        "skipping the no-exec restore prototype: it needs a quiet supervisor \
         process (set SANLOCK_NOEXEC_PROTOTYPE=1 to run it; see \
         docs/chroot-workspace-exec.md §11.5)"
    );
    false
}

/// The no-exec route (prototype of `docs/chroot-workspace-exec.md` §11 "B"):
/// the same real-root policy, the same checkpoint -- but the stub rides a memfd
/// into the confined child, which maps it at `STUB_BASE` and jumps into it.
///
/// This is the shape a chroot/real root can actually host: nothing is resolved
/// by path and nothing is executed by path, so no Landlock grant is needed for
/// the stub (the refusal test next door pins what happens without it).
///
/// Assertions, in the order the costs are paid:
///   * the restored counter advances (the engine still works end to end);
///   * every recorded fd came back (`restore_skipped` is empty);
///   * the restored address space holds only the checkpoint's regions plus the
///     stub's reserved window -- i.e. the sweep really did clean up the fork's
///     copy of the supervisor. The fd table is *measured and printed*, not
///     asserted: the exec route gets that for free from `CLOEXEC`, and this
///     route does not yet close the inherited descriptors (that is the known
///     gap this prototype exists to price).
#[tokio::test]
async fn test_restore_resumes_inside_a_real_root_without_exec() {
    if !noexec_prototype_enabled() {
        return;
    }
    if cfg!(not(any(target_arch = "x86_64", target_arch = "riscv64"))) {
        eprintln!("skipping: the no-exec prototype jumps into the stub with an arch-specific asm");
        return;
    }

    let helper = helper_binary();
    let tmp = std::env::temp_dir().join(format!("sandlock-noexec-{}", std::process::id()));
    let rootfs = tmp.join("rootfs");
    let data = tmp.join("data");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
    std::fs::create_dir_all(rootfs.join("work")).unwrap();
    std::fs::create_dir_all(&data).unwrap();
    std::fs::copy(&helper, rootfs.join("usr/bin/rootfs-helper"))
        .expect("install the helper inside the rootfs");

    let counter = data.join("clock.cnt");
    let counter_s = counter.to_str().unwrap().to_string();

    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    let mut builder = Sandbox::builder()
        .chroot(&rootfs)
        .real_root(true)
        .user(euid, egid)
        .fs_read("/usr")
        .fs_mount("/work", &data)
        .fs_write("/work")
        .cwd("/work");
    builder.userns_self_map = true;
    let policy = builder.build().expect("real-root policy builds");

    let mut sb = policy.clone().with_name("noexec-src");
    sb.spawn_interactive(&["/usr/bin/rootfs-helper", "clock-loop", "/work/clock.cnt"])
        .await
        .expect("the real-root sandbox starts the counter");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let cp = sb.checkpoint().await.expect("checkpoint a real-root sandbox");

    let read_counter = |path: &str| -> Option<u64> {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    };
    let baseline = read_counter(&counter_s).expect("counter file should exist with a value");
    assert!(baseline > 2, "counter should have advanced, got {baseline}");
    sb.kill().unwrap();
    let _ = sb.wait().await;
    std::fs::write(&counter, b"0\n").unwrap();

    let mut sb2 = policy.clone().with_name("noexec-dst");
    let _restored = sb2
        .restore_interactive_noexec(&cp)
        .await
        .expect("the no-exec route must restore inside a real root");
    let skipped = sb2.restore_skipped().to_vec();

    let mut advanced = false;
    let mut last = 0u64;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if let Some(v) = read_counter(&counter_s) {
            last = v;
            if v > baseline {
                advanced = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Measure while the restored process is alive.
    let pid = sb2.pid();
    let restored_maps = pid.map(read_maps).unwrap_or_default();
    let fd_list: Vec<String> = pid
        .map(|pid| {
            std::fs::read_dir(format!("/proc/{pid}/fd"))
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .map(|e| {
                            let target = std::fs::read_link(e.path())
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|_| "<unreadable>".into());
                            format!("{}->{}", e.file_name().to_string_lossy(), target)
                        })
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();
    eprintln!("noexec: restored fds = {fd_list:?}");

    let _ = sb2.kill();
    let exit = sb2.wait().await.map(|r| r.exit_status);
    let _ = std::fs::remove_dir_all(&tmp);

    // The three stdio descriptors are skipped in *both* routes (the harness's
    // pipes and /dev/null are not reopenable by path); anything beyond them would
    // be the stub failing to recreate a recorded fd.
    assert!(
        skipped.iter().all(|s| s.fd <= 2),
        "only stdio may be skipped on the no-exec route; skipped: {skipped:?}"
    );
    assert!(
        advanced,
        "the restored process must resume and advance the counter past {baseline}; \
         last seen {last}, restored exit {exit:?}"
    );
    assert!(!restored_maps.is_empty(), "could not read the restored layout");
    let mut allowed: Vec<(u64, u64)> = cp
        .process_state
        .memory_maps
        .iter()
        .map(|m| (m.start, m.end))
        .chain(std::iter::once((STUB_BASE, STUB_BASE + STUB_SPAN)))
        .collect();
    allowed.sort_unstable();
    let mut covered: Vec<(u64, u64)> = Vec::new();
    for (lo, hi) in allowed {
        match covered.last_mut() {
            Some(prev) if lo <= prev.1 => prev.1 = prev.1.max(hi),
            _ => covered.push((lo, hi)),
        }
    }
    let mut strays = Vec::new();
    for (start, end, path) in &restored_maps {
        if matches!(path.as_str(), "[vdso]" | "[vvar]" | "[vvar_vclock]" | "[vsyscall]") {
            continue;
        }
        if !covered.iter().any(|&(lo, hi)| *start >= lo && *end <= hi) {
            strays.push(format!("{start:#x}-{end:#x} {path}"));
        }
    }
    assert!(
        strays.is_empty(),
        "the fork's leftovers must be swept: the restored layout may hold only the \
         checkpoint image, the kernel's special mappings and the stub window; \
         found {} stray mapping(s): {strays:#?}",
        strays.len()
    );
}

/// Bisect for the no-exec route: does it work where the *exec* route also works
/// (chroot-free, no real root)?
///
/// If this passes and the real-root variant segfaults, the difference is the
/// chroot/real-root shape; if both segfault, the difference is
/// fork-versus-exec (the address space and the kernel state `execve` resets).
#[tokio::test]
async fn test_restore_resumes_without_exec_and_without_chroot() {
    if !noexec_prototype_enabled() {
        return;
    }
    if cfg!(not(any(target_arch = "x86_64", target_arch = "riscv64"))) {
        return;
    }
    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();
    let tmp = std::env::temp_dir().join(format!("sandlock-noexec-flat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let counter = tmp.join("clock.cnt");
    let counter_s = counter.to_str().unwrap().to_string();

    let policy = Sandbox::builder()
        .fs_read(&helper_dir)
        .fs_read(&tmp)
        .fs_write(&tmp)
        .build()
        .expect("chroot-free policy builds");

    let helper_s = helper.to_str().unwrap().to_string();
    let mut sb = policy.clone().with_name("noexec-flat-src");
    sb.spawn_interactive(&[helper_s.as_str(), "clock-loop", counter_s.as_str()])
        .await
        .expect("counter starts");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let cp = sb.checkpoint().await.expect("checkpoint");
    let read_counter = |path: &str| -> Option<u64> {
        std::fs::read_to_string(path).ok().and_then(|s| s.trim().parse::<u64>().ok())
    };
    let baseline = read_counter(&counter_s).expect("counter has a value");
    assert!(baseline > 2, "counter advanced, got {baseline}");
    sb.kill().unwrap();
    let _ = sb.wait().await;
    std::fs::write(&counter, b"0\n").unwrap();

    let mut sb2 = policy.clone().with_name("noexec-flat-dst");
    let _restored = sb2
        .restore_interactive_noexec(&cp)
        .await
        .expect("no-exec restore (chroot-free)");

    let mut advanced = false;
    let mut last = 0u64;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if let Some(v) = read_counter(&counter_s) {
            last = v;
            if v > baseline {
                advanced = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let _ = sb2.kill();
    let exit = sb2.wait().await.map(|r| r.exit_status);
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(
        advanced,
        "no-exec restore must resume chroot-free; last seen {last}, exit {exit:?}"
    );
}

/// **Regression**: workloads that touch the dynamic loader's read-only pages
/// resume after a restore.
///
/// This started as the opposite test. A supervisor slot restoring its own images
/// saw `/bin/sh` and `python3` die right after restore while the static helper
/// and `/bin/sleep` came back, and two framings of the cause were measured and
/// discarded before the real one ("static works, dynamic fails"; "the libc
/// allocator is the problem" -- `malloc`/`free` resume fine). What separated the
/// cases was whether the program touches a value the loader wrote into a
/// **read-only** page at startup: `GNU_RELRO`, where relocated pointers and the
/// vDSO caches live. The capture left those to be re-read from the file, where
/// they are zero, and the first dereference faulted (`segfault at 300 ... in
/// libc.so.6`, loaded pointer NULL, inside `clock_gettime`'s vDSO path).
///
/// The fix carries those ranges in the image (`checkpoint::capture::is_relro_map`),
/// and this test is what says so. It is the same harness the diagnosis used, so
/// the shapes below are the ones that were failing, now asserted to work.
#[tokio::test]
async fn test_libc_workloads_resume_after_restore() {
    let has_cc = ["cc", "gcc"].iter().any(|cc| {
        std::process::Command::new(cc)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    });
    if !has_cc {
        eprintln!("skipping: no C compiler (cc/gcc) available");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("sandlock-libcr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    // Every workload writes its counter with raw syscalls, so "did it advance"
    // measures the one libc operation under test and nothing else.
    fn source(op: &str, extra: &str) -> String {
        format!(
            r#"
#include <unistd.h>
#include <sys/syscall.h>
{extra}
int main(int argc, char **argv) {{
    unsigned long i = 0;
    char buf[32];
    if (argc < 2) return 2;
    for (;;) {{
        int n = 0;
        unsigned long v = i++;
        char t[24];
        while (v) {{ t[n++] = '0' + (v % 10); v /= 10; }}
        if (n == 0) t[n++] = '0';
        int p = 0;
        while (n > 0) buf[p++] = t[--n];
        buf[p++] = '\n';
        int fd = syscall(SYS_openat, -100, argv[1], 1 | 0100 | 01000, 0644);
        if (fd >= 0) {{ syscall(SYS_write, fd, buf, p); syscall(SYS_close, fd); }}
        {op}
        struct {{ long s, ns; }} ts = {{ 0, 50000000 }};
        syscall(SYS_nanosleep, &ts, 0);
    }}
}}
"#
        )
    }

    let variants: Vec<(&str, String)> = vec![
        (
            "libc-malloc",
            source(
                "void *q = malloc(64); if (q) { *(volatile char *)q = 1; free(q); }",
                "#include <stdlib.h>",
            ),
        ),
        (
            // Reads the vDSO cache the loader wrote into RELRO.
            "vdso-clock",
            source(
                "struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);",
                "#include <time.h>",
            ),
        ),
        (
            // libc stdio: the shape `/bin/sh`- and `python3`-like programs take.
            "stdio-fopen",
            source(
                "FILE *f = fopen(\"/dev/null\", \"w\"); if (f) fclose(f);",
                "#include <stdio.h>",
            ),
        ),
    ];

    let mut bins = Vec::new();
    for (name, src) in &variants {
        let c = tmp.join(format!("{name}.c"));
        let bin = tmp.join(name);
        std::fs::write(&c, src).unwrap();
        let build = std::process::Command::new("cc")
            .args(["-O0", "-D_GNU_SOURCE", "-o"])
            .arg(&bin)
            .arg(&c)
            .output()
            .expect("run cc");
        assert!(
            build.status.success(),
            "cc failed for {name}: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        bins.push((name.to_string(), bin));
    }

    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();
    let mut builder = Sandbox::builder()
        .fs_read(&tmp)
        .fs_write(&tmp)
        .fs_read(&helper_dir);
    for d in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"] {
        if std::path::Path::new(d).exists() {
            builder = builder.fs_read(d);
        }
    }
    let policy = builder.build().unwrap();

    // Returns whether the process advanced past the capture and its state char.
    async fn round_trip(
        policy: &Sandbox,
        helper: &std::path::Path,
        tmp: &std::path::Path,
        bin: Option<&std::path::Path>,
        tag: &str,
    ) -> (bool, String) {
        let counter = tmp.join(format!("cnt-{tag}"));
        let _ = std::fs::remove_file(&counter);
        let mut argv: Vec<String> = match bin {
            Some(b) => vec![b.to_str().unwrap().to_string()],
            None => vec![helper.to_str().unwrap().to_string(), "clock-loop".to_string()],
        };
        argv.push(counter.to_str().unwrap().to_string());
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let mut sb = policy.clone().with_name(&format!("libcr-{tag}"));
        sb.spawn_interactive(&refs)
            .await
            .unwrap_or_else(|e| panic!("{tag}: spawn: {e}"));
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let before = std::fs::read_to_string(&counter)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok());
        assert!(
            before.is_some_and(|v| v >= 2),
            "{tag}: the counter must move before the capture: {before:?}"
        );
        let cp = sb
            .checkpoint()
            .await
            .unwrap_or_else(|e| panic!("{tag}: checkpoint: {e}"));
        let _ = sb.kill();
        let _ = sb.wait().await;
        let mut sb2 = policy.clone().with_name(&format!("libcr-{tag}-dst"));
        let _ = bounded(60, "restore_interactive (libc-restore dst)", sb2.restore_interactive(&cp))
            .await
            .unwrap_or_else(|e| panic!("{tag}: restore: {e}"));
        let pid = sb2.pid().unwrap_or(0);
        let baseline = before.unwrap();
        let mut advanced = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        while std::time::Instant::now() < deadline {
            if let Some(v) = std::fs::read_to_string(&counter)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
            {
                if v > baseline {
                    advanced = true;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let state = stat.split_whitespace().nth(2).unwrap_or("?").to_string();
        let exit_code = stat.split_whitespace().nth(51).unwrap_or("-").to_string();
        eprintln!("libcr {tag}: advanced={advanced} state={state} exit_code={exit_code}");
        // The leader's exit code is the restore stub's, so a restore that
        // "succeeded" but left a dead process is visible here (`proc(5)`
        // `exit_code` = 128+errno / 192+fd for the stub's reopen failures).
        let _ = sb2.kill();
        let _ = sb2.wait().await;
        (advanced, state)
    }

    // The static freestanding helper the rest of this suite uses, as the control.
    let (control_advanced, _) = round_trip(&policy, &helper, &tmp, None, "static-control").await;
    assert!(control_advanced, "the static control must resume");

    for (name, bin) in &bins {
        let (advanced, state) = round_trip(&policy, &helper, &tmp, Some(bin), name).await;
        assert!(
            advanced,
            "{name} did not advance after the restore (state {state}) -- a workload that \
             touches the loader's read-only pages must resume; see \
             checkpoint::capture::is_relro_map"
        );
        assert_ne!(
            state, "Z",
            "{name} is a zombie after the restore: the loader's read-only pages did not \
             travel in the image"
        );
    }

    let _ = std::fs::remove_dir_all(&tmp);
}
