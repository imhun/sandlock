use super::*;
use crate::instance::{finish_parked_drain, take_drained, ParkedDrain};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[test]
fn run_as_parses_uid_and_gid() {
    let r = RunAs::from_str("1000:2000").unwrap();
    assert_eq!(r.uid, 1000);
    assert_eq!(r.gid, 2000);
}

#[test]
fn run_as_requires_both_ids() {
    // A bare UID (no `:GID`) is rejected — gid is not defaulted.
    assert!(RunAs::from_str("1000").is_err());
}

#[test]
fn run_as_rejects_garbage() {
    assert!(RunAs::from_str("root").is_err());
    assert!(RunAs::from_str("1000:abc").is_err());
    assert!(RunAs::from_str("").is_err());
}

#[test]
fn resolve_sandbox_path_plain() {
    let r = resolve_sandbox_path_to_host(Path::new("/etc/ssl/x.pem"), None, &[]);
    assert_eq!(r, PathBuf::from("/etc/ssl/x.pem"));
}

#[test]
fn resolve_sandbox_path_under_chroot() {
    let r = resolve_sandbox_path_to_host(
        Path::new("/etc/ssl/x.pem"),
        Some(Path::new("/srv/root")),
        &[],
    );
    assert_eq!(r, PathBuf::from("/srv/root/etc/ssl/x.pem"));
}

#[test]
fn resolve_sandbox_path_mount_takes_precedence() {
    let mounts = vec![(PathBuf::from("/etc/ssl"), PathBuf::from("/host/ssl"))];
    let r = resolve_sandbox_path_to_host(
        Path::new("/etc/ssl/x.pem"),
        Some(Path::new("/srv/root")),
        &mounts,
    );
    assert_eq!(r, PathBuf::from("/host/ssl/x.pem"));
}

#[tokio::test]
async fn inject_ca_nonexistent_path_errors_at_run() {
    // Wildcard host rule avoids DNS; the missing inject path must error
    // before any fork or network work.
    let mut policy = Sandbox::builder()
        .http_allow("GET */*")
        .http_inject_ca("/definitely/not/here/sandlock-bundle.pem")
        .build()
        .unwrap();
    let res = policy.run(&["true"]).await;
    assert!(res.is_err(), "expected error for missing --http-inject-ca path");
}

// --- SandboxBuilder integration ---

#[test]
fn builder_http_rules() {
    let policy = Sandbox::builder()
        .http_allow("GET api.example.com/v1/*")
        .http_deny("* */admin/*")
        .build()
        .unwrap();
    assert_eq!(policy.http_allow.len(), 1);
    assert_eq!(policy.http_deny.len(), 1);
    assert_eq!(policy.http_allow[0].method, "GET");
    assert_eq!(policy.http_deny[0].host, "*");
}

#[test]
fn builder_invalid_http_allow_returns_error() {
    let result = Sandbox::builder()
        .http_allow("GETexample.com")
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_invalid_http_deny_returns_error() {
    let result = Sandbox::builder()
        .http_deny("BADRULE")
        .build();
    assert!(result.is_err());
}

#[test]
fn default_max_processes_is_whole_box_256() {
    // F5.1 (Q10): `max_processes` is a whole-box ceiling — every process an
    // exec session forks shares one supervisor accounting block — so the
    // default is 256, not the legacy 64-per-command value.
    let policy = Sandbox::builder().build().unwrap();
    assert_eq!(policy.max_processes, 256);
    assert_eq!(policy.max_processes, crate::sandbox::DEFAULT_MAX_PROCESSES);
}

#[test]
fn builder_http_ca_without_key_returns_error() {
    let result = Sandbox::builder()
        .http_ca("/tmp/ca.pem")
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_http_key_without_ca_returns_error() {
    let result = Sandbox::builder()
        .http_key("/tmp/key.pem")
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_http_ca_and_key_together_ok() {
    let policy = Sandbox::builder()
        .http_ca("/tmp/ca.pem")
        .http_key("/tmp/key.pem")
        .build()
        .unwrap();
    assert!(policy.http_ca.is_some());
    assert!(policy.http_key.is_some());
}

#[test]
fn inject_ca_adds_443_and_requires_http_rule() {
    // No http rule -> error.
    let err = Sandbox::builder()
        .http_inject_ca("/etc/ssl/certs/ca-certificates.crt")
        .build();
    assert!(err.is_err());

    // With an http rule -> ok, and 443 is intercepted.
    let policy = Sandbox::builder()
        .http_allow("GET example.com/*")
        .http_inject_ca("/etc/ssl/certs/ca-certificates.crt")
        .build()
        .unwrap();
    assert!(policy.http_ports.contains(&443));
    assert_eq!(policy.http_inject_ca.len(), 1);
}

#[test]
fn http_ca_out_requires_trigger() {
    let err = Sandbox::builder()
        .http_allow("GET example.com/*")
        .http_ca_out("/tmp/out.pem")
        .build();
    assert!(err.is_err());

    let ok = Sandbox::builder()
        .http_allow("GET example.com/*")
        .http_inject_ca("/etc/ssl/certs/ca-certificates.crt")
        .http_ca_out("/tmp/out.pem")
        .build();
    assert!(ok.is_ok());
}

#[test]
fn allows_sysv_ipc_reads_extra_allow_syscalls() {
    let p = Sandbox::builder()
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    assert!(p.allows_sysv_ipc());

    let p2 = Sandbox::builder().build().unwrap();
    assert!(!p2.allows_sysv_ipc());

    let err = Sandbox::builder()
        .extra_allow_syscalls(vec!["other_group".into()])
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("unknown syscall group"));
}

#[test]
fn extra_allow_rejects_individual_syscall_names() {
    let err = Sandbox::builder()
        .extra_allow_syscalls(vec!["io_uring_setup".into()])
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("unknown syscall group"));
}

#[test]
fn extra_deny_accepts_group_names() {
    let p = Sandbox::builder()
        .extra_deny_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    assert_eq!(p.extra_deny_syscalls, vec!["sysv_ipc".to_string()]);

    let err = Sandbox::builder()
        .extra_deny_syscalls(vec!["not_a_syscall_or_group".into()])
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("unknown syscall or group"));
}

#[test]
fn extra_allow_and_deny_of_same_group_conflict() {
    let err = Sandbox::builder()
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .extra_deny_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("both allowed and denied"));
}

#[test]
fn extra_deny_of_member_syscall_conflicts_with_allowed_group() {
    let err = Sandbox::builder()
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .extra_deny_syscalls(vec!["shmget".into()])
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("belongs to allowed group"));
}

#[test]
fn builder_parses_net_deny() {
    let policy = Sandbox::builder()
        .net_deny("10.0.0.0/8")
        .build()
        .unwrap();
    // Scheme-less deny expands to a TCP rule plus a UDP rule.
    assert_eq!(policy.net_deny.len(), 2);
}

#[test]
fn builder_net_allow_bind_comma_and_ranges() {
    // Comma-separated ports and `lo-hi` ranges expand, sort, and dedup.
    let policy = Sandbox::builder()
        .net_allow_bind("8080,9000-9002")
        .net_allow_bind_port(443)
        .net_allow_bind("9001,443") // overlaps dedup away
        .build()
        .unwrap();
    assert_eq!(
        policy.net_allow_bind,
        BindPorts::Ports(vec![443, 8080, 9000, 9001, 9002])
    );
}

#[test]
fn builder_net_allow_bind_rejects_bad_specs() {
    assert!(Sandbox::builder().net_allow_bind("9000-8000").build().is_err()); // reversed
    assert!(Sandbox::builder().net_allow_bind("80,abc").build().is_err());    // bad port
    assert!(Sandbox::builder().net_allow_bind("70000").build().is_err());     // > u16
    assert!(Sandbox::builder().net_allow_bind("8080,").build().is_err());     // empty part
}

#[test]
fn builder_net_allow_bind_wildcard() {
    // `*`, padded ` * `, and a repeated bare wildcard (idempotent) all
    // mean "any port". This parser is the single implementation of the
    // wildcard rule; the SDKs forward specs verbatim over the C ABI.
    for specs in [vec!["*"], vec![" * "], vec!["*", "*"], vec!["*,*"]] {
        let mut builder = Sandbox::builder();
        for spec in specs.iter() {
            builder = builder.net_allow_bind(*spec);
        }
        let policy = builder.build().unwrap();
        assert_eq!(policy.net_allow_bind, BindPorts::All, "specs: {specs:?}");
    }
}

#[test]
fn builder_net_allow_bind_wildcard_rejects_mixing() {
    // Within one spec.
    assert!(Sandbox::builder().net_allow_bind("*,8080").build().is_err());
    // Across specs.
    assert!(Sandbox::builder()
        .net_allow_bind("*")
        .net_allow_bind_port(8080)
        .build()
        .is_err());
    assert!(Sandbox::builder()
        .net_allow_bind("8080")
        .net_allow_bind("*")
        .build()
        .is_err());
}

#[test]
fn builder_net_deny_bind_rejects_wildcard() {
    assert!(Sandbox::builder().net_deny_bind("*").build().is_err());
}

#[test]
fn builder_net_bind_map_requires_net_isolation() {
    let err = Sandbox::builder()
        .net_bind_map(50005, 8000)
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("net_isolation"));
}

#[test]
fn builder_net_bind_map_rejects_low_host_port() {
    // The design reserves the 50005+ host range for inbound mapping.
    let err = Sandbox::builder()
        .net_isolation(true)
        .net_bind_map(50004, 8000)
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("50005"));
}

#[test]
fn builder_net_bind_map_rejects_duplicate_host_port() {
    let err = Sandbox::builder()
        .net_isolation(true)
        .net_bind_map(50005, 8000)
        .net_bind_map(50005, 9000)
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("50005"));
}

#[test]
fn builder_net_bind_map_rejects_duplicate_sandbox_port() {
    let err = Sandbox::builder()
        .net_isolation(true)
        .net_bind_map(50005, 8000)
        .net_bind_map(50006, 8000)
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("8000"));
}

#[test]
fn builder_net_bind_map_requires_supervisor() {
    let err = Sandbox::builder()
        .net_isolation(true)
        .no_supervisor(true)
        .net_bind_map(50005, 8000)
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("supervisor"));
}

#[test]
fn builder_net_bind_map_roundtrips() {
    let policy = Sandbox::builder()
        .net_isolation(true)
        .net_bind_map(50005, 8000)
        .net_bind_map(50006, 9000)
        .build()
        .unwrap();
    assert_eq!(policy.net_bind_map, vec![(50005, 8000), (50006, 9000)]);
}

#[test]
fn builder_net_allow_bind_wildcard_exclusive_with_deny_bind() {
    assert!(Sandbox::builder()
        .net_allow_bind("*")
        .net_deny_bind_port(22)
        .build()
        .is_err());
}

#[test]
fn builder_rejects_net_allow_and_net_deny_together() {
    let err = Sandbox::builder()
        .net_allow("github.com:443")
        .net_deny("10.0.0.0/8")
        .build();
    assert!(err.is_err());
}

#[test]
fn builder_net_deny_bind_comma_and_ranges() {
    // Same port grammar as --net-allow-bind (comma lists + lo-hi ranges).
    let policy = Sandbox::builder()
        .net_deny_bind("8080,9000-9002")
        .net_deny_bind_port(443)
        .build()
        .unwrap();
    assert_eq!(policy.net_deny_bind, vec![443, 8080, 9000, 9001, 9002]);
    assert!(policy.net_allow_bind.is_default());
}

#[test]
fn builder_rejects_allow_bind_and_deny_bind_together() {
    let err = Sandbox::builder()
        .net_allow_bind("8080")
        .net_deny_bind("9090")
        .build();
    assert!(err.is_err());
    assert!(format!("{}", err.unwrap_err()).contains("mutually exclusive"));
}

#[test]
fn builder_net_deny_rejects_hostname() {
    let err = Sandbox::builder().net_deny("evil.com:443").build();
    assert!(err.is_err());
}

#[test]
fn net_deny_resolves_to_denylist_policies() {
    let policy = Sandbox::builder().net_deny("10.0.0.0/8").build().unwrap();
    let set = crate::network::resolve_net_deny(&policy.net_deny);
    assert!(!set.tcp.allows("10.0.0.5".parse().unwrap(), 443));
    assert!(set.tcp.allows("8.8.8.8".parse().unwrap(), 443));
}

// Keystone of the popen child-side fd wiring: relocate_high must move a pipe
// end to a fd >= 3 (disjoint from the 0/1/2 stdio targets) so dup2 onto a
// target can never alias or clobber it — the regression that lost a stream
// when a pipe end was allocated onto a std fd. Lock the invariant here; the
// full closed-std-fd trigger is not deterministically reproducible (the
// control PipePair claims the low fds first), so the value is this unit check
// plus the end-to-end popen tests exercising the relocate path.
#[test]
fn relocate_high_moves_fd_above_stdio_range() {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open("/dev/null").unwrap();
    let src = f.as_raw_fd();
    let hi = unsafe { relocate_high(src) };
    assert!(hi >= 3, "relocated fd must be >= 3 (disjoint from 0/1/2), got {hi}");
    assert_ne!(hi, src, "relocate must produce a new fd");

    // It is a dup of the same description, not a fresh open.
    let mut a: libc::stat = unsafe { std::mem::zeroed() };
    let mut b: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(src, &mut a) }, 0);
    assert_eq!(unsafe { libc::fstat(hi, &mut b) }, 0);
    assert_eq!((a.st_dev, a.st_ino), (b.st_dev, b.st_ino));

    // And it carries CLOEXEC (F_DUPFD_CLOEXEC), so it won't leak past execve.
    let flags = unsafe { libc::fcntl(hi, libc::F_GETFD) };
    assert!(flags >= 0 && (flags & libc::FD_CLOEXEC) != 0, "relocated fd must be CLOEXEC");

    unsafe { libc::close(hi) };
}

/// A `wait()` cancelled while it is joining the drains must leave the drain
/// parked, so a later `wait()` still returns the capture. Reaching that state
/// end to end needs a descendant holding the write end past the child's exit,
/// which is inherently racy (the integration test retries for it), so the
/// contract itself is pinned here: a pending join leaves the task parked, a
/// finished one leaves the bytes parked, and only an explicit take hands them
/// over.
#[tokio::test]
async fn a_cancelled_join_leaves_the_drain_parked() {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let mut slot = Some(ParkedDrain::Running(tokio::spawn(async move {
        let _ = rx.await;
        b"hello".to_vec()
    })));

    // The task cannot finish while the sender is held, so this join is still
    // pending when the timeout drops it — that drop is the cancellation.
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        finish_parked_drain(&mut slot),
    )
    .await;
    assert!(cancelled.is_err(), "the join must still have been pending");
    assert!(
        matches!(slot, Some(ParkedDrain::Running(_))),
        "a cancelled join must leave the task parked",
    );

    // Releasing it parks the bytes rather than handing them out.
    tx.send(()).unwrap();
    finish_parked_drain(&mut slot).await;
    assert!(
        matches!(slot, Some(ParkedDrain::Done(ref buf)) if buf == b"hello"),
        "a finished join must park its bytes in the slot",
    );

    assert_eq!(take_drained(&mut slot).as_deref(), Some(&b"hello"[..]));
    assert!(slot.is_none(), "taking the bytes must empty the slot");
}

/// The reason the bytes are parked rather than returned: the two streams are
/// joined one after the other, so the second join is a suspension point for a
/// capture the first one has already read in full. A cancellation there must
/// not take it.
#[tokio::test]
async fn a_finished_capture_survives_a_cancellation_at_the_sibling_join() {
    let mut stdout = Some(ParkedDrain::Running(tokio::spawn(async { b"hello".to_vec() })));
    // Held for the whole test, so this drain never finishes.
    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
    let mut stderr = Some(ParkedDrain::Running(tokio::spawn(async move {
        let _ = rx.await;
        Vec::new()
    })));

    // The shape of `collect_pipe_drains`: finish one, then the other.
    let cancelled = tokio::time::timeout(std::time::Duration::from_millis(50), async {
        finish_parked_drain(&mut stdout).await;
        finish_parked_drain(&mut stderr).await;
    })
    .await;
    assert!(cancelled.is_err(), "the second join must still have been pending");

    assert!(
        matches!(stdout, Some(ParkedDrain::Done(ref buf)) if buf == b"hello"),
        "a capture that finished before the cancellation must still be parked",
    );
}

// ============================================================
// F6.1 (SL-1): mediated-path identity gate
// ============================================================

/// Truth table for the C档 fail-closed gate: only a mediator that can remap
/// the sandbox to a different non-zero host uid — euid 0, or a non-root euid
/// holding effective CAP_SETUID/CAP_SETGID (the route-B ③ file-cap launcher
/// shape, F14) — with path mediation active is refused.
/// Same-uid A/B mediation, caps-free non-root supervisors, host uid 0
/// sandboxes, and no-mediation configs are all untouched.
#[test]
fn mediation_identity_gate_refuses_only_root_remap_with_mediation() {
    let refused = |euid: u32, host_uid: u32, mediation: bool, caps: bool| {
        crate::sandbox::mediation_remap_is_refused(euid, host_uid, mediation, caps)
    };

    // C档: root supervisor remapping to a non-zero host uid with mediation.
    assert!(refused(0, 10000, true, false));
    assert!(refused(0, 10000, true, true));
    assert!(refused(0, 1, true, false));
    // Same-uid A/B mediation is never refused...
    assert!(!refused(65534, 65534, true, false));
    assert!(!refused(65534, 65534, true, true));
    assert!(!refused(1000, 1000, true, false));
    assert!(!refused(0, 0, true, false), "host uid 0 needs no remap at all");
    // ...nor is a caps-free non-root supervisor (it cannot remap; RunAs
    // refuses separately), nor root without mediation (nothing runs
    // on-behalf).
    assert!(!refused(65534, 10000, true, false));
    assert!(!refused(0, 10000, false, false));
    // F14: a non-root euid holding effective CAP_SETUID/CAP_SETGID can
    // perform the same privileged cross-uid remap as euid 0 and is refused.
    assert!(refused(65533, 10000, true, true));
    assert!(refused(1000, 20000, true, true));
    assert!(!refused(65533, 10000, true, false));
    assert!(!refused(65533, 10000, false, true));
    assert!(!refused(65533, 0, true, true), "host uid 0 needs no remap");
}

/// F14 pure decision: the capability dimension is orthogonal to euid — a
/// non-root caps holder is refused exactly like euid 0, while the same euid
/// without caps stays untouched (the separate unprivileged-userns refusal in
/// context.rs covers it later, with a different message).
#[test]
fn mediation_identity_gate_refuses_nonroot_effective_caps_remap() {
    let refused = |euid: u32, host_uid: u32, mediation: bool, caps: bool| {
        crate::sandbox::mediation_remap_is_refused(euid, host_uid, mediation, caps)
    };

    // The route-B ③ launcher shape (euid != 0 + effective caps) is refused
    // for any non-zero remap target when mediation is active.
    assert!(refused(65533, 10000, true, true));
    assert!(refused(1000, 1000 + 1, true, true));
    // Host uid 0 needs no remap even with caps.
    assert!(!refused(65533, 0, true, true));
    // No mediation / no caps / same-uid remain untouched.
    assert!(!refused(65533, 10000, false, true));
    assert!(!refused(65533, 10000, true, false));
    assert!(!refused(65533, 65533, true, true));
}

/// I1 review fix: the on-behalf open gate is `has_denied_paths()` on the
/// shared `DeniedSet`, which receives both static `fs_denied` paths and
/// live `policy_fn`-issued `deny_path()` calls — so spawn-time mediation
/// capability must include a present `policy_fn`, not just the static
/// triggers.  The refusal is capability-based (conservative): the explicit
/// `supervisor` tier is the escape hatch.
#[test]
fn mediation_active_covers_policy_fn_deny_capability() {
    let active = |fs: bool, chroot: bool, cow: bool, pfn: bool| {
        mediation_active_for(false, fs, chroot, cow, pfn)
    };
    // Each static trigger alone activates mediation...
    assert!(active(true, false, false, false));
    assert!(active(false, true, false, false));
    assert!(active(false, false, true, false));
    // ...and so does a live path-denying policy_fn (the I1 shape).
    assert!(active(false, false, false, true));
    assert!(!active(false, false, false, false));
    // no_supervisor disables the notif supervisor, so nothing is mediated.
    assert!(!mediation_active_for(true, true, true, true, true));

    // Composite: root in-process + RunAs(nonzero) + policy_fn-only
    // mediation is refused under the default caller tier.
    assert!(mediation_remap_is_refused(
        0,
        10000,
        mediation_active_for(false, false, false, false, true),
        false,
    ));
    // Non-root and no-mediation composites stay untouched.
    assert!(!mediation_remap_is_refused(
        65534,
        65534,
        mediation_active_for(false, false, false, false, true),
        false,
    ));
    assert!(!mediation_remap_is_refused(
        0,
        10000,
        mediation_active_for(false, false, false, false, false),
        false,
    ));
}

#[test]
fn minimal_dev_registers_exactly_the_six_dev_nodes() {
    // The helper's six-node set is a semantic contract (F6.2/P5): drift here
    // would silently change which /dev nodes a caller exposes and whether a
    // whole-tree host /dev mount is still needed.
    let policy = Sandbox::builder().minimal_dev().build().unwrap();
    let expected: Vec<(PathBuf, PathBuf)> = [
        "/dev/ptmx",
        "/dev/pts",
        "/dev/null",
        "/dev/urandom",
        "/dev/zero",
        "/dev/tty",
    ]
    .iter()
    .map(|p| (PathBuf::from(p), PathBuf::from(p)))
    .collect();
    assert_eq!(policy.fs_mount, expected);
    assert!(
        policy.fs_mount_ro.is_empty(),
        "minimal_dev nodes are rw (guests write to null/zero/ptmx); ro must be \
         opted into per node, got: {:?}",
        policy.fs_mount_ro,
    );
}
