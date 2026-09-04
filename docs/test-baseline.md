# sandlock fork test baseline — Linux 7.0.14-orbstack-00380-ga7e0a2dc9535, Landlock ABI 8, Python 3.11.16

# Measured 2026-09-04 in sandlock-dev:latest (Debian trixie x86_64, cargo 1.98,
# python 3.11.16), repo mounted at /src, --privileged; kernel
# 7.0.14-orbstack-00380-ga7e0a2dc9535; Landlock ABI 8 (read via
# sandlock.landlock_abi_version() from the FFI debug lib).
#
# Two-phase full gate (see scripts/test-all.sh header):
#   1. non-root phase (entrypoint drops to uid 65534): core_lib, core_integ,
#      ffi, cli, cli_build, python — `sh scripts/test-all.sh`
#   2. root-mode phase: oci — `sh scripts/test-all.sh --oci-root` as root.
core_lib = 791 # F1.4 (SL-8): +1 plan unit test pidfd_release_is_idempotent
               # in resource.rs
core_integ = 488 # F2.1 (M0 lifecycle lift): 477 -> 481 (+4 lifecycle tests);
                 # F2.2 (shutdown seven-step order + idempotency): 481 -> 484,
                 # +3 in integration/test_instance_lifecycle.rs
                 # (test_shutdown_escalates_after_grace_for_term_ignoring_child,
                 # test_shutdown_without_wait_closes_pidfd_and_http_acl,
                 # test_drop_after_wait_child_disposes_cow_branch); the
                 # existing idempotent test gained explicit three-call +
                 # control-dir/no-residue assertions (same count).
                 # F2.2 review fix I-1: 484 -> 485, +1
                 # (test_shutdown_group_sweep_after_compliant_grace_exit).
                 # F2.3 (stats surface): 485 -> 488, +3 in
                 # integration/test_instance_lifecycle.rs
                 # (test_instance_stats_live_reconciled,
                 # test_one_shot_stats_terminal_after_shutdown,
                 # test_shutdown_draining_observable_on_cancelled_shutdown).
                 # All other suites unchanged. (481 = F1.4's +2 orphan tests
                 # on top of the F1.3 control-auth pair 471 -> 475, then
                 # +4 F2.1.)
ffi = 89
cli = 95      # after F0.4 wiring (cli suite includes net_bind_map tests)
supervise = 17 # F2b.1: new crates/sandlock-supervise (full-field policy entry +
               # uid self-check; 13 lib unit + 4 integration tests, including
               # test_supervise_refuses_wrong_uid and
               # test_policy_roundtrip_covers_every_field)
oci = 144     # ROOT-MODE: run via scripts/test-all.sh --oci-root as root. oci e2e
              # supervises OCI-default root containers; S1.2 fail-closes
              # RunAs(0,0) for non-root supervisors (tested feature). 140 = 55+67+18
              # (lib + bin + integration: the bin target recompiles the crate
              # module tests, so the F1.2 pair supervisor::tests::
              # early_exits_cap_drops_overflow / test_unknown_pid_exit_frame_bounded
              # runs in both unit targets, +4 over 127 = 51+63+13). F1.5 (SL-6):
              # 131 -> 133: +2 in the new tests/test_init_reaper.rs integration
              # target (test_adopted_orphan_is_reaped +
              # test_no_defunct_after_double_fork); lib/bin totals unchanged.
              # F1.7 (SECE-6): 133 -> 138, +5 net = +1 init::proto
              # signal_req_roundtrip unit test (lib 53->54, bin 65->66) and +3
              # in the new tests/test_process_groups.rs integration target
              # (test_child_killpg_does_not_hit_sibling,
              # test_instance_kill_covers_all_child_groups,
              # test_signal_to_sibling_pid_rejected); reaper target unchanged.
              # F1.8 (deadline): 138 -> 140, +2 net = +1 supervisor::tests::
              # test_request_timeout_returns_error_within_deadline unit test
              # (lib 54->55, bin 66->67); all three integration targets
              # unchanged (18). F1.6 (SL-5): 140 -> 144, +4 net = +1
              # init::proto::tests::frame_decoder_rejects_oversize_and_truncated
              # unit test (lib 55->56, bin 67->68) and +2 in tests/integration.rs
              # (test_malformed_frames_do_not_leak_fds +
              # test_eof_closes_received_fd; integration 18->20, now
              # 56 lib + 68 bin + 15 integration.rs + 2 reaper + 3 process
              # groups = 144).
cli_build = 0 # workspace release build gate (no test binaries; 0 = build passed)
python = 441  # fork S2.x-era python tests landed after the plan's 430/431 estimate
