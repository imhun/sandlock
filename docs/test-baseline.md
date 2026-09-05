# sandlock fork test baseline — Linux 7.0.14-orbstack-00380-ga7e0a2dc9535, Landlock ABI 8, Python 3.11.16

# Measured 2026-09-04 in sandlock-dev:latest (Debian trixie x86_64, cargo 1.98,
# python 3.11.16), repo mounted at /src, --privileged; kernel
# 7.0.14-orbstack-00380-ga7e0a2dc9535; Landlock ABI 8 (read via
# sandlock.landlock_abi_version() from the FFI debug lib).
#
# Two-phase full gate (see scripts/test-all.sh header):
#   1. non-root phase (entrypoint drops to uid 65534): core_lib, core_integ,
#      ffi, cli, cli_build, python — `sh scripts/test-all.sh`
#   2. root-mode phases: oci (`--oci-root`) and the supervise foreign-uid
#      acceptance (`--supervise-root`), both as root in the same privileged
#      container.
core_lib = 805 # F4.3/F4.4 (M2 update_network staleness + per-child network
               # binding): 803 -> 805, +2 unit tests in seccomp/state.rs
               # (bound_child_policy_wins_over_shared_static_policy,
               # sibling_group_never_shares_a_bound_policy).
               # F4.1/F4.2 (M2 per-exec params + S9): 799 -> 803, +4 unit
               # tests in the new core/src/exec_params.rs (S9 ceiling
               # validation: in-ceiling accepts, wider extra_writable refuses,
               # fs_deny never overridable, out-of-ceiling cwd/bind_ports
               # refuse). F1.4 (SL-8): +1 plan unit test pidfd_release_is_idempotent
               # in resource.rs.
               # F3.1 (exec machinery lift): 791 -> 797, +6 unit tests moved
               # verbatim with their code from sandlock-oci into
               # core/src/init/{proto.rs,fdpass.rs} (frame decoder + Req/Resp/
               # Signal round-trips + two SCM_RIGHTS round-trips). oci keeps
               # the same tests re-hosted against the re-export seam, so its
               # 144 stays exactly unchanged (relocation, not rewrite).
               # F3.2/3.3 review follow-up (deadline-orphan teardown): 797 ->
               # 799, +2 executor unit tests exercising the discard-late-
               # Started branches directly through the reader
               # (late_started_without_pending_is_recorded_for_teardown,
               # started_with_dropped_receiver_is_recorded_for_teardown).
core_integ = 507 # F4.3/F4.4 (M2 update_network staleness + per-child
                 # network binding): 506 -> 507, +1 in
                 # integration/test_instance_exec_params.rs
                 # (test_update_network_applies_to_new_exec_only_and_
                 # reports_staleness). F4.1/F4.2 (M2 per-exec params + S9):
                 # 503 -> 506, +3 in the
                 # new integration/test_instance_exec_params.rs
                 # (test_per_exec_cwd_and_env_apply,
                 # test_wider_policy_is_rejected,
                 # test_per_exec_bind_port_reaches_listener). F2.1 (M0
                 # lifecycle lift): 477 -> 481 (+4 lifecycle tests);
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
                 # F2b.2 (dual transport): 488 -> 493, +5 in
                 # integration/test_control.rs
                 # (test_socketpair_channel_rejects_third_party,
                 # test_fd_handoff_channel_rejects_third_party,
                 # test_path_mode_peer_uid_mismatch_closes,
                 # test_registered_path_channel_accepts_allowlisted_peer_with_token,
                 # test_sandbox_cannot_reach_sibling_channel).
                 # F2b.2 review fix (I1): 493 -> 494, +1
                 # (test_list_prune_keeps_live_registered_channel).
                 # F3.2 (per-child exec API): 494 -> 502, +8 in the new
                 # integration/test_instance_exec.rs
                 # (test_two_concurrent_exec_keep_independent_stdio,
                 # test_double_wait_child_is_idempotent,
                 # test_close_stdin_does_not_deadlock,
                 # test_exec_after_shutdown_returns_same_error,
                 # test_grandchild_holding_stdout_does_not_hang_wait_or_shutdown,
                 # test_child_registry_rejects_unknown_child_id,
                 # test_kill_child_after_reap_is_idempotent,
                 # test_exec_pty_returns_master_and_resize_works).
                 # The M0 no-arg wait_child became wait_main (per-child
                 # wait_child(child_id) is the F3.2 surface); no M0 test was
                 # removed or weakened.
                 # F3.2/3.3 review follow-up (exec-mode terminal semantics):
                 # 502 -> 503, +1 in test_instance_exec.rs
                 # (test_exec_mode_main_exit_is_terminal_and_verbs_close);
                 # one-shot outlives regression stays green in
                 # test_instance_lifecycle.rs.
ffi = 92 # F3.3 (instance exec FFI): 89 -> 92, +3 in the new
         # tests/instance_exec.rs (instance_exec_streams_stdio_and_waits_
         # by_child_id, instance_exec_rejects_unknown_stdio_mode,
         # instance_kill_after_reap_is_idempotent). The C smoke target
         # compiles the regenerated sandlock.h against the cdylib (still 1);
         # header regeneration also picks up pre-existing drift at HEAD
         # (missing sandlock_sandbox_builder_notify_rate_limit declaration).
cli = 95      # after F0.4 wiring (cli suite includes net_bind_map tests)
supervise = 35 # Non-root targets only (--lib --test supervise): the
               # root-mode foreign-uid target supervise_root is separate.
               # F2b.1: new crates/sandlock-supervise (full-field policy entry +
               # uid self-check; 13 lib unit + 4 integration tests, including
               # test_supervise_refuses_wrong_uid and
               # test_policy_roundtrip_covers_every_field).
               # F2b.2: 17 -> 22 (+1 lib unit egress_proxy_full_config_reads_back_equal,
               # +4 integration: real --policy <fd> happy path + timeout +
               # oversize-limit semantics, and single-generation fd-serve
               # lifecycle test_supervise_serves_control_fd_until_shutdown).
               # F2b.2 review fix (I2/I4): 22 -> 26, +4 integration
               # (test_supervise_serve_eof_without_shutdown_exits_nonzero,
               # test_supervise_serve_wrong_token_exits_nonzero,
               # test_supervise_rejects_non_socket_control_fd,
               # test_supervise_policy_fd_partial_write_stall_times_out).
               # F2b.3: 26 -> 34 (+4 lib units ProgramSpec parse/refuse
               # cases; +4 integration: instance verbs over fd serve
               # (test_supervise_fd_serve_launches_instance_and_serves_
               # instance_verbs), instance verbs over the registered path
               # (test_supervise_path_serve_launches_instance_and_serves_
               # verbs_until_shutdown), AF_UNIX SO_DOMAIN refusal
               # (test_supervise_rejects_non_unix_socket_control_fd), and
               # the forbidden-remap pin
               # (test_supervise_refuses_runtime_uid_map_verbs)).
               # F3.2 (exec verb + per-child verbs over both transports):
               # count unchanged (18 lib + 16 integration). The two instance
               # verb tests now drive a REAL exec (stdio fds over SCM_RIGHTS
               # on the F2b.2 control channel) with wait_child/kill_child
               # round-trips instead of the F3 skeleton error; supervise
               # generations now launch exec-capable sessions (launch_exec).
               # F3.2/3.3 review follow-up (main-exit generation end): 34 ->
               # 35, +1 integration
               # (test_supervise_main_exit_ends_generation_cleanly).
supervise_root = 2 # ROOT-MODE: run via scripts/test-all.sh
                   # --supervise-root as root (same privileged container as
                   # oci). F2b.3 foreign-uid acceptance in
                   # tests/supervise_root.rs: supervise as uid 65533 via
                   # setpriv, worker as uid 65534 —
                   # test_supervisor_as_foreign_uid_is_fully_functional
                   # (registered path; box/mediation/DNS/inbound/stats/
                   # shutdown/no-residue) and
                   # test_supervisor_as_foreign_uid_fd_handoff_serves_worker
                   # (fd transport, same genuine identities).
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
python = 446  # fork S2.x-era python tests landed after the plan's 430/431
              # estimate. F3.3: 441 -> 445, +4 in tests/test_instance_exec.py
              # (test_exec_returns_self_owned_process,
              # test_exec_after_close_returns_same_error,
              # test_exec_process_context_manager_reaps_on_error,
              # test_exec_pty_returns_master_and_resize).
              # F3.2/3.3 review follow-up (drop contract): 445 -> 446, +1
              # (test_dropped_exec_process_is_reaped_on_del).
