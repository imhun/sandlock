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
core_lib = 822 # F6.2 review I1/I2: 821 -> 822, +1 unit test
               # (sandbox::tests::minimal_dev_registers_exactly_the_six_dev_
               # nodes) pinning the minimal_dev() six-node rw set.
               # F6.1 review I1: 820 -> 821, +1 unit test
               # (mediation_active_covers_policy_fn_deny_capability) pinning
               # the policy_fn-mediated on-behalf trigger in the C档
               # predicate. F6.1 (SL-1): 816 -> 820, +4 unit tests in
               # sandbox/tests.rs (mediation_run_as parse/default/serde
               # round-trip + the C档 refusal-decision truth table).
               # F5 review I1: 813 -> 816, +3 unit tests for the pid-ns
               # stray-sweep translation guard (passthrough without pid_ns,
               # translation failure skips the raw ns pid, poisoned map
               # skips). F5 (M3 semantics): 812 -> 813, +1 unit test
               # (sandbox::tests::default_max_processes_is_whole_box_256)
               # pinning the whole-box max_processes default of 256 (F5.1).
               # F4 re-review (C1): 810 -> 812, +2 fork-based seccomp/state.rs
               # unit tests (pgid_entry_pruned_once_group_is_empty,
               # pgid_entry_survives_leader_exit_with_live_member) pinning
               # group-emptiness probing with kill(-pgid, 0) instead of
               # getpgid(leader). F4 review follow-up (I1/I2 + minors):
               # 805 -> 810, +1
               # exec_params S9 unit test (fs_deny'd cwd refused) and +4
               # seccomp/state.rs unit tests (DenyList-covered IP refused,
               # deny-all refused, per-protocol composition never widens a
               # deny-all/port-scoped ceiling, attributed-default child
               # prunes on exit). F4.3/F4.4 (M2 update_network staleness +
               # per-child network
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
core_integ = 531 # F8 (P6 design tradeoffs): 529 -> 531, +2 tradeoff-pin
                 # tests in integration/test_network.rs
                 # (test_injected_connect_reports_synthetic_addresses,
                 # test_nonblocking_connect_reports_einprogress) pinning the
                 # documented current behavior — injected connects report
                 # host-side peer/local (no synthetic address view) and the
                 # fd-inject connect path never surfaces EINPROGRESS
                 # (host-side completion, SO_SNDTIMEO bound). Both close
                 # fork-plan §F8 (P6) as documented design tradeoffs; see
                 # docs/e2b-integration.md §2 P6 / §3.10.
                 # F7 (P4): 526 -> 529, +3 chroot + net_isolation +
                 # net_bind_map mirror tests in integration/test_net_isolate.rs
                 # (mcp roundtrip / epoll loop / poll loop under chroot). The
                 # P4 "combined shape fails" premise was refuted by exhaustive
                 # reproduction (HEAD and the T4-era commit both green); the
                 # +3 pin the verified shape as regression coverage, not a fix.
                 # F6.2 (P5): count unchanged — the F6.1 chroot-form A档
                 # test now constructs /dev via the minimal_dev single-node
                 # helper (no whole-tree /dev mount, no fs_denied) and writes
                 # to /dev/null through it.
                 # F6.1 (SL-1): 522 -> 526, +4 — 2 in the new
                 # integration/test_mediation_identity.rs (A档:
                 # test_nonroot_created_file_owned_by_self,
                 # test_denied_path_still_denied), +1 chroot-form in
                 # integration/test_chroot.rs
                 # (test_chroot_mediated_create_is_owned_by_caller_and_self_
                 # chmod_works) and +1 COW-form in
                 # integration/test_cow.rs
                 # (test_cow_mediated_create_is_owned_by_caller_and_self_
                 # chmod_works).
                 # F5 (M3 semantics): 514 -> 522, +8 tests —
                 # 7 in integration/test_instance_semantics.rs
                 # (test_max_processes_default_bounds_whole_box,
                 # test_checkpoint_with_multiple_children_is_refused,
                 # test_checkpoint_single_live_child_captures_that_child,
                 # test_dead_state_surfaces_single_error_code,
                 # test_idle_timeout_drains_and_shuts_down,
                 # test_max_lifetime_forces_shutdown_with_live_child,
                 # test_pid_ns_procfs_scope_narrows_to_child) and 1 in
                 # integration/test_pid_ns.rs
                 # (test_init_reaps_ns_pid_1_exit). F4 re-review (C1/R2 +
                 # minors): 509 -> 514, +5 in
                 # integration/test_instance_exec_params.rs
                 # (test_bound_child_pgid_entry_survives_leader_exit,
                 # test_main_workload_egress_survives_exec_child_announcement,
                 # test_unattributed_orphan_is_denied_end_to_end,
                 # test_failed_chdir_is_loud_exit_125,
                 # test_update_network_refuses_static_denylist_destination);
                 # the update_network staleness test now runs a second
                 # concurrent pre-update child and asserts the exact stale
                 # list. F4 review follow-up (I2/I4): 507 -> 509, +2 in
                 # integration/test_instance_exec_params.rs
                 # (test_bound_lineage_escapee_is_denied_sibling_wide_
                 # destination, test_live_policy_tightening_denies_bound_
                 # child). F4.3/F4.4 (M2 update_network staleness + per-child
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
ffi = 98 # F6.2 review I1/I2: 96 -> 98, +2 in tests/fs_mount.rs
         # (test_rw_mount_point_resists_unlink_and_rename — EBUSY guard on
         # unlink/rename/link at mount points plus ro-over-writable-prefix
         # EACCES; test_single_file_leaf_opens_without_rootfs_parents — the
         # missing-parent direct-open pin). The I1 RED (rm of an rw mount
         # point deleted the host file) is in tmp/sdd/f6.2-fix-red-i1.log.
         # F6.2 (P5): 94 -> 96, +2 in tests/fs_mount.rs
         # (test_mount_single_file_node, test_mount_chardev_node) — single
         # file/chardev bind-mount points open instead of failing ENOTDIR.
         # F6.1 (SL-1): 92 -> 94, +2 in the new tests/mediation_run_as.rs
         # (builder_mediation_run_as_supervisor_lands_on_policy,
         # builder_mediation_run_as_defaults_to_caller_and_invalid_stays_
         # closed).
         # F5.4 adds SANDLOCK_INSTANCE_ERR_DEAD (code 6) to the error-code
         # mapping and header; no new FFI test target (mapping-only, covered
         # by the core Dead tests). F3.3 (instance exec FFI): 89 -> 92, +3 in the new
         # tests/instance_exec.rs (instance_exec_streams_stdio_and_waits_
         # by_child_id, instance_exec_rejects_unknown_stdio_mode,
         # instance_kill_after_reap_is_idempotent). The C smoke target
         # compiles the regenerated sandlock.h against the cdylib (still 1);
         # header regeneration also picks up pre-existing drift at HEAD
         # (missing sandlock_sandbox_builder_notify_rate_limit declaration).
cli = 98      # F6.2 (P5): 97 -> 98, +1 in tests/cli_test.rs
              # (test_fs_mount_flag_wired_end_to_end_single_file) — the
              # --fs-mount flag drives a chroot single-file mount through the
              # real binary (the --pid-ns wiring-miss class is pinned).
              # F6.1 (SL-1): 95 -> 97, +2 in tests/cli_test.rs
              # (test_mediation_run_as_flag_accepted_and_runs,
              # test_mediation_run_as_rejects_unknown_value_at_parse; the
              # root-tier wiring proof lives in the mediation_2uid suite).
              # after F0.4 wiring (cli suite includes net_bind_map tests);
              # F5.1 updates the no-supervisor default validation to
              # DEFAULT_MAX_PROCESSES (256), no count change
supervise = 36 # F6.1 (SL-1): 35 -> 36, +1 unit test
               # (policy::tests::mediation_run_as_rejects_unknown_wire_value)
               # alongside the mediation_run_as manifest/apply/verify/readback
               # extension. F5.4 adds the InstancePhase::Dead stats label; count
               # unchanged. Non-root targets only (--lib --test supervise): the
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
supervise_cost = 3 # F2b.4 cost target (release-only): new
                   # tests/supervise_cost.rs — the three plan-named cost
                   # tests (per-sandbox supervisor PSS within budget at the
                   # four protocol points, exec round-trip latency within
                   # budget with tmp/perf/ profile, exit frames never lost
                   # over 1000 rounds). Run by scripts/test-all.sh as its own
                   # release label (CARGO_BIN_EXE_sandlock-supervise = the
                   # release binary) with --test-threads=1. Counts/budgets
                   # documented in docs/supervise-capacity.md.
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
mediation_2uid = 5 # ROOT-MODE: run via scripts/test-all.sh
                   # --mediation-2uid as root (same privileged container as
                   # oci). F6.1 (SL-1) acceptance in
                   # crates/sandlock-supervise/tests/mediation_2uid.rs:
                   # test_two_supervisors_distinct_uids_isolate_files (B档
                   # two supervise mediators at uid 65531/65532 via setpriv,
                   # shared 1777+sticky dir, exact EPERM/ownership asserts),
                   # test_root_inprocess_mediation_is_refused (C档 default
                   # refusal + explicit supervisor tier with stats counter),
                   # test_root_inprocess_mediation_refused_with_policy_fn_
                   # deny_shape (review I1: live policy_fn deny_path()
                   # capability is a mediation trigger and is refused under
                   # caller; explicit supervisor tier runs),
                   # test_root_inprocess_mediation_with_caps_kept_would_leak
                   # (C档 control: root-owned file + sticky-bypassing
                   # unlink prove the downgrade is real), and
                   # test_cli_mediation_run_as_is_wired (root-tier CLI
                   # refusal vs --mediation-run-as supervisor warning).
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
python = 454  # F6.2 (P5): 453 -> 454, +1 in tests/test_fs_mount.py
              # (TestFsMount::test_minimal_dev_helper) — the minimal_dev()
              # helper content is exact and its /dev/null mount serves the
              # host chardev under chroot without fs_denied.
              # F6.1 (SL-1): 450 -> 453, +3 in tests/test_sandbox_config.py
              # (TestMediationRunAs defaults / native round-trip / invalid
              # value rejection). F5.1 updates the Sandbox default + builder condition to 256;
              # count unchanged. F4 (M2 per-exec params + S9 + update_network):
              # 446 -> 450, +4
              # in the new tests/test_instance_exec_params.py
              # (test_per_exec_cwd_and_env_apply,
              # test_wider_policy_is_rejected,
              # test_update_network_applies_to_new_exec_only_and_reports_
              # staleness, test_per_exec_bind_port_reaches_listener);
              # SandboxInstance.exec gained keyword-only cwd/env/clean_env/
              # extra_writable/bind_ports, update_network(ips) returns the
              # stale child ids, and wider requests raise PermissionError.
              # fork S2.x-era python tests landed after the plan's 430/431
              # estimate. F3.3: 441 -> 445, +4 in tests/test_instance_exec.py
              # (test_exec_returns_self_owned_process,
              # test_exec_after_close_returns_same_error,
              # test_exec_process_context_manager_reaps_on_error,
              # test_exec_pty_returns_master_and_resize).
              # F3.2/3.3 review follow-up (drop contract): 445 -> 446, +1
              # (test_dropped_exec_process_is_reaped_on_del).
