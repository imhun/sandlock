# sandlock fork test baseline — Linux 7.0.14-orbstack-00380-ga7e0a2dc9535, Landlock ABI 8, Python 3.11.16

> **2026-09-22 状态（E2B 侧；表已按这一轮的门禁绿跑刷新）**：上一版这张注记里的"数字本身不稳定"
> 查清了 —— 三条红的成因互不相同，**都已修**，而且顺着它挖出了两个把门禁挡住的真问题。现在
> **四个相位全绿**：默认相位 `core_lib 891 / core_integ 545 / ffi 104 / cli 97 / supervise 51 /
> supervise_cost 3 / cli_build 0 / python 465`（`--oci-root` 157、`--supervise-root` 4、
> `--mediation-2uid` 9）；证据是 fork 仓 `tmp/test-all-*.log`（2026-09-22 13:54–14:01）。
> 下面三格数字因此动过：`core_lib` 848 → 891、`core_integ` 543 → 545、`supervise` 43 → 51。
>
> 修的是什么：
>
> * `..._flaky.log` 的 **886/2**（`rename_staging_failure_fails_rename_and_rolls_back`、
>   `write_open_in_unreadable_dir_virtualizes`）**不是负载下的时序，是那次以 root 跑**：这两条用例
>   的夹具就是 `0o000` 模式位，而 `CAP_DAC_OVERRIDE` 直接读穿它。同文件里的兄弟用例早就写着
>   `Skipped as root, where CAP_DAC_OVERRIDE makes the directory readable`，这两条漏了。以 root 复现，
>   断言行号与原日志逐条一致（4823 / 4376）；补上同一守卫后，root 与非 root 两种形态都是 888/0。
> * `..._gate.log` 的 **887/1**（`sigstop_inside_the_fork_tracking_window_ends_as_a_real_stop`）是**两处**
>   真问题：① 夹具 `sh -c 'sleep 30'` 并不是"不会 fork 的 caller"——dash 对非内建命令 fork 并留在父位置，
>   那个 fork 与 SIGSTOP 竞争（负载下 40 次跑出 3 次红，断言 `!created`）；换成本身不 fork 的
>   `/bin/sleep 30` 后该断言不再红。② 之后暴露的 `State == 'T'` 断言把"窗口关闭"与"内核把 stop 投递给
>   已脱管任务"当成同一时刻读 —— 负载下读到 `R` + `TracerPid 0`（60 次跑出 4 次红）。改成有界等待
>   （5 s 轮询）后，**6 个 CPU hog / 8 核下 60+80 次全绿**；变异（把 `DETACH`-with-`SIGSTOP` 换回
>   `PTRACE_CONT`）仍然被抓：2/2 红在上述新断言上（`state 't'` + 残留 tracer）。
> * 修完复量：`cargo test -p sandlock-core --offline --lib` = **888 passed / 0 failed**，root 与非 root
>   两种形态、以及负载下均一致（4 次独立运行）。表里写的 848 是旧的，**正确的数是 888**。
> * `core_integ` 那条挂起**已修**（2026-09-22 同一轮，E2B 仓 N33）：`test_chroot_magic_fd_symlink_
>   resolves_to_child_fd` 的 magic link 让字节监控登记了子进程自己的 stderr **管道**并保留了自己的
>   dup，于是 capture 管道在子进程退出后仍不 EOF、`wait()` 永不返回（dup 只在 sandbox drop 时释放，
>   而 drop 在那次 wait 之后）。现在 `inject_watched` 只监控**有大小**的 open（`holds_a_file_size`），
>   创建非普通条目时的条目数记账保留；同一条路径还带来一个副作用修正：`/dev/null` 这类重定向不再
>   进字节监控（它正是"空池瞬间给后续 fork 留下 1 MiB 地板"的来源）。整档现在跑完：
>   **545 passed / 0 failed / 85.84s**（`core_integ` 那一格已按此更新）。RED 证明：把分类变异成
>   恒真后，新增的有界用例在 30 s 超时断言上红（`tmp/k0s/sigstop-logs/mutant-bounded.log`）。
> * 排查用提示（E2B 仓 N34）：这个套件直接跑二进制时要用**管道**接输出。`scripts/test-all.sh` 的
>   `run()` 早就为此把每条套件 tee 过匿名管道并写明理由；`--nocapture` + 文件重定向会让
>   `test_restore::test_restore_glibc_vdso_program_resumes` 红（恢复进程重开不了那个普通文件）。
> * 同一轮还修掉一个会把整个 chroot 家族变成假红的状态坑：共享夹具目录里的残留 rootfs 会让
>   `build_test_rootfs` 回退 `fs::copy`，而它的目标与共享的 `tests/rootfs-helper` **同 inode** ⇒
>   打开写入把源截断成 0 字节，之后所有 chroot 用例报 `Exec format error`。`test_chroot.rs` 现在与
>   `test_instance_chroot.rs` 一样（单调 seq + 先清目录），`build.rs::build_static` 改成编译到同级
>   临时文件再 `rename` 发布。E2B 仓 `docs/build-test-deploy-pitfalls.md` B12。
> * 挂起修好后门禁继续往下走，立刻撞到 N25/C 漏下的一处编译错误：`Req::RunExec` 新增的
>   `max_file_size` 在 `sandlock-oci` 里有 **1 处生产字面量 + 4 处测试字面量**没跟上，而
> `cli_build`（release 构建门）与 `--oci-root` 相位是唯一会编译那个 crate 的地方 —— 换句话说，
> N25 之后**从来没有人跑过这道门**。补的是 `None`（OCI 的 exec verb 没有预算旋钮），并让
> `sandlock-oci::init::req_roundtrip` 断言那个字段的**值**而不只是形状。E2B 仓 pitfalls 的 A6
> 就是这一族（"新增字段改不全，lane 全绿而 fork 门禁编译不过"），这轮多了一个新形状：
> 卡住它的不是 `--lib`，而是 release 构建 + oci 相位。
>
> 也就是说：这一轮既修掉了那三条时序红，也把挡住绿跑的**两个真问题**（magic-link 挂起、oci
> 缺字段）修掉了，表按绿跑刷新。E2B 侧的验收记录在 `docs/k8s-deployment.md` §22.5.12 与
> `docs/build-test-deploy-pitfalls.md` §B5–B9/B12。

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
#      container — plus mediation_2uid (`--mediation-2uid`) and the release
#      supervise_cost label inside the non-root phase.
#
# Invocation matters for `core_integ` (measured 2026-09-23, E2B N35 follow-up):
# it is a non-root, single-threaded suite, and running it as root with the
# default parallelism reports **8 failures** that are not defects:
# test_control::test_socketpair_channel_rejects_third_party,
# test_instance_lifecycle::test_shutdown_without_wait_closes_pidfd_and_http_acl,
# the five test_net_isolate::test_net_isolation_inbound_mapping_* cases (plain,
# _mcp_roundtrip, _poll_, _under_chroot_epoll_, _under_chroot_mcp_roundtrip) and
# test_transaction::test_txn_merge_failure_preserves_the_unmerged_change_set.
# Re-run as root *alone* only 4 of those 8 still fail (the other 4 are
# order-dependent), and all 8 pass in the canonical shape — the same class as
# the root-mode `0o000`-fixture reds recorded below: `CAP_DAC_OVERRIDE` and the
# shared container netns change what the fixtures observe. Canonical =
# `cargo test -p sandlock-core --offline --test integration -- --test-threads=1`
# as uid 65534 with CARGO_HOME/HOME pinned by scripts/test-all.sh.
#
# Final fork-plan full-gate re-verification (F9, 2026-09-05): every label below
# re-run green at the F9 tip in sandlock-dev:latest (--privileged, repo mounted
# at /src) — logs tmp/sdd/f9-gate-nonroot.log / f9-oci-root.log /
# f9-supervise-root.log / f9-mediation-2uid.log; wheels rebuilt and verified at
# the same tip (tmp/sdd/f9-wheel-build.log / f9-wheel-verify.log). Counts are
# unchanged from the per-task registrations below; this header is the dated
# confirmation for the fork-plan closure.
#
# F12 (2026-09-06): ProcessIndex one-entry-per-TGID modeling closure —
# 823 -> 827, +4 unit tests in resource.rs + seccomp/state.rs
# (thread_notification_registers_single_leader_entry,
# thread_notification_never_adds_second_key_for_tracked_leader,
# thread_notified_group_cleans_up_single_entry_on_exit,
# thread_of_tracked_leader_resolves_to_leaders_entry); one existing cwd test
# updated to the leader-aware tracking shape. core_integ unchanged at 533.
#
# F10 (2026-09-06): supervisor-tier × chroot create/launch regression fixed
# (confine_child runs the real chdir + Landlock rule build before the userns
# remap drops the child to the sandbox host uid, so a root-only 0700 image
# cache no longer EACCESes create/exec). +1 core_integ (new
# test_instance_chroot.rs non-root same-uid exec-only acceptance) and +3
# mediation_2uid (root RunAs(10000)/uid0 restrictive-cache acceptance) —
# logs tmp/sdd/f10-*.
#
# A3 (2026-09-10, A2 alias-normalization wave): every label below re-run at
# c6cbe03 in sandlock-dev:latest (--privileged, repo mounted at /src) — logs
# tmp/a3-gate-nonroot.log / a3-gate-oci-r1.log (red) + a3-gate-oci-final.log
# (the FUP-09 re-run; the only red was the pre-existing oci
# test_signal_to_sibling_pid_rejected timing flake, reproduced at aadb5ad —
# see tmp/a3-oci-full-repeat.log / a3-oci-baseline-repeat.log) /
# a3-gate-supervise-root.log / a3-gate-mediation.log, wheels rebuilt + verified
# at the same tip
# (tmp/a3-wheel-build.log / a3-wheel-verify.log). Only core_lib (842 -> 846)
# and core_integ (534 -> 539) move, by the A1/A2 test cases registered below;
# ffi / cli / supervise / supervise_cost / cli_build / python / oci /
# supervise_root / mediation_2uid are unchanged.
core_lib = 912 # 2026-09-25: 911 -> 912, +1: ending a freeze must *answer* the held
               # fork notifications instead of dropping them
               # (`resource::tests::release_held_forks_drains_and_reports_what_it_released`;
               # the end-to-end half is the core_integ case below).
               # 2026-09-25: 910 -> 911, +1: the placement planner must accept targets
               # that overlap the received numbers, which is the *real* shape
               # (SCM_RIGHTS lands on the lowest free numbers; the stub wants 3/4/5/6)
               # -- relocation is what makes it safe, and it has to be tried first.
               # 2026-09-25: 909 -> 910, +1: `exec_at_fd` runs a program that exists
               # only as a descriptor (`execveat(AT_EMPTY_PATH)`), which is how the
               # restore stub can be a child of the session rather than of the
               # supervisor -- the stub is a host artifact and is not in the tree the
               # sandbox's paths resolve against.
               # 2026-09-25: 904 -> 909, +5 and all five are the descriptor-placement
               # planner a restored session needs (`init::plan_fd_placements` /
               # `wire_fds`): relocation keeps the child's chosen numbers, declining
               # relocation when the reserved range is taken, and the three refusal
               # paths (a target another descriptor sits on, duplicate/reserved
               # targets, a swapped slot caught before anything is dup'd).
               # 2026-09-25: 902 -> 904, +2 and both are the RELRO capture fix
               # (`checkpoint::capture::is_relro_map`): one pins that the
               # loader's read-only-but-written range is dumped while `.rodata`
               # is not, the other that the rule does not claim anonymous,
               # cross-object, text-following or shared read-only ranges.
               # 2026-09-24: 897 -> 902, and all +5 are the aarch64 C/R port
               # (S3), not a new unit-test surface: `restore_blob.rs` gained
               # three (a checkpoint with no FP bytes is refused; the blob
               # header carries the thread pointer; and it says when there is
               # none), `resume.rs` gained the synthetic-image restore -- the
               # first test that runs the stub itself and reads TPIDR_EL0 /
               # FPSR / FPCR back out of the restored frame -- and
               # `network/readiness.rs` gained the epoll record round-trip that
               # pinned a real aarch64 bug: `struct epoll_event` is 12 bytes
               # with `data` at offset 4 on x86_64 (packed) but 16/8 on every
               # other LP64 ABI, and the supervisor had 12/4 hardcoded, so on
               # aarch64 it read the wrong half of every record it intercepted.
               # Measured: the canonical non-root run reports 902/0.
               # 2026-09-23: 891 -> 897, and the +6 is the N35 fork work that
               # landed after the last refresh, not a new unit test surface:
               # `44c40f3` (landlock: a mount's host source gets the rights its
               # mount point declares) added 4 in `landlock.rs`, and `86630ea`
               # (realroot: the image-rootfs shape builds a real root) added 2.
               # Measured: the canonical non-root run reports 897/0, and the
               # diff that landed today (`f1fecba`, `43cc62a`, `9246d09`) adds
               # no `#[test]`/`#[tokio::test]` in src at all.
               # 2026-09-22 (the E2B gate-repair round): 848 -> 891. 888 of
               # that is the settle-the-timing-reds work below; the last +3 is
               # `chroot::dispatch::watchable_open_tests` (a regular file has a
               # size to watch, a pipe does not, a character device does not),
               # pinning the classification that fixes the core_integ hang:
               # the wrong direction there is not an assertion but a wedged
               # run, so it is worth a unit test that can only ever be cheap.
               # 848 -> 888, because
               # the three reds the previous note recorded are all fixed and
               # the count is now deterministic — measured four times, 888/0
               # every time (uid 65534 and root shapes, plus 60 loaded runs of
               # the sigstop case alone). What each red actually was:
               # two mode-bit cases in `cow/seccomp.rs::tests`
               # (`rename_staging_failure_fails_rename_and_rolls_back`,
               # `write_open_in_unreadable_dir_virtualizes`) had lost the
               # "skipped as root" guard their siblings carry — the 886/2 run
               # was a root run, not load (reproduced at the same assertion
               # lines, 4823 / 4376); and
               # `resource.rs::tests::sigstop_inside_the_fork_tracking_window_
               # ends_as_a_real_stop` had two real problems: a fixture that
               # *did* fork (`sh -c 'sleep 30'` — dash forks and stays as the
               # parent, so the fork raced the SIGSTOP) and a state assertion
               # that read /proc once, racing the kernel's delivery of the
               # stop to the detached task. See the note at the top of this
               # file for the evidence paths and the mutant proof.
               # FUP-26 (2026-09-15): 844 -> 848, +4 unit tests in
               # `sys/fs.rs::tests` pinning the bounded `EAGAIN` retry of
               # `openat2(RESOLVE_IN_ROOT)` (openat2(2): the kernel could not
               # prove a `..` did not escape — a race, and the caller "may
               # choose to retry"): two injected `EAGAIN`s are absorbed and
               # the third attempt returns the fd (exact attempt/EAGAIN
               # counts); a permanent `EAGAIN` stops after the documented
               # budget of 4 retries and is handed back as `EAGAIN` — never
               # rewritten into `ENOENT`; a non-retryable errno (`ENOENT`) is
               # returned after exactly one attempt; and the injected path
               # still calls the kernel when nothing is injected. The seam is
               # a thread-local test-only fault injection inside the product
               # function, so the *product* retry loop, its budget and its
               # errno classification are what the tests exercise (a real
               # `EAGAIN` needs a racing rename on the walked path; the
               # kernel-level rate is measured in tmp/f26-eagain-*.log).
               # Evidence: tmp/f26-lib-redgreen-r03-green.log (848 passed),
               # mutant (budget forced to 0) red in
               # tmp/f26-lib-redgreen-r02-mutant.log.
               # sigstop (2026-09-14, fork `1f113cf`): 843 -> 844, +1 unit test —
               # `resource.rs::tests::sigstop_inside_the_fork_tracking_window_
               # ends_as_a_real_stop` (the job-control stop handed back with
               # PTRACE_DETACH(SIGSTOP) must end as a real kernel `T` stop with
               # no tracer). That fix was verified in the e2b lanes and did not
               # re-run this fork gate, so the entry is a catch-up: the first
               # FUP-24 gate run reported "baseline says 843 passed, run
               # produced 844" (tmp/fup24-gate-nonroot-r01.log) and the count
               # above is that run's, unchanged by FUP-24 itself.
               # F19/SL-13 (2026-09-14): 840 -> 843, +3 unit tests — the
               # refusal code's stable wire strings + serde form, the
               # closed/dead/policy-to-code mapping in error.rs
               # (only_the_classified_runtime_errors_carry_a_refusal_code,
               # refusal_codes_are_the_stable_wire_strings), and the
               # ControlResponse frame round-trip with/without `code`
               # (control.rs: refusal_code_rides_the_response_frame_without_
               # breaking_the_old_shape).
               # B3 (2026-09-11, SL-1 hard delete): 846 -> 840, -6 unit tests
               # removed with the privileged-mediator downgrade tier:
               # sandbox/tests.rs (-3: the MediationRunAs parse /
               # default / serde round-trip cases) and profile.rs (-3: the
               # profile `[config]` key parse / absent-default / TOML
               # round-trip cases). The C档 predicate truth table
               # (mediation_identity_gate_refuses_only_root_remap_with_
               # mediation, + the F14 caps case) and
               # mediation_active_covers_policy_fn_deny_capability stay.
               # A2+A3 (2026-09-10): 842 -> 846, +4 chroot resolve unit tests
               # (crates/sandlock-core/src/chroot/resolve.rs) pinning the
              # request-derived cwd + alias normalization:
              # host_to_virtual_tie_breaks_on_declaration_order,
              # mount_walk_folds_a_shared_directory_submount_onto_the_canonical_alias,
              # mount_walk_falls_back_to_the_input_when_it_cannot_converge,
              # deny_and_read_only_fold_across_every_alias_of_a_shared_directory.
              # F18 (2026-09-09): 841 -> 842, +1 device-node-vs-FIFO arg-filter
              # test (mknod/mknodat filtered on S_IFBLK|S_IFCHR so CAP_MKNOD inside
              # the sandbox's own userns cannot mint raw-device nodes, while
              # mkfifo -- the same syscall with S_IFIFO -- keeps working).
              # F15 (2026-09-08): 837 -> 841, +4 fd_assignment_tests in
               # init/mod.rs pinning per-frame descriptor ownership (a zero-fd
               # frame cannot shift the next exec's stdio, two execs split one
               # queue in order, a short queue fails closed without consuming,
               # zero-fd frames always succeed)
               # FUP-23 (2026-09-08): 833 -> 837, +4 unit tests in init/mod.rs
               # pinning the exec-stdio plan (relocation into the reserved range,
               # declining when a reserved number is taken without destroying it,
               # exact non-cross-talking delivery through the wired 0/1/2, and
               # refusing a slot that was swapped after the fork)
core_lib_fup07 = 833 # FUP-07/FUP-10 (2026-09-07, A/B cleanup wave): 828 -> 833,
               # +3 profile mediation_run_as tests (profile.rs) +2 signal
               # delivery unit tests (init/mod.rs escaped_group/unique pgids)
               # F14 (2026-09-06): 827 -> 828, +1 unit test
               # (sandbox::tests::mediation_identity_gate_refuses_nonroot_
               # effective_caps_remap) pinning the capability-aware C档
               # predicate — non-root effective CAP_SETUID/CAP_SETGID
               # (route-B ③ file-cap launcher shape) is refused for a
               # cross-uid remap with mediation, same-uid/no-caps/no-mediation
               # stay untouched. Existing truth-table test extended to the
               # 4-argument predicate (same count).
               # F12 (2026-09-06): 823 -> 827, +4 unit tests pinning the
               # one-entry-per-TGID ProcessIndex model — resource.rs
               # (thread notification with an untracked leader registers the
               # leader once under its pid; a thread of a tracked leader adds
               # no tid key; a thread-registered group cleans up its single
               # leader entry on group exit) and seccomp/state.rs (an
               # unregistered thread resolves through /proc to the leader's
               # key/state/address-space entry). One existing cwd test
               # updated (a thread without its own key counts as tracked via
               # its leader). core_integ unchanged at 533; F11 freeze and
               # argv-safety regressions stay green.
               # F11 (2026-09-06): 822 -> 823, +1 unit test in
               # freeze.rs (freeze_deduplicates_thread_group_keys) pinning
               # the TGID-key normalization of the argv-safety exec freeze
               # (a lazily-registered non-leader thread key next to its
               # leader must not make the freeze seize one thread group
               # twice — EPERM on the second pass, F11).
               # F6.2 review I1/I2: 821 -> 822, +1 unit test
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
core_integ = 558 # 2026-09-25: 555 -> 558, +3:
                 # * `test_a_dynamic_workload_resumes_into_a_session_under_a_real_root`
                 #   -- the deployment's shape exactly (real root + mounted /usr,
                 #   /bin, /lib, /etc + a dynamic python workload restored into a
                 #   session). The fixture has to create every mount destination
                 #   inside the rootfs (`lib64`) and bind `/dev` (the device nodes
                 #   of `minimal_dev()` cannot be created in a test).
                 # * `test_a_capture_does_not_wedge_a_forking_sibling` -- a capture
                 #   holds fork notifications box-wide; releasing the freeze by
                 #   dropping the ids left that sibling parked in `fork()` forever.
                 #   Deterministic red before the fix (`held=1`), green after.
                 # * `test_a_dynamic_workload_resumes_into_a_session` -- the same
                 #   (b) shape with a real program (python) instead of the static
                 #   helper, which is what a sandbox actually runs, and what
                 #   FUP-30 is about. Skips on an image without a python3.
                 # 2026-09-25: 554 -> 555, +1 for the shape a *pooled* deployment
                 # has: the session's main child is a park, so its workload is the
                 # single child beside it -- `checkpoint()` refuses that shape by
                 # name (asserted byte for byte) and
                 # `checkpoint_excluding_main()` captures it
                 # (`test_a_sessions_workload_is_captured_with_the_park_left_out`).
                 # 2026-09-25: 553 -> 554, +1 and it is the acceptance test for an
                 # exec-capable restore: a checkpoint restored *into a session*, after
                 # which the session still serves `exec` and `children_live` counts the
                 # resumed child (`test_a_child_restored_into_a_session_keeps_the_session_executable`).
                 # 2026-09-25: 552 -> 553, +1 and it is the prerequisite the
                 # restore work's (b) shape rests on: the session's parent can
                 # `process_vm_writev`/`PTRACE_ATTACH` into an init-spawned child
                 # (`test_the_session_parent_can_write_into_an_init_spawned_child`).
                 # 2026-09-25: 551 -> 552, +1 and it is the RELRO capture fix's
                 # regression case (`test_libc_workloads_resume_after_restore`:
                 # malloc, a vDSO `clock_gettime`, stdio, plus the static
                 # control, all asserted to resume). It replaced the diagnostic
                 # test that pinned the gap, which is why this is +1 and not +2.
                 # 2026-09-24: 548 -> 551, and all +3 are the aarch64 lane's
                 # own find, not a new integration surface: `net_fixture.rs`
                 # gained three unit cases for the pre-seeded `/etc/hosts`
                 # scan (`mapping_rides_over_blank_lines`,
                 # `mapping_ignores_a_host_that_is_not_there`,
                 # `mapping_ignores_an_unparsable_address`) together with the
                 # fix that made them necessary -- a blank line used to end the
                 # scan, so on a stock Ubuntu `/etc/hosts` the fixture never
                 # saw the entry the container entrypoint had seeded. The
                 # canonical non-root run reports 551/0 (`tmp/x86-core-integ-
                 # final.log`, 85.4s, through the gate's own subshell+pipe).
                 # 2026-09-23: 546 -> 548, +2 in
                 # crates/sandlock-core/tests/integration/test_restore.rs, the
                 # no-exec restore prototype (docs/chroot-workspace-exec.md
                 # §11.5): `test_restore_resumes_inside_a_real_root_without_exec`
                 # (the real root the exec route cannot serve) and
                 # `test_restore_resumes_without_exec_and_without_chroot` (the
                 # fork-versus-exec bisect that showed the failure was not about
                 # the root at all). Both pass in the canonical single-threaded
                 # non-root phase; both fail with SIGSEGV when the suite runs
                 # these concurrently in one process, which is the fork-of-a-
                 # multi-threaded-supervisor hazard §11.5 named -- recorded, not
                 # yet diagnosed.
                 # 545 -> 546 in
                 # crates/sandlock-core/tests/integration/test_restore.rs:
                 # `test_restore_resumes_inside_a_real_root` — checkpoint/restore
                 # cannot work with any chroot root (emulated or real): the
                 # restore stub is a host build artifact exec'd by its host
                 # path, and a chroot root resolves the workload's paths inside
                 # the rootfs, so the attempt ends in a 10 s READY timeout over
                 # a process that exited 127 ("execvp '…/restore-stub': No such
                 # file or directory"). The call now refuses up front and names
                 # the stub, the root and the way out; the test pins both root
                 # shapes refusing in < 2 s, and shapes the policy the route-B
                 # way (`user(euid)` + `userns_self_map`) so it also runs in the
                 # non-root phase — without that the child cannot
                 # unshare(CLONE_NEWNS) and the real root dies at step one.
                 # `test_restore_glibc_vdso_program_resumes` (chroot-free) stays
                 # the positive control. Evidence: 545 -> 546 passed / 0 failed
                 # in the canonical non-root shape, 2026-09-23.
                 # 2026-09-22: 543 -> 545, and the suite now *finishes* again.
                 # +1 is `test_chroot::a_magic_link_write_returns_instead_of_
                 # pinning_the_capture_pipe`, the bounded copy of the case that
                 # used to hang; the other +1 is the count the tip had already
                 # grown to while the suite could not get past that hang (the
                 # last measured complete run was 2026-09-16's 543). The hang
                 # itself: a write to the sandbox's own stdio through a magic
                 # link (`/tmp/errlog` -> `/dev/stderr` -> `/proc/self/fd/2`)
                 # made the byte watch register the child's stderr *pipe* and
                 # retain its own duplicate of it, so the capture pipe never
                 # reached EOF and `wait()` never returned — the duplicate is
                 # only dropped when the sandbox is dropped, which is after the
                 # wait it was blocking. `inject_watched` now watches only
                 # opens that have a size (`holds_a_file_size`), and the entry
                 # count still credits a created non-regular entry. Evidence:
                 # E2B `tmp/k0s/sigstop-logs/core_integ-green.log` (545 passed
                 # in 85.84s), mutant run red in `mutant-bounded.log`.
                 # pid-ns route-B self-map (2026-09-16): 542 -> 543, +1 in
                 # crates/sandlock-core/tests/integration/test_pid_ns.rs:
                 # `pid_ns_self_map_restores_guest_root` — with pid_ns the
                 # generation's user namespace is created by the *intermediate*
                 # process (before the final fork), and that process only knew
                 # "privileged remap" and "own identity": a route-B guest came
                 # up as its host uid (`id -u` = 65534 in the non-root phase)
                 # instead of the 0 the same policy yields without pid_ns. The
                 # intermediate now honours `userns_self_map` (`0 -> euid`), so
                 # the guest is root inside while its writes stay owned by the
                 # sandbox's host uid. RED on the pre-fix two-arm map (captured
                 # in the E2B parent repo's tmp/pidns-fork-red.log).
                 # FUP-26 (2026-09-15): 540 -> 542, +2 in
                 # crates/sandlock-core/tests/integration/test_instance_chroot.rs:
                 # `test_exec_through_a_dotdot_relative_symlink_resolves` (the
                 # exec path reached through a relative symlink whose target
                 # has `..` — the shape images ship as
                 # `/lib64/ld-linux-x86-64.so.2 -> ../lib/x86_64-linux-gnu/…` —
                 # must be served, not refused) and
                 # `test_exec_failure_names_the_kernel_errno_instead_of_exiting_
                 # 127_silently` (a symlink loop is `ELOOP`=40 at every
                 # attempt for every uid: the child's stderr must carry
                 # `sandlock-init: exec "/usr/bin/loop-a" failed (errno 40)`,
                 # and the genuinely-missing case stays the stock silent 127).
                 # RED on the pre-FUP-26 errno collapse:
                 # tmp/f26-integ-errno-r02-mutant.log (stderr empty).
                 # B3 (2026-09-11, SL-1 hard delete): 539 -> 540, +1 in
                 # crates/sandlock-core/tests/integration/test_mediation_identity.rs
                 # (privileged_in_process_mediation_is_refused_with_route_b_remedy:
                 # the C档 shape is refused before fork with the route-B
                 # remedy and no downgrade offered; phase-aware, the root
                 # branch is the acceptance and the unprivileged branch pins
                 # the userns-map refusal that fires first there). Count
                 # unchanged in test_instance_chroot.rs — the F10 non-root
                 # case lost its tier argument and was renamed
                 # (test_instance_exec_only_chroot_same_uid_launch_and_exec),
                 # keeping its role as the "mediation active + mediator ==
                 # host uid is untouched" reverse regression.
                 # A1+A2+A3 (2026-09-10): 534 -> 539, +5 in
                 # crates/sandlock-core/tests/integration/test_instance_chroot.rs —
                 # A1 (aadb5ad) pinned three cases in that file and A2 turns the
                 # two RED ones green
                 # (test_relative_open_from_second_workspace_alias_resolves_the_
                 # submount, test_getcwd_reports_the_requested_alias_not_the_best_
                 # match; test_getcwd_reports_the_alias_the_policy_declared is the
                 # guard that was already green at aadb5ad),
                 # A2 (c6cbe03) added two more
                 # (test_deny_declared_under_one_alias_covers_the_other_alias,
                 # test_read_only_declared_under_one_alias_covers_the_other_alias).
                 # FUP-13 (2026-09-07, A/B cleanup wave): 533 -> 534, +1
                 # pid-ns init-kill Dead matrix test (test_instance_semantics.rs)
                 # F11 (2026-09-06): 532 -> 533, +1 argv-safety root-cause
                 # regression in integration/test_policy_fn.rs
                 # (test_instance_exec_after_threaded_peer_succeeds): an
                 # exec-only instance whose threaded helper registers its
                 # worker TID (mediated mmap) must still accept a later
                 # exec — the second exec died exit 127 with "argv-safety
                 # freeze failed ... PTRACE_SEIZE ... Operation not
                 # permitted" on the F11 pre-fix tip.
                 # F10: 531 -> 532, +1 in the new integration/
                 # test_instance_chroot.rs
                 # (test_instance_exec_only_chroot_supervisor_same_uid_
                 # launch_and_exec) — mainless exec-only instance over a
                 # chroot + fs_mount workspace with the explicit supervisor
                 # tier (non-root A档 half of the F10 acceptance).
                 # F8 (P6 design tradeoffs): 529 -> 531, +2 tradeoff-pin
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
ffi = 104 # B3 (2026-09-11, SL-1 hard delete): 106 -> 104 — the whole
          # tests/mediation_run_as.rs target is gone with the tier it drove
          # (-2: builder_mediation_run_as_supervisor_lands_on_policy,
          # builder_mediation_run_as_defaults_to_caller_and_invalid_stays_
          # closed), and the FFI export itself is gone (symbol count 164 ->
          # 163 in the wheel verify). tests/failure_reason.rs keeps its two
          # count (only the pinned C档 text changed).
          # B1 (2026-09-11, SL-12): 101 -> 106, +4 in the new
          # tests/failure_reason.rs — the create/launch `*_with_err` symbols
          # publish the core's own failure text through the supervise
          # `err`/`err_msg` contract, and the legacy 4-arg `sandlock_create` /
          # 2-arg `sandlock_instance_launch` keep their ABI/behaviour. The
          # refusal fixture is phase-aware (unprivileged RunAs refusal in this
          # phase; C档 mediation refusal when the target is run as root, which
          # the root-phase reruns in tmp/sdd/b1-ffi-newtests-root.log cover),
          # so no test is skipped in either phase. +1 C smoke
          # (tests/c_smoke.rs create_error_smoke_compiles_and_runs over the new
          # tests/c/create_error_smoke.c): the hand-maintained sandlock.h
          # declarations must link from C and surface the prologue's reason.
          #  F16 (2026-09-08): 100 -> 101, +1 C smoke
          # (tests/c_smoke.rs supervise_client_smoke_compiles_and_runs —
          # the route-B worker client symbols must compile + link + fail a
          # nonexistent slot's request with the err/err_msg contract)
          # F13 (2026-09-06): 98 -> 100, +2 in tests/fs_mount.rs
          # (test_rw_mount_point_resists_link — the I1/P5 hard-link EBUSY
          # guard's direct pin; test_directory_mount_point_rmdir_is_refused —
          # rmdir of a directory bind-mount point is refused with EBUSY and
          # the host directory behind the mount survives). One legacy
          # contains-style assertion converted to exact equality. Core change:
          # chroot dispatch refuses rmdir (unlinkat AT_REMOVEDIR) at directory
          # mount leaves; file/chardev leaves still fall through to ENOTDIR.
          # F6.2 review I1/I2: 96 -> 98, +2 in tests/fs_mount.rs
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
cli = 98      # 2026-09-23: 97 -> 98, +1
              # `net_bind_map_tests::test_real_root_flag_reaches_runtime_policy`.
              # The N35 realroot work added `SandboxBuilder::real_root` without
              # an `arg(...)`/`clap(skip)` attribute, so clap derived a
              # *positional* bool and its debug assertions aborted every
              # `sandlock` invocation -- "Argument 'real_root' is positional and
              # it must take a value but action is SetTrue", measured in this
              # suite (3 tests red, suite aborted). The field is now the
              # `--real-root` flag (like `--pid-ns`) and the CLI forwards it
              # through `apply_flattened_bool_flags`, which the new test pins.
              # B3 (2026-09-11, SL-1 hard delete): 100 -> 97, -3 with the
              # `--mediation-run-as` flag: tests/cli_test.rs (-2:
              # test_mediation_run_as_flag_accepted_and_runs,
              # test_mediation_run_as_rejects_unknown_value_at_parse) and
              # tests/profile_integration.rs (-1: the FUP-07 no-clobber
              # profile-tier case; a profile that still carries the key is
              # now refused by name via ConfigSection's deny_unknown_fields).
              # FUP-01/FUP-07 (2026-09-07, A/B cleanup wave): 98 -> 100,
              # +1 --pid-ns runtime-policy unit test (main.rs) +1 profile
              # mediation_run_as acceptance test (profile_integration.rs)
              # F6.2 (P5): 97 -> 98, +1 in tests/cli_test.rs
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
supervise = 55 # 2026-09-25: 54 -> 55, +1: `checkpoint` with `exclude_main`, the flag
               # a pooled deployment's park-shape session needs -- assert the
               # refusal without it is byte-exact, and that with it the image is
               # the workload's pid while both children keep running
               # (`test_supervise_checkpoint_can_leave_the_parking_main_child_out`).
               # 2026-09-25: 53 -> 54, +1: the `restore` verb, which brings an image
               # back into a *live* generation (the pooled-slot shape of a resume) and
               # leaves its whole verb surface working.
               # 2026-09-25: 51 -> 53, +2 and both are this lane's own work --
               # the checkpoint verb (its test writes an image and asserts the
               # generation keeps running) and the restore-from-image mode
               # (a slot started from an image serves stats/refuses exec).
               # 2026-09-22 catch-up, not this round's work: the first
               # complete gate run since the N25 series reported "baseline says
               # 43 passed, run produced 51". The +8 are the supervise-side
               # cases that series added and never re-ran this gate for
               # (`c152d38` +106 lines in tests/supervise.rs for the entry cap /
               # dated walk / pinned overrun, `9a6f90a` +38, `e4122fa` +22 for
               # the ctl-override fixture). The number below is that run's.
               # F19/SL-13 (2026-09-14): 42 -> 43, +1 integration
               # (test_supervise_refusal_carries_the_generation_closed_code:
               # a generation whose M0 main exits collapses to `Exited` and
               # every later verb answers the unified closed-instance prose
               # **plus** code `generation_closed`; `wait_child` carries it
               # too, an unknown verb answers `verb_refused`, and `ok:true`
               # carries no code at all). The existing S9 case additionally
               # pins `policy_denied` on the ceiling refusal.
               # B3 (2026-09-11, SL-1 hard delete): 43 -> 42, -1 lib unit
               # (policy::tests::mediation_run_as_rejects_unknown_wire_value
               # went with the wire field; the field-list drift guard and the
               # full-field round-trip doc both lost the entry, same count).
               # SL-11 (2026-09-11, B2): 42 -> 43, +1 integration
               # (test_supervise_control_fd_stays_out_of_the_confined_tree:
               # the fd transport's own socket inode — the handed-over
               # `--control-fd` end — must appear in the slot's
               # `/proc/<pid>/fd` with `O_CLOEXEC` in `fdinfo`, and must not
               # appear in the confined init's fd table; a guard, not a bug
               # reproduction, measured clean 2026-09-09).
               # FUP-11 (2026-09-07, A/B cleanup): 36 -> 42, +2 lib units
               # (serve::tests::abnormal_end_log_reports_first_then_throttles,
               # registered_abnormal_end_line_is_pinned — the registered slot's
               # throttled abnormal-end log) +4 integration
               # (test_runtime_mediator_remap_invariant_is_pinned pinning the
               # FORBIDDEN_RUNTIME_MEDIATOR_REMAP constant + the flag surface,
               # and the three FUP-11f validate-and-exit × --program cases).
               # FUP-11a also converted every error-path `contains` in this
               # target to whole-line/exact pins (no count change).
               # F6.1 (SL-1): 35 -> 36, +1 unit test
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
supervise_root = 4 # ROOT-MODE: run via scripts/test-all.sh; +1 FUP-11d
                   # (test_harness_timeouts_and_flood_keep_their_contract:
                   # connect-retry vs per-verb I/O asymmetry + the refused
                   # flood crossing a log throttle window). The registered
                   # acceptance additionally pins the FUP-11c throttled slot
                   # log (300 refused connections -> 2 lines). +1 FUP-03
                   # exit-order harness (worker-close-first leaves no residue,
                   # 2026-09-07)
                   # --supervise-root as root (same privileged container as
                   # oci). F2b.3 foreign-uid acceptance in
                   # tests/supervise_root.rs: supervise as uid 65533 via
                   # setpriv, worker as uid 65534 —
                   # test_supervisor_as_foreign_uid_is_fully_functional
                   # (registered path; box/mediation/DNS/inbound/stats/
                   # shutdown/no-residue) and
                   # test_supervisor_as_foreign_uid_fd_handoff_serves_worker
                   # (fd transport, same genuine identities).
mediation_2uid = 9 # B3 (2026-09-11, SL-1 hard delete): 10 -> 9. Removed with
                   # the tier: test_root_inprocess_mediation_with_caps_kept_
                   # would_leak (the caps-kept control proving the downgrade
                   # was real) and test_cli_mediation_run_as_is_wired (the CLI
                   # flag); the two F10 `RunAs(10000)` create/launch
                   # acceptances became one refusal acceptance
                   # (test_root_chroot_privileged_remap_is_refused_before_fork).
                   # Added: that refusal, plus the two reverse regressions
                   # (test_root_pure_per_uid_run_as_is_still_accepted — a
                   # privileged per-uid remap with NO mediation stays legal;
                   # test_root_chroot_uid0_instance_exec_only_restrictive_cache
                   # — host uid 0 needs no remap). B档 (the two-supervisor
                   # pair + the Python-client slot case) is untouched.
                   # ROOT-MODE: run via scripts/test-all.sh
                   # --mediation-2uid as root (same privileged container as
                   # oci). F6.1 (SL-1) acceptance in
                   # crates/sandlock-supervise/tests/mediation_2uid.rs:
                   # F16 (2026-09-08): 9 -> 10, +1 Python-client B档
                   # (test_python_client_execs_distinct_uids_on_shared_sticky_dir —
                   # two distinct-uid registered slots driven by
                   # sandlock.supervise.SuperviseChannel exec + wait_child +
                   # shutdown; = T5 所缺的 Python 可达证据)
                   # F14 (2026-09-06): 8 -> 9, +1 file-cap launcher acceptance
                   # (test_nonroot_file_cap_launcher_is_refused_like_c_tier) —
                   # a scratch copy of the sandlock CLI stamped with
                   # cap_setuid,cap_setgid+eip and run at euid 65533 via
                   # setpriv is refused under the default caller tier with the
                   # capability-aware C档 message (RED: pre-F14 it fell to the
                   # late "unprivileged supervisor cannot map" refusal).
                   # F10 (2026-09-06): 5 -> 8, +3 restrictive-cache chroot
                   # acceptance tests in the same file
                   # (test_root_chroot_supervisor_runas1000_one_shot_
                   # restrictive_cache, ..._runas1000_instance_exec_only_
                   # restrictive_cache, ..._uid0_instance_exec_only_
                   # restrictive_cache) — root-owned 0700 cache + chroot +
                   # fs_mount workspace + explicit supervisor tier, covering
                   # the E2B create/launch regression. Plus the F6.1 cases:
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
oci = 157     # ROOT-MODE: run via scripts/test-all.sh --oci-root as root.
              # FUP-25 (2026-09-15): count unchanged. The three fd-count
              # assertions (test_eof_closes_received_fd,
              # test_malformed_frames_do_not_leak_fds,
              # exec_frames_deliver_their_own_output_and_leave_no_descriptor_
              # behind) sampled `/proc/<pid>/fd` straight after the probe
              # child published `r` — i.e. before `run_init` armed its
              # process-level SIGCHLD signalfd — so under load the baseline
              # could be short by exactly one fd and read as a leak
              # (`baseline 5 -> after return 6`; a real SCM_RIGHTS leak would
              # be +2). The sampling premise is now true instead of the
              # assertion being relaxed: a zero-fd request/response round trip
              # (a frame whose payload cannot parse, answered with an `Err`
              # reply) proves the serving loop — and therefore its fd table —
              # exists before the baseline is read. Evidence: the mechanism
              # harness tmp/f26-f25-race-mechanism-r02.log (pre-fix order:
              # baseline 5 and mismatch 50/50 with the race window widened;
              # fixed order: baseline 6, mismatch 0/50) and the loaded suite
              # tmp/f26-f25-loadprec-fixed-r05/r06.log (10/10 green at 8 and
              # at 16 CPU hogs).
              # FUP-24 (2026-09-15): 150 -> 157, +7 net. `kill --all`'s
              # daemon-gone fallback is now gated on `SendCommandError::
              # was_delivered()` (only a request the daemon cannot have
              # received — connect refused/absent, or a write that never got
              # the frame's delimiter out — takes the direct killpg path; a
              # lost *reply* is reported instead of re-delivering the signal).
              # +2 unit tests in `supervisor.rs::tests`
              # (a_lost_reply_after_a_complete_frame_is_a_delivered_request,
              # an_unreachable_socket_is_a_lost_request — the bin target
              # recompiles the crate module tests, so they count twice: +4) and
              # +3 tests in the new `tests/test_kill_all_delivery.rs` target
              # (lost_reply_after_a_delivered_frame_is_not_redelivered,
              # unreachable_socket_still_falls_back_to_a_direct_group_delivery,
              # normal_round_trip_delivers_exactly_once). Evidence:
              # tmp/fup24-oci-count-r01.log (157 passed / 0 failed) and the
              # --oci-root gate log tmp/fup24-gate-oci-final-r01.log.
              # f1oci (2026-09-14): count unchanged. The control channel now
              # f1oci (2026-09-14): count unchanged. The control channel now
              # frames a request at its `\n` (supervisor) and the CLI sends
              # payload+delimiter in one write, so the
              # test_signal_to_sibling_pid_rejected flake (instance signal
              # delivered twice via the CLI's daemon-gone killpg fallback after
              # the supervisor answered a request fragment) is deterministic:
              # 10/10 sequential `--oci-root` rounds 150 passed / 0 failed
              # (tmp/f1oci-oci10-r01..r10.log). The in-file raw-frame helper now
              # pins the framing boundary (no reply before the delimiter) and
              # both protected semantics were mutation-proved red
              # (tmp/f1oci-mutation-M{1,2}-*-red.log).
              # F15 (2026-09-08): 145 -> 150, +2 header-validation tests in
              # oci/src/init.rs (TooManyFds declaration + pre-F15 10-byte v1
              # header reports the version gap; the seam module recompiles in
              # both the lib and bin targets) and +1 integration test
              # (two RunExec frames in one read unit each get their own stdio).
              # FUP-23 (2026-09-08): 144 -> 145, +1 exec-stdio leak/delivery
              # regression driven through the real run_init control loop
              # (40 real execs: each round's stdout/stderr exact, init's fd table
              # back at baseline every round and after EOF)
              # previous: 144     # ROOT-MODE: run via scripts/test-all.sh --oci-root as root. oci e2e
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
python = 465  # F19/SL-13 (2026-09-14): 464 -> 465, +1 in
              # tests/test_supervise_channel.py
              # (test_a_served_refusal_is_typed_and_carries_its_stable_code:
              # a real slot's served `ok:false` surfaces as SlotRefusal with
              # `code` = policy_denied / verb_refused, and an uncoded answer
              # stays None rather than being guessed from the prose).
              # B3 (2026-09-11, SL-1 hard delete): 467 -> 464, -3 in
              # tests/test_sandbox_config.py (the whole TestMediationRunAs
              # class: default / native round-trip / invalid-value cases).
              # tests/test_failure_reason.py keeps its count (only the pinned
              # C档 text changed).
              # B1 fix round 1 (2026-09-11, SL-12 review): 463 -> 467, +4 in
              # tests/test_failure_reason.py — the missing reason export is a
              # named RuntimeError (guard helper + a subprocess probe that
              # loads the package against a stubbed pre-SL-12 .so), a verb on a
              # shut-down session raises the typed InstanceClosedError, and the
              # FFI instance error codes map to the typed session-gone errors
              # (closed=1 / dead=6) while keeping the reason text verbatim.
              #  B1 (2026-09-11, SL-12): 461 -> 463, +2 in the new
              # tests/test_failure_reason.py — `Sandbox.create` and
              # `SandboxInstance` must raise RuntimeError whose *whole* text is
              # `sandlock_create failed: <core Display>` /
              # `sandlock_instance_launch failed: <core Display>`. The refused
              # shape is phase-aware (unprivileged RunAs refusal in this phase;
              # the C档 `mediation_run_as=caller` refusal naming the route-B
              # remedy when pytest runs as root), so neither phase skips.
              #  F17 (2026-09-09): 455 -> 461, +6
              # tests/test_supervise_channel.py -- the route-B transport-1
              # (fd handoff) face: persistent session with no path and no token
              # (argv keeps the secret out, SL-10), token belt still refuses a
              # mismatch, `set_timeout` lets a `wait_child` park past the 2 s
              # default, a failed verb retires the shared stream instead of
              # mis-aligning it, and `check_control_fd` names a bad descriptor
              # (also the SL-9 regression: a transport failure raises
              # SandlockError with the server's text, never AttributeError).
              # +1: the handed-over control fd stays out of the confined init's fd
              # table (SL-4-class guard; measured clean before the FD_CLOEXEC restore,
              # pinned so neither side can regress silently).
              # F16 (2026-09-08): 454 -> 455, +1
              # tests/test_supervise_channel.py (same-uid registered slot:
              # SuperviseChannel exec-with-SCM_RIGHTS + wait_child + stats +
              # shutdown; python face of the route-B client)
              # F6.2 (P5): 453 -> 454, +1 in tests/test_fs_mount.py
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

# ---------------------------------------------------------------------------
# arm64 lane (2026-09-24): the S5 lane is a local Lima qemu VM (Ubuntu 24.04,
# kernel 6.14.0-37-generic, 6 vCPU, host = amd64 Darwin). No test binary leaves
# this machine; the aarch64 binaries are cross-built here with the wheel
# builder's zig toolchain (`CC_aarch64_unknown_linux_gnu=zigcc`) and copied
# into the guest over ssh (`deploy/scripts/arm-lane/lima-vm.sh`, and see
# `docs/arm-cr-s0-evidence.md` §7 for the four constraints + the 9p staleness
# trap that makes rsync-through-9p silently run the previous build).
#
# Shape: uid 501 (non-root), cwd = the mirrored source on the guest's own
# filesystem, `--test-threads=1` for core_integ and 4 for core_lib.
arm64_core_lib = 904   # 2026-09-24, first full run: 899/4 -> 904/0. The four
                       # first-round reds were all per-ABI tables; one was a
                       # real bug (`network/readiness.rs` had `struct
                       # epoll_event` hardcoded at 12 bytes with `data` at
                       # offset 4 -- x86_64's packed ABI -- while every other
                       # LP64 ABI is 16/8, so on aarch64 the supervisor read the
                       # wrong half of every intercepted epoll record), the rest
                       # were the `path_surface` ledger comparing x86_64 *names*
                       # on an ABI that has no `open`/`stat`/... at all.
arm64_core_integ = 551 # 2026-09-24: 551 passed / 0 failed, i.e. the *same*
                       # entire suite as x86_64 at this tip (551/0, 85.4s), on a
                       # real 6.14 kernel under qemu TCG (718s). The first round
                       # of this lane was 506/42 and **not one of the 42 was an
                       # aarch64 defect**: they were five lane artifacts, one
                       # test coupled to a libc's wording, and one flake. What
                       # each actually was, because two of them cost the most:
                       #
                       # * 17 -- the ACL/egress fixtures exec a python that
                       #   honours `http_proxy`, and Lima forwards the host's:
                       #   the sandboxed workload dialled the *host* proxy
                       #   instead of the address under test and the sandbox
                       #   denied it. `test_http_acl::test_http_allow_get` came
                       #   back "urlopen error [Errno 111] Connection refused"
                       #   and strace showed the run's one and only connect()
                       #   going to the proxy. The lane now unsets the proxy
                       #   vars for every `run`.
                       # * 17 -- `test_control::*` spawns the `sandlock` CLI via
                       #   the CARGO_BIN_EXE path cargo baked in, and the lane
                       #   had never cross-built or copied that binary ("spawn
                       #   sandlock: NotFound"). It is part of `sync` now.
                       # * 5 -- the named-unix-socket gate family (connect,
                       #   sendto, sendmsg, sendmmsg, symlink escape) answered
                       #   "CONNECTED"/"SENT" where the contract is EACCES. Not
                       #   an aarch64 bug: those tests keep their socket in
                       #   CARGO_TARGET_TMPDIR, and the lane's target root was
                       #   `/tmp/target-aarch64` -- *inside* the `fs_write
                       #   ("/tmp")` grant every one of those policies makes, so
                       #   the gate found the path writable by design and let it
                       #   through. The cross-build target root is now
                       #   `/var/tmp/aarch64-target`, which is 1777 like /tmp
                       #   but outside every grant.
                       # * 1 -- `test_chroot_hardlink_into_a_branch_is_refused`
                       #   asserted glibc's `strerror(EXDEV)`. The lane builds
                       #   `tests/rootfs-helper` statically with zigcc, which is
                       #   musl-only, and musl says "Cross-device link". The
                       #   assertion now matches the phrase, not the libc.
                       # * 1 -- `test_policy_fn::test_instance_exec_after_
                       #   threaded_peer_succeeds` execs `/usr/local/bin/
                       #   python3` (the lane image's layout); Ubuntu's is
                       #   /usr/bin/python3, so the helper exited 127 and the
                       #   test died on "threaded helper never reported ready".
                       #   The prep now plants that symlink.
                       # * 1 -- `test_transaction::test_txn_timeout_bounds_the_
                       #   stage_phase_not_the_commit` was a one-off under load;
                       #   it has not reproduced.
                       #
                       # The fixture fix the lane did land (a blank `/etc/hosts`
                       # line ending the pre-seeded scan) is in the fork, with
                       # the three unit cases that count in `core_integ` above.
                       # Two lane-side findings are worth keeping in mind for
                       # any arm64 rerun: `sync` must unlink an artifact before
                       # scp (the guest's sshd refuses to open over an existing
                       # one: "dest open ... Failure"), and the wildcard family
                       # still needs the entrypoint's `ip_unprivileged_port_
                       # start=0` on the *shared*-netns path -- measured, the
                       # same `test_egress` case passes in 1.9s with it and
                       # wedges past 130s without it. The deployed E2B shape sets
                       # E2B_ENABLE_NET_ISOLATION=true, where the gateway binds
                       # inside the sandbox netns and the sysctl is not in play.

# The rest of the arm64 table: the same five labels the x86_64 gate reports,
# each measured in the same shape `scripts/test-all.sh` uses (the phase runner
# sums the per-binary "test result: ok. N passed" lines exactly like the
# script does). Every one equals the x86_64 baseline at this tip.
arm64_ffi = 104          # uid 501. Same as x86_64. Three of the ten binaries
                         # only run at all once the lane transports the
                         # cross-built `libsandlock_ffi.so` (the C smoke tests
                         # link it; the ctypes binding loads it) and once
                         # `c_smoke`'s `cargo build -p sandlock-ffi --lib` can
                         # be pointed at a shim that refuses to pass unless that
                         # artifact is newer than every source it came from --
                         # the guest has no toolchain, and the path baked in at
                         # build time (`/root/.rustup/.../x86_64.../cargo`) is
                         # not even reachable as an unprivileged uid (EACCES
                         # through a 0700 /root, not ENOENT).
arm64_supervise = 51     # uid 501. Same as x86_64. Two cases needed fixing
                         # for the lane rather than for the product: both
                         # assumed the workload progresses inside a fixed
                         # wall-clock window, and on qemu TCG it does not --
                         # the events case read as "the channel never greeted"
                         # and the tightening case broke out of its stop loop
                         # on the first equal sample (2097152 -> 2097152), which
                         # on this lane means "has not written its next 1 MiB
                         # yet", not "cannot write any more". Both now wait for
                         # the bytes/state that made the assertion true, with a
                         # quiet deadline as the backstop.
arm64_oci = 157          # root phase (`--oci-root`). Same as x86_64. Carries
                         # the C/R round-trip through the OCI supervisor.
arm64_supervise_root = 4 # root phase (`--supervise-root`). Same as x86_64.
                         # Two lane-shaped reds stood in the way, neither an
                         # isolation defect: the shared ctl root was created by
                         # the root test process and then chmod-ed by the
                         # sandbox uid (which has no CAP_FOWNER) -- the root is
                         # now chown-ed to the uid that uses it, as the real
                         # per-user root is; and the policy denied `chmod`,
                         # which does not exist in the generic syscall table
                         # (aarch64 lowers chmod(2) to fchmodat), so the fork
                         # refused the rule by name.
arm64_mediation_2uid = 9 # root phase (`--mediation-2uid`). Same as x86_64.
                         # The CLI and the cdylib are found through
                         # <manifest>/../../target, which on this lane is the
                         # cross-build output rather than the container's
                         # target root.
