# Sandlock fork 独立完成计划（2026-09-04）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development 或 superpowers:executing-plans 逐任务执行。步骤用 `- [ ]` 跟踪。
> 本文只管 **fork（本仓库）** 一侧：所有改动在本仓库内完成，所有验证用本仓库自己的测试套件跑通，**不依赖 `sandlock-e2b` 仓库的任何动作**（不需要它的 xfail 标记、它的 test-runner 镜像、它的 compose 部署）。E2B 侧接线见该仓库 backlog `E10/M4`，不在本计划范围。
> 编号沿用 `docs/e2b-integration.md` §7 同步约定：`SL-*` = fork 缺陷，`P*` = E2B 提出的待做方案，`M*` = 每沙箱一实例的里程碑。

**Goal:** 在 fork 内一次性交付全部未完成目标 —— 安全前置 `SL-4/5/6/7/8` + 进程组/帧上限/deadline（M0′）、每沙箱一实例 `M0–M3`、路径中介身份 `P1/P2`、`fs_mount` 细粒度 `P5`、`net_isolation`+chroot 入站映射 `P4`、`P6` 已知限制补齐、**候选路线 B：supervisor 进程化（`sandlock-supervise`，待 E2B/用户确认）** —— per-uid 隔离与 SL-1 由构造解决；`P3` 一行修复在 F0.3 —— 每一项都带本仓库内的红→绿测试，且 fork 三套基线（lib 788 / integration 465 / python 430）零回退。

**Architecture:** 四条独立可交付的主线，按"能不能立刻在 fork 内验证"排序：(1) **F0 独立性基座** —— 把"完整套件一键跑 + wheel 构建 + 与 tip 一致性自证"收进本仓库，后续每条主线的验收都复用它；(2) **F1 安全门槛 M0′** —— 全部是既有代码的正确性/鉴权缺陷，可在当前 `sandlock-oci` 路径上先跑红，不依赖实例化改造；(3) **F2–F5 实例化 M0→M3** —— 三层边界（Policy / Instance / Child）落地，`exec` 从 `sandlock-oci` **下沉复用**到 core，不新写；(4) **F2b supervisor 进程化（候选路线 B，待 E2B/用户确认）**（2026-09-04 评估拟走 B 档：特权只在 create，服务中介的进程 euid == 沙箱 host uid）—— 它把 SL-1 从“修中介身份”变成“不需要修”，并把 SL-7 的控制通道从文件系统改成 create 时交接的 fd；(5) **F6–F7 文件身份断言与形态补齐**（SL-1 fail-closed / P5 / P4）—— 与主线 2/3 正交，可并行。

**Tech Stack:** Rust 2021（`sandlock-core` / `sandlock-ffi` / `sandlock-cli` / `sandlock-oci`）、Landlock + seccomp `USER_NOTIF`、`pidfd` / `SCM_RIGHTS` / `SO_PEERCRED`、tokio、cbindgen（C 头文件）、PyO3 + ctypes Python 绑定（`python/src/sandlock`）、Go SDK（`go/`，经 pkg-config 链接 `libsandlock_ffi.so`）、zig 交叉编译 manylinux_2_34 wheel、GitHub Actions（`ci.yml`）。

## Global Constraints

- 运行时基线分支 `upstream-pr/netns-free-clean`：**全程无 root 可用**；非 root（uid 65534 / `nobody`）必须能跑完整套验证（`b6ef050` 已固化，`tests/integration/net_fixture.rs` 提供无特权网络前置）。
- 允许 root 增益路径（`RunAs` 任意 host uid 需 root/CAP_SETUID）必须 **fail closed**，不得把 root-only 能力变成默认路径的前提（`sandbox.rs:2087-2104` 现有拒绝即范式）。
- 基线数字（Linux 容器 / 非 root）：lib `788`、integration `465`、python `430`；`cargo test --release --workspace` 另含 ffi/cli/oci 套件。**任何一条既有测试都不许改断言迁就新行为**，除非该行为正是本任务的目标，且改动在提交信息里点名。
- 测试规范：断言精确（退出码、属主 uid、错误码、计数逐一对齐，禁"包含即可"）；**禁 skip 掩盖能力缺失**（环境不满足就 fail 并打印取证输出）；日志驱动排查，不靠猜。
- Landlock 与 seccomp 只能加严：per-exec 只能**收窄**策略，放宽必须在实例创建时定死上限、越界**显式拒绝**（`sandbox-exec-security.md` §4.3 / S9）。
- 新增 FFI 符号必须同批更新：`crates/sandlock-ffi/src/lib.rs` → `cbindgen` 重生成 `crates/sandlock-ffi/include/sandlock.h`（CI 的 `cbindgen-header` job 会比对）→ Python ctypes 绑定 → C 冒烟用例（`crates/sandlock-ffi/tests/c/`）。
- 旧公共 API（`Sandbox.run/popen/spawn`、既有 FFI 符号）语义与 ABI **不破**：一次性实例语义保持现状。
- 每个任务收口：(a) 目标用例先红后绿；(b) F0 脚本全量跑通且基线不回退；(c) 一个提交；(d) `docs/e2b-integration.md` 对应条目状态改「已修（commit）」。
- 上游 PR 推送（P8）受 token 只读阻塞，**不属于本计划的完成条件**；交付口径是"本地提交 + wheel 可重建 + 全量自证"。

---

## 1. 验证入口与套件清单（F0 之后全部在 fork 内）

| 套件 | 命令 | 基线 | 承载本计划哪些验收 |
|---|---|---|---|
| core lib | `cargo test -p sandlock-core --offline --lib` | 788 | `ResourceState`/pidfd 记账、帧协议、DAC 判定纯函数 |
| core integration | `cargo test -p sandlock-core --offline --test integration -- --test-threads=1` | 465 | SL-4/6/7/8、SECE-6、M0–M3、SL-1、P4、P5 |
| ffi | `cargo test -p sandlock-ffi --offline` | 基线待登记 | 新 FFI 符号（`instance_exec` 等）、C 冒烟、`fs_mount` |
| cli | `cargo test -p sandlock-cli --offline` | 基线待登记 | 新开关的 CLI→builder 接线（`--pid-ns` 漏接线的教训不得重演） |
| oci | `cargo test -p sandlock-oci --offline -- --test-threads=1`（9 例） | 基线待登记 | SL-4/5/6/8 与 `early_exits`/deadline 的**现状可跑红**探针 |
| python | `cd python && pip install -e . && pytest tests/ -v` | 430 | P3、`SandboxInstance.exec`、控制面鉴权、中介身份 |
| go | `make install-go-lib && cd go && go test ./...` | CI 现有 | 新符号不破坏 pkg-config 链接 |

> 登记基线：F0.1 用一次全量运行把 ffi/cli/oci/go 的实测数写进 `docs/test-baseline.md`，之后脚本按精确数字比对（缺一个用例就红）。

## 2. 覆盖矩阵（目标 → 任务 → 新增测试）

| 目标 | 任务 | 新增测试（文件 :: 用例） | 套件 |
|---|---|---|---|
| SL-4 控制 fd 泄漏 | F1.1 | `integration/test_fd_inherit.rs :: test_control_socket_not_inherited_by_user_process`、`test_extra_fds_are_cloexec`、`test_stdio_still_inheritable`；`oci/tests/integration.rs :: test_forged_exit_frame_cannot_fake_success` | integration + oci |
| §10 H1/H2 `early_exits` | F1.2 | `oci/tests/integration.rs :: test_unknown_pid_exit_frame_bounded`、`lib: supervisor::tests :: early_exits_cap_drops_overflow` | oci + lib |
| SL-7 控制面鉴权 + 身份 | F1.3 + **F2b.2** | `integration/test_control.rs :: test_peer_uid_mismatch_closes`、`test_sibling_sandbox_cannot_read_other_policy`、`test_name_conflict_refuses_preempt`、`test_verb_without_token_rejected` | integration + python |
| SL-8 `proc_count` 泄漏 | F1.4 | `integration/test_resource.rs :: test_setsid_orphan_returns_proc_count`、`test_proc_count_matches_live_after_orphan_storm`；`lib: resource::tests :: pidfd_release_is_idempotent` | integration + lib |
| SL-6 init 非 reaper | F1.5 | `integration/test_init_reaper.rs :: test_adopted_orphan_is_reaped`、`test_no_defunct_after_double_fork` | integration |
| SL-5 fd 不关 / 分帧 | F1.6 | `oci/tests/integration.rs :: test_malformed_frames_do_not_leak_fds`、`test_eof_closes_received_fd`；`lib: init::proto::tests :: frame_decoder_rejects_oversize_and_truncated` | oci + lib |
| SECE-6 一条命令杀整箱 | F1.7 | `integration/test_process_groups.rs :: test_child_killpg_does_not_hit_sibling`、`test_instance_kill_covers_all_child_groups`、`test_signal_to_sibling_pid_rejected` | integration |
| `InitLink` 无 deadline | F1.8 | `oci/tests/integration.rs :: test_request_timeout_returns_error_within_deadline` | oci |
| B 档 supervisor 进程化 | F2b.1–F2b.5 | `integration/test_supervise.rs :: test_supervise_refuses_wrong_uid`、`test_policy_roundtrip_covers_every_field`、`test_supervisor_as_foreign_uid_is_fully_functional`；`integration/test_supervise_cost.rs :: test_per_sandbox_supervisor_rss_within_budget`、`test_exit_frames_never_lost_over_1000_rounds` | integration |
| 轮转槽位池回收不变式 | F2b.3（D2 已定） | `integration/test_slot_reuse.rs :: test_slot_restart_requires_no_residual_inodes`、`test_same_uid_reuse_cannot_see_previous_generation`（含反向鉴别力断言）、`test_uid_pool_rejects_reserved_ids` | integration |
| 控制通道改 fd 交接 | F2b.2 | `integration/test_control.rs :: test_socketpair_channel_rejects_third_party`、`test_sandbox_cannot_reach_sibling_channel` | integration |
| M0 生命周期上提 | F2 | `integration/test_instance_lifecycle.rs :: test_instance_outlives_first_process`、`test_shutdown_is_idempotent`、`test_shutdown_releases_control_dir_and_dns_gateway`、`test_legacy_run_still_reclaims_all_resources` | integration + python |
| M1 `exec` 下沉 + child 句柄 | F3 | `integration/test_instance_exec.rs :: test_two_concurrent_exec_keep_independent_stdio`、`test_double_wait_child_is_idempotent`、`test_close_stdin_does_not_deadlock`、`test_exec_after_shutdown_returns_same_error`；`python/tests/test_instance_exec.py :: test_exec_returns_self_owned_process`；`ffi/tests/instance_exec.rs` | 四套 |
| M2 per-exec 参数 + 子集校验 | F4 | `integration/test_instance_exec_params.rs :: test_per_exec_cwd_and_env_apply`、`test_wider_policy_is_rejected`、`test_update_network_applies_to_new_exec_only_and_reports_staleness`、`test_per_exec_bind_port_reaches_listener` | integration + python |
| M3 语义/默认/兜底 | F5 | `integration/test_instance_semantics.rs :: test_max_processes_default_bounds_whole_box`、`test_checkpoint_with_multiple_children_is_refused`、`test_dead_state_surfaces_single_error_code`、`test_idle_timeout_drains_and_shuts_down`、`test_pid_ns_procfs_scope_narrows_to_child`；`integration/test_pid_ns.rs :: test_init_reaps_ns_pid_1_exit` | integration + lib |
| SL-1 中介身份（P1/P2） | F6.1 | A 档 `test_nonroot_created_file_owned_by_self`、`test_denied_path_still_denied`；**B 档 `test_two_supervisors_distinct_uids_isolate_files`（跨 uid 硬证据）**；C 档 `test_root_inprocess_mediation_is_refused` + `..._with_caps_kept_would_leak`（降级档自证） | integration（A/B 两档都要跑） |
| `fs_mount` 细粒度（P5） | F6.2 | `ffi/tests/fs_mount.rs :: test_mount_single_file_node`、`test_mount_chardev_node`；`python/tests/test_fs_mount.py :: test_minimal_dev_helper`（该文件已存在） | ffi + python |
| `net_isolation`+chroot 入站（P4/T4） | F7 | `integration/test_net_isolate.rs :: test_mcp_inbound_mapping_under_chroot_and_net_isolation`（当前该形态即失败 ⇒ 新增即红） | integration |
| `notify_rate_limit` 假告警（P3/T2） | F0.3 | `python/tests/test_sandbox.py :: TestUnwiredFieldWarning::test_notify_rate_limit_is_declared_handled` | python |
| `getsockname`/`EINPROGRESS`（P6） | F8 | `integration/test_network.rs :: test_injected_connect_reports_synthetic_addresses`、`test_nonblocking_connect_reports_einprogress` | integration |

粒度说明：F0 与 F6.1 给到步骤级（含可直接落盘的代码），其余阶段给到"落点 file:line + 新增用例名 + 验收断言"的组粒度。每条主线开工前按 `writing-plans` 拆一次步骤级 plan，写进 `docs/fork-plan-2026-09-<phase>.md`，避免一次背六个阶段的细节。

未被本计划覆盖（明确排除）：`P7` cp310–313 wheel 矩阵（E2B 运行时已统一 3.14）、`P8` 上游推送（token 权限）、以及一切 E2B 仓库内的接线与部署验证。

---

## 阶段 F0：独立性基座（先做，后面每个任务的验收都依赖它）

### Task F0.1：fork 内一键全量验证 + 基线精确比对

**Files:**
- Create: `scripts/test-all.sh`
- Create: `docs/test-baseline.md`
- Modify: `Makefile`（新增 `.PHONY: check`，转调 `scripts/test-all.sh`；现有目标只有 `ffi`/`install-go-lib`/`uninstall-go-lib`）

- [ ] **Step 1** 写脚本：六个套件顺序跑，逐套件解析 `test result: ok. <N> passed` 与 pytest 末行，和 `docs/test-baseline.md` 的期望值**精确相等**；不等即退出码非 0，并把原始末行打印出来。

```sh
#!/bin/sh
# Run every sandlock suite in one shot and fail on ANY drift from the recorded
# baseline -- including a suite that quietly runs fewer tests than last time.
# Usage: scripts/test-all.sh          (normal uid, Linux; logs land in ./tmp/)
#        scripts/test-all.sh --wheels (also cross-build + verify wheel symbols)
set -eu
cd "$(dirname "$0")/.."
mkdir -p tmp
BASELINE="docs/test-baseline.md"

expect() {  # exact expected pass count for a suite label
    sed -n "s|^$1[[:space:]]*=[[:space:]]*\([0-9]\+\).*|\1|p" "$BASELINE" | head -1
}
rust_count() {  # sum "test result: ok. N passed" across all targets of a suite
    sed -n "s/.*test result: ok\. \([0-9]\+\) passed.*/\1/p" "$1" | awk '{s+=$1} END {print s+0}'
}
py_count() {
    sed -n "s/.*= *\([0-9]\+\) passed.*/\1/p" "$1" | tail -1
}

run() {  # run <label> <command...>
    label="$1"; shift
    log="tmp/test-all-$label.log"
    printf '==> %s\n' "$label"
    if ! "$@" >"$log" 2>&1; then
        printf '%s: suite FAILED (see %s)\n' "$label" "$log"; tail -40 "$log"; exit 1
    fi
    want="$(expect "$label")"
    if [ -z "$want" ]; then
        printf 'no baseline entry for %s in %s\n' "$label" "$BASELINE"; exit 1
    fi
    case "$label" in
        python) got="$(py_count "$log")" ;;
        *)      got="$(rust_count "$log")" ;;
    esac
    if [ "$want" != "$got" ]; then
        printf '%s: baseline says %s passed, run produced %s\n' "$label" "$want" "$got"
        tail -40 "$log"; exit 1
    fi
    if grep -Eq '[0-9]+ (skipped|ignored)|test result: ok\. [0-9]+ passed; [1-9]' "$log"; then
        printf '%s: skipped/ignored tests are not allowed -- fix the environment or the test\n' "$label"
        grep -En '[0-9]+ (skipped|ignored)|^test .* ... SKIPPED' "$log" | head -20
        exit 1
    fi
    printf '    %s passed -- matches baseline\n' "$got"
}

run core_lib   cargo test -p sandlock-core --offline --lib
run core_integ cargo test -p sandlock-core --offline --test integration -- --test-threads=1
run ffi        cargo test -p sandlock-ffi --offline
run cli        cargo test -p sandlock-cli --offline
run oci        cargo test -p sandlock-oci --offline -- --test-threads=1
( cd python && pip install -e . >/dev/null )
run python     pytest python/tests -q

if [ "${1:-}" = "--wheels" ]; then
    ./python/build-wheels.sh && ./python/verify-wheel.sh
fi
```

`docs/test-baseline.md` 的形状（数字取 F0.1 Step 2 的实测值，注释里写内核/Landlock ABI/Python 版本）：

```md
core_lib = 788
core_integ = 465
ffi = <登记>
cli = <登记>
oci = <登记>
python = 430
```

- [ ] **Step 2** 容器内非 root 实跑一次（`docker run --rm -v "$PWD":/w -w /w rust:1-slim-bookworm sh -c 'apt-get update -qq && apt-get install -y -qq python3-pip && setpriv --reuid=65534 --regid=65534 --clear-groups sh scripts/test-all.sh'` 之类，具体以能跑通为准），把六套实测数字写进 `docs/test-baseline.md`，并注明内核版本与 Landlock ABI。
- [ ] **Step 3** 脚本自检：临时从 baseline 改坏一个数字，跑脚本必须**非 0 退出且打印 diff 行**；改回来必须全绿。这条是"基线漂移即红"的能力证明，不做完不许进 F1。
- [ ] **Step 4** 提交 `test: add a one-shot full-suite runner with exact baseline assertions`。

### Task F0.2：wheel 构建自证（消掉 §3.4「产物无法自证与 tip 一致」）

**Files:** Create `python/build-wheels.sh`、`python/verify-wheel.sh`；Modify `docs/e2b-integration.md` §3.4

- [ ] **Step 1** 把 `sandlock-e2b/deploy/scripts/build-sandlock-wheels.sh`（42 行，zig + manylinux_2_34 + auditwheel，双架构单 builder）移植进本仓库为 `python/build-wheels.sh`，构建源改为**本仓库工作树**。
- [ ] **Step 2** `python/verify-wheel.sh`：解包 wheel → 读 `libsandlock_ffi.so` 的导出符号 → 与 `nm -D --defined-only target/release/libsandlock_ffi.so` 对比，并打印 `git rev-parse HEAD` 与 wheel 内 `sandlock/_version.py`。规则：**符号集必须等于当前 tip 的符号集**，缺一个即失败（新增 FFI 符号后 wheel 未重建 ⇒ 立刻红）。
- [ ] **Step 3** 在 F0.1 脚本末尾追加可选 `--wheels`（默认关，避免每次全量都交叉编译）。
- [ ] **Step 4** 提交 `build: own the wheel build and make wheel/tip consistency self-proving`。

### Task F0.3（P3 / E2B 侧称 T2）：登记 `notify_rate_limit`

**Files:** Modify `python/src/sandlock/_sdk.py:1138`；Test `python/tests/test_sandbox.py`（`class TestUnwiredFieldWarning`，约 :863）

- [ ] **Step 1 写失败测试**

```python
    def test_notify_rate_limit_is_declared_handled(self):
        """`notify_rate_limit` 经 FFI 生效，不得被当成未接线字段。"""
        import warnings
        assert "notify_rate_limit" in _NativePolicy._HANDLED_FIELDS
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _policy(notify_rate_limit=1000).run(["echo", "ok"])
        assert [str(x.message) for x in w if "notify_rate_limit" in str(x.message)] == []
```

- [ ] **Step 2** `pytest tests/test_sandbox.py::TestUnwiredFieldWarning -q` → 第一条断言 FAILED。
- [ ] **Step 3** 在 `_HANDLED_FIELDS` 的 `"uid", "gid",` 之后加 `"notify_rate_limit",`（`_sdk.py:1217-1218` 已在调 `sandlock_sandbox_builder_notify_rate_limit`）。
- [ ] **Step 4** 该类 PASS + python 全量 430（新增 1 例 ⇒ 431，同步 baseline）。
- [ ] **Step 5** 提交 `fix(python): register notify_rate_limit in _HANDLED_FIELDS (P3)`，`e2b-integration.md` §2/§3.2 标已修。

---

### Task F0.4（实测暴露）：修 `cli` feature 的构建，并把 workspace 全量纳入 runner

**Files:** Modify `crates/sandlock-core/src/sandbox/builder.rs:66`（`net_bind_map`）；Test `crates/sandlock-cli/tests/cli_test.rs`

- [ ] Step 1：`cargo build --release -p sandlock-cli` 复现失败（clap `_infer_ValueParser_for<(u16,u16)>` 无 value parser）——失败即基线。
- [ ] Step 2：给字段加**真 CLI 接线** `#[cfg_attr(feature = "cli", arg(long = "net-bind-map", value_name = "HOST:SANDBOX", value_parser = parse_port_pair))]` + 一个 `fn parse_port_pair(s: &str) -> Result<(u16,u16), String>`；**禁止用 `arg(skip)` 蒙过去**（那正是 `--pid-ns` 漏接线的同一类缺陷，且会让用户以为 CLI 支持该策略）。
- [ ] Step 3：CLI 用例 `test_net_bind_map_flag_reaches_builder`（断言 `--net-bind-map 50005:8080` 后 builder 字段确为 `(50005, 8080)`）+ `test_net_bind_map_rejects_privileged_port`（< 50005 必须报错）。
- [ ] Step 4：`scripts/test-all.sh` 增加 `run cli_build cargo build --release --workspace --locked`，并把 `cli`/`oci`/`ffi`/`go` 全纳入基线 —— 这次的教训是"只测 `-p sandlock-core` 的默认 feature"会漏掉整个 CLI 面。
- [ ] Step 5：提交 `fix(cli): wire net_bind_map through the clap builder (build break since S2.5)`。

---|---|---|---|
| **F1.1 SL-4** | `crates/sandlock-core/src/sandbox.rs:2317-2320`：`for &(target, source) in &extra_fds { dup2 }` ⇒ POSIX 语义清掉结果 fd 的 `FD_CLOEXEC` | `target >= 3` 的 `extra_fds` 用 `dup3(source, target, DUP_CLOEXEC)`；0/1/2 保持可继承（用户进程本来要拿到 stdio）；`sandlock-init` 在 fork/exec 用户进程前对控制 fd 再显式 `fcntl(F_SETFD, FD_CLOEXEC)` 兜第二道 | 沙箱内 `readlink /proc/self/fd/3` 必须失败；`fdinfo` 里控制 socket 不再出现 `flags: 02` |
| **F1.2 H1/H2** | `crates/sandlock-oci/src/supervisor.rs:44/99/142` `early_exits: HashMap` 无上限、不校验登记性 | 只接受**已登记 child pid** 的帧；未知 pid 计数并丢弃；`early_exits` 上限（默认 1024，可配）超限即丢 + 计数指标；宿主 `exec` 的返回值只能由真实等待路径决定 | 60k 伪造帧后 supervisor RSS 增长 < 1 MB；假 `Exited{pid=自造}` 不改变任何 `exec` 的退出码 |
| **F1.3 SL-7** | `crates/sandlock-core/src/control.rs:236-262`（`cred.uid != my_uid` 只 `eprintln`）、`:136-147`（`kill(pid,0)` 判活即 `remove_dir_all` 抢占） | 不匹配即**断开连接**（返回 `EACCES`/直接 close）；控制目录名改为**哈希**且**不落 `/dev/shm`**（抄 `sandlock-oci` 的 `state_dir/<fnv1a16(id)>.sock`：实测该形态沙箱内全 EACCES）；目录所有权加**身份 token 文件**（token + `/proc/<pid>/stat` starttime 比对），冲突**拒绝**而非抢占；verb 分级，`config`/`ports` 需 token | 两沙箱并存时，A 内枚举并连接 B 的 control.sock 一律 `EACCES`/`ECONNREFUSED`；双 worker 同名，第二个 create 失败且第一个目录仍在 |
| **F1.4 SL-8** | `crates/sandlock-core/src/resource.rs:126-131` 自增、`:545-560` 唯一归还点是阻塞 `wait4` | fork 登记时同时持 **pidfd**；归还以 pidfd 退出为权威（`pidfd_open` + 一个等待任务），`handle_wait` 变为幂等；新增对账 `proc_count` vs pidfd 存活数，偏差暴露为 `stats()` 字段 | `setsid` 孤儿生灭 N 轮后 `proc_count` 回到基线且仍能 fork（对照实测的 `1/7→2/8→2/5` 累加曲线） |
| **F1.5 SL-6** | `crates/sandlock-oci/src/init/mod.rs:118-207` 只按特定 pid `wait_exit` | `run_init` 主循环加 `waitpid(-1, WNOHANG)` 兜底：回收结果按 child 表路由，未知 pid 交对账器（与 F1.4 共用一张表）；无 pid_ns 时文档写清"孤儿归外层 PID 1"，开 `pid_ns` 后必须归 init | `<defunct>` 数量不随 double-fork 单调增长 |
| **F1.7 SECE-6** | child 共享 `pgid` = init ⇒ 沙箱内 `killpg(getpgid(0), SIGKILL)` 三条命令全灭 | **每 child 一个进程组**（`setpgid(0,0)` 于 child，实例级 kill 遍历组集合）；实例级操作改 `pidfd_send_signal` 定向；信号投递给"非本 child 子树的 pid"按同 uid 内核允许 ⇒ 在 init 侧拒绝转发，不由 supervisor 代为注入 | 沙箱内 `killpg(自身 pgid)` 只死自己；兄弟 child 与网关存活、输出不串 |
| **F1.8 deadline** | `crates/sandlock-oci/src/supervisor.rs:75-95` `request()` 无超时 | 每请求超时（默认 5 s，可配）；超时 ⇒ 通道标 `Dead`（与 F5 的 S5 错误码统一），调用方拿到明确错误而非挂死 | 注入 init 挂死 ⇒ 宿主在 `deadline + 1 s` 内返回错误 |
| **F1.6 SL-5** | 同上 init：解析失败/EOF/`RunMain` 分支不关收到的 fd；帧边界按字节流猜 | 每个出口分支显式关闭接收 fd（`Drop` 收口，禁止 `mem::forget`）；协议改**显式分帧**（长度前缀 + 版本 + 类型，拒超长/截断）；计数 `init_recv_fd_leaks` | 畸形帧 ×1000 且每帧附 fd ⇒ init 的 fd 数不增长；宿主侧流仍正常 EOF |

## 阶段 F1：M0′ 安全门槛（fork 侧独立可验证，exec 落地前必须清零）

> 本阶段全部任务**不依赖实例化改造**：探针跑在当前 `sandlock-oci` 路径上（`docs/sandbox-exec-security.md` §10 已实测前三类今天就能跑红）。顺序：F1.1 → F1.2 → F1.3 → F1.4 → F1.5 → F1.7 → F1.8 → F1.6（SL-5 优先级最低）。

| Task | 落点（现状） | 改造口径 | 验收（除矩阵所列用例） |
|
**F1 阶段收口**：`scripts/test-all.sh` 全绿（六套 + 新增用例计数已登记进 baseline）→ `python/build-wheels.sh --verify` → `e2b-integration.md` §3.9 表里 SL-4/5/6/7/8 全部改「已修（commit）」、`sandbox-exec-security.md` §7 的 M0′ 标"已清零"。

## 阶段 F2（M0）：实例生命周期上提，行为不变

**Files:** `crates/sandlock-core/src/sandbox.rs`（`do_create_stdio()` :1829→:2809 的 `ResourceState` 新建、`wait()` 收尾 :1061-1072、单槽 `child_pid`/`leader_pid` :1375/:1389/:1404、`control_handle` :3123）、新 `crates/sandlock-core/src/instance.rs`

- **F2.1** 引入 `SandboxInstance`：持 runtime、notif/throttle/loadavg/control listener、控制目录 + 身份 token、DNS 网关、`ResourceState`、`PolicyFn`/Network/Procfs/COW 状态。`Sandbox::run/popen/spawn` 内部改走"一次性 instance"，外部语义与 ABI 不变。验收：`test_instance_lifecycle.rs` 四条 + 全量与 F0.1 基线逐套件相等。
- **F2.2** `shutdown()` 按 §5.3 七步固定顺序实现且幂等（Draining → `Shutdown` 帧 + grace 5 s → 逐 child pidfd SIGKILL → 组集合 `killpg` → 实例组兜底 → 关宿主端 stdio → abort 后台任务 → token 比对后清目录 → 归还端口/预算/日志收尾）。验收：`shutdown()` 调三次不 panic、控制目录消失、无残留进程。
- **F2.3** `stats()` 增 `proc_count_vs_live`、`children_live`、`instance_state`（F1.4 的对账器在此露出）。

## 阶段 F2b（候选路线 B —— 待 E2B/用户确认）：supervisor 进程化 `sandlock-supervise`

> 2026-09-04 评估结论：per-uid 隔离拟走 **B 档**（**待 E2B/用户确认**，未确认前不视为已定路线）—— 特权只存在于 create 那一下，**服务中介的进程本身就是该沙箱的 host uid**。于是 SL-1（中介以 supervisor 身份代执行）与 SL-7（控制目录可枚举、`SO_PEERCRED` 形同虚设）**由构造消除**，不再需要在中介里补身份或丢 capability。⛔ **状态：候选路线，待确认**——已确认的只有「每沙箱一个长命实例」（e2b-integration §8）；未拍板前按 A 档兜底，per-uid 断言不得宣称成立。交接形态取舍已于 2026-09-04 拍板：**双传输（常驻池 path+token / 按需 launcher fd 交接）+ supervise 单代次**（见 F2b.2/F2b.3）。仍需拍板：per-uid 隔离是否本期必须、B 档是否最终确认（否则 A 档兜底）、按需形态是否接受 file-cap launcher（③，`cap_setuid,cap_setgid`，稳态清零）。
>
> 顺序：`F0 → F1（安全门槛）→ F2（M0）→ F2b.1/.2/.3（进程边界与控制通道）→ F3（exec，先在同进程验、再经 supervise 通道验同一套帧）→ F4 → F5 → F2b.4/.5（预算与交付物）→ F6–F9`。F2b 与 F3 共用同一份 instance API，区别只是它被谁持有。

> 别和旧否决记录混淆：`docs/sandbox-level-cow.md` 当年否掉的是**沙箱级 COW 文件层**（磁盘配额路线改走 XFS prjquota），不是「supervisor 进程常驻」这件事本身。F2b 只复用后者、不涉及前者 ⇒ supervise 不带 COW 位图，这也是它预期比 oci daemon 薄的原因之一。

为什么这条路在 fork 里几乎不需要新特权（两条既有事实）：

1. 非 root 进程可以给自己建 userns 并写单 entry map —— 本仓库已实现：`context.rs:290-292` 就是子进程自己 `write("/proc/self/uid_map", "0 <real_uid> 1")` + `setgroups deny` + `gid_map`。所以"supervisor 以 uid X 运行"即可让沙箱在 ns 内是 uid 0、在宿主上是 **X**，绕开 §3.5 的"任意 host uid 需 root/CAP_SETUID"（那条限制只针对**映射别人的 uid**）。
2. 非 root supervisor 全能力已被 S1.3 固化（uid 65534 下三套全绿）⇒ "supervisor 不是 root"不是新假设，只是新**归属**：一个 supervisor 进程服务一个沙箱。

### Task F2b.1：`sandlock-supervise` 二进制（策略全字段入口）

**Files:** Create `crates/sandlock-supervise/`（bin，进 `Cargo.toml` workspace）；复用 `crates/sandlock-core`（M0 之后的 `SandboxInstance`）

- 入口：`sandlock-supervise --policy <fd|path.json> --uid <X> --control-fd <N>`；启动即自检 `geteuid()==X`，不等则**拒绝启动**（防止 launcher 忘记降权 ⇒ 静默落回 C 档）。
- 策略传输必须是**全字段**：复用 Python 侧同一份 `Policy` 字段清单，反序列化后逐字段回读，任何"字段未落地"即启动失败 —— 这正是 `notify_rate_limit` 假告警（P3）暴露过的同类问题，用 `_HANDLED_FIELDS` 的等价机制在 Rust 侧守。
- 不接受 OCI runtime spec（§11 的评估结论：E2B 的网络/header 注入/`host_mask`/`max_open_files`/`clean_env` 在 OCI spec 里没有入口 ⇒ 用 fork 原生策略格式，别往 `policy.rs` 塞 E2B 专有扩展）。

**测试：** `integration/test_supervise.rs :: test_supervise_refuses_wrong_uid`、`test_policy_roundtrip_covers_every_field`（字段清单与 builder 支持集取并集后逐项断言，禁"未识别即忽略"）。

### Task F2b.2：控制通道双传输（path+token 常驻池 / fd 交接按需）

**Files:** Modify `crates/sandlock-core/src/control.rs`（现状：`UnixListener::bind(control.sock)` :111，peer uid 只告警 :236-262）

- 今天的模型是"supervisor bind 一个文件路径，别人来 connect"，peer 检查假设**对端与我自己同 uid**。B 档下对端是 worker（另一个 uid）⇒ 该检查方向必须反过来，而且 0700 目录反而会让合法 worker 连不上。
- **传输 1（按需 launcher / 同进程父→子）——fd 交接**：`socketpair()` 在 create 时建立，一端随 `SCM_RIGHTS` 交给 supervise 子进程（fd 号固定并记入实例状态），另一端留在宿主 worker ⇒ **路径不参与鉴权**，也不存在"沙箱内枚举他人控制目录"（§3.9 SL-7 的实测面）。凭证=fd 本身，再叠一次 token 握手防中间替换。
- **传输 2（常驻池 / 预启 slot）——path + token**：slot 由部署层以 uid X 拉起、worker 不是父进程 ⇒ 拿不到 create 时 socketpair，只能 connect 路径。**权限方向必须反转**：不能 0700 X 独占（worker 连不上）。socket 放共享目录（root-owned 1777+sticky 或注册通道专用目录），目录名哈希，peer 检查改为 **`SO_PEERCRED` ∈ 允许清单（worker uid 65534）+ token 握手**（F1.3 同一套断言）。
- 单机/CLI 仍保留同 uid path 模式（0700 + 哈希目录名 + 非 root 时 `SO_PEERCRED` 不匹配即断开），语义并入传输 2 的"允许清单只含自身"特例。

> **2026-09-04 E2B 拍板（生效前提：B 档被最终确认）：两种传输都实现，不二选一。**
> 常驻/预启形态走传输 2（path + token），按需/launcher 形态走传输 1（fd 交接）；
> 两种传输共用同一套 verb/帧/auth 断言。**supervise 固定为单代次：一个进程只服务一个沙箱，
> `shutdown()` 清场后 `exit(0)`**；任何“省重启”的复用诉求都回退为进程重启这一种实现（见 F2b.3）。

**测试：** `integration/test_control.rs :: test_socketpair_channel_rejects_third_party`、`test_fd_handoff_channel_rejects_third_party`、`test_path_mode_peer_uid_mismatch_closes`、`test_registered_path_channel_accepts_allowlisted_peer_with_token`、`test_sandbox_cannot_reach_sibling_channel`（沙箱内枚举/连接一律 `EACCES`/`ECONNREFUSED`）。

### Task F2b.3：身份交接契约（fork 只定契约，不装特权）

- fork 提供并测试的是："supervisor 进程以任意非 root uid 运行 ⇒ 全功能（含 Landlock/seccomp/notif/DNS 网关/入站映射）"，以及 `--uid` 自检。
- **"如何把进程变成 uid X" 留在 fork 之外**（E2B 侧 `uid_pool.py` 的 provisioning 或运维的 launcher/systemd），fork 侧只在 `docs/` 写清契约与两种可选实现（root launcher 持 CAP_SETUID/SETGID/CHOWN；或 setuid helper），默认**不安装任何 setuid 二进制**。
- create 期需要特权完成的三件事写进契约（按需 launcher 形态）：workspace 目录 `chown X`（需 CAP_CHOWN，建议改为 supervise 自建目录以免掉）、supervisor 进程降权、控制 fd 交接；常驻池（①）形态三者都不需要——身份由部署定、workspace 自建、控制走 path+token。特权动作都在 fork 之外 ⇒ fork 的 CI 与本机验证全程非 root。

**测试：** `integration/test_supervise.rs :: test_supervisor_as_foreign_uid_is_fully_functional`（本任务的核心验收，用 `unshare`+自映射或 `setpriv` 在测试里以第二 uid 起 supervise，断言建箱/中介/入站端口/stats 全通），并在 CI 里以非 root 跑通。

**"无 root"能做到的四种做法（2026-09-04 拍板：常驻形态选 ①；按需形态选 ③ file-cap launcher；不再要求 ① 与 fd 交接二选一）**

| 做法 | 运行期 root | 需要装/配什么 | 自研特权代码 | 备注 |
|---|---|---|---|---|
| **① 由部署期就把 supervise 进程起成 uid X**（容器形态：每 slot 一个容器/Pod，`user:` / `runAsUser` 固定不重叠；裸机形态才是 systemd 模板单元） | ❌ 不需要 | 一份 compose/k8s 清单 + uid 段配置，运行期不需要任何特权 API | 不装 setuid、不 setcap、不改 sysctl | 与 `context.rs:290` 的单 entry 自映射兼容 ⇒ fork 现有能力够用；workspace 由 supervise 自己创建，落盘即归 X，连 CAP_CHOWN 都不需要 |
| **② setuid `newuidmap`/`newgidmap` + `/etc/subuid`（多 entry userns）** | ❌ | 发行版自带的两个 setuid 二进制 + 一行 subuid | 无（fork 只需调 helper） | 受两个宿主前提：容器不能 `nosuid`/`no_new_privs`；Ubuntu 24.04 要 `kernel.apparmor_restrict_unprivileged_userns=0`（**那是 root 的 sysctl**，fork CI 就在设它，见 `ci.yml:32`）⇒ 它其实没有真的"零特权"，只是把特权挪到内核配置 |
| ③ `setcap cap_setuid,cap_setgid+eip` 的最小 launcher | ❌ | 装镜像时一次 `setcap` | ~50 行，能力面比 setuid 位窄 | 同样被 `nosuid` 挂载关掉；launcher 不解析策略 |
| ④ setuid-root helper | ❌（瞬时 euid 0） | `chmod +s` 自有二进制 | 是（要审计） | 攻击面最大，最后选择 |
| （对照）什么都不给 = 今天形态 | ❌ | — | — | 拿不到 distinct host uid ⇒ 只能 A 档 |

选 ① 的理由：它是唯一「运行期零特权、且不给宿主加 setuid/sysctl 例外」的做法。**落地形态取决于部署**：E2B 是容器部署（`docker-compose.yml:36`、`docker-compose.prod.yml:90` 的 envd 都是 `user: "65534:65534"`，共享卷 `sandbox-data:/var/lib/e2b-sandboxes`；另有 `deploy/k8s/worker.yaml`）⇒ 容器里没有 systemd 当 PID1，模板单元不可用。① 的实际形态是：**节点上预起 N 个 `sandlock-supervise` slot 容器，每个固定一个不重叠 uid、空闲待命**；分配 = 连接 + token，回收 = 重启该 slot。这条不需要 docker.sock，也不需要 kube API 的运行期创建权限（另一种落地是每沙箱一个 Pod，见 `deploy/k8s/`；但那要给 worker/控制面运行期创建权限，docker.sock 路线等于交出宿主 root，不选）。顺带：compose 里 `user: 65534` 配 `cap_add: SYS_ADMIN` 的实效本来就依赖 ambient cap（`xfs_quota.py:709` 探的是 effective cap 而非 euid），slot 池路线不碰这个不确定性。
按需形态（worker 自拉、两种部署都可能有）用 ③ file-cap launcher（`cap_setuid,cap_setgid`，瞬时有、落位后清零），fork 不装任何 setuid；② 多 entry userns 与 ④ setuid-root helper 维持排除。

代价与约束：

- **一个 uid = 一个 supervise 进程 = 一个沙箱**（若一个 supervise 同时服务两个沙箱，那俩又回到共享 uid）。所以并发达 N 就需要 N 个 uid 槽；容量从"进程数"问题变成"uid 池大小"问题，`E2B_UID_POOL_SIZE`（默认 1000）与节点 PID/RSS 预算要一起看（F2b.4）。
- **回收策略（候选，待 B 档确认后生效）：轮转槽位池（2026-09-04 评估）**，但要把上一轮的算例改正一处 —— **复用窗口不是 `M/N`**。
  立论基础就是「中介身份恒等于持有实例进程的 euid」，所以 slot 进程的 uid **只能在启动时定死**，段大小 M 不拉长窗口：同一 uid 要再服务一个沙箱，必须等它当前这个沙箱结束并重启该进程 ⇒ **窗口 = 同时存活的 slot 数 N**。M 的作用只剩「保证同一时刻 uid 唯一 + 审计区分度 + 不与别的身份撞号」。
  把窗口做大只有两条路：
  - **W1（默认）**：增大 N，用 N × F2b.4 的 ≤8 MB 预算换窗口（N=100 ⇒ 窗口 100 代）。部署形态就是 ① 的 slot 池，运行期零特权。
  - **W2（可选升级）**：slot 服务完即退出，由部署层以**新 uid** 重启 ⇒ 窗口 = M（段内轮转）。前提是「谁有权以新 uid 起进程」：k8s 下控制面用 SA 建 Pod（`runAsUser` 取新号）可行；裸机下需要一个能降权的 runner（即 ②/③/④ 的特权组件）；静态 compose 的 `user:` 做不到运行期变更（部署期渲染模板可以，但那等于回到 N）。
  - **⛔ 被排除的第三条**：让一个 uid 为 W 的 slot 在运行时给每个沙箱映射新的 host uid（② 的多 entry map）。那样中介仍跑在 W 里 ⇒ C 档复活、SL-1 原样回来。此路必须在代码与文档里写死为禁止，防止将来被当成「省内存的优化」走回去。
  两条共同的硬不变式（W1 下同 uid 必然复用，所以不是可选项）：
  1. 回收 = **先清场再复用**：该 uid 名下 inode 归零（`find -uid X` 为空）、XFS project 清理、workspace / `/tmp` / 控制目录销毁；
  2. 分配游标必须持久（W2 下段内未过期 uid 不得回卷重复发放）；
  3. fork 在 `stats()` 里露出「当前 host uid + 段 + 该进程已服务过的代次计数」，E2B 侧据此对账。

**2026-09-04 E2B 拍板：supervise 生命周期（写入本文，实施约束）**

- **单代次**：一个 supervise 进程 = 一个沙箱代次；`shutdown()` 完成清场（inode 归零、XFS project 清理、workspace / `/tmp` / 控制目录销毁）后 `exit(0)`。
- **不做 in-process 多代复用**：连续服务多个沙箱需要完美重置 runtime（notif/listener/child 表/记账/token），任何遗漏都把 D2 的"清场不干净"从窗口风险变成即时风险；一律以进程重启划代。
- 常驻池 = 部署层保持 N 个进程待命，各自服务一代后由部署层重启（同 uid 或按轮转游标取新 uid）；按需 = launcher 每代拉新进程。supervise 行为对两者完全一致，不产生第二套实现。
- **回收权归启动者**：worker（65534）不能 `kill` 不同 uid 的 slot 进程（无 CAP_KILL）⇒ 销毁/缩容只允许三种：slot 协议自退、PDEATHSIG（worker 死亡兜底）、启动者（部署层/launcher）回收。E2B 侧不得设计 worker 直接 kill。

**方案 R（未采纳前的完整记述）：单个中介进程 + 每沙箱启动时分配 host uid**

用户提出的这条是成立的，机制上就是既有代码的 privileged 路径：中介进程持 `CAP_SETUID/CAP_SETGID`，`fork` 出沙箱后由**父进程**替它写 `0 -> X` 的 map（`context.rs:312` 正是这条路径，与非 root 的自映射 `context.rs:290` 相对）⇒ 每个沙箱拿到互不相同的 host uid，per-uid DAC 成立，**不需要 N 个常驻进程**。

但它没有把中介身份问题变没：中介 syscall 仍由那个进程执行，其身份是 W ⇒ 必须走 C 档修法（F6.1 原稿里被我降级掉的那套），而且这次是**必须做**而不是"兜底兼容档"：

```text
中介线程一次性降权（不可恢复）：
  从 effective + permitted + inheritable 里去掉
      CAP_FOWNER, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FSETID, CAP_CHOWN
  保留  CAP_SETUID, CAP_SETGID           # setfsuid/setfsgid 到任意 uid 需要它
每次被中介的 syscall：
  caller_scope(uid=X, gid=G) { setfsuid(X); setfsgid(G); <syscall>; 恢复 }
  守卫内禁止 .await（setfsuid 是 per-thread 状态）⇒ 中介只能串行
```

三个真实代价（这是选 R 之前要认下的）：

1. **中介线程是全节点的串行点**。`setfsuid` 的 per-thread 语义要求"同一线程同一时刻只服务一个 caller"，而把不同 uid 分到不同线程又会重新引入"两条中介线程抢同一个 notif fd"的复杂度。⇒ 沙箱数量上去后，一条慢路径（例如某沙箱 connect 黑洞 IP 拖住 on-behalf）会牵连所有沙箱的 open/connect 延迟：这是 §4.8（SECE-8，实测合并额外开销 ~5%）从"单实例内"放大到"全节点"的版本。B/W1 的每个沙箱一条中介线程天然没有这个问题。
2. **爆炸半径回到"一个进程 = 全部沙箱"**：中介进程崩/被攻破 ⇒ 该节点所有沙箱陪葬，而它持有的恰好是"能给任意 uid"的能力；B 档下一次只塌一个沙箱，且那个进程只有它自己那一个 uid。
3. **对照组测试变成硬要求**：`test_root_supervisor_keeps_caps_defeats_the_fix`（保留 cap 时同一条 `unlinkat` 必须成功）从"可选自证"升为 F6.1 主用例之一，且必须覆盖"permitted 集里还留着 ⇒ 被攻破可自救"这条路径。

可行的折中：**R + 分片**——K 个中介进程（各持 CAP_SETUID），每个服务 M 个沙箱，K 由 §4.8 类延迟实验定，不拍脑袋。K=节点数即退回 B/W1，K=1 即纯 R。

⚠ **决策依赖一个没测的数**：R 的唯一净收益是"省掉 N 个常驻进程"，而那个成本目前只有 debug+双进程时代的 ≈25 MB 参照（见 F2b.4）。**先按 F2b.4 的协议实测 release、单中介线程的 supervise 空载 PSS**，再决定 R / W1 / R+分片——不要用一个我拍的数字来定架构。

- 交接细节改为：worker 通过 systemd socket activation 或固定路径连上 supervise（两者 uid 不同 ⇒ F1.3 的 `SO_PEERCRED` 语义必须从"对端==我"改成"对端 ∈ 允许清单 + token 握手"）；若坚持 create 时 `socketpair` 交接，则需 ②/③/④ 之一，不能是 ①。

> 这一条会改写 F2b.2/F2b.3 的接口选择：**① 与"fd 即凭证"不共存**（进程由 init 起，worker 拿不到创建时的 socketpair）。**2026-09-04 E2B 已拍板：不做二选一**——常驻/预启走「① + 路径通道 + peer 允许清单 + token」，按需/launcher 走「③ file-cap launcher + create 时 fd 交接」；fork 的 control 层两种 transport 都实现（见 F2b.2）。

**⚠ 部署前提（必须写进 `docs/`）**：B 需要一个 create 期的特权入口。E2B 当前生产 worker 是 `USER 65534`（非 root），**它自己无法把进程变成 uid X**，也无法 `chown` workspace ⇒ 落地 B 必须新增一个最小特权组件（root launcher 持 `CAP_SETUID/CAP_SETGID/CAP_CHOWN`，或 setuid helper），或改由 systemd/编排给每沙箱一个降权单元。拿不到这个组件时，部署按 A 档运行（per-uid 断言不成立，文档与 `stats()` 要如实反映）。

**uid 空间与保留值（B 档容量口径）**

| 量 | 值 | 来源 | 对本项目的意义 |
|---|---|---|---|
| `uid_t` / `kuid_t` | 32 位无符号 ⇒ **0 … 4,294,967,295** | 内核 ABI（Linux 自 1.4 起 32 位 uid） | 空间本身**不是瓶颈**：需求 = 并发 slot 数（几十~几百），不是沙箱总数 |
| `uid_map` 条目数 | **最多 340 条**（每条是一段范围） | `kernel/user.c` 的 `MAP_MAX` | 无影响：B 档每个沙箱只写单 entry `0 -> X` |
| 补充组上限 | **65536** | `include/linux/limits.h` 的 `NGROUPS_MAX` | 走 ② （多 entry gid_map）时才会撞上；B 档单 entry 无关 |
| 并发 userns | `user.max_user_namespaces`（默认按 `pid_max/3` 算，发行版常调小或设 0） | 内核 sysctl（per-netns） | **这才是数量级上限**：每沙箱至少一个 userns ⇒ 100 沙箱/节点要 ≥ 100；与 `kernel.apparmor_restrict_unprivileged_userns`（②/① 之外的另一个宿主前提）一起进部署检查 |
| 保留/危险值 | `0`；`1–999` 系统段；**`65534` = `nobody` = `kernel.overflowuid` = NFS `root_squash` 的 `anonuid` 惯例**；镜像自带 uid（`python:3.14-slim` 的 0/65534、nodejs 层的 1000） | 内核默认 + 发行版惯例 | 沙箱 uid 段必须**排除**这些；跨 ns/跨机视角下未映射 uid 一律显示为 65534，任何按 `st_uid` 判断的逻辑会误判 |

- 现有池：`E2B_UID_POOL_START=10000` + `E2B_UID_POOL_SIZE=1000` ⇒ `10000–10999`。
- **D2 的回收策略在这里变成一个容量问题**：若"每沙箱一个全新 uid"则一天 8.6 万沙箱/节点会吃掉 3100 万/年（仍远小于 2^32，但运维上无法与 `/etc/passwd`、其它服务共存）；若"slot 重启即复用同一 uid"则残留窗口 = 0（全靠清场做对）。折中且推荐：**轮转槽位池** —— 并发 slot 数 N（如 100），uid 段 M ≫ N（如 `20000–40000`），分配游标单向推进、到段尾回绕 ⇒ 同一 uid 被再次使用前已经过去 `M/N` 代沙箱（此例 200 代），把"清场没做干净"从即时风险变成窗口风险。
- 需要新增的用例（fork 侧）：`test_uid_pool_rejects_reserved_ids` —— 请求 `0`、`65534`、本进程 euid、或与段内已分配值重叠时**必须拒绝**（沿用 `sandbox.rs:2087-2104` 的 fail-closed 范式），并在 `stats()` 里露出当前 host uid 与段信息。
- ⚠ 与 `Dockerfile.envd:66-75` 的相互作用（E2B 侧要复核，不属 fork）：worker 起在 **65534** 正是 `overflowuid`/`nobody`/NFS `anonuid` 的那个号。本地命名卷没事（镜像里预 chown 给 65534），但共享卷走 NFS + `root_squash` 时，"未映射/被 squash 的身份"与 worker 是同一个 uid ⇒ 需要一条 E2B 用例断言"经 NFS 落盘的沙箱文件不会以 worker 身份可读"，或干脆把 worker 挪到独立的非保留 uid。

### Task F2b.4：预算与自证（B 档的成本必须被量出来）

| 指标 | 目标 | 依据 |
|---|---|---|
| 每沙箱 supervise 常驻（**空载**） | **先测再定预算**（不预设数字） | 唯一有依据的参照是 §11.1 的 **≈25 MB/沙箱**，但那是 `sandlock-oci` 的 **debug 构建**、而且是**两个**常驻进程（14.3 + 10.4 MB、9 线程 + 2 线程）。我上一轮写的 ≤8 MB 是"release + 单线程 + 更薄"的推断，**没有实测支撑 ⇒ 撤销**。 |

**测试：** `integration/test_supervise_cost.rs :: test_per_sandbox_supervisor_rss_within_budget`、`test_exec_roundtrip_latency_within_budget`（profile 落 `tmp/perf/`）、`test_exit_frames_never_lost_over_1000_rounds`。


**F2b.4 的度量协议（先跑这个，再谈 N 取多少）**

1. 指标用 **PSS**（`/proc/<pid>/smaps_rollup` 的 `Pss`）而不是 RSS 求和：N 个 slot 之间共享二进制 text/rodata、libc、根文件系统只读页，按 RSS 加总会**高估**节点占用。
2. 采四个点：空载 / 1 条命令 / 沙箱内 64 进程 / `exec` 轮转 1000 次之后（最后一项抓"缓慢泄漏"，与 F5.6 同源）。
3. 构建必须是 `--release`（`panic=abort` + strip），并把 `MALLOC_ARENA_MAX=1`、tokio `current_thread` + 单一中介线程这两种配置各测一遍 —— 中介线程数取 1 不是性能选择，是 F6.1"per-thread `setfsuid` 不得互踩"的功能约束。
4. profile 落 `tmp/perf/`（本仓库同样只用项目内 `tmp/`），数字与结论写回本节。
5. **反推 N**：`N_max = 节点可分给 supervise 的内存 / 实测每 slot PSS`。若 N 小于并发需求 ⇒ 走 F2b.3 的 W2（服务完退出、以新 uid 重启），而不是偷偷把窗口说大。
6. **调度账本要加一项**：supervise 进程**不在** Landlock/seccomp 的实例记账里（它是宿主侧进程），所以它是 §3.8 之外节点超卖的第二个来源。`docs/SCALING.md:71` 的"每 worker 可容纳数 = 各维度 `E2B_NODE_*_MB` / 默认沙箱需求"必须把 `N × 实测 PSS` 从分母里先扣掉，否则算出来的可容纳数系统性偏乐观。

**实测结果（2026-09-04，release，OrbStack 内核 7.0.14 / Landlock ABI v8，非 root 容器内）**

探针：`slz_sup_probe.rs`，测量件现存 `sandlock-e2b/tmp/measure-supervise/`；复测时拷回 `crates/sandlock-core/examples/` 再 `cargo build --release -p sandlock-core --example slz_sup_probe`（该目录已有 `openat_audit.rs` 先例），随 F2b 正式化。原始数据：`tmp/measure-supervise/out/results4.txt` 与 `detail-*`。——一个进程持有一个**活实例**（`sb.run(["/bin/sleep","900"])` 常驻），空转等控制流量；`idle` 档为同样 runtime 但不建实例。采样子集已验证 supervisor 侧确实有 `anon_inode:seccomp`（notif fd）、两个 `pidfd`、控制 socket 与捕获管道，且**每个 supervisor 都带着 1 个被禁子进程**（`children == live`），不是拆完实例的空壳。

| 形态 | tokio 工作线程 | 进程线程数 | Rss/proc | **Pss/proc（边际成本）** |
|---|---|---|---|---|
| idle（无实例） | 1 | 2 | 3.5 MB | **452 kB** |
| 1 实例，N=1 | 1 | 2 | 5.7 MB | 4 458 kB |
| 1 实例，N=8 | 1 | 2 | 5.6 MB | 1 035 kB |
| 1 实例，N=32 | 1 | 2 | 5.65 MB | **604 kB** |
| 1 实例，N=64 | 1 | 2 | 5.63 MB | **518 kB** |
| 1 实例，N=32 | 4 | 5 | 5.69 MB | 686 kB |
| 1 实例，N=32 | 8 | 9 | 5.84 MB | 800 kB |

读法与结论：

1. **`ps` 看到的 5.6 MB/进程几乎全是共享的文件映射**（N=1 时 Pss 4.46 MB、N=64 时 Pss 0.52 MB ⇒ 约 5 MB 是二进制 text/rodata 等在 N 个进程间分摊）。**节点真实成本 ≈ 0.5–0.6 MB/slot**，即 100 slot ≈ 50–60 MB、1 000 slot ≈ 0.5–0.6 GB。§11.1 的"25 MB/沙箱"是 debug 构建 + 两个常驻进程 + OCI 机制，不能拿来定容量。
2. ⇒ **W1（每沙箱一个 slot 进程）的成本假设成立**，R 路线（单中介进程 + 每线程降 cap + `setfsuid`）省下的正是我们其实不缺的东西，却要付出"全节点串行中介线程 + 爆炸半径 = 整个进程 + 长期持 `CAP_SETUID`"三条代价 ⇒ **fork 侧实测结论：若按 B 档落地，默认走 W1，R 不采纳**（保留 F2b.3 里那三条硬不变式与回收清场要求）。
3. 线程开销可忽略（每多一条 tokio 工作线程 ≈ +180 kB Pss），但 `setfsuid` 的 per-thread 约束（F6.1）不再适用于 W1 ⇒ 中介线程数按性能选即可。
4. **这个数是下界，不是最终预算**：探针只含"1 命令 + notif + 控制面 + 捕获管道"。`net_isolation`（DNS 网关任务）、`chroot` 镜像 rootfs、MCP 入站端口监听、PTY、COW 都要另测一档。F2b.4 的协议保留，正式 supervise 出来后按同样方法重采，并把结果写进 `docs/test-baseline.md` 旁边的一份容量表。
5. `/proc/meminfo` 的 `MemAvailable` 增减在本轮不可信（有正有负，页缓存回收主导）⇒ 容量口径一律用 PSS，别用 MemAvailable 差分。

**本轮顺带产出的两个真实缺陷**（已进计划）：

- **F0.4：`cargo build --release -p sandlock-cli` 在 fork tip 上编译不过** —— `sandbox/builder.rs:66` 的 `net_bind_map: Vec<(u16,u16)>`（S2.5，commit `3a07995` 引入）缺 `#[cfg_attr(feature = "cli", arg(...))]`，而 `sandlock-cli` 依赖 `sandlock-core` 的 `cli` feature ⇒ clap 找不到 `(u16,u16)` 的 value parser。本地验证命令只跑 `-p sandlock-core --lib/--test integration`（default features，不含 cli）与 python 套，所以一直没暴露；CI（`cargo test --release --workspace`）本来会抓到，但推送被 token 权限挡住 ⇒ 从未跑过。**这正是 F0.1 全量 runner 要抓的那类问题**，第一次跑就抓到两个：cli 构建坏了 + 下面这条。
- **F1.5 的现场证据**：我的测量容器 PID 1 是个 `sleep`（不 reap），于是 8 分钟内攒了 53 个 `sandlock-oci <defunct>` / `bash <defunct>` 僵尸 —— 与 SL-6 的实测结论同构（无 pid_ns 时孤儿归外层 PID 1，宿主不 reap 就一直堆）。计划里"回收 = `waitpid(-1, WNOHANG)` + pidfd 对账"的必要性由此再确认一次。

### Task F2b.5：交付物形态

- `sandlock-supervise` 要进 wheel/镜像（今天发布只打 `libsandlock_ffi.so` + Python 绑定，§0）：`python/build-wheels.sh` 增加二进制随包（或独立 artifact + `--verify` 校验其二进制存在与 `--uid` 自检行为）。
- F0.2 的 wheel/tip 自证扩到"符号集 + supervise 二进制指纹"。

## 阶段 F3（M1）：`exec` 下沉复用 + child 句柄

> B 档下 `exec` 的调用方是宿主 worker、被调用方是 `sandlock-supervise` 进程 ⇒ F3 的 child 句柄与 stdio 交付必须**同时**支持同进程（旧 API、单测）与跨进程（经 F2b.2 交接的 fd）两种持有者；帧协议只写一套。

**Files:** `crates/sandlock-oci/src/init/*`（`mod.rs`、`proto.rs`、`fdpass.rs`、`fdrecv.rs`）→ 下沉到 `crates/sandlock-core/src/init/`；`sandbox.rs`（去掉 `Process<'a>(&'a mut Sandbox)` 借用，:3022）；`crates/sandlock-ffi/src/lib.rs` + `include/sandlock.h`；`python/src/sandlock/`

- **F3.1** init 循环与帧协议搬到 core（`sandlock-oci` 改为**复用** core 的实现，删本地副本；oci 现有 9 例集成测试必须原样绿 ⇒ 证明是搬家不是重写）。
- **F3.2** `instance.exec(argv, stdio|pty) -> {child_id, fds}` + `wait_child(child_id)` / `kill_child(child_id, sig)` / `resize_child(child_id, rows, cols)`；stdio 经 `SCM_RIGHTS` 交付；退出帧按 child_id 路由（依赖 F1.2 的登记性校验）。
- **F3.3** FFI + Python：`sandlock_instance_exec` / `..._wait_child` / `..._kill_child`、`SandboxInstance.exec(...)` 返回自持句柄的 `Process`；cbindgen 重生成 + C 冒烟 + Go 构建不破。
- **验收（本阶段不开放给 E2B）**：矩阵 F3 行四例 + 双 wait 幂等 + "child 已退但孙子持 stdout ⇒ 按 fd 持有者收尾，不吊死"（§4.14）。

## 阶段 F4（M2）：per-exec 参数与策略子集校验

- **F4.1** `exec(argv, cwd, env, extra_writable, bind_ports)`：execve 前 `chdir` + envp 构造；`clean_env` 语义逐 exec 保持。
- **F4.2** **子集校验（S9）**：实例创建时定死策略上限，exec 请求越界 ⇒ `EPERM`/明确错误码 + 日志可见；on-behalf 注 fd 走同一套检查（它是 `fs_denied` 的旁路）。
- **F4.3** `update_network` 语义（S2）：新策略只对**新 exec** 生效，在跑 child 保持原策略，API 回报 staleness；在线收紧沿用 `PolicyFnState.live_policy`。
- **F4.4** 网络/凭据状态绑 pid（§4.5）：per-child 的 connect/send 判定不得串到兄弟 child。

## 阶段 F5（M3）：默认值、拒绝面与泄漏兜底

- **F5.1（Q10，风险最大）** `max_processes` 从"每命令 64"变"整箱 64" ⇒ 默认上调（建议 256）+ `CHANGELOG`/release note 写明；lib 单测断言新默认值，integration 断言"整箱第 N+1 个 fork 被拒"。
- **F5.2** 多 child 时 `checkpoint()` **显式拒绝**（禁止静默只存一条命令的 address space）。
- **F5.3** `pid_ns` 与实例并存：ns pid 1 退出不带走整棵树（实例级 reaper），或明确拒绝组合；开 `pid_ns` 时 on-behalf `/proc` 白名单按 `PidKey` 收窄到本 child 子树（`procfs.rs:210-231` 含 `cmdline`/`status` ⇒ 不收窄就是兄弟命令行泄露）。
- **F5.4** `Dead` 语义（S5）：listener/reaper 失败 ⇒ 统一错误码，所有后续 `exec/wait_child/kill_child` 同码，不静默重启。
- **F5.5** idle 超时与最大寿命（S7/S13）：child 表空且无 `wait_child` 订阅者持续 `T_idle` ⇒ Draining→shutdown；`T_max` 强制滚动；幂等。
- **F5.6** 长跑自证（S7）：`integration/test_instance_leak.rs :: ten_thousand_exec_roundtrip`（短时轮转 10k 命令，断言 fd 数、tokio 任务数、`ProcessIndex`、`proc_count` 无单调增长），并录 profile 到仓库内 `tmp/perf/`（本仓库同样只用项目内 `tmp/`）。

## 阶段 F6：文件身份（SL-1 / P1 + P2）与 `fs_mount`（P5）

### Task F6.1：路径中介的调用方身份（P1 / P2，SL-1）—— B 档下改造成"断言 + 拒绝"

**Files:** `crates/sandlock-core/src/seccomp/notif.rs`（`handle_notification` :2279 起；`openat/openat2 :1777`、`renameat2 :1799`、`mkdirat :1804`、`unlinkat :1819`、`fchmodat/fchownat/utimensat/mknodat :1687-1690`）、`crates/sandlock-core/src/cow/seccomp.rs`、`sandbox.rs` 的中介身份自检

**形态事实（决定本任务的性质）**：中介没有独立的特权进程，`notif::supervisor(...)` 就跑在持有实例的那个进程里（`sandbox.rs:2915` 的 `tokio::spawn`）⇒ **中介身份恒等于该进程的 euid**。所以只要那个进程本身是沙箱的 host uid（F2b 的 B 档），DAC 判定天然正确，SL-1 的三个症状（属主落 root、`chmod` 失效、1777+sticky 跨 uid 保护不成立）就不存在。fork 侧的既有机制已具备前提：非 root 进程可自映射单 entry userns（`context.rs:290-292`），非 root supervisor 三套全绿（S1.3）。

| 档 | 中介身份 | 本任务的改动 | 支持状态 |
|---|---|---|---|
| **A** 非 root supervisor，沙箱与它同 uid（无 per-sandbox uid） | 天然正确 | 只加断言 + 文档口径（不得把"同 uid"写成"per-uid 隔离"，§3.5） | ✅ 默认（生产） |
| **B** 每沙箱一个 supervisor 进程，其 euid == 该沙箱 host uid（F2b） | 天然正确**且** per-uid 成立 | 加"两 supervisor 不同 uid"的跨箱用例；中介线程不再需要任何身份技巧 | ⏳ 候选路线（待 E2B/用户确认；未确认前 A 档兜底） |
| **C** 单个中介进程持 `CAP_SETUID` + 每沙箱 `RunAs(X)`（今天测试容器测出的那档；= 方案 R） | **不正确，除非补每线程降权** | **显式不支持**：create 时检测到"本进程 euid==0 且 `host_uid != 0` 且启用了路径中介"⇒ 拒绝建箱（沿用 `sandbox.rs:2087-2104` 的 fail-closed 范式），错误信息指名"请用 `sandlock-supervise` 把实例交给 uid X 的进程，或显式 `mediation_run_as=supervisor` 承认降级" | ⛔ 默认拒绝 |

- [ ] **Step 1 A 档测试**（`integration/test_mediation_identity.rs`，非 root）：`fs_denied` 非空 ⇒ 必走代执行；沙箱内 `openat(O_CREAT,0644)`（显式 `umask(0)`）⇒ 宿主 `stat` 断言 `st_uid == 本进程 euid`、`st_mode == 0o100644`；沙箱内 `chmod 0600` 自己文件 ⇒ 宿主侧看到新 mode；`fs_denied` 目标仍 `EACCES`（防"改身份顺手放宽白名单"）。
- [ ] **Step 2 B 档测试（本任务的正题）**：`test_two_supervisors_distinct_uids_isolate_files` —— 以 uid X/Y 各起一个 `sandlock-supervise`（`setpriv` 或自映射 userns），双方都允许写同一共享目录（1777+sticky）：X 建的文件 Y 可读不可删（`EPERM`）、Y 的 `chmod` 不能改 X 的文件（`EPERM`）、X 自己的 `chmod` 生效。这是 SL-1 "修好了"的**唯一硬证据**，A 档测不出来（同 uid 无从区分）。
- [ ] **Step 3 C 档 fail-closed**：实现 + `test_root_inprocess_mediation_is_refused`（断言 create 返回那个明确错误，且 `mediation_run_as=supervisor` 显式声明后**建箱成功但 WARN 且计入 `stats()`**）。对照组 `test_root_inprocess_mediation_with_caps_kept_would_leak`（仅在显式 `supervisor` 档下运行，用来证明"降级档确实降级"，不是装饰）。
- [ ] **Step 4 `mediation_run_as`**：`caller`（默认；A/B 档等价，C 档被拒）/ `supervisor`（兼容档，显式）。builder + Policy + FFI setter + cbindgen + CLI `--mediation-run-as` + Python 绑定，CLI→运行时 builder 必须真接线（别重演 `--pid-ns` 漏接线）。
- [ ] **Step 5 两档都进验收**：`scripts/test-all.sh --mediation-2uid`（有第二 uid 时跑 B 档，没有就打印"B 档缺档"并让 baseline 对账失败，不许伪装 skip）；`docs/test-baseline.md` 分档登记。这一步顺带修掉"生产非 root、测试 root"的错位。
- [ ] **Step 6** chroot 与 COW 两形态各补同断言（`test_chroot.rs`、`test_cow.rs`）；F6.2 的最小 `/dev` helper 落地后，chroot 那份改成**不下发 `fs_denied` 也通过**。
- [ ] **Step 7** 提交 `fix(notif): bind mediation identity to the owning process; refuse root in-process remap (P1/P2, SL-1)`；`e2b-integration.md` §3.1 标「已修（构造消除，见 §8 B 档）」，§2 P1/P2 状态改为"由 F2b 取代，仅保留 fail-closed"。

> 定级沿用 §3.1：SL-1 是多租户 DAC 隔离缺陷，不是 Landlock 逃逸。C 档从"修"改成"拒"，是因为把它修对需要 per-thread 降 cap + `setfsuid` 一整套技巧且极易与 tokio 多线程互踩，而 B 档用进程边界一次性拿到同样的性质、还顺手解掉 SL-7 与 §3.8。

### Task F6.2（P5）：`fs_mount` 支持单节点 + 最小 `/dev` helper

**Files:** `fs_mount` 的实现点与 `crates/sandlock-ffi/tests/fs_mount.rs`（已存在）、`python/tests/test_fs_mount.py`（已存在）、`crates/sandlock-cli` 的 `--fs-mount` 接线

- [ ] 先写失败测试：`fs_mount("/etc/resolv.conf", ...)` 与字符设备节点（`/dev/null`）当前以 `ENOTDIR` 失效 ⇒ 断言 `mount` 成功且沙箱内读到预期内容/`openat` 成功。
- [ ] 实现 bind-mount 单节点路径（BindMount 支持 file/chardev，父目录预创建策略与 `deterministic_dirs` 对齐），并提供 `minimal_dev()` helper（`ptmx`+`pts`+`null`+`urandom`+`zero`+`tty`），让调用方**不再需要整树挂 `/dev`** ⇒ 直接消除 SL-1 的最大触发面。
- [ ] 提交并把 §2 P5 标 ✅；F6.1 的 chroot 用例改用它构造 `/dev`，验证 `fs_denied` 可省。

## 阶段 F7（P4 / E2B 侧称 T4）：`net_isolation` + chroot 下 MCP 入站映射起不来

**Files:** `crates/sandlock-core/src/network/*`（`net_bind_map` / `port_mappings` 路径）、chroot 建立顺序（`sandbox.rs` chroot + listener 启动顺序）、`integration/test_net_isolate.rs`、`test_port_remap.rs`

- [ ] 先写失败用例（矩阵 F7 行）：chroot + `net_isolation` + `port_mappings` ⇒ listener 起来、宿主侧映射端口 connect 成功、`poll/epoll` 可读性合成生效（纯 sandlock 形态今天 3/3 通过 ⇒ 可作为对照组同时保留）。
- [ ] 定位：对照两形态差异（chroot 后 `control_dir`/`/dev/shm` 路径可见性、bind 端口池、`net_allow_bind_port` 探针）把根因写进提交信息；禁"靠调整测试期望"绕过。
- [ ] 提交 `fix(net): inbound port mapping under chroot + net_isolation (P4)`。

## 阶段 F8（P6）：无特权默认路径的两个已知限制

- `getsockname`/`getpeername` 反映合成视图（今天返回宿主地址）；非阻塞 `connect` 的 `EINPROGRESS` 语义（今天宿主侧阻塞，`SO_SNDTIMEO` 为上界）。各一条 integration 用例 + §2 P6 状态更新。定位为低优先，但**不得再留在"未知"里**：做完或明确记为"设计取舍 + 文档条目"二选一。

## 阶段 F9：文档与交付收口

- [ ] `scripts/test-all.sh` + `python/build-wheels.sh --verify` 全绿，数字登记进 `docs/test-baseline.md`（含本计划新增用例数）。
- [ ] `docs/e2b-integration.md`：§1 落地表新增 M0–M3/SL-1/P5 行；§2 P1–P6 全部改状态；§3.1/3.2/3.3/3.8/3.9 标「已修（commit）」；§5 验证矩阵刷新日期与数字。
- [ ] `docs/sandbox-exec-security.md`：§7 M0′ 标"已清零"，§4 各条目标注修复 commit。
- [ ] `upstream-pr-netns-free.md`：PR 范围补上新增能力（`SandboxInstance`/`exec`/`mediation_run_as`/`fs_mount` 单节点），推送仍标"待有写权限的 token"。
- [ ] `CHANGELOG` / release note：`max_processes` 语义与默认值变更（Q10）、`mediation_run_as` 默认切换、ABI 增量符号清单。

## 放行门槛（fork 侧）

1. **F1 未清零 ⇒ F3 的 `exec` 不合并**：`instance.exec` 只有在 F1.1/F1.2/F1.3/F1.4/F1.7 全绿后才允许存在公共 API（M0/M1 的内部重构可先行，但 `exec` 的 FFI/Python 入口在 F1 收口前不导出）。
2. **F5.1（`max_processes` 默认）未做 ⇒ F3/F4 不放开多 child 并发**：否则现网表现为"能建箱但第 65 个进程 fork 失败"。
3. **F6.1 未做 ⇒ 实例长命化必须标注风险**（§8 S6：代打开属主错位从"每命令"放大到"整箱生命周期"），并在 `e2b-integration.md` 保留警告。
4. 每阶段收口都必须重跑 F0.1 全量 + `--wheels` 自证，不允许"只在开发机跑其中一套"。
5. **F2b（B 档）未完成前，任何“per-uid 隔离已成立”的表述都必须标注为未验证**：包括 E2B 侧 `written_by == ra.host_uid` 那类断言；A 档（同 uid）下这类测试没有鉴别力，不得当作通过。
6. **轮转不变式未测完 ⇒ B 档不得宣称 per-uid 隔离可用**：至少要有 `test_same_uid_reuse_cannot_see_previous_generation`（含「故意不清场时必须能读到」的反向鉴别力断言）与 `test_slot_restart_requires_no_residual_inodes` 两条绿。

## 风险与假设



1. **搬家风险（F3.1）**：init 从 `sandlock-oci` 下沉 core 时最容易原样带走 SL-4/5/6 三条 —— 因此 F1 的顺序在 F3 之前，且 F3.1 的验收包含"oci 现有 9 例不改断言全绿"。

2. **Q10 是用户可见行为变更**：默认值调整与 release note 必须同批，否则等于把超卖修复换成 fork 失败投诉。

3. **`setfsuid` 单独不够**：root supervisor 只要 effective 集里还有 `CAP_FOWNER`/`CAP_DAC_OVERRIDE`，内核就继续按特权裁决 DAC ⇒ C 档必须**同时**降 cap 与切 fsuid，并用对照组用例（保留 cap 时同一条 unlink 会成功）证明降权真的生效。而 A 档（非 root supervisor = 生产形态）根本不走这条改动 ⇒ **两档都得跑**，否则等于只验了非默认档。

4. **控制目录迁出 `/dev/shm` + 哈希命名（F1.3）会影响既有依赖明文目录名的运维脚本**：属于 fork 内部路径，`e2b-integration.md` 需给出迁移说明；E2B 侧接线（M4）按新约定使用 sandbox_id + token。

5. **本机可验证性**：OrbStack `7.0.14-orbstack` + Landlock ABI 8 足以跑 lib/integration/python/oci 与 exec 面探针；XFS prjquota 类用例本就不属于 fork 套件，不构成 fork 侧缺口。

6. 若 F1.4 的 pidfd 化与 `ProcessIndex`/`PidKey` 现有假设冲突，优先改记账层（F1.4）而不是回退到"靠 `wait4` 归还" —— 后者已被实测证明可累加泄漏。

7. **B 档是一次兼容性破坏（只对 C 档）**：root worker 进程内直接 `RunAs(X)` + 路径中介的组合，改完之后默认**拒绝建箱**（E2B 生产镜像是 `USER 65534`，不受影响；受影响的是以 root 跑的 worker 与他们的测试容器）。逃生口是显式 `mediation_run_as=supervisor` + WARN + `stats()` 计数，release note 必须点名。

8. **B 的成本是每沙箱一个常驻进程**：RSS/延迟预算见 F2b.4；策略字段跨进程传输的完整性是新风险面（用 `test_policy_roundtrip_covers_every_field` 守，等价物即 Python 侧 `_HANDLED_FIELDS`）。身份交接（把进程变成 uid X、`chown` workspace）留在 fork 之外，**fork 不提供也不默认安装任何 setuid 二进制**；拿不到第二 uid 的环境按 A 档运行并明确放弃 per-uid 断言。
