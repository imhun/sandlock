# A/B follow-up cleanup implementation plan（fork-plan-followups A 节 + B 节）

> **For agentic workers:** 按任务顺序执行；每任务先落测试/证据再改代码（TDD），
> 独立可测后提交。进度账本 `.superpowers/sdd/progress.md`；收口台账
> `docs/fork-plan-followups.md`（A/B 节状态行）+ `docs/CHANGELOG.md` +
> `docs/test-baseline.md`。

**Goal:** 把 `docs/fork-plan-followups.md` A 节（代码/接线类）与 B 节
（性能/构建/发布类）全部推到终态——已具备的实现补回归测试，仍缺的实现/接线
落地，纯决策/流程/不可观项显式关闭并留证据。

**Architecture:** 全部改动在 `third_party/sandlock`（fork 子模块，本地分支
`upstream-pr/netns-free-clean`，不推送）。测试在 `sandlock-dev:latest`
（--privileged --network host，root 预置后 setpriv uid 65534；root 档单独跑）
与宿主脚本（wheel/verify）验证。

**Tech Stack:** Rust workspace（core/cli/ffi/oci/supervise）、cargo offline
（repo-local tmp/cargo-home）、manylinux cp314 wheel 管线、POSIX sh 脚本。

## Global Constraints

- 不推送远程；fork 与主仓库均为本地提交。
- TDD：行为改动先落失败测试；测试断言全精确（禁 contains 部分匹配动态文本）。
- 禁止新增 skip / 过滤；门禁计数按 `docs/test-baseline.md` 登记增量。
- 临时产物只放各仓库 `tmp/`。
- 性能改动不回归功能；性能测试必录 profile（FUP-14）。
- 每个可独立测试的任务一个提交（消息含 FUP 编号）。

---

## Task 1 — FUP-01 CLI `--pid-ns` 端到端 pin

**Files:** `crates/sandlock-cli/tests/cli_test.rs`
**现状:** `SandboxBuilder` 已带 `#[cfg_attr(feature = "cli", arg(long = "pid-ns"))]`
且经 `RunArgs` flatten 进入真实 builder；缺 CLI 端到端回归测试。

- [ ] 新增 `test_pid_ns_flag_wired_end_to_end`：驱动真 CLI `run --pid-ns`，
  沙箱内 `kill -0 <宿主 pid>` 得 ESRCH（pid-ns 视图），对照无 flag 时可见。
- [ ] 容器 cli 套件跑绿；基线计数 +1 登记。
- [ ] 提交 `test(cli): pin --pid-ns end-to-end wiring (FUP-01)`。

## Task 2 — FUP-02 init seam 单归属（决策关闭）

**Files:** `docs/fork-plan-followups.md`
**现状:** F9 决策 = 维持双份复挂；无代码动作。
- [ ] followups FUP-02 状态行更新为「已关闭（决策：维持双份复挂，长期项）」。
- [ ] 提交 `docs(followups): close FUP-02 as keep-dual decision`。

## Task 3 — FUP-03 supervise 退出顺序 + overflow 覆盖

**Files:** `crates/sandlock-supervise/tests/supervise.rs`、
`crates/sandlock-core/src/init/executor.rs`（必要时）
- [ ] 审计现有 EOF/Exited 用例缺口；新增「worker 先关通道 / 无 shutdown 但 workload
  存活」的 supervise 退出顺序用例与 overflow_drops 单测。
- [ ] supervise 套件绿；提交。

## Task 4 — FUP-06 root fd-handoff pre_exec 只留 server_fd + EOF 异常路径

**Files:** `crates/sandlock-supervise/tests/supervise_root.rs`
- [ ] supervise child pre_exec 仅清 server_fd CLOEXEC（worker_fd 随 exec 关闭）；
- [ ] 新增/强化 EOF 异常路径（worker 不 shutdown 即退出 → supervise 非零退出）。
- [ ] supervise_root 套件绿；提交。

## Task 5 — FUP-07 mediation no-clobber 组合回归

**Files:** `crates/sandlock-cli/tests/cli_test.rs`
- [ ] profile 带 `mediation_run_as=supervisor` + CLI 省略 → supervisor 保留；
- [ ] profile supervisor + CLI `--mediation-run-as caller` → caller 覆盖；
- [ ] 套件绿；提交。

## Task 6 — FUP-08 knobs 配置面决策 + 落地

**Files:** 审计后定（`crates/sandlock-core/src/init/executor.rs` /
`crates/sandlock-oci/src/supervisor.rs` / CLI）
- [ ] 审计 `early_exit_cap`/`request_timeout`/`T_idle`/`T_max` 消费点；
- [ ] 若低成本可接：接线 CLI/profile/env + 测试；否则登记「维持 constructor
  默认 + 文档」决策关闭。
- [ ] 提交。

## Task 7 — FUP-09 egress flake 证据留存流程

**Files:** `scripts/test-all.sh` 头注 + `docs/fork-plan-followups.md`
- [ ] 在门禁纪律中写明：首轮红日志保留 `*-r1.log`，复跑绿保留 `*-final.log`，
  报告须列出两日志与根因；
- [ ] followups 关闭；提交。

## Task 8 — FUP-10 escape 会话比较 + dead_groups 去重

**Files:** `crates/sandlock-core/src/init/mod.rs`（`signal_child`/
`signal_all_children` 抽出纯判定函数）+ 单测
- [ ] RED：纯函数判定「setpgid 移组后 setsid 回组」为 escape；
- [ ] 实现 `escaped_group(recorded, current_pgid, current_sid, supervisor_sid)`；
- [ ] `signal_all_children` 先对 pgid 去重（live + dead），单测覆盖重叠不双送；
- [ ] core_lib 绿；提交。

## Task 9 — FUP-11 F2b/F3 测试与日志硬化

**Files:** 按审计清单逐项（cli/supervise/core 测试 + serve.rs 日志）
- [ ] 逐子项：error-path contains 收敛、eprintln 限速（如需）、
  `--program`+validate-exit 测试、recv 超时不对称注释/用例、stats settle 断言、
  `FORBIDDEN_RUNTIME_MEDIATOR_REMAP` 测试引用；
- [ ] 相关套件绿；每子项或合并提交。

## Task 10 — FUP-12 Start/Exec call-site Err 中继单测

**Files:** `crates/sandlock-supervise/tests/supervise.rs`
- [ ] 为 serve 的 start/exec 错误中继补单测（错误类型精确匹配）；
- [ ] 提交。

## Task 11 — FUP-13 F5 观察缺口收口

**Files:** `crates/sandlock-core/tests/integration/test_instance_semantics.rs`
- [ ] 审计现有覆盖（Dead 统一码、T_idle/T_max、pid-ns procfs 已存在）；
- [ ] 补 pid-ns 下 init 意外死亡 → `InstanceDead` 用例（如可构造）；
- [ ] 24h / 极端时序项以文档证据关闭（不可常规门禁观测，非行为缺陷）；
- [ ] 提交。

## Task 12 — FUP-14 reap 轮询事件化 + 延迟 profile

**Files:** `crates/sandlock-core/src/init/mod.rs` + `supervise_cost`
- [ ] RED：以可测延迟断言证明 100ms 地板（若稳定可测）；
- [ ] 用 signalfd/pidfd 就绪通知替代固定 100ms poll 睡眠（保持同语义）；
- [ ] supervise_cost 前后 profile 对比（exec 延迟、PSS）落 tmp/；
- [ ] 门禁绿；提交。

## Task 13 — FUP-15 release profile

**Files:** `Cargo.toml`
- [ ] `[profile.release] panic="abort"` + `strip="symbols"`（保持
  cli_build/supervise_cost 阈值内）；
- [ ] cli_build 绿 + supervise 二进制尺寸记录；提交。

## Task 14 — FUP-16 wheel 管线加固

**Files:** `python/build-wheels.sh` / `python/verify-wheel.sh`
- [ ] verify 校验 RECORD 行含注入 supervise 记录；manifest 目录解析不依赖
  `dirname $1` 单文件误配；uid 冒烟含 euid 精确断言；注入改 replace-in-place；
  pip 真机 0755 说明/检查；
- [ ] 重建 + verify 绿；提交。

## Task 15 — FUP-17 runner 硬化

**Files:** `scripts/test-all.sh`
- [ ] 无参/普通模式以 root 运行时拒绝并提示 root 档命令（对称守卫）；
- [ ] root 档 `CARGO_INCREMENTAL=0` 说明或实现；提交。

## Task 16 — FUP-18 容量表精度

**Files:** `docs/supervise-capacity.md`
- [ ] 用 FUP-14 前后 profile 数据回填 §4.1 区间/采样标注；提交。

---

## 收口

- fork 全量门禁（非 root 全套 + root oci/supervise_root/mediation_2uid）按
  baseline 或登记增量绿；
- wheel 重建 + verify（FUP-15/16 后必做）；
- E2B 侧：若 fork core/wheel 行为面变化，指针 bump + thread/gateway 探针 +
  full gate 复跑（沿用 F12–F14 流程）；
- 台账：fork-plan-followups A/B 节全部状态行、CHANGELOG、test-baseline、
  e2b-integration（如涉及）；
- 报告 `tmp/sdd/ab-cleanup-report.md`。
