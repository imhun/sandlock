# F12 执行计划 — ProcessIndex 一 TGID 一 entry（线程 tid 懒登记建模收口）

Branch: `upstream-pr/netns-free-clean`（本地，不推送）。进度账本：
`.superpowers/sdd/progress.md`。Base：fork docs tip（`bc6c892` 之上，即 core F11
tip `927d015`）。E2B 对接：main 仓库（指针 bump + 探针/全量复跑由 E2B 侧任务接续）。

> **状态（2026-09-06）**：✅ 已完成——实现 `68e7e84` + docs `194ffed`，报告
> `tmp/sdd/f12-report.md`（RED/GREEN/门禁/内核实证见报告与 followups 已处置段）。
> 计划登记时（⬜ 计划中）用户指示列入主要计划。前身：F11 修复只在
> exec 冻结侧把 keys 归一化为唯一 TGID（`freeze.rs`），**线程 tid 懒登记本身保留**；
> 本计划彻底消除「一个 TGID 在 `ProcessIndex` 有多个 key」的建模残余，属 fork 核心
> 建模改造，需逐消费点复核（见 §5 审计清单）。

## 1. 背景与动机

现状（F11 报告 + 代码证据）：

- `ProcessIndex` 以裸 pid/tid 为 key（`seccomp/state.rs` `register_with`，
  `PidKey { pid, start_time }`）。
- `clone(CLONE_THREAD)` 不做 birth-track/count（`resource.rs`
  `requires_process_creation_tracking` 明确排除）。
- 非 leader 线程发出被中介 syscall（内存记账下的 mmap/brk 等）时，
  `register_pid_if_new`（`resource.rs:137-196`）以该线程 tid 懒登记独立 entry
  （pidfd_open 失败后走 Linux 6.9 `PIDFD_THREAD`）。
- 后果：同一 TGID 可同时存在 leader key 与多个线程 tid key。

F11 只归一化了 freeze 的遍历集合（`freeze.rs:298-317`）。残余风险：

1. **消费点假设脆弱**：任何「遍历 index = 遍历进程」的新逻辑都可能把同一 TGID
   处理多次（F11 就是这类 bug 的一次实例）。
2. **每线程冗余状态**：懒登记线程各自带 pidfd watcher 与 `PerProcessState`；
   线程密集负载下 entry 数随线程数增长，退出清理与账本多路径。
3. **身份/日志口径**：key 可能是 tid 而非 leader pid，日志与指标里的 pid 字段
   可能显示线程号。
4. **记账归属靠隐式约定**：内存 charge、exec-from-thread、cwd 目前都靠
   "路由到 leader" 的 fallback 成立，缺少结构保证。

## 2. 目标与验收定义

**目标**：`ProcessIndex` 中每个 TGID 至多一个 entry；线程 syscall 一律解析并路由
到其 TGID leader 的 entry；不引入线程 birth-track/count，不改变内存/进程配额、
cwd、freeze、checkpoint 语义。

**DoD（全部通过才算完成）**：

- [ ] **唯一性不变量**：单测断言——多线程 holder 中 N 个线程各自发出 mmap/brk
  后，index 中该 TGID 恰好 1 个 entry（RED：当前 tip ≥2）。
- [ ] **F11 回归不倒退**：`freeze_deduplicates_thread_group_keys` 与
  `test_instance_exec_after_threaded_peer_succeeds` 保持绿；threaded peer 存在时
  后续 exec 持续可用。
- [ ] **生命周期无泄漏**：线程组退出后无残留 tid entry / watcher；
  `proc_count` 归零；wait4 侧释放语义与 pidfd 权威语义均不回归。
- [ ] **记账正确性矩阵**：线程内 mmap/munmap/brk 的 charge/credit 与现行为一致
  （单 leader entry 记账；exec memory reset 仍按 leader 路由）。
- [ ] **消费点复核清单全过**（§5 逐项：读码 + 用例或注释证）。
- [ ] 门禁：非 root 全套（core_lib/core_integ/ffi/cli/supervise/python）与 root
  档（oci-root/supervise_root/mediation_2uid）数字与基线一致或按登记增量；
  无新增 skip/xfail 掩盖。
- [ ] wheel 重建 + verify；E2B 指针 bump 后 gateway/thread 探针与 full gate
  A/B 复跑绿。
- [ ] 文档收口：`docs/CHANGELOG.md`、`docs/fork-plan-followups.md`、
  `docs/e2b-integration.md` §5/§8 状态行、test-baseline 同步。

## 3. 设计方向（实现时可细化，偏离需记录理由）

### 3.1 登记路径改造（`resource.rs` `register_pid_if_new` / `state.rs`）

- 收到来自 pid 的通知时先解析 `read_tgid_of_tid(pid)`：
  - `pid == tgid`（leader/单线程）：照旧以 pid 注册（天然唯一）。
  - `pid != tgid`（线程）：若 leader 已在 index → 直接返回 leader entry，
    **不建线程 key**；若 leader 尚未跟踪 → 以 leader pid 注册（读
    `/proc/<tgid>/stat` start_time + leader pidfd），并把本次通知路由到该 entry。
- 删除「线程单独注册」路径（不再为线程走 `PIDFD_THREAD` 建独立 entry）；
  `PIDFD_THREAD` 分支仅保留在必须确认线程存活/身份的角落（若有）。
- 线程通知的记账/处理沿用现有 leader 路由（`addr_space_state`/charge/credit/
  exec-memory-reset/cwd），确保改造后仍解析到同一 entry。

### 3.2 生命周期与释放

- 每个 TGID 只保留一个 pidfd watcher（leader）；线程退出不再产生独立清理动作
  （线程不拥有 mm，地址空间归组，最后由组内最后退出者释放——与内核语义一致）。
- 复核 wait4/pidfd 双路径下 `proc_count` 释放的 exactly-once 不变量（counted
  child 仍由 pidfd watcher 释放；lazy 仍 wait4 侧）。

### 3.3 freeze

- 保留 F11 的 TGID 归一化（防御性；即使登记已唯一，归一化无成本且防未来 key
  形态漂移）。freeze 枚举仍走 `/proc/<tgid>/task`，与登记策略解耦。

### 3.4 需要实现期核实的内核/竞态点（列测试）

- **leader 先于线程存在**的时序：线程不可能先于其 TGID leader 存在，但 leader
  可能尚未发过任何被中介 syscall——线程首条通知时 leader 未注册的路径必须覆盖。
- **leader 退出而线程仍存活**：Linux 线程组 leader 退出后的 TGID 语义、剩余线程
  的记账/退出释放归属（用集成用例实证，不猜）。
- **PID 复用/竞态**：注册与 `read_tgid_of_tid` 之间的退出竞态；pidfd 权威性不变。

## 4. RED 先行（用例先落、当前 tip 必须红）

建议落点（与 F11 同族）：

- `crates/sandlock-core/tests/integration/`：`test_instance_thread_syscalls_single_index_entry`
  ——实例内启动多线程 holder，线程反复 mmap/munmap/brk，期间再 exec 多次；
  断言 index 每 TGID 唯一 entry、exec 全部 exit 0、组退出后无残留。
- `resource.rs` unit：`register_pid_if_new` 对同一 TGID 的线程通知不新增 key
  （注入已跟踪 leader + 线程 pid 集合）。
- 生命周期：线程组退出后 `proc_count`/watcher 计数归零的断言。

## 5. 消费点复核清单（逐项读码 + 必要时补用例）

- [ ] `freeze.rs`：归一化保留；冻结枚举按 `/proc/<tgid>/task`（已改，复核）。
- [ ] `resource.rs` `addr_space_state`/charge/credit/reconcile_floor：
  thread 通知解析到 leader entry。
- [ ] `resource.rs` exec memory reset（`handle_exec_memory_reset`，
  `:615-631` 按 leader 路由）：线程 exec 场景不回归。
- [ ] `resource.rs` 退出/pidfd watcher/cleanup（`:1273-1320` 双路径）：
  leader-only entry 下 exactly-once 释放。
- [ ] `state.rs` `inherited_cwd`（线程共享 leader cwd cell）：线程 key 移除后
  语义不变。
- [ ] `ProcessIndex::iter`/keys 的全部枚举点（rg 复核）：kill-all/checkpoint/
  stats/日志不再假定一 key 一进程。
- [ ] `sandbox.rs`/`instance.rs` 引用 ProcessIndex 的路径（进程树、kill_child、
  stats、lifetime）。
- [ ] supervise/oci 复用 core 的路径（若同构则同清单）。

## 6. 门禁、wheel 与 E2B 复跑

- fork 非 root：core_lib 823 / core_integ 533 / ffi 98 / cli 98 / supervise 36 /
  supervise_cost 3 / cli_build 0 / python 454（或按新增用例登记 +N）。
- fork root：oci-root 144 / supervise_root 2 / mediation_2uid 8。
- `python/build-wheels.sh` 重建 cp314 双架构 + `verify-wheel.sh` 全绿。
- E2B：子模块 bump → 复跑 thread/gateway 探针
  （`tmp/fup3_thread_probe.py`、FUP-E3 gateway+命令契约）→ full gate A/B 绿。

## 7. 风险与缓解

- 线程组 leader 退出语义（3.4）：以集成实证为准，若行为与假设不符则按实测收窄
  范围并在文档记录，不与内核语义对抗。
- 逐消费点改造范围大：坚持 RED 先行 + 每消费点独立提交，评审逐点核对清单。
- 性能：线程 syscall 密集时从“每线程一个 pidfd”变为“每 TGID 一个”，整体应下降；
  若出现热点（每次线程通知都读 /proc），用 perf 探针记录并评估缓存 tgid 映射。

## 8. 提交与文档

- 每个消费点一个 fork 本地提交，消息形如
  `refactor(core): route thread notifications to TGID leader entry (F12 <n>)`；
- 收口提交同步 CHANGELOG / fork-plan-followups / e2b-integration / test-baseline；
- 报告 `tmp/sdd/f12-report.md`（RED/GREEN 日志、审计表、门禁数字、wheel/E2B
  复跑结果）。
