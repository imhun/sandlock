# F2 阶段执行计划 — M0：实例生命周期上提（fork-plan-2026-09 §F2）

Branch: `upstream-pr/netns-free-clean`（本地提交，不推送）。进度账本：`.superpowers/sdd/progress.md`。顺序：F2.1 → F2.2 → F2.3（F2b 阶段另文档/随行展开）。

## 设计总纲（来自 docs/sandbox-exec-security.md §5 与 plan §F2）

- M0 目标：把 `ResourceState`、notif/throttle/loadavg、control listener、控制目录+token、DNS 网关、PolicyFn/Network/Procfs/COW 状态的生命周期从"create/run 内联 + wait() 一次性收尾"上提到显式 `SandboxInstance`；`Sandbox::run/popen/spawn` 内部改走"一次性 instance"，外部语义与 ABI 不变；新增 instance API（exec/wait_child/kill_child/shutdown 的形态在 M0 立骨架，exec 语义下沉属 M1）。
- 行为不变式：全量六套计数与 F1 收口基线逐套件相等（除新增 instance 测试 +N，baseline 同 commit 更新并点名）；既有断言零弱化。
- shutdown 七步顺序（§5.3）：Draining 拒新 → init/Shutdown 帧 + grace 5s → 逐 child pidfd SIGKILL → 组集合 killpg → 实例组兜底 → 关宿主 stdio + abort 后台任务 + token 比对后清目录 → 归还端口/预算/日志收尾；幂等。

## Task F2.1：SandboxInstance 引入 + 一次性实例路径

- 新 `crates/sandlock-core/src/instance.rs`；`sandbox.rs` 重构点：`do_create_stdio()`（:1829→:2809 ResourceState 新建）、`wait()` 收尾（:1061-1072）、单槽 `child_pid`/`leader_pid`（:1375/:1389/:1404）、`control_handle`（:3123）。
- 验收测试（integration + python）：`test_instance_lifecycle.rs :: test_instance_outlives_first_process`、`test_shutdown_is_idempotent`、`test_shutdown_releases_control_dir_and_dns_gateway`、`test_legacy_run_still_reclaims_all_resources`。
- 本任务允许多 commit（task 范围 base..head），每 commit 语义自洽；评审按全范围。

## Task F2.2：shutdown() 七步固定顺序 + 幂等

- 验收：shutdown() 调三次不 panic；控制目录消失；无残留进程；§5.3 顺序在代码/注释可见；与 F1.5/1.7 组集合、F1.4 对账一致。

## Task F2.3：stats() 增量

- `proc_count_vs_live`、`children_live`、`instance_state`（F1.4 对账器在此露出）；python/FFI 若有读取面保持兼容（报告点名）。
