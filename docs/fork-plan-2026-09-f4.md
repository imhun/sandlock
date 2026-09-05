# F4 阶段执行计划 — M2：per-exec 参数与策略子集校验（fork-plan-2026-09 §F4）

Branch: `upstream-pr/netns-free-clean`（本地，不推送）。进度：`.superpowers/sdd/progress.md`。顺序：F4.1 → F4.2 → F4.3 → F4.4（同任务多 commit，评审按范围）。

> **状态（F9 收口，2026-09-05）：F4 全部 complete + reviewed（两轮 fix）**：per-exec
> params + S9 `b58b634`；update_network/per-child 网络 `9f959f1`；FFI/Python/supervise
> 面 `c5d1108`；review fixes `902e522`（I1–I4）与 `e5c7214`（C1/R2）。架构 seam
> （per-child 正向收窄、credential 归因、port-aware update_network）见
> `docs/fork-plan-followups.md` FUP-19/20/21。

## 总纲（plan §F4 + sandbox-exec-security §7 M2）

- F4.1 `exec(argv, cwd, env, extra_writable, bind_ports)`：execve 前 chdir + envp 构造；`clean_env` 语义逐 exec 保持。
- F4.2 子集校验（S9）：实例创建时定死策略上限，exec 请求越界 ⇒ `EPERM`/明确错误码 + 日志可见；on-behalf 注 fd 走同一套检查（fs_denied 旁路）。
- F4.3 `update_network` 语义（S2）：新策略只对**新 exec** 生效，在跑 child 保持原策略，API 回报 staleness；在线收紧沿用 `PolicyFnState.live_policy`。
- F4.4 网络/凭据状态绑 pid（§4.5）：per-child 的 connect/send 判定不得串到兄弟 child。
- 验收测试：`integration/test_instance_exec_params.rs :: test_per_exec_cwd_and_env_apply`、`test_wider_policy_is_rejected`、`test_update_network_applies_to_new_exec_only_and_reports_staleness`、`test_per_exec_bind_port_reaches_listener`（integration + python）。
