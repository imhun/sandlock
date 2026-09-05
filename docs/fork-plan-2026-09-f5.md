# F5 阶段执行计划 — M3：默认值、拒绝面与泄漏兜底（fork-plan-2026-09 §F5）

Branch: `upstream-pr/netns-free-clean`（本地，不推送）。进度：`.superpowers/sdd/progress.md`。顺序：F5.1 → F5.2 → F5.3 → F5.4 → F5.5（同任务多 commit；评审按范围）。

> **状态（F9 收口，2026-09-05）：F5.1–F5.5 全部 complete + reviewed（fix 轮后 clean）**：
> 整箱 256 `b56fcbe`；checkpoint 拒 `a5c7f3b`；pid_ns+instance `2c016bd`；InstanceDead
> `d67a363`；idle/T_max `8e22c5d`；argv-safety gate fix `e5c049c`；review fix `1321ba0`
> （I1–I3 + minors）。行为变化已入 `docs/CHANGELOG.md`。

## 总纲（plan §F5 + sandbox-exec-security §7 M3）

- F5.1（Q10，风险最大）`max_processes` 从"每命令 64"变"整箱 64" ⇒ 默认上调（建议 256）+ CHANGELOG/release note；lib 单测断言新默认，integration 断言"整箱第 N+1 个 fork 被拒"。
- F5.2 多 child 时 `checkpoint()` 显式拒绝（禁止静默只存单命令 address space）。
- F5.3 `pid_ns` 与实例并存：ns pid 1 退出不带走整棵树（实例级 reaper），或明确拒绝组合；开 pid_ns 时 on-behalf `/proc` 白名单按 `PidKey` 收窄到本 child 子树（procfs.rs:210-231 含 cmdline/status ⇒ 不收窄即兄弟命令行泄露）。
- F5.4 `Dead` 语义（S5）：listener/reaper 失败 ⇒ 统一错误码，所有后续 exec/wait_child/kill_child 同码，不静默重启。
- F5.5 idle 超时与最大寿命（S7/S13）：child 表空且无 wait_child 订阅者持续 T_idle ⇒ Draining→shutdown；T_max 强制滚动；幂等。
- 验收测试：integration/test_instance_semantics.rs（五例）+ integration/test_pid_ns.rs（init reaps ns pid1 exit）+ python/FFI 兼容。
