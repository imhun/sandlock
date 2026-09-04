# F1 阶段执行计划 — M0′ 安全门槛（fork-plan-2026-09 §F1）

Branch: `upstream-pr/netns-free-clean`（本地提交，不推送）。进度账本：`.superpowers/sdd/progress.md`。每任务：TDD 红→绿 → 实现子代理 → task reviewer → ledger。
顺序（plan §F1）：F1.1 → F1.2 → F1.3 → F1.4 → F1.5 → F1.7 → F1.8 → F1.6。

## F1.1 SL-4 控制 fd CLOEXEC（in progress）

- 落点 A：`crates/sandlock-core/src/sandbox.rs:2317-2319` — `for &(target,source) in extra_fds { dup2 }` 用 POSIX dup2 清掉结果 fd 的 `FD_CLOEXEC`。
- 改动：target >= 3 的 extra_fds 用 `dup3(source, target, O_CLOEXEC)`；target 0/1/2 保持可继承（stdio）。
- 落点 B：`crates/sandlock-oci/src/init/mod.rs` `spawn()`（fork/exec 用户进程前）对 `CONTROL_FD` 显式 `fcntl(F_SETFD, FD_CLOEXEC)` 兜第二道。
- 新测试：`crates/sandlock-core/tests/integration/test_fd_inherit.rs`：
  - `test_control_socket_not_inherited_by_user_process`（沙箱内 `readlink /proc/self/fd/3` 必须失败）
  - `test_extra_fds_are_cloexec`（fdinfo 不再见控制 socket 可继承 flags）
  - `test_stdio_still_inheritable`
- 验证：新测试 RED→GREEN；`cargo test -p sandlock-core --offline --lib` + `--test integration`（uid 65534, privileged 容器）全绿且计数不降；oci 127 root-mode 不回归。

## 其余 F1 任务（落点/改动/验收见 docs/fork-plan-2026-09.md 表，派发时补步骤）

- F1.2 H1/H2 early_exits 上限+登记校验（oci supervisor）
- F1.3 SL-7 控制面鉴权+身份（control.rs）+ F2b.2 fd 交接
- F1.4 SL-8 pidfd 归还权威（resource.rs）
- F1.5 SL-6 init reaper（oci init）
- F1.7 SECE-6 每 child 进程组
- F1.8 InitLink deadline
- F1.6 SL-5 fd/分帧（oci init，优先级最低）
