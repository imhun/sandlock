# F7–F8 阶段执行计划 — P4 入站映射 + P6 已知限制（fork-plan-2026-09 §F7/§F8）

Branch: `upstream-pr/netns-free-clean`（本地，不推送）。进度：`.superpowers/sdd/progress.md`。顺序：F7 → F8 → F9。

> **状态（F9 收口，2026-09-05）**：
> - F7（P4）：**前提证伪 + 回归 pin 关闭**（非代码修复）—— commit `4e78c98`（+3 镜像
>   pin）+ `da9c3a7`/`7183884`（e2b §2/§3.3 归因修正）。E2B 复测为 out-of-fork
>   follow-up（`docs/fork-plan-followups.md` FUP-E1）。
> - F8（P6）：**设计取舍 + 文档条目 + 回归 pin 关闭**—— commit `c8f76d4`（+2 pin，
>   core_integ 531）。
> - F9：本阶段收口完成（closure 清单与终验见 `tmp/sdd/f9-report.md`）。

## F7（P4）：net_isolation + chroot 下 MCP 入站映射起不来

- Files: core network/*（net_bind_map/port_mappings 路径）、sandbox.rs chroot + listener 顺序、integration/test_net_isolate.rs、test_port_remap.rs。
- 先写失败用例（矩阵 F7 行）：chroot + net_isolation + port_mappings ⇒ listener 起、宿主侧映射端口 connect 成功、poll/epoll 可读合成生效；纯 sandlock 形态（无 chroot）今日 3/3 通过 ⇒ 对照组保留。
- 定位根因（chroot 后 control_dir//dev/shm 可见性、bind 端口池、net_allow_bind_port 探针差异），提交 `fix(net): inbound port mapping under chroot + net_isolation (P4)`；§2 P4 ✅。禁靠调整测试期望绕过。

## F8（P6）：无特权默认路径两个已知限制

- getsockname/getpeername 合成视图（今天返回宿主地址）；非阻塞 connect EINPROGRESS 语义（宿主侧阻塞，SO_SNDTIMEO 上界）。各一条 integration 用例 + §2 P6 状态更新。定位低优先：做完或明确记"设计取舍 + 文档条目"二选一。
