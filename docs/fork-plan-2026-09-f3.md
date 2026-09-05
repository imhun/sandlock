# F3 阶段执行计划 — M1：exec 下沉复用 + child 句柄（fork-plan-2026-09 §F3）

Branch: `upstream-pr/netns-free-clean`（本地，不推送）。进度：`.superpowers/sdd/progress.md`。顺序：F3.1 → F3.2 → F3.3（同任务多 commit；F4/F5 随后，F2b.4/.5 在 F5 后）。

> **状态（F9 收口，2026-09-05）：F3.1–F3.3 全部 complete + reviewed**：init 搬家
> `d063437`（oci-root 144 精确不变）、per-child exec `4411c7b`、FFI/Python 面 `3d42bc7`、
> review fix `3fa0b95`（exec-mode 终态 / deadline 孤儿 / drop 契约）。seam 单归属维持
> 双份复挂（决策 + follow-up 见 `docs/fork-plan-followups.md` FUP-02）。

## 总纲（plan §F3 + sandbox-exec-security §7 M1）

- B 档下 exec 调用方 = 宿主 worker、被调方 = sandlock-supervise ⇒ child 句柄与 stdio 交付须同时支持同进程（旧 API/单测）与跨进程（F2b.2 fd 交接）；帧协议只写一套。
- 搬家不重写：oci init/proto/fdpass/fdrecv 下沉 core 后，sandlock-oci 复用并删本地副本，oci 既有集成全绿（现 144 基线）。
- F3.1 init 循环+帧协议搬到 core（`crates/sandlock-core/src/init/`）；F3.2 `instance.exec/wait_child/kill_child/resize_child`（stdio SCM_RIGHTS、退出帧按 child_id 路由、登记性校验沿用 F1.2）；F3.3 FFI（sandlock_instance_exec/_wait_child/_kill_child）+ Python `SandboxInstance.exec() -> Process`（自持句柄）+ cbindgen/C 冒烟/Go 不破。
- 验收：矩阵 F3 四例 + 双 wait 幂等 + "child 已退但孙子持 stdout ⇒ 按 fd 持有者收尾不吊死"（§4.14）。本阶段不开放 E2B。
