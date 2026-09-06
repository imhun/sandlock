# F13 执行计划 — fs 写家族挂载保护收尾（FUP-04 link 直击 + FUP-05 目录挂载点 rmdir + 断言精度）

Branch: `upstream-pr/netns-free-clean`（本地，不推送）。进度账本：
`.superpowers/sdd/progress.md`。Base：fork docs tip（`9d60058` 之上，即 F12 计划
登记后）。状态：✅ 已完成（2026-09-06，fork 本地提交；报告
`tmp/sdd/f13-report.md`；RED/GREEN/门禁与文档同步见报告与 followups 已处置段）。
计划登记时（⬜ 计划中）来源 = fork-c-class-design-assessment 第 1 项 +
fork-plan-followups FUP-04/FUP-05。

## 1. 目标

把 fs 挂载点写家族的保护补全到与真实 bind-mount 语义一致：

1. **FUP-04**：`link()` 于 rw 挂载点（单文件/设备节点与目录两种挂载）的直击
   测试——与既有 unlink/rename 保护族并列，断言 EBUSY；同时把遗留的
   `contains` 式断言收敛为整串/结构化精确断言。
2. **FUP-05**：**目录挂载点**的 `rmdir` 语义——沙箱视图内对活动挂载点执行
   `rmdir` 必须与内核 bind-mount 一致返回 `EBUSY`（不允许“删除挂载点”），
   不能仅靠宿主侧内核兜底（虚拟化挂载形态下宿主侧无真实挂载）。
3. 文档：`docs/e2b-integration.md` §3.1 的“目录挂载点 rmdir 暴露为既有问题”
   注记随实现更新为已闭环；`docs/CHANGELOG.md`、test-baseline 同步。

## 2. 现状与需要核实的位置

- unlink/rename/link 于挂载点的 EBUSY 保护已在 F6.2 收口（单文件/chardev 单节点
  bind-mount；写家族防宿主源被删/移）。
- 目录挂载点（fs_mount 目标为目录根，如 `/workspace`、minimal_dev 的 `/dev/pts`）
  的 rmdir 无 fork 侧拦截（评审已披露）。
- 实现前先定位：rmdir/unlinkat(AT_REMOVEDIR) 是否已进 on-behalf/notif 路径、
  挂载点判定表在哪（`resolve_chroot_mounts` / chroot resolve + notif handler），
  以及目录挂载点删除在“只影响视图 vs 影响宿主”之间的当前行为（预期：宿主侧
  目录是真实目录，沙箱内删除若被放行会删宿主目录——必须拒绝）。

## 3. 验收（RED 先行）

- [ ] RED 用例（当前 tip 红）：
  - `link()` 目标落在 rw 单节点挂载点 → EBUSY（若已有则证明为断言精度项）；
  - `rmdir` 沙箱视图内活动目录挂载点 → EBUSY（宿主目录与内容保持）；
  - 对照组：非挂载点目录可正常 mkdir/rmdir。
- [ ] 断言精度：fs_mount 相关测试无 `contains` 部分匹配残留（逐文件核对）。
- [ ] 门禁：非 root（core_lib/core_integ/ffi/cli/supervise/python，基线
  823/533/98/98/36/3/0/454 或按登记 +N）与 root 档（oci-root 144 /
  supervise_root 2 / mediation_2uid 8）全绿，无新增 skip。
- [ ] `docs/e2b-integration.md` §3.1 注记更新为“目录挂载点 rmdir 已闭环
  （F13）”。

## 4. 建议实现方向（偏离需记录）

- 在挂载点写家族判定（unlink/rename/link 所在 handler）中为 `rmdir`/
  `unlinkat(AT_REMOVEDIR)` 增加“目标是活动挂载点 ⇒ EBUSY”的分支；
- 若当前 rmdir 根本未走 on-behalf/notif（纯 Landlock/直通），先确认宿主目录
  是否可被沙箱 rmdir 命中，再决定拦截点；
- 不引入“卸载挂载点”能力（本期语义 = 与真实 bind-mount 一致，禁止删除）。

## 5. 风险

- 目录挂载点在 chroot/视图层的解析路径与单节点不同，判定需复用同一张
  “活动挂载目标”表，避免两套口径；
- rmdir 语义若被产品需要“卸载视图目录”时属新能力，另立设计，不在本任务
  扩展。

## 6. 提交与报告

- RED 用例独立提交（`test(core): pin link/rmdir EBUSY at writable mounts (F13 red)`）；
- 实现提交 `fix(core): refuse rmdir of active mount points like bind mounts (F13)`；
- 收口提交（文档 + baseline）。
- 报告 `tmp/sdd/f13-report.md`（RED/GREEN 日志、断言精度核对表、门禁数字）。
