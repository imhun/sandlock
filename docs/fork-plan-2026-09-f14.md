# F14 执行计划 — capability-aware 特权 remap gate（FUP-22，route-B ③ 前置）

Branch: `upstream-pr/netns-free-clean`（本地，不推送）。进度账本：
`.superpowers/sdd/progress.md`。Base：fork docs tip（F13 计划登记后）。状态：
⬜ 计划中（2026-09-06，用户指示排入计划；来源 = fork-c-class-design-assessment
第 2 项 + fork-plan-followups FUP-22）。交付时序：**route-B ③ file-cap
launcher 部署前必须完成**；实现期不引入真实 file-cap 部署，用 capability
夹具模拟。

## 1. 目标

C 档 gate（root 进程内 remap + 路径中介 ⇒ 建箱前拒绝）目前只按 `euid == 0`
触发。route-B 的 ③ file-cap launcher 形态（`supervise-identity-handoff.md`：
`setcap cap_setuid,cap_setgid+eip` 的 ~50 行 launcher 降权后 exec supervise）
进程 euid 非 0 但持 `CAP_SETUID/SETGID/CHOWN`——若出现，会绕过 gate 并在
non-root euid 下重现 root 式错位中介（SL-1 同类）。

目标：把“能否把沙箱 remap 到其它 host uid（特权跨 uid 中介）”的判定从
`euid == 0` 升级为 **capability-aware**：凡进程实际持有可执行跨 uid remap
的特权（effective caps 含 SETUID/SETGID，或等价可探测能力），即使 euid
非 0，也按 C 档 fail-closed 拒绝（除非走 B 档 supervise 交接——supervise
二进制本身无 remap/无 setuid 代码）。

## 2. 设计点（先出设计，随实现确认）

- 判定函数：探测 effective capability（`capget` 或等价），不依赖 euid；
  明确 ambient/inheritable/permitted 与 effective 的关系（以 effective 为准）；
- gate 位置：与现 C 档拒绝同一前置点（builder / instance launch 的
  mediation/remap 决策），确保 one-shot 与 instance 两路径同 gate；
- 消息与 stats：拒绝原因区分“euid==0”与“non-root effective caps”两种文本
  （便于部署排障），仍走同一 `NotifAction`/错误路径；
- route-B ③ 兼容：launcher 在 exec supervise **之前**完成降权并清除 caps
  （文档已要求）；若 launcher 形态需在持有 caps 期间调用 fork API（不应），
  另行评估——supervise 路径不经过本 gate（它不带 remap）。

## 3. 验收（RED 先行）

- [ ] RED：构造“euid≠0 但 effective caps 含 CAP_SETUID/SETGID”的调用方，
  尝试建特权 remap（RunAs 其它 uid）沙箱 → 当前按 euid 判定会放行/或行为
  不定（先实证），修复后必须 fail-closed 拒绝且原因明确；
- [ ] 非 root 普通（无 caps）行为不回归（B 档/自映射同 uid 仍可用）；
- [ ] root euid 原行为不回归（C 档 root 拒绝 + mediation_2uid root 档 8/8 保持；
  `mediation_run_as=supervisor` 显式档语义不因本 gate 改变）；
- [ ] 门禁：非 root 全套 + root 档按基线或登记增量；无新增 skip；
- [ ] 文档：`supervise-identity-handoff.md`（③ 形态与本 gate 的关系）、
  `sandbox-exec-security.md`（C 档判定口径）、`docs/CHANGELOG.md`、
  `docs/e2b-integration.md` §3.1 状态同步。

## 4. 风险

- Linux capability 语义与容器/Ambient 组合的贴合度（实现期用多形态夹具：
  file-cap 二进制、`capsh` 注入、Ambient 开关）验证判定不误伤；
- 判定点若在 remap 之后才拦截会留下窗口——必须前置到 remap 之前；
- 本任务不实现 launcher（部署侧），只在 fork 侧 gate + 夹具证明形态可被
  覆盖，避免“fork 假装能防住部署层”。

## 5. 提交与报告

- RED 用例提交（`test(core): refuse privileged remap under non-root effective caps (F14 red)`）；
- 实现提交 `fix(core): make privileged-remap gate capability-aware (F14)`；
- 文档收口提交。
- 报告 `tmp/sdd/f14-report.md`（RED/GREEN 日志、cap 形态矩阵、门禁数字）。
