# F6 阶段执行计划 — 文件身份（SL-1/P1/P2）与 fs_mount（P5）（fork-plan-2026-09 §F6）

Branch: `upstream-pr/netns-free-clean`（本地，不推送）。进度：`.superpowers/sdd/progress.md`。顺序：F6.1 → F6.2（F7/F8 随后）。

## F6.1（SL-1，plan 已给步骤级，读 §F6.1 全文）
- 形态事实：中介跑在持有实例的进程内 ⇒ 中介身份 = 该进程 euid；B 档下天然正确，SL-1 三个症状不存在 ⇒ 本任务 = "断言 + 拒绝" + B 档跨 uid 硬证据。
- A 档（同 uid 行为正确）+ B 档 `test_two_supervisors_distinct_uids_isolate_files`（uid X/Y 各自 supervise 写同一 1777+sticky 共享目录：Y 不可删 X 文件 EPERM、Y chmod X 文件 EPERM、X 自己 chmod 生效）+ C 档 fail-closed（root in-process mediation 拒绝；`mediation_run_as=supervisor` 显式档建箱成功但 WARN + stats 计数；对照组 caps-kept-would-leak）。
- `mediation_run_as`（caller 默认 / supervisor 显式）贯穿 builder+Policy+FFI+cbindgen+CLI `--mediation-run-as`+Python，CLI 真接线。
- runner `--mediation-2uid`（有第二 uid 跑 B 档；没有 → 打印缺档并使 baseline 对账失败，禁伪装 skip）；baseline 分档登记。
- chroot/COW 各补断言；F6.2 minimal_dev 落地后 chroot 用例不下发 fs_denied 也过。
- 提交 + e2b-integration §3.1/§2 状态更新。

## F6.2（P5）：fs_mount 单节点 + minimal /dev（plan §F6.2）
- bind-mount 文件/chardev 节点（resolv.conf、/dev/null 等），父目录预创建与 deterministic_dirs 对齐；minimal_dev() helper（ptmx/pts/null/urandom/zero/tty）。
- ffi/python 既有测试文件补用例；CLI --fs-mount 接线；§2 P5 ✅；F6.1 chroot 用例改用它省 fs_denied。
