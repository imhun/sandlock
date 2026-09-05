# Open follow-ups — sandlock fork（fork-plan-2026-09 F0–F9 收口后）

> 来源：各任务评审报告与 `.superpowers/sdd/progress.md` 的 Minor/residual 汇总
> （F9 逐条处置，见 `tmp/sdd/f9-report.md` 的 closure 清单）。每条 = 来源（task/commit）、
> 描述、为什么留到收口之后。凡已在 F9 内便宜修掉的（文档级）不在此列；本地 artifact
> 级（tmp/sdd 报告笔误、日志摘录、运行证据）不在此列。

## A. 代码 / 接线类（需要小代码 + 测试）

- **FUP-01 CLI `--pid-ns` 漏接线** — 来源：fork-plan §1 S1.1 行 / F6.1 review seam
  （`dd5a7e8` 时代仍无 main.rs 转发 `pb.pid_ns`；FFI/Python/profile 均已生效）。
  描述：`sandlock-cli` 从不暴露 `--pid-ns` 开关，用户会误以为 CLI 不支持该策略。
  为什么留：**既有历史缺陷**，真修 = 新增 clap arg + builder 接线 + CLI→运行时测试
  （`--mediation-run-as`/`--fs-mount` 已示范正确形态），属 F9 文档范围之外的小代码改动。
- **FUP-02 init seam 单归属决策（维持双份复挂）** — 来源：F3.1 review（`d063437`）。
  描述：init/proto/fdpass 从 oci 搬入 `core::init` 后，6 个随搬单测在 core 与 oci
  re-export seam 各跑一份（oci-root 144 精确不变是搬家证明的锚）。
  为什么留：F9 决策 = **维持**（双份防漂移，且单归属需要上游接受 core::init 独立演进
  后一次性删 oci 复挂副本并重测）；作为长期收尾项登记。
- **FUP-03 supervise 主退出顺序竞态** — 来源：F3.2/F3.3 review residual
  （`4411c7b`/`3d42bc7`/`3fa0b95`）。
  描述：worker 先关控制通道时主退出观察顺序可能异常（未测）；stray overflow cap
  无单测；>5 s deadline 竞态只以替身单测覆盖。
  为什么留：需要专用 exit-order harness（worker 必须先观察 Exited 才能收场的约束
  限制），超出 F9 文档范围。
- **FUP-04 fs_mount link-EBUSY 直击 + 断言精度** — 来源：F6.2 review（`6fcb8e2`）。
  描述：unlink/rename-at-mount-point 已 pin，`link()` 于 rw 挂载点无直击测试；
  `fs_mount` 测试遗留一处 contains 式断言未转精确。
  为什么留：I1 保护族已覆盖写家族主体；补 link pin 与转断言属测试代码级收尾。
- **FUP-05 目录挂载点的 rmdir 未保护（披露项）** — 来源：F6.2 review（`de2f749`/
  `6fcb8e2`；已在 e2b-integration §3.1 披露）。
  描述：对**目录** bind-mount 点的 rmdir 无 fork 侧保护；宿主侧真实挂载点由内核返回
  EBUSY，沙箱虚拟化形态下该语义需设计。
  为什么留：范围外披露项；需要先定虚拟化 fs 的 rmdir/卸载语义再实现。
- **FUP-06 fd root 用例 pre_exec 只清 server_fd** — 来源：F2b.3 review
  （`3afc9dd`/`4ea63fa`）。
  描述：root 阶段 fd-handoff 用例把 worker fd 也带进 supervise，EOF 异常路径未覆盖。
  为什么留：测试侧 exec 前 fd 清场 + 逐 fd 清单断言改动，非收口必需。
- **FUP-07 mediation no-clobber 专属回归测试** — 来源：F6.1 review M1
  （`b62e201`/`dd5a7e8`/`75bbe0b`）。
  描述：profile 携带 `mediation_run_as=supervisor` 而 CLI flag 省略（no-clobber）路径
  未 pin；I1 谓词保守（任何 policy_fn 存在即拒 root-remap caller）已文档化但同样未
  pin 独立回归。
  为什么留：CLI/config 组合测试面缺失，需新用例。
- **FUP-08 knobs 未接生产配置** — 来源：F1.2（`c5a0fe7` early_exit_cap）、F1.8
  （`df5d77a` request deadline）、F5 review（`1321ba0` idle/T_max constructor-only）。
  描述：`early_exit_cap=1024`、`request` 默认 5 s、`T_idle`/`T_max` 目前只走
  constructor/私有 API，未接 CLI/profile。
  为什么留：配置面是产品决策；测试已 pin 默认行为，接线留部署面任务。
- **FUP-09 F1.7 逃逸盲区 / dead_groups 重叠建议** — 来源：F1.7 review residual
  （`4b7f7d0`/`d2bd459`）。
  描述：两步逃逸（setpgid 移组 → setsid 后 pgid==pid 伪装组内）建议 getsid 会话比较
  或注释；dead_groups 与活 child pgid 复用重叠可能双 killpg（建议遍历前先去重）。
  为什么留：加固建议需 core 改动 + 新测试；现行形态 fail-safe 且无实际触发证据。
- **FUP-10 F2b/F3 测试与日志硬化小项** — 来源：F2b.1（`3339c12`）与 F2b.3
  （`3afc9dd`）review。
  描述：error-path contains 断言收敛（建议整串/结构化）；registered slot 拒绝
  eprintln 无速率上限；`--program`+validate-exit 模式无测试；registered worker 首
  verb 30 s recv 超时与 120 s connect 重试不对称；非 root path stats settle 断言弱于
  姊妹用例；`FORBIDDEN` 常量无测试引用。
  为什么留：断言/日志/测试强度收尾，非行为缺陷；逐项改需要各自对应文件的小改动。
- **FUP-11 F1.8 call-site 错误路径与 send 失败语义** — 来源：F1.8 review（`df5d77a`）。
  描述：Start/Exec 的 Err 中继已显式化但 call-site Err 未单测；send 失败不标 Dead
  （pre-existing、文档化）。
  为什么留：e2e deadline 用例绿；send 失败无消费者影响，直测收益低。
- **FUP-12 F5 语义观察缺口** — 来源：F5 review（`b56fcbe`..`1321ba0`）。
  描述：supervise `max_lifetime: None` 无运行时测试（24 h 不可观）；pid_ns 下 init 被
  kill（`InstanceDead`）未测；F4 dead-leader pgid entry 在组空后 linger 至 session
  结束（security-neutral、bounded）与 kill-probe 交错未 stress。
  为什么留：24 h / 极端时序不可在常规门禁内观测；linger 有界且安全中性，改需事件化
  设计（与 REAP_POLL_MS 同源）。

## B. 性能 / 构建 / 发布面

- **FUP-13 REAP_POLL_MS=100 事件化** — 来源：F2b.4（`799fc8f`，capacity doc §6）。
  描述：exec 往返 ~102 ms 有 ~100 ms 轮询地板；SIGCHLD self-pipe / pidfd 就绪通知可
  降到个位数 ms。
  为什么留：性能改动需核心行为变更 + 成本/延迟复测，F2b.4 明确留给后续。
- **FUP-14 release profile `panic=abort` + `strip`** — 来源：F2b.4（`799fc8f`）/
  F2b.5（`51b64ad`）。
  描述：仓库 release profile 即 cargo 默认（panic=unwind、未 strip），release
  supervise 二进制 ≈6.3–6.9 MB/arch、FFI cdylib 亦未 strip；plan 协议写的历史
  `panic=abort+strip` 未落地。
  为什么留：profile 决策影响发布面；加上只会更小，现有预算已按实测保留余量。
- **FUP-15 wheel 管线加固** — 来源：F2b.5 review（`51b64ad`）。
  描述：verify 不校验 RECORD 行；manifest 目录取 `dirname $1` 在跨目录 verify 时会
  错配；uid 冒烟 grep 未显式含 euid；旧版 supervise 已注入时再注入会追加第二条
  RECORD 行（建议 replace-in-place）；pip 真机落 0755 未直接执行验证。
  为什么留：本次 F9 rebuild 用默认 `wheels/` 流程全绿；上述为发布管线的防御性收尾。
- **FUP-16 runner 硬化（可选）** — 来源：F0.1 review。
  描述：`scripts/test-all.sh` 无参模式不拒 root（对称守卫可选）；root 与 uid 65534
  共享增量缓存有脏缓存隐患（建议 root 档 `CARGO_INCREMENTAL=0` 或独立 target）。
  为什么留：规范入口已由容器 entrypoint 控 uid；守卫属可选加固，不改测试数。
- **FUP-17 容量表 §4.1 区间/采样标注精度** — 来源：F2b.4 review（`799fc8f`）。
  描述：§4.1 的跨轮区间上界略低估、中位数采样标注不精确；预算余量仍 ≥28–37%。
  为什么留：需回放原始逐轮采样才可精确化；预算有效性不受影响。

## C. 架构 seam / 设计候补

- **FUP-18 per-child 正向 fs/bind 收窄不可内核强制** — 来源：F4 review
  （`b58b634`..`e5c7214`）。
  描述：exec child 从共享 Landlock 域 fork，ceiling 内 grant 是实例级的；要做"child A
  可写 X、child B 不可"的**强制**边界，须像 connect/send 那样按 pgid 中介 open/bind。
  为什么留：设计级；per-exec params 已携带记录，未来层可直接消费。
- **FUP-19 credential/HTTP-ACL per-child 归因** — 来源：F4 review（同 FUP-18）。
  描述：代理连接无 child 归因；同 IP 不同凭据的兄弟规则需要把 pid 穿进 proxy hand-off。
  为什么留：destination 级泄漏已被 connect verdict 关闭；凭据级归因属下一设计层。
- **FUP-20 port-aware `update_network` payload** — 来源：F4 review。
  描述：IP-any-port 是当前可表达单位；端口级 ceiling 不能被 IP-any-port update 收窄
  （拒绝而非静默放宽）。E2B 若需端口级收窄要加 port-aware payload。
  为什么留：需要扩展 wire/verdict 结构 + 测试；E2B 尚未要求。
- **FUP-21 non-root-but-CAP_SETUID launcher 形态** — 来源：F6.1 concern
  （`b62e201`）。
  描述：C 档 gate 只按 `euid==0` 触发；file-cap launcher（cap_setuid/cap_setgid ③）
  若出现，同类错位可绕过该 gate。
  为什么留：fork 不装特权组件；launcher 由部署侧提供，需在部署面评估（route-B 契约
  文档已列 ③ 为可选形态）。

## E. E2B 侧 / 仓库外（fork 无权执行，登记以不丢）

- **FUP-E1 P4/T4 E2B 复测** — 来源：F7（`4e78c98`/`7183884`）；`docs/e2b-integration.md`
  §3.3。
  描述：以 `E2B_BASE_IMAGE` + `xfail(run=True)` 复测
  `test_mcp_full_path_under_net_isolation`；仍失败则在 worker 栈抓 gateway stderr /
  宿主映射端口快照。
- **FUP-E2 E2B §8 M4 接线** — 来源：fork-plan §F9 / e2b-integration §8。
  描述：SandlockExecutor 持实例、`_CommandGate` 保留、控制目录名用 sandbox_id+token、
  超卖探针改断言、SCALING 账本项照改、`max_processes` 显式配、minimal_dev 替换整树
  /dev 与 carve-out。
- **FUP-E3 E2B 复验 §3.8 超卖消除** — M4 落地后按 e2b-integration §3.8 探针重测
  （gateway + 并发命令同实例）。

## 已处置（F9 内完成，追溯用）

- 文档级修正（F9 commit，见 `tmp/sdd/f9-report.md`）：plan/f2b 的 "≤8MB" 残留引用；
  fork-plan §1 套件表基线刷新；§2 矩阵 F1.1 行幻影 oci 用例归属订正；e2b §0/§1/§2/
  §3.1/3.3/3.8/3.9/§3.10/§5/§8 终审；sandbox-exec-security §4/§7 修复 commit 标注；
  phase plan f1–f7 complete 标注；upstream-pr-netns-free PR 范围补记；CHANGELOG；
  test-baseline 终局日期/注释刷新；supervise-identity-handoff §9 发布纪律补句。
- 登记的最小注释修正（无行为/ABI 变化）：`control.rs` 模块头与
  `setup_runtime_dir_no_socket` doc 的 create 期 pid-less 可回收表述（实际已无条件
  拒绝），与 `classify_existing_dir` 语义对齐。
- 已由后续任务自然关闭的 Minor（示例）：F2.1 B-2/B-3/B-5/B-7 → F2.2；F2b.2 全部
  residual → F2b.3；F1.4 drift 语义文档 → F2.3；F2b.1 egress_proxy 近同义断言 →
  F2b.2 read-back 强化；.DS_Store → `13736db`；F1.5/F1.6 非 Linux 软 skip 计数 → Linux
  门禁不适用（记录）。
- 本地 artifact 级（不登记）：报告数字/句子笔误、RED 证据摘录、日志 commit hash 头、
  运行证据留存文件等（评审记录已有出处）。
