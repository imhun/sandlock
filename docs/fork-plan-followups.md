# Open follow-ups — sandlock fork（fork-plan-2026-09 F0–F11 收口后）

> 来源：各任务评审报告与 `.superpowers/sdd/progress.md` 的 Minor/residual 汇总
> （F9 逐条处置，见 `tmp/sdd/f9-report.md` 的 closure 清单）。每条 = 来源（task/commit）、
> 描述、为什么留到收口之后。凡已在 F9 内便宜修掉的（文档级）不在此列；本地 artifact
> 级（tmp/sdd 报告笔误、日志摘录、运行证据）不在此列。

## A. 代码 / 接线类（需要小代码 + 测试）

- **F12（2026-09-06，已完成）** — ProcessIndex 一 TGID 一 entry
  （线程 tid 懒登记建模收口）。来源：F11 report concern #1 / e2b task-backlog
  row #2 残余。描述：`register_pid_if_new` 对发出被中介 syscall 的非 leader
  线程以 tid 懒登记独立 entry，一个 TGID 可多 key；F11 只在 freeze 侧归一化。
  完整修法 = 线程通知一律路由到 TGID leader entry、删除 per-tid 登记、
  逐消费点复核（freeze/记账/cwd/exit/枚举）。详细步骤、RED 用例与审计清单：
  `docs/fork-plan-2026-09-f12.md`。为什么留到 F12：建模改造需逐消费点复核，
  不能与 F11 修复同波冒险；现无已知活 bug（freeze 已归一化，记账/exec/cwd 走
  leader fallback）。**F12 已落地（fork 本地提交，见 `docs/CHANGELOG.md` /
  `docs/test-baseline.md`；报告 `tmp/sdd/f12-report.md`）**：登记归一化放在
  `register_pid_if_new`（线程通知 → leader；删除 `PIDFD_THREAD` 独立 key 路径），
  查询面（key_for/entry_for/contains/addr_space_state/cwd）对未登记 tid 做
  leader 解析；freeze TGID 归一化保留为防御。core_lib 823→827（+4 unit），
  core_integ 533 不变（F11 回归保持绿）；pidfd leader watcher 的「组退出才可读」
  语义已探针实证（`tmp/sdd/f12-pidfd-probe.log`）。

- **FUP-01 CLI `--pid-ns` 漏接线** — 来源：fork-plan §1 S1.1 行 / F6.1 review seam
  （`dd5a7e8` 时代仍无 main.rs 转发 `pb.pid_ns`；FFI/Python/profile 均已生效）。
  描述：`sandlock-cli` 从不暴露 `--pid-ns` 开关，用户会误以为 CLI 不支持该策略。
  为什么留：**既有历史缺陷**，真修 = 新增 clap arg + builder 接线 + CLI→运行时测试
  （`--mediation-run-as`/`--fs-mount` 已示范正确形态），属 F9 文档范围之外的小代码改动。
- **FUP-02 init seam 单归属决策（维持双份复挂）** — 来源：F3.1 review（`d063437`）。
  描述：init/proto/fdpass 从 oci 搬入 `core::init` 后，6 个随搬单测在 core 与 oci
  re-export seam 各跑一份（oci-root 144 精确不变是搬家证明的锚）。
  为什么留：F9 决策 = **维持**（双份防漂移，且单归属需要上游接受 core::init 独立演进
  后一次性删 oci 复挂副本并重测）；作为长期收尾项登记。**已关闭（2026-09-07，
  A/B cleanup wave）：决策维持双份复挂并登记为长期项，无代码动作；若上游接受
  core::init 独立演进再做单归属（届时 oci-root 144 是删副本后的重测锚点）。**
- **FUP-03 supervise 主退出顺序竞态** — 来源：F3.2/F3.3 review residual
  （`4411c7b`/`3d42bc7`/`3fa0b95`）。
  描述：worker 先关控制通道时主退出观察顺序可能异常（未测）；stray overflow cap
  无单测；>5 s deadline 竞态只以替身单测覆盖。
  为什么留：需要专用 exit-order harness（worker 必须先观察 Exited 才能收场的约束
  限制），超出 F9 文档范围。**2026-09-07（A/B cleanup wave）实证**：root 档
  fd-handoff 异常 EOF（无 shutdown）复测时观察到 supervise 异常退出后留下
  延迟出现的 uid-X 僵尸（state Z、ppid=1、容器无 subreaper 回收），与
  FUP-06 登记同源——异常退出路径存在 reaping/退出顺序缺口；修复需要专用
  exit-order harness，继续 open（专用 harness 任务）。
- **FUP-04 fs_mount link-EBUSY 直击 + 断言精度** — 来源：F6.2 review（`6fcb8e2`）。
  **状态：已完成（F13，2026-09-06，fork 本地提交）。**
  描述：unlink/rename-at-mount-point 已 pin，`link()` 于 rw 挂载点无直击测试；
  `fs_mount` 测试遗留一处 contains 式断言未转精确。
  为什么留：I1 保护族已覆盖写家族主体；补 link pin 与转断言属测试代码级收尾。
  处置：`tests/fs_mount.rs` 新增 `test_rw_mount_point_resists_link`（EBUSY 直击，
  宿主源完好、无新宿主文件）+ 既有 `contains` 断言转整串精确（ffi 98→100）。
- **FUP-05 目录挂载点的 rmdir 未保护（披露项）** — 来源：F6.2 review（`de2f749`/
  `6fcb8e2`；已在 e2b-integration §3.1 披露）。**状态：已完成（F13，2026-09-06，
  fork 本地提交）。**
  描述：对**目录** bind-mount 点的 rmdir 无 fork 侧保护；宿主侧真实挂载点由内核返回
   EBUSY，沙箱虚拟化形态下该语义需设计。
  为什么留：范围外披露项；需要先定虚拟化 fs 的 rmdir/卸载语义再实现。
  处置：chroot `handle_chroot_write` 对 `unlinkat(AT_REMOVEDIR)` 命中目录挂载点
  leaf 时返回 `EBUSY`（与真实 bind-mount 一致；单文件/chardev leaf 回落宿主
  ENOTDIR）；新测试 `test_directory_mount_point_rmdir_is_refused`（RED 先证
  空宿主目录可被沙箱 rmdir 删除 → GREEN EBUSY + 宿主目录保留，挂载点内普通
  目录 mkdir/rmdir 不受影响）。e2b §3.1 注记随 F13 闭环。
- **FUP-06 fd root 用例 pre_exec 只清 server_fd** — 来源：F2b.3 review
  （`3afc9dd`/`4ea63fa`）。
  描述：root 阶段 fd-handoff 用例把 worker fd 也带进 supervise，EOF 异常路径未覆盖。
  为什么留：测试侧 exec 前 fd 清场 + 逐 fd 清单断言改动，非收口必需。
  **已关闭（2026-09-07，A/B cleanup wave）**：supervise child pre_exec 只清
  server_fd（worker 端 CLOEXEC 随 exec 关闭，不再持有自己的对端掩蔽 EOF）；
  非 root EOF 用例已覆盖异常路径。root 档补异常 EOF 用例时观察到 supervise
  异常退出会留下延迟出现的 uid-X 僵尸（ppid=1、门禁环境无 subreaper 回收），
  该竞态并入 FUP-03（supervise 退出顺序/reaping）。
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
  **已关闭（2026-09-07，A/B cleanup wave，决策）**：无生产消费者需要调这些
  内部协议/生命周期旋钮（E2B 未请求端口/超时级配置），维持 constructor 默认 +
  测试 pin 的行为；若未来部署侧需要调优，从 `InstanceLifetime` /
  `InitLink::with_options` 的既有 seam 接 CLI/profile/env（届时按 F6.1
  `--mediation-run-as` 的接线纪律做端到端测试）。
- **FUP-09 egress flake 证据留存流程** — 来源：F2.1 ⚠️ / F5 gate / F8 gate
  （`8e22c5d`..`c8f76d4` 多轮观察；本 F9 终局一次即绿，未触发重试）。
  描述：`cli learn`（curl https://example.com）等外部 egress 用例与本环境偶发的
  control-dir 时序用例偶见抖动，历史做法是"重试到真实绿并留日志"，但没有脚本化的
  证据留存/重试策略（首轮红日志 vs 最终绿日志如何归档）。
  为什么留：属 runner/发布流程纪律（可选加固），非行为缺陷；F9 终局全绿无重试，
  相关观察继续记录在后续 gate 报告。
- **FUP-10 F1.7 逃逸盲区 / dead_groups 重叠建议** — 来源：F1.7 review residual
  （`4b7f7d0`/`d2bd459`）。
  描述：两步逃逸（setpgid 移组 → setsid 后 pgid==pid 伪装组内）建议 getsid 会话比较
  或注释；dead_groups 与活 child pgid 复用重叠可能双 killpg（建议遍历前先去重）。
  为什么留：加固建议需 core 改动 + 新测试；现行形态 fail-safe 且无实际触发证据。
- **FUP-11 F2b/F3 测试与日志硬化小项** — 来源：F2b.1（`3339c12`）与 F2b.3
  （`3afc9dd`）review。
  描述：error-path contains 断言收敛（建议整串/结构化）；registered slot 拒绝
  eprintln 无速率上限；`--program`+validate-exit 模式无测试；registered worker 首
  verb 30 s recv 超时与 120 s connect 重试不对称；非 root path stats settle 断言弱于
  姊妹用例；`FORBIDDEN` 常量无测试引用。
  为什么留：断言/日志/测试强度收尾，非行为缺陷；逐项改需要各自对应文件的小改动。
- **FUP-12 F1.8 call-site 错误路径与 send 失败语义** — 来源：F1.8 review（`df5d77a`）。
  描述：Start/Exec 的 Err 中继已显式化但 call-site Err 未单测；send 失败不标 Dead
  （pre-existing、文档化）。
  为什么留：e2e deadline 用例绿；send 失败无消费者影响，直测收益低。
  **已关闭（2026-09-07，A/B cleanup wave，证据）**：call-site 错误中继由
  oci supervisor 单测 `test_request_timeout_returns_error_within_deadline`
  与 `request on a Dead link must fail`（supervisor.rs:1815/1889）精确 pin
  （超时精确消息、Dead 后 fail-fast、waiter 不清除）；send 失败不标 Dead 维持
  pre-existing 文档语义（无消费者路径依赖该标记，直测收益低于文档成本）。
- **FUP-13 F5 语义观察缺口** — 来源：F5 review（`b56fcbe`..`1321ba0`）。
  描述：supervise `max_lifetime: None` 无运行时测试（24 h 不可观）；pid_ns 下 init 被
  kill（`InstanceDead`）未测；F4 dead-leader pgid entry 在组空后 linger 至 session
  结束（security-neutral、bounded）与 kill-probe 交错未 stress。
  为什么留：24 h / 极端时序不可在常规门禁内观测；linger 有界且安全中性，改需事件化
  设计（与 REAP_POLL_MS 同源）。**已关闭（2026-09-07，A/B cleanup wave）**：
  `max_lifetime: None` 由 F5.5 idle/T_max 用例矩阵覆盖（test_instance_semantics
  的 idle 用例即 None）；pid-ns init 被杀 → `InstanceDead` 新增矩阵用例
  `test_pid_ns_init_killed_lands_dead_with_unified_code`（core_integ 533→534）；
  dead-leader linger 与 kill-probe 交错的重复投送面由 FUP-10 的 pgid 去重关闭；
  24 h 寿命与极端时序仍不可常规门禁观测（非行为缺陷，文档化）。

## B. 性能 / 构建 / 发布面

- **FUP-14 REAP_POLL_MS=100 事件化** — 来源：F2b.4（`799fc8f`，capacity doc §6）。
  描述：exec 往返 ~102 ms 有 ~100 ms 轮询地板；SIGCHLD self-pipe / pidfd 就绪通知可
  降到个位数 ms。
  为什么留：性能改动需核心行为变更 + 成本/延迟复测，F2b.4 明确留给后续。
- **FUP-15 release profile `panic=abort` + `strip`** — 来源：F2b.4（`799fc8f`）/
  F2b.5（`51b64ad`）。
  描述：仓库 release profile 即 cargo 默认（panic=unwind、未 strip），release
  supervise 二进制 ≈6.3–6.9 MB/arch、FFI cdylib 亦未 strip；plan 协议写的历史
  `panic=abort+strip` 未落地。
  为什么留：profile 决策影响发布面；加上只会更小，现有预算已按实测保留余量。
- **FUP-16 wheel 管线加固** — 来源：F2b.5 review（`51b64ad`）。
  描述：verify 不校验 RECORD 行；manifest 目录取 `dirname $1` 在跨目录 verify 时会
  错配；uid 冒烟 grep 未显式含 euid；旧版 supervise 已注入时再注入会追加第二条
  RECORD 行（建议 replace-in-place）；pip 真机落 0755 未直接执行验证。
  为什么留：本次 F9 rebuild 用默认 `wheels/` 流程全绿；上述为发布管线的防御性收尾。
  **已实现（2026-09-07，A/B cleanup wave）**：build-wheels 注入改 replace-in-place
  （过滤既有 `sandlock/bin/sandlock-supervise` RECORD 行后写唯一一行，并修复
  执行位）；verify 新增 RECORD 行精确校验、同目录守卫、euid+--uid 双值 grep、
  提取 0755 权限检查。脚本 `sh -n` 通过；重建/verify 证据随最终 tip wheel 波。
- **FUP-17 runner 硬化（可选）** — 来源：F0.1 review。
  描述：`scripts/test-all.sh` 无参模式不拒 root（对称守卫可选）；root 与 uid 65534
  共享增量缓存有脏缓存隐患（建议 root 档 `CARGO_INCREMENTAL=0` 或独立 target）。
  为什么留：规范入口已由容器 entrypoint 控 uid；守卫属可选加固，不改测试数。
- **FUP-18 容量表 §4.1 区间/采样标注精度** — 来源：F2b.4 review（`799fc8f`）。
  描述：§4.1 的跨轮区间上界略低估、中位数采样标注不精确；预算余量仍 ≥28–37%。
  为什么留：需回放原始逐轮采样才可精确化；预算有效性不受影响。

## C. 架构 seam / 设计候补

- **FUP-19 per-child 正向 fs/bind 收窄不可内核强制** — 来源：F4 review
  （`b58b634`..`e5c7214`）。
  描述：exec child 从共享 Landlock 域 fork，ceiling 内 grant 是实例级的；要做"child A
  可写 X、child B 不可"的**强制**边界，须像 connect/send 那样按 pgid 中介 open/bind。
  为什么留：设计级；per-exec params 已携带记录，未来层可直接消费。
- **FUP-20 credential/HTTP-ACL per-child 归因** — 来源：F4 review（同 FUP-19）。
  描述：代理连接无 child 归因；同 IP 不同凭据的兄弟规则需要把 pid 穿进 proxy hand-off。
  为什么留：destination 级泄漏已被 connect verdict 关闭；凭据级归因属下一设计层。
- **FUP-21 port-aware `update_network` payload** — 来源：F4 review。
  描述：IP-any-port 是当前可表达单位；端口级 ceiling 不能被 IP-any-port update 收窄
  （拒绝而非静默放宽）。E2B 若需端口级收窄要加 port-aware payload。
  为什么留：需要扩展 wire/verdict 结构 + 测试；E2B 尚未要求。
- **FUP-22 non-root-but-CAP_SETUID launcher 形态** — 来源：F6.1 concern
  （`b62e201`）。**状态：已完成（F14，2026-09-06，fork 本地提交；route-B ③
  部署前必须完成的 gate 已就位）。**
  描述：C 档 gate 只按 `euid==0` 触发；file-cap launcher（cap_setuid/cap_setgid ③）
   若出现，同类错位可绕过该 gate。
  为什么留：fork 不装特权组件；launcher 由部署侧提供，需在部署面评估（route-B 契约
  文档已列 ③ 为可选形态）。
  处置：`privileged_userns` 与 C 档 gate 改为 capability-aware——euid 非 0 但
  effective caps 含 `CAP_SETUID/CAP_SETGID`（`/proc/self/status` CapEff 探测）也
  按特权跨 uid remap 分类，默认 `caller` 档在建箱前以点名能力的新错误 fail-closed
  （不再落到暗示无 caps 的晚拒）；无 caps 非 root / 同 uid 自映射 / route-B
  supervise 不受影响。RED 夹具 = `setcap cap_setuid,cap_setgid+eip` + `setpriv`
  euid 65533 真执行（mediation_2uid 9/9）。

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

## 已处置（F9–F14 内完成，追溯用）

- **F14（2026-09-06，本地提交）**：capability-aware 特权 remap gate（FUP-22 /
  route-B ③ 前置）——`privileged_userns` 分类与 C 档 gate 从 `euid==0` 升级为
  effective caps 探测（`CapEff` 含 `CAP_SETUID|CAP_SETGID` 即特权跨 uid remap）；
  默认 `caller` 档对 euid 非 0 + caps 的调用方（file-cap launcher 形态）以点名
  能力的新消息建箱前拒绝，不再落到暗示无 caps 的「unprivileged supervisor cannot
  map」晚拒；root euid 行为/消息不变，无 caps 非 root、同 uid 自映射、route-B
  supervise 不受影响。RED→GREEN：mediation_2uid 新夹具
  `test_nonroot_file_cap_launcher_is_refused_like_c_tier`（setcap eip +
  setpriv 65533 真执行，8→9）；core_lib +1 纯决策单测（827→828）。报告
  `tmp/sdd/f14-report.md`；门禁与文档同步见 CHANGELOG / e2b-integration §5 /
  supervise-identity-handoff / sandbox-exec-security / test-baseline。
- **F13（2026-09-06，本地提交）**：fs 写家族挂载保护收尾——FUP-04（`link()` 于
  rw 单节点挂载点 EBUSY 直击 pin + fs_mount 遗留 contains 断言转整串，ffi 98→100）
  与 FUP-05（目录挂载点 rmdir：chroot dispatch 对 `unlinkat(AT_REMOVEDIR)` 命中
  目录 mount leaf 返回 EBUSY，宿主目录不再可被沙箱视图 rmdir 删除；单文件/chardev
  leaf 回落宿主 ENOTDIR；挂载点内普通目录不受影响）。RED 证据
  `tmp/sdd/f13-red-rmdir.log`；门禁与文档同步见 CHANGELOG / e2b-integration
  §3.1/§5 / test-baseline；报告 `tmp/sdd/f13-report.md`。
- **F12（2026-09-06，本地提交 `68e7e84`）**：ProcessIndex 一 TGID 一 entry 建模
  收口——`register_pid_if_new` 对线程通知一律路由/注册到 TGID leader（删除
  `PIDFD_THREAD` 独立 tid key 路径），`ProcessIndex` key 集合 = TGID 集合；
  `key_for`/`entry_for`/`contains`/`addr_space_state`/cwd 对未登记 tid 做
  leader 解析（一次 `/proc` 读仅 miss 时），`entry_for_cleanup`/GC 保持按精确
  key；freeze TGID 归一化保留为防御（F11 回归不变）。RED→GREEN：4 个新单测
  （唯一性/leader 已跟踪不加 key/生命周期清理/leader entry 解析）+ 1 个既有
  cwd 用例语义更新；core_lib 823→827、core_integ 533 不变；pidfd leader
  watcher 的组退出语义由 C 探针实证（`tmp/sdd/f12-pidfd-probe.{c,log}`）。
  报告 `tmp/sdd/f12-report.md`；E2B 侧复跑完成（2026-09-07，wheel = 4d5f385：
  thread/gateway 探针 + full gate A/B/macOS 全绿，见 e2b-integration §5
  F12–F14 E2B 复跑行）。F11 报告 concern #1 / task-backlog row #2 残余随之
  关闭（F12 计划与报告）。
- **F11（2026-09-06，本地提交）**：argv-safety exec freeze × 多线程进程树
  （E2B M4 FUP-E3 网关+命令变体的 fork 侧阻塞）。根因：`ProcessIndex` 为发过
  被中介 syscall 的线程以 tid 为 key 懒登记（与 leader 同 TGID），exec 冻结把
  index keys 逐个当独立 TGID 走 `/proc/<tgid>/task` ⇒ 同一线程组枚举两次，
  第二次 `PTRACE_SEIZE` 命中已冻结 TID ⇒ EPERM ⇒ 后续 exec 全拒（exit 127）。
  修法：`freeze.rs` 冻结前把 keys 归一化为唯一 TGID，每线程组只冻结一次；
  TOCTOU 不变量与线程/进程语义不变（线程不做 birth-track、不计数——不需要，
  冻结本就按 `/proc/<tgid>/task` 发现全部线程）。验收：core_lib 822→823
  （`freeze_deduplicates_thread_group_keys`）、core_integ 532→533
  （`test_instance_exec_after_threaded_peer_succeeds`）；E2B 真栈探针
  （`e2b-sandlock-test:latest` + `tmp/fup3_thread_probe.py`）RED
  `PTRACE_SEIZE tid N: Operation not permitted` → GREEN `exit 0`；
  报告 `tmp/sdd/f11-report.md`。E2B 侧 FUP-E3 网关+命令变体待控制器重建
  wheel 后复跑。
- **F10（2026-09-06，本地提交）**：supervisor × chroot × 特权 RunAs 的
  create/launch 回归（E2B M4 每沙箱 uid 形态）——`confine_child` 对特权 remap
  形态把真实 chdir + NO_NEW_PRIVS + Landlock 前置到 userns remap 之前，root
  0700 镜像缓存不再令 create/exec EACCES；非 remap / netns 自映射 / pid-ns
  形态顺序不变；默认 `caller` C 档 fail-closed 不变。验收：root 档
  `mediation_2uid` 5→8、非 root 档 `core_integ` 531→532（新
  `test_instance_chroot.rs`）；报告 `tmp/sdd/f10-report.md`。E2B 侧待 wheel
  重建后复跑探针（§3.1 F10 段）。
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
