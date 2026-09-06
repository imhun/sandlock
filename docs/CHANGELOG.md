# CHANGELOG — sandlock fork（fork-plan-2026-09，F0–F10）

> 范围：`upstream-pr/netns-free-clean`（本地提交，未推送）。本文件以 release-note 语义
> 汇总 fork-plan F0–F10（2026-09-04/06）的特性、修复与**用户可见行为变化**；每条可追溯到
> commit（短 hash 见正文，完整链 `git log dab4087..HEAD` 与任务报告 `tmp/sdd/f*-report.md`）。
> 每套件实测基线见 `docs/test-baseline.md`；跨任务遗留见 `docs/fork-plan-followups.md`；
> E2B 集成状态见 `docs/e2b-integration.md`。

## 行为变化（升级 / 接线前必读）

- **`mediation_run_as=supervisor` × chroot × 特权 RunAs 的 create/launch 回归修复**
  （F10，本地提交）：E2B M4 每沙箱 uid 形态下（root holder 把沙箱 remap 到非零
  host uid、rootfs 缓存放 root 0700 目录），`Sandbox.run`/exec-only
  `SandboxInstance` 在 create/launch 阶段以
  `read notif fd from child: pipe closed` 失败——根因是 confined child 在 userns
  remap 把身份降到沙箱 host uid **之后**才做真实 `chdir` 与 Landlock 规则路径探测，
  无法穿越只对 holder 开放的镜像缓存目录（chdir EACCES → 建箱失败；Landlock 规则全
  被跳过 → 空 ruleset 在 exec 期 deny-all）。修法：仅对特权 remap 形态，把
  chdir + NO_NEW_PRIVS + Landlock 前置到 remap 之前（Landlock 层跨 userns 迁移
  只增不减，不削弱限制）；非 remap / netns 自映射 / pid-ns 形态保持原顺序。
  默认 `caller` + root + RunAs(≠holder) + 路径中介的 C 档 fail-closed **不变**。
- **`max_processes` 语义从"每命令 64"改为"整箱/实例上限"，默认 256**（F5.1，commit
  `b56fcbe`）。单实例整棵进程树共享一份配额；fork 超限在沙箱内被拒。exec 会话的
  fork-slot 由权威 pidfd 路径归还（顺带修复 argv-safety 冻结/线程迁移 hang，
  `e5c049c`）。E2B 若按沙箱显式配 `max_processes`，语义变为全沙箱聚合。
- **多 child 时 `checkpoint()` 显式拒绝**（`CheckpointMultipleChildren`，F5.2，
  `a5c7f3b`）；单 child legacy 捕获不变，单死 child ⇒ `CheckpointNoLiveChild`。
- **统一 Dead 语义**（F5.4 `d67a363` + F1.8 `df5d77a`）：listener/reaper/请求通道
  失败后实例进入 `InstanceDead`/`InstancePhase::Dead`，后续 exec/wait/kill 等一律返回
  同一错误（FFI code 6 `SANDLOCK_INSTANCE_ERR_DEAD`，Python 同名错误），不静默重启。
- **路径中介身份绑定 + `mediation_run_as`**（F6.1，`b62e201`/`dd5a7e8`/`7f81314`/
  `75bbe0b`）：默认 `caller` 下，root 进程内把沙箱 remap 到非零 host uid 且启用路径
  中介 ⇒ **建箱前拒绝**（错误点名改用 route-B supervise 或显式 `supervisor` 档）；
  显式 `supervisor` 档 WARN + `stats().mediation_downgrades` 计数，对照组证明该档真实
  降级。非 root（生产形态）无感知。
- **实例生命周期与空闲回收**（F5.5，`8e22c5d`）：child 表空且无 `wait_child` 订阅者
  持续 `T_idle`（默认 15 min）⇒ Draining→shutdown；`T_max`（默认 24 h）强制收尾；
  幂等。supervise/部署侧若曾依赖"进程随沙箱命令退出"，现需显式 shutdown/idle。
- **`fs_mount` 单节点与挂载点保护**（F6.2，`de2f749`/`6fcb8e2`）：单文件/chardev
  挂载不再 `ENOTDIR`；对挂载点的 unlink/rename/link 写家族返回 `EBUSY`（防 nofollow
  写家族直取宿主源）；源缺失的 leaf 不再回退 rootfs 同名对象（更贴近 bind-mount
  语义，可观察行为收紧）。
- **控制目录迁移 + 鉴权**（F1.3，`95608be`/`ceaa069`）：控制根从 `/dev/shm` 迁到
  `/tmp/sandlock-ctl-$UID`，目录名 FNV-1a 哈希；`SO_PEERCRED` 不匹配即断开；敏感
  verb 需身份 token；同名冲突**拒绝而非抢占**（依赖明文目录名的运维脚本需迁移）。
- **init 控制协议显式分帧**（F1.6，`0f51fce`）：带 magic/version/type/长度上限；
  既有合法客户端协议不变，畸形/截断帧被拒且不泄漏 fd。
- **per-exec 参数只能收窄**（F4，`b58b634`/`c5d1108` 等）：exec 的
  `cwd/env/extra_writable/bind_ports` 越出实例创建时定死的上限 ⇒ `EPERM`/
  `PolicyTooWide`；`update_network` 只对**新** exec 生效，在跑 child 保原策略，API
  回报 stale child id。
- **`pid_ns` + 实例并存**（F5.3，`2c016bd`）：开 `pid_ns` 后 on-behalf `/proc` 按
  `PidKey` 收窄到本 child 子树；ns PID 1 退出不静默带走整树（实例级 reaper 语义，
  见 `docs/e2b-integration.md` §3.9/§7.4 S4 解释）。
- **route-B supervise 单代次**（F2b，`3339c12`..`3afc9dd`）：一个 `sandlock-supervise`
  进程服务一个沙箱，euid == 沙箱 host uid；运行期禁止把中介 remap 成别的 host uid；
  shutdown 清场后 exit(0)。C 档（root 进程内 RunAs + 中介）默认被拒（见上）。

## 新能力

- **每沙箱显式实例 M0–M3**：`SandboxInstance` 生命周期（F2，`57f543c`..`2cb1d99`）；
  per-child `exec`/`wait_child`/`kill_child`/`resize_child` + SCM_RIGHTS stdio
  （F3，`d063437`/`4411c7b`/`3d42bc7`/`3fa0b95`）；per-exec 参数 + S9（F4）；语义/
  兜底（F5）。旧 `Sandbox.run/popen/spawn` 保持"一次性实例"语义与 ABI 不变。
- **`sandlock-supervise` 交付物**（F2b.5，`51b64ad`）：wheel 内
  `sandlock/bin/sandlock-supervise`（pip 落 0755）+ 独立
  `wheels/supervise/{x86_64,aarch64}/` + HEAD 钉住的 `SHA256SUMS.supervise`；
  verify 做 FFI 符号双向相等 + 指纹三方一致 + `--uid` 错 uid 拒绝冒烟。
- **`minimal_dev()` / 单节点挂载 helper**（F6.2，`de2f749`）：core 与 Python 都提供
  `ptmx/pts/null/urandom/zero/tty` 六节点 `/dev` 构造，chroot 形态不再需要整树挂
  `/dev` 或为 `/dev/shm` 下发 carve-out（SL-1 最大触发面消除）。
- **supervise 成本量化与容量表**（F2b.4，`799fc8f`）：release 实测
  （空载 ≈4.2–4.5 MB、每 slot 边际 ≈0.5 MB、1000 轮 exit frames 零丢失）；
  `docs/supervise-capacity.md` 给 N_max 公式与账本项。
- **F0 验证基座**：`scripts/test-all.sh` 一键全量 + 精确基线比对（`27a0150`）；
  wheel 构建/verify 收进 fork（`5fa6f72`）；root 档 oci/supervise_root/mediation_2uid
  与 release supervise_cost 分档（各 commit 见 test-baseline）。

## 安全修复（M0′：SL-4/5/6/7/8 + 进程组/上限/deadline）

- SL-4 控制 fd 泄漏（F1.1 `3d804b1`）；H1/H2 early_exits 上限 + 登记校验（F1.2
  `c5a0fe7`）；SL-7 控制面鉴权 + 目录身份（F1.3 `95608be`/`ceaa069` + F2b.2 双传输
  `990ae5b`..`06c6878`）；SL-8 proc_count pidfd 权威归还（F1.4 `f0b3d78`）；
  SL-6 init subreaper（F1.5 `793aaf3`/`e85d031`）；SECE-6 per-child 进程组 + 定向
  信号（F1.7 `4b7f7d0`/`d2bd459`）；InitLink 每请求 deadline（F1.8 `df5d77a`）；
  SL-5 fd 关闭 + 显式分帧（F1.6 `0f51fce`）。详细归属见
  `docs/sandbox-exec-security.md` §4/§7。

## FFI / ABI（本计划全部为增量，不破坏既有符号）

新增导出（`dab4087` → F9 tip，cbindgen 头同步重生成）：

```text
sandlock_sandbox_builder_mediation_run_as          # F6.1
sandlock_instance_launch                            # F3.3
sandlock_instance_exec                              # F3.3
sandlock_instance_exec_params                       # F4
sandlock_instance_update_network                    # F4
sandlock_instance_wait_child                        # F3.3
sandlock_instance_kill_child                        # F3.3
sandlock_instance_resize_child                      # F3.3
sandlock_instance_free                              # F3.3
```

- 新增错误码 `SANDLOCK_INSTANCE_ERR_DEAD`（= 6，头文件宏，F5.4 `d67a363`）。
- `sandlock.h` 重生成顺带修复既有声明漂移（补 `notify_rate_limit` builder 声明）。
- wheel 符号集双向相等（缺/多即红）是 verify 硬门（F0.2/F2b.5；F9 已在最终 tip
  重建 verify，见 `tmp/sdd/f9-wheel-verify.log`）。

## CLI / 配置接线

- `--net-bind-map HOST:SANDBOX`（F0.4 `502deb7`，修 cli feature 构建断）。
- `--mediation-run-as caller|supervisor`（F6.1 `dd5a7e8`，真接线 + root 档端到端）。
- `--fs-mount VIRTUAL:HOST[:ro]`（F6.2 `de2f749`，chroot 单文件/chardev 端到端）。
- `sandlock-supervise`：`--policy <fd|path> --uid X --control-fd N`、
  `--serve/--serve-path/--token/--program`（F2b.1–F2b.3）。
- 已知未接线：CLI `--pid-ns`（历史缺陷，follow-up FUP-01）。

## 测试 / 验证基座

- 全量门禁 = 非 root 档（core_lib 822 / core_integ 532 / ffi 98 / cli 98 /
  supervise 36 / supervise_cost 3 / cli_build 0 / python 454）+ root 档
  （oci 144 / supervise_root 2 / mediation_2uid 8）+ `--wheels`；
  数字逐 commit 登记 `docs/test-baseline.md`，脚本缺一即红、skip 即红。
- 本计划新增用例全部随阶段 commit 落盘（红→绿证据在 `tmp/sdd/f*-red*.log`，
  终局全绿 `tmp/sdd/f9-gate-*.log`）。

## 明确取舍 / 已知限制（不是缺陷修复）

- P6 getsockname/getpeername 合成视图与 fd-inject `EINPROGRESS`：设计取舍 +
  回归 pin（F8 `c8f76d4`，`docs/e2b-integration.md` §3.10）。
- P4（T4）chroot+net_isolation 入站：fork 侧前提证伪 + 回归 pin（F7 `4e78c98`），
  E2B 复测为 out-of-fork follow-up。
- 其余跨任务 Minor / follow-up 汇总：`docs/fork-plan-followups.md`。
