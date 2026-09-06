# E2B × sandlock：修改方案与未解决问题（集成事实源）

> EN: single source of truth for everything E2B (the `sandlock-e2b` runtime) has changed in,
> asks of, or is blocked by this fork. Maintained from the E2B side; keep in sync with
> `sandlock-e2b/docs/HANDOFF.md`, which now only points here.
>
> 维护方：E2B（`sandlock-e2b`）。本文是该 fork 的**已做改动 / 待做方案 / 未解决问题**的唯一事实源。
> 最后更新：2026-09-06（fork-plan F0–F9 于 2026-09-05 收口；F10 于 2026-09-06
> 修复 supervisor × chroot × 特权 RunAs 的 create/launch 回归，本文 §0/§2/§3.1/§5 已更新）

## 0. 基线与硬约束

| 项 | 现状 |
|---|---|
| 运行时基线分支 | `upstream-pr/netns-free-clean`（无 per-sandbox netns/veth，全程无 root 也能跑） |
| 参考分支 | `feature/network-socks5`（含 netns 的旧主线，仅参考，不再出 wheel）、`feature/network-inject` |
| wheel | `cp314` × `x86_64`/`aarch64`，`0.9.0b0 manylinux_2_34`；fork 自持 `python/build-wheels.sh`（zig + auditwheel 双架构单 builder，glibc pin 2.34）—— 产物与 tip 一致性由 fork 侧符号级自证 + supervise 指纹（§3.4，F9 已在最终 tip 重建） |
| 上游 PR | 分支已整理好但**未推送**：`sandlock-e2b` 侧 `GITHUB_TOKEN` 只读（push/写 API 403），且该机无 `gh` CLI |
| 原则 | 沙箱全程非 root（uid/gid 由 `RunAs` 决定）、无 root supervisor 也要可用；`E2B_ENABLE_NETNS` 仅作兼容保留 |
| 发布前 | 重跑 wheel 构建 + 重建 worker/测试镜像（wheel 与 tip 的一致性只能靠重跑自证） |

历史全绿基线（fork 自带三套，Linux 容器内非 root）：lib `788`、integration `465`、python `430`
（2026-09-03 计划期数字，**已被 F0.1 起的逐套实测替代**——当前全量数字按套件/档位登记在
`docs/test-baseline.md`，F9 终局复验：core_lib 822 / core_integ 531 / ffi 98 / cli 98 /
supervise 36 / supervise_cost 3 / cli_build 0 / python 454，root 档 oci 144 /
supervise_root 2 / mediation_2uid 5，见 §5）。F10（2026-09-06）：core_integ 532、
mediation_2uid 8（见 §3.1 与 §5 的 F10 行）。

## 1. 已落地的修改方案（fork 侧）

| # | 能力 | 落点 | 状态 / 验证 | 已知限制 |
|---|---|---|---|---|
| R1 | 通配域名解析 `NetTarget::HostWildcard`（deny 时拒绝域名） | network ACL 层 | ✅ | — |
| R2 | 合成地址 `SyntheticDns`（`10.250.0.0/16`，LRU 4096） | 同上 | ✅ | — |
| R3/R4 | connect/send 连接判定 + SSRF 护栏 | connect & send 路径 | ✅ | 护栏放行段可配（本环境 DNS 被改写为 `198.18.x`） |
| 默认无特权路径 | 每沙箱 loopback DNS 网关（`127.0.0.x:53`）+ `resolv.conf` memfd + connect/send 豁免 + netlink 合成视图（虚拟 eth0 `192.0.2.1/24`、`2001:db8::1/64`） | network / procfs | ✅ 全绿 | 出站已连接 socket 的 getsockname/getpeername 显示宿主地址；fd-inject 形态非阻塞 connect 无 `EINPROGRESS` —— 均为**设计取舍**（F8 闭环，见 §3.10） |
| R8–R11 | credential injection（`http_inject`，FFI `credential`/`http_auth`）、`host_mask`（只改 wire `Host`）、HTTP matcher 支持 `*.suffix`、HTTPS MITM 复用同一 handler | transparent_proxy + FFI + Python + CLI | ✅ | **同一 matcher 多 header 注入**曾 first-match-wins，已去 `break` 改为全量应用（同 header 后者覆盖，AddOnly 不变） |
| R12–R14 | SOCKS5 on-behalf 出口（`egress_proxy`）替代 LD_PRELOAD：RFC1928/1929、poll 驱动、10s 超时、fail closed、ATYP=domain/IPv4/IPv6；代理端点由 supervisor 代拨且**不进** `net_allow` | `network/egress.rs` | ✅ 7 单测 + 3 hermetic 集成 | — |
| S1.1 | PID namespace（`pid_ns`，`CLONE_NEWPID` 两级 fork；procfs 按 ns pid 重编号；on-behalf `/proc` 只读白名单；freeze/thaw/checkpoint/throttle/tty/stat 全覆盖） | `pid_ns` 开关，默认 false | ✅ lib/integration | CLI `--pid-ns` 早期未接运行时 builder，已随 S3 收尾 |
| S1.2 | 单 entry userns + `RunAs` 任意 host uid（root supervisor 下不同沙箱不同 host uid ⇒ 同路径文件/unix socket 内核级隔离） | `RunAs` | ✅ 机制可用 | **非 root supervisor 无法映射任意 host uid**（fail-closed 拒绝）→ E2B 侧降级为"固定 uid + Landlock" |
| S2.1–S2.5 | connect fd 注入（`fd_inject_connect`；CPython 兼容修正：**注入的 connect 必须返回 0**）、UDP（connected 注入 / datagram on-behalf 单向代发）、入站端口映射 `port_mappings`（Python 侧经 `_b_net_bind_map`）、`net_isolation` 下 listen 的 poll/epoll 可读性合成（E7.1） | FFI/Python/runtime | ✅ | `port_mappings` 无同名 FFI setter，是 `net_bind_map` 的封装（**不是缺口**） |
| E7 前置 | 运行时基线移除 per-sandbox netns/veth（`network/netns.rs`、test_netns、`netns` flag/FFI/Python 全删），通配走无特权共享路径 | — | ✅ | netns 集成测试仅存于 `feature/network-socks5` |
| M6 | cp314 双架构 wheel + 私有 index 安装；fork build.rs 加 `-mcmodel=large`（manylinux gcc-toolset-14 下 restore-stub 32 位绝对重定位溢出） | 构建 | ✅ | cp310 / 3.12–3.13 未做 |
| 测试 | 非 root 测试入口 `b6ef050`（`Dockerfile.test-runner` 里 `/usr/bin/python3 → /usr/local/bin/python3` 之类由 E2B 侧镜像负责） | python 测试 | ✅ 430 passed | — |
| M0 每沙箱一实例（fork-plan F2） | `SandboxInstance` 持 ResourceState / notif / 控制目录+token / DNS 网关；`Sandbox::run/popen/spawn` 走一次性实例（外部语义与 ABI 不变）；`shutdown()` 七步固定顺序且幂等；stats 露出 `proc_count_vs_live`/`children_live`/`instance_state` | `instance.rs`（F2.1–F2.3） | ✅ commit `57f543c`..`2cb1d99`（core_integ 477→488；全门绿） | §8 M4（E2B 接线）已由 E2B Task 1–11 于 2026-09-06 收口（见 §8 与 §7.6） |
| M1 `exec` 下沉 + child 句柄（fork-plan F3） | init/proto/fdpass 从 `sandlock-oci` 原样搬入 `core::init`（oci 走 re-export seam，oci-root 144 精确不变）；per-child `exec/wait_child/kill_child/resize_child` + SCM_RIGHTS stdio；FFI `sandlock_instance_*`（launch/exec/wait/kill/resize/free，F4 再加 exec_params/update_network，cbindgen 同步）；Python `SandboxInstance.exec() -> ExecProcess` | core::init + supervise 双传输 + FFI/Python | ✅ commit `d063437`、`4411c7b`、`3d42bc7` + fix `3fa0b95` | supervise 主退出顺序竞态等见 `docs/fork-plan-followups.md` |
| M2 per-exec 参数 + 子集校验（fork-plan F4） | per-exec `cwd/env/extra_writable/bind_ports`（execve 前 chdir/envp）；S9 单 choke point（越出实例上限 ⇒ EPERM/`PolicyTooWide`）；`update_network` 只绑新 exec + staleness 回报；per-child 网络按 pid 血缘、未归因 fail-closed | `exec_params.rs` + network 按 pgid 绑定 | ✅ commit `b58b634`、`9f959f1`、`c5d1108` + fixes `902e522`/`e5c7214` | per-child 正向收窄非内核可强制等 seam 见 follow-ups |
| M3 语义/默认/兜底（fork-plan F5） | 整箱 `max_processes` 默认 **256**（Q10）；多 child `checkpoint()` 显式拒绝；`pid_ns`+实例并存（PidKey 收窄 on-behalf /proc、init reaper）；统一 `InstanceDead`（FFI code 6 / python 消息）；idle `T_idle`/`T_max` | core + FFI/Python 错误面 | ✅ commit `b56fcbe`..`1321ba0`（F5.1–F5.5 + review fix） | **用户可见行为变化**已入 CHANGELOG（默认值/拒绝/Dead/寿命） |
| SL-1/P1/P2 路径中介身份（fork-plan F6.1，F10 收口） | A 档（同 uid 属主正确）+ B 档（两 supervise 不同 uid 真内核隔离硬证据）+ C 档 fail-closed（root 进程内 remap + 路径中介 ⇒ 建箱前拒绝）；`mediation_run_as=caller|supervisor` 贯穿 builder/Policy/FFI+cbindgen/CLI/Python/supervise 全字段；F10 修复显式 supervisor 逃生门下 chroot × 特权 RunAs 的 create/launch 回归（remap 前做 chdir + Landlock） | notif/builder + 全栈 | ✅ commit `b62e201`、`dd5a7e8`、`7f81314` + fix `75bbe0b`；F10 本地提交 | `--pid-ns` CLI 旧漏线等见 follow-ups |
| P5 `fs_mount` 单节点 + `minimal_dev`（fork-plan F6.2） | 单文件/chardev bind-mount（不再 ENOTDIR、ro 保持、写家族 EBUSY 防宿主源被删/移）；`minimal_dev()`（`ptmx/pts/null/urandom/zero/tty`）免整树挂 /dev 与 `/dev/shm` carve-out | core + FFI + CLI `--fs-mount` + Python | ✅ commit `de2f749`、`dc0edf3` + fix `6fcb8e2`（ffi 98、python 454） | link-at-mount-point 直击测试、目录挂载点 rmdir 等见 follow-ups |

## 2. 待实施的修改方案（E2B 提出，需要改 fork）

| 编号 | 方案 | 优先级 | 说明 |
|---|---|---|---|
| **P1** | **SL-1 修法**：路径中介必须以**调用方身份**执行（`setfsuid/setfsgid(caller)` 包住被中介的 syscall，或 `openat(O_CREAT)` 后 `fchown` 回调用 uid）；`unlinkat/renameat2/fchmodat/fchownat` 需按**调用方**复现内核 DAC 判定（owner / sticky / `CAP_FOWNER` 相对该 inode 所在 mount 的 userns），不成立返回 EPERM | 高（多租户隔离） | **F10 终态：由 F2b 取代，仅保留 fail-closed**（route B 的 supervise 进程 euid == 沙箱 host uid ⇒ 原修法不再需要；`mediation_run_as=caller` 下 root 进程内 remap + 路径中介在 spawn 前被拒）。F6.1 commit `b62e201` + B/C 档验收 `7f81314` + fix `75bbe0b`；F10 修复 supervisor 逃生门下 chroot × 特权 RunAs 的 create/launch 回归。详见 §3.1 |
| **P2** | 提供 `mediation_run_as = caller \| supervisor` 开关，便于既有依赖 COW/chroot 语义的调用方渐进迁移 | 中 | **F10 终态：已落地**（F6.1，commit `b62e201`/`dd5a7e8`）：builder / Policy / profile / FFI+cbindgen / CLI `--mediation-run-as` / Python / supervise 全字段清单；显式 `supervisor` 档 WARN + `stats()` 计数；**F10 前该逃生门在 chroot × root-0700 缓存 × 特权 RunAs 形态仍 create/launch 失败，F10 修复后可用**（`confine_child` 前置 chdir+Landlock 到 remap 前，仅特权 remap 形态）。详见 §3.1 |
| **P3** ✅（commit `17ee48d`） | `_HANDLED_FIELDS` 登记 `notify_rate_limit`（**一行**） | 低（但污染每条日志） | **F9 终态：已修**：名字已登记入 `_HANDLED_FIELDS`，假告警消除；python 全量 454 已在 F0.1 基座 + F9 终局实测登记（`docs/test-baseline.md`） |
| **P4** ✅（F7 前提证伪 + 回归 pin，commit `4e78c98`；文档 `da9c3a7`/`7183884`） | 修 T4：`net_isolation` + chroot（镜像 rootfs）下 MCP 入站端口映射起不来 | 中（该形态是 E2B 生产形态之一） | **F9 终态：fork 侧已闭环（非代码修复）**：chroot + `net_isolation` + `net_bind_map` 三合一形态经 9 种忠实构造（HEAD 与 T4 观测时代 `be387c7`）验证可用；新增 3 条镜像测试（mcp/epoll/poll under chroot，core_integ 529）。e2b 侧 T4 有真实 image-rootfs + netns 失败记录（strict-1 实跑，2026-09-03，与 §3.3 一致）；残差可能在 envd gateway 接线层，需 e2b 侧以 `E2B_BASE_IMAGE` + `xfail(run=True)` 复测 —— **显式 out-of-fork follow-up**（见 §3.3 / `docs/fork-plan-followups.md` FUP-E1） |
| **P4** ✅（F7 前提证伪 + 回归 pin，commit `4e78c98`；文档 `da9c3a7`/`7183884`） | 修 T4：`net_isolation` + chroot（镜像 rootfs）下 MCP 入站端口映射起不来 | 中（该形态是 E2B 生产形态之一） | **F9 终态：fork 侧已闭环（非代码修复）**：chroot + `net_isolation` + `net_bind_map` 三合一形态经 9 种忠实构造（HEAD 与 T4 观测时代 `be387c7`）验证可用；新增 3 条镜像测试（mcp/epoll/poll under chroot，core_integ 529）。e2b 侧 T4 有真实 image-rootfs + netns 失败记录（strict-1 实跑，2026-09-03，与 §3.3 一致）；**FUP-E1 已关闭（2026-09-06，E2B Task 10/11）**：残差根因 = envd 基镜像组成缺 mcp-gateway（ENOENT exit 2），MCP-capable 基镜像 `python-mcp:3.14`（E2B `deploy/docker/Dockerfile.mcp-base`）下 image-rootfs + netns MCP 契约两形态全绿，E2B 侧 xfail 已摘（见 §3.3） |
| **P5** ✅（F6.2，commit `de2f749` + fix `6fcb8e2`） | `fs_mount` 目前只接受目录根（单文件/设备节点会以 `ENOTDIR` 失效）⇒ 调用方只能整树挂 `/dev`，进而**必须**下发 `fs_denied` 挡 `/dev/shm`，正好踩 SL-1。希望支持单节点挂载，或提供"最小可用 /dev（ptmx/pts/null/urandom）"构造 helper | 中（消除 SL-1 触发面） | **F9 终态：已修**：单文件/chardev 单节点 bind-mount（`resolv.conf`、`/dev/null` 形态不再 ENOTDIR，ro 保持、挂载点写家族 EBUSY）+ `minimal_dev()` helper（`ptmx/pts/null/urandom/zero/tty`），调用方可省整树 `/dev` 挂载与 `/dev/shm` carve-out；F6.1 chroot A档用例已改经 helper 构造 `/dev`（全程不下发 `fs_denied`）。详见 §3.1 |
| **P6** ✅（F8 设计取舍，commit `c8f76d4`） | 无特权默认路径的细节补齐：`getsockname/getpeername` 反映合成视图、非阻塞 `connect` 的 `EINPROGRESS` 语义 | 低 | **F9 终态：设计取舍 + 文档条目**（非代码修复）：注入连接按宿主侧视图执行（peer/local 为真实宿主端点）；fd-inject 形态的 connect 由宿主侧阻塞完成、子进程 `SO_SNDTIMEO` 为上界、不向客户端报 `EINPROGRESS`（legacy dup 路径原生 EINPROGRESS 成立，取舍仅限 fd-inject 形态）。矩阵两条用例 pin 当前文档化行为（core_integ 529→531）。详见 §3.10 |
| **P7** | wheel 矩阵补 cp310 / cp312–313（沿用 zig 交叉编译流程） | 低 | E2B 运行时已统一 3.14 |
| **P8** | 上游 PR 推送（需有写权限的 token）+ 合入后 E2B 回切官方 wheel | 中 | 阻塞在权限，不在技术 |
| **P9** ✅**已采纳，见 §8** | 支持**一沙箱一实例**：`Sandbox.spawn(cmd, cwd=None, env=None) -> Process`（不占用"单活进程"busy 标记、每个 Process 自持 handle、并发上限由 `max_processes` 内核核算）+ per-exec `cwd`/`env` 覆盖（见 §3.7 评估） | 中（做进程级 checkpoint / 开 `pid_ns` 的前置） | E2B 当前不需要，故未催 |
| ~~P10~~ ⊘被 §8 取代 | ~~跨实例的共享资源组~~：一旦 §8 落地，记账边界即沙箱边界，无需组对象；仅作为 §8 不可行时的退路保留：内存/CPU/进程数目前按 `Sandbox` 实例各自记账（`brk`/`mmap` 的 USER_NOTIF 记账挂在实例的 `ctx` 上），同一沙箱的 N 个并发命令 ⇒ N 份配额。希望提供"调用方给一个 resource-group id，多个 Sandbox 共享同一份内存/CPU/进程核算"的能力（见 §3.8 实测） | 高（多租户 QoS/超卖） | E2B 侧可先用 per-sandbox cgroup 兜，但记账与 `max_memory` 语义不一致会持续踩坑 |

## 3. 未解决问题

### 3.1 SL-1 路径中介以 supervisor 身份执行系统调用（High，多租户 DAC 隔离）

**已修（构造消除 + fail-closed，fork-plan F2b / F6.1；commit `b62e201`（core 拒绝+断言）、
`dd5a7e8`（全栈 `mediation_run_as`）、`7f81314`（B/C 档验收 + runner 分层）、`75bbe0b`
（review I1 policy_fn 谓词），2026-09-05）**：中介没有独立特权进程，
`notif::supervisor(...)` 跑在持有实例的那个进程里，所以**中介身份恒等于该进程的 euid**。
route B 下每个沙箱由一个 `sandlock-supervise` 进程服务、且该进程 euid == 沙箱 host uid
（见 `docs/supervise-identity-handoff.md`），DAC 判定由构造正确：属主落 root、
`chmod` 失效、1777+sticky 跨 uid 保护不成立这三个症状在 A/B 档下不存在。

fork 侧 F6.1 把这一点固化成「断言 + 拒绝」：

- **A 档（同 uid 行为正确，默认 gate）**：`test_nonroot_created_file_owned_by_self`、
  `test_denied_path_still_denied`，外加 chroot 与 COW 两形态的同一组断言
  （文件属主 = 调用方 euid、自 chmod 生效、deny carve-out 仍 EACCES）。
- **B 档（跨 uid 硬证据，root 容器阶段 `--mediation-2uid`）**：
  `test_two_supervisors_distinct_uids_isolate_files` —— uid X/Y 各起一个
  `sandlock-supervise`（setpriv，真实内核身份），双方都允许写同一 1777+sticky
  共享目录：X 建的文件属主 X、X 自 chmod 生效，Y 可读但 `rm`/`chmod` 均 EPERM。
- **C 档（fail-closed）**：`mediation_run_as`（默认 `caller`）下，root 进程内中介
  + `RunAs(非 0 host uid)` + 路径中介 ⇒ **建箱前拒绝**并点名 route B 修法与显式
  `supervisor` 档；显式档建箱成功但 WARN 且 `stats()` 计数，对照组
  （root 保留 caps、chroot 中介）证明降级档真实降级（文件属主 root、同一条
  `unlinkat` 成功绕过 sticky）——默认档拒绝不是装饰。

字段已贯通 builder / Policy / profile 序列化 / FFI setter + cbindgen 头 /
CLI `--mediation-run-as`（真接线）/ Python `Sandbox(mediation_run_as=...)` /
supervise 全字段 policy 清单。历史复现与影响分析见 git 历史与
`docs/sandbox-exec-security.md` §4.12（SL-1 叠加说明）。唯一遗留：C 档对照组依赖
chroot 形态的中介代执行。F6.1 新增的 chroot/COW 断言本身**不下发** `fs_denied`
（chroot/COW dispatch 本身就是 on-behalf 触发）；F6.2 已按 plan 文字把 chroot
A档用例的 `/dev` 提供者换成 `minimal_dev()`（`fs_mount` 单节点集合，
`ptmx/pts/null/urandom/zero/tty`），用例在沙箱内写 `/dev/null` 且**全程不下发
`fs_denied` 也通过**——不再需要整树挂宿主 `/dev` 或为 `/dev/shm` 下发
carve-out，SL-1 的最大触发面由构造消除。另注：对挂载点本身的
unlink/rename/link 按真实 bind-mount 语义返回 `EBUSY`（防 nofollow 写家族
直取宿主源删/移宿主文件）；目录挂载点的 `rmdir` 暴露为既有问题，不在 F6.2
范围内。

**F10 收口（2026-09-06，supervisor × chroot × 特权 RunAs 的逃生门真实可用）**：
E2B M4 实测发现，显式 `supervisor` 档在 **chroot + root holder + `RunAs(非 0)`**
形态下仍然 create/launch 失败（FFI/Python 只吐泛化
`sandlock_create failed`/`sandlock_instance_launch failed`；Rust 层真实错误 =
child 死于 notif-fd 前：`sandlock child: chdir: Permission denied (os error 13)`）。
根因不在中介身份，而在 **remap 之后 confined child 用沙箱 host uid 去走真实
路径**：镜像 rootfs 缓存（root 0700，不对外可遍历）使 `chdir` 到
`rootfs/cwd` EACCES（建箱失败）；绕过 chdir 后，Landlock 规则构建的
`exists()`/path_beneath 探测同样全部 EACCES ⇒ 空 ruleset 在 exec 期 deny-all。
修法（fork 本地提交，F10）：**仅对特权 remap 形态**，把 `confine_child` 的真实
`chdir` + `NO_NEW_PRIVS` + Landlock 前置到 userns remap 之前（Landlock 层跨
userns 只增不减，限制不削弱）；非 remap / netns 自映射 / pid-ns 形态顺序不变
（netns 自映射必须先在 Landlock 前写自身 `/proc/self/uid_map`）。默认 `caller`
C 档 fail-closed 不变。回归用例：root 档 `mediation_2uid` 新增 one-shot
`RunAs(10000)`、instance `RunAs(10000)`、instance uid-0 三个 restrictive-cache
验收（5→8），非 root 档新增 `test_instance_chroot.rs` 同 uid exec-only 验收
（core_integ 531→532）。**E2B 侧需在 fork wheel 重建后复跑 §8/M4 探针**
（`tmp/mediation_probe.py` / `tmp/instance_probe.py`；修复已按探针根因对应）。

### 3.2 `notify_rate_limit` 假告警（Low）

`UserWarning: Policy field 'notify_rate_limit' is set but not wired through FFI` 每次建沙箱都打，
但字段**确实生效**（§2 P3）。风险是被误读成"配额/限流没起作用"。
**已修（commit `17ee48d`，2026-09-04）**：`_HANDLED_FIELDS` 已登记该名字，假告警消除。

### 3.3 T4：`net_isolation` + chroot 下 MCP 入站映射不通（Medium）

**已修口径 = fork 侧前提证伪 + 回归 pin（非代码修复；F7，commit `4e78c98` + 文档
`da9c3a7`/`7183884`，2026-09-05）**：
`net_isolation` + 镜像 rootfs 组合下 MCP 入站映射"起不来"的形态在 fork 内 9 种忠实构造下全部验证可用——
in-process mcp/epoll/poll、python3 exec（mount 宿主目录）、asyncio/uvicorn 型 0.0.0.0、
instance-exec（S12）、root supervisor + `RunAs(1000)`、以及真实 python3.14 镜像 rootfs + 真
`mcp-gateway.py` 栈；HEAD 与 T4 观测时代 commit（`be387c7`）均绿，无可修根因（证据与日志见
`tmp/sdd/f7-report.md` 与 `tmp/sdd/f7-red-*.log` / `f7-red-old*.log`）。

**T4 观测证据的准确归因（本段为 brief §2 之外的显式 scope 扩展）**：
`full-strict-1.log`（2026-09-03 11:30，407a59c 之前的同款新 runner 环境：XFS 已挂载、
`E2B_BASE_IMAGE` 与 `E2B_TEST_NET_ISOLATION` 均已设置）是一次**真实的 image-rootfs + netns 实跑**，
其中 `test_mcp_full_path_under_net_isolation` **FAILED**（`mcp-gateway did not start listening`），
与 e2b T4 记录一致（同场另有三个无关 failures/errors 与 volume_quota 1 skip）。
该 run **没有同场 pure-shape 对照**（"纯 sandlock 3/3 通过"来自其他 run），因此它不能证明
pure 形态失败，也不与 fork-core 9 种直构 GREEN 矛盾——两者独立成立。407a59c 之后才加上
keyed on `E2B_BASE_IMAGE` 的 `xfail(strict=True, run=False)`，故该用例此后未再被真实执行。
残余缺陷可能位于 envd gateway 接线层。**E2B 侧 follow-up（超出 fork 范围）**：以
`E2B_BASE_IMAGE` + `xfail(run=True)` 复测
`tests/contract/test_mcp_netns.py::test_mcp_full_path_under_net_isolation`；若仍失败，
在 worker 栈定位（gateway stderr / 宿主映射端口快照）；修好前 §2 P4 的 E2B 侧 xfail 保持不动。

**FUP-E1 关闭（2026-09-06，E2B Task 10/11）**：T4 根因 = envd 侧 base-image 组成
（slim rootfs 无 `/usr/local/bin/mcp-gateway` → ENOENT exit 2），非 fork；改用本仓库
`Dockerfile.mcp-base` 构建的 MCP-capable 基镜像 `python-mcp:3.14` 后，
`test_mcp_full_path_under_net_isolation` 在 image-rootfs + netns 档通过，xfail 已摘除；
E2B 全量门禁（Task 11）复跑全绿。基镜像构建与运行要求见 E2B 仓库
`docs/HANDOFF.md`「M4 收口」与 `tests/contract/test_mcp_netns.py` 模块头。

### 3.4 wheel 与 tip 的一致性：fork 侧符号级自证 + supervise 指纹（已落地，F0.2 / F2b.5）

wheel 产物时间戳早于 tip 提交，无法从文件本身判定；F0.2 起 fork 自己拥有 wheel 构建，产物与 tip 的
一致性由 fork 侧脚本**符号级自证**，不再依赖外部仓库重跑：

- `python/build-wheels.sh`：zig + manylinux_2_34 + auditwheel 双架构单 builder（builder 资产随仓库放
  在 `python/wheel-builder/`；`Dockerfile`/`zigcc`/`cargo-config.toml`），构建上下文 = fork 工作树的
  精简镜像（`Cargo.toml`/`Cargo.lock`/`crates`/`python`），一次构建产出 amd64 + arm64 两个
  manylinux_2_34 cp314 wheel 到 git-ignored 的 `wheels/`。
- `python/verify-wheel.sh`：解包 wheel → `nm -D --defined-only` 读 `libsandlock_ffi*.so` 的导出符号 →
  与当前 tip 的 `target/release/libsandlock_ffi.so`（容器内构建）双向对比。规则是**符号集必须等于当前
  tip 的符号集**：tip 有而 wheel 缺的符号逐个点名并以非零退出（新增 FFI 符号后 wheel 未重建 ⇒ 立刻红），
  wheel 多出的符号同样点名失败；同时打印 `git rev-parse HEAD` 与 wheel 内 `sandlock/_version.py`。

F2b.5 起 `sandlock-supervise` 随 wheel 发布（今天发布只打 `libsandlock_ffi.so` + Python 绑定的事实改变），
同一 buildx 运行按架构用同一 zig 交叉配方（wheel-builder 同款 glibc 2.34 pin）构建 supervise release 二进制，
一份字节三种形态：

- 每个 wheel 内 `sandlock/bin/sandlock-supervise`（auditwheel repair 之后由 `python/build-wheels.sh` 注入并
  更新 RECORD ⇒ `pip install` 落 0755，E2B 可直接 exec）；
- 独立 artifact `wheels/supervise/{x86_64,aarch64}/sandlock-supervise`（镜像构建 COPY 用，不经 pip）；
- `wheels/SHA256SUMS.supervise` 指纹清单：sha256 + 构建时 `HEAD`（wheel/独立副本/清单同批同源）。

`python/verify-wheel.sh` 的 F2b.5 自证：清单 `HEAD` 必须等于当前 tip（stale 清单即红并点名两个 commit）；
wheel 内 supervise 必须存在、ELF 机器与 wheel 架构一致、sha256 与清单及独立副本三方相等（篡改/删除即红并点名）；
再对宿主架构的 supervise 做 `--uid` 自检冒烟：以与 euid 不符的 `--uid` 启动必须拒绝（exit ≠ 0，stderr 点名
两个 uid）。自证命令与 F0.2 相同（见上）：`docker buildx build` 后容器内 `HEAD=<sha> python/verify-wheel.sh`。

符号核对佐证 fork 侧能力（`sandlock_sandbox_builder_{egress_proxy,http_auth,credential,host_mask,
notify_rate_limit,pid_ns,net_isolation,fd_inject_connect}`，`port_mappings` 走 `net_bind_map`，本就不是
独立符号）仍成立。发布前重跑 `python/build-wheels.sh && python/verify-wheel.sh`（
`scripts/test-all.sh --wheels` 已把两者串起来）并重建 worker/测试镜像。
**发布纪律（F9 复核补记）**：rebuild 前工作树应为 clean（`git status` 除 git-ignored
产物外无改动）；wheel/standalone/清单必须同批取用；supervise 指纹是**构建时锚定**
（构建容器与 dev 容器工具链不同，无法在容器内逐字节再推导），verify 以清单 HEAD 钉住
tip —— 源码变更后必须先 rebuild 再 verify，stale 清单即红。F9 已在 fork 最终 tip
重建并 verify（§5）。

### 3.5 非 root supervisor 无法映射任意 host uid（S1.2 约束，结构性）

单 entry userns 只能映射调用者自身 ⇒ 非 root worker 下"每沙箱独立 host uid"不可得，
E2B 只能退到"固定 uid + Landlock"模型；叠加 SL-1 时隔离更弱（root supervisor + 中介 ⇒ 全部 root 属主）。

### 3.6 上游可观测性/一致性未逐一验证

`port_mappings`、`notify_rate_limit`、`pid_ns` 等字段在 **CLI / profile TOML / FFI / Python** 四层的
暴露是否与 `Sandbox()` 完全对齐，目前只按 E2B 用到的路径验证过，缺一次矩阵化核对。

### 3.7 设计评估：一沙箱一 sandlock 实例（2026-09-03 实测）

现状是**一命令一实例**：`sandlock-e2b/envd_service/executors/sandlock.py` 的
`start()` 里每条命令 `_build_sandbox(config)` 新建一个 `Sandbox`。评估过改成
"一沙箱一实例"，实测数据（容器内，root supervisor，host_uid=4242，`/bin/sh -c 'echo hi'`，N=25）：

| 指标 | 每命令新实例 | 复用同一实例 |
|---|---|---|
| 策略构建（Python→builder FFI 重放全套字段） | **0.12 ms** p50 | — |
| `run()`（含 fork + execve + 等待） | 8.11 ms p50 / 11.10 p95 | **7.48 ms** p50 / 9.90 p95 |
| 差值 | — | 省 ≈0.6 ms/命令（≈8%） |
| 第二条命令在第一条存活时 | 正常（各自实例） | **0.2 ms 内被拒**：`RuntimeError: sandbox is already running` |

结论：**当前不值得改**。收益只有 8% 的命令内开销（且这部分只占 e2b 首字节预算 100 ms 的一小截，
瓶颈在 RPC/流式管道与 `asyncio.to_thread` 调度），而代价是三处功能倒退：

1. 绑定层规定一个 `Sandbox` 同时只能有一个活子进程（`python/src/sandlock/sandbox.py:670`
   `_check_not_running`），而 e2b 语义允许同一沙箱并发命令、后台进程、以及**长驻的 MCP 网关**
   共存 —— 现在正是靠"每命令一实例"满足的；
2. `cwd` / `env` / `clean_env` 是**策略字段**，每命令可变（`ExecConfig.cwd/env`）⇒
   复用实例必须支持 per-exec 覆盖；
3. 句柄归属是刻意拆开的（`_reject_if_popen`：popen 的 handle 归 `Process`，
   沙箱生命周期方法不得触碰），复用前要把"每个 handle 独立 wait/kill、不串扰"重做一遍。

反过来，复用实例能买到、但目前 E2B 用不上的能力：跨命令统一 pid namespace
（E2B 侧 `pid_ns` **零引用**，默认关）、进程级 checkpoint/恢复（E2B 的 pause 是 SIGSTOP、
快照是文件系统拷贝）、真正的沙箱级并发进程核算。因此把正确切法记为 **P9**（已于 §8 采纳为实施方案）：
不是复用 Python 对象，而是复用已经建好的 `_NativePolicy`（`_sdk.py:1120`，本来就在
`__del__` 才释放、每次 `create` 都用同一个 `native.ptr`），只把"单活进程"限制改成
"`spawn` 返回独立 `Process` + `max_processes` 内核核算"。触发条件：一旦要开 `pid_ns`
或做进程级 checkpoint，P9 就是前置项。

另注：P9 不改变 §3.1（SL-1）的结论——chroot 形态下 `fs_denied` 的代打开仍会把文件写成
root 属主，实例复用只会把这个错位从"每条命令"变成"整个沙箱生命周期"，日志与配额归属更难查。

### 3.8 内存/CPU/进程配额是按**实例**而非按沙箱（实测会超卖）

**已修（fork 侧 M0–M3 落地，2026-09-05；commit `57f543c`（M0 SandboxInstance）..
`1321ba0`（M3 语义 review fix）；E2B 侧 §8 M4 接线 2026-09-06 收口（Task 1–11）——
`SandlockExecutor` 每沙箱一只 exec-only `SandboxInstance`，命令与 MCP 网关都经
`instance.exec()`，执行边界 = 产品边界 ⇒ 超卖由构造消除）**：下面保留的是 2026-09-03
的实测证据（历史形态：E2B 每条命令一个实例）。E2B 侧落地后内存/CPU/进程数按**实例**
记账即按**沙箱**记账；fork 侧配套默认/语义见 §2 P9 采纳、`docs/fork-plan-2026-09.md`
阶段 F2–F5 与 CHANGELOG。两个 fork-blocked 边界登记在 E2B `docs/task-backlog.md`
「M4 收口后的 open follow-ups」：fork F11（多线程进程存在后 argv-safety exec 冻结
EPERM——FUP-E3 网关+命令变体依赖其修复）与网关 ledger headroom（512M 箱内 MCP server
子进程仅剩 ~180M）。

`max_memory` 由 `crates/sandlock-core/src/resource.rs` 在 `brk`/`mmap` 的 USER_NOTIF 里记账，
账本挂在**该 Sandbox 实例**的运行时状态上（同实例内父+子会一起算，所以限额本身是有效的）。
但 E2B 是"每条命令一个实例"（§3.7），于是同一沙箱的 K 个并发命令各拿一份配额。

容器内实测（`max_memory=512M`，`host_uid=4242`）：

| 场景 | 结果 |
|---|---|
| 单实例申请 600M | **被拒**（限额按实例内全树聚合，有效） |
| 3 个实例（3 条并发命令）各 200M | **全部成功 ⇒ 峰值 600M > 512M** |
| 同实例顺序 3×400M | 各自成功（串行，退出即归还 ⇒ 不是泄漏，是并发叠加） |

倍数 K = 该沙箱当前存活的实例数，而 K≥2 是常态：`Sandbox.create(mcp=...)` 的网关是长驻实例，
用户命令再并发几条；官方 SDK 的 `background=True` 进程也各占一个实例。
同理 `max_processes`（每实例 64）与 `max_cpu`（每实例一份）也会被乘以 K。

**K 由什么决定（E2B 侧）**：`envd_service/process/manager.py` 的 `_CommandGate` 限制每沙箱并发
命令数，默认 `E2B_MAX_CONCURRENT_COMMANDS_PER_SANDBOX=1`（多的排队、超队列 429）；
但 **MCP 网关不走闸口**（`runtime/context.py:167` 直接 `executor.start()`，且长驻）。
因此 `K = max_concurrent_commands_per_sandbox + 长驻实例数(网关=1)` ——
**默认配置就已经实测超卖**：网关 + 一条命令各申请 450M 同时成功 ⇒ 900M 峰值 / 标称 512M
= **1.76x**（各 300M 时 1.17x）；闸口调到 N 则约 **(N+1)x**。

**不受影响的**：磁盘——XFS project id 是按沙箱目录设置、被所有实例共享，所以多条命令写同一个
project，限额是真加总的（这也是为什么只有内存/CPU/进程数会超）。

**放大到节点层面**：E2B 的准入台账按沙箱预留 `_record_quota_dims()`（一次 `memory_mb`），
所以实例级超卖直接变成**节点超卖**：E9 的空闲检测/驱逐/自动扩缩看到的都是"预留值"，
实际 RSS 可以远超，OOM 会先于准入判定发生。


### 3.9 一沙箱一实例的安全前置：exec 复用新开的攻击面（2026-09-04）

**已清零（M0′：fork-plan F1.1–F1.8 全部落地，2026-09-05；commit `3d804b1`（SL-4）/
`c5a0fe7`（H1/H2）`95608be`+`ceaa069`（SL-7）/`f0b3d78`（SL-8）/`793aaf3`+`e85d031`
（SL-6）/`4b7f7d0`+`d2bd459`（SECE-6）/`df5d77a`（deadline）/`0f51fce`（SL-5）；
相关计数逐 commit 登记在 `docs/test-baseline.md`，oci-root 144 与全门在 F9 终局复验）**：
下方表格即 M0′ 各放行门槛的原始记录 —— 每行的缺陷现在都有对应修复 + 红→绿用例，
不再构成 exec 放行门槛。

§8 的改造在**沙箱内部**新开一类回退（今天互不可见的兄弟命令，合并后同 uid、同 pid 空间、同一条
宿主控制 socket），并把 `sandlock-oci` 现状实现与本文件既有的记账/鉴权问题合计**五条**变成放行门槛：

| 编号 | 缺陷 | 严重度 |
|---|---|---|
| **SL-4** | `extra_fds` 用 `dup2` 落位（`sandbox.rs:2319`）⇒ 清掉 `FD_CLOEXEC`，**宿主↔init 控制 socket（fd 3）被每个沙箱进程继承**（实测 `3 -> socket:[同 inode]`、`fdinfo flags: 02`）。fd 3 是 init 那一端 ⇒ 沙箱可**向宿主 daemon 注入伪造应答**：**实测**一条假 `Exited` 让宿主 `exec` 返回退出码 0 而目标进程仍在跑；假 `Exited{未知 pid}` 进 `early_exits`（无上限）⇒ 60k 帧 supervisor RSS **+5.3 MB** 且功能照常。（原记"发 `Shutdown` 打死整箱"**已实测否证**、"抢读宿主请求偷 stdio fd"**未复现**） | High |
| **SL-5** | `init/mod.rs:118-207` 在解析失败 / EOF / `RunMain` 分支不关闭收到的 fd + 帧边界按字节流猜。**可触达性修正**：能向 init 发帧的只有宿主 daemon ⇒ 属**正确性缺陷**，非沙箱可触发攻击 | Low-Medium |
| **SL-7** | **控制协议无鉴权**：服务端 `SO_PEERCRED` 不匹配时**只 eprintln 不拒绝**（`control.rs:236-262`，注释假设"dir 0700 should prevent this"），帧协议仅"4 字节长度前缀 + JSON"、verb 不绑定租户。**实测**：整树 bind `/dev` 后（= E2B 镜像 rootfs 形态），沙箱内 python 枚举出 `['M','N','O','P']` 并对**别人的** control.sock 发 `config` ⇒ `ok=True` 返回对方 filesystem/limits/network 策略；不挂 /dev 时同一操作 EACCES ⇒ 配置相关。**`exec` verb 进这个协议 = 跨租户执行入口** | **High（exec 硬阻塞项）** |
| **SL-8** | 进程数记账**没有退出兜底**：`proc_count` 唯一归还点是拦截到阻塞 `wait4/waitid`（`resource.rs:545-560`），没有 pidfd/`wait(-1)` 对账 ⇒ 孤儿/被收养进程**永久占用配额**。**实测**（`/proc/loadavg` 第 4 字段 = `proc_count`）：setsid 孤儿生灭一轮 `1/7→2/8→2/5`，第二轮 `2/5→3/6→3/5` ⇒ 可累加泄漏 | **High（已实测）** |
| **SL-6** | `run_init` 只按特定 pid `wait_exit`，无 `waitpid(-1, WNOHANG)` 兜底 ⇒ 被收养的孤儿无人回收。**实测修正**：oci **没有 pid namespace**（容器与沙箱 `ns/pid` 相同）⇒ 孤儿归**外层 PID 1**（E2B worker 的 python 不 reap ⇒ 仍堆积）；开 `pid_ns` 后才归 init。**两档下 `proc_count` 都泄漏**（唯一归还点是 `wait4` 通知） | Medium-High |

另有两条**合并语义**的实测确认（不新增 SL 编号，属设计后果）：沙箱内 `os.killpg(os.getpgid(0), SIGKILL)` 可打死整个实例（所有 child 共享 `pgid`=init，实测三条命令全灭）；`delete --force` 后 setsid 孤儿仍存活且能 `write()` 已打开的 fd（新 `open` 因监听者消失返回 ENOSYS ⇒ fail closed 但收尾不可靠）。

第三批实测又改了两条判断（详见 `sandbox-exec-security.md` §10.3 / §4.15）：
**沙箱内是"可打扰、不可窥探"** —— 兄弟进程的 `/proc/<pid>/{cmdline,stat,maps,environ,mem}` 全 EACCES、
`ptrace` EPERM、`/proc` 不可枚举，但 `kill(pid)` 同 uid 可投递 ⇒ 原 SECE-4（"root 替你读兄弟元数据"）
**在无 `pid_ns` 的当前形态不成立**，只在按 S8 打开 `pid_ns` 后成立（届时 on-behalf 白名单含 `cmdline`）
⇒ 开 `pid_ns` 必须同步把白名单按 `PidKey` 收窄到本 child 子树。
另实测到两条收尾事实：`delete --force` 后 setsid 孤儿仍存活且能 `write()` 已打开的 fd（新 `open` 返回 ENOSYS）；
child 退出但其孙子持有 stdout 时，attached `exec` 被吊住约 30 s ⇒ 收尾必须按 **fd 持有者**判定。

结构性约束：Landlock 与 seccomp 只能加严 ⇒ **per-exec 只能收窄**；放宽必须在实例创建时定死上限、
越界的 exec 请求**显式拒绝**（on-behalf 注 fd 是 `fs_denied` 的旁路，必须走同一套检查）。
归属口径：`sandlock-oci` **今天不在本项目部署路径上**（fork wheel 只含 `libsandlock_ffi.so` + Python 绑定，
发布 Makefile 只 `build -p sandlock-ffi`，envd 走 `Sandbox.popen()`）⇒ SL-4/5/6 这三条是**潜在**缺陷，
真正的风险是 §8 M1 把这套 init 下沉进 core 时原样带过来（哪些条目属于 OCI-live、
哪些只在 E2B 才成立，见 `sandbox-exec-security.md` §4.0 的归属分级表）。

以下有**本机实测**支撑（OrbStack `7.0.14-orbstack` + Landlock ABI **8** ⇒ macOS 也能做 exec 面
验收，README 的"macOS 不得作为 Sandlock 验收环境"只对 Docker Desktop 成立；XFS prjquota 类用例仍不可用）：
命令、输出与被否证项见 `sandbox-exec-security.md` §10。

完整分析（13 条攻击面、归属分级、会话生命周期状态机、`shutdown()` 顺序、放行门槛与测试矩阵）见
[`sandbox-exec-security.md`](sandbox-exec-security.md)。

### 3.10 P6：`getsockname/getpeername` 合成视图与非阻塞 connect `EINPROGRESS`（设计取舍，F8 闭环）

**结论**：两条均按「设计取舍 + 文档条目」收口，不做代码修复（fork-plan §F8，2026-09-05）。
矩阵用例
`crates/sandlock-core/tests/integration/test_network.rs::test_injected_connect_reports_synthetic_addresses`
与 `...::test_nonblocking_connect_reports_einprogress` 作为回归 pin 固定**当前文档化行为**
（现在即绿；未来若实现合成视图或 EINPROGRESS 转发，必须连同本条目一起翻转断言），
core_integ 529→531。

**1) getsockname/getpeername 合成视图 —— 取舍**

- 实测（HEAD `7183884`，uid 65534，`fd_inject_connect` on/off 两形态）：沙箱 DNS 把
  `conn.example.com` 解析成合成 `10.250.0.2` 后 connect，沙箱内 `getpeername()` 返回
  宿主侧真实 peer（fixture `198.18.0.99:<port>`），`getsockname()` 返回宿主侧本地地址
  （同为 `198.18.0.99` + 宿主临时端口）——合成目的地址不反映到连接视图。
- 机制证据：注入连接在宿主侧执行，注入 fd 的内核视图就是宿主视图；`getpeername` 目前
  **没有任何 seccomp 拦截点**（notif 列表只有 `getsockname`，见
  `seccomp_plan.rs` 的 `NETLINK_NOTIF_SYSCALLS`/`PORT_REMAP_SYSCALLS`）。要造假
  peer/local 需要新增 syscall trap + 逐 (pid, fd) 合成地址登记 + dup/fork/close 全
  生命周期镜像；而共享 netns 默认路径没有沙箱自有地址/端口空间可报（netlink 合成 eth0
  `192.0.2.1` 不可 bind，伪造本地视图会让复用该地址的应用坏掉）。bind/listen 侧的虚拟
  端口视图已由 `port_remap` 的 getsockname 拦截覆盖；**出站已连接 socket 没有**对应的
  虚拟地址空间。
- 用户可见语义：沙箱内对被中介的出站连接调用 `getsockname/getpeername` 看到的是真实
  宿主端点。Sandlock 对被中介连接的契约是「策略放行过的连接」，不承诺合成地址视图。

**2) 非阻塞 connect EINPROGRESS —— 取舍（仅限 fd-inject 形态）**

- fd-inject 路径（S2.1/S2.2）的 seccomp 通知模型是「一次 connect 一条响应」：supervisor
  必须在响应前完成宿主侧 connect 并把已连接 fd 注入（`SECCOMP_IOCTL_NOTIF_ADDFD` 需要
  pending 通知；响应后没有后续 hook），因此子进程永远看不到 `EINPROGRESS`。
  `new_host_socket`（`network/connect.rs`）把子进程 `SO_SNDTIMEO` 镜像到宿主 socket
  （`mirror_child_connect_timeout`，lib 单测 pin），作为阻塞上界——supervisor 不会卡在
  内核默认 TCP 超时。
- 真实 EINPROGRESS 转发需要「先回 EINPROGRESS → 后台宿主 connect → 稍后注入 fd 并合成
  可写事件」，并覆盖 poll/select/send 全生命周期，属特性级重构，超出低优先补齐范围；
  还会破坏 fd-inject 形态的既有契约：注入 connect 的 syscall 结果必须返回 0
  （该约束在**非阻塞可观察面**严格成立——阻塞形态宿主侧完成后同样返回 0；
  CPython `socket.connect()` 兼容，既有回归 pin）。
- 默认共享 netns 的 legacy dup 路径不受此限：connect 在子进程自己的 socket 对象上执行，
  内核继续异步握手，`EINPROGRESS` 原生透传（`test_net_isolate.rs` 的 `connect_script`
  注释已记录）。取舍范围仅限 fd-inject 形态。
- 用户可见语义：fd-inject 形态下非阻塞 client 的 connect 调用会阻塞到宿主侧完成 /
  `SO_SNDTIMEO` 到期，返回最终 errno（0 / ETIMEDOUT 等），永不为 `EINPROGRESS`。

## 4. E2B 侧当前缓解（不改 fork）

- 纯 sandlock（无 chroot）形态**不再下发** `fs_denied`：这些路径本就不在 Landlock 可读白名单内，
  denial 冗余却要付 SL-1 的代价。改后实测：属主 = 沙箱 host uid、`chmod` 正常、
  跨 uid sticky 保护真的生效。落点 `envd_service/executors/sandlock.py`。
- 镜像 rootfs 形态仍保留 denial（`/dev` 必须整树挂进 chroot 才有 ptmx/devpts，见 §2 P5；
  fork 侧已落地 `minimal_dev()` 单节点 `/dev` 集合，E2B 切过去后可撤整树挂载与该
  denial），该形态的属主问题由 `xfail(strict=True)` 跟踪，非 chroot 形态则**必须**通过。
- 测试环境补齐：容器 runner 自动 loop 挂载 XFS(`prjquota`) 并把沙箱工作目录放上去、
  `xfsprogs`/`e2fsprogs`/`nodejs`/`npm`、双形态默认同跑、`E2B_TEST_STRICT_SKIPS=1`
  把"能力型 skip"直接判失败。

## 5. 验证矩阵（最近一次，2026-09-05）

| 套件 | 结果 |
|---|---|
| E2B 全量 gate A（Linux 容器，image-rootfs python-mcp:3.14 + netns + XFS + npm + strict；2026-09-06 实测，E2B 侧，log `tmp/m4-full-gate-a.log`） | `925 passed / 1 skipped / 1 xfailed(T5) / 0 failed / 0 error`（历史 09-03 行已被取代） |
| E2B 全量 gate B（Linux 容器，pure sandlock + netns + strict；2026-09-06 实测，E2B 侧，log `tmp/m4-full-gate-b.log`） | `921 passed / 3 skipped / 3 failed`（3 failed = pre-existing pure-shape migration trio，`4f34e55` 复现，非 fork/M4 回归；E2B FUP） |
| E2B 全量（macOS 宿主，unit+contract+sdk python/js+security；2026-09-06 实测，E2B 侧，log `tmp/m4-full-gate-macos.log`） | `865 passed / 58 skipped / 0 failed / 0 error` |
| fork 全量门禁非 root 档（F9 终局，2026-09-05，sandlock-dev:latest 特权容器） | core_lib `822` / core_integ `531` / ffi `98` / cli `98` / supervise `36` / supervise_cost `3` / cli_build `0` / python `454`（log `tmp/sdd/f9-gate-nonroot.log`） |
| fork 全量门禁 root 档（F9 终局，2026-09-05，同容器 root 阶段） | oci-root `144` / supervise_root `2` / mediation_2uid `5`（log `tmp/sdd/f9-oci-root.log`、`f9-supervise-root.log`、`f9-mediation-2uid.log`） |
| fork wheel 自证（F9 终局重建，2026-09-05） | `python/build-wheels.sh` 双架构 + `python/verify-wheel.sh` 全绿（FFI 符号双向相等 + supervise 指纹三方一致 + `--uid` 拒绝冒烟；清单 HEAD = F9 tip）（log `tmp/sdd/f9-wheel-build.log`、`f9-wheel-verify.log`） |
| fork 全量门禁非 root 档（F10 终局，2026-09-06，sandlock-dev:latest 特权容器） | core_lib `822` / core_integ `532` / ffi `98` / cli `98` / supervise `36` / supervise_cost `3` / cli_build `0` / python `454`（log `tmp/sdd/f10-gate-nonroot.log`） |
| fork 全量门禁 root 档（F10 终局，2026-09-06，同容器 root 阶段） | oci-root `144` / supervise_root `2` / mediation_2uid `8`（log `tmp/sdd/f10-oci-root.log`、`f10-supervise-root.log`、`f10-mediation-2uid.log`） |
| E2B 探针（mediation/instance，F10 修复后需 tip wheel 重建验证） | fork 源码侧按探针根因修复并落 Rust 回归用例；wheel 重建后复跑 `tmp/mediation_probe.py` / `tmp/instance_probe.py`（预期：one-shot chroot+RunAs(1000)+supervisor 与 instance uid0/1000/65534+supervisor 全过；caller+RunAs(≠holder) 仍 C 档拒绝） |

逐套件权威数字与历史注释见 `docs/test-baseline.md`（F9 终局已复核；本计划新增用例数
已随各 commit 登记）。E2B 侧两行是 E2B 仓库 2026-09-03 的实测，fork F0–F9 期间未复跑
（fork 侧只负责本仓库自证）。

fork 侧复跑命令（非 root 全程，入口脚本做一次性 root 准备）见
`sandlock-e2b/docs/HANDOFF.md`「sandlock fork 验证」。

## 6. 迁入本仓库的 E2B 方案文档

这些是 E2B 为 sandlock 写的改动方案，原先放在 `sandlock-e2b/docs/`，现统一在此（保持原文件名）：

| 文档 | 内容 | 状态 |
|---|---|---|
| `docs/sandlock-network-wildcard.md` | E2B Network API 能力对齐总纲（R1–R14：通配解析、合成地址、SSRF 护栏、credential 注入、host mask、SOCKS5 on-behalf） | ✅ 已落地（§1 对应条目） |
| `docs/netns-isolation-fd-injection.md` | 方案 1：loopback netns + supervisor fd 注入（ADDFD 无特权可行性与 PoC 结论） | ✅ 落地为 S1.1/S2.1–S2.5；netns 部分已从运行时基线移除 |
| `docs/sandbox-level-cow.md` | 沙箱级 COW（常驻 supervisor 路线）评估 | ❌ **已否决**，最终采用 XFS project quota（方案在 E2B 仓库 `docs/sandbox-disk-quota.md`） |
| `docs/upstream-pr-netns-free.md` | 无特权上游 PR 的范围、分支与推送状态 | ⏸ 分支就绪，推送受 token 权限阻塞（§0） |

> 反向引用（E2B 仓库 `docs/HANDOFF.md`、`docs/sandbox-disk-quota.md`、
> `docs/superpowers/plans/*`）已改为指到这里。

## 7. 同步约定

1. 本文是 sandlock 侧的唯一事实源；E2B 仓库 `docs/sandlock-upstream-issues.md` 退化为编号索引
   （SL-1 / T4 / T5 → 本文对应小节）。
2. fork 修复后，请在本文把条目状态改为"已修（commit/PR）"，E2B 侧的 `xfail(strict=True)` 会
   因 XPASS 立刻失败，提示摘除标记与恢复断言。
3. 编号沿用：`SL-*` = fork 缺陷，`T*` = E2B 待办，`R*/S*/E*/M*` = 已落地方案编号。

## 8. 采纳方案：每沙箱一个实例（2026-09-03 复核后按最小改动界定）

> **F9 收口（2026-09-05）**：本方案的 fork 侧实现（M0–M3 + F2b route-B supervise +
> F3–F5 exec/per-exec/语义/兜底）已全部落地并全门复验 —— 对应 §1 M0–M3 行与
> §2 P9 采纳。余下的 **M4（E2B 接线：SandlockExecutor 持实例、`_CommandGate` 保留、
> 控制目录名 sandbox_id + token、超卖探针改断言）在 E2B 仓库执行**，不在 fork 范围；
> fork 侧文档与 follow-up 见 `docs/fork-plan-followups.md`。

> **E2B M4 收口（2026-09-06，Task 1–11）**：上段"余下的 M4"已在 E2B 仓库全部落地——
> `SandlockExecutor` 每沙箱一只 exec-only `SandboxInstance`（命令与网关都 exec），
> 控制目录名用 sandbox_id + token，`update_network` 按 D4=A（S2 收窄/409），
> `minimal_dev`、`max_processes=256`、§3.8 超卖探针转断言（FUP-E3 sibling-exec 形态）；
> fork 核心冻结（wheel = b955ae9）不变。gate A（image-rootfs）+ macOS 全量 0 failed；
> gate B pure 形态 3 条 migration 为既有缺陷（E2B FUP，非 fork/M4 回归）。详见 E2B
> `docs/HANDOFF.md`「M4 收口」。

> 决策：一个 E2B 沙箱 = 一个长命 sandlock 实例，命令是"往这个实例里 exec 一个进程"。
> 目的：让**执行边界 = 产品边界**，§3.8 的内存/CPU/进程数超卖从根上消失。

### 7.1 复核：fork 已经支持什么（这部分不用做）

| 已具备 | 证据 |
|---|---|
| **沙箱内部进程树**：子进程的 fork/clone 被拦截并登记 | `resource.rs:85 handle_fork`、`ProcessIndex::key_for`、`resource.rs:130 rs.proc_count += 1` |
| 进程数按**树**核算（不是按单进程） | `proc_count`/`peak_proc_count` + `max_processes`（`state.rs:12`） |
| 冻结是**整棵树**：`hold_forks` 挂起 fork，checkpoint freeze 已按沙箱设计 | `state.rs` 注释、`resource.rs:119` |
| 内存记账按地址空间归属、exec/exit 会**自动归还有效额度**（多进程已经是对的） | `resource.rs:693` 注释、`604/610/625/658` |
| 活沙箱有**控制通道**（unix socket + JSON 帧，带 `args` 字段，目前 `dead_code`） | `control.rs:274 ControlRequest`、`:340 "config"`、`:341 "ports"` |
| **一实例多进程 + exec 的完整骨架**（stdio fd 传递、按 pid 退出回报、Shutdown） | `sandlock-oci`：`supervisor.rs:341-364`、`init/mod.rs:118-207`、`init/proto.rs`、`fdpass.rs` |
| 宿主可拿到 pid、kill、wait、pause/resume、port mappings、checkpoint | FFI `sandlock_handle_{pid,kill,wait,wait_timeout,checkpoint,free,port_mappings}` |

⇒ **不需要**三层重写（我上一版 §8 写重了）。真正缺的是"从宿主再往活沙箱里塞一个根进程并把 stdio 交出来"，
以及"实例生命周期不再等于第一个进程的生命周期"。

### 7.2 缺口（这才是改造面）

1. **`exec` verb + fd 传递**：机制**已在 `crates/sandlock-oci` 跑通**（受限 PID-1 `sandlock-init`
   + `RunMain`/`RunExec`/`Shutdown` + `fdpass.rs`/`init/fdrecv.rs` 的 SCM_RIGHTS + 按 pid 路由 `Exited`）；
   确实只有 `control.rs` 侧没有 exec verb。⇒ 改造是**下沉复用**，不是新写，见 `sandbox-exec-security.md` §1。
2. **实例生命周期解耦**：`wait()` 的收尾会 abort notif/throttle/loadavg/**control listener**、
   清控制目录、关 DNS 网关（`sandbox.rs:1061-1072`，`control_handle` 见 :1065/:3123）
   ⇒ 要变成"最后一个被 exec 出来的进程退出"或显式 `instance.shutdown()` 才做这些。
3. **child id 与退出回报**：`sandlock_handle_wait` 等全部锚在单槽 `leader_pid.or(child_pid)`
   （:1375/:1389/:1404）⇒ 需要 `exec` 返回 child id、按 id wait/kill、退出码经控制通道回报；
   宿主侧 `Process` 不再是 `&'a mut Sandbox` 的借用（:3022）。
4. **per-exec 的 `cwd`/`env`**：今天 `cwd`/`env`/`clean_env` 是策略字段（builder 上设），
   每命令可变 ⇒ 需要 execve 前 chdir + envp 构造（E2B 现依赖：PTY 的 `/dev/ptmx,/dev/pts` 可写、
   MCP 的 `net_allow_bind` 端口，也都要变成 per-exec 增量）。
5. **`ResourceState` 归属**：它现在在 `do_create_stdio()` 里 new（:1829→:2809）⇒ 提升到 instance，
   否则每 exec 又拿到一份新预算，改造就白做。
6. **名字 = 身份**：`control.rs:136-147` 用 `kill(pid,0)` 判活、判死就 `remove_dir_all` 抢占
   ⇒ 沙箱 id 作 name 后，pid 复用/双 worker 竞态会误清活沙箱目录 ⇒ 加身份 token（写 token 文件 +
   比对 `/proc/<pid>/stat` starttime），冲突时**拒绝**而非抢占。

### 7.3 目标形态（宿主侧 API）

```text
SandboxInstance（长命：runtime、notif listener、ResourceState、PolicyFn/Network/Procfs/COW 状态、
                 控制 socket、DNS 网关、控制目录+身份 token）
   ├─ exec(argv, cwd?, env?, stdio|pty, extra_writable?, bind_ports?) -> {child_id, fds...}
   ├─ wait(child_id) / kill(child_id, sig) / resize(child_id)      ← 按 child
   ├─ freeze() / thaw() / checkpoint() / stats()                   ← 沙箱级（多数已现成）
   └─ shutdown()   幂等：停 listener、关网关、清目录、回收预算
```
FFI 增量：`sandlock_instance_exec` / `sandlock_instance_wait_child` / `..._kill_child`（或统一走控制
socket，宿主只拿 fd）；Python 增量：`SandboxInstance.exec(...)` 返回自持句柄的 `Process`。
旧 API（`Sandbox.run/popen/spawn`）保持"一次性实例"语义不破 ⇒ ABI 与既有测试不炸。

### 7.4 必须提前定的语义（不定会返工）

| # | 待决 | 建议 |
|---|---|---|
| S1 | **`max_processes` 从"每命令 64"变"整箱 64"** ⇒ 现网可能立刻 fork 失败 | 同步上调默认（如 256），写进 release note；E2B 侧按沙箱显式配 |
| S2 | **`update_network`**：实例长命后"下一条命令生效"不再自动成立（Landlock 只能加不能撤，deny→allow 做不到在线放宽） | 采用"新策略对**新 exec** 生效、已在跑的 child 保持原策略"，并在 API 上回报 staleness；在线收紧走已有 `PolicyFnState.live_policy` 路子 |
| S3 | **checkpoint 范围**：冻结已是整树，但内存快照目前面向单 address space | 多 child 时**显式拒绝**（禁止静默只存一条命令）；要支持得单独设计 |
| S4 | **pid_ns**：ns pid 1 = 首个进程，它退出会带走整棵树 | 实例化后需要一个内部 reaper/init（或明确"共享 pidns 暂不支持"），否则不能和 `pid_ns=true` 同时用 |
| S5 | **失败爆炸半径**：listener/runtime panic 现在会带走整箱而不是一条命令 | 定义 instance dead ⇒ 宿主见明确错误 ⇒ E2B 重建沙箱；不做静默重启 |
| S6 | **`fs_denied`(SL-1) 与长命实例叠加**：chroot 形态代打开的属主错位会从"每命令"变"整箱生命周期" | 先落 SL-1 修法（§2 P1/P2），或至少在实例化前复测 `command-logs.jsonl` 归属 |
| S7 | 泄漏面（今天"进程退出即回收"天然无泄漏） | 显式 `shutdown()` + child 表空 + idle 超时兜底；E2B 的 delete/kill/迁移/驱逐/重启全路径接；24h FD/线程泄漏测试 |

### 7.5 分期与验收

- **M0**：`ResourceState` 与 listener/控制目录生命周期从 create 路径提到 instance（行为不变，旧 API
  走一次性 instance）。验收：fork 三套全绿 + E2B 全量不变（当前 `867 passed / 1 skipped / 2 xfailed`）。
- **M1**：`exec` + SCM_RIGHTS + child id + 按 child 的 wait/kill/resize（不开放 e2b 使用）。
  验收：lib/integration 新增并发 exec、fd 归属、双 wait 幂等、stdin 关闭不死锁的用例。
- **M2**：per-exec `cwd/env/extra_writable/bind_ports`（Q4/S2 的 staleness 语义同时定死）。
- **M3**：S1 默认值调整、S3/S4 的拒绝或支持、S5/S6/S7 的生命周期与泄漏兜底。
- **M4**：E2B 接线（`SandlockExecutor` 持 instance、`_CommandGate` 保留、控制目录名用 sandbox_id
  + 身份 token），并把 §3.8 的超卖探针从"记录"改成**断言**（第二条命令申请应被拒）。
  ✅ 完成（E2B Task 1–11，2026-09-06；FUP-E3 sibling-exec 断言已落
  `tests/contract/test_memory_quota_boxed.py`；网关+命令变体 fork-blocked → F11）。

### 7.6 需要 E2B 同步做的

**已完成（E2B Task 1–11，2026-09-06；提交与门禁见 E2B `docs/HANDOFF.md`「M4 收口」）**：
instance 持有与释放时机（delete/kill/migrate/evict/worker 重启 → `close()` 幂等收口，
closed/dead 重建一次）；`_build_sandbox` 的 per-command 字段改走 `exec` 参数
（`cwd/env/clean_env/bind_ports`，PTY 用 `ExecStdio.PTY`）；`max_processes` 整箱默认
256 与节点容量联动（`2048/256=8`）；`update_network` 按 S2 落地（D4=A：收窄可应用、
放宽/翻转 409 不落库、staleness 日志）并同步契约测试；`minimal_dev` 替换整树 /dev；
`docs/SCALING.md` / `resource-contention.md` 的"按沙箱预留 = 按实例核算"一致性说明已随
M4 关闭 §3.8。残余：T5（route-B 前置，strict xfail）与 E2B 侧 follow-up
（pure-shape workspace 属主对齐、远程 pause/resume 投递），见 E2B `docs/task-backlog.md`。

### 7.65 已评估的替代入口：直接把 `sandlock-oci` 当主入口（2026-09-04）

结论：**可行但不推荐做长期主入口**（完整评估见 `sandbox-exec-security.md` §11）。
实测支撑：envd 可用纯 Python `sendmsg + SCM_RIGHTS` 直连 `state_dir/<fnv1a16(id)>.sock`
驱动 `exec`（CPython 3.14 无 `send_fds`）；`/bin/sh -c true` 的每命令成本
基线 1.24 ms → 沙箱内直连 exec **5.85 ms** → 走 CLI **11.57 ms**（必须绕开 CLI）；
共享预算（本方案主收益）在 oci 路径上**今天就成立**（§10.2 V5）。
不推荐的理由：E2B 的策略字段（网络 / header 注入 / host_mask / bind 端口 / `max_open_files` /
`clean_env` / protection）在 OCI spec 里没有入口，要往 `policy.rs` 塞 E2B 专有扩展；
且只有组级 `Signal`（实测一发打死整箱）、无 `pause/resume/stats/update_network` verb、无 PTY、
**Exit 帧可丢**（直连 12 次丢 2 次）、每沙箱常驻 ≈25 MB（`E2B_MAX_SANDBOXES=100` ⇒ ≈2.5 GB/节点）。
反过来该抄的两样：**exec 通道不要落 `/dev/shm`、目录名要哈希**（oci 的通道在沙箱内实测全 EACCES，
而 §8 原计划落 `/dev/shm/sandlock-<uid>/<明文 id>` ⇒ 正是 §3.9 SL-7 的可枚举可连面）。
唯一值得重评 §8 决策的分支：fork 侧愿意把"策略扩展 + per-child verb + stats/pause/resume"
做成 oci 一等能力（可先探上游意愿）。
