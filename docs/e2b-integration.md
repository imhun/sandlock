# E2B × sandlock：修改方案与未解决问题（集成事实源）

> EN: single source of truth for everything E2B (the `sandlock-e2b` runtime) has changed in,
> asks of, or is blocked by this fork. Maintained from the E2B side; keep in sync with
> `sandlock-e2b/docs/HANDOFF.md`, which now only points here.
>
> 维护方：E2B（`sandlock-e2b`）。本文是该 fork 的**已做改动 / 待做方案 / 未解决问题**的唯一事实源。
> 最后更新：2026-09-03

## 0. 基线与硬约束

| 项 | 现状 |
|---|---|
| 运行时基线分支 | `upstream-pr/netns-free-clean`（无 per-sandbox netns/veth，全程无 root 也能跑） |
| 参考分支 | `feature/network-socks5`（含 netns 的旧主线，仅参考，不再出 wheel）、`feature/network-inject` |
| wheel | `cp314` × `x86_64`/`aarch64`，`0.9.0b0 manylinux_2_34`，由 `build-sandlock-wheels.sh` 用 zig 交叉编译（glibc pin 2.34） |
| 上游 PR | 分支已整理好但**未推送**：`sandlock-e2b` 侧 `GITHUB_TOKEN` 只读（push/写 API 403），且该机无 `gh` CLI |
| 原则 | 沙箱全程非 root（uid/gid 由 `RunAs` 决定）、无 root supervisor 也要可用；`E2B_ENABLE_NETNS` 仅作兼容保留 |
| 发布前 | 重跑 wheel 构建 + 重建 worker/测试镜像（wheel 与 tip 的一致性只能靠重跑自证） |

历史全绿基线（fork 自带三套，Linux 容器内非 root）：lib `788`、integration `465`、python `430`。

## 1. 已落地的修改方案（fork 侧）

| # | 能力 | 落点 | 状态 / 验证 | 已知限制 |
|---|---|---|---|---|
| R1 | 通配域名解析 `NetTarget::HostWildcard`（deny 时拒绝域名） | network ACL 层 | ✅ | — |
| R2 | 合成地址 `SyntheticDns`（`10.250.0.0/16`，LRU 4096） | 同上 | ✅ | — |
| R3/R4 | connect/send 连接判定 + SSRF 护栏 | connect & send 路径 | ✅ | 护栏放行段可配（本环境 DNS 被改写为 `198.18.x`） |
| 默认无特权路径 | 每沙箱 loopback DNS 网关（`127.0.0.x:53`）+ `resolv.conf` memfd + connect/send 豁免 + netlink 合成视图（虚拟 eth0 `192.0.2.1/24`、`2001:db8::1/64`） | network / procfs | ✅ 全绿 | getsockname/getpeername 仍显示宿主地址；非阻塞 connect 无 `EINPROGRESS` |
| R8–R11 | credential injection（`http_inject`，FFI `credential`/`http_auth`）、`host_mask`（只改 wire `Host`）、HTTP matcher 支持 `*.suffix`、HTTPS MITM 复用同一 handler | transparent_proxy + FFI + Python + CLI | ✅ | **同一 matcher 多 header 注入**曾 first-match-wins，已去 `break` 改为全量应用（同 header 后者覆盖，AddOnly 不变） |
| R12–R14 | SOCKS5 on-behalf 出口（`egress_proxy`）替代 LD_PRELOAD：RFC1928/1929、poll 驱动、10s 超时、fail closed、ATYP=domain/IPv4/IPv6；代理端点由 supervisor 代拨且**不进** `net_allow` | `network/egress.rs` | ✅ 7 单测 + 3 hermetic 集成 | — |
| S1.1 | PID namespace（`pid_ns`，`CLONE_NEWPID` 两级 fork；procfs 按 ns pid 重编号；on-behalf `/proc` 只读白名单；freeze/thaw/checkpoint/throttle/tty/stat 全覆盖） | `pid_ns` 开关，默认 false | ✅ lib/integration | CLI `--pid-ns` 早期未接运行时 builder，已随 S3 收尾 |
| S1.2 | 单 entry userns + `RunAs` 任意 host uid（root supervisor 下不同沙箱不同 host uid ⇒ 同路径文件/unix socket 内核级隔离） | `RunAs` | ✅ 机制可用 | **非 root supervisor 无法映射任意 host uid**（fail-closed 拒绝）→ E2B 侧降级为"固定 uid + Landlock" |
| S2.1–S2.5 | connect fd 注入（`fd_inject_connect`；CPython 兼容修正：**注入的 connect 必须返回 0**）、UDP（connected 注入 / datagram on-behalf 单向代发）、入站端口映射 `port_mappings`（Python 侧经 `_b_net_bind_map`）、`net_isolation` 下 listen 的 poll/epoll 可读性合成（E7.1） | FFI/Python/runtime | ✅ | `port_mappings` 无同名 FFI setter，是 `net_bind_map` 的封装（**不是缺口**） |
| E7 前置 | 运行时基线移除 per-sandbox netns/veth（`network/netns.rs`、test_netns、`netns` flag/FFI/Python 全删），通配走无特权共享路径 | — | ✅ | netns 集成测试仅存于 `feature/network-socks5` |
| M6 | cp314 双架构 wheel + 私有 index 安装；fork build.rs 加 `-mcmodel=large`（manylinux gcc-toolset-14 下 restore-stub 32 位绝对重定位溢出） | 构建 | ✅ | cp310 / 3.12–3.13 未做 |
| 测试 | 非 root 测试入口 `b6ef050`（`Dockerfile.test-runner` 里 `/usr/bin/python3 → /usr/local/bin/python3` 之类由 E2B 侧镜像负责） | python 测试 | ✅ 430 passed | — |

## 2. 待实施的修改方案（E2B 提出，需要改 fork）

| 编号 | 方案 | 优先级 | 说明 |
|---|---|---|---|
| **P1** | **SL-1 修法**：路径中介必须以**调用方身份**执行（`setfsuid/setfsgid(caller)` 包住被中介的 syscall，或 `openat(O_CREAT)` 后 `fchown` 回调用 uid）；`unlinkat/renameat2/fchmodat/fchownat` 需按**调用方**复现内核 DAC 判定（owner / sticky / `CAP_FOWNER` 相对该 inode 所在 mount 的 userns），不成立返回 EPERM | 高（多租户隔离） | 详见 §3.1 |
| **P2** | 提供 `mediation_run_as = caller \| supervisor` 开关，便于既有依赖 COW/chroot 语义的调用方渐进迁移 | 中 | 与 P1 同批实现成本最低 |
| **P3** | `_HANDLED_FIELDS` 登记 `notify_rate_limit`（**一行**） | 低（但污染每条日志） | 字段其实**已生效**：`_sdk.py:1217` 调 `sandlock_sandbox_builder_notify_rate_limit`；集合 `_sdk.py:1138` 起漏了名字 ⇒ 每次建沙箱都打假告警 |
| **P4** | 修 T4：`net_isolation` + chroot（镜像 rootfs）下 MCP 入站端口映射起不来 | 中（该形态是 E2B 生产形态之一） | E2B 侧 `xfail(strict)` 跟踪，修好即 XPASS 报警 |
| **P5** | `fs_mount` 目前只接受目录根（单文件/设备节点会以 `ENOTDIR` 失效）⇒ 调用方只能整树挂 `/dev`，进而**必须**下发 `fs_denied` 挡 `/dev/shm`，正好踩 SL-1。希望支持单节点挂载，或提供"最小可用 /dev（ptmx/pts/null/urandom）"构造 helper | 中（消除 SL-1 触发面） | 见 §3.1 影响面 |
| **P6** | 无特权默认路径的细节补齐：`getsockname/getpeername` 反映合成视图、非阻塞 `connect` 的 `EINPROGRESS` 语义 | 低 | 已知限制条目化 |
| **P7** | wheel 矩阵补 cp310 / cp312–313（沿用 zig 交叉编译流程） | 低 | E2B 运行时已统一 3.14 |
| **P8** | 上游 PR 推送（需有写权限的 token）+ 合入后 E2B 回切官方 wheel | 中 | 阻塞在权限，不在技术 |
| **P9** ✅**已采纳，见 §8** | 支持**一沙箱一实例**：`Sandbox.spawn(cmd, cwd=None, env=None) -> Process`（不占用"单活进程"busy 标记、每个 Process 自持 handle、并发上限由 `max_processes` 内核核算）+ per-exec `cwd`/`env` 覆盖（见 §3.7 评估） | 中（做进程级 checkpoint / 开 `pid_ns` 的前置） | E2B 当前不需要，故未催 |
| ~~P10~~ ⊘被 §8 取代 | ~~跨实例的共享资源组~~：一旦 §8 落地，记账边界即沙箱边界，无需组对象；仅作为 §8 不可行时的退路保留：内存/CPU/进程数目前按 `Sandbox` 实例各自记账（`brk`/`mmap` 的 USER_NOTIF 记账挂在实例的 `ctx` 上），同一沙箱的 N 个并发命令 ⇒ N 份配额。希望提供"调用方给一个 resource-group id，多个 Sandbox 共享同一份内存/CPU/进程核算"的能力（见 §3.8 实测） | 高（多租户 QoS/超卖） | E2B 侧可先用 per-sandbox cgroup 兜，但记账与 `max_memory` 语义不一致会持续踩坑 |

## 3. 未解决问题

### 3.1 SL-1 路径中介以 supervisor 身份执行系统调用（High，多租户 DAC 隔离）

**现象**：启用**路径中介**后，沙箱自己创建的文件属主是 **uid 0**，且它请求的 mode 不生效
（`chmod` → EPERM）；同时共享目录里"非 owner 不得删除他人文件"（1777 + sticky）的保护不再成立。
中介的**实测触发条件**是 `fs_denied` 非空，或 chroot（镜像 rootfs）；源码里还有第三组
`cow_path_syscalls()`（COW 分支），本文未单独验证其触发条件。

**机制定位**

```text
crates/sandlock-core/src/seccomp_plan.rs
  cow_path_syscalls():    openat openat2 execve unlinkat mkdirat mknodat renameat2
                          symlinkat linkat fchmodat fchownat truncate utimensat
                          newfstatat statx faccessat readlinkat getdents64 chdir getcwd (+ 旧式)
  chroot_path_syscalls(): 同一组路径相关调用
crates/sandlock-core/src/seccomp/notif.rs
  这些调用由 supervisor 侧代发；全文没有 setfsuid / seteuid / geteuid ⇒ 身份 = supervisor(root)
```

即：Landlock 规则仍约束**子进程**（越出可写集合的写入照旧被拒，本文已验证），
但凡经中介的操作，内核看到的操作者是 root —— 中介改变了"路径解析"却没有保留"操作者身份"。

**证据（同一脚本，仅切换 `fs_denied`；两个沙箱 uid=4242 / 4343，共享目录 `0777`）**

```text
fs_denied=["/dev/shm"]      A: chmod=1 (Operation not permitted)   宿主: -rw-r--r-- 1 0 0 a.txt
                            B: rm=0                                ← 删掉了 A 的文件
fs_denied=[]（对照）        A: chmod=0                             宿主: -rw------- 1 4242 4242 a.txt
                            B: rm=1 (Operation not permitted)      ← sticky 保护正常
```

**影响**

1. 沙箱无法管理自己的产物：`pip`/`npm install` 之类需要 `chmod`/utime 的流程不可用；
2. 沙箱之间在共享路径（卷、workspace 父级、临时目录）上失去内核 DAC 区分，可互相删除/改名；
3. worker 上积累"不可信代码产生、属主却是 root"的文件：按 uid 审计、project-id 配额归属、
   清理逻辑全部失真。
**不是** Landlock 逃逸：`/var/lib`、`/etc` 等未授权写入仍被拒。

**复现（不依赖 E2B 代码）**

```python
import os, subprocess, tempfile
from pathlib import Path
from sandlock import Sandbox

shared = Path(tempfile.mkdtemp()); os.chmod(shared, 0o777)
def sbx(uid, denied):
    ws = Path(tempfile.mkdtemp()); os.chown(ws, uid, uid); os.chmod(ws, 0o700)
    return Sandbox(fs_writable=[str(ws), str(shared)], fs_readable=["/usr","/lib","/bin"],
                   fs_denied=denied, uid=uid, gid=uid, max_memory="256M",
                   max_processes=32, max_open_files=512, max_cpu=100, clean_env=True, cwd=str(ws))
a, b = sbx(4242, ["/dev/shm"]), sbx(4343, ["/dev/shm"])
a.run(["/bin/sh","-c",f"printf x > {shared}/a.txt; chmod 600 {shared}/a.txt; echo chmod=$?"])
b.run(["/bin/sh","-c",f"rm -f {shared}/a.txt; echo rm=$?"])
print(subprocess.run(["ls","-n",str(shared)],capture_output=True,text=True).stdout)
```

（`fs_denied=[]` 的对照组请同时新建两个沙箱，勿复用同一 `shared`，因为 A 的文件已被删。）

### 3.2 `notify_rate_limit` 假告警（Low）

`UserWarning: Policy field 'notify_rate_limit' is set but not wired through FFI` 每次建沙箱都打，
但字段**确实生效**（§2 P3）。风险是被误读成"配额/限流没起作用"。

### 3.3 T4：`net_isolation` + chroot 下 MCP 入站映射不通（Medium）

`net_isolation` + 镜像 rootfs 组合下，MCP 网关监听起不来（宿主侧映射端口整段连不上）；
纯 sandlock 形态同一套件 3/3 通过。E2B 侧 `net_isolation` + chroot 用例标 `xfail(strict=True)`。

### 3.4 wheel 与 tip 的一致性只能靠重跑自证

wheel 产物时间戳早于 tip 提交，无法从文件本身判定。已用符号核对佐证其**包含** fork 侧能力：
`sandlock_sandbox_builder_{egress_proxy,http_auth,credential,host_mask,notify_rate_limit,pid_ns,net_isolation,fd_inject_connect}`
均在 `.so` 中导出（`port_mappings` 走 `net_bind_map`，本就不是独立符号）。发布前仍应重跑
`scripts/build-sandlock-wheels.sh` 并重建 worker/测试镜像。

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

## 4. E2B 侧当前缓解（不改 fork）

- 纯 sandlock（无 chroot）形态**不再下发** `fs_denied`：这些路径本就不在 Landlock 可读白名单内，
  denial 冗余却要付 SL-1 的代价。改后实测：属主 = 沙箱 host uid、`chmod` 正常、
  跨 uid sticky 保护真的生效。落点 `envd_service/executors/sandlock.py`。
- 镜像 rootfs 形态仍保留 denial（`/dev` 必须整树挂进 chroot 才有 ptmx/devpts，见 §2 P5），
  该形态的属主问题由 `xfail(strict=True)` 跟踪，非 chroot 形态则**必须**通过。
- 测试环境补齐：容器 runner 自动 loop 挂载 XFS(`prjquota`) 并把沙箱工作目录放上去、
  `xfsprogs`/`e2fsprogs`/`nodejs`/`npm`、双形态默认同跑、`E2B_TEST_STRICT_SKIPS=1`
  把"能力型 skip"直接判失败。

## 5. 验证矩阵（最近一次，2026-09-03）

| 套件 | 结果 |
|---|---|
| E2B 全量（Linux 容器，镜像 rootfs + netns + XFS + npm + strict） | `867 passed / 1 skipped / 2 xfailed / 0 failed / 0 error` |
| E2B 全量（macOS 宿主，unit+contract+sdk python/js+security） | `813 passed / 53 skipped / 0 failed` |
| fork lib / integration / python | 历史基线 `788 / 465 / 430`（本轮未重跑） |

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
| 宿主可拿到 pid、kill、wait、pause/resume、port mappings、checkpoint | FFI `sandlock_handle_{pid,kill,wait,wait_timeout,checkpoint,free,port_mappings}` |

⇒ **不需要**三层重写（我上一版 §8 写重了）。真正缺的是"从宿主再往活沙箱里塞一个根进程并把 stdio 交出来"，
以及"实例生命周期不再等于第一个进程的生命周期"。

### 7.2 缺口（这才是改造面）

1. **`exec` verb + fd 传递**：控制协议现在只有 `config`/`ports`，且**全仓库没有 SCM_RIGHTS/sendfd**
   ⇒ 新增 `exec`（args: argv、cwd、env、额外可写、bind 端口、pty 请求）并用
   `sendmsg/recvmsg + SCM_RIGHTS` 把 stdin/stdout/stderr（或 pty master）三个 fd 传回宿主。
2. **实例生命周期解耦**：`wait()` 的收尾会 abort notif/throttle/loadavg/**control listener**、
   清控制目录、关 DNS 网关（`sandbox.rs:1050-1086`，`control_handle` 见 :1065/:3123）
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

### 7.6 需要 E2B 同步做的

instance 持有与释放时机（delete/kill/migrate/evict/worker 重启）；`_build_sandbox` 的 per-command
字段改走 `exec` 参数；`max_processes` 默认与容量联动（S1）；`update_network` 按 S2 落地并改契约测试；
`command-logs.jsonl` 与 SL-1 复测（S6）；`docs/SCALING.md`、`resource-contention.md` 里
"按沙箱预留 = 按实例核算"的一致性说明随之关闭 §3.8。
