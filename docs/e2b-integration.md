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
| **P9** ✅**已采纳，见 §7** | 支持**一沙箱一实例**：`Sandbox.spawn(cmd, cwd=None, env=None) -> Process`（不占用"单活进程"busy 标记、每个 Process 自持 handle、并发上限由 `max_processes` 内核核算）+ per-exec `cwd`/`env` 覆盖（见 §3.7 评估） | 中（做进程级 checkpoint / 开 `pid_ns` 的前置） | E2B 当前不需要，故未催 |
| ~~P10~~ ⊘被 §7 取代 | ~~跨实例的共享资源组~~：一旦 §7 落地，记账边界即沙箱边界，无需组对象；仅作为 §7 不可行时的退路保留：内存/CPU/进程数目前按 `Sandbox` 实例各自记账（`brk`/`mmap` 的 USER_NOTIF 记账挂在实例的 `ctx` 上），同一沙箱的 N 个并发命令 ⇒ N 份配额。希望提供"调用方给一个 resource-group id，多个 Sandbox 共享同一份内存/CPU/进程核算"的能力（见 §3.8 实测） | 高（多租户 QoS/超卖） | E2B 侧可先用 per-sandbox cgroup 兜，但记账与 `max_memory` 语义不一致会持续踩坑 |

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
快照是文件系统拷贝）、真正的沙箱级并发进程核算。因此把正确切法记为 **P9**（已于 §7 采纳为实施方案）：
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

## 7. 采纳方案：每沙箱一个实例（Instance 化改造）

> 决策（2026-09-03）：确定按"一个 E2B 沙箱 = 一个 sandlock 实例 = N 个并发子进程"实现，
> 取代 P10（共享资源组）。目标不是省那几毫秒，而是让**执行边界 = 产品边界**：
> 内存/CPU/进程数/冻结/身份自然归沙箱，超卖问题（§3.8）从根上消失。

### 7.1 验收标准（做到什么算完成）

1. 同一沙箱内 K 条并发命令共享**一份** `max_memory`/`max_processes`/`max_cpu` 预算：
   §3.8 的"网关 + 一条命令各 450M ⇒ 900M"必须变成第二个申请被拒。
2. 命令之间互不干扰：任一命令 kill/崩溃/超时不影响同沙箱其它命令（除显式沙箱级操作）。
3. E2B 现有全部语义保持：每命令独立 `cwd/env`、独立 stdio/PTY、独立 stdin 通道、
   `update_network` 语义有明确定义（见 Q6，必须先定）。
4. 无泄漏：最后一个子进程退出/沙箱删除/迁移/驱逐后，instance 的 runtime、FD、控制目录、
   tokio 线程全部回收（worker 长跑 24h 无 FD/线程增长）。
5. 命令首字节 p50 ≤ 现有 8.1ms（`tests/perf` 预算收紧为 8ms 防回退）。

### 7.2 现状事实（改造的根据，逐条带坐标）

| 事实 | 坐标 |
|---|---|
| 每次 `create/popen` **新建 Sandbox 对象 + 新建 tokio runtime**：`prepare()` → `policy.clone().with_name()` | `sandlock-ffi/src/lib.rs:1309-1326`、`build_live_runtime` |
| 运行时状态是**单槽**：`child_pid`、`leader_pid`、`_stdin_write`、`_stdout_read`、`_stderr_read`、`state: RuntimeState` | `sandlock-core/src/sandbox.rs:292,299,307,308,317` |
| `Process<'a> { sandbox: &'a mut Sandbox }`：借用互斥 ⇒ 结构上只能有一个活子进程；`take_stdin/take_stdout` 直接读写沙箱级槽位 | `sandbox.rs:3022-3045` |
| `ResourceState`（`mem_used/proc_count/peak_*/hold_forks/held_notif_ids/load_avg`）在**每次 create 路径里 new** | `sandbox.rs:1829`(`do_create_stdio`)→`2809`，赋值 `2868` |
| 沙箱级操作全部锚在 `leader_pid.or(child_pid)`：pause/resume/stat/throttle | `sandbox.rs:890-895,1375-1404` |
| 名字即身份：控制目录 `sandbox_dir(name)`，冲突时用 `kill(pid,0)` 判活，判死就 `remove_dir_all` 抢占 | `control.rs:126-148`；`sandbox.rs:2486-2506` |
| `wait()` 收尾会 abort notif/throttle/loadavg/control 任务、清控制目录、回收 COW 分支、关 DNS 网关 ⇒ 全是"沙箱级"动作 | `sandbox.rs:1050-1086` |
| CPU 限流是每实例一个采样任务，作用于 `group_pid` | `sandbox.rs:2969-2972` |
| 限额的 live 通道只有 `max_memory`（`PolicyFnState.live_policy` 的 `grant_/restrict_max_memory`），网络/Landlock 无在线更新 | `policy_fn.rs:213-241`、`resource.rs:676-683` |

⇒ 结论：这不是"去掉 `_check_not_running`"级别的改动，而是要把 **Policy / Instance / Child 三层拆开**。

### 7.3 目标架构

```text
SandboxPolicy   （不可变配置：fs/net/limits/uid/chroot/egress…，可 clone，无运行时）
      │ build
SandboxInstance （长命，= 一个 E2B 沙箱；Send+Sync；持 tokio runtime、notif listener、
      │           ResourceState、PolicyFnState、NetworkState、控制目录/身份 token、
      │           DNS 网关、COW 分支（沙箱级）、child table）
      ├── Child #1  （pid、每子进程 stdio 三端、cwd/env 覆盖、RuntimeState、ProcessIndex 项）
      └── Child #n  （并发上限由 ResourceState.max_processes 内核化核算）
```

- `Instance::spawn(cmd, SpawnOpts{cwd, env, stdio, extra_writable, bind_ports}) -> Child`
- `Instance::kill_child(id, sig)` / `Child::wait()`；`Instance::freeze()/thaw()/checkpoint()`
  为**沙箱级**（跨全部 child），`Instance::shutdown()` 幂等并回收。
- 引用计数：child 表空 ⇒ instance 进入 idle；E2B 侧决定 idle TTL（建议：保留预算但释放
  listener/线程，或干脆立即 free，由 §7.6 的 M1 先取"立即 free"）。

### 7.4 API 形状

| 层 | 新增 | 保留 |
|---|---|---|
| Rust core | `SandboxInstance`、`Child`、`SpawnOpts`；`ResourceState` 提升为 instance 字段；child 表 + 每 child 的 stdio/pid/state | `Sandbox`（改名 `SandboxPolicy` 或保留别名），单命令 `run()` 走"临时 instance" |
| FFI | `sandlock_instance_new/free`（refcount）、`sandlock_instance_spawn`、`sandlock_child_wait/kill/take_stdio/resize`、`sandlock_instance_stats`、`sandlock_instance_update_limits` | `sandlock_popen/create/start/wait`（内部退化为"一次性 instance"）⇒ ABI 不破 |
| Python | `SandboxInstance(policy)` + `.spawn()` → `Process`（自持句柄）；`Process` 不再是 `&'a mut Sandbox` | `Sandbox.run()/popen()` 现语义不变 |
| CLI/profile | `sandlock-cli` 不变；profile TOML 可选新增 `identity.mode = per_sandbox` | — |

新字段一律登记进 `_HANDLED_FIELDS`（顺带补 SL-2 漏掉的 `notify_rate_limit`）。

### 7.5 问题点清单（全部要在实施前定/修，按优先级）

| # | 问题 | 影响 | 决定/建议 |
|---|---|---|---|
| Q1 | 单槽 child/stdio/状态 + `Process<'a>` 借用模型 | 不改就无法并发；`take_stdin` 等会串台 | 全部 per-child 化；`Child` 自持 fd 与 handle（P0） |
| Q2 | runtime/listener 目前每 create 新建 | 提升到 instance 后要 `Send+Sync` + 内部锁；单 runtime 卡死拖全部命令 | instance 持一个 multi-thread runtime；notif handler 加超时与看门狗（P0） |
| Q3 | **pid_ns 下 ns pid 1 = 首个子进程**：它退出即销毁整个 pid namespace ⇒ 连带杀死同沙箱其它命令 | 开 `pid_ns` 后是致命语义 | M1 明确**不支持共享 pidns**；要支持则引入沙箱内 reaper/init（instance 先 fork 一个 ns pid 1），并复测 freeze/stat（P0，须早定） |
| Q4 | freeze/checkpoint 是单进程语义（`hold_forks`、单 address space） | 沙箱级冻结才满足一致快照；单 child checkpoint 会**静默只存一条命令** | checkpoint 要么扩展为多进程，要么在 child>1 时**显式报错**，禁止静默降级（P0） |
| Q5 | `cwd/env/extra_writable/bind_ports` 现在是策略字段，而 E2B 每命令都不同（PTY 要 `/dev/ptmx,/dev/pts`；MCP 要 `net_allow_bind`） | 不解决就只能每命令重建实例（回到原点） | 提供 `SpawnOpts` 覆盖：per-spawn `cwd`/`env`（execve 前 chdir + envp，保留 `clean_env` 语义）、per-spawn 额外可写与 bind 端口（P0） |
| Q6 | **`update_network` 语义改变**：现在"下一条命令生效"是免费得到的；实例常驻后策略属于 instance | 不定清楚会出现"改了网络策略但已在跑的 child 不变"或"改策略必须杀全部命令" | 三选一，需 E2B 拍：(a) 新增 `instance.update_net_policy()` 在线生效（Landlock 只能加不能撤，deny→allow 方向做不到）；(b) 新 child 用新策略、老 child 保持（要求 per-child 网络视图，改动大）；(c) 改策略即优雅 drain（等 child 结束）并回报生效延迟。**建议 (c) + 文档化**（P0，最需早定） |
| Q7 | 名字成为身份：`kill(pid,0)` 判活会被 **pid 复用**骗过 ⇒ 误删活沙箱控制目录（两 worker/重启竞态） | 可用性/安全（别人的沙箱目录被清） | 目录内加身份校验（supervisor 启动写 token + `/proc/<pid>/stat` starttime），冲突时**拒绝**而非抢占（P1，但简单必做） |
| Q8 | 生命周期与泄漏：今天进程退出即回收，改后要显式 free | FD/线程/目录堆积；worker 长跑必炸 | instance refcount + E2B 侧 delete/kill/migrate/evict/restart 全路径释放；加"最后一次 child 退出且 idle 超时"兜底 reaper；用 `E2B_TEST_STRICT_SKIPS` 那套环境跑 24h 泄漏测试（P0） |
| Q9 | 爆炸半径：一个 listener/runtime 服务全部命令，panic 或卡死影响整箱 | 从"一条命令失败"变成"整个沙箱失败" | 定义失败策略：handler panic ⇒ 标记 instance dead ⇒ E2B 见 503 后重建沙箱；禁止静默重启 listener（P1） |
| Q10 | **`max_processes` 语义收紧**：现在每命令 64（K 条命令共 K×64），改后整箱 64 | 现网可能立刻出现"多开几条命令 fork 失败" | 迁移时把默认从 64 提到能覆盖真实并发（如 256），并在 E2B 侧按沙箱显式配置；变更写进 release note（P0，回归风险最大项） |
| Q11 | SL-1 交互：chroot 形态 `fs_denied` 的代打开使文件属主变 root，实例常驻后从"每命令"变成"整箱生命周期"，worker 写的 `command-logs.jsonl` 与沙箱写的文件混在同一生命周期里 | 日志/配额归属更难查，问题被放大 | instance 化前先把 §3.1（SL-1 修法 P1/P2）落掉，或至少先去掉非 chroot 形态的 denial（E2B 已做）（P1） |
| Q12 | 兼容与 ABI：三层拆分是破坏式重构 | 现有 CLI/测试/其它语言绑定会碎 | 旧 `sandlock_popen/run` 内部实现为"一次性 instance"，新 API 并行提供，至少一个版本周期不删（P1） |
| Q13 | 多阶段流水线（`SharedCow`）与 stage 归属：stage 是 child 还是 instance？ | 事务性 pipeline 语义会变（分支提交粒度） | 明确：COW 分支属 instance（沙箱级），stage 属 child；`shared_cow` 现逻辑迁移时逐项复测（P1） |
| Q14 | 性能：锁竞争、单 runtime 调度 | 命令延迟可能不降反升 | 保留 §3.7 探针为基准（fresh 8.11ms / reused 7.48ms p50），M1 起纳入 CI 预算（P2） |
| Q15 | 测试面（真正的大头） | 并发/信号/stdin 死锁/泄漏都得新写 | 见 §7.7；fork 侧先绿，E2B 侧再切开关（P0） |

### 7.6 分期实施

- **M0 拆分（无行为变化）**：`SandboxPolicy` 与 `SandboxInstance` 分离，instance 内部仍"一个 child"；
  旧 API 走 `instance` 一次性包装。验收：fork 三套测试全绿（lib 788 / integration 465 / python 430）+
  E2B 全量不变（867 passed / 1 skipped / 2 xfailed）。
- **M1 child 表 + per-child stdio/状态 + `SpawnOpts.cwd/env`（Q1、Q5）**：仍不并发暴露（内部支持，
  外部只允许一个 child）。验收：单测覆盖 child 表增删、fd 归属、`wait` 幂等。
- **M2 开放并发（Q2、Q8、Q9、Q10）**：`spawn` 可并发；instance 生命周期与 reaper；
  `max_processes` 沙箱级并调默认值；泄漏测试。验收：§7.1 第 1/4/5 条。
- **M3 沙箱级操作（Q3、Q4、Q6、Q13）**：freeze/checkpoint/网络策略语义落地（含 pid_ns 的
  reaper 方案或明确不支持），与 §3.1 的 SL-1 修法联动。验收：§7.1 第 3 条 + Q4 不静默降级。
- **M4 E2B 接线**：`SandlockExecutor` 持 instance（沙箱级）+ child 映射到 pid；`update_network`
  按 Q6 决定实现；控制目录身份校验（Q7）。验收：E2B 全量 0 failed，§3.8 探针必须变成"第二个被拒"。

### 7.7 测试矩阵（实施即按此补齐）

fork：并发 spawn 的记账（内存/CPU/进程数）、child 退出归还、kill 路由正确性、单 child panic 隔离、
`wait` 幂等/双 wait、stdin 关闭死锁（`Process::take_stdin` 注释的情形要 per-child 复现）、
checkpoint/freeze 多 child、pid_ns reaper、控制目录身份抢占拒绝、24h 泄漏（FD/线程/目录计数）、
旧 API 回归（证明不破坏）。
E2B：`tests/sdk/python/test_commands.py`（并发/后台/connect/kill/超时）、`test_pty.py`、
`test_mcp.py`（网关与用户命令并发）、`test_features.py`（卷 + 配额）、`tests/security/*`
（属主/SL-1 断言）、`tests/perf`（首字节预算 8ms）、§3.8 超卖探针转**断言**。

### 7.8 需要 E2B 侧同步做的

`SandlockExecutor` 从"无状态工厂"变成"每沙箱一个 instance 的持有者"（含 free 时机：delete/kill/
migrate/evict/worker shutdown/异常重启）；`_build_sandbox` 里 per-command 的策略字段改为 `SpawnOpts`
（PTY 可写集、`net_allow_bind`/MCP 端口）；`max_processes` 默认值与调容量联动（Q10）；
`update_network` 落地 Q6 的选择；控制目录名用 e2b `sandbox_id` 并配身份 token（Q7）；
`command-logs.jsonl` 与 SL-1（Q11）复测；`docs/SCALING.md` 与 `resource-contention.md` 的
"按沙箱预留 = 按实例核算"一致性说明（§3.8 那条随之关闭）。

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

## 6. 同步约定

1. 本文是 sandlock 侧的唯一事实源；E2B 仓库 `docs/sandlock-upstream-issues.md` 退化为编号索引
   （SL-1 / T4 / T5 → 本文对应小节）。
2. fork 修复后，请在本文把条目状态改为"已修（commit/PR）"，E2B 侧的 `xfail(strict=True)` 会
   因 XPASS 立刻失败，提示摘除标记与恢复断言。
3. 编号沿用：`SL-*` = fork 缺陷，`T*` = E2B 待办，`R*/S*/E*/M*` = 已落地方案编号。
