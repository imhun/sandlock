# per-sandbox 网络隔离方案 1：loopback netns + supervisor fd 注入

## 1. 目标与背景

当前所有沙箱共享 worker 的网络命名空间（共享 netns），网络隔离依赖
每进程出站策略（seccomp + Landlock）。目标：**无特权运行下实现
per-sandbox 内核级网络隔离**（独立 loopback / 端口空间 / 沙箱间不可见），
同时不牺牲数据面性能。

约束：

- worker/supervisor **无特权运行**（sandlock 支持 uid 65534）；
- 不用 veth/CAP_NET_ADMIN（方案 3 预置池在无特权下不可行）；
- 数据面尽量走内核（不做用户态逐字节转发）。

## 2. 核心设计：loopback netns + 宿主建连 + fd 注入

```
沙箱（独立 netns，只有 loopback）         supervisor（宿主 netns，无特权）
─────────────────────────────            ────────────────────────
connect(目标) ──seccomp 通知──▶ 判定策略 → 宿主建 socket + connect 目标
   │                                              │
   │◀────────── inject_fd_and_send（ADDFD）────────┘
   │        （已连接的 fd 注入沙箱，connect 返回成功）
   │
   └──▶ read/write 该 fd：数据面走内核，无用户态拷贝
```

关键机制：`SECCOMP_IOCTL_NOTIF_ADDFD` 把 supervisor 在宿主 netns 建立的
已连接 socket 注入沙箱进程（sandlock 已有 `inject_fd_and_send`，
`crates/sandlock-core/src/seccomp/notif.rs:948`）。沙箱进程直接读写注入的
fd——**数据面保持内核直连**，只有连接建立经 supervisor。

## 3. 无特权论证（逐项）

| 操作 | 特权要求 | 无特权下如何满足 |
|---|---|---|
| `unshare(CLONE_NEWNET)` | userns 内无需特权 | 沙箱先 `unshare(CLONE_NEWUSER)` 再建 netns（rootless 容器同款）✓ |
| `lo up` | 对自有 netns 需 CAP_NET_ADMIN | 新 netns owner userns = 沙箱 userns，沙箱在 userns 内是"根" ✓ |
| supervisor 宿主建连 | 无 | 普通用户可 connect ✓ |
| ADDFD 注入 | 对目标有 ptrace 权限 | supervisor 是沙箱子进程的父进程（fork 关系）✓（需 Linux 实测确认） |
| 沙箱内 DNS 网关 | bind 53 低端口 | 网关搬进沙箱 netns，由沙箱 userns 内进程 bind（userns 内持有 CAP_NET_BIND_SERVICE）✓ |
| 入站端口映射 | 无（高端口） | supervisor 宿主监听 50005+ ✓ |

附加收益：共享 netns 形态下 DNS 网关绑定 `127.0.1.x:53` 需要 root 一次性
`sysctl ip_unprivileged_port_start=0`；方案 1 网关在沙箱 netns 内，**该
sysctl 不再需要**——比现状更"无特权"。

## 4. 性能评估（实测 + 修正）

### 实测基线（OrbStack VM 回环，iperf3 单流）

| 路径 | 吞吐 | 说明 |
|---|---|---|
| 内核直连 | 54.9 Gbps | 当前共享 netns 数据面 |
| 用户态转发（asyncio） | 6.85 Gbps | 错误建模参考（不适用 fd 注入） |
| 用户态转发（socat） | 11.2 Gbps | 同上 |
| slirp4netns | 1.56 Gbps | 方案 2 |

### 修正：fd 注入版数据面 ≈ 内核直连

早期评估误以为方案 1 = 用户态数据转发（read/write 循环），实测 7-11 Gbps。
实际上 ADDFD 注入后沙箱直接读写内核 socket，**数据面无用户态拷贝**，
吞吐预期接近内核直连（54 Gbps 级别，需 Linux 实测确认）。

延迟实测（echo 往返）：用户态代理/slirp 增量 <0.2ms（回环噪声级），
真实网络场景可忽略。fd 注入版仅在连接建立时增加"宿主建连 + 注入"
（每连接一次，长连接/连接池无感）。

### PoC 实测（2026-09-01，OrbStack 容器，非 root uid 1000）

最小验证程序 `tmp/addfd_probe.c`：父进程 seccomp listener + 子进程
`unshare(CLONE_NEWUSER|CLONE_NEWNET)` + connect 通知 + 宿主建连 +
`SECCOMP_IOCTL_NOTIF_ADDFD` 注入 + 数据面测试。结果：

| 验证点 | 结果 |
|---|---|
| 无特权 `process_vm_readv`（父读 userns 子进程内存） | ✅ 成功 |
| 无特权 ADDFD 注入（宿主 fd → userns 子进程） | ✅ 成功 |
| 注入 fd RTT | **0.006 ms**（200 轮，纯内核路径） |
| 注入 fd 双向吞吐 | **~14 Gbps**（受 echo server 单线程限制，无用户态拷贝） |

实现要点（PoC 发现）：

- `SECCOMP_ADDFD_FLAG_SEND` 让被拦截 syscall **返回注入的 fd 号**
  （connect 返回 fd 号而非 0）——connect handler 需按此语义适配；
- 父进程不能安装自己的 seccomp filter（会拦截自身的宿主 connect 造成
  死锁）；listener fd 由子进程创建后经 `SCM_RIGHTS` 传给父进程
  （sandlock 现有 notif-fd 传递机制同款）。

## 5. 改动清单

### sandlock fork（核心，中-大）

1. connect handler：`connect_on_behalf`（代连沙箱 fd）→ 宿主建连 +
   `inject_fd_and_send`；
2. 沙箱创建路径：`unshare(CLONE_NEWNET)` + `lo up`；
3. DNS：getaddrinfo 通知解析（沙箱 netns 内 127.0.1.x 网关不可用，
   DNS 网关搬进沙箱 netns 或走通知/转发）；
4. UDP：connected UDP 可注入；无 connect datagram 复用现有 on-behalf
   send 路径；
5. 入站端口映射（可选）：supervisor 宿主监听 → accept → 注入；
6. 与 egressProxy / HTTP 代理 / 通配域名路径集成与回归。

### S2.2 已落地（2026-09-01）：`SandboxBuilder::net_isolation`

- 新开关 `net_isolation(true)`（默认 `false`）：沙箱 spawn 路径在 userns
  之后 `unshare(CLONE_NEWNET)`，进入独立 netns（仅 loopback）；`lo up`
  由沙箱 userns 内进程通过 `SIOCSIFFLAGS` 完成（新 netns 的 owner userns
  即沙箱 userns，无需父命名空间特权）。默认 `false` 保持共享 netns 无特权
  路径，全量回归零破坏。
- 与 S2.1 `fd_inject_connect` 的关系（两开关互相独立）：
  - `(false, false)`：默认共享 netns + legacy dup 代连（现状，回归保障）；
  - `(false, true)`：共享 netns + fd 注入（S2.1）；
  - `(true, false)`：loopback-only 沙箱——外部 IP connect 在内核层失败
    （沙箱 netns 无路由），语义正确、不逃逸；
  - `(true, true)`：方案 1 完整路径——沙箱 connect 走宿主建连 + ADDFD
    注入；注入路径的 dup 回退在 `net_isolation` 下失效（dup 的 socket 在
    沙箱 loopback-only netns，永远到不了目标），改为 fail-closed
    `ECONNREFUSED`，绝不静默降级。
- 通配域名受限（待 S2.3）：共享 netns 的 `127.0.1.x:53` DNS 网关在
  netns 沙箱内不可达；`net_isolation` + 通配域名规则在 spawn 时 fail-fast
  报错（"restricted until the in-netns DNS gateway lands (S2.3)"），默认
  路径不受影响。
- netlink 视图：netns 沙箱仍走 NETLINK_ROUTE 虚拟化，但合成视图为
  loopback-only（去掉共享 netns 模式的虚拟 eth0），`ip addr` 只见 lo，
  与真实内核视图一致；send/recv 安全中介路径保持不变。

### E2B 侧（小-中）

- MCP/gateway 到沙箱内 MCP 的路径适配（E7.1 已落地：S2.5 入站映射 +
  poll/epoll 可读性合成，事件循环型 server 也能被外部连接唤醒）；
- 网络配置透传（策略判定逻辑不变；E7.2 已落地：
  `E2B_ENABLE_NET_ISOLATION` / `E2B_FD_INJECT_CONNECT` / `E2B_PORT_MAPPINGS`
  默认关闭，MCP 端口在 netns 下自动做恒等映射）；
- 全量 SDK/安全测试回归（E7.2/E7.3 已落地：默认形态零回归，netns 开启
  形态全绿；注入 connect 改为返回 0，CPython `socket.connect()` 兼容）。

## 6. 风险清单

1. **fd 注入语义**：沙箱内 `getsockname/getpeername` 看到注入 fd 的宿主侧
   地址而非目标地址——依赖本地地址的程序错乱；
2. **入站/监听**：沙箱内 listen 的服务器无法被外部直连（需端口映射，
   E2B 场景低需求但 MCP 要验证）；
3. **UDP/ICMP 边缘**：无 connect 的 UDP datagram、组播/广播受限；
4. **回归面大**：DNS 合成、通配域名、HTTP MITM、egressProxy、网络策略
   更新等现有特性全部要适配；
5. **连接建立频率**：高频短连接场景（每请求新建）放大 supervisor 参与成本；
6. ~~Linux 实测点~~：ADDFD 无特权 + userns 子进程下的 ptrace 权限与 fd
   注入吞吐已在 PoC 验证通过（见 §4）；剩余需在 sandlock 集成环境确认
   connect handler 适配与全量回归。

## 7. 与方案 2（slirp4netns）对比

| | 方案 1（fd 注入） | 方案 2（slirp4netns） |
|---|---|---|
| 性能 | ≈ 内核直连（最优） | 1.56 Gbps 上限 |
| 无特权 | ✅（运行时完全无特权） | ✅ |
| sandlock 改动 | 大（connect 核心路径，2-4 周） | 小（策略叠加验证，1-2 周） |
| 风险 | fd 语义 / 入站 / UDP / 回归面 | 吞吐上限、每沙箱进程 |
| 适合场景 | 高带宽/性能敏感 + 可接受核心改造 | 轻量流量 + 快速落地 |

## 8. 结论

- **无特权 + 高性能 + per-sandbox 内核级网络隔离**三者兼得的唯一路线是
  方案 1（fd 注入版）；
- 真实性能代价远小于早期估计（数据面 ≈ 内核直连），复杂度集中在
  sandlock 最核心的 connect 路径；
- 若性能可放宽 → 方案 2（slirp）快速落地；若性能是硬需求且可接受
  sandlock 核心改造周期 → 方案 1。

## 9. 相关

- 实测脚本：`tmp/proxy_bench.py`（用户态转发参考）、`tmp/rtt_client.py`
  （延迟）；吞吐/延迟实测记录见对话 2026-09-01。
- 方案 2 评估与共享 netns 现状见 `docs/security-hardening.md` 与
  `docs/upstream-pr-netns-free.md`。
