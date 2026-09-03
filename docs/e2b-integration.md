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
