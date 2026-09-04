# 每沙箱一实例：给 sandlock 实例加 `exec` 的深度分析

> 日期 2026-09-04。承接 `e2b-integration.md` §3.7（一沙箱一实例评估）、§3.8（按实例核算导致超卖）、
> §8（采纳方案与缺口清单 P9）。§8 回答的是"要改哪些地方"，本篇回答 §8 没回答的三个问题：
>
> - **(a) `exec` 的机制到底是什么 —— 有现成实现吗？**（有：`crates/sandlock-oci`）
> - **(b) 复用一个长命实例会新开哪些攻击面？**（12 条，其中 2 条是现状代码里的真实缺陷）
> - **(c) 会话生命周期到底谁管、按什么状态机管？**

## 0. 结论摘要

1. **机制不用从零设计。** `crates/sandlock-oci` 已经跑通了完整的"一实例多进程"骨架：
   受限的 in-sandbox PID-1（`sandlock-init`，`create_with_in_child_main` 不 execve 直接跑循环）
   + 一条宿主↔init 的 socketpair 控制通道 + `RunMain`/`RunExec`/`Shutdown` 协议
   + `SCM_RIGHTS` 传 3 个 stdio fd + 按 pid 路由 `Exited{code,signal}`。
   ⇒ 真正的工作是**把这套机制从 OCI crate 上提成 `sandlock-core` 的一等实例 API**（再过 FFI/Python 到 envd），
   不是发明它。§7.1/§7.2 里"全仓库没有 SCM_RIGHTS"的判断是错的，已订正。
2. **收益的主体不是延迟，是边界正确性。** 实测复用实例只省 ≈0.6 ms/命令（≈8%，§3.7），
   但 §3.8 的按实例超卖（默认配置 1.76x，闸口 N → ≈(N+1)x）从根上消失，
   准入/计费/驱逐/E9 空闲检测的"按沙箱预留"与内核"按实例核算"终于一致；
   `pid_ns`、进程级 checkpoint、真实沙箱级并发核算这些能力也才有承载体。
3. **代价是三处功能回退 + 一类新回退。** 功能回退：组级 `kill`/`freeze`（§8 已记）、单槽 `wait`、
   per-exec 策略字段。新回退（§8 没展开）：**今天互不可见的兄弟命令，合并之后同 uid、同 pid 空间、
   同一条宿主控制 socket** —— 沙箱内隔离从"实例边界"塌到"内核 DAC 边界"。
4. **三个必须在接线前修掉的 fork 侧缺陷**（都是 `sandlock-oci` 现状代码，非推测，见 §4.1/§4.2/§4.13；
   该 crate 今天不在 E2B 部署路径上，风险在于 §7 M1 下沉时原样带进来，见 §4.0）：
   - **SL-4（High，已运行时证实）**：控制通道映射成 fd 3，core 的 `extra_fds` 用 `dup2` 落位
     把 `FD_CLOEXEC` 清掉 ⇒ **每个沙箱进程都继承这条宿主↔init 控制 socket**（`O_RDWR`、
     `fdinfo flags: 02`）。fd 3 是 **init 的同一端** ⇒ 沙箱写它 = **向宿主 daemon 注入伪造应答**：
     实测一条伪造 `Exited` 让宿主 `exec` **返回 0 而目标进程仍在运行**；未知 pid 的 `Exited`
     被永久塞进 `early_exits`（无上限、无清理）⇒ 60k 帧使 supervisor **RSS +5.3 MB 且功能照常**。
     （原稿"沙箱可发 `Shutdown` 打死整箱"**已被实测否证作废**，见 §4.1 / §10）
   - **SL-5（Medium）**：`run_init` 在 JSON 解析失败 / EOF / `RunMain` 分支上**不关闭收到的 fd**，
     也不校验请求来源。与 SL-4 叠加 = 沙箱内进程可制造 init 的 fd 泄漏，
     并把宿主侧 stdout 管道永久吊住（EOF 再也不来 → 会话挂死）。
   - **SL-6（Medium-High）**：`run_init` 只按特定 pid `wait_exit`，无 `waitpid(-1)` 兜底 ⇒
     ns PID 1 不收养孤儿 ⇒ 容器内 `<defunct>` 堆积，且这些进程的 `proc_count` 记账**永不归还**（§4.13）。
5. **一条结构性约束决定 API 形状**：Landlock 与 seccomp 都只能**加严**，一个已经受限的进程
   不可能通过"再来一次 exec"获得更宽的权限。所以 per-exec 参数天然只能**收窄**；
   放宽必须在**实例创建时定死上限**，越界的 exec 请求必须**显式拒绝**（返回错误），
   绝不可以"用实例默认"糊过去 —— 后者是 fail-open。
6. **生命周期必须由 E2B 显式接管。** 今天"实例生命周期 = 第一条命令的生命周期"，所以
   `进程退出即回收` 是免费的：listener、DNS 网关、控制目录、fd、预算全部随实例走。
   合并之后这些回收全部要有所有者、要有幂等 `shutdown()`、要有 idle 兜底，并且要能测。
7. **本机就是可实测环境**：OrbStack 内核 `7.0.14-orbstack`、`landlock_abi_version() == 8` ⇒
   README 那条"macOS Docker Desktop 内核不满足、不得作为 Sandlock 验收环境"的限制
   **不适用于 OrbStack**（只有 XFS prjquota 类用例仍不可用：容器内无 `/dev/loop-control`）。
   本文 SL-4 的结论全部来自本机实跑，命令与输出见 §10。
8. **放行门槛建议（两轮实测后已加长）**：SL-4（控制 fd 继承）、SL-6（孤儿无回收）、**SL-7（控制协议无鉴权，
   实测跨箱 `config` 成功）**、**SL-8（`proc_count` 无退出兜底，实测可累加）** 四项修复，
   加上组级 kill/freeze 拆成 per-child（**实测沙箱内可主动打死整箱**），
   这五项没落地就不要在 E2B 侧开 `exec`（§7）。

> **三轮实测后的四处改口**（原文保留 + 标注，避免后人重复推错）：
> ①"沙箱可用继承的 fd 3 发 `Shutdown` 打死整箱" **否证作废**（方向是宿主读端，§4.1）；
> 但同样的后果**由 `killpg` 实测成立**（§4.6，纯内核语义）；
> ②"与 init 抢读宿主请求偷 stdio fd" **未复现**（§4.1 表），从 High 可实现下调为理论可能；
> ③"共享 notif 循环导致跨命令拖死" 实测净增量只有 **~5%**（§4.8），B6 下调为 Low-Medium。
> ④"root 替你读兄弟 `/proc/cmdline`"（SECE-4）**当前形态不成立**（实测全 EACCES + ptrace EPERM +
> `/proc` 不可枚举），只在按 S8 打开 `pid_ns` 后成立 ⇒ 改挂到 S8 决策下（§4.4 / §4.15）。
> 同时新出三条实测确认：**跨沙箱 control.sock 无鉴权读取成功**（§4.10）、
> **`proc_count` 可累加泄漏**（§4.7）、**`delete` 后 setsid 孤儿仍能用已打开的 fd 写入**（§4.14）。

## 1. 机制：exec 到底怎么进一个活实例

### 1.1 现状（一命令一实例）

```text
envd_service/executors/sandlock.py:701  start()
  └─ :717  sb = self._build_sandbox(config)     ← 每条命令重新构造完整策略
  └─ :718  sb.popen(...)                        ← fork + userns + 装 seccomp/Landlock
                                                  + pidfd_getfd(notif fd) + 起 notif 循环
                                                  + 起 DNS 网关 + 建控制目录/socket + 起 drain 任务
```

`Sandbox` 一次只能有一个活子进程是**绑定层**的限制，不是内核限制：
`python/src/sandlock/sandbox.py:670 _check_not_running`（"sandbox is already running"）。
supervisor 侧早就是多进程结构 —— `ProcessIndex` 按 `PidKey{pid, start_time}` 登记整个进程树
（`seccomp/state.rs:166-235`、`resource.rs:85 handle_fork`、`notif.rs:2673 spawn_pid_watcher`）。
⇒ **核算与拦截这一层不用动**，缺的是"宿主再往活实例里塞一个根进程"的入口。

### 1.2 唯一正确的实现姿势：受限 PID-1 + fd 传递

要在同一个实例里跑第二条命令，只有两条路，其中一条是错的：

| 路线 | 结论 |
|---|---|
| 宿主再 `fork()` 一个新子进程、重新装一遍同一套策略、把它挂到旧 notif fd 上 | **不可行**。一个 task 只能有一个 `SECCOMP_FILTER_FLAG_NEW_LISTENER`（`sandbox.rs:613` 注释），新子进程无法把自己的 notif 交给旧循环；而且它会有一段**未约束窗口**（fork→装 filter 之间），并把 COW/chroot/DNS/端口的实例级状态复制成两份 |
| 让**已经在实例内的进程**（受限 init）`fork()+execve()` 新命令 | **可行且唯一**。seccomp filter 与 Landlock domain 沿 fork/exec 继承 ⇒ 新命令从第一条指令起就在同一监督下，**没有未约束窗口**；stdio 用 `SCM_RIGHTS` 从宿主递给 init，init `dup2` 到 0/1/2 |

sandlock-oci 选的就是第二条，而且顺手解决了"init 自己不能被 execve（Landlock 要授权 execve，而 init 没有镜像路径）"这个鸡生蛋问题：
`create_with_in_child_main(name, extra_fds, entrypoint)`（`sandbox.rs:1349-1372`）让受限子进程
**在进程内跑 init 循环而不是 exec 一个二进制** —— "nothing is exec'd，Landlock has no execution to authorize"。

```text
宿主 (envd / OCI daemon)                      沙箱内
  │  UnixStream::pair()  ── child end → fd 3 ──┐
  │                                            ▼
  ├─ RunMain{argv,env,cwd} ─────────────►  sandlock-init (ns pid 1)
  │       + SCM_RIGHTS[stdin,out,err]        │  fork() ×N   ← filter/Landlock 自动继承
  │  ◄─ Started{pid}                         ├─ execvp(argv) ──► 命令 A（组/会话见 §4.6）
  │  ◄─ Exited{pid,code,signal}              │  fork() ────────► 命令 B
  └─ Shutdown                                └─ wait() reaper 线程
```

### 1.3 分层缺口（把上面这套搬到 core/FFI/Python 需要动什么）

| 层 | 现状 | 要做 |
|---|---|---|
| `sandlock-core` | 有 `create_with_in_child_main`、`extra_fds`、`control.rs` socket（只有 `config`/`ports`，`args` 字段 `#[allow(dead_code)]` `control.rs:278`）；init 循环在 **oci crate** | init 循环 + `proto` + `fdpass`/`fdrecv` 下沉到 core（或共用 crate）；`Runtime` 从"单槽"改"child 表"；`ResourceState`/listener/控制目录/DNS 网关从 `do_create_stdio()` 提到实例（§8 缺口 2/5） |
| `sandlock-core` API | `wait()` 收尾会 abort notif/throttle/loadavg/**control listener**、清控制目录、关 DNS 网关（`sandbox.rs:1061-1072`） | 新增 `instance.exec()/wait_child()/kill_child()/shutdown()`；`run/popen/spawn` 保持"一次性实例"语义不破（ABI 与既有测试不炸） |
| 进程组 | 子进程 `setpgid(0,0)`（`sandbox.rs:1579`）⇒ **一个实例一个组**；`kill`/`freeze`/`thaw` 全是 `killpg(pid,...)`（:909/:921/:933/:1381/:1396） | per-child 组（或 pidfd 定向信号）+ 实例级"所有组的集合"；见 §4.6 |
| 记账 | `proc_count` 在 `handle_fork` +1、在 **`handle_wait`**（拦截到阻塞 `wait4/waitid`）-1（`resource.rs:126-131`、`resource.rs:545-560`） | 见 §4.7：孤儿子树无人 wait ⇒ 永久泄漏 |
| FFI/Python | `sandlock_handle_wait` 等锚在 `leader_pid.or(child_pid)` 单槽（`sandbox.rs:1375/1389/1404`）；`Process.kill()` = `os.killpg(pid, SIGKILL)`（`python/.../sandbox.py:1669-1693`）；`_check_not_running`/`_reject_if_popen` | child id 化的 handle；`Process` 不再借 `&'a mut Sandbox`；`SandboxInstance.exec()` 返回自持句柄的 `Process` |
| envd | `_build_sandbox()` 每命令下发全套字段；`SandlockExecutor` 已经是**每沙箱一个对象**（天然持有者）；`_CommandGate` 默认并发 1 | executor 持实例；per-command 字段（`cwd/env/pty 的 /dev/ptmx/MCP 的 net_allow_bind`）改走 exec 参数；§8 缺口 4 |

**per-exec 字段的硬不对称**（决定 §4.3）：

- 可以 per-exec 收窄：再叠一层 Landlock ruleset（`landlock.rs:586 restrict_self` 只加不减）
  + 一层纯 BPF deny filter（不开 listener，避开"一 task 一 listener"限制）。
- **不能 per-exec 放宽**：新进程继承的是实例的 domain，任何实例外的路径/端口/目的地都拿不到。
- 想放宽只有两扇门：① 实例创建时就把上限取成所有命令的**并集**（棘轮，见 SECE-3）；
  ② 走宿主的 on-behalf 注入（`SECCOMP_IOCTL_NOTIF_ADDFD`）。②**必须**先过 `fs_denied` 与
  实例上限检查 —— 拿到 fd 就等于拿到访问，Landlock 管不到一个已经打开的 fd，
  而 `fs_denied` 恰恰是靠 on-behalf 路径中介实现的（§3.1 SL-1 同一根因）。

## 2. 收益

### 2.1 边界正确性（主收益）

| 项 | 今天（每命令一实例） | 合并后 |
|---|---|---|
| 内存/CPU/进程数 | 按实例核算 ⇒ 同沙箱 K 份预算 ⇒ **实测默认配置 1.76x 超卖**（§3.8） | 一沙箱一份预算，`max_memory` 就是沙箱的 `memory_mb` |
| 控制面准入（`_record_quota_dims()` 按沙箱预留一次） | 预留值 ≠ 实际 RSS，**OOM 先于准入判定**，E9 空闲检测/驱逐/扩缩都看着假数 | 预留与内核核算同一维度 |
| `max_processes=64`（`E2B_DEFAULT_MAX_PROCESSES`） | 每命令 64，fork 炸弹的爆炸半径 = 一条命令 | 整箱 64（**需要同时上调默认**，§8 S1） |
| 磁盘（XFS prjquota 按沙箱目录） | 本来就正确（唯一不受影响的维度，§3.8） | 不变 |

**实测（§10.2 V5，上限 512 MiB）**：同一个实例内两个 child 各申请 300 MB ⇒
**只有 1 个成功**（另一个静默被杀）；把两条命令放进**两个容器**（各自 512 MiB 上限）⇒
**两个都成功**，宿主侧实测 RSS `316608 kB + 316712 kB ≈ 600 MB`（标称 512 MB）。
⇒ §3.8 的超卖与"合并即修复"都拿到了直接证据。

### 2.2 语义保真

- **一个沙箱一台机器**：跨命令的统一 pid 空间、`ps` 能看到彼此、后台进程与命令共存 —— 这才是官方
  E2B（每沙箱一台 microVM）给 SDK 的观感。今天"每命令一实例"是在用一个 per-command 边界
  去模拟 per-machine 边界，凡是依赖"上一条命令还在跑"的行为都得靠宿主记账表硬凑。
- 平台组件（MCP 网关）与用户命令进入同一预算/同一监督：网关不再是"绕过 `_CommandGate` 的长驻实例"
  （`runtime/context.py:191` 直接 `executor.start()`），也不再单独乘一份 K。
- `pid_ns` 第一次有可用场景（今天 E2B 侧零引用，§3.7）：开了它才有"外箱 pid 不可见、
  `kill(host_pid,0)` 必 ESRCH"（`procfs.rs:1497-1542` 已有断言）与正确的孤儿回收（§4.7）。
- 进程级 checkpoint / 沙箱级 freeze 有承载体（虽然多 child 的 checkpoint 仍要先拒绝，§4.11）。

### 2.3 性能（诚实版）

实测（§3.7，N=25，容器内）：策略构建重放 0.12 ms + `run()` 8.11→7.48 ms，**省 ≈0.6 ms/命令 ≈8%**。
合并后额外省掉的每命令成本：userns/pidns 建立、`pidfd_getfd` 取 notif fd、notif 循环与
dispatch table 重建、DNS 网关起停、控制目录/socket 建删、`ChaCha8Rng`/vDSO patch 重算。
但这些在 §3.7 的测量里已经被"复用同一实例只省 0.6 ms"覆盖 ⇒ **别把性能当卖点**，
瓶颈仍在 RPC/流式管道与 `asyncio.to_thread` 调度。
（§10.2 V6 另有一组 OCI 形态数字：`exec` 54 ms/op vs `create+start+delete` 204 ms/op，
≈3.8x；但两者都被 CLI 进程自身 fork 开销支配，**不能**外推到 Python 绑定路径。）反向新增成本：每命令一次
`RunExec` 往返 + `SCM_RIGHTS`，以及 notif 循环串行化带来的队头阻塞（§4.8）。

## 3. 问题与回退清单

| # | 问题 | 证据 | 严重度 |
|---|---|---|---|
| B1 | `kill`/`freeze`/`thaw` 是 `killpg` 组级 ⇒ 一条命令超时/被杀 = **整箱（含网关）被 SIGKILL**（**已实测**，且沙箱内代码可主动触发，§4.6）| `sandbox.rs:909/921/933/1381/1396`、`python/.../sandbox.py:1669` | High（功能） |
| B2 | `wait()` 单槽 + 收尾即拆实例 ⇒ 无法按 child 等，且第一个 child 退出会把实例状态拆掉 | `sandbox.rs:1061-1072`、`:1375/1389/1404` | High |
| B3 | `cwd/env/clean_env` 是策略字段，每命令可变 | `_build_sandbox()` kwargs；§8 缺口 4 | Medium |
| B4 | 网络/凭据状态实例级，`update_network` 的"下一条命令生效"模型失效 | `envd_service/executors/sandlock.py:346`、`runtime/context.py` | Medium-High（见 SECE-5） |
| B5 | 兄弟命令互相可见/可信号/可偷 fd（沙箱内隔离塌到同 uid DAC） | 见 §4.1–§4.5 | **High（安全）** |
| B6 | notif 循环单任务串行 + `notify_rate_limit` 变沙箱级 ⇒ 跨命令拖死 | `seccomp/notif.rs:2593-2646` | **Low-Medium**（实测合并额外开销仅 ~5%，§10.2 V2；connect 黑洞路径未测）|
| B7 | `proc_count` 依赖阻塞 `wait4` 通知递减 ⇒ 孤儿子树永久 poisoning 实例配额 | `resource.rs:545-560` | **High（已实测，可累加）**|
| B8 | 多 child 的 checkpoint 无法覆盖（restore-stub 面向单地址空间） | `checkpoint/`、§8 S3 | Medium |
| B9 | 资源回收不再是免费的：fd/任务/目录/预算要有显式所有者与幂等 shutdown | 本文 §5 | High（工作量） |
| B10 | 确定性语义漂移：`random_seed`/`time_start` 的 RNG 流与 offset 从"每命令一份"变"每实例一份" | `sandbox.rs` `random_state`、`vdso::patch` | Low（E2B 未用） |

## 4. 安全分析：合并实例新开的攻击面

> 判定口径：**今天（每命令一实例）不存在、合并后出现**的才算新增漏点；已有的既有问题标"既有+放大"。
> 沙箱之间（跨租户）的边界在下面的分析里基本不变 —— 变的几乎全在**沙箱内部**，
> 但"沙箱内部"对 E2B 并不是安全边界：里面住着**平台自己的 MCP 网关**。

### 4.0 归属分级（哪些是 `sandlock-oci` 现状缺陷，哪些只在 E2B 才成立）

> 前提事实：`sandlock-oci` **目前不在 E2B 的部署路径上** —— fork wheel 只含
> `libsandlock_ffi.so` + Python 绑定（`wheels/fork/*.whl` 的 namelist），`Makefile:19` 的发布目标
> 只有 `-p sandlock-ffi`，envd 走的是 `Sandbox.popen()`（每命令一实例）。
> ⇒ 下表标 **OCI-live** 的是"那个 crate 里现在就存在、但今天没被本项目部署"的缺陷；
> 它们的真正风险在于 **§7 M1 把这套 init 下沉进 core 时会原样带过来**。

| 项 | 归属 | 说明 |
|---|---|---|
| SL-4 控制 fd 继承 | **OCI-live，已实测证实** | 主 workload 与 exec 出来的进程都带 `3 -> socket:[同一 inode]`、`flags: 02`；沙箱侧 `write(3)` 成功，宿主 `reader_task` 无条件信任并路由伪造 `Resp` |
| SL-5 收到的 fd 不关 | **OCI-live** | 同上；OCI 侧可见症状是 `exec` 的 stdio 管道被第三方持有 ⇒ 永不 EOF |
| **SL-6** 孤儿无人回收（§4.13） | **OCI-live（归因已按实测修正）** | 实测**没有 pid namespace**（容器与沙箱 `ns/pid` 同一个）⇒ 孤儿被**外层 PID 1** 收养而非 init；但 `proc_count` 泄漏照旧（唯一归还点是 `wait4` 通知，谁收养都不会通知 sandlock） |
| ~~沙箱发 `Shutdown` 打死容器~~ | **已否证，作废** | `Shutdown` 是发给 **init** 的请求，而沙箱持有的 fd 3 与 init 是**同一端**，写它进的是**宿主的读端**。实测写 `{"req":"shutdown"}` 后容器照常 running、keepalive 继续推进。真正的方向是**伪造应答**，见上一行 |
| SECE-3 per-exec 策略棘轮 | **只在 E2B** | OCI 没有 per-exec 策略参数（一个容器一份 spec），不存在放宽需求 |
| SECE-4 `/proc` 兄弟元数据、SECE-5 网络/凭据实例级 | **只在 E2B** | OCI 容器内进程同属一个信任域，且网络策略本就是容器级（匹配 OCI spec） |
| SECE-6 组级 kill/freeze、B1/B2 单槽 | **E2B 才致命** | OCI 的"主进程退出即容器结束"让组级语义刚好正确；E2B 没有主进程 |
| SECE-7 `proc_count` 只减于 `wait4` | 两边都有，**E2B 才不可逆** | 与 SL-6 同根：容器短命时泄漏随容器消失 |
| SECE-8/9 循环队头、listener 失效 | 两边都有 | OCI 也是"一个容器一个会话"，但容器内无平台组件，危害面小一档 |
| SECE-10 控制目录名 = sandbox_id | **只在 E2B** | oci 用自己的 `state_dir()/<容器 id>`（`/run/sandlock-oci` 或 rootless 的 `$XDG_RUNTIME_DIR/sandlock-oci`，`state.rs:18-50`），socket 0700；rootless 下"一个 uid = 一个租户"成立。E2B 的一个 worker uid 下住着**多个租户**，且 `/dev/shm/sandlock-<uid>` 一旦落到非 root worker 回退就同 uid 互连 |
| SECE-11 checkpoint 范围、SECE-12 fork 安全/凭据驻留 | 部分 OCI-live | `checkpoint` 是 core 能力；`init` 多线程 fork 是 OCI-live（SL-6 同一函数） |

### 4.1 SECE-1 / **SL-4（High，接线前必修）**：宿主控制 socket 泄漏进每一个用户进程

**证据链（全部现状代码）**

1. `sandlock-oci/src/supervisor.rs:341` `UnixStream::pair()` 取子端；**无论 std 的 pair 是否自带 `SOCK_CLOEXEC` 都无关紧要** —— 下一步的 `dup2` 一定清掉它；
2. `:350` `extra_fds = vec![(CONTROL_FD /*=3*/, child_ctl.as_raw_fd())]`；
3. `sandlock-core/src/sandbox.rs:2319` 在子进程里 `libc::dup2(source_fd, target_fd)` 落位 ——
   **`dup2` 的语义是清除目标 fd 的 `FD_CLOEXEC`**（core 自己在 `sandbox.rs:3310` 的注释里写明了这一点：
   "`dup2` clears `O_CLOEXEC` on the target (it survives execve)"）；
4. `sandlock-oci/src/init/mod.rs:33-72` `spawn()`：只关闭 SCM_RIGHTS 收到的 stdio fd，
   **不关 fd 3，也不给它加 `FD_CLOEXEC`**，随后 `execvp` ⇒ 用户进程带着 fd 3 活着跑起来。

**方向要先说清（我原稿写反过一次，这决定严重度）**：`extra_fds` 把 **`child_ctl`** 映射成 init 的
fd 3，所以沙箱进程持有的是 **init 那一端**。于是「写」进的是**宿主的读端**，「读」才是与 init
**抢宿主要发给 init 的请求**。两个方向的可利用性差别很大，必须分开判定。

| 能力 | 判定 | 实测 / 依据 |
|---|---|---|
| **向宿主注入伪造应答**（`{"resp":"exited","pid":N,...}`） | **已证实**（High） | 宿主 `exec` 以 **rc=0 返回，而 pid 55 仍在运行**（§10 H1）。`supervisor.rs:119-152` 的 `reader_task` 对这条通道上任何合法 `Resp` **无条件信任**并按 pid 路由。`exec` 退出码是编排系统判定任务成败的依据 ⇒ **退出码伪造** |
| **未知 pid 的 `Exited` 被永久缓存** | **已证实**（OCI Medium / 下沉后 High） | `reader_task` 的 else 分支 `early_exits.insert(pid, resp)`（`supervisor.rs:142`）**无上限、无淘汰**：60k 帧 ⇒ supervisor RSS `14336 → 19772 kB`（**+5.3 MB**）且 exec 功能照常（§10 H2）⇒ 静默增长。E2B 里这套状态属于**共享 envd worker** ⇒ 从"每容器一个 supervisor"升级成**跨租户内存 DoS** |
| **抢占 `pending` 槽**（伪造 `Started`/`Err`） | 可达性差 | `reader_task` 无条件 `pending.take()`，理论上可把在途请求配到假 pid；但洪泛实测**未打断**（宿主 8/8 exec 正常）⇒ 需要抢在 init 的真实回包之前 |
| **与 init 抢读宿主请求**（偷 `RunExec` 及其 SCM_RIGHTS stdio fd） | **未复现**，降级为"理论可能" | 攻击者 `cat <&3` 期间宿主 6/6 与 8/8 条 exec 全部正常送达、`/stolen` 为空 ⇒ **init 作为更早进入 sleep 的读者通常先被唤醒**。忙轮询或多读端可能改写结论，但**本机没打出来**，不得当已证实漏洞写 |
| **让通道永不 EOF** | 结构性 | 任何进程持 fd 3 ⇒ 宿主看不到 EOF ⇒ "通道关 ⇒ 清理 `pending`/`exit_waiters`"（`supervisor.rs:149-151`）失效；配合 double-fork + `setsid` 逃出 `killpg` 即可长期挂住 |

**为什么合并后仍会变严重**：今天控制 socket 只在单条命令存活期存在、没有兄弟进程；
合并后 fd 3 成为**整个会话内所有进程（含平台 MCP 网关）的公共 fd**，
伪造/缓存类攻击的面从"一个容器"扩到"一个沙箱的所有命令 + 宿主 worker 的共享状态"。

**必修缓解**

1. **core 修一处，全部调用方受益**：`extra_fds` 落位后立即 `fcntl(target, F_SETFD, FD_CLOEXEC)`
   （`sandbox.rs:2319`）。core 在别处本来就守这条纪律（`relocate_high` 用 `F_DUPFD_CLOEXEC`、
   `connect.rs:736-784` 专门镜像 `FD_CLOEXEC`、`sandbox/tests.rs:430` 断言 reloc fd 必带 CLOEXEC）
   ⇒ `extra_fds` 是纪律上的**缺口**，不是有意设计；
2. `run_init` 进循环先 `fcntl(ctl, F_SETFD, FD_CLOEXEC)`，并在 fork 出的子进程里显式 `close(ctl)`
   （即便宿主用旧 wheel 也挡得住）；
3. **宿主侧不能只靠"这 fd 不该在那"**：这条通道必须能识别非 init 写者 —— 宿主 `recvmsg` 带
   `SCM_CREDENTIALS` 校验 `pid == 登记的 init pid`（`SO_PEERCRED` 只给建立时凭据，**不区分后来的写者**），
   不匹配即丢弃 + 计数。这是唯一能兜住"fd 已被继承"的一层；
4. `early_exits` 加上限 + TTL，并且**只接受宿主自己登记过的 pid** 的 `Exited`（未知 pid 直接丢）
   —— 这条独立于 fd 泄漏，属宿主侧健壮性；
5. `InitLink::request()` 加**每条请求的 deadline**（`supervisor.rs:75-95` 现在持写锁 `rx.await`
   无超时 ⇒ init 不回话就永久卡住该实例后续所有 `exec/config/Shutdown`）；
6. 回归用例（本机已可跑，脚本见 §10）：沙箱内 `readlink /proc/self/fd/3` 必须失败；
   伪造 `Exited` 必须被宿主丢弃（`exec` 仍等真实退出码）；`Exited{未知 pid}` 不得改变 supervisor RSS。

### 4.2 SECE-2 / **SL-5（Low-Medium 攻击面 / 必修正确性）**：fd 不关 + 帧边界按字节流猜

`init/mod.rs:118-207` 的三条路径拿到 `fds` 却不关：解析失败（`Err(e) => send(Err); continue`）、
EOF `break`、以及 `RunMain`（忽略 fds 但没关）。`Resp::Err` 之后 fds 就漏在 init 里。

- **可触达性按 §4.1 的方向修正**：能向 init 发帧（并附 fd）的只有**宿主 daemon** —— 沙箱进程持有的是
  init 那一端，往那个方向写进的是宿主的读端。所以**这条不是沙箱可触发的攻击**，而是
  "daemon 侧协议出错就漏"的**正确性缺陷**：宿主一旦发出解析失败/带 fds 的组合（例如未来加了
  携带 fd 的新 verb、或版本不匹配），init 就永久漏 fd；init 是**会话级长命**进程，
  泄漏不再随命令消失（fd 上限 4096，`config.py:122`）。
- 另一个真实后果：宿主 `reader_task` 是 `lines()` 逐行读（**不带控制缓冲的 recvmsg**），
  沙箱侧若真附了 fd，内核会**静默丢弃**这些 fd ⇒ 表现为"exec 悄悄失败/stdio 没接上"，
  难查。⇒ 缓解同下，且**优先级低于 SL-4/SL-6**。
- 另外 `recv(ctl, 3)` 用 64 KiB 定长缓冲一次一条（`init/fdrecv.rs`）：请求帧无长度上限、无速率限制，
  SOCK_STREAM 上"一条 recvmsg = 一帧"并不成立（大 argv/env 帧会被拆包，双方都按" trim 后整段解析"
  处理）⇒ **帧边界混淆**：合并后这条通道承载整个会话的控制流，必须先定长头或显式换行分帧。
  注：实测里我给 init 写 `{"req":"shutdown"}` 之所以没生效，正是因为方向是宿主读端 —— 但**这个
  实验同时说明**：只要帧边界混淆让 init 误把两段拼成一帧，行为就会偏离双方的预期。

**缓解**：任何提前 `continue`/`break` 分支必须 `close(fds)`；`RunMain` 显式拒收 fds；
按行缓冲解析（累积到 `\n` 再 dispatch）并设帧长上限；每通道速率限制；init 侧对
`RunExec` 计数并回报宿主（观测 + 反压）。

### 4.3 SECE-3（High，设计层）：per-exec 策略只能是"子集"，否则就是 fail-open

`§1.3` 的硬不对称落到工程上只有三种可选实现，其中两种有安全含义：

| 做法 | 安全后果 |
|---|---|
| 实例上限 = 所有历史命令请求的**并集**（想放宽就放宽） | **策略棘轮**：第一条命令要 `/etc` 可读，此后整箱永久可读；`update_network` 收紧只对新 exec 生效、旧 child 保持宽策略（§8 S2）。对 E2B 是租户内自伤，对 sandlock 是**产品级承诺失效**（SDK 用户以为 `allow_internet_access=False` 之后跑的东西还在联网） |
| 走 on-behalf 注 fd 绕过 Landlock | **直接击穿 `fs_denied`**：deny 是靠 on-behalf 路径中介实现的（`sandbox.py` 注释 + §3.1 SL-1），注入一个已打开的 fd 不经过它 ⇒ "拒绝列表 + 实例上限"双失 |
| **exec 参数必须是实例上限的子集，越界显式拒绝**（推荐） | 无新增漏点；代价是 E2B 必须把每命令差异放进 exec 参数而不是偷偷抬实例上限 |

**必做**：`exec` 入口做一次子集校验（路径前缀、端口、目的地规则、`fs_denied` 命中），
不满足返回 `EPERM`/明确错误；on-behalf 注入路径（`SECCOMP_IOCTL_NOTIF_ADDFD`）
必须与被中介的 open 走**同一套** `fs_denied` + 实例上限检查，并写进 `command-logs.jsonl` 归属。
契约测试要覆盖"第二条命令请求更宽策略 ⇒ 被拒"，而不是静默变宽。

### 4.4 SECE-4（**下调：条件性，只在开 `pid_ns` 后成立**）：on-behalf `/proc` 元数据与"root 替你读兄弟"

`procfs.rs:196-231` 的白名单（`status/stat/cmdline/io/...`，明确排除 `environ/mem/smaps/pagemap/fd/N`）
写得很克制，理由就写在注释里：*"An on-behalf open with the supervisor's credentials would otherwise
bypass the sandbox's own Landlock deny list and ptrace restrictions"*。问题在于**这个白名单的作用域
从"实例内一棵树"变成"沙箱内所有树"**：

- 今天：用户命令的 Landlock 不含 `/proc`，且 `/proc/<pid>` 只中介本实例进程 ⇒ 看不到网关。
- 合并后：MCP 网关、其它命令都在同一 `ProcessIndex` ⇒ 用户命令 `open("/proc/<gateway_pid>/cmdline")`
  会被**以 supervisor 凭据**代为打开。而 E2B 把网关配置以 `--config <json>` 放在 argv 上
  （`runtime/context.py` `start_mcp_gateway`）⇒ 配置里的上游凭据变成**沙箱内可读**。
- `environ` 不在白名单，但它是**同 uid 的 ptrace 可读面**：`pid_ns` 一开，网关与命令的 ns pid
  互相可见，可读性反而更"自然"。

> **实测下修（§10.3 W1）**：当前形态（oci，**无 pid_ns**）下，从一条命令探测另一条命令：
> `listdir /proc` → **ENOENT**（不可枚举）、`/proc/<pid>/{cmdline,stat,maps,mem,environ}` → **全 EACCES**、
> `ptrace(ATTACH)` → **EPERM**。⇒ 我原稿说的"root 通过 on-behalf 白名单替你读兄弟 cmdline"
> **在这个形态里根本不成立**；它的前提是 `pid_ns` 打开后走 `ON_BEHALF_READABLE_METADATA`
> （含 `cmdline`/`status`，`procfs.rs:210-231`）那条翻译路径 ⇒ **本条改挂到 S8 决策下**（见 §6）。
> 反过来实测确认的是 **`kill(pid, 0)` 同 uid 可投递**（信号可通、读不通）⇒ 沙箱内是"可打扰、不可窥探"。

**缓解**：① 网关配置改走 0600 secret 文件（已有 `_materialize_http_inject` 的同类机制）而不是 argv；
② 网关用**独立 uid**跑（`per_sandbox_uid` 之下再分一档），或干脆保持"网关=独立实例"（半合并，§8 之外）；
③ on-behalf `/proc` 白名单再加一层"只允许本 child 及其后代"的树内判定（把 §4.4 重新变成硬边界）。

### 4.5 SECE-5（Medium-High）：网络/凭据状态是实例级的，per-exec 网络策略必须绑 pid

`NetworkState`、`SyntheticDns` LRU、HTTP ACL 代理、`http_inject` 的 supervisor-only secret、
`host_mask`、`net_allow_bind`/`port_remap` 全部挂在实例（`NotifPolicy`/`Runtime`）。
拦截响应虽然带 `notif.pid`（`ProcessIndex` 已能定身份），但**策略本身没有 per-child 维度**。

- 不解决就实现 exec ⇒ "宽命令的放行渗漏给窄命令"：一条命令 `allowOut=*`，之后所有命令都能出网；
  更糟的是 `transform.headers` 的**凭据注入**会作用在窄命令的请求上（把 secret 发给窄命令自己选的目的地）。
- 缓解：策略查找必须是 `notif.pid → PidKey → 该 child 的 exec 策略`，
  **表里没有就拒（fail closed），不得回落实例默认**；`live_policy`（`policy_fn.rs`）已经是
  "在线收紧"的正确路子，放宽一律走 S2 的 staleness 上报 + 新 exec 生效；
  DNS 合成表要按 child 记录归属，避免窄命令拿到宽命令解析出的合成 IP。

### 4.6 SECE-6（**High，已实测证实**）：进程组语义 —— 一条命令能杀整箱

`killpg` 三兄弟（B1）之外，还有一处**今天就存在、合并后放大**的坑：E2B 的 PTY 桥在中间进程里
`os.setsid()`（`envd_service/executors/sandlock.py:52-58`）⇒ 真正的用户命令**脱离了实例的进程组**，
组级 SIGKILL 打不到它。宿主 `pause_all/resume_all` 也在用 `os.killpg(os.getpgid(proc.pid), ...)`
（`process/manager.py:473-502`）—— 这是宿主直接对沙箱进程发信号，合并后 `getpgid` 返回的是
**整个沙箱的组**，一次 `SIGSTOP` 停全箱。

**实测（§10.2 V0）**：`sandlock-init`、主 workload 与每条 `exec` 出来的 child 的
`pgid` **全部相同**（都等于 init 的 pid 37；`sid` 也共享 27）⇒ 组共享成立。
沙箱内一段普通 python（`os.killpg(os.getpgid(0), SIGKILL)`）执行后：
init、主 workload、以及**另一条正在跑的 100MB child 全部消失**，`state` 变 `stopped`。
⇒ "**一条命令打死整个沙箱（含其它命令与平台网关）**"不需要任何宿主侧 bug、
不需要控制通道，纯内核语义，**今天每命令一实例时做不到（各自一组）**。

**必做**：exec 时为每个 child 建独立进程组（init 侧 `setpgid(child, child)`），
per-child kill/stop/cont 走 `pidfd_send_signal` 或组号；实例级操作 = 遍历登记的组集合；
PTY 桥的 `setsid` 要么去掉，要么由实例显式登记该会话的组；`_CommandGate` 的
超时/取消路径改成"只杀这一条"。**验证**：并发两条命令，杀其一，另一条与网关必须存活且可观测。

### 4.7 SECE-7（**High，已实测证实**）：配额中毒 —— `proc_count` 靠"有人 wait"才归还

`handle_fork` +1，`handle_wait` -1（`resource.rs:126/545-560`），内存那条路是稳的
（pidfd watcher → `cleanup_pid` → `release_charge`，`notif.rs:2706-2733`）。
但**进程数没有退出事件兜底**：今天的回收时机等价于"命令进程被它的父进程 wait"。

- 一个 child `setsid()`/double-fork 变孤儿 ⇒ 在**没有 pid_ns** 的宿主上它被宿主 init 收走
  ⇒ sandlock-init 永远不会 `wait4` 它 ⇒ `proc_count` 只增不减。
- 今天这个泄漏随实例（命令）结束一起消失，看不见；合并后它**在沙箱的整个生命周期里累积**，
  直到 `proc_count >= max_processes` ⇒ 之后**该沙箱所有 fork 一律 EAGAIN**，且内存回收仍正常，
  症状极像"用户程序 bug"。
- **实测（§10.2 V1，用 `/proc/loadavg` 第 4 字段 = `proc_count` 做探针）**：
  基线 `1/7` → 孤儿在跑 `2/8` → **孤儿退出后仍是 `2/5`**；第二轮 `2/5 → 3/6 → 3/5`。
  即每个 setsid 孤儿**永久吃掉一格进程预算且可累加**，而 `total` 字段回落 ⇒ 症状是
  "看不见的泄漏"，只能靠 `peak_proc_count`/实测存活数对账发现。
- **必做**：① 开 `pid_ns`（init 是 ns pid 1，天然是 reaper）或给 init 设 `PR_SET_CHILD_SUBREAPER`；
  ② `ProcessIndex` 的 pidfd watcher 同时作为 `proc_count` 的**权威兜底**（退出即归还，
  `wait4` 只做幂等扣减，二选一以 pidfd 为准）；③ 周期对账：实测活进程数 vs `proc_count`，
  偏差即告警（§5.6）；④ 用例：double-fork + setsid 的孤儿，N 次后仍能 fork。

### 4.8 SECE-8（Medium → **实测下调**：合并额外开销 ~5%）：单一 notif 循环与节流耦合

`supervisor()` 明确"Notifications are processed sequentially (not spawned)"
（`notif.rs:2593-2646`），`notify_rate_limit` 是这条循环上的每秒窗口计数（超限就 `sleep`）。
合并后：**A 命令的 open/connect 洪水会拖慢 B 命令的每一个被拦截 syscall**，
而 on-behalf connect 本身可能等远端 SYN 超时（秒级）⇒ 一条命令连一个黑洞 IP，
整箱命令卡住。这既是可用性也接近安全（沙箱内 DoS 面）。

> **实测下修（§10.2 V2）**：同一实例内另一 child 狂开文件时，被测 `open` 延迟
> 193.9 → **319.8 µs（+65%）**；把骚扰者换成**另一个容器**（独立 notif 循环）时是
> **305.9 µs（+58%）** ⇒ 绝大部分增量是 VM 内 CPU/缓存争用，**共享 notif 循环只多约 5%**。
> 未覆盖：on-behalf `connect` 黑洞（OCI spec 没有网络策略入口，本机无法构造）⇒
> "一条命令拖住整箱"在 connect 路径上仍是**代码级推论**，须在 M1 后用 E2B 网络策略重测。

**缓解**：至少在文档与默认值上明确"限流是沙箱级的"；
把 on-behalf connect 挪进 deferred/并发通道（已有 `defer_sem`/`DEFER_MAX_INFLIGHT` 机制可复用）
并加连接超时；每 child 的通知速率单独记点，便于定位是谁把循环占了；
指标 `notif_loop_lag_ms` 上告警线（§5.6）。

### 4.9 SECE-9（Medium）：listener 卡死/退出的失效模式要定义，不能靠"随进程消失"

按 `seccomp_unotify(2)`，通知投递不出去时该 syscall 失败（ENOSYS/`SET_OWNER` 相关错误），
所以**保密性是 fail closed 的**（`connect`/`open` 直接被拒），但合并后代价从"一条命令报错"
变成"整箱所有命令同时报错且已经跑着的进程可能卡在拦截点上"。
`Runtime` 里的 `notif_handle`/`control_handle`/`throttle_handle`/`loadavg_handle` 是
`JoinHandle`，panic 被吞（今天 `wait()` 会 join/abort）。

**必做**：实例侧一个健康探针（listener 心跳 + 最近一次处理时间）⇒ 超阈值把实例标记 `Dead`，
`exec`/`wait_child` 返回**明确错误码**，宿主据此**重建沙箱**（§8 S5），不做静默重启。

### 4.10 SECE-10（**High，跨沙箱读取已实测**）：控制目录名字 = 沙箱 id + 控制协议无鉴权

`control.rs:130-147`：目录存在 → `kill(supervisor_pid, 0)` 判活 → **判死就 `remove_dir_all` 抢占**。
合并后 `name` 用 `sandbox_id`，两个放大：

1. **pid 复用/双 worker 竞态**会把**活沙箱**的控制目录连带 0600 的 control.sock 删掉；
   名字从随机/自增生成变成**可预测的租户 id**，抢占窗口从"毫秒级"变成"整个会话"。
2. 控制目录根是 `/dev/shm/sandlock-<getuid()>`（`control.rs:45-51`）—— 按 **supervisor 的 uid** 分。
   worker 以 root 起时沙箱子进程是 uid 1000/4242，进不去（目录 0700）；
   但**非 root worker 回退**（`SandlockExecutor._non_root_fallback_warned`）下
   同 worker 内所有沙箱的控制 socket 彼此同 uid ⇒ 一个沙箱可连**另一个沙箱**的 control.sock
   发 `config`/（未来）`exec`。今天这个面已经存在，但 exec verb 一旦进控制协议，
   它的后果从"读配置"升级成"在别人沙箱里跑代码"。

**实测（§10.2 V3/V4）** —— 把 E2B 镜像 rootfs 形态的 `/dev` 整树 bind 进容器后，
在沙箱 P 内运行一段普通 python：

```text
LIST ['M','N','O','P']                     # 别的沙箱的控制目录可直接枚举，目录名 == 沙箱 id
OTHER config M => ok=True dataKeys=[filesystem, limits, network, program] bytes=292
OTHER config N => ok=True ...   OTHER ports M => ok=True   SELF config P => ok=True
```

⇒ **跨沙箱控制 socket 可达、可发帧、`config` 成功返回别的沙箱的完整策略**（文件系统/限额/网络）。
原因有三：(a) `SO_PEERCRED` 在服务端**只 `eprintln!` 不拒绝**（`control.rs:236-262`，注释写着
"dir 0700 should prevent this"，而 0700 在**同 uid worker + `/dev/shm` 可见**时根本不成立）；
(b) 帧协议无鉴权（4 字节长度前缀 + JSON，`control.rs:266-300`）；(c) verb 无租户绑定。
对照组：**不挂 `/dev`** 时 `listdir('/dev/shm/sandlock-0')` 直接 EACCES ⇒ 这是**配置相关**的洞，
而 E2B 的镜像 rootfs 形态恰好就整树挂 `/dev`（`executors/sandlock.py` 的 `mount_map["/dev"]`）。

⇒ **这条是 exec 的硬阻塞项**：`exec` verb 一旦进这个协议，同一入口就是**跨租户执行**。
关闭顺序：① 服务端 `SO_PEERCRED` 不匹配就**断开**；② 加"身份 token 文件 + starttime 比对"；
③ verb 分级，`exec` 类必须带每次 exec 下发的会话密钥；④ 控制目录换到沙箱不可见的私有路径
（或每个沙箱独立 `/dev/shm`）。

### 4.11 SECE-11（Medium）：freeze/checkpoint 的范围与静默丢数据

`freeze()` = `hold_forks=true`（实例全局）+ `killpg`（组级，见 B1）；
checkpoint 的 restore-stub 面向**单个地址空间**。合并后若不定语义，最坏情形是
"用户以为快照了整箱，实际只存了第一条命令"。**必做**：多 child 时**显式拒绝** checkpoint（§8 S3），
freeze 拆成 per-child（冻结一条命令的树）与 per-sandbox（全部）两档，E2B 的 `pause/resume`
明确选后者并保证网关一起冻结/恢复。

### 4.12 SECE-12（Low-Medium，审计项）：init 的 fork 安全性与凭据驻留

- `init::spawn()` 在 `fork()` 之后调用 `set_var`/`Vec`/`CString`/`execvp`（glibc 会 malloc），
  而 init 里**有并发 reaper 线程**（`init/mod.rs:161-207`）⇒ 多线程进程 fork 后只做非
  async-signal-safe 调用，属"实践中 glibc 基本可用、形式上不安全"的类。要么 init 单线程化
  （用 `waitpid(-pid,..,WNOHANG)` + 信号驱动），要么显式记录该假设并加 `pthread_atfork` 审计。
- 凭据驻留时长上升：`http_inject` secret 文件、IAM JWT 签发（`_mint_iam_jwt`）、
  `GATEWAY_ACCESS_TOKEN` 随实例长期驻留，且实例活着期间 supervisor 始终持有可读句柄。
  合并后应改为**随 child 生灭**（exec 时签发、child 退出即撤销），否则一条命令拿到的
  注入能力会服务到整个会话。
- SL-1 叠加：chroot 形态 on-behalf 代打开造成的属主错位，从"每条命令"变成"整个会话"
  （§3.7 末注），`command-logs.jsonl` 的归属更难查 ⇒ **P1/P2 先于 exec 落地**。

### 4.13 SECE-13 / **SL-6（Medium-High，OCI-live）**：`sandlock-init` 不是 reaper，收养的孤儿变僵尸

`run_init` 的回收全部是"**对特定 pid 起一个线程 `wait_exit(pid)`**"
（`init/mod.rs:152-159` 主 workload、`:190-198` exec 出来的 child），
**没有 `waitpid(-1, WNOHANG)` 的兜底扫描**。

> **实测修正（§10 E2）**：本机跑起来的 oci **没有 pid namespace** —— 容器 PID 1 与沙箱进程
> `ns/pid` 是同一个 `pid:[4026532452]`（`main.rs:5` 写明 "without kernel namespaces"，
> bundle 只有 `{"type":"mount"}`）。⇒ 孤儿被**外层（容器/worker）PID 1** 收养，不是 `sandlock-init`；
> README 里 "sandlock-init acts as PID 1" 是**逻辑**说法，别按内核语义读。分两档：
> **(a) 现状（无 pid ns）** 回收责任在外层 PID 1 —— E2B worker 的 PID 1 是个不 reap 的 python 进程，
> 僵尸照样堆积；**(b) 若按 S8 打开 `pid_ns`（E2B 的建议路线）** 收养者变成 `sandlock-init`，
> 缺 `wait(-1)` 就**直接**变成沙箱内僵尸堆积。
> **两档下 `proc_count` 都泄漏**（唯一归还点是拦截到 `wait4`，谁收养都不会通知 sandlock）。

于是容器内任何 double-fork 守护进程（`sshd`、`supervisord`、`npm`/`vite` dev server、
Jupyter kernel、`nohup … &`）在中间进程退出后，其退出**永远不会被回收** ⇒

- 容器内 `ps` 里堆积 `<defunct>`，占 pid 表。"PID 1 必须扫僵尸"是容器领域的经典约束
  （runc 的 init 自带 `wait(-1)` 回收环，`--init`/tini 亦为此存在），本项目的 init 缺这一环。
- 与 SECE-7 同根但**更狠**：`handle_fork` 在它出生时已经 `proc_count += 1`
  （`resource.rs:126-131`），而唯一的归还点是拦截到阻塞 `wait4/waitid`
  （`resource.rs:545-560`）。init 既然从不 `wait(-1)`，这个 +1 **在实例生命周期内永不归还**
  ⇒ 每次 double-fork 泄漏一格进程预算。

**修法（三行级）**：init 的主循环改为 `waitpid(-1, WNOHANG)` 扫尾 + 按 pid 查表路由 `Exited`
（登记表里有的才回报，没有的静默回收），并保留 `PR_SET_CHILD_SUBREAPER` 的替代路径给"不共享 pid ns"的宿主。
**用例**：容器内 `sh -c 'sleep 1 & exit'` ×50 ⇒ `ps` 无 defunct、`proc_count` 回到基线、之后仍能 fork。


### 4.14 SECE-14（**已实测**）：`setsid` 残留进程能活过 `delete`，且还能用已打开的 fd 干活

V7 实测：主容器 `delete --force` 之后 —— supervisor 进程消失（`135/144: GONE`），
但 setsid 孤儿 `158` 仍 `state=S` 存活；它在"宿主已经不在了"的状态下继续执行并报告：

```text
ALIVE-AFTER-DELETE write on pre-opened fd OK      # write(已打开的 fd) 不被拦截 ⇒ 仍然可写
new open FAIL Function not implemented(38)        # 新 openat 走 user-notif ⇒ 监听者没了 ⇒ ENOSYS
```

两个方向的结论都要记：

- **不担心静默提权**：`connect`/`open`/`mmap` 这类被中介的 syscall 在监听者消失后**失败**
  （fail closed，印证 §4.9），内存分配那一行也没写进日志（mmap 同样拿不到放行）。
- **担心收尾不可靠**：它**已经打开的 fd 仍然可用** —— 在合并实例里那可能是别的命令的 stdout 管道、
  宿主侧的日志文件、或 §4.1 的**控制 socket**。也就是说"`delete` 沙箱 = 一切停止"这个假设不成立：
  `killpg` 打不到 setsid 的后代，而残留者还能继续往已交付的 fd 里写字节。
- **附带实测到的同类现象（§10.3 X2）**：一条 `exec` 的直接子进程 fork 出 3 个睡 30 s 的孙子后自己
  1 s 退出，但 **attached `exec` 的 CLI 被吊住约 30 s** —— 孙子们持有 stdio 管道写端，宿主看不到 EOF。
  ⇒ "child 退出"不等于"输出结束"：`_drive` 的看门狗（`process/manager.py:358`）在合并形态下
  要按 **fd 持有者**而不是按 child 生命周期判定收尾。
- **必做**：会话收尾必须 ①按 child 的子树逐个 `pidfd_send_signal`（不能只靠组信号），
  ②关闭宿主侧持有的**所有**该会话 fd（管道/socket），③可选：给实例配 cgroup 以 `cgroup.kill` 兜底
  （sandlock 不用 cgroup 是刻意的，那就只能靠 ①②）；④`delete` 之后校验"该会话已无存活进程"，
  不满足就告警（§5.6）。

### 4.15 沙箱内兄弟可见性矩阵（实测，决定"合并把内边界塌到哪一档"）

同一实例内两条命令互相探测（§10.3 W1/X1）：

| 操作 | 实测 | 含义 |
|---|---|---|
| `os.listdir('/proc')` | **ENOENT** | 不能枚举兄弟 pid（合成 /proc 只给顶层文件）|
| `open('/proc/<pid>/cmdline' / 'stat' / 'maps' / 'environ' / 'mem')` | **全 EACCES** | 不能窥探兄弟命令行/环境/内存 |
| `ptrace(PTRACE_ATTACH, 兄弟)` | **EPERM** | 不能注入或读内存（seccomp 屏蔽 ptrace 生效）|
| `os.kill(兄弟_pid, 0)` | **OK** | 同 uid ⇒ **信号可投递**：给定 pid 就能 SIGKILL 兄弟命令或平台网关 |
| `os.killpg(os.getpgid(0), SIGKILL)` | **打死整个实例**（§10.2 V0）| 组共享 ⇒ **不需要知道任何 pid** |
| `open('/proc/loadavg')` | OK，`running/total` + `last_pid` | `running`=`proc_count`（§4.7 的可观测点）、`total`=`ProcessIndex` 规模、`last_pid`=**最近分配**（实测受害者 pid=38 而 `last_pid`=48 ⇒ **不泄露兄弟 pid**）|
| `open('/proc/meminfo')` | OK，`MemTotal` = 限额 | 记账对用户可见，也是 §3.8 修复后的正确观感 |

⇒ **合并真正新增的沙箱内能力只有两类**：(1) 组级一键杀（§4.6，实测）；
(2) 共享记账数字的弱侧信道（`running/total` 会随别的命令的进程数变化，可接受）。
"读兄弟"（原 SECE-4）当前形态不成立，只在 S8 打开 `pid_ns` 后才需要处理。
定点 kill 需要 pid 来源，合并本身不给 —— 但 **E2B 的 API 会给**（`process.list()` 把 pid 返回给同一租户），
所以"用户代码 SIGKILL 掉平台 MCP 网关"在合并后 = 一次 API 读 + 一次 `os.kill` ⇒
**网关必须换 uid 或保持独立实例**（§4.4 缓解②）。

## 5. 会话生命周期管理

### 5.1 谁的生命周期？三层要分清

| 层 | 载体 | 今天 | 合并后 |
|---|---|---|---|
| **会话（沙箱）** | `SandboxInstance` + `SandlockExecutor` + envd `RuntimeContext` | 隐式：由 N 个命令实例拼出来，没人真正持有"沙箱级执行状态" | **必须有一个显式对象**：实例 = 会话，生命周期 = 沙箱生命周期 |
| **命令（进程）** | `Process`/`ManagedProcess` | 一个命令实例（含全套策略与资源） | 一个 child id + 3 个 stdio fd + 一个组号 |
| **子树（命令的后代）** | 内核 | 随命令实例消失 | **必须有 reaper**（§4.7） |

今天"删沙箱"实际做的是：`_CommandGate.remove()`（拒后续命令）+ `kill_all()`（逐命令组 kill）
+ 网关 `kill(9)` + MCP 端口回池（`runtime/context.py:shutdown`）。合并后必须再加一步
`instance.shutdown()`，且**顺序**要紧（见 5.3）。

### 5.2 实例状态机

```text
        create(policy_ceiling)
 Provisioning ──────────────► Ready ──exec──► Active{n}
   │  失败/上限非法              ▲  │             │  最后一个 child 退出
   │                            └──┘│             ▼
   ├─(SL-4 校验/身份冲突)─► Dead    │           Ready(idle) ──idle 超时/最大寿命──► Draining
   │                                │                                                │
   pause/resume（全箱冻结/解冻） Frozen ◄┘                        不接新 exec，等 child 自然退出
                                       │                                                    │
   listener 心跳丢失 / reaper 死 / exec 帧协议错乱 ─► Dead ◄── 超时/显式 shutdown/delete/kill/驱逐 ──┘
```

不变式（**每条都要有测试**）：

1. `exec` 只在 `Ready/Active/Frozen` 受理，其他状态返回明确错误码（不得静默排队到重建）；
2. `shutdown()` **幂等**，且必须"child 表已空或已被 SIGKILL 覆盖"才允许清控制目录；
3. 实例进入 `Dead` ⇒ 之后所有 `exec/wait_child/kill_child` 一律同一错误码，宿主据此重建；
4. 实例不死于任何单个 child：`RunMain` 语义（OCI 的"主进程退出即容器结束"，`init/mod.rs:155-168`）
   **不能带进 E2B** —— 这里没有"主进程"，只有显式 `shutdown`/idle 超时/删除；
5. 反向也要成立：不能因为"还有一个 child 没登记退出"就永久不回收 ⇒ 必须有最大寿命兜底。

### 5.3 `shutdown()` 的固定顺序（错序会留孤儿或吊死流）

1. 标记 `Draining`：拒新 `exec`，`_CommandGate` 已在 `remove()` 时拒排队者（复用，别重复造）；
2. 向 init 发 `Shutdown`（init 自己 `killpg` 收拢后代）；给 grace（默认 5 s）；
3. 升级：逐 child `pidfd_send_signal(SIGKILL)` → 再实例组集合 `killpg` → 兜底 `killpg(实例组)`；
4. 关 stdio 管道宿主端（否则订阅者永远等不到 EOF）；
5. `abort` notif / throttle / loadavg / control / DNS 网关任务（今天这些在 `wait()` 收尾，`sandbox.rs:1061-1072`）；
6. 关控制 socket、按**身份 token 比对**后再删控制目录（§4.10）；
7. 归还 MCP 端口、预算记账清零、`command-logs.jsonl` 收尾。

顺带一个好消息：宿主 worker 崩溃时子进程不会变孤儿 —— 受限子进程设了
`PR_SET_PDEATHSIG, SIGKILL`（`sandbox.rs:1580/2173`），worker 死 ⇒ 沙箱进程死。
实例化之后这条恰好是"不复活旧会话"的保证，要在文档里写成**有意行为**（否则运维会以为能恢复）。

### 5.4 E2B 侧接线点清单（每一个都要落到代码 + 测试）

| 触发 | 现在做什么 | 合并后必须做什么 |
|---|---|---|
| `Sandbox.delete` / kill | `context.shutdown()` | + `instance.shutdown()`（幂等，且在 `kill_all` 之后仍安全） |
| TTL 到期 / 驱逐 / 扩缩 | 控制面回收 | 同上；驱逐前允许 `Draining`（优雅），硬驱逐直接 `Dead` |
| `pause` / `resume` | 宿主 `killpg(SIGSTOP/SIGCONT)` 每命令 | 实例级 `freeze/thaw`（含网关）；per-child 档留给 `process.send_signal` |
| worker 重启 | 无实例可恢复 | **明确不恢复**（PDEATHSIG 已保证）；控制面把该 worker 的沙箱标死，SDK 见 `not_found` |
| `update_network` | 下一条命令生效 | 按 §8 S2：新 exec 生效 + staleness 回报；已在跑 child 保持原策略（收紧也做不到立即）|
| 快照 / 文件 API | 与执行无关 | 快照是文件系统拷贝 ⇒ 与实例解耦，但要保证 `Draining` 期间不再写 |
| 命令超时（`max_command_timeout`） | `_drive` 看门狗 → `kill` | **只能杀该 child 的子树**（§4.6），否则一条超时杀全箱 |
| SDK `background=True` 长跑进程 | 各占一实例 | 各占一 child ⇒ 预算共享（这正是 §3.8 想要的）|

### 5.5 空闲与回收策略（必须显式选一个）

- **idle 超时**：child 表空且无 `wait_child` 订阅者持续 `T_idle`（建议 15 min，可配
  `E2B_INSTANCE_IDLE_TIMEOUT_S`）⇒ `Draining`→`shutdown`。不做的话，被"忘了 kill"的沙箱
  会永久占着一个 listener + DNS 网关地址 + 控制目录 + 一个 tokio 任务集。
- **最大寿命**：`T_max`（如 = 沙箱 TTL）强制滚动重建，兜住"实例内状态缓慢泄漏"这类看不清的 bug。
- **child 数上限 ≠ `max_processes`**：`_CommandGate` 保留（并发闸口），
  它现在挡的是"同时跑几条命令"，合并后仍是唯一能防止单沙箱把 notif 循环打满的东西（§4.8）。
- **半合并作为过渡**：先只把**网关 + 命令**并进一个实例（K 从 2 起降），
  `max_concurrent_commands_per_sandbox` 保持 1 ⇒ 一次只有一条命令在跑，
  §4.6/§4.8 的耦合面最小，能拿到 §3.8 大部分收益。这是推荐的落地顺序。

### 5.6 可观测性（合并后没有这些就是瞎子）

实例侧指标（`stats()` 已有 `peak_mem_used/peak_proc_count`，`sandbox.rs:963-967`）：

- `instance_children_live / instance_children_total`（区分"泄漏"与"确实在跑"）
- `proc_count_vs_live`（**对账偏差 = §4.7 的直接告警条件**）
- `notif_loop_lag_ms`、`notify_rate_limit_hits`（按 child 归因，§4.8）
- `init_control_fds_inherited`（SL-4 的自检：应为 0）、`init_recv_fd_leaks`（SL-5）
- `instance_state`（含 `Dead` 原因计数）、`shutdown_grace_escalations`
- 沙箱 id ↔ instance id ↔ child id 三元组贯穿日志（`docs/tenant-isolation.md` 的归属链）

### 5.7 新增测试矩阵（合并后才存在的场景，今天一条都覆盖不到）

| 用例 | 断言 |
|---|---|
| 并发 2 条命令 + 网关 | 三者共存；`max_memory` 全局只一份（把 §3.8 探针从"记录"改成**断言**：第二条申请应被拒）|
| 杀其中一条 | 另一条与网关存活、输出不串（§4.6）|
| 用户代码探测/滥用 fd 3 | `readlink /proc/self/fd/3` 必须失败；伪造 `Exited` 必须被宿主丢弃（exec 仍等真实退出码）；`Exited{未知 pid}` 不得改变 supervisor RSS（§10 H1/H2 现状即红）|
| 畸形 exec 帧 ×1000 + 附 fd | init fd 数不增长；宿主侧流仍正常 EOF（§4.2）|
| 第二条命令请求更宽策略 | 显式拒绝，日志可见（§4.3）|
| double-fork + `setsid` 孤儿 | 回收后 `proc_count` 归零，之后仍能 fork（§4.7）|
| 一条命令 connect 黑洞 IP | 另一条命令的 open/connect p95 延迟不受牵连（§4.8）|
| 沙箱内 `killpg(自身 pgid)` | 不得波及其它 child 与网关（per-child 组，§4.6）|
| 兄弟进程互相探测（cmdline/environ/maps/ptrace/kill） | 读与 ptrace 必须仍被拒；信号只允许投向本 child 子树（§4.15）|
| child 已退出但孙子持有 stdout | attached 流不得被无限吊住：按 fd 持有者判定收尾（§4.14）|
| 沙箱内枚举/连接 `\`/dev/shm/sandlock-<uid>/*` | 一律 EACCES/ECONNREFUSED；`SO_PEERCRED` 不匹配必须**断开**而非告警（§4.10）|
| `delete` 后残留进程检查 | 该会话不得有存活进程；已交付的管道/控制 fd 必须全部关闭（§4.14）|
| 24 h 长跑，轮转 10k 命令 | fd / 任务 / `ProcessIndex` / `proc_count` 无单调增长（§8 S7）|
| 实例 `Dead`（注入 listener 失败） | `exec`/`wait_child` 同错误码，E2B 重建，不静默重启（§4.9）|
| 双 worker 同名沙箱 | 第二个**拒绝**而非抢占（§4.10）|

## 6. 必须先定的语义（§8 §7.4 的 S1–S7 之外，新增 6 条）

| # | 待决 | 建议 |
|---|---|---|
| S8 | 兄弟命令是否互相可见（`pid_ns` 开不开） | **开**（同时解决 §4.4 的可见性与 §4.7 的 reaper）；代价一：`Sandbox::pid()` 报 ns pid，E2B 的 `process.pid` 要换成 child id 语义；代价二（**实测相关**）：开了 `pid_ns` 之后 `/proc/<pid>/*` 会从"全 EACCES"（§10.3 W1）变成**走 supervisor 的 on-behalf 白名单**，而白名单含 `cmdline`/`status`（`procfs.rs:210-231`）⇒ **必须同时把白名单收窄到"仅本 child 及其后代"（按 `PidKey` 判定）**，否则 §4.4 的兄弟命令行泄露才真正成立 |
| S9 | exec 参数越出实例上限 | **拒绝**，不抬上限（§4.3） |
| S10 | 每 child 一个进程组 | **是**；实例级操作遍历组集合（§4.6） |
| S11 | 谁是 reaper | init（ns pid 1 或 `PR_SET_CHILD_SUBREAPER`），并且 `proc_count` 以 pidfd 为权威（§4.7） |
| S12 | "主进程退出即结束"要不要保留 | E2B **不保留**：无主进程，只有显式 shutdown/idle/删除（§5.2 不变式 4） |
| S13 | 空闲/最大寿命/崩溃爆炸半径的产品语义 | `T_idle` 15 min、`T_max`=沙箱 TTL、`Dead` ⇒ SDK 见 `not_found` 并由调用方重建（§5.5/§4.9） |

## 7. 分期与放行门槛

沿用 §8 的 M0–M4，但把安全前置单列，并**明确 gate**：

- **M0′（fork 侧安全前置，先于一切）**：`run_init` 的 `waitpid(-1, WNOHANG)` 收养回收（SL-6）+ `extra_fds` 落位加 `FD_CLOEXEC`（SL-4）+
  宿主侧**通道凭据校验**（`reader_task` 只认 init 写的帧）+ `early_exits` 上限/只认已登记 pid（§10 H1/H2）+
  `InitLink::request()` 每请求 deadline（`supervisor.rs:75-95` 无超时）+
  init 的 fd 关闭/显式分帧（SL-5，优先级最低）+ 控制目录身份 token（§4.10）+
  per-child 进程组与 pidfd 定向信号（§4.6，**实测可由沙箱内主动触发**）+
  `proc_count` 的 pidfd 兜底与对账（§4.7，**实测可累加泄漏**）+
  **控制 socket 鉴权**：`SO_PEERCRED` 不匹配即断开 + 身份 token + verb 分级（§4.10，**实测跨箱 `config` 已成功**）。
  验收：§5.7 的"fd 3 探测 / 伪造退出码 / 未知 pid 内存 / 杀一条 / 孤儿"用例先过
  —— 前三条**现在就能在本机 OCI 路径上跑红**（§10），不必等 core。
- **M0**：`ResourceState`、listener、控制目录、DNS 网关生命周期从 create 路径提到 instance（行为不变）。
  验收：fork 三套全绿 + E2B 全量不变（基线 `867 passed / 1 skipped / 2 xfailed`）。
- **M1**：init 循环与 `proto`/`fdpass` 从 `sandlock-oci` 下沉到 core，`instance.exec()/wait_child()/kill_child()`
  + child id + stdio 交付（不开放给 E2B）。验收：并发 exec、fd 归属、双 wait 幂等、stdin 关闭不死锁。
- **M2**：per-exec `cwd/env/extra_writable/bind_ports` + **子集校验**（S9）+ S2 的 staleness 语义 +
  网络策略绑 pid（§4.5）。
- **M3**：S1 默认值联动（`max_processes` 64→按沙箱上调）、S3/S4 拒绝或支持、S5–S7 与 S8/S11/S13。
- **M4（E2B 接线）**：**先只做"网关 + 命令"半合并**（§5.5），把 §3.8 的超卖探针改成断言；
  稳定后放开并发命令 exec，同步调 `_CommandGate` 与容量文档（`docs/SCALING.md`、
  `docs/resource-contention.md`），关闭 §3.8。

**不要做的事**：不要在 M0′ 之前把 `exec` 接进 envd —— 那等于把 §4.1 的"任何用户命令可打死整箱、
可偷另一条命令的 stdout"直接送进生产；也不要用"配额除以 K"糊过去（见 §8），那是把一个正确性
问题换成一个更难查的用户体验问题。

## 8. 不做的替代方案（以及为什么只配当过渡）

| 方案 | 效果 | 为什么不选 |
|---|---|---|
| 每沙箱预算除以 K（K = 闸口并发 + 长驻数） | §3.8 超卖消失 | 512 M 标称变 256 M/命令，且 K 随并发漂移；`max_processes` 也要除，用户体验与文档口径双伤 |
| 共享 resource group（旧 P10） | 多实例共账 | 已被 §8 取代：要在内核里再造一层跨实例账本归属，比"执行边界=产品边界"更复杂，且不解决 pid_ns/可见性 |
| 只合并网关（命令仍独立实例） | K 从 2 降到 1.x | 不解决并发命令超卖；但**作为 M4 的第一步成本极低**，故已纳入分期 |
| 不做 exec，改用真 microVM | 语义最正 | 项目前提就是无特权/无 netns 的宿主内沙箱（§0 基线） |

**推荐**：按 §7 做，收益按"边界正确性 → 半合并 → 全合并"的顺序兑现；
安全前置 M0′ 与功能前置 B1/B2/B7 未清零前，`exec` 不进 envd。

## 9. 证据索引（本文所有 file:line）

```text
envd_service/executors/sandlock.py      701 start() / 717 每命令 _build_sandbox / 346 update_network
                                        52-58 PTY setsid / 119-124 resize 带内帧 / 249 kill / 270-274 wait
envd_service/process/manager.py         124-206 _CommandGate / 451-502 send_signal·kill_all·pause_all(killpg)
envd_service/runtime/context.py         191 网关绕过闸口（start_mcp_gateway 起于 167）/ shutdown()·pause()·resume()
envd_service/config.py                  119 max_processes=64 / 122 max_open_files=4096 / 128 闸口默认 1
sandlock-core/sandbox.rs                293-330 Runtime 单槽 / 613 一 task 一 NEW_LISTENER / 909-933 freeze·kill
                                        1050-1086 wait 收尾拆实例 / 1349-1372 create_with_in_child_main
                                        1375/1389/1404 leader_pid.or(child_pid) / 1579 setpgid / 1580 PDEATHSIG
                                        2292-2320 child fd 落位（dup2）/ 3306-3315 dup2 清 CLOEXEC 的注释
sandlock-core/seccomp/state.rs          1-120 ResourceState（实例级）/ 166-235 ProcessIndex·PidKey（多进程已就绪）
sandlock-core/seccomp/notif.rs          2529-2646 supervisor 串行循环 + rate limit / 2673-2733 pidfd watcher·cleanup_pid
sandlock-core/resource.rs               100-135 handle_fork（EAGAIN + 计数）/ 545-560 handle_wait 才 -1
sandlock-core/procfs.rs                 196-231 on-behalf 白名单（排除 environ/fd/N）/ 1497-1542 ns 内 ESRCH 断言
sandlock-core/control.rs                45-51 /dev/shm/sandlock-<uid> / 130-147 kill(pid,0)+remove_dir_all 抢占
                                        278 args dead_code / 340-341 只有 config·ports
sandlock-oci/supervisor.rs              341 UnixStream::pair / 350 CONTROL_FD=3 / 364 drop(child_ctl)
                                        75-95 InitLink.request 持写锁 rx.await（**无 deadline**）
                                        119-152 reader_task：**无条件信任通道上的 Resp**；134 pending.take()、
                                          138-142 exit_waiters/early_exits（无上限）；685-748 handle_exec（717 drop(fds)）
sandlock-oci/init/mod.rs                33-88 spawn(fork+set_var+execvp，不关 fd3) / 118-207 run_init（fds 泄漏分支）
sandlock-oci/init/fdrecv.rs             1-31 64KiB 单帧 recvmsg
sandlock-oci/README.md                  「init 是 PID 1，workload 与所有 exec 共享一个 sandbox」；exec 仅非 TTY
部署面：wheels/fork/*.whl namelist = libsandlock_ffi.so + sandlock/*.py（无 oci 二进制）；Makefile:19 只 build -p sandlock-ffi
core 内无 close_range/fd 清扫（grep 全仓）；CLOEXEC 在别处是被认真处理的：sandbox.rs:3260 relocate_high、
   network/connect.rs:736-784（镜像 FD_CLOEXEC）、inbound.rs:165、sandbox/tests.rs:430（断言 reloc fd 必带 CLOEXEC）
实测脚本与原始输出（本机可重跑，tmp/ 不入库）  第一批 oci-exec-probe / oci-fd3-exploit /
                     oci-fd3-forge{,2} / oci-fd3-final；第二批 oci-bench{2,3,4,5}.sh +
                     probes/*.py（t0/hold/orphan/orphan2/ioop/sock3/killgrp），
                     输出 oci-bench{,2,3,4,5}.out
control.rs                          236-262 SO_PEERCRED **只告警不拒绝** / 266-300 长度前缀帧、无鉴权
procfs.rs                           729 /proc/loadavg 第 4 字段 = proc_count（记账的可观测探针）
python/src/sandlock/sandbox.py          670 _check_not_running / 676 _reject_if_popen / 1669 Process.kill=killpg
```


## 10. 本机实测记录（2026-09-04）

**环境**：macOS + **OrbStack**，`docker info` 报 `kernel=7.0.14-orbstack-00380-ga7e0a2dc9535`；
test-runner 容器内 `sandlock.landlock_abi_version() == 8`；
`--security-opt seccomp=unconfined`（sandlock 需要用户命名空间）。
⇒ **README 里"macOS Docker Desktop 内核不满足、不得作为 Sandlock 验收环境"这一条对 OrbStack 不成立**，
本机可以做 exec/隔离面的运行时验收；仍不可用的是 XFS prjquota 类用例
（`test-runner: no /dev/loop-control: XFS gates unavailable`）。

**被测对象**：`target-linux/debug/sandlock-oci`（预编译 x86-64）+ `tests/rootfs-helper`（静态），
bundle 用 `crates/sandlock-oci/tests/integration.rs:create_bundle` 的最小 config（`namespaces:[mount]`）。
探针脚本（留在 `tmp/`，可重跑）：`tmp/oci-exec-probe.sh`、`tmp/oci-fd3-exploit.sh`、
`tmp/oci-fd3-forge{,2}.sh`、`tmp/oci-fd3-final.sh`。

| # | 实验 | 结果 |
|---|---|---|
| E1 | `state` 拿到 init pid，比较 `/proc/<init>/fd` 与 `/proc/<workload>/fd` | 两者都有 `3 -> socket:[2183970]`（**同一 inode**），`/proc/<pid>/fdinfo/3` 报 `flags: 02` ⇒ **无 `O_CLOEXEC`（02000000）**，跨过 `execve` 存活 |
| E2 | `readlink /proc/1/ns/pid` vs `readlink /proc/<init>/ns/pid` | 同为 `pid:[4026532452]` ⇒ **没有 pid namespace**（修正 §4.13 归因） |
| E3 | 沙箱内 `ls /proc/self/fd`、`open("/proc/self/fd/3", O_WRONLY)` | **EACCES**（Landlock 挡住 /proc；`ON_BEHALF_READABLE_METADATA` 也不含 `fd/N`）⇒ **靠路径拿不到**，但**已继承的 fd 不需要 open** |
| E4 | 沙箱内 `readlink /proc/self/fd/3` | `socket:[2183970]`，rc=0 ⇒ mediator 允许自家 fd 链接的 readlink（无害，但可用于**确认通道存在**） |
| **H1** | 宿主 `exec --pid-file` 起一条长命令（pid=55），沙箱内另一条 `exec` 执行 `printf '{"resp":"exited","pid":55,"code":0,"signal":null}' >&3` | 宿主 `exec` CLI **rc=0**（返回"退出码 0"），**而 pid 55 仍在运行** ⇒ **退出码伪造成立**，`reader_task` 无条件信任该通道 |
| **H2** | 沙箱内循环 60000 次写 `{"resp":"exited","pid":1xxxxxx,...}`（未知 pid），比较 supervisor 进程 `VmRSS` | `14336 kB → 19772 kB`（**+5.3 MB**），且随后 `exec echo ALIVE` 仍 rc=0 ⇒ `early_exits` **无上限/无淘汰**，静默增长 |
| T-SD | 沙箱内写 `{"req":"shutdown"}` 到 fd 3 | 容器 **status=running**、keepalive 从 109 继续推进、init 存活 ⇒ 原稿"打死整箱"**否证作废** |
| T-TH | 沙箱内 `cat <&3 > /stolen` 期间，宿主连发 6 条 / 8 条 `exec` | **全部正常送达**，`/stolen` 为空 ⇒ 抢读宿主请求（连带偷 SCM_RIGHTS stdio fd）**本机未复现**（init 是更早的睡眠读者，通常先被唤醒）；从"High 可实现"下调为"理论可能" |
| T-FLOOD | 沙箱内洪泛 400 条伪造 `Started` 后连发 8 条宿主 `exec` | 8/8 正常 ⇒ 抢 `pending` 槽需要精确时序，**volume 打不出来** |

**没做/做不了的**：SL-6 的僵尸堆积要一个"fork 后父进程先退出"的原语，`rootfs-helper` 没有该子命令，
`/bin/sh -c '...&'` 在这个 mini-sh 里也不支持后台 ⇒ 该项仍是**代码级推论 + E2 的命名空间实测**，
需要给 helper 加一个 `orphan` 子命令才能闭环；§4.10 的非 root worker 跨箱控制 socket 需要
rootless worker 部署形态，本机 demo 未覆盖。


### 10.2 第二批实测（exec 语义与配额，2026-09-04）

同一环境（OrbStack `7.0.14` + ABI 8）。这轮把 rootfs 换成**完整 python 环境**
（`tar` 容器自身的 `usr bin sbin etc lib lib64`，`cp -al` 硬链接派生到每个 bundle），
config.json 里带上 `linux.resources.memory` / `pids` ⇒ 可以直接观测合并实例的行为。

| # | 实验 | 结果 | 影响本文哪条 |
|---|---|---|---|
| V0 | 读 `init`/workload/exec-child 的 `pgid`+`sid`；沙箱内 `os.killpg(os.getpgid(0), SIGKILL)` | 三者 `pgid=37`（init）、`sid=27` 全共享；执行后 init、主 workload、**另一条正在跑的 100MB child 全部消失**，`state=stopped` | **§4.6 由推论升为实测**；且不需要控制通道 |
| V1 | `/proc/loadavg` 第 4 字段（= `proc_count`）在"setsid 孤儿出生→退出"前后的变化，跑两轮 | `1/7 → 2/8 → 2/5`；`2/5 → 3/6 → 3/5` ⇒ **每个孤儿永久吃掉一格且可累加** | **§4.7 实测** |
| V2 | 同实例内一条 child 狂开文件 vs 换到**另一个容器**狂开文件，测被测 `open` 延迟 | 基线 193.9 µs；同实例骚扰 319.8 µs；跨容器骚扰 305.9 µs ⇒ **共享 notif 循环的净增量 ≈5%** | **§4.8 下调**（原稿高估）|
| V3 | 沙箱内 `listdir('/dev/shm/sandlock-0')`（**不**挂 /dev） | `EACCES` ⇒ 默认配置下不可枚举 | §4.10 对照组 |
| V4 | 同上，但按 E2B 镜像 rootfs 形态**整树 bind `/dev`** | 枚举出 `'[M,N,O,P]'`（目录名=沙箱 id），并对**别人的** control.sock 用长度前缀帧 `config` ⇒ **`ok=True`，返回 filesystem/limits/network/program 策略**；`ports` 同样成功 | **§4.10 实测：控制协议无鉴权 ⇒ exec verb 的硬阻塞项** |
| V5 | 上限 512 MiB：同实例 2×300MB vs 跨容器 2×300MB | 同实例**只有 1 个成功**；跨容器**两个都成功**，宿主 RSS `316608+316712 kB ≈ 600 MB` | **§2.1 收益实测**（§3.8 超卖 + 合并即修复）|
| V6 | `exec` ×20 vs `create+start+delete` ×8 的每次耗时 | 54 ms/op vs 204 ms/op（≈3.8x），但两者都被 CLI 进程自身 fork 开销支配 ⇒ 不可外推到 Python 绑定 | §2.3 补充说明 |
| V7 | `delete --force` 之后 setsid 孤儿的下场 | supervisor 消失，孤儿**仍存活**并能 `write()` 已预先打开的 fd；新 `open` 返回 **ENOSYS(38)**（监听者没了 ⇒ fail closed）；随后自行退出 | **新增 §4.14**：`delete` 不等于一切停止；但也没有静默提权 |

**仍未闭环**（下一轮要补）：
(a) on-behalf `connect` 黑洞造成的队头阻塞 —— OCI spec 没有网络策略入口，得等 M1 之后用 E2B 的
`net_allow` 路径重测（V2 只覆盖了 open 路径）；
(b) `notify_rate_limit` 的沙箱级节流效果、`hold_forks` 全局冻结的波及面 —— 需要 `live_policy`/checkpoint
入口，oci 侧无接口；
(c) 非 root worker（`_non_root_fallback`）下 V4 的跨箱读取是否仍有 `ok=True` —— 预期更容易中招，
需要一套 rootless 部署；
(d) 孤儿"分配内存"那一行没写进日志：mmap 通知失败后 python 的具体死法未确认（是被 SIGKILL 还是异常退出），
不影响 V7 的结论但值得钉死。

### 10.3 第三批实测（沙箱内可见性与收尾）

| # | 实验 | 结果 | 影响 |
|---|---|---|---|
| W1 | 同实例两条命令互探：`listdir /proc`、`/proc/<pid>/{cmdline,stat,maps,environ,mem}`、`ptrace ATTACH`、`kill(pid,0)` | `/proc` **ENOENT**；四个 proc 文件**全 EACCES**；`ptrace` **EPERM**；`kill(pid,0)` **OK** ⇒ 可打扰、不可窥探 | **§4.4 下调**、新增 §4.15、S8 加约束 |
| X1 | 只读 `/proc/loadavg` 能否定位兄弟 pid | `running/total=1/7`、`last_pid=48`，受害者真实 pid=38 ⇒ **不命中**（`last_pid` 只是最近分配，`procfs.rs:726-733`）| §4.15 |
| X2 | child 1 s 退出、留 3 个睡 30 s 的孙子持有 stdout 写端 | attached `exec` 的 CLI 被**吊住约 30 s** | **§4.14 新增收尾判据** |
| V7′ | `delete --force` 后 setsid 孤儿（承接 §10.2 V7） | supervisor 消失、孤儿存活并 `write()` 成功；新 `open` → **ENOSYS(38)**（fail closed）| §4.14 |

**本文判定的三档现状**：
*已实测证实* —— SL-4（伪造退出码 + `early_exits` 无界）、SL-7（跨箱 control.sock 无鉴权读取）、
SL-8（`proc_count` 可累加泄漏）、§4.6（沙箱内 `killpg` 一把杀）、§4.14（孤儿活过 delete）、
§2.1（同实例共享预算 vs 跨实例 600 MB/512 MB 超卖）、§4.15（可见性矩阵）。
*已实测否证或未复现* —— `Shutdown` 帧打死容器、抢读宿主请求偷 stdio fd、
notif 循环队头是主要拖死源（净增仅 ~5%）、当前形态下 root 代读兄弟 `/proc`。
*仍是推论* —— on-behalf `connect` 黑洞造成的队头、`notify_rate_limit` 的沙箱级节流波及、
rootless worker 下跨箱 control.sock 读取、多 child checkpoint 的失败形态。


## 11. 备选路线评估：把 `sandlock-oci` 当 E2B 主入口（2026-09-04 实测）

**问题**：既然 oci 已经有"一实例多进程 + `exec`"，能不能不下沉 core，直接让 envd 用 oci？
**结论**：**机制上已经跑通（我用纯 Python 客户端直连 daemon 协议驱动过）**，它省掉 M0/M1 的大块实现，
但换来的活儿不比下沉 core 少，而且**一条安全前置都省不掉**。判定：可作为实验后端与参考实现，
不建议做长期主入口；但它有两样东西**应该反过来抄进 §8 方案**（见 11.3）。

### 11.1 实测可行性与成本（本机，`tmp/oci-entry4.sh` / `tmp/oci-entry5.sh`，`tmp/oci-lat.py`）

| 项 | 实测结果 |
|---|---|
| envd 侧客户端可行性 | **可行**：连 `--root/<fnv1a16(container id)>.sock`（0700），`sendmsg` 一行 JSON + `SCM_RIGHTS` 三根管道 ⇒ 拿到 `{"result":"pid"}` 与后续 `{"result":"exit"}`；`ping`/`signal` 同理。注意 **CPython 3.14 这个镜像里没有 `socket.send_fds`**，必须用 `sendmsg/recvmsg` |
| 每命令成本（命令 = `/bin/sh -c true`，12 次取分位） | 裸 `fork+exec` 基线 **1.24 ms**；**沙箱内 exec 直连协议 5.85 ms p50**（机制净增 ≈4.6 ms）；**走 `sandlock-oci exec` CLI 11.57 ms**（CLI 进程白送 +5.7 ms）⇒ **必须绕开 CLI**，但绕开后 5 ms 级仍远低于 E2B 100 ms 首字节预算 |
| 共享预算（§3.8 收益） | **今天就成立**：同实例两 child 各 300 MB / 上限 512 MiB ⇒ 只有 1 个成功（§10.2 V5）|
| 协议健壮性 | **Exit 帧会丢**：直连客户端 12 次里 **2 次**读到 EOF 却没拿到 `Exit`（daemon 先关了连接）⇒ 客户端绝不能把"连接关闭"当"退出码 0"。CLI 侧 12/12 rc 正常，但未验证它是等到了 `Exit` 还是丢了当成功 ⇒ **待复核 `cmd_exec` 收尾** |
| 连接模型 | **一条连接一个命令**（`send_command` 的用法），exec 例外（同连接上 `Pid` → 稍后 `Exit`）⇒ 无事件订阅通道，E2B 的多订阅者/重放仍在 envd 侧自建（与现状一致）|
| 现有 verb | 只有 `Start / Ping / Shutdown / Checkpoint / Exec / Signal`（`supervisor.rs:166-191`）|
| 常驻成本 | 每容器**两个常驻进程**（一个 9 线程/16 fd 带 tokio+notif 循环，一个 2 线程/5 fd），RSS ≈ **14.3 + 10.4 ⇒ 约 25 MB / 沙箱**（**debug 构建**，release 会更低）。`E2B_MAX_SANDBOXES=100` ⇒ **≈2.5 GB/节点** 只是 supervisor 常驻 |

### 11.2 走 oci 会省掉什么、又会新增什么

**省掉**：M0/M1 的核心工作（init 循环、`proto`、`fdpass`、child 表、退出回报、per-exec `argv/env/cwd`）
全是现成的，`checkpoint` 也有 verb。

**新增（这才是真实成本，且不比 core 化小）**：

1. **策略入口**：E2B 每条命令/沙箱下发的 `net_allow / net_deny / http_allow / http_inject / host_mask /
   egress_proxy / net_allow_bind / fs_denied / fs_mount / max_open_files / uid / gid / clean_env /
   protection_policy` 都在 Python 绑定 kwargs 上，而 OCI config 只映射了
   `memory / pids / cpu / mounts / user`（`policy.rs:232-272`）⇒ 必须在 oci 侧开一条扩展通道
   （annotations 或自定义 spec 字段）+ 契约测试。**这是 §8 清单之外的新工作量**，且是 E2B 专有字段，
   上游接受概率低。
2. **per-child 生命周期缺失**：只有组级 `Signal{signum}` —— 实测一发就把**整个容器**打死
   （§10.2 V0），而 E2B 的命令超时/取消必须只杀一条 ⇒ 需要新增 `Signal{pid}` / `Kill{child}` /
   `Wait{child}` verb（等于把 §7.4 S10 在协议上做一遍）。
3. **缺 `pause/resume`、`stats`、`update_network`、port-mappings 的 verb** ⇒ E2B 的
   `sandbox.pause()`、`/metrics`、`PUT /network`、`get_port_mapping` 全要新增。
4. **PTY 不支持**：`-t/--console-socket` 接受但忽略（crate README）⇒ 只能继续套现有 in-sandbox
   PTY bridge（带内 resize 帧那套）。
5. **per-exec 策略增量依旧没有**（PTY 要 `/dev/ptmx` 写、网关要 bind 端口）⇒ §4.3 的
   "实例上限 = 并集"棘轮问题一模一样，走 oci 不解决。
6. **运维面**：N 个 Rust 常驻进程的监管（崩溃重启、僵尸、systemd/容器编排里的 sidecar 语义）、
   metrics 抓取、autoscaler 与驱逐要按"进程组"重算；worker 重启时这些 supervisor 的归属要明确
   （core 方案里它们随 envd 进程一起消失）。

### 11.3 oci 反过来该被 §8 抄走的两件事

| 维度 | oci 现状（实测） | §8 计划（exec 进 core 控制 socket） |
|---|---|---|
| 通道位置 | `state_dir()/<fnv1a16(id)>.sock`，root = `/run/sandlock-oci` 或 rootless `$XDG_RUNTIME_DIR/sandlock-oci`，目录/socket 0700 | `/dev/shm/sandlock-<getuid()>/<**明文 sandbox id**>/control.sock` |
| 沙箱内可见性 | `/run/sandlock-oci`、state 目录、`/dev/shm`（默认配置）**全 EACCES** ⇒ **exec 通道在沙箱内不可见** | 一旦 `/dev` 进挂载表（E2B 镜像 rootfs 形态就这么干）：**可枚举、可 connect、`config` 无鉴权返回对端策略**（§10.2 V4）|

⇒ 若照 §8 把 `exec` verb 塞进 core 那个明文名字 + `/dev/shm` + 只告警不拒绝的协议，
等于**把"在别人沙箱里跑代码"的入口放进租户可见的位置**。所以无论走哪条路，都应吸收 oci 的布局：
**exec 通道不落 `/dev/shm`、目录名哈希、`SO_PEERCRED` 不匹配即断开、再加会话 token**（§4.10 缓解④）。

### 11.4 一条都省不掉的前置

SL-4（fd 3 继承 ⇒ 伪造退出码 + `early_exits` 无界，均已实测）、SL-5（init 的 fd 关闭/分帧）、
SL-6（孤儿无回收）、SL-8（`proc_count` 可累加泄漏，实测）、per-child 进程组（§4.6 实测可一把杀）、
SL-1（on-behalf 写入身份）。而且**一旦 oci 成主入口，这些从"潜在缺陷"直接变成生产现网问题**
—— 租户代码今天就拿得到 daemon 的写端。

### 11.5 建议

- **短期想拿 §3.8 的收益**：可以起一个 **oci 后端实验分支**（feature flag、先不接网络策略），
  用它验证"共享预算 + 会话生命周期 + 驱逐/删除收尾"的真实手感 —— 门槛低（本实验已跑通），
  但**不要接生产租户**，11.4 一项未修。
- **长期主入口仍建议"取机制、不取接口"**：init/proto/fdpass 下沉 core（M1），envd 走绑定；
  因为 11.2 的第 1/2/3 项在 core 里只是方法签名，在 oci 里要开协议洞 + 塞 E2B 专有字段。
- **例外**：如果 fork 侧愿意把 11.2 的 1/2/3 做成 oci 的一等能力（annotations + per-child verb +
  `stats/pause/resume`），那"oci 当主入口"就变成合理选择 —— 这时 E2B 侧反而不用碰 core。
  这是唯一一个值得重新评估 §8 决策的分支，可以先探上游意愿。
