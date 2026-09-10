# CHANGELOG — sandlock fork（fork-plan-2026-09，F0–F17）

> 范围：`upstream-pr/netns-free-clean`（本地提交，未推送）。本文件以 release-note 语义
> 汇总 fork-plan F0–F12（2026-09-04/06）的特性、修复与**用户可见行为变化**；每条可追溯到
> commit（短 hash 见正文，完整链 `git log dab4087..HEAD` 与任务报告 `tmp/sdd/f*-report.md`）。
> 每套件实测基线见 `docs/test-baseline.md`；跨任务遗留见 `docs/fork-plan-followups.md`；
> E2B 集成状态见 `docs/e2b-integration.md`。

## 行为变化（升级 / 接线前必读）

- **cwd 由请求决定 + 挂载别名确定性（A2，2026-09-10）**：同一个宿主目录被挂在多个
  虚拟路径下时（E2B 的 `/workspace` 与 `/home/user` 就是同一个目录），此前有三处
  行为由「宿主路径反查」决定，结果既歧义又依挂载声明顺序：
  ① `chdir` 记录的是 `host_to_virtual(readlink(fd))`（平局取**最后**一个声明），
  于是 `chdir("/workspace")` 会记成 `/home/user`，`getcwd` 与之后所有相对路径都
  跟着错；② `host_to_virtual` 平局取末位，`/proc/<pid>/fd`、`/proc/<pid>/cwd` 的
  命名同样不确定；③ 相对路径按别名落到 `/home/user` 后，**看不到**声明在
  `/workspace/mnt/data` 下的子挂载，`cat mnt/data/x` 得到 `EACCES`。
  **现在**：`chdir` 记录请求的虚拟路径（存在性/errno 仍由 `openat2_in_root` 证明）；
  `host_to_virtual` 平局按**声明顺序取第一个**（longest-host-source 优先）；
  挂载查找先经「宿主实现 + 反查」把别名归一到规范拼写再匹配，于是子挂载对其
  同源别名同样可见（`/home/user/mnt/data/x` → 卷）。**用户可见**：`pwd`/`getcwd`
  报告请求的别名；同源别名下声明在兄弟别名上的子挂载现在可达（此前 `EACCES`）。
  **deny / read-only 取更严（同一宿主对象的别名拼写都生效）**：别名归一让
  `/home/user/mnt/data/...` 也能落到卷上，于是 `fs_deny` 与 `fs_mount_ro` 的判定
  同时吃三处拼写 —— **请求拼写**、归一后的**规范拼写**、以及该宿主路径在**每个
  挂载下**的拼写，任一命中即算命中（deny 优先于只读，只读优先于「已挂载即放行」）。
  否则「写在 `/workspace/mnt/data` 上的 deny」会被同源别名 `/home/user` 绕过 ——
  那正是别名归一新引入的暴露面（评审构造路径）；三个别名时「写在中间别名上的
  deny」同样会被走第三个别名的请求绕过，所以按宿主对象折叠而不是按两个拼写。
  放行面（`is_mounted`）仍按请求拼写，不因别名归一而收紧；反方向（deny 写在被
  更深挂载遮蔽的别名上、请求走规范拼写）**未**折叠 —— 那是「deny 按虚拟前缀匹配」
  的既有语义，本次不动。
  **cwd 是逻辑路径**：`chdir` 记录请求拼写，因此 `cd <符号链接>` 之后的 `..`
  按**逻辑父目录**解析、`getcwd` 报告请求拼写，而不是内核解析出的物理路径
  （与 POSIX `getcwd` 的物理路径语义不同；用户决定 #2）。
  本提交另加 core_lib +3（`host_to_virtual_tie_breaks_on_declaration_order`、
  `mount_walk_folds_a_shared_directory_submount_onto_the_canonical_alias`、
  `mount_walk_falls_back_to_the_input_when_it_cannot_converge`）、
  core_integ +2（`test_deny_declared_under_one_alias_covers_the_other_alias`、
  `test_read_only_declared_under_one_alias_covers_the_other_alias`）；
  `test_instance_chroot` 的两条 RED（别名子挂载、请求别名身份）由 `aadb5ad` 引入，
  在此转绿。

- **route-B 客体内身份对齐（F18，2026-09-10）+ 设备节点按文件类型拒绝**：
  E2B 把 `E2B_PER_SANDBOX_UID` 翻成默认后实测发现，同一负载在两种后端下客体内身份
  不一致 —— 进程内后端（特权 supervisor 为子进程写 `0 -> host_uid`）里沙箱是
  **uid 0**，而 route-B 槽位本身就是那个 host uid，`confine_child` 的 `userns_needed`
  判定「请求身份已等于当前 euid」⇒ 不建 userns ⇒ 客体内直接是 X（`apt-get`、
  `chown`、bind 低位端口这类用法就此失效）。
  **修法**：新增 `SandboxBuilder::userns_self_map`（只在 Rust 侧，不上 policy wire、
  不进 CLI）。槽位在 `euid != 0 && user.is_some()` 时先 `probe_userns_self_map()`
  —— fork 一个一次性子进程真做 `unshare(CLONE_NEWUSER)` + 写 `0 euid 1`，因为
  Ubuntu 24.04 的 `apparmor_restrict_unprivileged_userns=1` 会让「unshare 成功、
  map 失败」—— 可用才置位；`confine_child` 随即自映射 ⇒ 客体内 uid 0、宿主侧仍是 X
  （内核比较 kuid，跨租户 DAC 不变）。**探测不通就不建 ns**，客体内保持 host uid：
  比请求的权限更少、绝不更多，因此不失败；实际形态经 `stats.guest_uid`
  （`uid-0-in-userns` / `host-uid`）回报，槽位 stderr 也写一行，worker 据此记日志。
  **配套收紧**：自映射带来 in-ns `CAP_MKNOD`，沙箱便可能在可写目录里造**块/字符设备
  节点**再 open（现实上只有 runtime 的 device cgroup 会挡，裸进程没有）。因此
  `mknod`/`mknodat` **按文件类型位**过滤（`AND S_IFMT` 后比 `S_IFBLK`/`S_IFCHR`），
  不是整号屏蔽 —— `mkfifo()` 用的正是同一 syscall 的 `S_IFIFO`，真实负载需要它。
  新增 `test_arg_filters_block_device_nodes_but_not_fifos`（core_lib 841 → 842）；
  端到端证据在 E2B 契约
  `test_slot_restores_in_guest_root_without_device_nodes`（客体内 `id -u`=0、
  `mkfifo` 成功、`mknod b` 得 EPERM 且节点不存在）。

- **route-B transport 1 的语言面 + 客户端错误分支修复（F17，2026-09-09）**：F16 只把
  registered-path（transport 2）暴露给 C/Python，fd handoff（transport 1）仍只有 Rust
  （worker 需要一条已连好的 `UnixStream`）。E2B 接线 route B 时实测出这条缺口为何要紧：
  registered 形态的 channel token 只能经 `--token` **argv** 提供，而
  `/proc/<pid>/cmdline` 是 0444 且**不受 ptrace 门约束**（`environ` 才 0400）⇒ 本机任意
  uid 都能读到别人槽位的 token 与 socket 路径（当前仅被 `--peer-uid` 白名单兜住）。
  **新增 C ABI**：`sandlock_supervise_connect_fd(fd, token, err, err_msg)`（取 fd 的私有
  dup 作为**持久会话**；`token` 可为 NULL——描述符本身就是凭证）、
  `sandlock_supervise_check_fd(fd)`（交付前预检：非 socket / 非 SOCK_STREAM / 非 AF_UNIX
  点名拒绝）、`sandlock_supervise_set_timeout(h, timeout_ms, err, err_msg)`
  （`0` = 一直等到槽位回答）。`sandlock_supervise_request` 不改签名，按 handle 形状分派。
  **Python**：`SuperviseChannel(fd=..., token="", timeout_ms=...)`（与
  `SuperviseChannel(path, token)` 同一 `.request()` 面）、模块级 `check_control_fd(fd)`。
  **持久单流的两条纪律**：会话由 handle 内的锁串行（绝不让两个线程在同一连接上交错帧）；
  任何 verb 失败即**退役**该会话（后续调用点名 "frame alignment"，不再冒用可能错位的响应），
  所以新通道默认仍是 fail-fast 的 2 s deadline，只有明确要 park 的调用方（`wait_child`
  等一个活着的子进程）才 `set_timeout(0)`。**修 SL-9**：`_take_err_msg` 过去对
  `ctypes.byref(...)` 取 `.contents` ⇒ 每个 transport 失败都抛
  `AttributeError: '_ctypes.CArgObject' object has no attribute 'contents'` 并吞掉服务端
  文本；现在按地址读取并释放，失败一律是带文本的 `SandlockError`。**用户可见**：FFI 动态
  符号 159 → 162；registered 路径行为不变（每 verb 一条新连接、固定默认 deadline）；
  `python` 基线 455 → 460（+5，`test_supervise_channel.py` 的 fd-handoff 用例）。
  envd 侧由此把 route-B 槽位的 token 与 socket 路径从 argv/`/tmp` 彻底拿掉（E2B
  `E2B_ROUTE_B_TRANSPORT` 默认 `fd`），并顺带获得「worker 崩溃 ⇒ 通道 EOF ⇒ 槽位按
  `finish()` 异常收口自杀」的生命周期保证。

- **F17 附带硬化：控制描述符的 `FD_CLOEXEC`（同文件 `serve_control_fd`）**：fd handoff
  要求 launcher 清掉 `FD_CLOEXEC` 描述符才能跨 `exec` 存活；若 supervise 不再置回，
  主管**自己的**控制端就可能被 `sandlock-init` 及其子进程继承 —— SL-4 同族（沙箱内进程读到
  发给 worker 的帧、含 SCM_RIGHTS 的 stdio 描述符；并会把连接吊住，使这一代沙箱熬死 worker）。
  本树实测：core 交给 init 的是显式 fd 集合，**未观察到泄漏**（把 fix 前后都跑过一遍，
  `/proc/<stats.pid>/fd` 比对结果相同），因此这是**护栏**而非 bug 复现：仍在 launch 前无条件
  `fcntl(F_SETFD, FD_CLOEXEC)`，并用 fork python 用例把不变量钉住（比对 worker 端 socket
  inode）。附带收益：worker 崩溃后槽位按 EOF 走 `finish()` 异常收口（E2B 侧契约
  `test_worker_death_ends_the_generation` 实测槽位退出）。

- **route-B worker 侧客户端暴露给 C 与 Python（F16，2026-09-08）**：registered-path
  槽位（`sandlock-supervise --serve-path NAME --token T [--peer-uid UID]...`）的
  worker 面此前只有 Rust（`channel_request_with_fds`；`connect_and_request` 不带 fd）。
  F16 新增 C ABI：`sandlock_supervise_connect(path, token, err, err_msg)` /
  `sandlock_supervise_request(h, verb, args_json, fds, n_fds, err, err_msg)`（返回
  `ControlResponse` JSON 原文，`exec` 的 stdio 三端随帧 SCM_RIGHTS 交付）/
  `sandlock_supervise_free(h)`（错误沿用既有 `err`/`err_msg` 约定）；Python 薄包装
  `sandlock.supervise.SuperviseChannel(path, token).request(verb, args=None,
  fds=()) -> data`（非 ok 响应抛 `SandboxError`，transport 错误抛
  `SandlockError`）。**用户可见**：FFI 动态符号 156 → 159（verify 双向相等随之更新）；
  envd（E2B）从此能当 route-B worker（exec + wait_child + kill_child +
  update_network + shutdown）；T5 的 per-uid 卷保护从此有 Python 可达证据
  （`mediation_2uid` 新增跨 uid Python-client 用例）。wire 不变（registered 协议
  与 init 帧协议互不相干）；两条部署约束（`sun_path` 108 字节上限；一 uid = 一个
  supervise = 一代沙箱，槽位复用只能靠重启）见
  `docs/supervise-identity-handoff.md` §10。

- **控制帧每帧声明自己的描述符数（F15，2026-09-08，`FRAME_VERSION` 1 → 2）**：init
  控制通道是 `SOCK_STREAM`，一次 `recvmsg` 可并入多帧，而内核交回的 SCM_RIGHTS 描述符是
  **一条拼接列表**；旧实现把「本读单元的全部 fd」当成「本帧的 fd」（`fdrecv::recv(ctl, 3)` +
  `received.fds[0..3]`），前一帧带 fd 时后一帧的 stdio 会整体位移——两个 `RunExec` 合并在
  一次读里时，exec #2 的 stdout 会写进 exec #1 的管道并整条丢失。**修法**：帧头新增 1 字节
  `n_fds`（`FRAME_HEADER_LEN` 10 → 11），发送侧在 `encode_frame` 声明每帧 fd 数（只有
  `RunExec` 是 3），接收侧用纯函数 `take_frame_fds` 按声明从读单元队列切分，声明与队列不符
  ⇒ 整读单元拒绝（不投毒任何一帧）；`MSG_CTRUNC` / `MSG_TRUNC` 不再被忽略——描述符或载荷
  被内核截断即整个控制通道 fail-closed。`RunExec` 需**恰好** 3 个描述符，多了/少了都回
  `exec needs 3 fds`。**用户可见**：wire 不兼容（v1 帧在 v2 init 下建箱期即点名拒绝），
  半升级不会静默错输出；合并帧场景下每个 exec 只拿到自己声明的 stdio。夹具：
  core_lib 837→841（`take_frame_fds` 4 条纯函数单测）、root 档 oci 145→150
  （两帧一次写出六端各归其主 + 帧头 `TooManyFds` / v1 头版本点名单测）。本变更与 FUP-23
  的 stdio 预搬迁/身份校验正交（F15 只改「哪三个 fd 进 `stdio`」）。

- **exec stdio 在宿主形态下会被外部换端 ⇒ init 侧 fork 前预搬迁 + 子进程装配前身份校验
  （FUP-23，2026-09-08）**：pure 形态（沙箱与宿主 agent 同进程）下，命令的 stdout 可能
  **整条静默丢失**（CPython `exit 120`、`/bin/echo x` ⇒ 1、shell 重定向 ⇒ 2），判别变量是
  宿主进程的 fd 表。取证：父端送出、init `recvmsg` 返回、装配前、`fork` 前、`fork` 后 init
  自身这五个快照点的 `(O_ACCMODE, st_dev, st_ino)` 全部正确，只有子进程 `fork` 后第一条指令处
  第 3 端已变成另一条管道的读端（marker 管道实验证明父子 fd 表不共享）⇒ SCM_RIGHTS 链路清白，
  换端由**外部方**在新生儿身上装低号描述符造成（E2B 侧 argv 安全的 ptrace fork 事件跟踪 /
  supervisor `NOTIF_ADDFD` 一类注入）。换到 stdout 槽就丢输出，换到 stderr 槽只是没人发现 ——
  旧「多开 1 个 fd 即恢复」的绿只是换到了不致命的槽。**修法**：init 在 `fork()` 前把三端
  `dup3` 到保留号段 64+（保留号不全部空闲就整体退回原号，绝不覆盖别人还持有的描述符），
  子进程 dup2 之前逐槽校验身份；被换端 ⇒ **拒绝装配**，消息写到仍然完好的流上并以退出码
  **124** 结束该 exec —— 最坏情况从「静默丢数据」变成「明确失败」。父进程 fork 后关闭保留
  副本，子进程关闭保留号与原始接收号（既不漏描述符，也不破坏宿主侧 EOF）。
  **用户可见**：上述丢输出回归消失；新增 124 这一条 exec 级失败语义（与 125 chdir、
  126 setpgid、127 exec 失败并列）；FUP-14 事件化 reap 的回退撤销，exec 往返 p50 恢复
  5.35 ms 一档。夹具：core_lib 833→837（搬迁与身份 / 占号退让 / 三端精确不串流 /
  换端拒装配）、root 档 oci 144→145（真 `run_init` 控制环 40 轮 exec：逐轮输出精确、
  init fd 表逐轮回到基线）。取证与修法细节见
  `docs/fork-plan-followups.md`「FUP-23 根因闭环与修复」。

- **C 档特权 remap gate 升级为 capability-aware（F14，本地提交）**：路径中介
  建箱前拒绝的判定从 `euid == 0` 扩展为「实际持有跨 uid remap 特权」——euid 为 0，
  或 euid 非 0 但 effective caps 含 `CAP_SETUID/CAP_SETGID`（route-B ③ file-cap
  launcher 形态，`setcap cap_setuid,cap_setgid+eip`）。此前这类进程（euid 非 0 +
  caps）会绕过 C 档 gate，落在晚到的「unprivileged supervisor cannot map」拒绝
  （错误信息暗示无 caps，部署排障误导）；现按 C 档 fail-closed 以点名能力的新
  错误在建箱前拒绝。无 caps 的非 root（生产形态）、同 uid 自映射、host uid 0、
  route-B supervise 交接均不受影响；root euid 原行为与消息不变。
- **目录挂载点的 rmdir 与真实 bind-mount 一致拒绝（F13，本地提交）**：chroot /
  `fs_mount` 形态下对**目录**挂载点本身执行 `rmdir`（含 `unlinkat(AT_REMOVEDIR)`）
  返回 `EBUSY`，不再直通宿主目录——此前空宿主目录会被沙箱视图内的 rmdir 直接删除
  （FUP-05 披露项闭环）。普通目录在挂载点内部仍可正常 mkdir/rmdir（只保护挂载点
  本身）；单文件/chardev 挂载点的 rmdir 仍回落到宿主 ENOTDIR（与内核一致）。
  顺带补 `link()` 于 rw 单节点挂载点的直击 pin（既有 EBUSY 守卫的测试缺口，
  FUP-04a）并把遗留的 `contains` 式断言收敛为整串精确断言。
- **ProcessIndex 改为每 TGID 一个 entry（建模收口，F12，本地提交）**：发出过被
  中介 syscall 的非 leader 线程不再以线程 tid 懒登记独立 entry（Linux 6.9+
  `PIDFD_THREAD` 路径删除）——线程通知一律解析并路由到其 TGID leader 的 entry；
  leader 未跟踪时以 leader pid 注册（pidfd + start_time）。`ProcessIndex`
  的 key 集合即 TGID 集合：无每线程 pidfd watcher/冗余状态，freeze/记账/cwd/退出
  清理不再依赖「同 TGID 多 key + leader fallback」的隐式约定（F11 冻结侧归一化
  保留为防御）。**用户可见**：内存/进程配额、exec、cwd、freeze、checkpoint 语义
  不变；`stats().live_watchers` 现按进程组计数（此前 6.9+ 内核下被中介过的线程
  会各自占一个 watcher 计数）；6.9+ 内核上虚拟化 `/proc` 列表不再单独列出被中介
  线程的 tid 目录（与旧内核既有行为一致，列表按 leader 归组）。旧内核形态
  （线程永不建 key）从「部分内核的角落」变成唯一形态，`/proc/<tid>` 可读性判定
  同步改为 leader-aware。E2B 真栈 thread/gateway 复跑（wheel = 4d5f385，
  2026-09-07）全绿：线程化 holder 存活时后续 exec 恢复成功、FUP-E3
  gateway+命令变体 pure 4/4、full gate A/B/macOS 0 failed（见
  `docs/e2b-integration.md` §5 F12–F14 E2B 复跑行）。
- **argv-safety exec 冻结兼容实例内多线程进程**（F11，本地提交）：E2B 探针实测
  线程化网关/uvicorn 一旦存活，后续每条命令 exec 都被拒
  （`argv-safety freeze failed ... PTRACE_SEIZE ... Operation not permitted`
  → child exit 127）。根因不是"线程未被 birth-track 而不可 seize"，而是
  `ProcessIndex` 会为发出过被中介 syscall 的非 leader 线程**额外登记一个以线程
  tid 为 key 的条目**（与 leader 同 TGID）；exec 冻结按 index key 逐个当作独立
  TGID 走 `/proc/<tgid>/task`，同一线程组被枚举两次，第二次
  `PTRACE_SEIZE` 命中的正是本冻结刚冻结的 TID ⇒ EPERM ⇒ 拒 exec。修法：冻结前
  把 index keys 归一化为唯一 TGID（`freeze.rs`），每个线程组只冻结一次；
  TOCTOU 不变量不变（argv 写入者 = 同 TGID 兄弟线程 + 异 TGID peer，仍全部
  冻结到 NOTIF_SEND 之后），线程数/进程数语义、birth-track 与计费规则不动。
  用户可见变化：多线程进程存在后，exec-only 实例的后续 exec 恢复成功（E2B
  FUP-E3 网关+命令变体的 fork 侧阻塞解除）。
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
- **A/B cleanup wave 的行为变化（FUP-01..18，2026-09-07，本地提交）**：
  * `--pid-ns` 在 CLI 上真正接线（FUP-01，`262c0cf`）：此前 flatten 后的参数没转发给
    runtime builder，CLI 用户无法开 `pid_ns`（FFI/Python/profile 早已生效）；现按
    `--mediation-run-as` 的形态有 CLI→运行时回归。
  * supervise **异常代次结束**改为同步清场后再退出（FUP-03，`dac18ed`）：worker 先关
    控制通道时不再与进程退出竞速，此前会留下 ppid=1 的 uid-X 僵尸/孤儿 workload。
  * 信号面两步逃逸（setpgid → setsid 伪装箱内）被检测，`dead_groups` 与活 child pgid
    重叠时去重，不再可能双 `killpg`（FUP-10，`d5bbdd8`）。
  * ~~exec/exit 往返去掉 ~100 ms 轮询地板（FUP-14，`7671240`）~~ **已回退**
    （`bb1cb42`）：事件化 reap 实测能把 p50 从 101.75 ms 降到 5.35 ms，但它让 init 多占
    一个低位 fd，从而把 FUP-23（exec stdio 对 fd 号敏感）从潜伏变成可达——pure 形态下
    命令 stdout 整条丢失。收益随回退一并撤回，重做需与 FUP-23 一起验证。
  * route-B registered slot 的异常连接日志改**节流**（FUP-11c）：首条照常点名，其后每
    256 条打一条并带累计数——被拒连接数不再线性放大 slot stderr（300 条被拒 → 2 行）。
  * release profile 变发布面（FUP-15，`b1e2e32`）：`panic=abort` + `strip="symbols"`；
    wheel 侧 supervise 注入改 RECORD **replace-in-place**（不再追加第二行）+ verify
    增校 RECORD/0755/euid+`--uid`（FUP-16，`b87524a`）。
  * profile 支持 `mediation_run_as` 且 CLI 省略 flag 时不覆盖 profile 值（FUP-07，
    `48968a5`）；非 root runner 拒绝以 root 跑非 root 档（FUP-17，`e57cebf`）。

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
- `--pid-ns`（FUP-01 `262c0cf`，A/B cleanup wave 接线）：flatten 后的参数此前没有
  转发给 runtime builder，CLI 形态下 `pid_ns` 静默不生效；现在与
  `--mediation-run-as` 同形态，并有 CLI→运行时回归钉住。

## 测试 / 验证基座

- 全量门禁 = 非 root 档（core_lib 833 / core_integ 534 / ffi 100 / cli 100 /
  supervise 42 / supervise_cost 3 / cli_build 0 / python 454）+ root 档
  （oci 144 / supervise_root 4 / mediation_2uid 9）+ `--wheels`；
  数字逐 commit 登记 `docs/test-baseline.md`，脚本缺一即红、skip 即红。
- 本计划新增用例全部随阶段 commit 落盘（红→绿证据在 `tmp/sdd/f*-red*.log`，
  终局全绿 `tmp/sdd/f9-gate-*.log`）。
- A/B cleanup wave（2026-09-07）另加两条纪律：门禁日志必须带 ENV-HEADER
  （commit / 容器镜像 / 时间），套件 flake 时保留首条红档 `<label>-r1.log` 另跑
  `-final.log`（FUP-09）；supervise 的 error-path 断言一律整行/整串精确，
  唯一允许的动态段是 OS 分配的 fd 号与 elapsed 计数（FUP-11a）。

## 明确取舍 / 已知限制（不是缺陷修复）

- **⚠ pure 形态 exec stdio 的低位 fd 依赖（FUP-23，2026-09-07 发现，未修）**：
  承载沙箱的进程如果**除 0/1/2 外不持有任何描述符**（下一个可用 fd = 3），pure
  形态下 exec 出去的命令会**丢掉整条 stdout**（CPython 退出期 flush 失败 ⇒ exit
  120；`/bin/echo x` ⇒ exit 1；`> /tmp/f` ⇒ exit 2），只要预先多开 1 个 fd 就正常。
  根因面在 stdio 搬迁下界（`relocate_high` 只要 ≥3）与桩/控制通道的**固定低位号**
  （`CONTROL_FD = 3` + READY/GO）可重叠，被覆盖后子进程 fd 1 不可写。A/B 取证：同一
  镜像只换 debug `.so`，本波之前 tip `4d5f385` 绿、FUP-14 `7671240` 红 ⇒ **本波的
  signalfd 让潜伏缺陷变得可达**（FUP-14 自身功能与延迟收益不受影响）。全量门禁与
  入库契约看不到它：pytest/cargo 进程天然持有几十个 fd。生产 envd 服务在启动后即
  打开监听 socket ⇒ 不在触发条件内，但**任何以「几乎空 fd 表」嵌入沙箱的形态会踩到**。
  登记与修法见 `docs/fork-plan-followups.md` FUP-23；E2B 侧对应
  `docs/task-backlog.md` #22。**本波已用「回退 FUP-14」把它压回潜伏状态**（当前
  wheel 不带这个用户可见故障），但根因未修：任何改动 init 低位 fd 分配的改动都可能
  再次触发，升级前仍请读这条。

- P6 getsockname/getpeername 合成视图与 fd-inject `EINPROGRESS`：设计取舍 +
  回归 pin（F8 `c8f76d4`，`docs/e2b-integration.md` §3.10）。
- P4（T4）chroot+net_isolation 入站：fork 侧前提证伪 + 回归 pin（F7 `4e78c98`），
  E2B 复测为 out-of-fork follow-up。
- 其余跨任务 Minor / follow-up 汇总：`docs/fork-plan-followups.md`。
