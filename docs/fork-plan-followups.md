# Open follow-ups — sandlock fork（fork-plan-2026-09 F0–F11 收口后）

> 来源：各任务评审报告与 `.superpowers/sdd/progress.md` 的 Minor/residual 汇总
> （F9 逐条处置，见 `tmp/sdd/f9-report.md` 的 closure 清单）。每条 = 来源（task/commit）、
> 描述、为什么留到收口之后。凡已在 F9 内便宜修掉的（文档级）不在此列；本地 artifact
> 级（tmp/sdd 报告笔误、日志摘录、运行证据）不在此列。

## A. 代码 / 接线类（需要小代码 + 测试）

- **FUP-25 oci fd 计数测试的 baseline 采样竞态（FUP-24 门禁中发现，2026-09-15）** —
  来源：FUP-24 的 `--oci-root` 第一轮红（`crates/sandlock-oci/tests/integration.rs:1152`，
  `baseline 5 -> after return 6`；日志 `tmp/fup24-gate-oci-red1.log`）。
  描述：`spawn_run_init_probe` 让探针子进程在**调用 `run_init` 之前**先写 `r`（`integration.rs`
  的 `libc::write(ready_w, b"r")` 紧接 `run_init()`），父进程一读到 `r` 就采 `baseline` fd 数；
  而 `run_init` 的 SIGCHLD `signalfd`（`crates/sandlock-core/src/init/mod.rs` 的 `sigfd`，
  进程级、`run_init` 返回时**从不关闭**）是在那**之后**才创建。父进程的 `/proc/<pid>/fd`
  读取一旦赢下这场启动竞态，baseline 就少算这一个 fd，EOF 之后的计数永远 = baseline + 1。
  算术上可排除产品泄漏：若收到并泄漏了 `SCM_RIGHTS` fd，计数应是 baseline + 2（signalfd + fd），
  实测恒为 +1；两条用例（`test_eof_closes_received_fd`、`test_malformed_frames_do_not_leak_fds`）
  共用同一采样点，因此同红同绿。
  **实证（在改动前的 tip `1f113cf` 上复现，与本任务改动无关）**：集成目标单跑 10 轮 + 8 个
  CPU 占用进程，**3 轮红**（`test_eof_closes_received_fd` ×1 / `test_malformed_frames_do_not_leak_fds`
  ×2，断言文本与数字逐字相同：`baseline 5 -> after return 6` / `baseline 5 -> after 6`）——
  `tmp/fup24-eof-loadprec-head-r01.log`；同 tip 无负载 9 轮全绿（`tmp/fup24-eof-precedent-r01..r09.log`），
  集成目标单跑 15 轮 1 红（另一条 `oci_stop_collapses_process_group`，`integration.rs:824`，
  同属该目标的负载敏感家族）——`tmp/fup24-eof-precedent2-r01.log`。
  建议修法（**测试侧**，必须保住「fd 表已终态」这一语义、不放宽断言）：把 baseline 推迟到
  子进程**跑完一轮完整请求/应答**之后再采（例如先发一条 `Ping`、读回 `Pid` 再采样），
  或让探针的 `r` 在 `run_init` 建好进程级 fd 之后才发布。
  为什么留：是测试夹具的采样时机竞态、不在 FUP-24 范围（本次只做 `kill --all` 的兜底判据），
  且修法要先定「谁代表 fd 表已终态」这一观测边界，属独立小改动。
  **已关闭（2026-09-15，FUP-26/25 批次）**：采样点改为「先拿到一次**请求/应答往返**再读
  `/proc/<pid>/fd`」，断言判据**一字未放宽**。往返用的是一条**零 fd**、payload 不能解析的帧
  （`{"req":…}` 解析失败 ⇒ init 回 `Err`）——它与 `Resp::Err` 的既有契约一致，且证明「服务循环
  已在跑」＝「进程级 fd（signalfd）已建好」，于是 baseline 就是终态表；三处采样点全部改用它
  （`test_eof_closes_received_fd`、`test_malformed_frames_do_not_leak_fds`，以及本轮门禁又暴露的
  第三处 `exec_frames_deliver_their_own_output_and_leave_no_descriptor_behind`，它的红是同一签名
  `baseline 5 -> now 6`，见 `tmp/f26-f25-loadprec-fixed-r04.log`）。
  机制确定性证据（临时探针 harness，已随任务删除，副本 `tmp/f26/keep-f26_f25_probe.rs.txt`）：
  把竞态窗口人为放宽 10 ms 后，**旧采样顺序** 50/50 次读到未终态 baseline（恒为 5，断言必红），
  **新采样顺序** 50/50 次读到终态 baseline（恒为 6，断言必绿）；不放大窗口时 50/50 两边都读到 6
  —— 与「无负载 9 轮全绿、8 核占用 10 轮 3 红」一致（`tmp/f26-f25-race-mechanism-r02.log`）。
  负载回归：8 个 CPU 占用进程下 10 轮 **10/10 绿**，16 个下再 10 轮 **10/10 绿**
  （`tmp/f26-f25-loadprec-fixed-r05.log` / `-r06.log`）。计数不变（oci 仍 157）。

- **FUP-27 core_lib `list_preserved_default_base_spans_pids` 的 pid/uid 子串误判
  （FUP-26 门禁中发现，2026-09-15）** — 来源：本轮非 root 门禁 `core_lib` 红
  （`crates/sandlock-core/src/cow/seccomp.rs:6786`，`the default base name must not embed the
  pid, got /tmp/sandlock-cow-65534`；`tmp/f26-gate-nonroot-r01.log` 的后续轮次）。
  描述：该用例用「整条路径的 substring」判断 pid 是否进了 base 名，而 tmp 兜底名是
  `sandlock-cow-<uid>`；门禁以 uid **65534** 跑，其十进制串本身就含有 34/53/55 等 pid 的数字，
  于是**正确**的 base 名会被误判 —— 实测在**改动前的 tip**（把本批改动全部 stash 后重编译）
  30 次里 1 次红（pid=34）、另一次 24 次里 2 次红（pid=53/55）：`tmp/f26-f27-preexisting-*.log`。
  与 FUP-26/FUP-25 无关，但会让任何一次门禁随机变红（约 3–8%/轮）。
  **已关闭（2026-09-15，FUP-26/25 批次）**：判据改为只比较 base 名里的**数字 token**
  （`name.split(!is_ascii_digit)` 后与 pid 比较），语义仍是「base 名里不许有 pid token」，
  而「`create(None)` 选到了 per-pid base」这条 revert 仍由它上面的 `chosen_base == expected_base`
  等价断言与本条一起抓住。验证：修后 uid 65534 下 60 次 **0 红**（`tmp/f26-f27-fixed-r02.log`）；
  变异证明：把 `tmp_storage_base` 改回 `sandlock-cow-<uid>-<pid>` ⇒ 每次必红
  （`tmp/f26-f27-mutant-r03.log`）。计数不变（core_lib 仍 848）。

- **FUP-28 e2b 侧「`..` 相对软链改写」可以撤掉的条件（跨仓 follow-up，2026-09-15）** —
  来源：FUP-26（本批）在 fork 侧吃掉了这一切。
  背景：`envd_service/runtime/image_resolver.py::_root_absolute_links` 会把镜像里带 `..` 的
  相对软链改写为等价的 root-absolute 目标，用来绕开「`openat2(RESOLVE_IN_ROOT)` 的 `EAGAIN`
  被当硬失败 ⇒ exit 127 + 空 stderr」。**本轮保留不动**（fork 修复必须先落地并随 wheel 上线）。
  前提（撤之前必须全部满足）：① fork 侧 `EAGAIN` 有界重试已随 wheel 上线（`# HEAD=` 指向
  含 FUP-26 的提交，且镜像内 `sandlock-supervise`/`libsandlock_ffi.so` 指纹与 manifest 一致）；
  ② 目标平台的宿主内核在 `RESOLVE_IN_ROOT` + `..` 上确实会返回 `EAGAIN`（而不是只在我们
  这台 orbstack 内核上）—— 即上线的**所有** worker 宿主都跑过 ③ 的验证；
  ③ 验证方式（按宿主逐个跑，任何一次不为 0 就不要撤）：取一个**未改写**的镜像 rootfs
  （对任意 entry 复制一份、把 `lib64/ld-linux-x86-64.so.2` 还原成 `../lib/x86_64-linux-gnu/…`），
  在**等价竞态负载**下用产品路径打点：受管 open 连续 97482 次必须 0 失败、300 条
  `exec /bin/echo` 必须 0 次「127 + 空 stderr」，同时内核侧原始 `EAGAIN` 必须 > 0（证明
  重试真的在起作用）。本批的这条命令与数字见 `.superpowers/sdd/task-f26-report.md` §3。
  撤掉后的回归网：`tests/unit/test_image_rootfs_links.py`（整树无 `..` 相对软链）与
  `tests/unit/test_oci_registry.py` 的「chroot 内解析到同一 inode」钉子需要同步调整/删除，
  这正是当初为了绕开本 bug 才加的那两条。

  **前提②已在部署宿主上量过（2026-09-22，E2B 侧）**：把触发机制直接复现 —— 一个
  `..` 相对符号链接（`lib64/ld.so -> ../lib/real/ld.so`）+ `RESOLVE_IN_ROOT`，同时用
  4 条线程在**被走的路径下面**反复 rename，然后统计 errno（探针
  `sandlock-e2b/tmp/k0s/probe_openat2_eagain.py`，一次 40000 次 openat2）：

  | 宿主 | 内核 | EAGAIN / 40000 | 成功 |
  |---|---|---|---|
  | `.94`（k0s 控制面节点） | 6.12.0-211.34.1.el10_2.aarch64 | **8107（20%）** | 18398 |
  | `.140`（worker 节点） | 6.12.0-211.34.1.el10_2.aarch64 | **6855（17%）** | 17511 |
  | 开发容器（对照） | 7.0.14-orbstack x86_64 | 730 / 20000（3.7%） | 7446 |

  ⇒ **这两个宿主内核确实会返回 EAGAIN**（不是只有开发内核会），所以本仓的 `EAGAIN`
  有界重试在线上是**真的在被用**；前提①也成立（集群 worker 镜像里的 wheel manifest
  HEAD = `7b60349c`，含 FUP-26）。**剩下的只有前提③**：那是**产品路径**的竞态 soak
  （受管 open 连续 97482 次 0 失败、300 条 `exec /bin/echo` 0 次「127 + 空 stderr」、
  同时内核侧原始 EAGAIN > 0），要在**部署宿主**上跑，而 worker 镜像里没有 cargo ——
  要么在节点上起 sandlock-dev 类镜像，要么交叉编译出 arm64 的 soak 二进制塞进一次性 pod。
  在那之前**保留改写**（它的代价只是每沙箱建箱时一次树走查 + "沙箱看到的文件系统与镜像不同"
  这一点），撤掉的收益不足以承担没有 soak 的风险。

- **FUP-29 「已捕获的（park 形态）会话里再 exec」在本机 harness 上间歇性卡死
  （2026-09-25 开、同日关闭）** — 来源：为 E2B 的 route-B 形态新增
  `SandboxInstance::checkpoint_excluding_main()`（会话主子进程是 park 时，捕获"旁边那一个"），
  在新用例里先捕获、再往**同一会话** `exec` 一条命令、然后读它的 stdout。

  现象：约 1/3 的运行卡在"`exec` 返回之后、读到那条命令输出之前"，测试主线程停在 `futex`。

  **根因（已定位，2026-09-25）**：是**测试夹具**，不是引擎。`#[tokio::test]` 默认是
  **单线程** runtime，而这个用例在 `read_exact_bytes` 里**阻塞**读子进程的 stdout——
  那一次阻塞读占住了唯一的线程，于是沙箱的**通知循环**（同一个 runtime 里的一个 task）
  再也跑不了，被 exec 的孩子的**第一次 `write` 都得不到应答**：读在等一段永远产不出来的
  输出。之所以间歇，取决于"孩子是否在读开始之前就把输出写完了"。
  `sandlock-supervise` 跑的是多线程 runtime，**夹具也必须**：改成
  `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]` 后，那条 exec 断言**连跑 5 次
  全绿**（0.12–0.14 s）。断言已回到用例里（`test_a_sessions_workload_is_captured_with_the_park_left_out`
  的第 3 条），并连同"为什么必须多线程"写进用例注释。
  同一陷阱的另一面见 FUP-30 的本机 half。

- **FUP-30 「恢复进会话的**动态**程序会死」——2026-09-25 开、同日关闭：
  **不是引擎问题，是验收脚本的命令形状**（本机 probe 的"卡死"则是 FUP-29 的 runtime 问题）**
  — 来源：E2B 侧 checkpoint/restore 的集群验收（E2B 仓
  `docs/checkpoint-restore-e2b-half.md` §6(g)）。

  集群现象（当时的读法）：沙箱 pause（捕获）、删宿主 worker 的 pod、resume，worker 日志逐字报告
  `resumed … into the session (child 1, pid 30)`，但几秒后节点上只剩 worker、slot 与 park，
  **被恢复的 pid 不在 `/proc`**，计数器文件停在 pause 时的值。

  **定位过程（值得留下的是方法，不是结论）**：
  1. 先给验收脚本加 **boot 标记**：负载第一句把自己的 pid 写进文件 —— resume 之后文件仍是旧 pid
     ⇒ 被恢复的进程**连一行都没跑到**（不是"跑起来后被拒"）。
  2. 再给引擎加 **restore 面包屑**（本仓 `89e8ab2`：`checkpoint::resume::note`，`SANLOCK_RESTORE_TRACE=1`
     打开；E2B 侧 `65ad183` 在 restore 之后把 slot 的 stderr 尾巴打进 worker 日志，因为会话里
     子进程的 stdio 是 /dev/null、slot stderr 只被留了一个尾巴）。
  3. 面包屑一眼看出两件事：**握手全部走完**（READY → 填了内存 → sweep → GO 发出），
     而 **50 ms 后子进程已经死了**（`child alive 50ms after the handshake: false`）；
     更关键的是**这张图根本不像 python**：`maps=19`、填进 397312 字节（~388 KiB）。
     本机同样形状（真 python）是 `maps=32..40`、6 MB 上下。
     **19 个映射 / 388 KiB 是 dash 的大小** —— 被捕获的是**包装用的 shell**。

  **根因**：验收脚本的命令串写成 `sh -c 'exec python3 …'`，而 E2B worker 本来就把每条命令包成
  `/bin/sh -c "<串>"`。于是**会话的活子进程是第二个 shell**，python 成了它的孙子：
  捕获按设计只抓"会话里那一个活子进程" ⇒ 抓到的就是那个 shell；恢复出来的也是 shell，
  而它唯一的孩子早就不在了，于是它 `wait4` 拿到 ECHILD、走完脚本、**立刻退出**。
  把命令串改成 `exec python3 …`（`exec` 是**第一个词**，worker 自己的 shell 会原地把自己换成
  python）之后：图变成 `maps=32`、填充 6279168 字节（6.3 MB），
  `child alive 50ms after the handshake: true`，计数器继续前进，验收脚本**全绿**。

  **顺带留下的产品语义**（已写进 E2B 的设计文档）：一次 pause 捕获的是**会话里那个活子进程**，
  也就是 worker 自己 exec 的那条 `/bin/sh -c <命令串>`。单条简单命令会被 dash 原地 `exec`，
  但 `sh -c '…'`、管道、`&&` 列表这类**会 fork 出子 shell** 的形状，被抓的就是那个子 shell。
  引擎没有错（它只答应"抓一个地址空间"），要改的是"谁来做那个地址空间"。

  **这条追下来的真产出**（都不是它自己，见各自条目）：restore-stub 必须随 wheel（`2d5f2e9`）、
  冻结窗口挂起的 fork 通知必须**释放**而不是丢掉（`685301c` / FUP-31）、
  `SANLOCK_RESTORE_TRACE` 面包屑（`89e8ab2`）。
  本机那半（probe 卡死）是 FUP-29 的 runtime 问题；把动态程序 + 真根 + 会话 + restore 做成了
  两个常驻用例。**集群验收（E2B `tmp/k0s/checkpoint_acceptance.py`）现在全绿**。

- **FUP-31 冻结窗口里的 fork 通知被"忘记"而不是释放（2026-09-25，已修）** — 来源：
  E2B 的 checkpoint/restore 线上化（写"park 旁边的兄弟进程"这类用例时量到）。

  描述：捕获/冻结会把 fork 通知**box-wide 挂起**（`NotifAction::Hold` = **不应答**），
  让被冻结子树之外的兄弟进程停在 `fork()` 里；可两处收尾都只做
  `held_notif_ids.clear()`——**把手里的 id 丢了**，于是那个进程永远停在内核里，
  没有任何错误、没有任何日志，沙箱只是"某个子树不再前进"。实测：一个 `while :; do /bin/true; done`
  的 park 在第一次捕获后停住（`held=1`），计数器不再增长。

  **已修（2026-09-25）**：新增 `resource::release_held_forks`（先清 `hold_forks`、
  再逐个 `seccomp::notif::continue_notification` 应答，答案失败即目标已死、忽略），
  notify loop 把自己的 fd 发布到 `ResourceState.notif_fd` 供其应答；
  `Sandbox::thaw` 与 `Instance::capture_checkpoint` 的收尾都改用它。

  RED→GREEN：`test_a_capture_does_not_wedge_a_forking_sibling`（core_integ）——修复前
  稳定红（`held=1`、park 停在 `fork()`），修复后连跑绿；单测
  `release_held_forks_drains_and_reports_what_it_released` 钉住"清 flag + 抽干 + 报数"。
  复现要点写在用例注释里：**多线程 runtime**（否则派发循环在捕获期间根本没机会跑，
  这个 bug 就永远不会被触发）+ 一个**长窗口**（128 MiB 的 python 负载，dump 就是窗口）+
  一个**在窗口内持续 fork 的兄弟**（不受 `killpg` 影响的 park）。

- **FUP-24 `kill --all` 的兜底判据仍是「任何发送错误」而不是「连不上」（f1oci，
  2026-09-14）** — 来源：f1oci 对 oci `test_signal_to_sibling_pid_rejected` flake
  的定真因（见 `docs/CHANGELOG.md` 的 f1oci 两条 + `.superpowers/sdd/task-f1oci-report.md`）。
  描述：修复前 CLI 把控制请求的 payload 与 `\n` 分两次写、supervisor 把一次 `recvmsg`
  当成整条请求，于是 supervisor 在两次写之间应答并关闭连接 ⇒ 客户端补写 `\n` 拿到
  `EPIPE`；而 `cmd_kill` 的 `if sent.is_err() { killpg(state.pid, signum) }`
  把这次 EPIPE 当成「daemon 没收到」自行再投一次 ⇒ 实例级非幂等信号被投递两次。
  **本次已修**分帧（supervisor 读到 `\n` 才成帧；CLI 与 exec 请求把分隔符并进同一次写），
  该触发路径消失；但兜底判据本身仍过宽：真正「请求已送达、答复丢失」（例如 supervisor
  卡到 10 s 答复超时）时仍会再投一次。为什么留：把兜底收窄成「socket 连不上才兜底」
  必须同时给「daemon 已死仍要能 kill」这条降级路径补验收（SIGKILL supervisor 后
  `kill --all` 仍须成功），属独立小改动；当前无已知活 bug（正常路径不可能再触发）。
  建议修法：`cmd_kill` 只在 `UnixStream::connect(socket_path(id))` 失败时兜底，
  其余错误原样上抛（`crates/sandlock-oci/src/main.rs` 的 `cmd_kill` 分支）。
  **已关闭（2026-09-15，FUP-24 收口）**：`supervisor::send_command` 现在返回带分类的
  `SendCommandError`（`NotDelivered` = 连接从未建立、或整条帧的 `\n` 分隔符没写出去；
  `Delivered` = 整条帧已交给 socket，之后的失败只是**答复**丢了）。`cmd_kill --all` 只在
  `!err.was_delivered()` 时兜底 `killpg(state.pid, signum)`（daemon 已死仍能 kill 的降级路径
  保持），`Delivered` 则把错误原样上抛（退出码 1），不再重复投递。`cmd_delete` 的 Shutdown
  兜底**有意保持**原样（SIGKILL 幂等，且 delete 必须把状态拆干净）。RED→GREEN：新增
  `crates/sandlock-oci/tests/test_kill_all_delivery.rs` 三条（「答复丢失但帧已送达」老代码
  确定红：投递 2 次；ENOENT/ECONNREFUSED 仍兜底 1 次；正常回环 1 次 + exit 0）+ 2 条
  `supervisor::tests` 分类单测；oci 150 → 157；wheel 按口径重建 + verify（manifest
  `# HEAD=` = 本次提交）。报告 `.superpowers/sdd/task-fup24-report.md`。

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
  （`--fs-mount` 已示范正确形态），属 F9 文档范围之外的小代码改动。
  **已关闭（2026-09-08，F15 台账收口）**：`--pid-ns` 在 flatten 后转发给运行时 builder
  （`262c0cf`；`main.rs:478-479` + 单测 `main.rs:1214 test_pid_ns_flag_reaches_runtime_policy`
  + `cli_test.rs` 端到端）。台账行漏写关闭结论，本次补记（无代码改动）。
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
  **已关闭（2026-09-07，A/B cleanup wave）**：新增 root 档 exit-order harness
  `test_supervisor_as_foreign_uid_fd_handoff_worker_close_first_leaves_no_residue`
  （worker 先关、workload 存活 → supervise 非零退出且无 uid-X 活进程/僵尸）；
  RED 复现竞态后修 `serve.rs` abnormal end：与正常路径一致先同步
  `instance.shutdown()`（kill+reap+清理）再退出，不再依赖 Drop 与进程退出竞速。
  修复后 harness 8/8 绿（supervise_root 2→3）；>5 s deadline 替身单测与
  overflow cap 覆盖维持既有（F1.8/executor 单测）。
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
  **已关闭（2026-09-08，F15 台账收口）**：两半都有独立回归——no-clobber 在
  `profile.rs:60`/`profile.rs:821` 与 `profile_integration.rs:40`，I1 半在
  `sandbox/tests.rs:648 mediation_active_covers_policy_fn_deny_capability`（注释点名
  「the I1 shape」），落地于 `48968a5`。台账行漏写关闭结论，本次补记（无代码改动）。
  **B3（2026-09-11）作废该关闭结论**：`mediation_run_as` 档位与 profile 键整体删除，
  no-clobber 这条路径随之不存在（带该键的 profile 现在按 unknown field 拒绝）；
  I1 半不受影响，仍是 live `policy_fn` deny 能力的守卫。
- **FUP-08 knobs 未接生产配置** — 来源：F1.2（`c5a0fe7` early_exit_cap）、F1.8
  （`df5d77a` request deadline）、F5 review（`1321ba0` idle/T_max constructor-only）。
  描述：`early_exit_cap=1024`、`request` 默认 5 s、`T_idle`/`T_max` 目前只走
  constructor/私有 API，未接 CLI/profile。
  为什么留：配置面是产品决策；测试已 pin 默认行为，接线留部署面任务。
  **已关闭（2026-09-07，A/B cleanup wave，决策）**：无生产消费者需要调这些
  内部协议/生命周期旋钮（E2B 未请求端口/超时级配置），维持 constructor 默认 +
  测试 pin 的行为；若未来部署侧需要调优，从 `InstanceLifetime` /
  `InitLink::with_options` 的既有 seam 接 CLI/profile/env（届时按 F6.1 的接线纪律
  做端到端测试：flag 必须真的到运行时 builder，别只停在 parse 面）。
- **FUP-09 egress flake 证据留存流程** — 来源：F2.1 ⚠️ / F5 gate / F8 gate
  （`8e22c5d`..`c8f76d4` 多轮观察；本 F9 终局一次即绿，未触发重试）。
  描述：`cli learn`（curl https://example.com）等外部 egress 用例与本环境偶发的
  control-dir 时序用例偶见抖动，历史做法是"重试到真实绿并留日志"，但没有脚本化的
  证据留存/重试策略（首轮红日志 vs 最终绿日志如何归档）。
  为什么留：属 runner/发布流程纪律（可选加固），非行为缺陷；F9 终局全绿无重试，
  相关观察继续记录在后续 gate 报告。
  **已关闭（2026-09-08，F15 台账收口）**：`run()` 现自动把同名旧日志轮换成
  `tmp/<label>-rN.log`（先写纪律 `-r1`/`-final` 从注释变成机制），落地于
  `8e0adce`（Task 6，本计划）；front 半（纪律注释 `scripts/test-all.sh:33-39`）来自
  `e57cebf`。
- **FUP-10 F1.7 逃逸盲区 / dead_groups 重叠建议** — 来源：F1.7 review residual
  （`4b7f7d0`/`d2bd459`）。
  描述：两步逃逸（setpgid 移组 → setsid 后 pgid==pid 伪装组内）建议 getsid 会话比较
  或注释；dead_groups 与活 child pgid 复用重叠可能双 killpg（建议遍历前先去重）。
  为什么留：加固建议需 core 改动 + 新测试；现行形态 fail-safe 且无实际触发证据。
  **已关闭（2026-09-08，F15 台账收口）**：`d5bbdd8` 落地 getsid 会话比较 +
  `unique_signal_pgids` 去重（`init/mod.rs:540-566`，单测 `:970`/`:981`）；FUP-13
  亦记「重复投送面由 FUP-10 关闭」。台账行漏写关闭结论，本次补记（无代码改动）。
- **FUP-11 F2b/F3 测试与日志硬化小项** — 来源：F2b.1（`3339c12`）与 F2b.3
  （`3afc9dd`）review。
  描述：error-path contains 断言收敛（建议整串/结构化）；registered slot 拒绝
  eprintln 无速率上限；`--program`+validate-exit 模式无测试；registered worker 首
  verb 30 s recv 超时与 120 s connect 重试不对称；非 root path stats settle 断言弱于
  姊妹用例；`FORBIDDEN` 常量无测试引用。
  为什么留：断言/日志/测试强度收尾，非行为缺陷；逐项改需要各自对应文件的小改动。
  **已关闭（2026-09-07，A/B cleanup wave，逐项处置）**：
  **1a** supervise 错误路径断言全部转「整行 / 整串」精确——`tests/supervise.rs`
  原有的 `contains` 式 error 断言清零（只剩 `--help` 面的正/负存在性检查）：uid
  自检拒绝、未知 policy 字段、closed / non-socket / AF_INET control fd、
  `--policy <fd>` 超时（fd 号与 deadline 精确，仅 elapsed 计数留白并校验其量级）、
  oversize cap、EOF 与 token 的异常结束行、跨进程 S9 `PolicyTooWide`、
  `unknown verb: <verb>`；`serve.rs` 的三处 ProgramSpec 单测同步转整串。
  **1b** 新增 `test_runtime_mediator_remap_invariant_is_pinned`：钉
  `FORBIDDEN_RUNTIME_MEDIATOR_REMAP` 原文 + CLI flag 面（不存在任何运行期 remap
  flag，`--uid <X>` 仍是唯一 uid 绑定）；registered path 也钉 `map-uid` ⇒
  `unknown verb: map-uid`（此前只有 fd transport 钉过）。
  **1c** registered slot 的异常连接日志改走 `AbnormalEndLog`：首条必打（可归因），
  其后每 `REPORT_EVERY=256` 条打一条且带累计数。lib 单测钉节流序列 + 整行文本，
  root 档 foreign-uid 验收再钉「300 条被拒连接 ⇒ 恰好 2 行日志」。
  **1d** `REGISTERED_CONNECT_RETRY=120 s` / `VERB_IO_TIMEOUT=30 s` 提为命名常量并
  经 worker config 传给 python 夹具（消除双写），注释说明取舍：等 slot 建出 socket
  是**启动预算**，而连接后 verb 卡死必须更快失败；新增
  `test_harness_timeouts_and_flood_keep_their_contract` 钉住该关系。
  **1e** 非 root registered path 的 stats settle 断言补 `proc_count_vs_live == 0`
  （与 fd 姊妹用例同强度）；root 档 worker report 同样精确断言 drift 归零。
  **1f** validate-and-exit 模式审计：仍在（`main.rs` 的 `ServeMode::None`）且补 3 例
  ——合法 program 静默 exit 0 且**绝不 launch**、`{"argv": []}` 与不可读 program
  文件按整串点名拒绝。
  计数：supervise 36→42（+2 lib unit / +4 integration）、supervise_root 3→4；
  行为变化仅 1c 的日志形态（用户可见：slot stderr 不再随被拒连接数线性增长）。
  证据 `tmp/sdd/f11-supervise-r1.log`（非 root lib+integration 42 绿）、
  `f11-supervise-root-r3.log`（root 档 4 绿）、`f11-gate-nonroot-final.log`（非 root
  全量 8 档）与 `f11-gate-root-final.log`（root 三档：supervise_root 4 /
  mediation_2uid 9 / oci 144）。
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

- **FUP-23 pure 形态 exec stdio 低位 fd 串流（2026-09-07，P1，本波发现）** —
  来源：A/B cleanup wave 的 E2B 复跑（`tmp/f11_fup3_probe.py` 网关+命令探针不可
  复现，进而二分）。
  现象：pure（无 base image）形态下，沙箱命令的 **stdout 整条丢失**——CPython 因
  退出期 flush 失败退 **120**、`/bin/echo x` 以写错误退 **1**、`echo hi > /tmp/f`
  退 **2**；stderr 通路在同一布局下也受影响，而**入库契约与三档全量门禁全绿**。
  精确触发条件（唯一变量 = 承载 harness 的客户端进程 fd 表）：客户端除 0/1/2 外
  **不持有任何 fd**（下一个可用 fd = 3）时必现；只要预先多开 1 个 fd（或 8/24/64）
  即完全正常。
  A/B 定位（同一镜像 `39ed2a82b08b`、同一 E2B 代码、只热替换 debug
  `libsandlock_ffi.so`）：fork `4d5f385`（本波之前）⇒ `FAILURES: []`；
  `7671240`（FUP-14 事件化 reap）⇒ 复现。即**本波把潜伏缺陷变成可达**。
  根因面（读码所得，待 RED 钉死）：`sandbox.rs` 的 stdio 装配为了规避
  「管道端正好占住 0/1/2」用了 `relocate_high()`，但搬迁目标是
  `F_DUPFD_CLOEXEC(src, 3)`（只要 ≥3），而桩/控制通道用**固定低位号**
  （`init/proto.rs: pub const CONTROL_FD: i32 = 3`，另有 READY/GO）⇒ 搬迁目标可与
  被保留的控制 fd 或兄弟流的源 fd 重叠，被 dup2/dup3 覆盖后子进程 fd 1 变成不可写
  （`/proc/self/fd/1` 存在但 `write` 失败，正是本现象）。FUP-14 在 init 里新增
  signalfd，使低位 fd 分配整体位移，恰好把 pure 形态推进这个重叠区。
  为什么门禁看不见：pytest / cargo 测试进程天然持有几十个 fd（socket、缓存、
  `/proc` 句柄），stdio 管道不会落在 3；只有「fd 表几乎为空」的嵌入形态踩得到。
  建议修法：①搬迁下界改为「与 0/1/2 **以及全部保留控制 fd** 不相交」的号段
  （或由 spawn 侧先把保留 fd 搬到固定高位号，再统一 dup2 下发），②`dup2`/`close`
  返回值在异步信号安全前提下失败即 `_exit` 点名（现在被忽略），③RED 用可控 fd 表
  （子进程 helper 先 close 掉 3..N 再建管道）钉「三端各归其位且互不串流 + stdout
  精确到达」，并加一条「保留 fd 号段与 relocate 下界不相交」的纯决策单测。
  **2026-09-08 状态：已修复** —— init 侧「fork 前把三端搬到保留号段」+ 子进程「装配前逐槽
  身份校验，被换端就以 124 明确失败」双保险（见本条目末「根因闭环 + 修复」）。FUP-14 的回退
  缓解已撤销、事件化 reap 重新上线，收益（exec 往返 p50 5.35 ms）一并恢复。
  E2B 侧现象/复现记入 main 仓库 `docs/task-backlog.md` #22。
  - 触发方已钉死（上两条取证），但「为什么 init 多占一个低位 fd 就能让子进程 fd 1
    不可写」还没有 fork 侧可控 RED——cargo/pytest 进程都太"胖"，落不进危险号段。
    RED 正确姿势 = 在子 shell helper 里先把 fd 表压到「下一个可用 = 3」再建管道
    exec，断言 stdout 精确到达且三端互不串流。
  - **2026-09-08 再收窄（实测数据，下一轮直接从这里起；已订正一次误读）**：
    诊断按「只匹配目标命令 argv」过滤后重测（先前那版把网关 holder 的 exec 也采样进来了，
    结论有误，以下为订正数据）：
    ① 装配后子进程 `fcntl(0/1/2, F_GETFD)` 三个都「开着且非 CLOEXEC」，但
    `write(1)` = EBADF ⇒ fd 1 是**开着的读端**；
    ② init 收到的三元组 `O_ACCMODE`：**N=0（坏）= `(rd, rd, wr)`，N=1（好）=
    `(rd, wr, rd)`** ⇒ **两种布局下顺序都是错位的**，只是坏布局把读端挤进了 stdout 槽、
    好布局把它留在 stderr 槽（stderr 是读端不影响本探针断言）。所以本因不是「FUP-14
    让某个号撞车」这种偶发，而是**交给 init 的 stdio 三元组顺序本身就不稳定**，
    FUP-14 只是把错位从 stderr 槽推进了 stdout 槽；
    ③ 因此下一步应该查 `exec` 侧 `child_ends` 三端的**产生与移交顺序**
    （`build_exec_stdio` → `exec_with_fds` 的 `raw` → `fdpass::send_with_fds` →
    init `recv_with_fds` 的解析顺序，含 `cmsg_len` 与 3 fd 的 `CMSG_SPACE` 对齐），
    以及网关 holder 与命令 exec 在同一条 link 上交替发送时 host 端/child 端是否
    发生混用；④「帧头声明 fd 数」候选补丁叠加 FUP-14 复测仍红 ⇒ 多帧合并不是本因
    （它仍是独立缺陷，补丁继续存档）。
    判别变量确认为父进程 fd 表（多开 1 个 fd 即恢复）+ 只回退 `7671240` 即绿。
    ⇒ 下一轮的方向应从「继续查 stdio 装配」转向**同一条 control link 上是否有交叠的
    sendmsg**（网关 holder 的 exec 与命令的 exec 同时在飞、回复与 fd 归属交叉），
    以及 `fdpass::send_with_fds` 的 `cmsg_len`/`CMSG_SPACE` 在 3 fd 时是否与被
    `MSG_CTRUNC` 静默丢弃的路径相互作用。
    复现三件套（本轮验证有效、未提交，避免把 `_exit` 探针留在仓库）：在带 FUP-14 的
    工作树里对 `init/mod.rs` 的 stdio 装配加 `MODES1`（装配前三端 `O_ACCMODE`，
    `64+9*a0+3*a1+a2`，68=正常、65=第二端是读端）、`MODES2`（装配后 0/1/2 的
    `F_GETFD` 状态，0=closed/1=open/2=cloexec）、`QLEN`（读单元实收 fd 数
    `100+n`），构建 debug `.so` 后热替换镜像内
    `site-packages/sandlock/libsandlock_ffi.cpython-314-x86_64-linux-gnu.so`，跑
    E2B 侧 `tmp/f11_harness_queue_probe.py`（父进程打印送出 modes）与
    `tmp/f11_fdcount_probe.py`（N=0/N≥1 对照）。现成工作树：
    `tmp/wt-fix`（FUP-14 已恢复 + 候选补丁 + 上述三处诊断，未提交）。
    **2026-09-08 归档**：诊断不再依赖工作树存活 —— 成对探针（argv token + `child_id` +
    `(O_ACCMODE, st_dev, st_ino)` 身份 + 子进程经自己 stdout 端回送快照）已导出为
    `tmp/sdd/f24b-paired-identity-probes.patch`（基线 `f623184`，`git apply` 即可复现）；
    取证用的临时工作树已回收。
  - **2026-09-08 成对测量（把范围从"stdio 装配"移到 sendmsg/recvmsg 边界）**：
    用同一 argv 过滤器同时在两端取值（父端 = `exec_with_fds_inner` 里即将交给
    `fdpass::send_with_fds` 的三个描述符；子端 = init 装配前 `spawn` 收到的三元组），
    打包成退出码（`64 + 9*acc0 + 3*acc1 + acc2`；68=(rd,wr,wr) 正常）：

    | 客户端多开 fd | 父端送出 | init 收到 |
    | --- | --- | --- |
    | 0（坏） | **68 = (rd, wr, wr)** | **65 = (rd, rd, wr)** |
    | 1（好） | **68 = (rd, wr, wr)** | **67 = (rd, wr, rd)** |

    并且该读单元**确实只收到 3 个**（把 `fdrecv` 放宽到 16 后，"非 0/3"告警从未触发）。
    ⇒ 三条推论：①**父端数组是对的**，之前"发送端把顺序搞反"的怀疑排除；
    ②错位只发生在**送出之后、收到之前**这一段（含 `CMSG_SPACE`/`cmsg_len` 计算、
    SOCK_STREAM 上"一条消息的 fd 与另一条消息的字节"配对、以及 tokio/`UnixStream`
    克隆共享 fd 表这些方向），**不是** stdio 装配；③我此前"init 装配循环先搬 stdio
    就能修"的假设因此作废（那个 relocation 实验也确认不改变结果），不要再往那个方向修。
    成对探针（含两端 argv 过滤与打包）存档在 `tmp/sdd/f24-paired-send-recv-probes.patch`，
    下一轮直接在带 FUP-14 的工作树上 `git apply` 复现；它是在
    `fup23-wip-frame-fd-count.patch`（帧头声明 fd 数 + CTRUNC fail-closed）之上叠加的，
    两个补丁都不改变本现象，故均非本因。
    **下一步具体动作**：在 `fdpass::send_with_fds` 送出点打印 `fds.len()`、
    `fds_bytes`、`CMSG_SPACE`/`cmsg_len`，在 `fdrecv::recv` 收取点打印
    `msg_flags`（含 `MSG_CTRUNC`/`MSG_TRUNC`）、实收 fd 数与逐个 `O_ACCMODE`，
    同一次 exec 两端对齐比较 —— 若父端 3 个 (rd,wr,wr) 而子端 3 个含两个读端，
    就剩"谁把写端换成了读端"这一问，重点查 `send_with_fds` 的 cmsg 空间计算与
    链接上并发 sendmsg 的配对。
  - 排查中发现**另一个独立缺陷**（与 FUP-23 无因果，已实测排除为其成因）：init 控制
    通道是 SOCK_STREAM，一次 `recvmsg` 可并入多帧，而 SCM_RIGHTS 描述符是一个拼接
    列表；现有 `fdrecv::recv(ctl, 3)` + `received.fds[0..3]` 把「本读单元已收的全部
    fd」当成「本帧的 fd」⇒ 前一帧带 fd 时后一帧的 stdio 会整体位移（实测正是
    `(rd, rd, wr)` 这种"stdout 变成读端"的形状），且 `fdrecv` 不看 `MSG_CTRUNC`，
    内核丢弃的描述符无人发现。候选补丁（帧头声明 fd 数 + 按声明分配 + CTRUNC
    fail-closed + 4 条纯函数单测，全绿）存档在
    `tmp/sdd/fup23-wip-frame-fd-count.patch`；它要 bump `FRAME_VERSION`（wire 不兼容），
    故本波（FUP-23 修复波）不夹带上车。
  **F15 已落地（2026-09-08）**：帧头新增 1 字节 `n_fds`（`FRAME_VERSION` 1 → 2、
  `FRAME_HEADER_LEN` 10 → 11），`fdrecv` 对 `MSG_CTRUNC`/`MSG_TRUNC` fail-closed，
  读循环用纯函数 `take_frame_fds` 按声明从读单元队列切分（不符 ⇒ 整读单元拒绝）；
  fork 提交 `c50f407`（RED）/ `8640223`（fix）/ `3020ea0`（docs）；门禁与 wheel 见
  `docs/CHANGELOG.md` F15 条目与 `docs/e2b-integration.md` §5 终态行。候选补丁存档
  （`tmp/sdd/fup23-wip-frame-fd-count.patch` 及 E2B 侧副本）已按用户确认清理
  （2026-09-09），不再保留。

  复现与取证（供修复会话直接接手）：
  - 判别条件：`tmp/f11_fdcount_probe.py`（E2B 仓库，main `8ae1a40`）在跑
    `tmp/f11_fup3_probe.py` 前于客户端进程多开 N 个 `/dev/null` ——
    **N=0 必现、N≥1 全绿**（`highest=3` 即下一个可用 fd 已被占住时安全）。
  - 引入点 A/B：同一测试镜像 `39ed2a82b08b`、同一 E2B 代码，只把
    `site-packages/sandlock/libsandlock_ffi.cpython-314-x86_64-linux-gnu.so`
    换成对应 tip 的 debug 构建 ⇒ `4d5f385` 绿、`7671240`（FUP-14）红。
  - 子进程侧观察：`/proc/self/fd/1` 存在但 `write(1)` 失败（`/bin/echo x` ⇒ 1、
    CPython flush ⇒ 120、shell 重定向 ⇒ 2），`write(2)` 同布局下也不可信
    ⇒ 是 **fork 侧 stdio 装配接错端**，不是 envd/SDK 的传输丢数据。
  - 待验证的收窄假设：碰撞点是「某个 stdio 端正好落在被保留的低位 fd 上」
    （`CONTROL_FD = 3`，桩另有 READY/GO 固定号），修复方向 = 先搬 stdio 再装
    保留 fd，或让保留 fd 号段从 stdio 分配范围里排除；RED 夹具需在子进程里
    把 fd 表压到「下一个可用 = 3」才能覆盖（现有 cargo/pytest 进程都太“胖”）。

### FUP-23 根因闭环与修复（2026-09-08）

成对探针升级到「同一 argv token + 子进程退出码 packed + 子进程用自己的 stdout 端回送快照」，
并在链路上打了六个快照点（`fcntl(F_GETFL)` 取 `O_ACCMODE` + `fstat` 取 `(st_dev, st_ino)`）。
N=1（旧「绿」布局）一轮实测，同一次 exec（父端行带 `child_id=2` 与 argv token，子端退出码
即 packed，两端不可能来自不同次尝试）：

| 快照点 | 三元组（`fd:mode:inode`） | 判定 |
| --- | --- | --- |
| 父端送出（`exec_with_fds_inner`） | `60:0 65:1 67:1` = (rd, wr, wr) | 正确 |
| A：`fdrecv::recv` 返回处 | `5:0:…024 6:1:…025 7:1:…026`，1 个 cmsg、`len28 n3`、`msg_flags=0` | 正确、无 CTRUNC |
| B：帧循环装配前 | 同 A | 正确 |
| S1/S2：`spawn` 内 `dup3` 前 / `fork` 前 | 同 A | 正确 |
| S3：`fork` 返回后 init 自身 | 同 A（另见 fd 8 为 init 自己的描述符） | 正确 |
| C：子进程 `fork` 后第一条指令处 | `5:0:…024 6:1:…025` **`7:0:9485707`** | **第 3 端被换成另一条管道的读端**（其写端在子进程 fd 8；`readlink /proc/self/fd/7` = `pipe:[9485707]` 自证，`write(7)` = EBADF 实证） |

三条结论：

1. **SCM_RIGHTS 收发链路清白**：`fdpass::send_with_fds` 的 `CMSG_SPACE`/`CMSG_LEN` 计算、
   描述符写入顺序，与 `fdrecv::recv` 的 cmsg 遍历、`msg_flags` 处理，逐项核对并实测正确。
   此前「发送端顺序错」「多帧合并串 fd」「`MSG_CTRUNC` 静默丢端」三条假设全部作废
   （帧头声明 fd 数的候选补丁是**独立**缺陷修复，与本因无因果；已作为 F15 落地，
   2026-09-08，见 CHANGELOG F15 条目）。
2. **换端发生在 `init` 的 `fork()` 与子进程第一条指令之间，且不是 init 自己干的**：
   init 自身表在 fork 前后都完好；marker 管道实验（子进程 `pipe2` 落在 9/10，且该 inode
   从不出现在后续 init 侧快照里）证明父子 **不共享** fd 表。⇒ 由**外部方**在新生儿身上
   安装低位描述符。E2B 宿主形态独有：argv 安全路径会对发出 `clone` 通知的进程做一次性
   ptrace fork 事件跟踪并在新生儿上注册状态（supervisor 侧还有 `NOTIF_ADDFD` 一类注入），
   pure 形态下 envd 与沙箱同进程，号段由客户端 fd 表决定 —— 所以「客户端多开 1 个 fd」
   改变的只是**哪个槽**被换，而不是「是否被换」（每次都换）。
3. **旧「红/绿」是同一损坏的两种落点**：红 = 换到 stdout 槽 ⇒ 所有写 EBADF
   （`/bin/echo x` 1、CPython flush 120、shell 重定向 2）；绿 = 换到 stderr 槽 ⇒
   本探针断言不到（stderr 是读端只是写不进去）。

修复（`crates/sandlock-core/src/init/mod.rs`，不依赖揪出注入方）：

- **预搬迁**：init 在 `fork()` **之前**把收到的三端 `dup3` 到保留号段
  `EXEC_STDIO_BASE = 64`，子进程一律从保留号 dup2 下发；低号段留给外部方随便分配，
  再也撞不到「即将被 dup2 的待装配描述符」。保留号**必须三个都空**才搬迁
  （`fcntl(F_GETFD)` == EBADF），否则整体退回原号 —— `dup3` 会静默覆盖占用中的目标号，
  毁掉 init 或长命兄弟进程仍持有的描述符比本次竞态更糟；搬迁失败（例如沙箱
  `RLIMIT_NOFILE` 低于该号段）同样退回，行为不劣于修复前。
- **装配前身份校验**：子进程在 dup2 之前逐槽比对 `(O_ACCMODE, st_dev, st_ino)` 与 init
  搬迁时记录的身份；不一致 ⇒ **拒绝装配**，把说明写到仍然完好的槽上并以退出码
  `EXEC_STDIO_SWAPPED_EXIT = 124` 结束该 exec。同类竞态最坏是「命令明确失败」，
  不再静默丢输出。
- **收尾**：父进程 fork 后关闭保留副本（否则每轮 exec 漏 3 个描述符），子进程关闭保留号
  **和**原始接收号（否则 workload 手里留着自家 stdout 写端，宿主侧永远等不到 EOF）。

验证：FUP-14 已恢复的工作树上，E2B 侧 `tmp/f11_fdcount_probe.py`（main 仓库）
**N = 0 / 1 / 2 / 8 全部 `FAILURES: []`**（网关 `['echo']`、trivial exit 0 +
stdout `post-gateway-ok\n`、450 M 超卖 137 + `Killed\n`、50 M 控制 exit 0 +
`got 50\n`、record `memoryMB 1024`）；`tmp/f23_multi_probe.py 0 4` 四个不同 marker
连发，每条命令各拿到自己那条 stdout。夹具：core_lib +4（搬迁与身份 / 占号退让 /
三端精确不串流 / 换端拒装配）、oci root 档 +1（真 `run_init` 控制环 40 轮 exec：
每轮输出精确、init fd 表每轮回基线、EOF 后仍基线）。

- **FUP-14 REAP_POLL_MS=100 事件化** — 来源：F2b.4（`799fc8f`，capacity doc §6）。
  描述：exec 往返 ~102 ms 有 ~100 ms 轮询地板；SIGCHLD self-pipe / pidfd 就绪通知可
  降到个位数 ms。
  为什么留：性能改动需核心行为变更 + 成本/延迟复测，F2b.4 明确留给后续。
  **✅ 已重新上线（2026-09-08：`bb1cb42` 的回退已撤销，随 FUP-23 修复一起复验）**：本波曾落地「init 阻塞 SIGCHLD 并挂 signalfd，
  poll 集合 = 控制通道 + signalfd；`REAP_POLL_MS` 保留为无 signalfd/孤儿兜底；
  spawn 子进程在 exec 前解除 SIGCHLD 阻塞（workload 语义不变）。release
  supervise_cost latency：p50 101.75 → 5.35 ms、p95 102.61 → 5.84 ms、
  max 103.06 → 7.22 ms（≈19×；latency 测试总时长 32.6 s → 1.75 s；
  样本 `tmp/perf/fup14-latency-{before,after}.txt`）；core_lib/core_integ/
  supervise 全量回归绿。** 但 E2B 真栈复跑把它打回：signalfd 让 init 的低位 fd 分配整体
  位移，把 **FUP-23**（exec stdio 对 fd 号敏感）从潜伏变成可达——pure 形态下「承载沙箱的
  进程 fd 表只剩 0/1/2」时命令 stdout 整条丢失。取证两条都可复现：①同一测试镜像只换
  debug `.so` ⇒ `4d5f385` 绿 / `7671240` 红；②只回退 `7671240` 的构建 ⇒ 同一 N=0 场景
  立刻 `FAILURES: []`（五项签名全对）。故本波一度以回退为**缓解**，latency 收益一并撤回。
  **2026-09-08 现状**：FUP-23 根因闭环（见上一条目）后回退撤销、事件化 reap 重新上线，
  `supervise_cost` 预算恢复 FUP-14 的紧预算，并与 FUP-23 的 stdio 搬迁/校验一起在同一棵树上
  跑完整门禁 + E2B 三档复验。
- **FUP-15 release profile `panic=abort` + `strip`** — 来源：F2b.4（`799fc8f`）/
  F2b.5（`51b64ad`）。
  描述：仓库 release profile 即 cargo 默认（panic=unwind、未 strip），release
  supervise 二进制 ≈6.3–6.9 MB/arch、FFI cdylib 亦未 strip；plan 协议写的历史
  `panic=abort+strip` 未落地。
  为什么留：profile 决策影响发布面；加上只会更小，现有预算已按实测保留余量。
  **已关闭（2026-09-08，F15 台账收口）**：`b1e2e32`（`Cargo.toml:24-26`
  `[profile.release] panic=abort + strip=symbols`，wheel 体积 10.4/9.5 →
  8.3/7.4 MB）。台账行漏写关闭结论，本次补记（无代码改动）。
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
  **已关闭（2026-09-08，F15 台账收口）**：两半齐——front（无参/`--wheels` 拒 root +
  三个 root 档正向守卫）`e57cebf`（`scripts/test-all.sh:130+`）；back（root 三档
  `CARGO_INCREMENTAL=0`，root 与 uid-65534 不再共享增量缓存）`8e0adce`（Task 6）。
  复验：runner 改动后默认 8 档 + root 档计数零漂移，归档机制生效
  （`tmp/sdd/f15-runner-default-final.log` / `f15-runner-root-run{1,2}.log`）。
- **FUP-18 容量表 §4.1 区间/采样标注精度** — 来源：F2b.4 review（`799fc8f`）。
  描述：§4.1 的跨轮区间上界略低估、中位数采样标注不精确；预算余量仍 ≥28–37%。
  为什么留：需回放原始逐轮采样才可精确化；预算有效性不受影响。
  **已关闭（2026-09-07，A/B cleanup wave）**：capacity doc §4.1 补采样标注
  （实测=稳定后 3×200 ms 中位数；跨轮区间=4 配置×多轮 min–max，含 2 729 离群；
  1000 轮后上界=batched 高水位 5 203）；§4.2 延迟表换 FUP-14 前后双列实测；
  §5/§6 同步 release profile（FUP-15）与事件化（FUP-14）已落地。

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
  **已关闭（E2B 侧，2026-09-06，T4/Task 10）**：根因 = envd 侧 base-image 组成
  （slim rootfs 无 mcp-gateway，ENOENT exit 2），非 fork；改用 MCP-capable 基镜像
  `python-mcp:3.14` 后 chroot+netns MCP 契约两形态 3/3 绿，xfail 已摘（主仓
  `883d38d`/`f67a6b9`）。fork 无权执行，条目保留作追溯。
- **FUP-E2 E2B §8 M4 接线** — 来源：fork-plan §F9 / e2b-integration §8。
  描述：SandlockExecutor 持实例、`_CommandGate` 保留、控制目录名用 sandbox_id+token、
  超卖探针改断言、SCALING 账本项照改、`max_processes` 显式配、minimal_dev 替换整树
  /dev 与 carve-out。
  **已关闭（E2B 侧，2026-09-06，Task 11）**：fork 侧 M0–M4/F0–F10 在子模块 b955ae9；
  E2B 接线 5d38537（Task 0.5 supervisor 档）→ 4f34e55…f67a6b9（Task 11 收口，
  全量门禁见 HANDOFF）。fork 无权执行，条目保留作追溯。
- **FUP-E3 E2B 复验 §3.8 超卖消除** — M4 落地后按 e2b-integration §3.8 探针重测
  （gateway + 并发命令同实例）。
  **已关闭（E2B 侧，2026-09-06，FUP #3）**：per-sandbox 默认内存 512→1024 MiB
  （`E2B_DEFAULT_MEMORY_MB`）给网关 ledger 与 450M MCP server 留出空间；gateway+命令
  变体 pure 探针与契约两形态全绿（gate A/B 计数见主仓 task-backlog FUP #3 行）。
  fork 无权执行，条目保留作追溯。

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
