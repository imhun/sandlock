# aarch64 checkpoint/restore — S0 实测记录（2026-09-24）

**结论先行**：`docs/fork-plan-2026-09-aarch64-restore.md` 的 S0 三条 spike **全部成立**，
S1–S3 可以按本页定下的常量动手。两处需要按实测修正计划：**SVE 的 fail-closed 判据**（§5.6）
和**vdso 搬迁的强制前提**（必须"同 delta 搬两个映射"，§5.5）。

## 0. 环境与跑法

| 项 | 值 |
|---|---|
| 目标机 | k0s 两节点 `172.18.80.94` / `172.18.80.140`（经跳板机） |
| OS / 内核 | Rocky Linux 10.2 / `6.12.0-211.34.1.el10_2.aarch64`（与线上 worker 同族） |
| 编译器 | gcc 14.3.1（节点自带；无 glibc-static，故探针用动态链接 + 手工 asm） |
| 用户 VA | 48 位（实测，见 §3） |
| 探针 | `spikes/arm-s0/`（`s0a`–`s0d` + `run.sh`）；两节点结果逐字段一致（`s0e-restart.c` 是 S2 期间补的，见 §5.6） |

探针只做只读探测与"移动自己进程的 vDSO"，不触碰节点上任何服务；节点侧中间产物在
`/tmp/arm-cr-s0`。

## 1. S0a — 信号帧（表 1）

内核在 `SA_SIGINFO` 交付时建的帧，用哨兵寄存器 + FP 图案逐字段定位（`s0a-sigframe.c`）：

| 字段 | 实测 | 说明 |
|---|---|---|
| frame base | `== handler 入口 sp == &frame->info` | `rt_sigframe.info` 在偏移 0 |
| `&frame->uc - frame` | `0x80` (128) | `sizeof(struct siginfo)` = 128 |
| **sigcontext 相对 frame** | **`0x130`** | 等于 `uc + 0xb0`（`ucontext` 里 `__unused` 之后，16 字节对齐） |
| `regs[i]` | `sc + 0x08 + 8*i` | 共 34×u64：`regs[0..30]`、`sp @0x100`、`pc @0x108`、`pstate @0x110` |
| `sc.regs[8]` | `0x83` = 131 = `tgkill` | **x8 在信号里就是 syscall 号**（`rearm_restartable_syscall` 要的那条） |
| `sc.pstate` | `0x1000` | EL0t + SSBS（不是 0） |
| `sc.fault_address` | `0` | 异步信号的正常值 |
| `__reserved` | `sc + 0x120` | 16 字节对齐；整帧约 `0x1340` |
| fpsimd 记录 | `__reserved + 0`：magic `0x46508001`、size `0x210`、`fpsr @+8`、`fpcr @+12`、**vregs @+16**（32×16B） | 与 `arch/arm64/include/uapi/asm/sigcontext.h` 一致，但偏移要实测才敢写死 |
| TPIDR_EL0 | **不在帧里** | 见 §2 |
| FP 图案落点 | `v0 @ sc+0x130`、`v31 @ sc+0x330` | 数组线性，v0 的落点即足以定基址 |

**手工构造帧 + `rt_sigreturn`（S0a 的第二个问题）：成功。** 手写帧把 `pc` 指到自己的入口、
`sp` 指到私有栈、`pstate=0`、`x0=0xc0ffee`、`x19=0xdeadbeefcafef00d`、v0/v31 填图案，然后
`x8=__NR_rt_sigreturn(139); svc #0`，落地实测：

```
  x0  (frame regs[0]) : 0x0000000000c0ffee
  sp  (frame sp)      : 0x00000000004273c0      <- 私有栈，不是原栈
  x19 (frame regs[19]): 0xdeadbeefcafef00d
  v0.d[0]  (fpsimd)   : 0xf0f0000000000000      <- 帧里的 FP 图像被吃下
  v31.d[0] (fpsimd)   : 0xf0f000000000001f
  nzcv    (pstate)    : 0x0000000000000000      <- pstate=0 被接受
  TPIDR_EL0 unchanged : 0x0000ffff8d39f760      <- 内核不碰 TLS（= S0b 的伏笔）
```

> 两条踩过的坑（探针注释里也记着）：① 把 `x19–x28` 写成哨兵，内核会在 `rt_sigreturn` 时按帧
> 把它们复原，于是**调用者**的 callee-saved 变量被破坏 → 主程序 SIGSEGV；探针现在先存后还原。
> ② 把 TLS 哨兵放进寄存器/常量，编译器会留一份在 x24，帧里就"找到"了——假阳性。现在哨兵在
> asm 里由活的 `TPIDR_EL0` XOR 派生，并在 `svc` 前清掉暂存寄存器。

## 2. S0b — 线程指针（表 2）

| 探针 | 实测 |
|---|---|
| EL0 `msr/mrs tpidr_el0` | **往返成功，无 SIGILL** ⇒ `SCTLR_EL1.TIDCP` 未陷入（计划担心的那条不成立） |
| `NT_PRSTATUS` GETREGSET | `272` 字节 = 34×u64；停机在 syscall 里时 `x8=129 (kill)`，`pc/sp/pstate` 齐全 |
| `NT_ARM_TLS` (0x401) | 8 字节；GET 值与子进程自己 `mrs` **一致**；SET 后再 GET 往返一致 |
| 恢复通道实证 | SETREGSET 写入哨兵 → `PTRACE_CONT` → 子进程 `mrs` **读到哨兵**（恢复侧真能改到它） |
| `NT_PRFPREG` (2) | `528` = `0x210` 字节，**无头部**（裸 fpsimd；与 x86_64 的 `NT_X86_XSTATE` 不同） |
| `NT_ARM_SVE` (0x405) | **存在且有内容**：`size=544 max_size=592 vl=16B max_vl=16B flags=0`（见 §5.6） |
| `NT_ARM_SSVE/ZA/ZT/FPMR` | `EINVAL`（无 SME / FPMR） |
| `NT_ARM_TAGGED_ADDR_CTRL` | 8 字节，值 0 |
| `NT_ARM_PAC_MASK` / `PACA_KEYS` / `PACG_KEYS` | **`EINVAL`** ⇒ PAC 键未暴露 |
| `NT_ARM_HW_BREAK` / `HW_WATCH` | 各 64 字节 |
| `NT_ARM_SYSTEM_CALL` | 4 字节 = `0xffffffff`（与 `NT_PRSTATUS.x8` 不是同一语义，别混用） |

## 3. S0c — 地址空间与 vDSO（表 3）

| 探针 | 实测 |
|---|---|
| 用户 VA 上限 | **48 位**：最高可 mmap 页 `0xffff_ffff_f000`；`2^48` 处 `ENOMEM` |
| `STUB_BASE` = 3 TiB (`0x300_0000_0000`) | **可 mmap**，不与 `mmap_base`（≈128 TiB）或栈（≈256 TiB 一侧）冲突 ⇒ 可与 x86_64 同值 |
| 192 GiB / 1 / 16 / 64 / 128 / 255 TiB | 皆可 |
| `[vvar]` / `[vdso]` | `[vvar]` **16 KiB 紧邻** `[vdso]` 8 KiB **之前**（`gap=0`）；`AT_SYSINFO_EHDR == [vdso] base` |
| vDSO 取数据页的方式 | 整段 8 KiB 里 **0 条 `adrp`**、14 条 `adr` 目标落在 `[vvar]`（delta −13 KiB…−18 KiB）⇒ **相对位置是链接期常量** |
| `mremap` 语义 | `MREMAP_MAYMOVE|MREMAP_FIXED` 对两个映射都成功、返回目标地址，但它是**移动**：旧地址随即失效 |

## 4. S0d — vDSO 搬迁，逐条实证

第一版 s0c 把"搬完再调**旧**指针"当成失败——那是自己的测量错误：`mremap` 移走映射后，旧地址
当然是 `SEGV_MAPERR`（`si_addr == 老 [vdso] 基址 + 0x760`）。正确判据是"调**平移后**的地址"：

| 场景（各自 fork 一个子进程） | 结果 | 含义 |
|---|---|---|
| **B**：`[vvar]`+`[vdso]` 按**同一 delta** 搬走，调平移后的 `__kernel_clock_gettime` | **成功**（`rc=0`，两节点复现） | **arm64 上 vDSO 可以搬迁**，前提是保持两者相对位置 |
| **A**：只搬 `[vdso]`，调平移后地址 | `SEGV_MAPERR @ new_vdso−0x4000`，`pc` 在新 vdso 内 | 数据页访问落到空处 ⇒ 相邻关系是硬前提（`plan_vdso_moves` 的"同一 shift"正是这条） |
| **C**：**不动**任何映射，直接读 `[vvar]` 两页 | 第 2 页 `SIGBUS/BUS_ADRERR` | **既有性质**，与搬迁无关；引擎只 `mremap` 不读它，故无影响 |
| **C2**：只搬 `[vvar]` 再读搬后页 | 同样在第 2 页 `SIGBUS` | 与 C 一致 ⇒ 搬迁没让 `[vvar]` 更坏 |
| **D**：搬完两个映射后 `raise(SIGUSR1)` 并返回 | **存活** | 信号交付/返回不依赖被搬走的旧基址 |
| **E**：搬完两个映射后走 glibc 的 `clock_gettime`（启动时缓存过 vdso 指针） | `SIGSEGV @ 老 [vdso] 基址` | **这正是引擎必须把 vdso 搬回 checkpoint 记录基址的原因**：镜像里的进程带的是老地址指针 |

## 5. 对 S1–S3 的定案（可直接写进代码）

1. **capture**：`PTRACE_GETREGSET(NT_PRSTATUS)` 34×u64（syscall 号在 `regs[8]`）；FP 走
   `NT_PRFPREG`（528B 裸 fpsimd）；TLS 走 `NT_ARM_TLS`（8B）——信号帧里**没有** TLS。
2. **镜像**：`ProcessState`/`Checkpoint` 增加 `tls: Option<u64>`，`IMAGE_VERSION` +1，旧镜像明确拒绝。
3. **restore_blob**：`STUB_BASE = 0x300_0000_0000`（3 TiB，实测可用）；FP 图像封装为
   `{magic 0x46508001, size 0x210, fpsr, fpcr, vregs[32]}`，放在 `sigcontext + 0x120`；
   `sigcontext` 在 `frame + 0x130`。
4. **stub**：`__aarch64__` 分支——入口 `sp → x0`、切 `.bss` 私有栈、`msr tpidr_el0`（帧里没有
   TLS，必须显式写回）、`x8 = __NR_rt_sigreturn` 后 `svc #0`；`pstate` 用 0 已被实测接受。
5. **vdso 搬迁**：必须**同 delta 搬 `[vvar]` + `[vdso]`**，且目标就是 checkpoint 记录的原基址
   （§4 B/E）；不要读 `[vvar]` 的内容（第 2 页 SIGBUS）。
6. **SVE 判据只看 `flags` 那一位**：本机**普通 glibc 进程**的 `NT_ARM_SVE` 就有内容
   （`size=544`、`vl=16B`），所以"regset 有内容就 fail-closed"会把一切都拒掉；但判据也不能带
   `vl`——本页初稿写的 `vl > 16 || flags & SVE_PT_REGS_SVE` 里，**`vl > 16` 那半条是错的**：
   `vl` 是*线程*的向量长度，在有 SVE 的硬件上默认就等于系统默认 VL（64 字节，硬件最大更小时取
   硬件最大），所以 Graviton3（256 位）上**每个普通进程**都会报 `vl = 32, flags = 0`，而那种状态
   恰恰能恢复、也只需要按 fpsimd 存。内核文档 `Documentation/arch/arm64/sve.rst` 分得很清楚：

   * `SVE_PT_REGS_FPSIMD`（= 0）：*"SVE registers are not live"*，payload 就是一个
     `struct user_fpsimd_state`（16 字节头 + 528 = 实测的 `size = 544`）；
   * `SVE_PT_REGS_SVE`（= 1）：*"SVE registers are live"*。

   ⇒ 判据只有 `(flags & SVE_PT_REGS_MASK) != SVE_PT_REGS_SVE`；寄存器视图在 `flags` 位里，不在
   长度里。SME/FPMR 不存在、`NT_ARM_PAC_MASK` 等 `EINVAL` ⇒ PAC/MTE 的 fail-closed 判据也要按
   实测（不是按架构能力表）来写。
7. **门槛**：`sandbox.rs` 的架构判断与 `build.rs::is_restore_arch` 加 aarch64（缺 stub 变致命）。

## 6. 仍然未知（留给 S5 与后续）

* 跨内核版本：本页只覆盖 `6.12.0-211` 一族；S5 的 arm64 lane 上要跑全门禁再登记基线。
* `--oci-root` 的 C/R 往返、`test_restore_resumes_inside_a_chroot_root` 两种形态——S5 验收。
* arm64 上 `mm->context.vdso` 在 `mremap` 之后是否被内核更新（D 存活说明信号路径没受影响；
  若将来出现"恢复后一收信号就崩"，第一个查这里）。
* SVE 实做（按 §5.6 判据先 fail-closed，再按工作负载需求放开）。

## 7. aarch64 lane 的搭法（本地交叉编译 + 真内核运行）

S1 起需要在 **aarch64 的真内核上跑 fork 自己的测试**：QEMU 用户态会把 ptrace/regset 变成模拟器
语义（`ptrace`/`process_vm_writev` 直接 ENOSYS），S0 的所有结论在它下面都不成立。两个可用的执行
环境——**本地 Lima VM**（S3 起主用）和**目标节点**——吃的是同一份本地交叉编出的二进制：

1. **本地（Mac，amd64 docker）交叉编译**：用 fork 自带的 wheel-builder recipe 先建一个 builder 镜像
   （manylinux_2_34 + rustup + `aarch64` target + zig 交叉链接器）：

   ```sh
   docker buildx build --builder multiarch --platform linux/amd64 \
     --build-arg BASE_IMAGE=quay.io/pypa/manylinux_2_34_x86_64 \
     --target build -t sandlock-zig-builder:local \
     -f python/wheel-builder/Dockerfile --load .
   ```

   然后用它编 aarch64 测试二进制（`-e ZIG_TARGET=aarch64-linux-gnu.2.34`）。
   **坑（实测）**：镜像里的 cargo config 把 *两个* target 的 linker 都指向 `zigcc`，而 `zigcc`
   只读一个全局 `ZIG_TARGET`，于是宿主的 build script / proc macro 会被当成 aarch64 链接而失败
   （`libcompiler_builtins ... is incompatible with aarch64linux`）。解法是把**宿主的 linker 钉回
   系统 `cc`**：

   ```sh
   CARGO_TARGET_DIR=/tmp/target-aarch64 \
   ZIG_TARGET=aarch64-linux-gnu.2.34 \
   CC_aarch64_unknown_linux_gnu=zigcc CC_x86_64_unknown_linux_gnu=cc \
   CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
   cargo test --target aarch64-unknown-linux-gnu -p sandlock-core --lib --no-run
   ```

   产物在 `$CARGO_TARGET_DIR/aarch64-unknown-linux-gnu/debug/deps/`，是 aarch64 ELF（glibc 2.34 基线，
   节点上能直接跑）。
2. **本地真内核 VM（S3 起主用）**：Lima + qemu，在宿主（Darwin/amd64）上跑一台 aarch64 虚拟机，
   把上面那份二进制放进去运行。实例定义 `tmp/arm-vm/sandlock-arm.yaml`、驱动脚本
   `tmp/arm-lane/lima-vm.sh`（`sync` / `run` / `shell` / `start` / `stop`）都在主仓：

   ```sh
   limactl create --name sandlock-arm --tty=false tmp/arm-vm/sandlock-arm.yaml
   limactl start  sandlock-arm --tty=false
   tmp/arm-lane/lima-vm.sh sync
   tmp/arm-lane/lima-vm.sh run '/tmp/target-aarch64/aarch64-unknown-linux-gnu/debug/deps/\
       integration-* test_restore:: --test-threads=1'
   ```

   四条实测约束，改配置前先读：

   * **不要写 `networks:`**。`lima: shared` 需要 `socket_vmnet`，装它要 sudo 密码；默认的 user-mode
     网络加上 Lima 自己的 ssh 端口转发足够（这台 VM 不对外提供服务）。
   * **guest 内核要 ≥ 6.10**。Ubuntu 24.04 自带的 6.8 只有 Landlock ABI v4，而引擎的策略要求
     `FsIoctlDev`（ABI v5），于是所有带策略的用例在起沙箱时就失败。装上
     `linux-image-6.14.0-37-generic` 之后 Landlock 报 v6。
   * **工作区必须是 guest 本机文件系统，9p 只能当传输**。实测：在 9p 挂载上
     `landlock_add_rule` 返回 0、`landlock_restrict_self` 返回 0，但随后 `execve` 该目录下的文件
     一律 **EACCES**（最小复现：同一段三十行代码，目录换成 guest 本机路径就成功）。所以 lane 的
     形状是「`/lima-repo` = 宿主仓库只读 9p 传输；运行根镜像到 guest 本机」，细节在脚本头注释。
   * **`/tmp` 重启会被清**。`/tmp/target-aarch64` 这类编译期烘焙的绝对路径每次重启都要重建，
     `sync` 会做这件事。

   还有一条与“绿的真假”有关：`stub_path()` 是编译期烘焙的绝对路径，路径不存在时那三条 stub 用例
   会**静默 skip**（只 `eprintln!` 然后 `return`）。跑完必须确认输出里没有 `skip:` —— 第一轮真内核
   的“46/46”就是这么来的假绿。

   以及一条**传输层**的坑（S5 实测，代价是一次假 RED）：`/lima-repo` 这个 9p 挂载在宿主**原地重写**
   一个文件后仍把**旧内容**给 guest —— 在宿主 `printf > f` 把文件从 6 字节改成 29 字节，guest 侧
   `cat` 仍然是旧的 6 字节、`stat` 还是旧 mtime，等 12 秒也一样（新建的路径倒是立刻可见）。于是
   **rsync 的快速检查判定"没变"，什么都不复制**，lane 会拿着上一次的二进制跑出"结果"来。所以
   `lima-vm.sh sync` 现在把源码用 `tar` 流过 ssh、把产物用 `limactl copy` 送进去；9p 只留作随手看。
3. **推到节点运行（备选）**：`tmp/k0s/tools.sh node-put <bin> <host> <path>`，然后在节点上（root）跑
   `--test-threads=1` 的子集/全量。节点侧只需要一个可写目录（S1 用 `/opt/arm-lane`）；**不需要**
   在节点上装 rust/cargo，也不要把源码推上去编译。
