# 计划：checkpoint/restore 的 aarch64 移植（2026-09-24）

## 0. 为什么排这个

**E2B 的生产 worker 是 aarch64**（`docs/fork-plan-followups.md` FUP-23 的实测表里，
worker 节点内核是 `6.12.0-211.34.1.el10_2.aarch64`），而**恢复引擎只支持 x86_64 与 riscv64**：

* `sandbox.rs::restore_interactive` 第一步就 `cfg!(not(any(x86_64, riscv64)))` → 拒绝；
* `checkpoint/restore-stub.c` 只有 `__x86_64__` / `__riscv` 两套分支，其它架构
  `#error "unsupported architecture"`；
* `build.rs::is_restore_arch` 同样只含这两个架构 ⇒ **非这两个架构上 stub 构建失败只是 warning**，
  所以 wheel 的 aarch64 腿照常产出、`resume::stub_path()` 指向一个不存在的文件；
* `restore_blob.rs` 的 `STUB_BASE`（x86_64 3 TiB / riscv64 192 GiB）、FP 帧常量
  （`FP_XSTATE_MAGIC1/2`）、`rearm_restartable_syscall`（x86_64/riscv64 两个实现 + 一个
  "不支持就报错"的兜底）都按那两个架构写。

**E2B 侧的 A 方案（stub 改由描述符投递 + 一条宿主路径授权，fork `a6f6b04`）没有一行架构相关代码**，
所以本计划**不动投递**：移植完成后 A 直接可用。B（no-exec 原型）不在本计划范围内——它与架构无关的
阻塞点相同，且 aarch64 上连可跳入的 stub 都不存在。

## 1. 目标 / 非目标

**目标**：在 aarch64 上让 `restore_interactive` 可用并验收通过，包含 `chroot`（模拟）与
`real_root`（真根）两种形态，且不改变 x86_64/riscv64 的任何行为。

**非目标**：① 不改 A 的投递（fd + 宿主授权）；② 不做 SVE/MTE/PAC 的完整支持（见 §4，先 fail-closed）；
③ 不扩到 riscv64 之外的其它架构；④ 不碰 E2B 侧的镜像存储/pause-resume 生命周期（那是
`docs/chroot-workspace-exec.md` §11.6 的清单，与架构无关）。

## 2. 代码坐标（要改的地方）

| 文件 | 位置 | 现状 | 要做的 |
|---|---|---|---|
| `checkpoint/capture.rs` | 41–66（x86_64）、78–99（riscv64） | `PTRACE_GETREGSET(NT_PRSTATUS)` → 27/32 个 u64 | 加 aarch64：`user_pt_regs{regs[31], sp, pc, pstate}`（34×u64）；syscall 号在 `regs[8]`；测试断言加 34 |
| `checkpoint/capture.rs` | 120–160 | FP 走 `NT_PRFPREG` + x86_64 的 `NT_X86_XSTATE(0x202)` | aarch64：`NT_PRFPREG` = `user_fpsimd_state{32×u128, fpsr, fpcr}`；另需 `NT_ARM_TLS` 取 `tpidr_el0` |
| `checkpoint/mod.rs` | `ProcessState`/`Checkpoint` | 无 TLS 字段 | 加 `tls: Option<u64>`（或 arch 相关的 `arch_state`）；**`IMAGE_VERSION` +1**，旧镜像明确拒绝而不是错读 |
| `checkpoint/restore_blob.rs` | 48–52 | `STUB_BASE` 只给 x86_64/riscv64 | 加 aarch64（按 §3-S0c 实测选值；3 TiB 在 48 位 VA 内） |
| `checkpoint/restore_blob.rs` | 56–64、445–505 | x86_64 信号帧 FP 图像（xstate magic） | aarch64：按 §3-S0a 钉死的 `sigcontext` + `fpsimd` 记录布局封装 |
| `checkpoint/restore_blob.rs` | 415–436（x86_64）/437–444（riscv64）/527+（兜底报错） | 可重启 syscall 的修复 | 加 aarch64：`-ERESTART*` 时把 `pc` 退回 `svc` 指令、`regs[8]` 放回原 syscall 号 |
| `checkpoint/restore-stub.c` | 62–98（syscall 号）、102–145（FP 常量）、146–160（`rt_sigreturn`）、551–585（`_start`） | 只有 x86_64/riscv64 | 加 `__aarch64__`：syscall 号、`_start`（入口 sp → x0、切 `.bss` 栈、`bl _start_c`）、`rt_sigreturn`（`x8=__NR_rt_sigreturn; svc #0`）、FP 帧写入、**`msr tpidr_el0` 写回 TLS** |
| `sandbox.rs` | `restore_interactive*` 开头 | 架构门槛 x86_64/riscv64 | 加 aarch64 |
| `build.rs` | 53–55 | `is_restore_arch` | 加 aarch64，让"缺 stub"在那里**致命**（现在是 warning） |
| `tests/integration/test_restore.rs`、`crates/sandlock-ffi/tests/restore.rs` | — | 已有 x86_64/riscv64 断言 | 复用同一批用例跑 arm64（不需要新用例，但需要 arm64 lane） |

## 3. 阶段（每阶段先 RED 后 GREEN，沿用本仓的证据纪律）

### S0 先降不确定度（arm64 lane 上跑三个 spike，**不碰产品代码**）

* **S0a 信号帧**：写一个静态程序，**手工构造 arm64 信号帧**（`struct sigcontext{fault_address,
  regs[31], sp, pc, pstate}` + 紧随其后的 FP 记录）并 `rt_sigreturn` 到一个已知寄存器/栈状态，
  用写文件证明它生效。**这一条是整块移植里最贵也最容易错的 ABI 细节**，必须在写 stub 之前钉死；
  若手工帧走不通，就换成"用 `sigaction` 装一个 handler、让内核给我们建一帧、把该帧 dump 出来当模板"
  作为对照。
* **S0b TLS**：用户态 `mrs/msr tpidr_el0` 往返；`PTRACE_GETREGSET(NT_ARM_TLS)` 读回同一个值；
  确认目标内核没有把 EL0 访问 `TPIDR_EL0` 陷入（`SCTLR_EL1.TIDCP`）。
* **S0c 地址与 vDSO**：在目标内核上确认 `STUB_BASE` 候选值（3 TiB）落在用户 VA 内且不与
  `mmap_base`/栈冲突；确认 `[vdso]`/`[vvar]` 能被 `mremap` 搬到记录基址（沿用 x86_64 的
  `plan_vdso_moves`；现有 `clock-loop` 用例正好覆盖"恢复后仍走 vDSO"这一点）。

**S0 的产出**：一份 `docs/` 实测记录（三张表 + 原始输出），以及 S1–S3 需要的常量/布局定案。

> **已完成（2026-09-24）**：`docs/arm-cr-s0-evidence.md` + `spikes/arm-s0/`。三条 spike 全部成立
> （手工帧能 `rt_sigreturn`；EL0 能写 `TPIDR_EL0` 且 ptrace 通道往返；3 TiB 可用、`[vvar]`+`[vdso]` 按同一
> delta 可搬迁）。两处与计划的差异：**SVE 判据**要按 `vl>16 || flags & SVE_PT_REGS_SVE` 而不是「regset 有
> 内容」，**vdso 搬迁**在 arm64 上必须同 delta 搬两个映射（只搬 `[vdso]` 实测 `SEGV_MAPERR`）。

### S1 capture（arm64 分支）

`PTRACE_GETREGSET(NT_PRSTATUS)` 取 34×u64 + `NT_PRFPREG` 取 FP + `NT_ARM_TLS` 取 TLS；
`regs[8]` 作为 syscall 号来源（对照 x86_64 的 `orig_rax` 用法）；`IMAGE_VERSION` +1；
`capture.rs` 里的长度断言加 aarch64。**RED**：先在 aarch64 上让"捕获一个 `clock-loop`"这一步
用断言失败（字段数/FP 长度不符），再补实现到 GREEN。

### S2 blob/frame（restore_blob）

`STUB_BASE`（S0c 定值）、FP 图像封装（S0a 定布局）、`rearm_restartable_syscall` 的 arm64 实现
（`pc` 回退 + `regs[8]`）。这一阶段的判据是 `restore_blob` 的单元测试在 aarch64 上全绿，
外加一条新的"帧布局与 S0a 模板逐字节一致"的断言。

### S3 stub（restore-stub.c 的 `__aarch64__` 分支）

按 S0a/S0b 的定案实现入口、syscall 号、FP 写入、TLS 写回、`rt_sigreturn`。**这是第二个高风险点**
（汇编 + 帧构造）。判据：`test_restore_glibc_vdso_program_resumes` 在 aarch64 上通过（它同时证明
vDSO 搬迁、寄存器/FP 恢复、fd 重开、`rt_sigreturn` 全部成立）。

### S4 门槛与构建

`sandbox.rs` 架构门槛加 aarch64；`build.rs::is_restore_arch` 加 aarch64（缺 stub 变致命）。
**判据**：aarch64 上删除 stub 会让构建失败（而不是静默出包），且 x86_64/riscv64 四种门禁相位不下滑。

### S5 lane 与验收（见 §5）

搭 arm64 lane（当前 `sandlock-dev:latest` 与 `e2b-sandlock-test:latest` **都是 amd64**，
`docker image inspect` 实测），把 fork 非 root 相位 + 三条 root 相位在 arm64 上跑一遍并登记
`docs/test-baseline.md` 的 arm64 基线；E2B 侧在 arm64 镜像上跑 `tests/security`（开关两态）。

## 4. 风险与处置（先 fail-closed，再按需放开）

| 风险 | 处置 |
|---|---|
| **SVE（变长向量）**：若工作负载启用 SVE，FP 图像不是定长 | 第一版**拒绝**：捕获时若发现 SVE 状态非零/已启用（`NT_ARM_SVE` 有内容），直接报错并说清（与 riscv64 对"可重启 syscall"的 fail-closed 同风格）；后续按需支持 |
| **MTE / PAC**：带标签/签名的指针会破坏恢复后的指针 | 捕获时检测（`NT_ARM_PAC_MASK`/`NT_ARM_TAGGED_ADDR_CTRL`）；启用即拒绝，并在错误里点名 |
| **VA 位宽 39 vs 48**：`STUB_BASE` 可能越界或撞 `mmap_base` | S0c 在目标内核上实测后定值；保留 x86_64 的"stub 窗口外一律 sweep"断言 |
| **内核版本差异**（开发 7.0.14 x86_64 vs 生产 6.12 aarch64） | 所有 ABI 结论以**目标内核**（生产同族）为准；S0 就在 arm64 上做 |
| **镜像格式兼容**：新增 TLS 字段 | `IMAGE_VERSION` +1 + 明确拒绝旧版本（不静默错读）；`policy.dat` 的 `serde(skip)` 字段不受影响 |
| **回归**：x86_64/riscv64 行为 | 全部改动都在 `#[cfg(target_arch = "aarch64")]` 内 + FP/帧的重构保持两架构路径不变；四种门禁相位在 x86_64 上继续跑，作为回归证据 |

## 5. 验收标准（可执行）

**arm64 lane 上（fork）**：

```sh
# 1) 非 root 相位（与 x86_64 同形：uid 65534、--test-threads=1、CARGO_HOME/HOME 由脚本钉）
docker run --privileged --rm -v "$PWD":/src -w /src <arm64-dev-image> sh scripts/test-all.sh
# 2) 三条 root 相位
docker run --privileged --rm -v "$PWD":/src -w /src --entrypoint bash <arm64-dev-image> \
    -c 'sh scripts/test-all.sh --oci-root'          # 含 C/R 往返
docker run ... -c 'sh scripts/test-all.sh --supervise-root'
docker run ... -c 'sh scripts/test-all.sh --mediation-2uid'
```

**必须逐条成立**：

1. `test_restore_glibc_vdso_program_resumes`（vDSO + 寄存器 + FP + fd + `rt_sigreturn`）；
2. `test_restore_resumes_inside_a_chroot_root` 的**两种形态**（模拟 chroot 与 `real_root(true)`）
   都恢复、计数器前进、`restore_skipped` 只有 stdio、恢复后 fd 表无平台 fd；
3. `crates/sandlock-ffi/tests/restore.rs` 的 C ABI 往返；
4. `--oci-root` 的 C/R 用例（checkpoint → image → restore）；
5. `docs/test-baseline.md` 新增 **arm64 基线一格**（与 x86_64 基线并列，数字各自独立）；
6. x86_64 侧四种门禁相位**不下滑**（同一轮的回归证据）。

**arm64 lane 上（E2B 侧）**：`tests/security` 在 `E2B_REAL_ROOT=0/1` 两态各跑一遍（生产形态是
`chroot` + `real_root`），并重跑 `tests/unit/test_checkpoint_restore_unused.py` 的守卫语义；
E2B 侧的 arm64 镜像与 wheel 腿（`deploy/scripts/build-sandlock-wheels.sh` 已在产 aarch64）一起登记。

## 6. 顺序与工作量（一个人，相对量级）

`S0a/S0b/S0c`（先做，风险最高的未知量集中在这里）≈ 1 天 → `S1`≈1–2 天 → `S2`≈1–2 天 →
`S3`≈2–3 天（最难点）→ `S4`≈0.5 天 → `S5`（lane 搭建 + 三相位 + E2B 侧）≈1.5 天。
**合计约一周**，但**只有在 S0 的三条 spike 都成立**的前提下才值得投入 S3。

**如果 S0a 或 S0b 不成立**（例如目标内核把 `TPIDR_EL0` 陷入、或手工帧无法 `rt_sigreturn`），
本计划在 S0 就停下并重新评估（那时可选：放弃 aarch64 的 C/R，或改用"不做进程态恢复"的
冻结/replay 路线——见 E2B 仓 `docs/chroot-workspace-exec.md` §11.4 的 F/G 两类）。

---

## S1 状态（2026-09-24，已落地）

capture 侧的 aarch64 分支已按 S0 的实测落地并双向绿：

* `capture.rs`：新增 `ptrace_get_tls()`（aarch64 走 `PTRACE_GETREGSET(NT_ARM_TLS)`，其它架构
  `None`），`capture()` 里 **fail-closed**（TLS 读不到就失败，而不是给一个会崩的镜像）；
  寄存器/FP 沿用已有分支（34×u64；`NT_PRFPREG` 528 字节裸 fpsimd）。
* `mod.rs`：`ProcessState` 增加 `tls: Option<u64>`。
* `image.rs`：`IMAGE_VERSION` 2 → 3，新增 `process/threads/tls.bin`；**aarch64 上缺该字段的 v3
  镜像直接拒绝**（不是当成 None），其它架构保持"没有就是 None"。
* 测试（先 RED 后 GREEN）：`aarch64_stop_inside_a_syscall_keeps_the_number_in_x8`
  （x8=129 在停机时仍是 syscall 号 + sp/pc/pstate 语义）、
  `capture_records_the_thread_pointer_where_the_arch_keeps_one`（与子进程自己 `mrs` 的值逐位相等；
  非 aarch64 断言为 `None`）、`aarch64_fp_capture_is_one_fpsimd_record`（528 = 0x210）、
  `image_version_covers_the_thread_pointer`，并把 tls 加进既有的 save/load 往返断言。

**证据**：RED = 交叉编译报 `no field tls on type ProcessState` ×3 + `cannot find function
ptrace_get_tls`；GREEN = aarch64 上 `checkpoint::` 子集 **32 passed / 0 failed**（x86_64 同子集
**40 passed / 0 failed**，两种架构各自独立通过）。

**aarch64 lane 的搭法**（S2/S3/S5 复用，细节与坑见 `docs/arm-cr-s0-evidence.md` §7）：本地用
fork 自带的 zig builder 镜像交叉编译，产物推到目标节点跑——**不在节点上装工具链、不在节点上编译**。

---

## S2 状态（2026-09-24，已落地）

恢复侧的 aarch64 分支落地，`capture` 侧补上 SVE 门槛：

* `restore_blob.rs`
  * `STUB_BASE = 0x300_0000_0000`（**与 x86_64 同值**；S0c 实测 48 位 VA 下 3 TiB 可 mmap、不撞
    `mmap_base`/栈，所以不需要第三个数字）。
  * `build_fpstate_image` 的 aarch64 分支：把 ptrace 交回的 `user_fpsimd_state`（vregs 在前、
    fpsr/fpcr 在后、末尾 2 个内核保留字）**重排**成内核 `rt_sigreturn` 要解析的
    `struct fpsimd_context`（`{magic 0x46508001, size 0x210, fpsr, fpcr, vregs[32]}`），落在
    `sigcontext + 0x120`；内核保留字**不转发**。
  * `rearm_restartable_syscall`：aarch64 上是**空操作**，只在 `x0` 里出现重启哨兵时 fail-closed
    （理由见下）。
  * `plan()` 对 aarch64 增加 FP 长度门槛：只接受 0（无 FP）或 528 字节，其它长度直接报错并说明
    期望值——x86_64 有"降级到 legacy fxsave"的安全形态，aarch64 没有，写错长度的记录要么被内核
    拒绝，要么静默丢向量。
  * 两个 sweep 窗口用例（`sweep_removes_a_leftover_stack...`、`plan_rejects_a_checkpoint_overlapping...`）
    的 cfg 加上 aarch64——它们本来就只在 `STUB_BASE > 0` 的架构上有意义。
* `capture.rs`
  * restart 哨兵检查从 riscv64 扩到 aarch64（同为 fail-closed，且发生在内存转储之前）。
  * 新增 **SVE fail-closed**（`reject_aarch64_sve` + 纯函数 `parse_user_sve_header` /
    `sve_registers_are_restorable` / `sve_refusal`）。

### 新增实测：arm64 上重启修复发生在 ptrace 停**之前**

`spikes/arm-s0/s0e-restart.c`（两个阶段：`read` 的 -ERESTARTNOHAND、`nanosleep` 的
-ERESTART_RESTARTBLOCK），用引擎同一条 attach 路径（`PTRACE_SEIZE` + `PTRACE_INTERRUPT`）：

| 观测 | `read` (63) | `nanosleep` (101) |
|---|---|---|
| `pc - svc` | **0**（正好停在 `svc` 上） | **0** |
| `x0` | 原参数（fd = 3） | 原参数（`&timespec`） |
| `x8` | 63（原 syscall 号） | **101（原号，不是 128）** |
| `/proc/<pid>/syscall` | `-1`（NO_SYSCALL） | `-1` |
| `NT_ARM_SYSTEM_CALL` | `0xffffffff` | `0xffffffff` |
| `GET_SYSCALL_INFO` | `op = NONE` | `op = NONE` |
| CONT 之后 | syscall **真的重新执行**（read 返回 1） | 内核在**放行之后**才换成 `restart_syscall`(128) |

内核源码印证（v6.12 `arch/arm64/kernel/signal.c::do_signal`）：`regs->regs[0] = regs->orig_x0;
regs->pc = restart_addr;` 就在 `get_signal()` **之前**，代码注释原文是 *"Prepare for system call
restart. We do this here so that a debugger will see the already changed PC."*；而
`setup_restart_syscall()`（把 `x8` 换成 `__NR_restart_syscall`）在 `get_signal()` **之后**的"无信号"
分支里。⇒ ptrace 停点上看到的永远是"可重执行"形态。

两条推论：

1. x86_64 那种"回退 `pc`、重载返回寄存器"的做法在 arm64 上**是错的**：`pc` 已经在 `svc` 上，
   再减 4 就落到 `svc` 的前一条指令里；而 `orig_x0` 又不在 `user_pt_regs` 里，重载也做不到。
2. arm64 比 x86_64 更省：`-ERESTART_RESTARTBLOCK` 因为 `x8` 保留原 syscall 号，恢复后是**重跑原
   syscall**（超时按原值重来），与 x86_64 用 `orig_rax` 达到的效果相同，却不需要额外字段。

### S0 §5.6 的 SVE 判据修正

S0 写的判据是 `vl > 16 || flags & SVE_PT_REGS_SVE`。**`vl > 16` 那半条是错的**：`vl` 是线程的向量
长度，在有 SVE 的硬件上默认等于系统默认 VL（64 字节；硬件最大更小时取硬件最大），因此 Graviton3
（256 位）上**每个普通进程**都会报 `vl = 32, flags = 0`——按旧判据会把所有 checkpoint 都拒掉，而
那种状态恰恰是能恢复的。内核文档 `Documentation/arch/arm64/sve.rst` 说的很直白：

* `SVE_PT_REGS_FPSIMD`（= 0）: *"SVE registers are not live"*，payload 就是一个
  `struct user_fpsimd_state`（16 字节头 + 528 = 实测到的 `size = 544`）；
* `SVE_PT_REGS_SVE`（= 1）: *"SVE registers are live"*。

⇒ 判据只有这一位：`(flags & SVE_PT_REGS_MASK) != SVE_PT_REGS_SVE`。落到代码里是
`capture::sve_registers_are_restorable` / `sve_refusal`（纯函数，本地 lane 可测），regset 读取与
"内核没有 SVE 就返回 EINVAL"的语义在 `reject_aarch64_sve`。

### 证据（全部本地，2026-09-24）

* **RED**（`tmp/arm-lane/s2-red.log`）：先只加测试、不实现 → aarch64 上 `checkpoint::` 子集
  **33 passed / 3 failed**，三条正是新加的 `aarch64_fpstate_image_is_a_fpsimd_record_not_a_kernel_fpsimd_state`、
  `aarch64_rearm_rejects_a_restart_sentinel_left_in_x0`、`aarch64_a_fp_capture_of_the_wrong_size_is_refused`
  （`left: 0, right: 528`；`an un-fixed-up restart must be refused: ()`；`512 bytes is not a fpsimd state: RestorePlan { .. }`）。
* **GREEN（aarch64）**：同一子集 **33 passed / 8 failed**，8 条失败全部是 qemu-user 不实现
  `ptrace` / `process_vm_writev`（`Os { code: 38, kind: Unsupported, message: "Function not implemented" }`）
  的用例；新增的帧布局、哨兵、FP 长度、SVE 判据全部通过。
* **GREEN（x86_64 回归）**：`cargo test -p sandlock-core --lib checkpoint::` → **40 passed / 0 failed**。

### 本地 lane 的边界（重要）

本地 aarch64 目前只有 `--platform linux/arm64` 容器一条路，而它是 **qemu-user**（`ptrace` 直接
ENOSYS）。于是：

* 纯逻辑（FP 帧封装、blob 布局、策略、镜像格式、SVE 判据）**可以在本地跑**，速度也够；
* 需要**真内核**的（capture 的 `PTRACE_*`、stub 的 `rt_sigreturn`/`mremap`、`process_vm_writev`
  填页、`--oci-root` 的 C/R 往返）在 qemu-user 下**既跑不动也不可信**：S0 的 ABI 结论、S1 的绿、
  以及 S3/S5 的动态验收都属于这一类。
