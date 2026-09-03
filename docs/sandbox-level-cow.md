# 沙箱级 COW 完整方案（常驻 supervisor 路线）

> **状态：已否决（2026-09-01）**。经完整评估（事务性非沙箱刚需、sandlock
> 契约改造风险、数据层冲突 COW 也无法解决），最终采用
> [XFS project quota 磁盘配额方案](../../../docs/sandbox-disk-quota.md)。
> 本文档保留为 COW 路线评估记录。

## 1. 目标与背景

当前 E2B 沙箱直接读写共享 workspace 目录（`E2B_WORKSPACE_BASE/<sandbox_id>`），
无写层、无磁盘配额（实测 1.5G 写入无限制）、无命令并发防护。目标：

1. **沙箱级磁盘配额**：一个沙箱的写入总量受 `max_disk` 约束（多条命令累计）；
2. **事务性写入**：沙箱内容变更在删除/快照时统一落盘，命令失败不产生半写状态；
3. **命令串行化**：同一沙箱的写访问互斥，消除并发文件竞争；
4. **background 兼容**：常驻命令（server/长任务）与后续命令在同一变更集上工作。

## 2. 决策记录

- **路线**：沙箱级**常驻 supervisor**（一个 sandlock 实例长期存活、管理沙箱全部
  命令），放弃"每命令新建实例 + `open_existing` 磁盘恢复"路线；
- **volume 配额**：独立配额（见 §7），不纳入沙箱 COW 记账。

## 3. 常驻 supervisor 模型

### 3.1 结构

```
worker
└─ /var/lib/e2b-sandboxes
   ├─ <sandbox_id>/            # workdir（lower）
   │   ├─ workspace/           # 沙箱可见视图（upper 叠加）
   │   ├─ sandbox.json         # 元数据（含 cow_storage / quota）
   │   └─ control.sock         # sandlock per-sandbox control socket
   └─ _cow/<sandbox_id>/       # 沙箱级分支（durable）
       ├─ upper/
       └─ deleted.log
```

- **一个沙箱 = 一个常驻 sandlock 实例**（worker 进程内对象）：supervisor
  （seccomp 通知循环）、COW 分支（`disk_used`/deleted 集合）、资源记账
  （memory/processes/CPU）、网络策略、DNS 合成映射全部是**实例内存态**，
  跨命令持续存在。
- 命令 = 常驻实例派生（spawn）的子进程；命令之间 read-committed 可见
  （同 Transaction 语义），**命令结束不 merge**，沙箱处置时才统一 commit/abort。
- background 命令 = 常驻实例的普通子进程，与后续命令共享同一实例状态，
  **不存在跨实例分支竞争**（解决开放问题 1）。

### 3.2 与"每命令实例"模型对比

| | 每命令实例（现状） | 常驻 supervisor |
|---|---|---|
| COW 分支状态 | 进程内、命令结束即毁，需磁盘恢复 | 实例内存态，天然跨命令 |
| background/并发 | 跨实例共享分支竞争 | 同一实例，无竞争 |
| 资源记账 | 每命令独立 | 跨命令准确累计 |
| 网络/DNS 状态 | 每命令重建 | 持续复用 |
| sandlock 改动 | 中（加 open_existing） | 大（实例契约扩展） |
| 命令串行化 | E2B 层加锁 | 实例内命令队列天然串行 |

## 4. sandlock fork 改动

### 4.1 Session 模式（核心扩展）

在现有实例模型上增加"一个 supervisor 多次派生"的能力，复用已存在的两块基础：

- **control socket**（`crates/sandlock-core/src/control.rs`）：已有 per-sandbox
  Unix socket + control loop，当前只做 introspection（`config` verb）；
- **in_child_main / OCI sandlock-init**（`sandbox.rs:539`）：child 内运行
  PID-1 控制循环的机制已验证。

新增 `SandboxSession`：

```rust
/// 常驻沙箱会话：一个 supervisor + COW 分支 + 资源/网络状态，支持多次派生命令。
pub struct SandboxSession { /* 内部持有 Sandbox runtime + COW branch + state */ }

impl SandboxSession {
    /// 创建会话（建 COW 分支、起 supervisor、绑 control socket）。
    pub fn create(builder: &SandboxBuilder) -> Result<Self, SandlockError>;
    /// 派生一条命令（复用 supervisor 的 seccomp 域与 COW 分支）。
    pub async fn spawn(&self, cmd: Vec<CString>) -> Result<SessionProcess, SandlockError>;
    /// 处置：合并（commit）或丢弃（abort）分支，然后结束会话。
    pub async fn dispose(self, action: BranchAction) -> Result<(), SandlockError>;
}
```

要点：

- **命令串行**：`spawn` 内部按到达顺序执行（会话内命令队列），天然互斥，
  E2B 层无需再加深锁；
- **COW 分支由会话持有**：`disk_used`、deleted 集合为内存态，无需
  `open_existing`；分支 durable 落盘只用于崩溃恢复（§4.2）；
- **进程管理**：每条命令仍是独立子进程/进程组（PTY、kill、SIGSTOP/SIGCONT
  节流语义不变），但受同一 supervisor 管辖；
- **Control socket 扩展**：`spawn`/`wait`/`kill`/`config` verb，供 E2B
  worker 驱动（worker 内直接持有实例对象时可进程内调用；socket 保留给
  未来跨进程形态）。

### 4.2 崩溃恢复

- 会话进程崩溃后：分支 upper + deleted.log 在磁盘（durable），
  `read_preserved` / `list_preserved` 可枚举未决分支；
- worker 启动时扫描 `_cow/`：分支 Open 且沙箱记录存在 → 重建会话
  （加载分支继续，状态重建只在崩溃后发生，正常路径无开销）；
  MergeInterrupted → 按策略补 merge 或丢弃；
- 恢复正确性依赖 `deleted.log` 的 durable 写（现有机制）与分支 marker
  （workdir 匹配校验，防串用）。

### 4.3 单测

- 会话内多命令顺序执行与 read-committed 可见性；
- 配额跨命令累计（命令 1 写 800M，命令 2 写超余量被拒）；
- background 子进程与后续命令共享分支（无竞争）；
- 崩溃恢复矩阵（Open/MergeInterrupted/孤儿分支）。

## 5. E2B 侧改动

### 5.1 沙箱运行时（`envd_service`）

- `RuntimeSandbox` 增加 `cow_storage`、`cow_disk_mb`；
  `SandboxRuntimeContext` 持有 `SandboxSession`（替代/包装 ProcessManager）；
- 沙箱创建：启动 session（建分支、起 supervisor）；
- 命令 RPC（`rpc.py`）：`session.spawn(...)` 替代 `executor.start(...)`，
  事件流（start/stdout/stderr/pty/end）语义不变；
- background/PTY：子进程管理在会话内，SDK 语义不变；
- 沙箱删除：`session.dispose(Abort)`（或保留策略 Commit）后清理目录；
- 快照：会话内 `commit`（merge 到 workdir）→ `copytree` → 会话重建空分支；
- 迁移：worker-1 停命令 → 分支状态落盘（durable）→ worker-2 用崩溃恢复
  路径重建会话（分支在共享存储，跨 worker 可见）。

### 5.2 命令串行化

会话内命令队列天然串行，**无需 E2B 层锁**；快照/删除/迁移前等待队列排空
（会话提供 `drain()`）。

### 5.3 配额

- `max_disk` = 沙箱配额，记账累计在会话持有的 upper；
- 控制面准入（`E2B_MAX_TOTAL_DISK_MB`）不变；
- volume 独立配额（见 §7）。

## 6. 兼容性与测试矩阵

- sandlock：lib 全量（745+）+ Session 模式新增用例；Linux 双架构；
- E2B 回归：`test_files / test_commands / test_stdin / test_pty / test_sandbox /
  test_features / test_shared_volumes / test_multinode / test_snapshots /
  test_templates` 全量；
- 专项：配额累计、快照含未提交变更、迁移重建会话、崩溃恢复、background 共享
  分支、volume 配额。

## 7. volume 配额（推荐方案）

**结论：volume 独立配额，不纳入沙箱 COW 记账。**

理由：volume 是独立实体（`Volume.create` 独立于沙箱、可被多沙箱共享、生命周期
独立于沙箱），配额语义属于 volume 本身；混入沙箱 COW 会造成"一个沙箱的配额
吃掉共享 volume"的错位，且多沙箱并发写同一 volume 时 COW 记账会竞争。

实现（三层）：

1. **元数据**：`VolumeRegistry` 的 volume 记录增加 `quota_mb`（创建时指定，
   默认 `E2B_DEFAULT_VOLUME_DISK_MB`）；控制面创建 volume 时写入；
2. **写前检查（推荐先做）**：worker 在命令写 volume 前检查 volume 目录
   大小（周期缓存，如每命令一次 `du`），超过 `quota_mb` 拒绝该写入并返回
   明确错误；实现简单、无内核依赖；
3. **内核硬限制（可选演进）**：若 worker 文件系统为 XFS，用 project quota
   对每个 volume 目录设硬配额（`xfs_quota`），写超即 ENOSPC，无需应用层
   检查；否则保持写前检查。

## 8. 开放问题

1. **常驻实例内存**：每个活跃沙箱一个 session（supervisor + 状态），空闲
   沙箱按 TTL 回收（沿用现有 TTL sweep），峰值内存需压测；
2. **Session 与 OCI 模式的关系**：优先扩展非 OCI 路径（E2B 直接持有实例）；
   sandlock-oci 的 sandlock-init 仅作参考不并线；
3. **迁移窗口**：依赖 durable 落盘 + 队列排空，需在 multinode 测试验证
   双 worker 重建的一致性；
4. **max_disk 语义**：只计 upper——快照 merge 后重建空分支，配额随快照
   "重置"是否符合预期（与 volume 独立配额策略一致）；
5. **删除保留策略**：默认 abort，可选 commit 保留现场。

## 9. 实施里程碑

| 里程碑 | 内容 | 验证 |
|---|---|---|
| M1 | sandlock `SandboxSession`（create/spawn/dispose + control socket 扩展）+ 单测 | sandlock-core 全绿 |
| M2 | E2B 运行时接入 session（创建/命令/删除），命令串行由会话保证 | files/commands/pty/stdin 回归 |
| M3 | 崩溃恢复 + worker 启动扫描 | 恢复矩阵用例 |
| M4 | 快照/迁移联动（commit→copytree→重建；跨 worker 重建） | snapshots/multinode 回归 |
| M5 | volume 独立配额（元数据 + 写前检查） | volume 专项 |
| M6 | wheel 构建 + 镜像发布 + 远程复测 | `security-probe2/3` + smoke |

## 10. 风险

- **SandboxSession 是 sandlock 契约扩展**（one-process-per-instance →
  one-supervisor-multi-spawn），改动面大，需 Linux 全量回归；
- 常驻 supervisor 崩溃 = 运行时状态丢失（分支在磁盘可恢复，但会话内未落盘
  的记账/网络状态会重置）；
- 写路径仍走 seccomp 记账（COW 固有成本，无 merge 放大）；
- 迁移/恢复正确性依赖 deleted.log 与分支 marker 的 durable 语义。
