# supervise 容量表 — route-B 每沙箱 PSS（fork-plan F2b.4 正式复采）

> Task F2b.4 的正式成本 harness 落地为
> `crates/sandlock-supervise/tests/supervise_cost.rs`
> （runner label `supervise_cost`，`cargo test --release`），三例：
> `test_per_sandbox_supervisor_rss_within_budget`、
> `test_exec_roundtrip_latency_within_budget`、
> `test_exit_frames_never_lost_over_1000_rounds`。
> 本文档是容量表（plan F2b.4 要求"写在 `docs/test-baseline.md` 旁边"），
> plan 的对应小节指针见 `docs/fork-plan-2026-09.md` §Task F2b.4
> 「正式复采（2026-09-05）」。

## 1. 方法（协议落地）

1. **指标 = PSS**：`/proc/<pid>/smaps_rollup` 的 `Pss` 行，逐进程读取；
   不按 RSS 求和（N 个 slot 共享二进制 text/rodata/libc ⇒ RSS 高估节点占用）。
   采样 = 状态稳定后取 3 次（间隔 200 ms）的**中位数**。
2. **四个点**（一个 slot 的生命周期推进，M0 = `--program ["/bin/sleep","900"]`）：
   - **空载**：generation 已 launch、只有 M0（`children_live == 1`），无 worker 命令；
   - **1 条命令**：再 exec 1 个常驻 child（`children_live == 2`）；
   - **64 进程**：M0 + 63 个 exec child（`children_live == 64`）；
   - **1000 轮 exec 之后**：清掉 63 个常驻 child，跑 1000 轮
     `exec /bin/sh -c "exit N"` + `wait_child`（每轮断言 child_id→退出码精确匹配、
     id 不重不漏），再采 PSS —— 抓缓慢泄漏。
3. **构建/配置**：release 二进制（`cargo build --release`，即 runner
   `cli_build` 门用的仓库默认 release profile —— 工作区无
   `[profile.release]` 覆盖，实测为 panic=unwind、未 strip，见 §5 备注）；
   矩阵 = `MALLOC_ARENA_MAX ∈ {1, 默认}` × tokio 工作线程
   `∈ {TOKIO_WORKER_THREADS=1, 默认 nproc(=8)}`。
   发布二进制固定用多线程 runtime；`TOKIO_WORKER_THREADS=1` 即协议说的
   "单一中介线程"cell（与 2026-09-04 探针 `worker_threads(1)` 同形）。
4. **profile 产物**：`tmp/perf/supervise-cost-4points-{batch,seq}.json`、
   `tmp/perf/supervise-cost-cohort.json`、
   `tmp/perf/supervise_cost_rss_4points.json`、
   `tmp/perf/supervise_exec_roundtrip_latency.log`、
   `tmp/perf/supervise_exit_frames_1000_rounds.log`（不提交）。
5. **环境**：sandlock-dev:latest（Debian trixie x86_64，uid 65534），
   OrbStack 内核 `7.0.14-orbstack-00380`，Landlock ABI 8；2026-09-05。

## 2. 实测：四点 × 配置变体（单 supervisor，PSS kB）

registered-path 批量轮转矩阵（1000 轮 batched，python 探针，中位数采样）：

| 配置 | 空载 | 1 命令 | 64 进程 | 1000 轮后 | 进程线程数 |
|---|---:|---:|---:|---:|---:|
| threads=1, arena=1（**正式测试配置**） | 4 453 | 4 404 | 4 239 | 5 013 | 3 |
| threads=1, arena=默认 | 4 488 | 4 432 | 4 306 | 5 080 | 3 |
| threads=8, arena=1 | 4 487 | 4 430 | 4 339 | 5 087 | 10 |
| threads=8, arena=默认（部署默认） | 4 537 | 4 509 | 4 379 | 5 203 | 10 |

fd 交接传输、正式测试配置（Rust cost 测试最终 GREEN 实测；RED→GREEN
多轮采样落在同一区间）：

| 采样 | PSS kB | RSS kB | 线程 |
|---|---:|---:|---:|
| 空载（live M0） | 4 302 | 6 960 | 3 |
| 1 命令 | 4 283 | 6 960 | 3 |
| 64 进程 | 4 279 | 7 124 | 3 |
| 1000 轮后（batched） | 4 862 | 7 520 | 3 |

fd 多轮采样区间：空载 4 108–4 453 kB，1 命令 4 102–4 404 kB，
64 进程 4 067–4 339 kB，batched 1000 轮后 4 666–5 203 kB
（单进程 PSS 逐轮波动主因是分配器/共享页计数抖动，量级稳定）。
逐轮（sequential）1000 轮后的样本落在 **4.05–4.15 MB**（4 配置 × 1000 轮后
PSS 4 050/4 075/2 729/4 154；其中 threads=8/arena=1 一轮出现 2 729 的低值）。

读法：

- 单 supervisor 的 PSS ≈ **4.1–4.7 MB**（空载档），几乎全是它自己的
  二进制 text/rodata + 私有堆；与 2026-09-04 探针的 N=1 行（4 458 kB）一致。
- "64 进程 / 1000 轮后"的 PSS 增量主要反映**分配器高水位**（batched 1000 轮
  后 +0.5–0.7 MB；sequential 慢速轮转时堆会被 trim 回落到 ≤ 空载）。
  1000 轮内没有无界增长证据（batched 高水位 × 三轮采样 5 013/5 080/5 087/
  5 203，非单调外推泄漏）；与 F5.6 同源的 10k 轮长跑（断言单调平台）仍留
  F5.6 目标，不在 F2b.4 内重复实现。
- arena/线程变体对空载 PSS 影响 ≈ ±1 %（tokio 工作线程栈只计入常驻页）；
  线程数是部署侧性能选择（F2b.4 结论 3），容量口径无需按线程细分。

## 3. 边际每 slot PSS（N 并发，route-B W1 形态）

同环境并发 N 个 supervise（threads=1/arena=1），每进程 PSS 中位数：

| N | live（各持一实例） | idle（无实例） |
|---|---:|---:|
| 8 | 914 kB | 849 kB |
| 16 | 631 kB | 630 kB |
| 32 | **486 kB** | 500 kB |
| 64 | **418 kB** | 442 kB |

读法：N 大时分摊后 **每 slot 边际 PSS ≈ 0.42–0.49 MB**（N=32–64），
与 2026-09-04 探针（N=64 → 518 kB、N=32 → 604 kB）同量级且略低。
容量建议值：**每 slot 按 0.5 MB 计**（N≤100 保守上取整；100 slot ≈ 50 MB、
1 000 slot ≈ 0.5 GB）。

## 4. 预算与延迟上界的推导（先测后定）

### 4.1 RSS/PSS 预算（测试常量，kB）

（fd，正式配置；括号为跨轮区间）

| 点 | 实测（fd，正式配置） | 预算 | 余量 |
|---|---:|---:|---:|
| 空载 | 4 302（4 108–4 657 跨轮/跨配置） | **6 144**（6 MB） | +32–50 % |
| 1 命令 | 4 283（4 102–4 509） | **6 144** | +36–50 % |
| 64 进程 | 4 279（4 067–4 379） | **6 144** | +40–51 % |
| 1000 轮后 | 4 862（batched 高水位 5 203 为全矩阵上界） | **6 656**（6.5 MB） | +28–37 % |

余量吸收：跨轮/跨机器抖动、二进制演进、分配器高水位；同时仍守住
"1000 轮不把单进程 PSS 推到 >6.5 MB"的回归线。**测试断言单进程**
（每 slot 私有+其独占共享份额的上界）；**容量用 §3 的 N 并发边际数**，
两者口径在文档中显式区分。

采样标注（FUP-18，2026-09-07 复核）：每点"实测" = 状态稳定后 3 次
（间隔 200 ms）的**中位数**（§1 方法）；"跨轮区间" = 4 配置 × 多轮实测的
最小–最大，含 §2 记录的 2 729 kB 离群低值；"1000 轮后"上界取 batched
高水位 5 203 kB（全矩阵最大值），不用单点中位数作上界。

### 4.2 exec 往返延迟（worker verb → child 启动 → wait 返回）

顺序 1000 轮实测（fd 与 registered 同量级，四配置一致）：

| 统计 | 实测（2026-09-05，100 ms 轮询地板） | 实测（2026-09-07，FUP-14 事件化后；**该实现已回退 `bb1cb42`，本列仅作历史**） | 预算 |
|---|---:|---:|---:|
| mean | 102.2–102.8 ms | 5.38 ms | — |
| p50 | 102.0–102.6 ms | 5.35 ms | **200 ms** |
| p95 | 102.9–104.5 ms | 5.84 ms | **300 ms** |
| max | 105–203 ms（单次调度尖刺） | 7.22 ms | **2 000 ms** |

上界推导：p50/p95 预算 ≈ 实测 × 2–3 倍（吸收慢 CI 与调度抖动，仍能抓住
"退出帧不再路由/事件唤醒失效导致往返翻倍"级别的回归）；max 预算留 10×
给偶发调度停顿。2026-09-05 行的 ~100 ms 地板来自
`crates/sandlock-core/src/init/mod.rs` 的 `REAP_POLL_MS = 100`（子进程退出后
由 init 的 100 ms 控制通道轮询收割并回路由 Exited 帧；exec 启动腿本身
~1.5 ms）。**FUP-14（2026-09-07）曾改为 SIGCHLD signalfd 事件唤醒**（因触发
   FUP-23 已回退，见 `docs/fork-plan-followups.md`；下表"事件化后"列为回退前的历史测量）
（`REAP_POLL_MS` 保留为无 signalfd/孤儿兜底）：p50 101.75 → 5.35 ms
（≈19×），latency 测试总时长 32.6 s → 1.75 s。延迟样本存
`tmp/perf/fup14-latency-{before,after}.txt`。

## 5. 容量口径与调度账本项（binding）

- **N_max**：`N_max = 节点可分给 supervise 的内存 / 实测每 slot PSS`
  （§3 边际数；部署按 N 所在区间取表值，建议 0.5 MB/slot 上取整）。
  若 N_max < 并发需求 ⇒ 走 F2b.3 W2（服务完退出、部署层以新 uid 重启），
  不许把窗口说大。
- **账本项（fork 侧记录，E2B 侧 `docs/SCALING.md:71` 必须照改）**：
  supervise 进程是**宿主侧进程，不在 Landlock/seccomp 的实例记账里**——
  它是 §3.8 实例超卖之外节点超卖的第二个来源。节点每 worker 可容纳数 =
  `(各维度 E2B_NODE_*_MB − N × 实测每 slot PSS) / 默认沙箱需求`：
  **先扣 N × PSS，再除 N**。fork 仓库内没有 SCALING.md，本账本项写在此容量表
  并点名 E2B 侧（上游 docs/SCALING.md 与 e2b-integration.md §8）。
- 与 §11.1（`docs/sandbox-exec-security.md`）对照：≈25 MB/沙箱是
  sandlock-oci **debug** 构建 + **两个**常驻进程（14.3+10.4 MB、9+2 线程）；
  正式 supervise **release 单进程**：单进程 PSS ≈ 4.2–4.7 MB（仍 < 25 MB），
  N 并发分摊后 0.42–0.5 MB/slot（100 slot ≈ 50 MB，比 §11.1 口径低 ~50×）。
  **不得再用 §11.1 数字定容量**。
- profile 备注：**FUP-15（2026-09-07）已落地 `[profile.release] panic=abort +
  strip=symbols`**；2026-09-07 release 实测 sandlock-supervise 5.82 MB、
  libsandlock_ffi.so 5.57 MB（此前 2026-09-05 为 9.99 MB、含符号、unwind）。
  PSS/代码体积只会更小，现有预算仍然有效（见 §6）。

## 6. 测量暴露、点名的后续项（本任务不做范围外实现）

1. ~~**`REAP_POLL_MS = 100` 给每次 exec 往返一个 ~100 ms 地板**~~ —
   **曾关闭 → 已回退重新 open（FUP-14，2026-09-07 落地、2026-09-08 回退 `bb1cb42`）**：
   init 曾改为 SIGCHLD signalfd 事件唤醒（重做前须与 FUP-23 一并验证），
   `REAP_POLL_MS` 降级为无 signalfd/孤儿兜底；exec 往返 p50 101.75 → 5.35 ms
   （§4.2 新行）。
2. ~~**release profile 无 `panic=abort`/`strip`**~~ — **已关闭（FUP-15，
   2026-09-07）**：`[profile.release] panic=abort + strip=symbols` 落地，
   supervise 二进制 9.99 → 5.82 MB。
3. 1000 轮 batched 高水位 +0.5–0.7 MB、sequential 回落：无泄漏证据，
   但 10k 轮单调平台断言归 F5.6。

## 7. 复测方法

```sh
# 全矩阵四点（batched 1000 轮，快）与顺序延迟（1000 轮，~4 min/4 配置）
python3 tmp/sdd/f2b.4-measure.py batch 1000
python3 tmp/sdd/f2b.4-measure.py seq 1000
# N 并发边际
python3 tmp/sdd/f2b.4-cohort.py
# 正式三例（runner label 同款）
cargo test --release -p sandlock-supervise --test supervise_cost -- --test-threads=1
```
