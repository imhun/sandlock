# C 类设计项评估（fork followups C + FUP-05，2026-09-06）

评估对象（fork-plan-followups C 节 + A 节的目录挂载点设计项）：
FUP-19（per-child 正向 fs/bind 强制）、FUP-20（credential/HTTP-ACL per-child
归因）、FUP-21（port-aware `update_network`）、FUP-22（non-root-but-CAP_SETUID
launcher）、FUP-05（目录挂载点 rmdir 语义）。评估维度：问题本质、影响面、可行性
路径、工作量量级、风险、依赖、建议层级。结论供立项排序用，不代表立即实现。

## FUP-19 — per-child 正向 fs/bind 收窄不可内核强制

- **本质**：实例级 ceiling（Landlock/`net_allow_bind`）是“整箱共享域”；
  per-exec 的 `extra_writable`/`bind_ports` 只做 S9 子集校验与**记录**
  （`exec_params.rs`），执行期由共享内核域放行。要“child A 可写 X、child B
  不可”/“child A 可 bind p、child B 不可”的**强制**边界，必须像 connect/send
  一样按 pgid 走中介 open/bind（每次文件写/bind 过 USER_NOTIF）。
- **影响**：只影响需要“同沙箱内不同 child 不同权限”的产品形态（per-command
  文件 ACL、逐命令 bind 隔离）。E2B 当前不需要：命令与网关同实例共享 MCP 端口
  ceiling 是 M4 既定设计（FUP-19 已作为已知边界文档化）；无 per-command 文件
  ACL 需求。
- **可行性路径**：新增 per-child 记录（已有）+ 对 open/bind 家族按 pgid 归因
  的中介判定（把 connect/send 的按 pid 血缘模式扩展到 fs/bind）。工作量大：
  open/bind syscall 面宽、on-behalf 路径与既有无 deny 直通路径交互多。
- **成本/风险**：高（核心中介面扩展）；回归面大（fs/bind 现有矩阵）；perf
  影响（每 open 一次通知）。
- **建议**：**候补（触发式立项）**。触发条件：E2B/产品出现逐命令文件或端口
  授权需求（如未来 per-command secret 文件、逐命令监听端口）。当前保留
  “记录已带、未强制”的文档边界即可，不立项实现。

## FUP-20 — credential / HTTP-ACL per-child 归因

- **本质**：透明代理的 ACL/凭据匹配按 Host/URI 全局进行（`service.rs`
  verify_host + matcher），无“哪个 child 发起的请求”概念；同实例内两个 child
  使用不同凭据访问同一 host 时无法区分。connect 层已按 pid 血缘做 verdict，
  但 proxy hand-off 不携带 child 身份。
- **影响**：只影响“同一 host 上按进程区分凭据”的场景。E2B 的 `http_inject`
  规则是**实例级静态** matcher（域名级），无 per-child 凭据模型；destination
  级泄漏已由 connect verdict 关闭。多租户隔离边界在沙箱之间，不在同箱 child
  之间。
- **可行性路径**：把 child pid/pgid 穿透到 proxy hand-off（connect 通知时已可
  得），per-child 规则集进 session 状态；proxy 按来源 pid 选择 matcher 集。
  工作量中；需同步 Python/FFI 参数面（若暴露）。
- **建议**：**候补（触发式立项）**。触发条件：出现同沙箱内多命令、同
  destination、不同凭据的隔离需求。当前文档化即可；若做 FUP-19（按 pgid
  中介），本项可一并设计，避免两套 pid 穿透。

## FUP-21 — port-aware `update_network` payload

- **本质**：`update_network(ips)` 的可表达单位是 IP-any-port；端口级 ceiling
  无法被 IP-only update 收窄（越界即拒绝，不静默放宽，D4=A 已采用并文档化）。
- **影响**：E2B 侧 D4=A 已把 live 可表达定义为 IP-literal allowOut 收窄；
  denyOut/default-allow 实例 live-immutable。端口级动态收窄目前无消费者。
- **可行性路径**：wire/verdict 增加端口维度（如 `update_network([("ip",
  port)])` 或规则对象），`ExecCeiling`/binding 结构扩展，FFI/Python 参数面
  同步，E2B 契约再扩。工作量中；会改变 D4=A 的单调语义面（需重新定义
  “可收窄”偏序）。
- **建议**：**候补（需求出现再立项）**。若未来产品要“运行时只放开 443、
  不放其它端口”，可基于 FUP-21 开一个独立 fork 任务并先出设计（含与 F12
  ProcessIndex 改造的耦合检查）。

## FUP-22 — non-root-but-CAP_SETUID launcher 形态

- **本质**：C 档（root 进程内 remap + 路径中介 ⇒ 建箱前拒绝）的 gate 只按
  `euid == 0` 触发。route-B 的 file-cap launcher（supervise-identity-handoff
  ③，`setcap cap_setuid,cap_setgid+eip` 后降权 exec supervise）的进程 euid
  非 0 但持 `CAP_SETUID/SETGID`——若未来 launcher 形态绕过 gate，会在
  non-root euid 下重现“root 式错位中介”同类问题。
- **影响**：安全 gate 完整性问题；当前 fork 不装特权组件、无此部署，因此无
  活漏洞；但 T5/route-B 的 ③ launcher 形态已在文档中列为可选部署，一旦启用
  即成为真实攻击面。
- **可行性路径**：把“是否持有可 remap 到其它 uid 的特权”判定从 euid 改为
  capability 探测（`prctl(PR_CAP_AMBIENT)`/`capget` 或试 remap 的 fail-closed
  语义），gate 文案与测试矩阵同步（file-cap 形态必须建箱前拒绝，除非走
  supervise B 档交接）。
- **成本/风险**：小到中；风险主要是判定与内核 capability 语义的贴合度
  （ambient/effective/inheritable），需 root/非 root 双档用例。
- **建议**：**立项（高优先级，随 route-B 部署时序）**——不是今天实现，而是
  在部署 route-B ③ 形态前必须完成的设计 + gate 加固；建议单独小任务，先 RED
  （file-cap launcher 非 root euid 尝试建特权 remap 沙箱必须被拒）再修。

## FUP-05 — 目录挂载点 rmdir 语义

- **本质**：真实 bind-mount 下内核自身对挂载点 unlink/rename/link/rmdir
  返回 EBUSY（宿主源受保护）；fork 的虚拟化挂载（fs_mount 在 chroot/视图层
  实现）对 unlink/rename/link 已有 EBUSY 保护（F6.2 收口），**目录挂载点的
  rmdir 仍暴露**——虚拟形态下缺少内核级“挂载点不可删”保护，可能允许沙箱
  删除其视图中的挂载点目录。
- **影响**：挂载点完整性/宿主源不被误删的收尾缺口；属正确性/健壮性而非
  已知越权（写家族防宿主源删除已由 F6.2 的 EBUSY 保护覆盖单文件节点，目录
  形态是剩余面）。
- **可行性路径**：在 rmdir 通知/on-behalf 路径上把“目标是活动挂载点”映射为
  EBUSY（复用 unlink 同款判定）；若目录挂载点语义需允许“卸载后再删”，先定
  语义（建议：不允许，与真实 bind-mount 一致）。
- **成本/风险**：小到中；风险低（行为向内核 bind-mount 语义对齐）。
- **建议**：**立项（中优先级，测试/语义补齐）**——可并入下一次“fs 写家族
  保护收尾”小批（FUP-04 link 直击 + FUP-05 rmdir 语义 + 断言精度），作为纯
  fork 任务，不做 E2B 联动。

## 排序结论

| 项 | 建议 | 理由 |
|---|---|---|
| FUP-22 | **立项（随 route-B ③ 部署前）** | 安全 gate 完整性；小成本、有触发时序 |
| FUP-05 | **立项（中优先，fs 收尾小批）** | 语义向内核对齐；小成本、无 E2B 依赖 |
| FUP-19 | 候补（触发式） | 大改动；E2B/产品无 per-child 授权需求 |
| FUP-20 | 候补（触发式，可与 19 合并设计） | 无 per-child 凭据模型 |
| FUP-21 | 候补（需求出现再立项） | D4=A 已收窄；无端口级需求 |

建议执行顺序：先把 FUP-05（+FUP-04 link 直击）作为小批实现；FUP-22 编入
route-B 部署前置清单（设计先行、随 ③ launcher 形态交付）；FUP-19/20/21
保持候补，在 F12（ProcessIndex 一 TGID 一 entry）完成后再评估是否与 pid
穿透设计合并。
