# sandlock 扩展方案：E2B Network API 能力对齐总纲

> 状态：Block A（通配域名）与 Block B（header 注入 / host 掩码）已在 fork
> 落地；Block C（SOCKS5 on-behalf）未开始。目标版本基线：sandlock 0.8.6
> （main 分支 2026-08-23，含 credential injection 但未发版）。

## 1. 背景与目标

E2B 官方 Network API 有三块能力本项目尚未与标准对齐，它们都依赖 sandlock
层能力：

- **Block A — 域名通配符**：`allowOut` 的 `*.example.com` 是官方合法条目，
  与是否配置 `egressProxy` 无关；
- **Block B — HTTP(S) header 注入 / 改写**：`rules[domain].transform.headers`
  与 `maskRequestHost`；
- **Block C — egressProxy on-behalf 完整化**：SOCKS5 隧道由 sandlock
  on-behalf 路径执行（替代 LD_PRELOAD，覆盖静态/Go 应用与 IPv6）。

现状：

- 通配域名：egressProxy 模式已支持（LD_PRELOAD 库内过滤）；普通模式 400；
- headers/maskRequestHost：API 层显式 400（依赖 B2 能力）；
- egressProxy：LD_PRELOAD 实现，仅 IPv4、仅动态链接应用。

目标：三块能力都由 sandlock 内核/on-behalf 层执行，不降低安全模型（沙箱
unaware、静态/Go 应用同样受限），与 E2B 标准一致。

## 2. 为什么必须改 sandlock（不能走 LD_PRELOAD）

普通模式的过滤由 sandlock 的 seccomp user-notification 在 supervisor
`connect_on_behalf` 代连路径执行，是**内核级、不可被沙箱绕过**的强制。

LD_PRELOAD 是沙箱进程内的用户态 hook：

- 静态链接 / Go / 自实现 syscall 的应用不受影响（可绕过规则）；
- 沙箱内可检测并规避（`LD_PRELOAD` 可被清空、`dlsym(RTLD_NEXT)` 可被绕开）；
- 违反 E2B "sandbox unaware / 平台强制" 语义。

因此这些规则必须下沉到 sandlock 的 on-behalf / transparent-proxy 路径。

## 3. 现状：sandlock 0.8.6 网络模型（源码依据）

| 模块 | 职责 | 与通配域名的关系 |
|---|---|---|
| `crates/sandlock-core/src/network/rules.rs` | `--net-allow/--net-deny` 解析；hostname **创建时 DNS 解析进 IP 集合**；虚拟 `/etc/hosts` 组装 | hostname 规则在创建时被"固化"成 IP，无法表达动态子域 |
| `crates/sandlock-core/src/network/verdict.rs` | `destination_verdict(ip, port)` 纯函数 | 只拿到 IP，无 hostname 上下文 |
| `crates/sandlock-core/src/network/materialize.rs` | sockaddr 解析（TOCTOU 安全） | 同上 |
| `crates/sandlock-core/src/network/connect.rs` | `connect_on_behalf`：策略判定 + `ConnectPlan`（redirect/remap/passthrough）→ 代连 | 决策点是 IP，扩展点在这里 |
| `crates/sandlock-core/src/seccomp/notif.rs` | `NetworkPolicy::{AllowList{per_ip,cidrs,any_ip_ports}, DenyList, Unrestricted}` | `per_ip` 是 hostname 解析后的落点 |
| `crates/sandlock-core/src/netlink/synth.rs` | 虚拟网卡/地址的 netlink 合成 | 已具备"虚拟网络视图"能力，DNS 合成可复用思路 |
| `python/src/sandlock/sandbox.py` | Python 参数 `net_allow` 等 → FFI | 规则语法扩展的透传点（无 Python API 破坏） |

关键结论：sandlock 的 hostname 规则 = "创建时解析 → 固定 IP 集合"。要支持
`*.example.com`，必须让 supervisor 在**连接时**知道目标 hostname 并做后缀
匹配。

## 4. 需求点（Block A：域名通配符）

### R1 — 规则语法：`net_allow` 接受通配域名

- `net_allow` 条目支持 `*.example.com`（仅 TCP/UDP 目标规则，语法沿用
  `host:port` 后缀）。
- 语义：匹配任意**子域**（`api.example.com`、`a.b.example.com`），**不匹配
  裸域名** `example.com`（与 egress-proxy 库 `*.suffix` 语义一致）。
- 与字面 hostname 规则、IP/CIDR 规则共存；`net_deny` 保持仅 IP/CIDR
  （E2B 标准 deny 不支持域名）。
- 验收：`Sandbox(net_allow=["*.example.com:443"])` 可创建；非法形态
  （`**`、空后缀、带 scheme 的通配）报清晰错误。

### R2 — 沙箱内 DNS：通配域名的子域解析返回合成 IP

- 沙箱内 `getaddrinfo("api.example.com")` 返回一个**专用合成 IP**（如
  `127.0.0.2/8` 段，与 egress-proxy 库同段或独立段），不触发真实 DNS；
- supervisor 维护 `hostname ↔ 合成 IP` 映射（线程安全、容量上限、LRU 或
  按规则域分组）；
- 非通配 hostname 规则保持现状（创建时解析 pin 真实 IP）。
- 验收：沙箱内解析命中通配域的子域返回合成 IP；映射可查询；并发解析无
  竞态。

### R3 — on-behalf connect：合成 IP 反查 hostname 并匹配

- `connect_on_behalf` 在拿到目标 IP 后：若是合成 IP → 反查 hostname →
  按 `*.suffix` 规则匹配（allow 命中才继续）；
- 匹配通过后：supervisor **实时解析该 hostname**（保持 E2B "远程 DNS /
  dial-time 解析" 语义）并代连；解析失败 → `ECONNREFUSED`（fail closed）；
- 未命中任何通配规则、或沙箱直接连接字面 IP：走现有 `NetworkPolicy` IP
  判定，**不允许借合成 IP 段绕过字面规则**。
- 验收：通配子域连接成功且目标正确；非匹配子域被拒；字面 IP 连接仍受
  allow/deny 约束；静态/Go 客户端（不走 libc getaddrinfo 的直连 IP）无法
  绕过。

### R4 — 合成 IP 段的防绕过

- 合成 IP 段对沙箱只用于"承载 hostname"：任何直连合成 IP（不经过
  hostname 反查）必须拒绝，且合成 IP 永不作为真实出口地址；
- 沙箱内无法把任意 hostname 注册进映射（映射只由 supervisor 在解析
  getaddrinfo 时写入）；
- 验收：沙箱内 `connect(合成IP:任意端口)` 不匹配任何规则时返回
  `ECONNREFUSED`；模拟恶意直接写合成 IP 无法建立出站。

### R5 — HTTP ACL / rules 域名的通配（可选，随 R1-R4 一并设计）

- `http_allow` / `http_deny` 的 host 位置支持 `*.example.com`（当前仅
  `*` 任意）；为 B2（credential injection 按域名注入）铺路。
- 验收：`http_allow=["GET *.example.com/*"]` 拦截并放行子域、拒绝裸域。

### R6 — 项目接入：校验放开 + 策略映射

- `gateway_common/network.py`：普通模式下 `allowOut` 允许 `*.example.com`
  （不再依赖 `egressProxy`）；
- `SandlockExecutor`：把通配条目原样传给 sandlock `net_allow`（不展开、
  不转换）；普通模式不再需要 LD_PRELOAD 参与过滤。
- 验收：`POST /sandboxes` 普通模式带 `allowOut: ["*.example.com"]` 返回
  201 并回显；sandlock 沙箱内子域可达、裸域拒绝。

### R7 — 兼容与回归

- 现有字面 hostname / IP / CIDR / bind / egressProxy / rules 行为不变；
- 单机与多节点（共享 workspace、迁移、Redis）回归全绿；
- 动态更新（`PUT /sandboxes/{id}/network`）下一条命令生效。

## 4B. 需求点（Block B：HTTP(S) header 注入 / 改写）

### R8 — 暴露 credential injection（ffi + Python）

- 上游 Rust 层已有 `credential.rs`（`InjectRule { name, matcher: HttpRule,
  auth: AuthShape, secret: SecretString, on_existing }`）与
  `transparent_proxy/service.rs` 的注入执行，但 **ffi / Python 未暴露**：
  - `sandlock-ffi/src/lib.rs` 新增 inject-rule builder（沿用现有
    `http_*` builder 模式）；
  - `python/src/sandlock/sandbox.py` 新增 `http_inject` 参数
    （`list[dict]`：matcher / auth shape / secret 源 / on_existing）。
- 映射 E2B `rules[domain].transform.headers`：matcher=域名，auth shape=
  header 名，secret 源=`env:`/`file:`（对应 E2B IAM 占位符
  `${e2b.identity.tokens.*}` → 平台注入 env 或文件后引用）。
- 验收：沙箱对注册域名的请求携带注入 header；明文 HTTP 触发一次性告警；
  secret 不出沙箱（`SecretString` 零化语义保持）；denied 请求不触达 secret。

### R9 — HTTPS MITM 复用

- 复用现有 `http_ca` / `http_key` / `http_inject_ca`（0.8.6 已有）：
  注入执行发生在 MITM 代理内，HTTPS 走 CA 注入 + per-SNI 证书。
- 验收：HTTPS 请求 header 注入生效，沙箱信任链含代理 CA。

### R10 — maskRequestHost（host 掩码）

- 上游无对应物：`transparent_proxy/service.rs` 转发前改写请求
  authority / `Host`（`*.example.com` → 掩码 host）。
- 验收：匹配域名的请求 `Host` 被改写为目标掩码，上游收到掩码 host。

### R11 — HTTP ACL 域名通配（与 R5 合并的正式化）

- `http_allow` / `http_deny` 的 host 位置支持 `*.suffix`（当前仅字面或
  `*`）；为 R8 的 matcher 提供通配能力。
- 验收：`http_allow=["GET *.example.com/*"]` 放行子域、拒绝裸域。

## 4C. 需求点（Block C：egressProxy on-behalf 完整化）

### R12 — `ConnectPlan` 增加 SOCKS5 上游分支

- `network/connect.rs` 的 `ConnectPlan` 增加 `Socks5Upstream`：
  - allow/deny 过滤通过后，TCP 目标改为用户代理地址；
  - 域名目标用 SOCKS5 `ATYP=domain`（远程 DNS），IP 目标用
    `ATYP=IPv4/IPv6`；
  - RFC 1929 认证（username/password）；
  - UDP/ICMP 不隧道（与 E2B 语义一致）。
- 验收：python/node/静态二进制（不走 libc getaddrinfo 的直连）都经代理；
  代理收到 `ATYP=domain`；UDP 直出。

### R13 — fail closed 与地址校验

- 代理不可达 / 握手失败 / 非 SOCKS5 → `ECONNREFUSED`（绝不回退直连）；
- 创建前校验代理地址（控制面已有：公网 IPv4；扩展支持 IPv6 时同步
  校验规则）。
- 验收：代理宕机时沙箱出站失败；内网代理创建被拒。

### R14 — LD_PRELOAD 库退役策略

- on-behalf SOCKS5 落地后，LD_PRELOAD 库（`envd_service/egress/`）退役或
  保留为"沙箱外兜底"（二选一，默认退役）；
- 退役后普通模式/egressProxy 模式的过滤统一由 sandlock 执行。

## 5. 技术方案（Block A：逐文件改动）

### 5.1 `network/rules.rs` — 规则解析

- `NetRule` 增加通配 hostname 变体：`*.suffix`（剥离 `*.` 存 suffix，
  校验：suffix 至少一个 `.`、无其他 `*`）。
- 解析阶段：通配规则**不 DNS 解析**，进入新的策略字段
  `wildcard_suffixes: Vec<HostSuffixRule>`（连同端口）；字面 hostname 规则
  维持现状（解析进 `per_ip`）。
- `/etc/hosts` 虚拟化：通配规则不再参与字面 pin；DNS 拦截逻辑改由
  supervisor 处理子域解析（见 5.2）。

### 5.2 DNS 合成 — 新模块 `network/dns_synth.rs`（或并入 rules.rs）

- 拦截沙箱 `getaddrinfo`（现有 seccomp 通知/`/etc/hosts` 路径扩展）：
  - 解析目标 hostname，若匹配任一 `*.suffix` → 分配合成 IP
    （`127.0.0.2/8` 内，全局唯一）并登记映射；
  - 不匹配 → 现有行为。
- 映射表：`Arc<RwLock<HashMap<synth_ip, String>>>`，容量上限（如 4096），
  超限 LRU 淘汰（防沙箱耗尽 supervisor 内存）。
- 合成 IP 段选择需与 egress-proxy 库错开或统一（避免两套过滤语义冲突）。

### 5.3 `network/connect.rs` + `network/verdict.rs` — 连接判定

- `destination_verdict` 增加 hostname 上下文重载：
  `destination_verdict_with_host(effective, ip, port, hostname)`：
  - 先查合成 IP 映射拿 hostname → 匹配 `wildcard_suffixes`；
  - 命中 → 放行进入代连（supervisor 解析 hostname）；
  - 未命中/无映射 → 走现有 IP/CIDR 判定；
  - 合成 IP 直连且无映射 → 拒绝。
- `connect_on_behalf` 在 `ConnectPlan` 计算处调用新判定；代连目标由
  "已解析 IP" 改为 "实时解析 hostname 的首个 IP"（失败 fail closed）。
- 端口语义：通配规则带端口（`*.example.com:443`）时按端口匹配。

### 5.4 `sandlock-ffi` — 无 ABI 变化

通配条目只是 `net_allow` 字符串，FFI 已透传字符串数组，无需改 C ABI。

### 5.5 Python 绑定（`python/src/sandlock/`）

- `sandbox.py` 字段文档更新（`net_allow` 支持 `*.suffix`）；
- 无参数结构变化；`_sdk.py` builder 已按字符串透传，改动最小。

### 5.6 本项目接入

- `gateway_common/network.py`：`allow_wildcard_domain` 不再依赖
  `egressProxy`（普通模式放开）；denyOut 限制不变。
- `SandlockExecutor`：通配条目直接进 `net_allow`；egress-proxy 库的过滤
  仅保留给 egressProxy 模式。
- 测试：`tests/security/test_network_enforcement.py` 新增通配用例
  （`*.example.com` 子域成功 / 裸域拒绝 / 静态直连 IP 不可绕过）。

## 5B. 技术方案（Block B：header 注入 / 改写）

### 5B.1 `sandlock-ffi/src/lib.rs` — 暴露 inject rule

- 参照现有 `sandlock_sandbox_builder_http_*` builder，新增
  `sandlock_sandbox_builder_http_inject_rule(builder, matcher, auth_shape,
  secret_source, on_existing)`；`_sdk.rs` 增加对应 `_b_http_inject`。

### 5B.2 `python/src/sandlock/` — 参数与序列化

- `sandbox.py` 新增 `http_inject: Sequence[Mapping]`（字段校验 + 默认空）；
- `_sdk.py` / `_profile.py` 序列化规则（JSON 表达 matcher/auth/secret 源）。

### 5B.3 `transparent_proxy/` — maskRequestHost 与通配 matcher

- `service.rs`：转发前改写 authority/Host（新增 `host_mask` 配置）；
- `mod.rs` / `service.rs`：`HttpRule` host 匹配支持 `*.suffix`
  （R11）；注入执行已就绪（R8 只差配置暴露）。

### 5B.4 本项目接入

- `gateway_common/network.py`：`rules[domain].transform.headers` 与
  `maskRequestHost` 从"400 拒绝"改为映射到 `http_inject` / `host_mask`；
  IAM 占位符解析（平台注入 secret env/file）。
- `SandlockExecutor`：`http_inject` / `host_mask` 透传；CA 注入复用现有
  每沙箱信任副本逻辑。

## 5C. 技术方案（Block C：egressProxy on-behalf）

### 5C.1 `network/connect.rs` + `verdict.rs` — SOCKS5 分支

- `ConnectPlan::Socks5Upstream { proxy, creds, dest: DomainOrIp }`；
- 过滤（Block A 的 hostname 判定）通过后执行：先 real connect 代理
  （net_allow 放行代理端点），再 SOCKS5 握手（RFC 1928/1929），域名目标
  ATYP=domain；全部失败 → `ECONNREFUSED`。
- 代理地址在 supervisor 侧解析（支持 hostname/IPv4/IPv6）。

### 5C.2 配置透传

- `sandbox.py` 新增 `egress_proxy` 参数（address/user/pass）；ffi 新增
  builder；`SandlockExecutor` 普通模式也把过滤统一交给 sandlock。

## 6. 需要维护的所有部分

### 6.1 fork 仓库

- fork：**`https://github.com/imhun/sandlock`**（默认分支 `main`，已验证
  可克隆；上游 `multikernel/sandlock`）。所有改动在 fork 上进行：
  - 基于上游 tag（当前 0.8.6 或更新）建 `feature/network-wildcard`
    分支（Block A/B/C 可拆 `feature/network-inject`、
    `feature/network-socks5` 等独立分支）；
  - 改动以 patch 形式维护，禁止整体改写；
  - 本地协作：fork 为 `origin`，上游 `multikernel/sandlock` 为 `upstream`；
    每次上游发版 rebase 一次，冲突集中在 rules/connect 两文件。

### 6.2 Rust 核心（`sandlock-core`）

- `network/rules.rs`、`network/connect.rs`、`network/verdict.rs`、
  `seccomp/notif.rs`（`NetworkPolicy` 扩展）、新增 `network/dns_synth.rs`；
- 新增单元测试（verdict 纯函数可测）+ `tests/integration/test_network.rs`
  集成用例；
- 关注内存/并发安全（映射表锁、合成 IP 分配）、TOCTOU（沿用
  materialize 先拷贝后判定的既有约束）。

### 6.3 FFI 与 Python 绑定

- `sandlock-ffi`：原则上零改动，但需回归验证；
- `python/src/sandlock/`：文档、类型提示；如需要可在 `_profile.py`
  补充序列化测试。

### 6.4 wheel 构建与发布矩阵

- 构建工具：`setuptools-rust`（仓库自带 `python/setup.py`）；
- 必须产出的 wheel 矩阵（与官方 0.8.6 对齐）：
  - Python：cp310 / cp311 / cp312 / cp313 / cp314；
  - 平台：`manylinux_2_34_x86_64` + `manylinux_2_34_aarch64`；
- 发布方式二选一：
  a. 私有 wheel index（如 `pip index`/`devpi`/OSS 私有桶），Dockerfile 指向；
  b. 镜像构建时从 fork 源码 `pip install git+https://github.com/<org>/sandlock@<rev>`
     （`setuptools-rust` 需在构建镜像内装 Rust 工具链，镜像变大、构建变慢）；
- 建议 a：保持 `deploy/docker/Dockerfile.envd` / `deploy/docker/Dockerfile.test-runner` 只改一行
  `sandlock==<fork-version>` 来源。

### 6.5 镜像与依赖锁定

- `deploy/docker/Dockerfile.envd` / `deploy/docker/Dockerfile.test-runner`：sandlock 安装来源改为
  fork wheel/index；
- 锁定 fork 版本（`requirements` 或 pip `==`），升级需重新跑全量；
- 多架构镜像构建（`deploy/scripts/build-images.sh`）需在 CI 里对两个架构各编译
  wheel 一次。

### 6.6 测试矩阵

- 单元：`rules.rs` 解析、`verdict` 纯函数、合成 IP 映射并发；
- 集成：`tests/integration/test_network.rs`（真实 sandlock 沙箱）；
- 项目侧：`tests/unit/test_network_config.py`、`tests/security/`
  （通配用例 + 现有 egress-proxy/隔离回归）；
- 平台：x86_64 + arm64 各跑一遍 Linux 全量（Landlock ABI ≥ 6）；
- 回归基线：macOS 227 passed / Linux 249 passed（当前）。

### 6.7 安全面

- 合成 IP 段防绕过（R4）；
- 映射表资源上限（防 OOM）；
- 实时 DNS 解析的 SSRF 面：supervisor 解析 hostname 后仍需经过
  allow/deny（含 CIDR）二次校验，避免"通配规则 + DNS rebinding"绕过；
- 与 egress-proxy 库并存时两套过滤的一致性测试。

### 6.8 上游 PR 与回切

- 把改动整理成面向 `multikernel/sandlock` 的 PR（先 RFC/issue 对齐设计，
  再提代码）；
- 上游合入并发版后：切回官方 wheel，fork 分支归档；回切前跑同一测试矩阵
  确认行为一致。

### 6.9 Secret 管理（Block B 新增）

- `SecretString` 的 `env:/file:/fd:` 源选择：E2B IAM 占位符由平台解析并
  注入 worker 环境/文件，sandlock 只持有引用；
- 不得把明文 secret 写入沙箱可见文件/环境（只经 supervisor 渲染到出站
  请求）；`literal:` 源保持拒绝；
- 轮换：更新 `network.rules` 时替换 secret 引用（env 文件更新后重建
  runtime context）。

### 6.10 与 LD_PRELOAD egress 库的并存/退役

- Block C 落地前：两套过滤并存（sandlock 普通模式 / LD_PRELOAD 代理模式），
  需各自回归；
- Block C 落地后（R14）：LD_PRELOAD 库退役，删除 `envd_service/egress/`
  相关代码与镜像内 `/opt/egress/libegress_proxy.so`，`deploy/docker/Dockerfile.envd`
  的 builder 阶段移除（镜像更小）；
- 退役前跑一次双实现行为一致性对照（同一规则集）。

## 7. 里程碑

| 阶段 | 内容 | 产出 |
|---|---|---|
| M0 | fork + Rust 工具链 + 复现官方 wheel 构建（x86_64） | 可构建的 fork 基线 |
| M1 | R1+R2：规则解析 + DNS 合成 + 映射表 + 单元测试 | `net_allow=["*.example.com:443"]` 可解析、沙箱内返回合成 IP |
| M2 | R3+R4：connect 反查/匹配/实时解析代连 + 防绕过 | 通配子域可连、裸域/直连合成 IP 拒绝 |
| M3 | R6：项目接入（普通模式通配放开）+ SDK 用例 | 普通模式 API 放开 |
| M4 | Block B：ffi/Python 暴露 inject + maskRequestHost + http 通配（R8-R11） | ✅ `feature/network-inject` 已落地（header 注入与 host 掩码可用；项目侧 5B.4 映射待 fork wheel 切源） |
| M5 | Block C：SOCKS5 on-behalf 分支（R12-R14） | egressProxy 完整化、LD_PRELOAD 退役 |
| M6 | wheel 矩阵（cp310-314 × x86_64/aarch64）+ Dockerfile 切源 | 可发布、可部署 |
| M7 | 全量回归（双架构）+ 上游 PR（按 Block 拆分提交） | 与官方对齐、可回切 |

## 8. 备选与渐进路径

- **短期**：维持"egressProxy 模式支持通配、普通模式 400"现状（README 已
  标注差异），不阻塞现有功能；
- **中期（部分一致）**：Block B 优先于 A/C——header 注入靠上游 credential
  injection（Rust 已就绪，只需 ffi/Python 暴露），通配域名继续走
  egressProxy；
- **长期（本方案）**：sandlock on-behalf 域名规则引擎 + SOCKS5 分支 +
  inject 暴露，完整对齐 E2B。

## 9. 实现状态（2026-08-29，fork: imhun/sandlock）

> 分支：Block A → `feature/network-wildcard` / `feature/network-netns`
> （当前主线，含无特权默认路径 + per-sandbox netns 可选增强）；Block B →
> `feature/network-inject`（基于 network-netns）。

### 已落地（sandlock-core 0.8.6 fork，全部带单测）

- **R1 规则解析**：`NetTarget::HostWildcard`（`*.suffix`，剥离前缀存
  suffix）；`net_allow` 接受 `*.example.com[:ports]`（TCP/UDP；ICMP 显式
  拒绝）；非法形态（`**` / `*.` / `*.com` / `*.*.x` / 带 path / 端口 0）
  报清晰错误；`net_deny` 仍拒绝域名（含通配）。`resolve_net_allow` 把
  通配条目放入新的 `ResolvedNetAllow.wildcard_domains`，**不做 DNS、不
  产生 per-IP / `/etc/hosts` 条目**。`format_net_rule` 反序列化支持
  `*.suffix` 往返。
- **R2 映射表（新模块 `network/dns_synth.rs`）**：`SyntheticDns` ——
  hostname ↔ 合成 IP（`127.0.0.2/8`，与 egress 库同段）双向映射，LRU
  容量上限（默认 4096，防沙箱耗尽 supervisor 内存），合成段耗尽 fail
  closed；`wildcard_suffix_matches` 后缀匹配（匹配任意子域、不匹配裸域
  与部分后缀如 `badexample.com`、大小写不敏感）。
- **R3/R4 连接判定**：`destination_verdict_with_host` —— 带 hostname 时
  先做通配匹配（后缀 + 端口），未命中回落普通 IP 判定（hostname 不能
  借合成段绕过字面规则）；`connect_on_behalf` 对合成段地址先反查映射
  （无映射直接 `ECONNREFUSED`，防直连合成 IP 绕过），命中后 supervisor
  实时 DNS 解析（dial-time，失败 fail closed）并改写 sockaddr 代连，
  解析结果再过一次 IP 级判定（防 DNS rebinding + 通配规则绕过）。
  `NetworkPolicy::AllowList` 增加 `wildcard_domains`，`NetworkState`
  增加 `synthetic_dns`。

测试与产物：

- sandlock-core 新增 20 个用例（解析 8 + resolve 2 + dns_synth 7 +
  verdict 5）；lib 全量 `745 passed`（2 个既有 cow/seccomp 用例在容器
  root 下环境性失败，改动前后一致）。
- M0 基线：`cargo build --workspace` 通过；wheel
  `sandlock-0.8.6-cp311-cp311-linux_x86_64.whl` 可在容器内构建。

### 已落地（Block B — `feature/network-inject`）

- **R11 HTTP 通配 matcher**：`HttpRule::matches` host 位置支持 `*.suffix`
  （子域匹配、裸域不匹配、大小写不敏感），`parse` 校验非法形态；
  `extend_net_allow_for_http` 对 `*.suffix` 规则映射
  `NetTarget::HostWildcard`（走 DNS 合成 + SSRF 护栏）。
- **R8 credential injection 暴露**：FFI `credential` / `http_auth` builder；
  Python `Sandbox.http_inject`（matcher/auth/secret/name/on_existing）；
  secret 仅存 supervisor（`env:` 变量从子进程剥离）。
- **R10 maskRequestHost**：`host_mask` 贯穿 Sandbox/builder/CLI/FFI/Python/
  profile；透明代理转发前只改 wire `Host`（`${PORT}` 替换），URI 保持真实
  目标驱动连接；非法掩码 fail closed。
- **R9 HTTPS MITM 复用**：注入/掩码在明文与 MITM 共用 handler，TLS 终止
  路径既有测试覆盖。
- 验证：lib 763→771（2 个既有 root 环境性失败）、http_acl integration
  16/16、hermetic 代理测试、Python 412 passed、wheel 可构建。

### 未落地（下一步，按序）

- **Block C（M5）— SOCKS5 on-behalf**：`ConnectPlan::Socks5Upstream`
  替代 LD_PRELOAD egress 库（R12–R14），纯 TCP 握手无特权可实现。
- **Block C（M5）— SOCKS5 on-behalf**：`ConnectPlan::Socks5Upstream`
  替代 LD_PRELOAD egress 库（R12–R14），纯 TCP 握手无特权可实现。
- **M6 — wheel 矩阵**：cp310–314 × x86_64/aarch64 + 私有 index / git
  安装切换（worker 与测试镜像当前仍装 PyPI 0.8.6）。
- **M7 — 上游 PR**：把无特权部分整理成面向 `multikernel/sandlock` 的 PR；
  netns 留 fork 分支（上游是无特权项目）。
- **项目侧**：security 通配 e2e（fork wheel 下）、迁移（跨 worker netns
  重建）验证。

> 说明：R2 运行层的两条路径均已落地——默认**无特权共享 netns**（每沙箱
> loopback DNS 网关 `127.0.0.x:53`、合成 IP 段 10.250.0.0/16、netlink 虚拟
> eth0 修复 AI_ADDRCONFIG）与可选 **per-sandbox netns**（veth + 网关代连、
> `netns(true)`）。M3 项目接入已完成（wildcard 默认放行，netns 仅作隔离
> 增强）。
