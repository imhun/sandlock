# Sandbox identity hand-off contract (fork route B — F2b.3)

> 摘要：fork 提供并测试的是「supervisor 进程以任意非 root host uid X 运行 ⇒
> 全功能」（Landlock/seccomp-notif 中介、DNS 网关、入站端口映射、实例生命周期），
> 并以 `--uid X` 启动自检兜底。**fork 不安装、也不默认提供任何特权组件**：
> “如何把进程变成 uid X”留在部署侧（root launcher 持
> `CAP_SETUID/CAP_SETGID/CAP_CHOWN`、file-cap launcher、或常驻 slot 池 ①）。
> create 期需要特权的三件事（workspace chown、supervisor 降权、控制 fd 交接）
> 都定义在 fork 之外；supervise 自建 workspace，连 CAP_CHOWN 都不需要。
> **禁止**“运行期把中介进程重新映射到新的 host uid”（C 档复活），该路径在
> 代码与本文档中写死。W1/W2 回收语义与硬不变式见文末。

Plan references: `docs/fork-plan-2026-09.md` §F2b（B 档决策、
2026-09-04 拍板）、`docs/fork-plan-2026-09-f2b.md` Task F2b.3。
The acceptance suite that pins this contract end-to-end is
`crates/sandlock-supervise/tests/supervise_root.rs`
(`test_supervisor_as_foreign_uid_is_fully_functional`,
`test_supervisor_as_foreign_uid_fd_handoff_serves_worker`), run in the root
container phase via `scripts/test-all.sh --supervise-root`.

## 1. What the fork provides and tests

`sandlock-supervise` is a single-generation supervisor: one process owns one
sandbox `SandboxInstance`, built from the full-field policy (fork-plan F2b.1)
and — when a workload program is provisioned with `--program` — launched
**first**, before any control verb is served (F2b.3 launch-first). The
process then serves instance-level verbs over either control transport until
a `shutdown` verb completes the generation (clean teardown, exit 0).

The capability the fork claims and proves is *identity independence of the
supervisor*: the sandbox mechanism needs no privileges from whoever runs it,
so a supervisor that a deployment started as **any non-root uid X** is fully
functional:

- Landlock path policy and the seccomp deny filter (kernel-side);
- the seccomp user-notification supervisor (network allow/deny, resource
  accounting, port remap, procfs virtualization, …);
- the per-sandbox DNS gateway (wildcard-domain rules, synthetic answers);
- S2.5 inbound port mapping (a host listener on `127.0.0.1:host_port`,
  owned by the supervisor's uid, served into the sandbox's `accept()`);
- instance lifecycle (`stats`/`ports`/`run`/`shutdown`, exec verb skeleton
  for F3).

The only identity-related code in the fork is the **startup self-check**: the
binary refuses to start unless `geteuid() == --uid X` (before touching the
policy transport), so a launcher that forgot to drop privileges cannot
silently run the sandbox in the wrong identity class (the route-B C-grade
fallback). That check plus the `--peer-uid` worker allowlist is the entire
fork-side identity surface.

## 2. Fork boundary: privileges are never installed by the fork

The fork does not ship, install, or default to any setuid binary, and it
contains no `CAP_SETUID`/`setuid`/`setfsuid` code and no runtime uid
re-mapping. How a supervise process *becomes* uid X is entirely a deployment
concern. The accepted deployment shapes (plan table, 2026-09-04):

| Shape | Runtime root? | What the deployer installs/does | Fork involvement |
|---|---|---|---|
| **① pooled slot** (default for route B) | No | Start N long-lived `sandlock-supervise` processes, one fixed uid per slot (k8s `runAsUser`, compose `user:`, systemd template units); worker connects by registered path + token | Zero: identity is set by deployment, workspace is self-created, control is path+token |
| **③ file-cap launcher** (on-demand) | No | `setcap cap_setuid,cap_setgid+eip` on a ~50-line launcher that drops to uid X and hands over the control fd, then clears its capabilities | Launcher never parses policy; supervise does |
| **② `newuidmap`/`newgidmap` multi-entry userns** | No | Setuid helpers + `/etc/subuid` | **Excluded** (see §5: the forbidden runtime re-map is built on this class) |
| **④ setuid-root helper** | Instant euid 0 | `chmod +s` on a helper | **Excluded** — largest attack surface; last resort only |

Route B's default is ①; on-demand/launcher deployments use ③. The fork itself
never exercises ②/③/④ — in the fork's own CI and local verification the
supervisor always runs unprivileged (uid 65534 in the non-root phase, uid
65533 in the root-phase foreign-uid acceptance, both without any capability).

> **F14（2026-09-06）— ③ 形态与本 gate 的关系**：route-B ③ launcher 的正确使用
> 方式不变——launcher 持有 `cap_setuid,cap_setgid+eip` **只在 drop 到 uid X 并
> exec `sandlock-supervise` 之前**，supervise 自身无 caps/无 remap 代码。若
> 部署形态误把持有 effective `CAP_SETUID/CAP_SETGID` 的进程直接调 fork 的进程内
> API（不经 supervise），fork 侧的 C 档 gate 现已 capability-aware：euid 非 0 但
> effective caps 含上述两能力也按特权跨 uid remap 分类，在**建箱前**以点名能力的
> 消息 fail-closed 拒绝（不再落到暗示无 caps 的晚拒）。launcher 必须在任何
> sandlock API 调用前完成降权/清 caps（supervise 交接路径不经本 gate）。

## 3. The three privileged create-time actions (and how to avoid them)

For the on-demand/launcher shape (③), "creating" a sandbox needs privilege
for exactly three things — all outside the fork:

1. **Workspace chown to X** (needs `CAP_CHOWN`). *Avoided by design*:
   supervise creates its own workspace/state directories as the uid it is
   running as, so the on-disk state is owned by X from the first `mkdir` and
   no chown ever happens. Deployers must hand supervise a *writable parent*
   (e.g. a per-uid data dir already provisioned by the orchestrator), not a
   root-owned directory that needs re-owning.
2. **Dropping the supervisor process to uid X** (needs `CAP_SETUID`/
   `CAP_SETGID`). The launcher does this before `exec`; supervise's `--uid`
   self-check is the guard that the drop actually happened.
3. **Handing over the control fd** (transport 1, fd hand-off). The launcher
   creates the `socketpair()` at create time and passes one end as
   `--control-fd N`; the fd itself is the credential. Nothing privileged
   happens at runtime.

In the pooled-slot shape (①) none of the three exists: identity is fixed by
deployment, workspace is self-created, and control goes over the registered
path + token (transport 2, below). The fork treats ① and ③ identically after
startup — supervise has exactly one implementation for both.

## 4. Control transports and the worker identity model

Both transports share one verb/frame/auth session (4-byte big-endian length +
JSON, version 1, per-verb channel token; see `crates/sandlock-core/src/
control.rs`):

- **Transport 1 — fd hand-off (on-demand/launcher).** No filesystem path
  exists; the descriptor is the credential, and the per-channel token is the
  belt layered on top. Serve entry: `--control-fd N --serve [--token T]`.
- **Transport 2 — registered path + token (pooled slots).** The slot binds a
  hashed socket in the shared 1777+sticky registry
  (`/tmp/sandlock-ctl-<uid>-registry`, `SANDBOX_CTL_ROOT`-overridable) and a
  worker connects by path. Authentication is `SO_PEERCRED` membership in the
  allowlist (`--peer-uid`, empty = same-uid-only single-machine mode) **plus**
  the channel token on every verb. Serve entry:
  `--serve-path NAME --token T [--peer-uid UID]...`.

Route B's worker default is uid 65534 (`nobody`/overflowuid) — the E2B worker
image's `USER`. The allowlist is explicit configuration, not a fork constant;
deployments on another worker uid pass that uid. The genuine cross-uid
kernel-peer acceptance (`supervise` as 65533 serving a 65534 worker) is the
root-phase suite in §7.

Instance-level verb surface (all served against the live `SandboxInstance`):

| Verb | Semantics |
|---|---|
| `config` | Full-field policy snapshot (unchanged from F2b.2) |
| `run` | Launch-first trigger/state query: ok with the instance pid once the M0 process is running; explicit error when no `--program` was provisioned |
| `stats` | `instance_state` / `children_live` / `proc_count_vs_live` (+ pid) |
| `ports` | Live S2.5 inbound mappings (`sandbox_port`/`host_port`/`live`) + live `port_remap` table |
| `exec` | F3.2: registers a new child; the worker's three stdio fds arrive attached to the frame (SCM_RIGHTS) and the reply carries `child_id` + pid |
| `wait_child` / `kill_child` | F3.2 per-child verbs by `child_id`: exit status round-trip / registered signal delivery |
| `shutdown` | Ends the generation: response, then full §5.3 teardown, exit 0 |

`--program <fd|PATH.json>` carries the generation's first-process argv
(`{"argv": [...]}`), deliberately separate from the policy wire (the policy
describes what the sandbox allows, not what it runs; env/cwd/workdir/user
come from policy fields, exactly like `Sandbox::run`). Multi-process exec is
F3, on top of the same instance API.

## 5. Forbidden: runtime re-mapping of the mediator to a new host uid

> ⛔ **Hard invariant (pinned in code and docs).** A slot running as uid W
> must never give its sandboxes *different* host uids at runtime via a
> multi-entry uid map (shape ②). The sandbox mediator **is the supervise
> process**; if the mediator stayed W while the sandbox files/processes
> claimed uid X, the C-grade failure class returns and SL-1 (the mediator
> acting on a sandbox's behalf under the wrong identity) is back by
> construction.

Pinned in code:

- `crates/sandlock-supervise/src/lib.rs` —
  `FORBIDDEN_RUNTIME_MEDIATOR_REMAP` constant and the crate-root invariant
  note; supervise exposes no verb, flag, or code path that setuid/setfsuid/
  uid-maps a live generation to another host uid.
- `crates/sandlock-supervise/src/serve.rs` — “Identity boundary” module
  note: the mediator host uid is fixed at exec (`--uid` self-check), and the
  sandbox's userns maps only the supervisor's own uid (single-entry map).
- `crates/sandlock-supervise/src/main.rs` — startup contract note: this
  binary contains no setuid bit, no `CAP_SETUID` code, no runtime uid
  re-map.

Pinned in tests: the wire surface has no remap verb — an unknown
`map-uid`-class verb is refused as “unknown verb” by the shared handler, and
the foreign-uid acceptance asserts the mediator's files/processes are
actually owned by uid X (per-uid DAC holds by construction, not by
simulation).

F6.1 (SL-1) adds the core-side fail-closed twin of this invariant: the
`mediation_run_as` tier (default `caller`) makes the mediator-identity
contract explicit at the sandbox API level.  A *root in-process* mediator
remapping a sandbox to a non-zero host uid with path mediation active is
refused before fork — the exact route-B-C-grade revival this section forbids
— and only the explicit `mediation_run_as=supervisor` tier can opt into it
(warning + `stats().mediation_downgrades`, never silent; the root-mode
`--mediation-2uid` acceptance proves that tier really runs as the root
mediator).  Route B slots keep the single-entry self-map and never need the
downgrade tier.

## 6. W1/W2 recycle semantics and hard invariants

One uid = one supervise process = one sandbox generation; supervise is
structurally single-generation (there is no in-process “serve another
generation” path — reuse would require perfectly resetting the runtime, which
route B enforces by process restart instead). Recycling a slot therefore
means restarting the process, and the uid reuse window is the number of
simultaneously alive slots, not a per-slot duty cycle:

- **W1 (default)** — enlarge N: the pooled slot fleet is pre-started with
  fixed, non-overlapping uids, and each slot restarts in place (same uid)
  after its generation. Window = N.
- **W2 (optional upgrade)** — a slot exits after serving and the deployment
  restarts it under a **new** uid from a persistent allocation cursor, so the
  window becomes the uid segment size M. W2 requires a privileged
  restarter (k8s control plane creating a pod with `runAsUser`, or a
  can-drop-privileges runner on bare metal); static compose `user:` cannot do
  runtime uid changes.

Hard invariants under both:

1. Recycle = clean first, then reuse: the uid's inodes return to zero (the
   instance control dir and registered channel socket are removed by
   `shutdown`/process exit), XFS project accounting is released, and the
   generation leaves no process behind (the root-phase acceptance asserts
   exactly this).
2. The allocation cursor is persistent; within a W2 segment an unexpired uid
   is never re-issued while still in use.
3. `stats()`/deployment accounting exposes the current host uid and the
   generation count (surface lands with F2b.4/F2b.5).

Reclamation authority belongs to the starter: the worker (65534) cannot kill
a different-uid slot; teardown is allowed only as (a) the slot's own protocol
shutdown, (b) PDEATHSIG arranged by the starter, or (c) the starter
(deployment/launcher) reclaiming it.

Generation lifetime is deployment-owned in the same sense. `sandlock-supervise`
launches its instance with the core **maximum-lifetime cap disabled**
(`max_lifetime: None`): a slot's TTL is decided by the W1/W2 recycle policy
above (pool size / allocation cursor / starter reclamation), never by a
24-hour core default that could force-drain a long-lived workload. The core
idle reclaim default (15 min, only when the child table is empty with no
`wait_child` subscriber) still applies. Deployments must keep their own outer
timeouts for in-flight operations — core expiry is enforced at verb entry and
does not preempt an already-parked `wait_child` (see
`docs/sandbox-reference.md` "Instance lifetime").

## 7. How the fork proves the claim (test harness and uid choice)

The non-root gate cannot construct a second host uid (no CAP_SETUID), so the
genuine acceptance runs in the **root container phase** — the same privileged
`sandlock-dev:latest` phase as the oci root gate:

```text
docker run --privileged --rm -v "$PWD":/src -w /src --entrypoint bash \
  sandlock-dev:latest -c 'sh scripts/test-all.sh --supervise-root'
```

`tests/supervise_root.rs` then:

- spawns supervise with `setpriv --reuid=65533 --regid=65533 --clear-groups`
  (uid X; chosen outside every reserved/meaningful id — not 0, not the
  1–999 system range, not 65534/`nobody`/overflowuid, not the E2B worker);
- spawns the control worker with `setpriv --reuid=65534` (the route-B worker
  uid), so `SO_PEERCRED`, DAC, and process identity are all real kernel
  facts;
- asserts box creation, a mediated workload (Landlock deny + seccomp deny),
  DNS-gateway synthetic resolution, an external inbound round-trip through
  the uid-X-owned host listener, a stable reconciled `stats` snapshot, and a
  `shutdown` that exits 0 with no uid-X residue (processes, listeners,
  sockets, state dirs).

Both transports are covered: the full functional acceptance runs over the
registered path; the fd hand-off runs the same instance lifecycle with the
same genuine identities. There is no early-return soft skip anywhere — run
outside the root phase, the target fails loudly. The non-root phase runs the
rest of the supervise suite (`--lib --test supervise`), including both
transports' instance verbs in the same-uid special case.

## 8. Operational notes for deployers

- Always pass `--uid X` equal to the uid the process actually runs as; the
  refusal message names both uids.
- Registered-path tokens are provisioned out-of-band (`--serve-path` requires
  `--token`; supervise never prints a generated one).
- Give the slot a writable parent for its workspace; supervise creates the
  rest. Do not pre-chown anything to X from the fork side — there is no
  chown code here.
- Without a privilege component at all, deployments fall back to route A
  (per-uid DAC assertions do not hold there) — that fallback is a deployment
  decision, documented in the plan, not something supervise silently
  downgrades into.

## 9. Release deliverable: where the binary and fingerprint ship (F2b.5)

`sandlock-supervise` now ships with the wheel release, built per-arch in the
same buildx run as the wheels (`python/build-wheels.sh`, zig cross-linker,
glibc 2.34 pin identical to the FFI `.so`). One build produces three forms of
the same bytes:

- **In-wheel**: each `sandlock-*manylinux_2_34_{x86_64,aarch64}.whl` carries
  `sandlock/bin/sandlock-supervise`. `python/build-wheels.sh` injects it after
  auditwheel repair and updates RECORD, so `pip install` lands it executable
  (0755) at `site-packages/sandlock/bin/sandlock-supervise`. E2B image builds
  that already `pip install` the per-`TARGETARCH` wheel can exec it directly,
  e.g. `python -c 'import sandlock, pathlib; print(pathlib.Path(sandlock.__file__).parent / "bin" / "sandlock-supervise")'`.
- **Standalone**: `supervise/{x86_64,aarch64}/sandlock-supervise` next to the
  wheels for image builds that COPY the binary without pip (`COPY --from` /
  `docker cp` from the release directory, picking the dir that matches
  `TARGETARCH`; `chmod +x` is not needed, the file is 0755).
- **Fingerprint**: `SHA256SUMS.supervise` next to the wheels records the sha256
  of each arch's binary plus the `HEAD` commit the run built from. Take wheel,
  standalone binary, and manifest from the **same** release directory — they
  are the same bytes; a mixed-commit pair fails the release self-proof below.
  Note the asymmetry on purpose: the supervise fingerprint is **anchored at
  build time** (the manylinux builder toolchain differs from the dev container,
  so the bytes cannot be re-derived inside the verify container the way the FFI
  symbol set can). `python/verify-wheel.sh` therefore refuses stale manifests —
  rebuild the wheels from the tip before verifying (release discipline,
  `docs/e2b-integration.md` §3.4).

Release self-proof (extended F0.2 verifier): build the tip release lib
in-container, then run

```sh
HEAD=<sha> python/verify-wheel.sh   # default: wheels/*.whl
```

The verifier unpacks each wheel and asserts (in addition to the F0.2 FFI
symbol-set equality) that `sandlock/bin/sandlock-supervise` is present, is the
wheel's own architecture, and its sha256 equals both the manifest entry and the
standalone copy; the manifest `HEAD` must equal the current tip. It then
executes the extracted host-arch binary with a mismatched `--uid` and requires
a refusal (exit ≠ 0, stderr naming both uids) — the same startup contract as
§1, proven against the shipped artifact rather than only the source tree.
Deleting or tampering with the supervise binary, the standalone copy, or the
manifest goes red with the offending path/hash named.

## 10. Language client access surface（F16，2026-09-08）

route-B 的 worker（E2B envd，Python）今天**当不了** registered-path 客户端：`exec`
verb 的三端 stdio 必须随请求帧以 SCM_RIGHTS 交到 slot（`serve.rs` `handle_exec`），
而现有语言面只有 Rust（`control.rs` 的 `channel_request_with_fds` 与
`RegisteredPathChannel::connect_and_request`，后者不带 fds）。F16 把同一协议面
暴露给 C 与 Python：

- **C ABI（命名沿用 `sandlock_*` 纪律，错误沿用既有 `err: *mut c_int` +
  `err_msg: *mut *mut c_char` 约定，消息用 `sandlock_string_free` 释放）**：
  - `sandlock_supervise_connect(path, token, err, err_msg) -> void*`：只保存
    path/token 身份（registered transport 每 verb 一条新连接，连接建立延迟到
    request）；参数非法返回 null + err。
  - `sandlock_supervise_request(h, verb, args_json, fds, n_fds, err, err_msg)
    -> char*`：返回序列化的 `ControlResponse` JSON（`v/ok/data/err` 原样，
    调用方自己解析——客户端不做实例语义）。
  - `sandlock_supervise_free(h)`。
- **Python**：`sandlock.supervise.SuperviseChannel(path=..., token=...)`，
  `.request(verb, *, args=None, fds=()) -> dict`（ctypes 薄包装）；`exec` 的
  `fds` 必须是恰好 3 个 `[stdin, stdout, stderr]` 的 child 端；传输/协议错误翻成
  `exceptions.py` 的既有异常（connect/transport → `SandlockError`，非 ok 响应 →
  `SandboxError` 带服务端 err 文本）。`shutdown()` 便捷方法。
- **明确不做（本小节边界）**：不在 F16 里加实例语义——`exec`/`wait_child`/
  `kill_child` 的 verb 语义由服务端（Generation/handle_*）定义，客户端只做
  「发一请求、收一响应、附上要交的 fd」；不做 fd-handoff（transport 1）的
  语言面（worker 需要一条已建好的 UnixStream，部署面用 Rust/既有脚本）；不
  给 registry 协议加版本门（wire 版本与 init 帧协议 `FRAME_VERSION` 无关）。
- **两条部署约束（会咬人，接线前必读）**：
  1. `sun_path` 108 字节上限：registered registry 根路径过长会让 slot 假失败
     （fork 门禁自己踩过，`scripts/test-all.sh:12-20`）——E2B 侧 registry 根
     路径长度要进部署检查表；
  2. **一 uid = 一个 supervise = 一代沙箱**：槽位复用只能靠**重启进程**
     （§6）；uid 复用窗口 = 同时在世槽数 N。E2B 的 per-sandbox uid 池
     （`envd_service/uid_pool.py`）必须先选 W1/W2 之一再接线（见主仓库
     task-backlog #5 / 本计划 Task 9 Step 5）。
