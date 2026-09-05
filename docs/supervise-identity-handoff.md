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
| `exec` | **Explicit F3 skeleton**: returns a clear “exec arrives with F3” error — never a silent no-op |
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
