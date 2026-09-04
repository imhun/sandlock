# F2b 阶段执行计划 — 路线 B：supervisor 进程化 `sandlock-supervise`（fork-plan-2026-09 §F2b）

Branch: `upstream-pr/netns-free-clean`（本地提交，不推送）。进度账本：`.superpowers/sdd/progress.md`。顺序：F2b.1 → F2b.2 → F2b.3 → F2b.4 → F2b.5（与 F3–F5 共用 instance API；F2b.4/.5 在 F3–F5 后收口）。

## 已确认决策（2026-09-04 用户拍板，plan 引用）

- B 档：per-uid 隔离——服务中介进程本身 = 该沙箱 host uid；特权只存在于 create 那一下。
- 双传输都实现：常驻/预启 slot = path+token（传输 2）；按需/launcher = fd 交接（传输 1）；共用同一套 verb/帧/auth 断言。supervise 固定**单代次**（一个进程一个沙箱，shutdown 清场后 exit(0)）。
- 回收 = 轮转槽位池；W1（默认）：增大 N，slot 池预起固定 uid；W2（可选）：服务完退出由部署层新 uid 重启。禁止"运行期把中介进程映射新 host uid"（C 档复活路径，代码+文档写死禁止）。
- fork 不装 setuid/特权组件：身份/降权/workspace chown 在 fork 外（E2B uid_pool/launcher/部署清单）。fork CI 全程非 root。
- 硬不变式：回收先清场再复用（inode 归零、XFS project 清理、workspace//tmp/控制目录销毁）；分配游标持久；stats 露出 host uid+段+代次。

## Task F2b.1：`sandlock-supervise` 二进制（策略全字段入口）

- 新 crate `crates/sandlock-supervise/`（bin，workspace）；入口 `--policy <fd|path.json> --uid X --control-fd N`；启动 `geteuid()==X` 自检否则**拒绝启动**；策略全字段（复用 Rust builder 字段集，反序列化→逐字段回读，字段未落地即启动失败——`_HANDLED_FIELDS` 等价机制）；不接受 OCI spec。
- 测试：`integration/test_supervise.rs :: test_supervise_refuses_wrong_uid`、`test_policy_roundtrip_covers_every_field`（字段清单与 builder 支持集取并集逐项断言，禁"未识别即忽略"）。
- runner 适配：新 crate 测试目标需纳入 `scripts/test-all.sh`（新 label `supervise`）+ baseline（本阶段内定数）。

## Task F2b.2：控制通道双传输（path+token / fd 交接）

- 传输 1 fd 交接：create 时 socketpair，一端 SCM_RIGHTS 交 supervise（fd 记入实例状态），一端留宿主 worker；路径不参与鉴权；再叠 token 握手。
- 传输 2 path+token：slot 以 uid X 预起；socket 放共享目录（root-owned 1777+sticky 或注册通道目录），目录名哈希；peer 检查 SO_PEERCRED ∈ 允许清单（worker uid 65534）+ token 握手（F1.3 同套断言）。单机/CLI 同 uid path 并入"允许清单只含自身"特例。
- 测试：test_control.rs 五条（socketpair/fd-handoff 拒第三方、path uid mismatch closes、registered path allowlist+token、沙箱内不可达 sibling）。

## Task F2b.3：身份交接契约（fork 只定契约，不装特权）

- fork 提供/测试："supervisor 进程以任意非 root uid 运行 ⇒ 全功能（Landlock/seccomp/notif/DNS 网关/入站映射）" + `--uid` 自检；"如何变成 uid X" 留在 fork 外文档契约。
- 测试：`test_supervisor_as_foreign_uid_is_fully_functional`（unshare/自映射或 setpriv 第二 uid 起 supervise，建箱/中介/入站端口/stats 全通）。

## Task F2b.4：预算与自证（B 档成本量化）— F3–F5 后

- 每沙箱 supervise RSS 预算（plan ≤8MB 期望）；slot 池内存/pid 预算；test_supervise_cost.rs 用例。

## Task F2b.5：交付物形态 — F3–F5 后

- 文档/契约/e2b-integration §8 更新；stats 露出 host uid+段+代次；回收/清场验证（test_slot_reuse.rs 等）。
