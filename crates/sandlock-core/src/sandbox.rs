use std::collections::HashMap;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::context;
use crate::error::SandboxError;
pub use crate::http::{http_acl_check, normalize_path, prefix_or_exact_match, HttpRule};
use crate::instance::{InstanceStats, RuntimeState, SandboxInstance};
pub use crate::network::{IpCidr, NetAllow, NetDeny, NetRule, NetTarget, Protocol};
use crate::protection::{Protection, ProtectionPolicy, ProtectionState, ProtectionStatus};

mod builder;
pub use builder::SandboxBuilder;

/// Step trace for `SANLOCK_EVENT_TRACE=1` — the same switch the chroot mediator
/// prints under. It exists because a hang in the run path has to be attributed
/// to a *step* (create / start / wait) rather than guessed at from process
/// state alone (2026-09-22, the magic-fd case).
pub(crate) fn trace_step(msg: &str) {
    if std::env::var("SANLOCK_EVENT_TRACE")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
    {
        eprintln!("sandlock: {msg}");
    }
}

/// Default `max_processes`: the whole-box concurrent-process ceiling for a
/// sandbox session (fork-plan F5.1 / M3 S1).
///
/// Historically the value meant "64 per command" because every command ran in
/// its own sandbox instance, each with its own supervisor accounting block.
/// An exec-capable `SandboxInstance` shares **one** supervisor block across
/// every command, so the same knob now bounds the whole box; the default is
/// raised to 256 so switching from per-command to whole-box accounting does
/// not silently turn previously-fine workloads into EAGAIN victims (Q10).
pub const DEFAULT_MAX_PROCESSES: u32 = 256;

/// A byte size value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub fn bytes(n: u64) -> Self {
        ByteSize(n)
    }

    pub fn kib(n: u64) -> Self {
        ByteSize(n * 1024)
    }

    pub fn mib(n: u64) -> Self {
        ByteSize(n * 1024 * 1024)
    }

    pub fn gib(n: u64) -> Self {
        ByteSize(n * 1024 * 1024 * 1024)
    }

    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(SandboxError::Invalid("empty byte size string".into()));
        }

        // Check for suffix
        let last = s.chars().last().unwrap();
        if last.is_ascii_alphabetic() {
            let (num_str, suffix) = s.split_at(s.len() - 1);
            let n: u64 = num_str
                .trim()
                .parse()
                .map_err(|_| SandboxError::Invalid(format!("invalid byte size: {}", s)))?;
            let scale: u64 = match suffix.to_ascii_uppercase().as_str() {
                "K" => 1024,
                "M" => 1024 * 1024,
                "G" => 1024 * 1024 * 1024,
                other => {
                    return Err(SandboxError::Invalid(format!(
                        "unknown byte size suffix: {}",
                        other
                    )))
                }
            };
            // Checked: the multiply wraps in a release build, so a value that
            // parses cleanly but does not fit, such as "17179869184G", used to
            // come back as a ceiling of zero bytes rather than as an error.
            n.checked_mul(scale)
                .map(ByteSize)
                .ok_or_else(|| SandboxError::Invalid(format!("byte size out of range: {}", s)))
        } else {
            let n: u64 = s
                .parse()
                .map_err(|_| SandboxError::Invalid(format!("invalid byte size: {}", s)))?;
            Ok(ByteSize(n))
        }
    }
}

/// Identity to run the sandboxed process as.
///
/// Applied via a single-entry user-namespace map (`unshare(CLONE_NEWUSER)` +
/// `uid_map`/`gid_map`).  The interpretation depends on the supervisor:
///
/// * **Privileged supervisor** (root in its user namespace): `uid`/`gid` are
///   the **host** identity — the parent writes the map `0 -> uid` (and
///   `0 -> gid`) and the sandbox process runs as uid 0 *inside* the namespace
///   while the host sees the requested `uid`/`gid`.  Two sandboxes with
///   different `RunAs` ids therefore get kernel-enforced file and unix-socket
///   isolation (0700 + distinct host uid), even against a shared volume.
/// * **Unprivileged supervisor**: a single-entry userns can only map the
///   caller's own euid, so a `RunAs` that differs from the supervisor
///   identity can never be honored as a *host* uid — the sandbox would
///   silently keep the caller's host identity and cross-sandbox isolation
///   would be absent.  Such requests are **refused** at spawn with an
///   explicit error.  Per-sandbox independent host uids require a
///   privileged supervisor (root/CAP_SETUID in the parent user namespace)
///   or an equivalent mapping mechanism; only a `RunAs` matching the
///   supervisor's own identity (which skips the userns entirely) is
///   accepted without privilege.
///
/// Either way exactly one uid and one gid are representable (no
/// supplementary groups on the privileged path, no id ranges).
///
/// Parsed from `UID:GID`; both ids are required (no implicit default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
}

impl std::str::FromStr for RunAs {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (u, g) = s
            .split_once(':')
            .ok_or_else(|| format!("expected UID:GID, got {:?}", s))?;
        let uid = u.trim().parse::<u32>().map_err(|_| format!("invalid uid {:?}", u))?;
        let gid = g.trim().parse::<u32>().map_err(|_| format!("invalid gid {:?}", g))?;
        Ok(RunAs { uid, gid })
    }
}

/// C档 fail-closed gate (fork-plan F6.1 Step 3; F14 extends the trigger from
/// euid 0 to non-root effective CAP_SETUID/SETGID): refuse in-process path
/// mediation when the mediator would run the sandbox at a *different*
/// non-zero host uid — the mediated syscalls would run as the mediator
/// (euid 0, or a non-root euid holding effective CAP_SETUID/CAP_SETGID — the
/// route-B ③ file-cap launcher shape) and every per-uid DAC boundary
/// (ownership, `chmod`, sticky) would be wrong. Same-uid mediation
/// (host_uid == mediator euid) never remaps and is untouched.
///
/// Pure decision helper (unit-tested); the spawn site applies it with the
/// process's live euid, effective privileged-remap capability, the sandbox's
/// host uid and the resolved mediation features.
pub(crate) fn mediation_remap_is_refused(
    euid: u32,
    host_uid: u32,
    mediation_active: bool,
    privileged_remap_caps: bool,
) -> bool {
    mediation_active
        && host_uid != 0
        && (euid == 0 || (privileged_remap_caps && host_uid != euid))
}

/// True when this process's effective capability set would let it remap a
/// sandbox to an arbitrary host uid while euid is non-zero — the route-B ③
/// file-cap launcher shape (`cap_setuid,cap_setgid+eip` grants effective
/// CAP_SETUID/CAP_SETGID on exec). Reads `CapEff` from `/proc/self/status`;
/// capabilities are process-static after exec unless the process changes
/// them itself, so the read is stable for the process lifetime.
///
/// euid 0 is handled separately by [`mediation_remap_is_refused`] (kept
/// fail-closed even if root dropped its caps), so this helper only needs to
/// recognize the non-root-with-caps shape.
fn effective_caps_allow_privileged_remap() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            let Ok(mask) = u64::from_str_radix(hex.trim(), 16) else {
                return false;
            };
            // Capability numbering is a stable Linux UAPI
            // (include/uapi/linux/capability.h): CAP_SETGID = 6,
            // CAP_SETUID = 7. libc does not expose these constants on every
            // supported toolchain, so the bit positions are written out.
            const CAP_SETUID_BIT: u64 = 1 << 7;
            const CAP_SETGID_BIT: u64 = 1 << 6;
            return mask & (CAP_SETUID_BIT | CAP_SETGID_BIT) != 0;
        }
    }
    false
}

/// Whether this sandbox can exercise supervisor-side path mediation at
/// spawn time (I1 review fix): static `fs_denied` carve-outs, chroot and
/// COW dispatch all perform on-behalf opens, and — because the on-behalf
/// gate is `PolicyFnState::has_denied_paths()`, whose `DeniedSet` also
/// receives live `policy_fn`-issued `deny_path()` calls — a present
/// `policy_fn` is treated as mediation-capable too.  Conservative by
/// design: the refusal is about *capability*, not whether a deny has fired
/// yet.  `no_supervisor` disables the notif supervisor entirely, so no
/// on-behalf path exists.
pub(crate) fn mediation_active_for(
    no_supervisor: bool,
    fs_denies: bool,
    chroot: bool,
    cow: bool,
    policy_fn: bool,
) -> bool {
    !no_supervisor && (fs_denies || chroot || cow || policy_fn)
}

/// Confinement for confining the current process in place.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confinement {
    pub fs_writable: Vec<PathBuf>,
    pub fs_readable: Vec<PathBuf>,
}

impl Confinement {
    pub fn builder() -> ConfinementBuilder {
        ConfinementBuilder::default()
    }
}

#[derive(Default)]
pub struct ConfinementBuilder {
    fs_writable: Vec<PathBuf>,
    fs_readable: Vec<PathBuf>,
}

impl ConfinementBuilder {
    pub fn fs_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_writable.push(path.into());
        self
    }

    pub fn fs_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_readable.push(path.into());
        self
    }

    pub fn build(self) -> Confinement {
        Confinement {
            fs_writable: self.fs_writable,
            fs_readable: self.fs_readable,
        }
    }
}

impl TryFrom<&Sandbox> for Confinement {
    type Error = SandboxError;

    fn try_from(sandbox: &Sandbox) -> Result<Self, Self::Error> {
        let mut unsupported = Vec::new();
        if !sandbox.fs_denied.is_empty() { unsupported.push("fs_denied"); }
        if !sandbox.extra_deny_syscalls.is_empty() { unsupported.push("extra_deny_syscalls"); }
        if !sandbox.net_allow.is_empty() { unsupported.push("net_allow"); }
        if !sandbox.net_deny.is_empty() { unsupported.push("net_deny"); }
        if !sandbox.net_allow_bind.is_default() { unsupported.push("net_allow_bind"); }
        if !sandbox.net_deny_bind.is_empty() { unsupported.push("net_deny_bind"); }
        if !sandbox.net_bind_map.is_empty() { unsupported.push("net_bind_map"); }
        if sandbox.net_bind_inject { unsupported.push("net_bind_inject"); }
        if sandbox.allows_sysv_ipc() { unsupported.push("extra_allow_syscalls=[\"sysv_ipc\"]"); }
        if !sandbox.http_allow.is_empty() { unsupported.push("http_allow"); }
        if !sandbox.http_deny.is_empty() { unsupported.push("http_deny"); }
        if !sandbox.inject.is_empty() { unsupported.push("http_auth"); }
        if !sandbox.http_ports.is_empty() { unsupported.push("http_ports"); }
        if sandbox.http_ca.is_some() { unsupported.push("http_ca"); }
        if sandbox.http_key.is_some() { unsupported.push("http_key"); }
        if !sandbox.http_inject_ca.is_empty() { unsupported.push("http_inject_ca"); }
        if sandbox.http_ca_out.is_some() { unsupported.push("http_ca_out"); }
        if sandbox.host_mask.is_some() { unsupported.push("host_mask"); }
        if sandbox.egress_proxy.is_some() { unsupported.push("egress_proxy"); }
        if sandbox.max_memory.is_some() { unsupported.push("max_memory"); }
        if sandbox.max_processes != super::DEFAULT_MAX_PROCESSES {
            unsupported.push("max_processes");
        }
        if sandbox.max_open_files.is_some() { unsupported.push("max_open_files"); }
        if sandbox.max_file_size.is_some() { unsupported.push("max_file_size"); }
        if sandbox.max_cpu.is_some() { unsupported.push("max_cpu"); }
        if sandbox.random_seed.is_some() { unsupported.push("random_seed"); }
        if sandbox.time_start.is_some() { unsupported.push("time_start"); }
        if sandbox.no_randomize_memory { unsupported.push("no_randomize_memory"); }
        if sandbox.no_huge_pages { unsupported.push("no_huge_pages"); }
        if sandbox.no_coredump { unsupported.push("no_coredump"); }
        if sandbox.deterministic_dirs { unsupported.push("deterministic_dirs"); }
        if sandbox.workdir.is_some() { unsupported.push("workdir"); }
        if sandbox.cwd.is_some() { unsupported.push("cwd"); }
        if sandbox.fs_storage.is_some() { unsupported.push("fs_storage"); }
        if sandbox.max_disk.is_some() { unsupported.push("max_disk"); }
        if sandbox.on_exit != BranchAction::Commit { unsupported.push("on_exit"); }
        if sandbox.on_error != BranchAction::Abort { unsupported.push("on_error"); }
        if !sandbox.fs_mount.is_empty() { unsupported.push("fs_mount"); }
        if sandbox.chroot.is_some() { unsupported.push("chroot"); }
        if sandbox.clean_env { unsupported.push("clean_env"); }
        if !sandbox.env.is_empty() { unsupported.push("env"); }
        if sandbox.gpu_devices.is_some() { unsupported.push("gpu_devices"); }
        if sandbox.cpu_cores.is_some() { unsupported.push("cpu_cores"); }
        if sandbox.num_cpus.is_some() { unsupported.push("num_cpus"); }
        if sandbox.port_remap { unsupported.push("port_remap"); }
        if sandbox.fd_inject_connect { unsupported.push("fd_inject_connect"); }
        if sandbox.net_isolation { unsupported.push("net_isolation"); }
        if sandbox.user.is_some() { unsupported.push("user"); }
        if sandbox.policy_fn.is_some() { unsupported.push("policy_fn"); }

        if !unsupported.is_empty() {
            return Err(SandboxError::UnsupportedForConfine(unsupported.join(", ")));
        }

        Ok(Self {
            fs_writable: sandbox.fs_writable.clone(),
            fs_readable: sandbox.fs_readable.clone(),
        })
    }
}

/// Action to take on branch exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BranchAction {
    #[default]
    Commit,
    Abort,
    Keep,
}

// ============================================================
// Session instance — the heap-allocated state behind a running sandbox now
// lives in `crate::instance::SandboxInstance` (M0 lifecycle lift); this
// module keeps the per-child stdio modes and the `Sandbox` config/API.
// ============================================================

/// How one of a child's standard streams (stdin/stdout/stderr) is wired.
///
/// `Inherit` shares the supervisor's own fd (the child writes to the same
/// terminal/file the parent has). `Piped` creates a pipe whose caller-side end
/// is handed out via [`Process`] so the caller can stream to/from the live
/// process. `Null` connects the stream to `/dev/null`.
///
/// The discriminants are a stable contract: the FFI/Python bindings pass them
/// as a `u32`, so they are pinned with `#[repr(u32)]`.
/// How `restore_interactive*` delivers the restore stub
/// (`docs/chroot-workspace-exec.md` §11).
#[derive(Clone, Copy, PartialEq, Eq)]
enum RestoreLaunch {
    /// `execve` the stub by its host path (the historical route; needs the path
    /// to resolve inside the sandbox and a Landlock grant on it).
    Exec,
    /// Map the stub image from a memfd inside the confined child and jump into
    /// it: no path, no exec, no grant (the prototype route for chroot/real
    /// roots).
    InProcessNoExec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StdioMode {
    /// Inherit the supervisor's corresponding fd.
    Inherit = 0,
    /// Connect to a pipe; the caller owns the other end (see [`Process`]).
    Piped = 1,
    /// Connect to `/dev/null`.
    Null = 2,
}

/// Per-stream stdio wiring for a child process.
#[derive(Debug, Clone, Copy)]
struct StdioSpec {
    stdin: StdioMode,
    stdout: StdioMode,
    stderr: StdioMode,
}

impl StdioSpec {
    /// Capture mode used by `run`/`spawn`: stdin inherited, stdout/stderr piped
    /// and drained into the `RunResult` by `wait`.
    fn capture() -> Self {
        StdioSpec { stdin: StdioMode::Inherit, stdout: StdioMode::Piped, stderr: StdioMode::Piped }
    }

    /// Interactive mode: every stream inherits the supervisor's fd.
    fn inherit() -> Self {
        StdioSpec { stdin: StdioMode::Inherit, stdout: StdioMode::Inherit, stderr: StdioMode::Inherit }
    }

    /// True when every stream inherits, i.e. the run is interactive and the
    /// child may take the terminal foreground group.
    fn all_inherit(&self) -> bool {
        self.stdin == StdioMode::Inherit
            && self.stdout == StdioMode::Inherit
            && self.stderr == StdioMode::Inherit
    }
}

/// A COW branch (one `upper` over the workdir) shared by every stage of a
/// [`Transaction`](crate::transaction::Transaction). Cloned into each stage's
/// `SandboxInstance` so sequential stages accumulate writes in the same upper
/// (read-committed), while the coordinator retains the original to commit/abort
/// once at the end.
#[derive(Clone)]
pub(crate) struct SharedCow {
    /// The shared supervisor COW state (holds the single `SeccompCowBranch`).
    pub(crate) state: Arc<tokio::sync::Mutex<crate::seccomp::state::CowState>>,
    /// The branch's upper dir. Granted to each stage's Landlock ruleset for the
    /// same reason a single sandbox grants its own upper: Landlock checks
    /// EXECUTE against a file's real path, which for anything written inside the
    /// workdir is the upper. Cached here to avoid locking `state` to read it.
    pub(crate) upper_dir: PathBuf,
}

/// TCP bind allowlist (`--net-allow-bind`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindPorts {
    /// Allow binding only the listed ports. Empty means no bind is
    /// permitted while the NetTcp protection is active (the default).
    Ports(Vec<u16>),
    /// `--net-allow-bind '*'`: any TCP port may be bound.
    All,
}

impl Default for BindPorts {
    fn default() -> Self {
        BindPorts::Ports(Vec::new())
    }
}

impl BindPorts {
    /// True when no allowlist was configured (the default deny-all state).
    pub fn is_default(&self) -> bool {
        matches!(self, BindPorts::Ports(p) if p.is_empty())
    }

    /// True for the `'*'` wildcard (any port may be bound).
    pub fn is_all(&self) -> bool {
        matches!(self, BindPorts::All)
    }
}

/// Serde default for `control_socket` — deserialized configs that don't
/// mention the field still get introspection enabled.
fn default_control_socket() -> bool {
    true
}

/// Sandbox configuration.
#[derive(Serialize, Deserialize)]
pub struct Sandbox {
    // Filesystem access
    pub fs_writable: Vec<PathBuf>,
    pub fs_readable: Vec<PathBuf>,
    /// Host-side paths granted to the sandbox *as host paths*, bypassing the
    /// chroot translation `fs_readable` goes through (`landlock::build_ruleset`
    /// prefixes those with the rootfs and drops the ones that are not inside
    /// it). The only user is the checkpoint restore path: the restore stub is a
    /// build artifact on the host, a chroot root cannot name it (measured:
    /// `execvp` ENOENT, then a 10 s READY timeout), so it is delivered by
    /// descriptor and this grants that one file `EXECUTE|READ_FILE` -- Landlock
    /// judges a file by its real path whether or not the fd named it
    /// (`docs/chroot-workspace-exec.md` §11).
    ///
    /// `serde(skip)`: it is set in-process right before a restore launches, and
    /// skipping keeps the serialized policy layout (checkpoint images, the
    /// supervise wire) unchanged.
    #[serde(skip)]
    pub fs_readable_host: Vec<PathBuf>,
    pub fs_denied: Vec<PathBuf>,

    // Extra syscall filtering on top of Sandlock's default blocklist.
    pub extra_deny_syscalls: Vec<String>,
    pub extra_allow_syscalls: Vec<String>,

    /// Per-protection enforcement policy. Default
    /// (`ProtectionPolicy::strict_all()`) preserves the historical hard
    /// `MIN_ABI = 6` behaviour; `SandboxBuilder::allow_degraded` /
    /// `::disable` deviate from strict-all per protection.
    ///
    /// Part of the checkpoint: a saved sandbox restores with its exact
    /// protection posture. Without this, a sandbox built with a
    /// `disable()` opt-out (required on, e.g., a v5 host that cannot
    /// provide a v6 scope) would silently reset to `strict_all()` on
    /// load and fail to restore.
    pub protection_policy: ProtectionPolicy,

    // Network
    /// Outbound endpoint allowlist as a list of `(protocol, host?, ports)`
    /// rules. Each rule names a protocol (TCP/UDP/ICMP) and either a
    /// concrete host or "any IP." TCP and UDP rules carry ports; ICMP
    /// rules have none.
    ///
    /// **Protocol gating falls out of rule presence.** With no network
    /// rules at all, Sandlock denies UDP and ICMP socket creation. Once
    /// any network destination policy is active, datagram sockets may be
    /// created so libc DNS/address-selection probes can run, but actual
    /// UDP/ICMP destinations are still denied unless a matching rule for
    /// that protocol exists. Scheme-less specs expand to a TCP + UDP rule
    /// pair at parse time, so any of them opts UDP traffic in; ICMP always
    /// needs an explicit rule (`icmp://*` for any ICMP echo). TCP is
    /// always permitted.
    ///
    /// Empty `net_allow` and empty `http_allow`/`http_deny` together
    /// mean "deny all outbound" (Landlock direct path denies, no
    /// on-behalf path is enabled). Otherwise, the on-behalf path
    /// enforces these rules: a destination is permitted iff any rule
    /// matches the protocol, destination IP (or has `host: None` = any
    /// IP), and destination port (N/A for ICMP).
    ///
    /// HTTP rules with concrete hosts auto-add a matching
    /// `(Tcp, host, [80])` (and `(Tcp, host, [443])` when `--http-ca`
    /// is set) entry at build time so the proxy's intercept ports
    /// remain reachable. HTTP rules with wildcard hosts auto-add
    /// `(Tcp, None, [80])` instead.
    pub net_allow: Vec<NetAllow>,
    /// Parsed `--net-deny` rules (default-allow, IP/CIDR/port denylist).
    /// Mutually exclusive with `net_allow`.
    pub net_deny: Vec<NetDeny>,
    /// `--net-allow-bind`: TCP ports the sandbox may bind (default-deny
    /// allowlist, Landlock-enforced; `All` leaves Landlock's `BIND_TCP`
    /// hook unhandled so any port may be bound). Mutually exclusive with
    /// `net_deny_bind`.
    pub net_allow_bind: BindPorts,
    /// `--net-deny-bind`: TCP ports the sandbox may NOT bind (default-allow
    /// denylist, enforced on the on-behalf `bind()` path). Mutually
    /// exclusive with `net_allow_bind`.
    pub net_deny_bind: Vec<u16>,
    /// S2.5 inbound port mapping: `(host_port, sandbox_port)` pairs. When the
    /// sandbox listens on `sandbox_port` inside its own netns
    /// (`net_isolation` required), the supervisor listens on the host loopback
    /// at `host_port` (>= 50005) and serves the sandbox's `accept()` from that
    /// host listener by injecting the accepted connection fd (MCP-server path:
    /// external gateway -> host mapped port -> sandbox listener).
    #[serde(default)]
    pub net_bind_map: Vec<(u16, u16)>,
    /// S2.5 bind-injection mode: instead of letting the sandbox bind inside
    /// its own netns and serving `accept()` from a supervisor-side host
    /// listener, the supervisor *replaces the sandbox's socket* at `bind()`
    /// time with a socket it created and bound on the host loopback at the
    /// mapped `host_port` (`SECCOMP_ADDFD_FLAG_SETFD`, the mechanism
    /// `fd_inject_connect` already uses).
    ///
    /// The sandbox then `listen()`s and `accept()`s on a real host-netns
    /// listening socket: `accept()` needs no interception, the event loop's
    /// `ppoll`/`epoll_pwait` never enter the supervisor (no host-side queued
    /// connection needs synthesizing), and accepted connections are ordinary
    /// kernel accepts. The trade-off is the bind address — the host socket is
    /// bound to `127.0.0.1`/`::1`, never `0.0.0.0`, so that is what
    /// `getsockname()` reports.
    ///
    /// Requires `net_isolation` (the injected socket must not collide with the
    /// sandbox's own netns sockets) and a non-empty `net_bind_map` (the mapped
    /// pairs are exactly the ports that may be injected, and on which host
    /// port).
    #[serde(default)]
    pub net_bind_inject: bool,
    // HTTP ACL
    pub http_allow: Vec<HttpRule>,
    pub http_deny: Vec<HttpRule>,
    /// Credential-injection rules, applied in the MITM proxy after the ACL
    /// check. `Arc` so the (non-Clone) secrets flow to the proxy by sharing.
    /// Not serialized: the resolved secrets live only in the supervisor and are
    /// re-loaded from their sources on each build, never persisted in a policy.
    #[serde(skip)]
    pub(crate) inject: std::sync::Arc<Vec<crate::credential::InjectRule>>,
    /// `env:` var names to remove from the child's environment (so an env-sourced
    /// credential can't be read straight out of the agent's own env). Just names,
    /// no secrets — safe to serialize, but tied to `inject` which isn't restored.
    #[serde(skip)]
    pub(crate) inject_env_strip: Vec<String>,
    /// TCP ports to intercept for HTTP ACL. Defaults to [80] (plus 443 when
    /// http_ca is set). Override with `http_ports` to intercept custom ports.
    pub http_ports: Vec<u16>,
    /// PEM CA cert for HTTPS MITM. When set, port 443 is also intercepted.
    pub http_ca: Option<PathBuf>,
    /// PEM CA key for HTTPS MITM. Required when http_ca is set.
    pub http_key: Option<PathBuf>,
    /// Trust-bundle paths to splice the MITM CA into (zero-config HTTPS).
    pub http_inject_ca: Vec<PathBuf>,
    /// Path to write the active MITM CA public cert (PEM) for external trust
    /// wiring (e.g. NODE_EXTRA_CA_CERTS). Never writes the private key.
    pub http_ca_out: Option<PathBuf>,
    /// Mask the outbound `Host`/authority for every request the HTTP ACL proxy
    /// forwards. The token ``${PORT}`` (if present) is replaced with the
    /// request's destination port, so ``localhost:${PORT}`` maps a request to
    /// ``127.0.0.1:8080`` onto ``Host: localhost:8080``. Matches the official
    /// ``maskRequestHost`` semantics: the upstream sees the masked host while
    /// the sandboxed child keeps addressing the real destination.
    #[serde(default)]
    pub host_mask: Option<String>,
    /// SOCKS5 egress proxy for all outbound TCP (after allow/deny filtering).
    /// UDP/ICMP are not tunneled. The proxy endpoint is dialed by the
    /// supervisor and is not reachable directly from the sandbox. Contains
    /// the optional RFC 1929 password, so it is never serialized.
    #[serde(skip)]
    pub egress_proxy: Option<crate::network::egress::EgressProxyConfig>,
    /// Optional observation callback for HTTP learn mode. When set the proxy is
    /// spawned even without ACL rules; every request is logged via this closure.
    #[serde(skip)]
    pub(crate) http_log_fn: Option<std::sync::Arc<dyn Fn(&str, &str, &str) + Send + Sync>>,

    // Resource limits
    pub max_memory: Option<ByteSize>,
    pub max_processes: u32,
    pub max_open_files: Option<u32>,
    /// Per-**file** size ceiling (RLIMIT_FSIZE, soft and hard), in bytes.
    ///
    /// A single file may not exceed it; a tree may. That asymmetry is the
    /// point: this is the one disk bound the kernel enforces *during* a write,
    /// so a runaway `dd`/`cat` hits it with no supervisor, no accounting and
    /// no polling in the loop -- which is exactly what a per-write ENOSPC
    /// would cost instead. Set to a caller's whole box budget it can never
    /// refuse a file that box was allowed to hold.
    pub max_file_size: Option<ByteSize>,
    pub max_cpu: Option<u8>,
    /// Max seccomp user-notifications processed per second (see builder).
    #[serde(skip)]
    pub notify_rate_limit: Option<u32>,

    // Reproducibility
    pub random_seed: Option<u64>,
    pub time_start: Option<SystemTime>,
    pub no_randomize_memory: bool,
    pub no_huge_pages: bool,
    pub no_coredump: bool,
    pub deterministic_dirs: bool,

    /// The COW upper dir granted read+exec at spawn time so Landlock can
    /// execute binaries the workload creates in the workdir. An internal
    /// grant, not user policy: recorded here so `sandbox_to_profile` can
    /// keep it out of inspect output. Spawn-time state, not serialized.
    #[serde(skip)]
    pub(crate) cow_upper: Option<PathBuf>,

    // Filesystem branch
    pub workdir: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub fs_storage: Option<PathBuf>,
    pub max_disk: Option<ByteSize>,
    /// Host-maintained disk accounting for ``statfs(2)``: a file holding
    /// ``<total_bytes> <used_bytes>``. See `Builder::disk_stats_path`.
    pub disk_stats_path: Option<PathBuf>,
    pub on_exit: BranchAction,
    pub on_error: BranchAction,

    // Mount mappings: (virtual_path_inside_chroot, host_path_on_disk)
    pub fs_mount: Vec<(PathBuf, PathBuf)>,
    // Virtual paths (a subset of fs_mount destinations) mounted read-only:
    // reads allowed, writes denied even on a writable rootfs.
    pub fs_mount_ro: Vec<PathBuf>,

    // Environment
    pub chroot: Option<PathBuf>,

    /// When set, the confined child runs this function in-process instead of
    /// `execve`-ing a workload. Used to run an in-sandbox PID-1 (the OCI
    /// `sandlock-init` control loop) without exec'ing a separate image: the
    /// child is already a fork of the supervisor, so its code is mapped, and
    /// because nothing is exec'd, Landlock has no execution to authorize. The
    /// function must not return (it loops and `_exit`s); `confine_child` calls
    /// `_exit(0)` if it does.
    #[serde(skip)]
    pub in_child_main: Option<fn()>,

    pub clean_env: bool,
    pub env: HashMap<String, String>,
    // Devices
    pub gpu_devices: Option<Vec<u32>>,

    // CPU
    pub cpu_cores: Option<Vec<u32>>,
    pub num_cpus: Option<u32>,
    pub port_remap: bool,

    /// Connect fd-injection path (S2.1): supervisor-side connect + fd
    /// injection into the sandbox. Defaults to `false`; only meaningful
    /// under the seccomp-notif supervisor (not the Confinement path).
    #[serde(default)]
    pub fd_inject_connect: bool,

    /// Per-sandbox network namespace isolation (S2.2): when true, the
    /// sandbox spawns in its own netns (`unshare(CLONE_NEWNET)` after the
    /// user namespace), containing only loopback brought up from inside the
    /// sandbox's userns. Defaults to `false` (shared network namespace).
    /// Independent of `fd_inject_connect`. With wildcard-domain rules the
    /// DNS gateway binds inside the sandbox's own netns (S2.3), so the host
    /// `ip_unprivileged_port_start` sysctl is not needed for netns sandboxes.
    #[serde(default)]
    pub net_isolation: bool,

    /// Skip the seccomp user-notification supervisor. The sandbox runs
    /// with Landlock + a kernel-only deny filter, with none of the
    /// supervisor-mediated features (IP allowlist, resource limits,
    /// COW, chroot mediation, /proc virtualization, custom handlers).
    /// Required when nesting inside another sandlock — the kernel only
    /// allows one `SECCOMP_FILTER_FLAG_NEW_LISTENER` per task.
    pub no_supervisor: bool,

    /// Run the sandboxed workload in a private PID namespace
    /// (`CLONE_NEWPID`): the sandbox's first process is PID 1 inside its
    /// own namespace, foreign PIDs are invisible (`kill(pid, 0)` on host /
    /// other-sandbox processes returns `ESRCH`), and `/proc` is filtered
    /// and renumbered to the sandbox's own processes. Defaults to `false`.
    #[serde(default)]
    pub pid_ns: bool,

    /// Build a *real* root for the image-rootfs shape: a mount namespace owned
    /// by the sandbox's user namespace, the rootfs as its root, the policy's
    /// `fs_mount` entries bound inside it, and `pivot_root` into it (see
    /// `crate::realroot`). Turned on by a caller that has a `chroot` root and
    /// wants the kernel, not the mediator, to resolve paths -- which is what
    /// makes `#!` scripts and static binaries work (E2B N35). Requires
    /// `CAP_SYS_ADMIN` in the sandbox's user namespace, which is the sandbox's
    /// own; the capability is dropped before the workload starts, and the
    /// container the sandbox runs in must admit the mount-family syscalls.
    /// Defaults to `false`.
    #[serde(default)]
    pub real_root: bool,

    /// Self-map the supervisor's own host uid to in-namespace uid 0 (see
    /// `SandboxBuilder::userns_self_map`): how a route-B slot restores
    /// "root inside the sandbox, host uid outside". Honoured by both writers
    /// of the generation's uid_map: `confine_child` here, and the pid-ns
    /// intermediate process, which creates the user namespace before the
    /// final fork.
    #[serde(skip, default)]
    pub userns_self_map: bool,

    /// Enable the per-sandbox control socket for introspection (`sandlock ps`,
    /// `sandlock inspect`, etc.). Defaults to `true`. Set to `false` to skip
    /// the runtime dir, pid file, and control-socket tokio task entirely.
    #[serde(skip, default = "default_control_socket")]
    pub control_socket: bool,

    // User-namespace identity (run-as uid/gid)
    pub user: Option<RunAs>,

    // Dynamic policy callback
    #[serde(skip)]
    pub policy_fn: Option<crate::policy_fn::PolicyCallback>,

    // Sandbox instance name (exposed as virtual hostname; auto-generated if None).
    // Not serialized — instance names are set at runtime, not in the policy file.
    #[serde(skip)]
    pub name: Option<String>,

    /// Operating-mode marker (e.g. "learn") written to the runtime dir at
    /// spawn time and shown as STATUS by `sandlock ps`, so an operator sees
    /// why a sandbox exists (learn's read-everything observation run would
    /// otherwise be indistinguishable from a dangerously permissive one).
    /// Instance metadata like `name`, not policy — never serialized.
    #[serde(skip)]
    pub mode: Option<String>,

    // COW fork init function — runs once in the child before COW cloning.
    // Not serialized; not cloned (FnOnce can't be cloned — drops to None on clone).
    #[serde(skip)]
    init_fn: Option<Box<dyn FnOnce() + Send + 'static>>,

    // COW fork work function — runs in each COW clone.
    // Not serialized; cloned via Arc (cheap).
    #[serde(skip)]
    work_fn: Option<Arc<dyn Fn(u32) + Send + Sync + 'static>>,

    // Heap-allocated session state (a `SandboxInstance`); `None` when not
    // started. The sandbox drives a one-shot instance: run/popen/spawn and the
    // create/start/wait lifecycle operate on this block, and `wait()` shuts it
    // down (see `crate::instance`). Internal (crate-visible for the instance
    // handover in `SandboxInstance::launch`), not serialized, not cloned.
    #[serde(skip)]
    pub(crate) runtime: Option<Box<SandboxInstance>>,

    // Fds the last `restore_interactive` could not transparently recreate.
    // Runtime state: not serialized, not cloned.
    #[serde(skip)]
    restore_skipped: Vec<crate::checkpoint::SkippedFd>,
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandbox")
            .field("fs_readable", &self.fs_readable)
            .field("fs_writable", &self.fs_writable)
            .field("max_memory", &self.max_memory)
            .field("max_processes", &self.max_processes)
            .field("max_file_size", &self.max_file_size)
            .field("policy_fn", &self.policy_fn.as_ref().map(|_| "<callback>"))
            .field("name", &self.name)
            .field("runtime", &self.runtime.as_ref().map(|_| "<runtime>"))
            .finish_non_exhaustive()
    }
}

impl Clone for Sandbox {
    /// Clone a `Sandbox` — config and runtime-kwargs fields are cloned; the
    /// runtime state is not (the clone starts with `runtime: None`).
    ///
    /// Field clone semantics:
    /// - `policy_fn` — Arc bump (cheap).
    /// - `work_fn`   — Arc bump (cheap); multiple Sandboxes share the closure.
    /// - `init_fn`   — **dropped to `None`** (FnOnce can't be cloned). If the
    ///   clone also needs an init function, call `.init_fn(...)` on it
    ///   separately or set it via `SandboxBuilder::init_fn`.
    /// - `runtime`   — always `None`; the clone is a fresh, un-started Sandbox.
    fn clone(&self) -> Self {
        Self {
            fs_writable: self.fs_writable.clone(),
            fs_readable: self.fs_readable.clone(),
            fs_readable_host: self.fs_readable_host.clone(),
            fs_denied: self.fs_denied.clone(),
            extra_deny_syscalls: self.extra_deny_syscalls.clone(),
            extra_allow_syscalls: self.extra_allow_syscalls.clone(),
            protection_policy: self.protection_policy.clone(),
            net_allow: self.net_allow.clone(),
            net_deny: self.net_deny.clone(),
            net_allow_bind: self.net_allow_bind.clone(),
            net_deny_bind: self.net_deny_bind.clone(),
            net_bind_map: self.net_bind_map.clone(),
            net_bind_inject: self.net_bind_inject,
            http_allow: self.http_allow.clone(),
            http_deny: self.http_deny.clone(),
            inject: self.inject.clone(),
            inject_env_strip: self.inject_env_strip.clone(),
            http_ports: self.http_ports.clone(),
            http_ca: self.http_ca.clone(),
            http_key: self.http_key.clone(),
            http_inject_ca: self.http_inject_ca.clone(),
            http_ca_out: self.http_ca_out.clone(),
            host_mask: self.host_mask.clone(),
            egress_proxy: self.egress_proxy.clone(),
            http_log_fn: self.http_log_fn.clone(),
            max_memory: self.max_memory,
            max_processes: self.max_processes,
            max_open_files: self.max_open_files,
            max_file_size: self.max_file_size,
            max_cpu: self.max_cpu,
            notify_rate_limit: self.notify_rate_limit,
            random_seed: self.random_seed,
            time_start: self.time_start,
            no_randomize_memory: self.no_randomize_memory,
            no_huge_pages: self.no_huge_pages,
            no_coredump: self.no_coredump,
            deterministic_dirs: self.deterministic_dirs,
            // Cloned for the control-loop snapshot, which is taken after the
            // spawn-time upper grant lands in fs_readable.
            cow_upper: self.cow_upper.clone(),
            workdir: self.workdir.clone(),
            cwd: self.cwd.clone(),
            fs_storage: self.fs_storage.clone(),
            max_disk: self.max_disk,
            disk_stats_path: self.disk_stats_path.clone(),
            on_exit: self.on_exit.clone(),
            on_error: self.on_error.clone(),
            fs_mount: self.fs_mount.clone(),
            fs_mount_ro: self.fs_mount_ro.clone(),
            chroot: self.chroot.clone(),
            in_child_main: self.in_child_main,
            clean_env: self.clean_env,
            env: self.env.clone(),
            gpu_devices: self.gpu_devices.clone(),
            cpu_cores: self.cpu_cores.clone(),
            num_cpus: self.num_cpus,
            port_remap: self.port_remap,
            fd_inject_connect: self.fd_inject_connect,
            net_isolation: self.net_isolation,
            no_supervisor: self.no_supervisor,
            pid_ns: self.pid_ns,
            real_root: self.real_root,
            userns_self_map: self.userns_self_map,
            control_socket: self.control_socket,
            user: self.user,
            policy_fn: self.policy_fn.clone(),
            name: self.name.clone(),
            mode: self.mode.clone(),
            // init_fn (FnOnce) cannot be cloned — the clone gets None.
            // If the clone also needs an init function, set it explicitly.
            init_fn: None,
            // work_fn is Arc-wrapped — clone bumps the reference count.
            work_fn: self.work_fn.clone(),
            // Runtime is NOT cloned — the clone starts with no runtime.
            runtime: None,
            // Restore diagnostics belong to the original's run, not the clone.
            restore_skipped: Vec::new(),
        }
    }
}

/// Live process-accounting snapshot from the supervisor (SL-8 reconciliation).
///
/// `proc_count` is the bookkeeping count (`handle_fork` +1, released on the
/// authoritative exit path). `live_watchers` is the number of registered,
/// pidfd-watcher-backed processes the supervisor still tracks. `drift` is the
/// signed deviation (`proc_count − live_watchers`); in argv-safety mode a
/// persistent positive drift is the orphan-leak alarm, and zero is the
/// quiescent expectation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessStats {
    /// Bookkeeping concurrent-process count (root + unreleased fork children).
    pub proc_count: u32,
    /// Live pidfd-watcher-backed tracked processes (`ProcessIndex` size).
    pub live_watchers: u32,
    /// `proc_count − live_watchers` (signed; positive = leaked slots).
    ///
    /// F2.3 note: this is the same number the instance stats surface exposes
    /// as [`InstanceStats::proc_count_vs_live`]. Drift is transiently
    /// *negative* during exit cleanup: cleanup releases the `proc_count`
    /// slot before it unregisters the exiting process's `ProcessIndex`
    /// entry, so a snapshot in that window counts one fewer bookkeeping slot
    /// than live watchers; it resolves to zero once the unregister lands.
    /// Only a *persistent* positive drift is the orphan-leak alarm.
    pub drift: i64,
}

impl Sandbox {
    pub fn builder() -> SandboxBuilder {
        SandboxBuilder::default()
    }

    /// Returns true iff the policy grants the `sysv_ipc` syscall group.
    pub fn allows_sysv_ipc(&self) -> bool {
        self.extra_allow_syscalls.iter().any(|s| s == "sysv_ipc")
    }

    /// Validate cross-section invariants — checks that span multiple fields.
    ///
    /// Currently a no-op; retained as an extension point and for API
    /// stability. Idempotent: calling repeatedly is safe.
    pub fn validate(&self) -> Result<(), SandboxError> {
        // S2.5 inbound port mapping needs the per-sandbox loopback netns so
        // the supervisor can own the host mapped port, and the seccomp
        // supervisor to intercept listen/accept/close. Without either, the
        // mapping would be silently ignored — refuse instead of running with a
        // quietly weaker configuration.
        if !self.net_bind_map.is_empty() {
            if !self.net_isolation {
                return Err(SandboxError::Invalid(
                    "net_bind_map (inbound port mapping) requires net_isolation(true): \
                     the sandbox must live in its own loopback-only netns so the \
                     supervisor can own the host mapped port"
                        .into(),
                ));
            }
            if self.no_supervisor {
                return Err(SandboxError::Invalid(
                    "net_bind_map (inbound port mapping) requires the seccomp \
                     supervisor and is incompatible with no_supervisor=true"
                        .into(),
                ));
            }
        }
        // Bind-injection mode answers `bind()` by replacing the sandbox's
        // socket with a host-loopback one, so it needs the mapped port set
        // (which ports, on which host port) and the same supervisor the
        // mapping path needs.
        if self.net_bind_inject {
            if self.net_bind_map.is_empty() {
                return Err(SandboxError::Invalid(
                    "net_bind_inject requires net_bind_map: the mappings define \
                     which sandbox ports are injectable and on which host port"
                        .into(),
                ));
            }
            if !self.net_isolation {
                return Err(SandboxError::Invalid(
                    "net_bind_inject requires net_isolation(true): the injected \
                     host socket only makes sense while the sandbox owns its \
                     own loopback-only netns"
                        .into(),
                ));
            }
            if self.no_supervisor {
                return Err(SandboxError::Invalid(
                    "net_bind_inject requires the seccomp supervisor and is \
                     incompatible with no_supervisor=true"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    /// Resolve the per-protection state against the host's current
    /// Landlock ABI. Returns one entry per `Protection`. Useful for
    /// post-`build()` posture inspection.
    pub fn active_protections(&self) -> Result<Vec<(Protection, ProtectionStatus)>, crate::error::SandlockError> {
        let host_abi = crate::landlock::abi_version().map_err(|e| {
            crate::error::SandlockError::Runtime(crate::error::SandboxRuntimeError::Confinement(e))
        })?;
        Ok(Protection::all()
            .map(|p| (p, ProtectionStatus::resolve(p, host_abi, &self.protection_policy)))
            .collect())
    }

    // ================================================================
    // Runtime accessor helpers (private)
    // ================================================================

    fn rt(&self) -> &SandboxInstance {
        self.runtime.as_ref().expect("sandbox not started")
    }

    fn rt_mut(&mut self) -> &mut SandboxInstance {
        self.runtime.as_mut().expect("sandbox not started")
    }

    // ================================================================
    // Runtime lifecycle API (public)
    // ================================================================

    /// Set the sandbox instance name (also exposed as the virtual hostname).
    /// Auto-generated if not set.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    /// Set the sandbox instance name and return `self`. Convenience for
    /// pipeline fan-out where a base config is cloned and each clone gets a
    /// fresh name:
    ///
    /// ```ignore
    /// let template = Sandbox::builder()...build()?;
    /// let mut s1 = template.clone().with_name("worker-1");
    /// let mut s2 = template.clone().with_name("worker-2");
    /// ```
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the COW-fork init function and return `self`.
    ///
    /// The init function runs once in the child process before any COW clones
    /// are created. Use it to load expensive shared state.
    pub fn with_init_fn(mut self, f: impl FnOnce() + Send + 'static) -> Self {
        self.init_fn = Some(Box::new(f));
        self
    }

    /// Set the COW-fork work function and return `self`.
    ///
    /// The work function runs in each COW clone (`fork(N)` produces N clones).
    pub fn with_work_fn(mut self, f: impl Fn(u32) + Send + Sync + 'static) -> Self {
        self.work_fn = Some(Arc::new(f));
        self
    }

    /// Return the sandbox name if set, or `None` if not yet started.
    pub fn instance_name(&self) -> Option<&str> {
        self.runtime.as_ref().map(|r| r.name.as_str())
            .or_else(|| self.name.as_deref())
    }

    /// Return the child PID if spawned.
    pub fn pid(&self) -> Option<i32> {
        self.group_pid()
    }

    /// Host PID of the process group to signal when freezing or killing
    /// the sandbox. With a PID namespace the group leader is the sandbox's
    /// first process (ns pid 1, host pid `leader_pid`); without one it is
    /// the direct child. The direct child itself is only waited/reaped.
    fn group_pid(&self) -> Option<i32> {
        self.runtime
            .as_ref()
            .and_then(|rt| rt.leader_pid.or(rt.child_pid))
    }

    /// Return whether the child is currently running or paused.
    pub fn is_running(&self) -> bool {
        self.runtime.as_ref().map(|r| {
            matches!(r.state, RuntimeState::Running | RuntimeState::Paused)
        }).unwrap_or(false)
    }

    /// Send SIGSTOP to the child's process group.
    pub fn pause(&mut self) -> Result<(), crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        let pid = self.group_pid().ok_or(SandboxRuntimeError::NotRunning)?;
        let ret = unsafe { libc::killpg(pid, libc::SIGSTOP) };
        if ret < 0 {
            return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
        }
        self.rt_mut().state = RuntimeState::Paused;
        Ok(())
    }

    /// Send SIGCONT to the child's process group.
    pub fn resume(&mut self) -> Result<(), crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        let pid = self.group_pid().ok_or(SandboxRuntimeError::NotRunning)?;
        let ret = unsafe { libc::killpg(pid, libc::SIGCONT) };
        if ret < 0 {
            return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
        }
        self.rt_mut().state = RuntimeState::Running;
        Ok(())
    }

    /// Send SIGKILL to the child's process group.
    pub fn kill(&mut self) -> Result<(), crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        let pid = self.group_pid().ok_or(SandboxRuntimeError::NotRunning)?;
        let ret = unsafe { libc::killpg(pid, libc::SIGKILL) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(SandboxRuntimeError::Io(err).into());
            }
        }
        Ok(())
    }

    /// Set a callback invoked whenever a port bind is recorded.
    pub fn set_on_bind(&mut self, cb: impl Fn(&HashMap<u16, u16>) + Send + Sync + 'static) {
        // Ensure runtime exists so we have somewhere to store the callback.
        // In practice, set_on_bind is always called before spawn.
        let _ = self.ensure_runtime();
        self.rt_mut().on_bind = Some(Box::new(cb));
    }

    /// Return the current virtual-to-real port mappings.
    pub async fn port_mappings(&self) -> HashMap<u16, u16> {
        if let Some(ref rt) = self.runtime {
            if let Some(ref net) = rt.supervisor_network {
                let ns = net.lock().await;
                return ns.port_map.virtual_to_real.clone();
            }
        }
        HashMap::new()
    }

    /// N25/L2c: take the written-directory ledger (see [`crate::dirty::DirtyDirs`]).
    ///
    /// Returns `(directories, overflow)`; `overflow` means the sandbox touched
    /// more directories than the ledger remembers, so the caller must fall
    /// back to one whole-tree walk instead of trusting the list. Empty and
    /// `false` when the sandbox was never spawned or runs without a mediator
    /// that resolves paths (the pure shape has no path notifications at all).
    pub fn drain_dirty_dirs(&self) -> (Vec<std::path::PathBuf>, bool) {
        match self
            .runtime
            .as_ref()
            .and_then(|rt| rt.supervisor_dirty.as_ref())
        {
            Some(dirty) => dirty.drain(),
            None => (Vec::new(), false),
        }
    }

    /// Return observed resource peaks from the supervisor state.
    /// Returns `(peak_mem_used_bytes, peak_proc_count)`.
    pub async fn resource_peaks(&self) -> (u64, u32) {
        if let Some(res) = self.runtime.as_ref().and_then(|rt| rt.supervisor_resource.as_ref()) {
            let rs = res.lock().await;
            (rs.peak_mem_used, rs.peak_proc_count)
        } else {
            (0, 0)
        }
    }

    /// Return the live process-accounting snapshot from the supervisor.
    ///
    /// `live_watchers` is the number of registered, pidfd-watcher-backed
    /// processes still in the index; `drift` is `proc_count - live_watchers`.
    /// In argv-safety mode (where every counted fork child is birth-registered
    /// and released on pidfd exit) the two should agree while the sandbox is
    /// quiescent, so a persistent positive drift is the SL-8 orphan-leak alarm.
    /// In lazy mode registration coverage is partial, so the fields are
    /// diagnostic rather than exact (threads and never-notified children can
    /// legitimately differ).
    ///
    /// The drift is transiently negative during exit cleanup, which releases
    /// the `proc_count` slot before unregistering the watcher entry (see the
    /// [`ProcessStats::drift`] field docs); the instance stats surface
    /// ([`Sandbox::stats`]) exposes the same reconciler as
    /// `proc_count_vs_live`.
    pub async fn process_stats(&self) -> ProcessStats {
        if let Some(rt) = self.runtime.as_ref() {
            if let (Some(res), Some(procs)) = (
                rt.supervisor_resource.as_ref(),
                rt.supervisor_processes.as_ref(),
            ) {
                let rs = res.lock().await;
                let proc_count = rs.proc_count;
                let live_watchers = procs.len() as u32;
                let drift = proc_count as i64 - live_watchers as i64;
                return ProcessStats { proc_count, live_watchers, drift };
            }
        }
        ProcessStats { proc_count: 0, live_watchers: 0, drift: 0 }
    }

    /// Return the embedded session's M0 stats surface
    /// ([`SandboxInstance::stats`](crate::instance::SandboxInstance::stats)):
    /// the F1.4 process reconciliation (`proc_count_vs_live`), the M0
    /// single-child liveness (`children_live`), and the lifecycle phase
    /// (`instance_state`). `None` before the sandbox has been spawned.
    pub async fn stats(&self) -> Option<InstanceStats> {
        match self.runtime.as_ref() {
            Some(rt) => Some(rt.stats().await),
            None => None,
        }
    }

    /// The sandbox's DNS gateway address (only when wildcard-domain network
    /// rules made a gateway necessary). The one-shot session releases the
    /// gateway — and with it this address's `:53` listener — when `run`/
    /// `popen`/`spawn`'s wait tears the session down.
    pub fn dns_gateway_addr(&self) -> Option<std::net::Ipv4Addr> {
        self.runtime.as_ref().and_then(|rt| rt.dns_gateway_addr)
    }

    /// Wait for the child process to exit.
    ///
    /// One-shot session semantics (M0 lifecycle lift): the sandbox's runtime
    /// *is* a [`SandboxInstance`], and this wait is that instance's
    /// `wait_one_shot()` — wait for the child, then shut the session down
    /// (supervisor tasks, control directory, DNS gateway). That is what keeps
    /// `run`/`popen`/`spawn` one-shot with exactly the historical
    /// reclamation behaviour: `run`/`popen`/`spawn` all end in this wait.
    ///
    /// Dropping the returned future does not cost the captured output: the pipe
    /// drains belong to the instance, so a caller that cancels this `wait()`
    /// (a `timeout` or `select!` around it) and calls `wait()` again still gets
    /// what the child wrote. That holds wherever the cancellation lands —
    /// before the drains start, while the child is still running, or while the
    /// final join is blocked because a descendant is still holding the write
    /// end open past the child's own exit.
    pub async fn wait(&mut self) -> Result<crate::result::RunResult, crate::error::SandlockError> {
        self.rt_mut().wait_one_shot().await
    }

    /// Fork the sandboxed child and install policy (seccomp + notif
    /// supervisor + rlimits + landlock + COW + network/HTTP proxies).
    /// The child is parked between policy install and `execve`; call
    /// `start()` to release it. Stdout/stderr are captured for later
    /// retrieval via `wait()`.
    pub async fn create(&mut self, cmd: &[&str]) -> Result<(), crate::error::SandlockError> {
        self.do_create(cmd, true).await
    }

    /// Like `create` but inherits stdio (no capture).
    pub async fn create_interactive(&mut self, cmd: &[&str]) -> Result<(), crate::error::SandlockError> {
        self.do_create(cmd, false).await
    }

    /// `create_interactive`, but the child `execveat`s an already-open
    /// descriptor instead of resolving `cmd[0]` through its path space.
    ///
    /// `cmd` still supplies the process name and `argv[0]`. Used by checkpoint
    /// restore, whose stub is a host build artifact that a chroot root cannot
    /// name (`docs/chroot-workspace-exec.md` §11).
    pub async fn create_interactive_exec_fd(
        &mut self,
        cmd: &[&str],
        exec_fd: std::os::unix::io::RawFd,
    ) -> Result<(), crate::error::SandlockError> {
        self.ensure_runtime()?;
        self.rt_mut().exec_fd = Some(exec_fd);
        self.do_create(cmd, false).await
    }

    /// Release a previously `create()`d child to `execve` the configured
    /// command. Returns immediately; use `wait()` to collect the exit
    /// status when the child finishes.
    pub fn start(&mut self) -> Result<(), crate::error::SandlockError> {
        self.do_start()
    }

    /// Sugar for `create()` + `start()` that also blocks until the child
    /// has completed `execve()` and is executing user code. After this
    /// returns, operations that read user-code state (e.g. `checkpoint()`,
    /// `/proc/<pid>/exe`) observe the requested binary rather than the
    /// supervisor.
    pub async fn spawn(&mut self, cmd: &[&str]) -> Result<(), crate::error::SandlockError> {
        self.create(cmd).await?;
        self.start()?;
        self.wait_until_exec().await
    }

    /// Like `spawn` but inherits stdio (no capture).
    pub async fn spawn_interactive(&mut self, cmd: &[&str]) -> Result<(), crate::error::SandlockError> {
        self.create_interactive(cmd).await?;
        self.start()?;
        self.wait_until_exec().await
    }

    /// Spawn `cmd` with per-stream stdio wiring and return a live [`Process`].
    ///
    /// Unlike `run` (which buffers stdout/stderr into a `RunResult` only after
    /// the process exits), `popen` hands the caller the pipe end of every
    /// [`StdioMode::Piped`] stream so it can drive the process's stdio while it
    /// is alive — MCP/LSP servers, REPLs, any request/response protocol over
    /// stdio. The child is released to `execve` before this returns and runs
    /// under the full confinement. It is owned by this `Sandbox`: dropping the
    /// `Sandbox` (or calling [`Sandbox::kill`] / [`Process::kill`]) sends SIGKILL
    /// to its process group and reaps it.
    ///
    /// Note: the seccomp-notify supervisor runs as a task on the async runtime,
    /// and a confined child only makes progress while that supervisor is pumped.
    /// Do not block the runtime's executor on a piped stream — read/write the
    /// `Process` fds from a separate thread (or async IO), and run on a
    /// multi-threaded runtime. A blocking pipe read on a single-threaded runtime
    /// starves the supervisor and deadlocks the child.
    pub async fn popen(
        &mut self,
        cmd: &[&str],
        stdin: StdioMode,
        stdout: StdioMode,
        stderr: StdioMode,
    ) -> Result<Process<'_>, crate::error::SandlockError> {
        self.do_create_stdio(cmd, StdioSpec { stdin, stdout, stderr }).await?;
        // No wait_until_exec here: a streaming caller does not need the child to
        // have reached user code (a reader naturally blocks until bytes arrive),
        // and the exec poll would spuriously time out on a process that exits
        // before it is observed. `start` releases the child to execve.
        self.start()?;
        Ok(Process { sandbox: self })
    }

    /// Restore a checkpoint into a fresh, fully-sandboxed process.
    ///
    /// Reuses the normal create path to fork a child with the saved policy and
    /// the full notify stack in place, then `execve`s the freestanding
    /// restore-stub into it. The stub rebuilds the checkpoint's address space in
    /// an otherwise empty one and `rt_sigreturn`s into the saved register
    /// context; the supervisor writes the anonymous page contents in at the
    /// stub's READY barrier and releases it. Confinement is installed before the
    /// `execve`, so the restored program runs under the policy from its first
    /// instruction.
    ///
    /// The restored process ends up with an address space holding only the
    /// checkpoint image, a fresh kernel vDSO, and the stub's own few pages in a
    /// reserved window the checkpoint provably does not use: anything else the
    /// kernel set up for the stub's startup is unmapped before control passes to
    /// the restored program.
    ///
    /// The process comes up already sandboxed and running; like
    /// [`Sandbox::popen`], the returned [`Process`] is the handle to it (no
    /// `start()` step). Fds that could not be transparently recreated are
    /// recorded on this `Sandbox`; query them with [`Sandbox::restore_skipped`].
    /// x86_64, aarch64 and riscv64 restore engines supported. A checkpoint taken
    /// while the process was blocked in a restartable syscall (nanosleep, futex,
    /// read, ...) is rejected on aarch64 and riscv64, whose kernels expose no
    /// `orig_x0`/`orig_a0`: once a restart sentinel is visible the original
    /// first argument is not recoverable from the register file, so that resume
    /// cannot be made correct. (On aarch64 that is the fail-closed guard rather
    /// than the routine path: the kernel rewinds `pc` onto the `svc` and
    /// restores `x0` before the ptrace stop, so a blocked syscall normally
    /// resumes by re-executing it.)
    ///
    /// The kernel vDSO is relocated onto the checkpoint-recorded base during
    /// restore, so ordinary libc/glibc programs that call vDSO functions (e.g.
    /// `clock_gettime`) resume correctly. Assumes a same-kernel restore.
    ///
    /// On error the child may be left mid-restore; the caller should drop/kill
    /// the Sandbox (Drop reaps it).
    pub async fn restore_interactive(
        &mut self,
        cp: &crate::checkpoint::Checkpoint,
    ) -> Result<Process<'_>, crate::error::SandlockError> {
        self.restore_interactive_with(cp, RestoreLaunch::Exec).await
    }

    /// Restore without `execve`-ing the stub (prototype of the route in
    /// `docs/chroot-workspace-exec.md` §11, "B").
    ///
    /// Same engine, same blob, same protocol -- the only difference is delivery:
    /// the stub binary rides a memfd into the confined child, which maps it at
    /// `STUB_BASE` and jumps into it. Nothing is resolved by path and nothing is
    /// executed by path, so this works inside a chroot or real root and needs no
    /// Landlock grant for the stub. What it costs (a fork's dirty address space
    /// to sweep, a payload that must not allocate or lock) is documented on
    /// `crate::checkpoint::noexec`.
    pub async fn restore_interactive_noexec(
        &mut self,
        cp: &crate::checkpoint::Checkpoint,
    ) -> Result<Process<'_>, crate::error::SandlockError> {
        self.restore_interactive_with(cp, RestoreLaunch::InProcessNoExec).await
    }

    async fn restore_interactive_with(
        &mut self,
        cp: &crate::checkpoint::Checkpoint,
        launch: RestoreLaunch,
    ) -> Result<Process<'_>, crate::error::SandlockError> {
        use crate::checkpoint::{restore_blob, resume};
        use crate::error::SandboxRuntimeError;

        if cfg!(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ))) {
            return Err(SandboxRuntimeError::Child(
                "checkpoint restore is only implemented on x86_64, aarch64 and riscv64".into(),
            )
            .into());
        }

        let stub = resume::stub_path();
        if !stub.exists() {
            return Err(SandboxRuntimeError::Child(format!(
                "restore-stub was not built ({}); a C compiler is required to build sandlock \
                 with checkpoint restore",
                stub.display()
            ))
            .into());
        }

        // Resolve the confinement's chroot root and mounts so the plan can
        // translate the checkpoint's HOST-recorded mapping/fd paths into the
        // child's in-chroot view before the stub reopens them. Empty/None
        // without a chroot, leaving paths untranslated.
        let chroot_root = crate::chroot::resolve::resolve_chroot_root(self.chroot.as_deref())?;
        let mounts = crate::chroot::resolve::resolve_chroot_mounts(&self.fs_mount);
        // A chroot root -- emulated or real -- used to make this impossible: the
        // stub is a host build artifact and the exec route handed it to the child
        // by its host path, which no rootfs resolves. Measured 2026-09-23 on both
        // shapes: `execvp '/src/target/.../restore-stub': No such file or
        // directory`, then "restore stub never signalled READY within 10000ms:
        // exited with restore-stub code 127" -- and for a while the call was
        // refused up front instead (43cc62a), because that was true.
        //
        // It is not true any more: the stub goes in by descriptor
        // (`RestoreLaunch::Exec` below) and the ruleset grants that one host file
        // the right Landlock actually judges, so *both* chroot shapes restore --
        // pinned by `test_restore_resumes_inside_a_chroot_root`, which runs the
        // emulated and the real root. This paragraph is kept (corrected) because
        // it is the reason the delivery route looks the way it does.
        // The stub reopens the checkpoint's fds *inside* this sandbox, so the
        // plan has to know what this sandbox can reach (see `FdReach`).
        let reach = restore_blob::FdReach {
            readable: &self.fs_readable,
            writable: &self.fs_writable,
            mounts: &mounts,
        };
        let plan = restore_blob::plan(cp, chroot_root.as_deref(), &mounts, &reach)
            .map_err(SandboxRuntimeError::Child)?;

        let channel = resume::StubChannel::new(&plan.blob)
            .map_err(|e| SandboxRuntimeError::Child(format!("restore control channel: {e}")))?;

        match launch {
            RestoreLaunch::Exec => {
                // The stub is delivered by descriptor (`execveat(AT_EMPTY_PATH)`)
                // and the ruleset grants that one host file EXECUTE|READ_FILE --
                // Landlock judges a file by its real path whether or not an fd
                // named it (measured; docs/chroot-workspace-exec.md §11.6.1).
                // This is what makes a chroot root work: nothing resolves the
                // stub through the sandbox's path space, so neither the rootfs
                // nor the mediator has to carry it.
                let stub_path = stub.canonicalize().unwrap_or_else(|_| stub.clone());
                use std::os::unix::fs::OpenOptionsExt;
                let stub_fd = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                    .open(&stub_path)
                    .map_err(|e| {
                        SandboxRuntimeError::Child(format!(
                            "open the restore stub {}: {e}",
                            stub_path.display()
                        ))
                    })?;
                self.fs_readable_host = vec![stub_path];
                self.ensure_runtime()?;
                let mut fds = channel.extra_fds();
                fds.push((resume::STUB_EXEC_FD, stub_fd.as_raw_fd()));
                self.rt_mut().extra_fds = fds;
                let stub_s = stub.to_string_lossy().into_owned();
                self.create_interactive_exec_fd(&[stub_s.as_str()], resume::STUB_EXEC_FD)
                    .await?;
            }
            RestoreLaunch::InProcessNoExec => {
                // No path, no exec, no grant: the image goes in over a memfd and
                // the already-confined child installs it and jumps.
                let image = crate::checkpoint::noexec::memfd_with_file(&stub).map_err(|e| {
                    SandboxRuntimeError::Child(format!("restore stub image memfd: {e}"))
                })?;
                let mut fds = channel.extra_fds();
                fds.push((crate::checkpoint::noexec::STUB_IMAGE_FD, image.as_raw_fd()));
                self.create_with_in_child_main(
                    "restore-stub",
                    fds,
                    crate::checkpoint::noexec::install_and_jump_entry,
                )
                .await?;
                // Dropping `image` here is safe: the child holds its own dup of
                // the memfd (the launch dups every `extra_fds` entry).
                drop(image);
            }
        }
        let pid = self.pid().ok_or(SandboxRuntimeError::NotRunning)?;
        // Release the parked child to execve the stub. From here the stub runs
        // confined, and its openat calls flow through the notify supervisor,
        // which only makes progress while this runtime is pumped, hence the
        // spawn_blocking below rather than a blocking wait on the executor.
        self.start()?;

        let (plan, channel, result) = tokio::task::spawn_blocking(move || {
            let r = resume::finish_restore(pid, &channel, &plan);
            (plan, channel, r)
        })
        .await
        .map_err(|e| SandboxRuntimeError::Child(format!("restore join error: {e}")))?;
        drop(channel);
        result?;

        self.restore_skipped = plan.skipped;
        Ok(Process { sandbox: self })
    }

    /// Fds that the last [`Sandbox::restore_interactive`] on this sandbox could
    /// not transparently recreate (sockets, pipes, memfds, pseudo-filesystem
    /// paths); the restored process runs without them. Empty if this sandbox
    /// never restored a checkpoint or every fd was restored.
    pub fn restore_skipped(&self) -> &[crate::checkpoint::SkippedFd] {
        &self.restore_skipped
    }

    /// Wait for the child to finish `execve`. Detected by `/proc/<pid>/exe`
    /// no longer matching `/proc/self/exe` (before execve the child still
    /// shares the supervisor's binary). The kernel offers no direct event
    /// for execve completion, so this polls every 1ms with a 5s ceiling.
    async fn wait_until_exec(&self) -> Result<(), crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        let pid = self.pid().ok_or(SandboxRuntimeError::NotRunning)?;
        let Some(our_exe) = std::fs::read_link("/proc/self/exe").ok() else {
            return Ok(());
        };
        let child_link = format!("/proc/{}/exe", pid);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Ok(child_exe) = std::fs::read_link(&child_link) {
                if child_exe != our_exe {
                    return Ok(());
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(SandboxRuntimeError::Child(
                    "child did not exec() within 5s".into(),
                ).into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }

    /// Create with explicit stdin/stdout/stderr fd redirection. Child is
    /// parked after policy install; call `start()` to release.
    #[doc(hidden)]
    pub async fn create_with_io(
        &mut self,
        cmd: &[&str],
        stdin_fd: Option<std::os::unix::io::RawFd>,
        stdout_fd: Option<std::os::unix::io::RawFd>,
        stderr_fd: Option<std::os::unix::io::RawFd>,
    ) -> Result<(), crate::error::SandlockError> {
        self.ensure_runtime()?;
        self.rt_mut().io_overrides = Some((stdin_fd, stdout_fd, stderr_fd));
        self.do_create(cmd, false).await
    }

    /// Like `create_with_io` but also maps extra fds into the child.
    #[doc(hidden)]
    pub async fn create_with_gather_io(
        &mut self,
        cmd: &[&str],
        stdin_fd: Option<std::os::unix::io::RawFd>,
        stdout_fd: Option<std::os::unix::io::RawFd>,
        stderr_fd: Option<std::os::unix::io::RawFd>,
        extra_fds: Vec<(i32, i32)>,
    ) -> Result<(), crate::error::SandlockError> {
        self.ensure_runtime()?;
        self.rt_mut().io_overrides = Some((stdin_fd, stdout_fd, stderr_fd));
        self.rt_mut().extra_fds = extra_fds;
        self.do_create(cmd, false).await
    }

    /// Create a confined child that, instead of `execve`-ing a workload, runs
    /// `entrypoint` in-process after confinement is installed. The child is a
    /// `fork()` of this process, so `entrypoint`'s code is already mapped; no
    /// image is exec'd, so Landlock has nothing to authorize for the child's own
    /// startup. `extra_fds` maps caller fds onto fixed fd numbers in the child
    /// (e.g. the control channel). Used to run the OCI in-sandbox PID-1.
    ///
    /// `name` is not exec'd; it sets the child's process name
    /// (`/proc/<pid>/comm`). `start()` releases the parked child to run
    /// `entrypoint`.
    pub async fn create_with_in_child_main(
        &mut self,
        name: &str,
        extra_fds: Vec<(i32, i32)>,
        entrypoint: fn(),
    ) -> Result<(), crate::error::SandlockError> {
        self.ensure_runtime()?;
        self.in_child_main = Some(entrypoint);
        self.rt_mut().extra_fds = extra_fds;
        self.do_create(&[name], false).await
    }

    /// Freeze the sandbox: hold fork notifications + SIGSTOP the process group.
    pub(crate) async fn freeze(&self) -> Result<(), crate::error::SandlockError> {
        use crate::error::{SandboxRuntimeError, SandlockError};
        let rt = self.runtime.as_ref().ok_or(SandlockError::Runtime(SandboxRuntimeError::NotRunning))?;
        let pid = rt.leader_pid.or(rt.child_pid)
            .ok_or(SandlockError::Runtime(SandboxRuntimeError::NotRunning))?;
        if let Some(ref resource) = rt.supervisor_resource {
            let mut rs = resource.lock().await;
            rs.hold_forks = true;
        }
        unsafe { libc::killpg(pid, libc::SIGSTOP); }
        Ok(())
    }

    /// Thaw the sandbox: release held fork notifications + SIGCONT.
    pub(crate) async fn thaw(&self) -> Result<(), crate::error::SandlockError> {
        use crate::error::{SandboxRuntimeError, SandlockError};
        let rt = self.runtime.as_ref().ok_or(SandlockError::Runtime(SandboxRuntimeError::NotRunning))?;
        let pid = rt.leader_pid.or(rt.child_pid)
            .ok_or(SandlockError::Runtime(SandboxRuntimeError::NotRunning))?;
        if let Some(ref resource) = rt.supervisor_resource {
            // Release, do not drop: each held id is a sandboxed `fork()` parked
            // in the kernel (see `resource::release_held_forks`).
            crate::resource::release_held_forks(resource).await;
        }
        unsafe { libc::killpg(pid, libc::SIGCONT); }
        Ok(())
    }

    /// Capture a checkpoint of the running sandbox.
    pub async fn checkpoint(&self) -> Result<crate::checkpoint::Checkpoint, crate::error::SandlockError> {
        use crate::error::{SandboxRuntimeError, SandlockError};
        let pid = self.runtime.as_ref()
            .and_then(|rt| rt.leader_pid.or(rt.child_pid))
            .ok_or(SandlockError::Runtime(SandboxRuntimeError::NotRunning))?;
        self.checkpoint_pid(pid).await
    }

    /// Capture a checkpoint targeting a specific pid instead of the sandbox's
    /// direct child. The target must be a fork-descendant confined by the same
    /// policy (e.g. the workload spawned by sandlock-init). `target_pid` must
    /// be positive.
    pub async fn checkpoint_pid(&self, target_pid: i32) -> Result<crate::checkpoint::Checkpoint, crate::error::SandlockError> {
        use crate::error::{SandboxRuntimeError, SandlockError};
        if target_pid <= 0 {
            return Err(SandlockError::Runtime(SandboxRuntimeError::NotRunning));
        }
        self.freeze().await?;
        let cp = crate::checkpoint::capture(target_pid, self);
        self.thaw().await?;
        cp
    }

    // ================================================================
    // One-shot / lifecycle instance API
    // ================================================================

    /// One-shot: spawn, wait, and return the result. Stdout and stderr are
    /// captured. This is the primary way to run a sandboxed command:
    ///
    /// ```ignore
    /// let mut sandbox = Sandbox::builder()
    ///     .fs_read("/usr")
    ///     .name("my-sandbox")
    ///     .build()?;
    /// let result = sandbox.run(&["echo", "hello"]).await?;
    /// ```
    pub async fn run(
        &mut self,
        cmd: &[&str],
    ) -> Result<crate::result::RunResult, crate::error::SandlockError> {
        self.do_create(cmd, true).await?;
        self.do_start()?;
        self.wait().await
    }

    /// Run with inherited stdio (interactive mode).
    pub async fn run_interactive(
        &mut self,
        cmd: &[&str],
    ) -> Result<crate::result::RunResult, crate::error::SandlockError> {
        self.do_create(cmd, false).await?;
        self.do_start()?;
        self.wait().await
    }

    /// One-shot run with user-supplied syscall handlers.
    pub async fn run_with_handlers<I, S, H>(
        &mut self,
        cmd: &[&str],
        handlers: I,
    ) -> Result<crate::result::RunResult, crate::error::SandlockError>
    where
        I: IntoIterator<Item = (S, H)>,
        S: TryInto<crate::seccomp::syscall::Syscall, Error = crate::seccomp::syscall::SyscallError>,
        H: crate::seccomp::dispatch::Handler,
    {
        let pending = sandbox_collect_handlers(handlers, self)?;
        self.ensure_runtime()?;
        self.rt_mut().handlers = pending;
        trace_step("run: do_create");
        self.do_create(cmd, true).await?;
        trace_step("run: do_start");
        self.do_start()?;
        trace_step("run: wait");
        let result = self.wait().await;
        trace_step("run: wait returned");
        result
    }

    /// Interactive-stdio counterpart of `run_with_handlers`.
    pub async fn run_interactive_with_handlers<I, S, H>(
        &mut self,
        cmd: &[&str],
        handlers: I,
    ) -> Result<crate::result::RunResult, crate::error::SandlockError>
    where
        I: IntoIterator<Item = (S, H)>,
        S: TryInto<crate::seccomp::syscall::Syscall, Error = crate::seccomp::syscall::SyscallError>,
        H: crate::seccomp::dispatch::Handler,
    {
        let pending = sandbox_collect_handlers(handlers, self)?;
        self.ensure_runtime()?;
        self.rt_mut().handlers = pending;
        self.do_create(cmd, false).await?;
        self.do_start()?;
        self.wait().await
    }

    /// Dry-run: create, start, wait, collect filesystem changes, then abort.
    ///
    /// The branch action is forced to `Abort`, not `Keep`: a dry run must never
    /// merge, and must not leave its upper on disk either — the changes are read
    /// out of the branch here and returned, so nothing needs preserving. `Keep`
    /// would additionally ask the branch to survive an abandoned run (`?` on
    /// create/wait below), which for a dry run is a pure leak.
    pub async fn dry_run(
        &mut self,
        cmd: &[&str],
    ) -> Result<crate::dry_run::DryRunResult, crate::error::SandlockError> {
        self.on_exit = BranchAction::Abort;
        self.on_error = BranchAction::Abort;
        self.do_create(cmd, true).await?;
        self.do_start()?;
        let run_result = self.wait().await?;
        let changes = self.collect_changes().await;
        self.do_abort().await;
        Ok(crate::dry_run::DryRunResult { run_result, changes })
    }

    /// Dry-run with inherited stdio. Same branch handling as [`Self::dry_run`].
    pub async fn dry_run_interactive(
        &mut self,
        cmd: &[&str],
    ) -> Result<crate::dry_run::DryRunResult, crate::error::SandlockError> {
        self.on_exit = BranchAction::Abort;
        self.on_error = BranchAction::Abort;
        self.do_create(cmd, false).await?;
        self.do_start()?;
        let run_result = self.wait().await?;
        let changes = self.collect_changes().await;
        self.do_abort().await;
        Ok(crate::dry_run::DryRunResult { run_result, changes })
    }

    /// Create N COW clones of this sandbox.
    ///
    /// `fork()` requires `init_fn` and `work_fn` to be set on the sandbox (via
    /// `SandboxBuilder::init_fn` / `work_fn`, or `Sandbox::with_init_fn` /
    /// `with_work_fn`). Returns an error if either is missing.
    pub async fn fork(&mut self, n: u32) -> Result<Vec<Sandbox>, crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        use std::os::fd::{FromRawFd, OwnedFd};

        // Pull init_fn / work_fn directly from self (they live on Sandbox, not
        // Runtime, so ensure_runtime hasn't consumed them yet).
        let init_fn = self.init_fn.take()
            .ok_or_else(|| SandboxRuntimeError::Child("fork() requires init_fn and work_fn — use SandboxBuilder::init_fn() / work_fn() or Sandbox::with_init_fn() / with_work_fn()".into()))?;
        let work_fn = self.work_fn.take()
            .ok_or_else(|| SandboxRuntimeError::Child("fork() requires init_fn and work_fn — use SandboxBuilder::init_fn() / work_fn() or Sandbox::with_init_fn() / with_work_fn()".into()))?;

        // Initialize the runtime block so we can record child PID / state below.
        self.ensure_runtime()?;

        let sandbox_cfg = self.clone(); // config only, no runtime

        let mut ctrl_fds = [0i32; 2];
        if unsafe { libc::pipe2(ctrl_fds.as_mut_ptr(), 0) } < 0 {
            return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
        }
        let ctrl_parent = unsafe { OwnedFd::from_raw_fd(ctrl_fds[0]) };
        let ctrl_child_fd = ctrl_fds[1];

        let mut pipe_read_ends: Vec<OwnedFd> = Vec::with_capacity(n as usize);
        let mut pipe_write_fds: Vec<i32> = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let mut pfds = [0i32; 2];
            if unsafe { libc::pipe(pfds.as_mut_ptr()) } >= 0 {
                pipe_read_ends.push(unsafe { OwnedFd::from_raw_fd(pfds[0]) });
                pipe_write_fds.push(pfds[1]);
            } else {
                pipe_write_fds.push(-1);
            }
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe { libc::close(ctrl_child_fd) };
            return Err(SandboxRuntimeError::Fork(std::io::Error::last_os_error()).into());
        }

        if pid == 0 {
            drop(ctrl_parent);
            unsafe { libc::setpgid(0, 0) };
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

            let _ = crate::landlock::confine(&sandbox_cfg);

            let deny = crate::context::blocklist_syscall_numbers(&sandbox_cfg);
            let args = crate::context::arg_filters(&sandbox_cfg);
            let filter = match crate::seccomp::bpf::assemble_filter(&[], &deny, &args) {
                Ok(f) => f,
                Err(_) => unsafe { libc::_exit(1) },
            };
            let _ = crate::seccomp::bpf::install_deny_filter(&filter);

            init_fn();

            drop(pipe_read_ends);
            crate::fork::fork_ready_loop_fn(ctrl_child_fd, n, &*work_fn, &pipe_write_fds);
            unsafe { libc::_exit(0) };
        }

        unsafe { libc::close(ctrl_child_fd) };
        for wfd in &pipe_write_fds {
            if *wfd >= 0 { unsafe { libc::close(*wfd) }; }
        }
        self.rt_mut().child_pid = Some(pid);
        self.rt_mut().state = RuntimeState::Running;

        let ctrl_fd = ctrl_parent.as_raw_fd();
        let mut pid_buf = vec![0u8; n as usize * 4];
        sandbox_read_exact(ctrl_fd, &mut pid_buf);

        let clone_pids: Vec<i32> = pid_buf.chunks(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap_or([0; 4])) as i32)
            .collect();
        let live_count = clone_pids.iter().filter(|&&p| p > 0).count();

        let mut code_buf = vec![0u8; live_count * 4];
        sandbox_read_exact(ctrl_fd, &mut code_buf);
        self.rt_mut().ctrl_fd = Some(ctrl_parent);

        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        let mut code_idx = 0;
        let mut clones = Vec::with_capacity(live_count);
        let mut pipe_iter = pipe_read_ends.into_iter();

        let rt_name = self.rt().name.clone();
        for &clone_pid in &clone_pids {
            let pipe = pipe_iter.next();
            if clone_pid <= 0 { continue; }

            let code = i32::from_be_bytes(
                code_buf[code_idx * 4..(code_idx + 1) * 4].try_into().unwrap_or([0; 4])
            );
            code_idx += 1;

            let mut clone_sb = sandbox_cfg.clone();
            let clone_name = format!("{}-fork-{}", rt_name, clone_pid);
            clone_sb.runtime = Some(Box::new(SandboxInstance {
                name: clone_name,
                state: RuntimeState::Stopped(if code == 0 {
                    crate::result::ExitStatus::Code(0)
                } else if code > 0 {
                    crate::result::ExitStatus::Code(code)
                } else {
                    crate::result::ExitStatus::Killed
                }),
                child_pid: Some(clone_pid),
                leader_pid: None,
                pidfd: None,
                notif_handle: None,
                policy_fn_worker: None,
                throttle_handle: None,
                loadavg_handle: None,
                _stdout_read: None,
                _stderr_read: None,
                stdout_drain: None,
                stderr_drain: None,
                _stdin_write: None,
                seccomp_cow: None,
                supervisor_resource: None,
                supervisor_processes: None,
                supervisor_cow: None,
                supervisor_dirty: None,
                supervisor_write_fds: None,
                supervisor_network: None,
                ctrl_fd: None,
                stdout_pipe: pipe,
                io_overrides: None,
                extra_fds: Vec::new(),
                exec_fd: None,
                http_acl_handle: None,
                dns_gateway_handle: None,
                dns_gateway_addr: None,
                on_bind: None,
                handlers: Vec::new(),
                ready_w: None,
                shared_cow: None,
                tty_foreground_taken: false,
                restore_skipped: Vec::new(),
                control_handle: None,
                control_dir: None,
                phase: crate::instance::InstancePhase::Live,
                on_exit: sandbox_cfg.on_exit.clone(),
                on_error: sandbox_cfg.on_error.clone(),
                exec_ceiling: None,
                exec_session: None,
                policy_image: None,
                // A clone of a `Sandbox` is not an exec-capable session, so it
                // never arms the stub grant itself (`restore_into_session`
                // refuses it as "not exec-capable" before this is read).
                restore_stub_grant: None,
                pid_ns_map: None,
                lifetime: crate::instance::InstanceLifetime::default(),
                launched_at: std::time::Instant::now(),
                idle_since: None,
                expired: None,
            }));
            clones.push(clone_sb);
        }

        Ok(clones)
    }

    /// Reduce: wait for all clones, then run a reducer command.
    pub async fn reduce(
        &self,
        cmd: &[&str],
        clones: &mut [Sandbox],
    ) -> Result<crate::result::RunResult, crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;

        let mut combined = Vec::new();
        for clone in clones.iter_mut() {
            if let Some(ref mut rt) = clone.runtime {
                if let Some(pipe) = rt.stdout_pipe.take() {
                    combined.extend_from_slice(&sandbox_read_fd_to_end(pipe));
                }
            }
        }

        let mut stdin_fds = [0i32; 2];
        if unsafe { libc::pipe2(stdin_fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
        }

        let write_fd = stdin_fds[1];
        let write_handle = tokio::task::spawn_blocking(move || {
            unsafe {
                libc::write(write_fd, combined.as_ptr() as *const _, combined.len());
                libc::close(write_fd);
            }
        });

        let base_name = self.instance_name()
            .unwrap_or("sandbox")
            .to_owned();
        let reducer_name = base_name + "-reduce";
        let mut reducer = self.clone().with_name(reducer_name);
        reducer.ensure_runtime()?;
        reducer.rt_mut().io_overrides = Some((Some(stdin_fds[0]), None, None));
        reducer.do_create(cmd, true).await?;
        reducer.do_start()?;
        unsafe { libc::close(stdin_fds[0]) };

        let _ = write_handle.await;
        reducer.wait().await
    }

    /// Whether named (pathname) `AF_UNIX` connects should be gated by the
    /// fs-write grants (`has_unix_fs_gate`). Active whenever the sandbox
    /// confines the filesystem; Landlock cannot gate unix-socket connect, so
    /// the seccomp layer does. Single source of truth for both the
    /// `NotifPolicy` flag and the `notif_syscalls` BPF set.
    pub(crate) fn has_unix_fs_gate(&self) -> bool {
        !self.fs_readable.is_empty() || !self.fs_writable.is_empty()
    }

    /// Lazily initialize the session instance block.
    ///
    /// Called by lifecycle methods (`spawn`, `run`, `fork`, etc.) on first
    /// use. Validates and resolves the sandbox name. Idempotent: returns
    /// immediately if runtime is already set.
    pub(crate) fn ensure_runtime(&mut self) -> Result<(), crate::error::SandlockError> {
        if self.runtime.is_some() {
            return Ok(());
        }
        let name = sandbox_resolve_name(self.name.as_deref())?;
        self.runtime = Some(Box::new(SandboxInstance {
            name,
            state: RuntimeState::Created,
            child_pid: None,
            leader_pid: None,
            pidfd: None,
            notif_handle: None,
            policy_fn_worker: None,
            throttle_handle: None,
            loadavg_handle: None,
            control_handle: None,
            control_dir: None,
            _stdout_read: None,
            _stderr_read: None,
            stdout_drain: None,
            stderr_drain: None,
            _stdin_write: None,
            seccomp_cow: None,
            supervisor_resource: None,
            supervisor_processes: None,
            supervisor_cow: None,
            supervisor_dirty: None,
            supervisor_write_fds: None,
            supervisor_network: None,
            ctrl_fd: None,
            stdout_pipe: None,
            io_overrides: None,
            extra_fds: Vec::new(),
            exec_fd: None,
            http_acl_handle: None,
            dns_gateway_handle: None,
            dns_gateway_addr: None,
            on_bind: None,
            handlers: Vec::new(),
            ready_w: None,
            shared_cow: None,
            tty_foreground_taken: false,
            restore_skipped: Vec::new(),
            phase: crate::instance::InstancePhase::Live,
            on_exit: self.on_exit.clone(),
            on_error: self.on_error.clone(),
            exec_ceiling: None,
            exec_session: None,
            policy_image: None,
            restore_stub_grant: None,
            pid_ns_map: None,
            lifetime: crate::instance::InstanceLifetime::default(),
            launched_at: std::time::Instant::now(),
            idle_since: None,
            expired: None,
        }));
        Ok(())
    }

    /// Override the confined child's stdio with caller-supplied fds (used by
    /// [`SandboxInstance::launch_exec`](crate::instance::SandboxInstance::launch_exec)
    /// to wire `sandlock-init` — and with it the RunMain workload — to
    /// /dev/null). Crate-internal setter: `io_overrides` is a private runtime
    /// field.
    pub(crate) fn set_child_stdio_override(
        &mut self,
        stdin: Option<i32>,
        stdout: Option<i32>,
        stderr: Option<i32>,
    ) {
        self.rt_mut().io_overrides = Some((stdin, stdout, stderr));
    }

    /// Attach a transaction's shared COW branch to this sandbox before `create`.
    /// The stage reuses the shared upper instead of building its own, and leaves
    /// commit/abort to the transaction coordinator. Internal — used only by
    /// [`Transaction`](crate::transaction::Transaction).
    pub(crate) fn set_shared_cow(&mut self, shared: SharedCow) -> Result<(), crate::error::SandlockError> {
        self.ensure_runtime()?;
        self.rt_mut().shared_cow = Some(shared);
        Ok(())
    }

    // ================================================================
    // Internal: collect_changes / do_abort
    // ================================================================

    async fn collect_changes(&self) -> Vec<crate::dry_run::Change> {
        if let Some(ref rt) = self.runtime {
            if let Some(ref cow) = rt.seccomp_cow {
                return cow.changes().unwrap_or_default();
            }
        }
        Vec::new()
    }

    async fn do_abort(&mut self) {
        if let Some(ref mut rt) = self.runtime {
            if let Some(ref mut cow) = rt.seccomp_cow {
                let _ = cow.abort();
            }
        }
    }

    // ================================================================
    // Internal: do_create (fork + policy install; child parks at the
    // ready_r read, awaiting do_start to release it to execve).
    // ================================================================

    /// Thin compatibility wrapper: `capture` selects between the capture stdio
    /// spec (stdin inherited, stdout/stderr piped-and-drained) and full inherit.
    pub(crate) async fn do_create(
        &mut self,
        cmd: &[&str],
        capture: bool,
    ) -> Result<(), crate::error::SandlockError> {
        let stdio = if capture { StdioSpec::capture() } else { StdioSpec::inherit() };
        self.do_create_stdio(cmd, stdio).await
    }

    async fn do_create_stdio(&mut self, cmd: &[&str], stdio: StdioSpec) -> Result<(), crate::error::SandlockError> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
        use crate::error::SandboxRuntimeError;
        use crate::context::{PipePair, read_u32_fd};
        use crate::network;
        use crate::seccomp::ctx::SupervisorCtx;
        use crate::seccomp::notif::{self, NotifPolicy};
        use crate::seccomp::state::{ChrootState, CowState, NetworkState, PolicyFnState, ProcfsState, ResourceState, TimeRandomState};
        use crate::sys::syscall;
        use std::time::Duration;

        self.ensure_runtime()?;

        if !matches!(self.rt().state, RuntimeState::Created) {
            return Err(SandboxRuntimeError::Child("sandbox already spawned".into()).into());
        }

        if cmd.is_empty() {
            return Err(SandboxRuntimeError::Child("empty command".into()).into());
        }

        // N14 S5 (2026-10-04): the **emulated root is retired**. A `chroot`
        // root without `real_root` used to be served by translating every path
        // the mediator saw (`chroot/dispatch.rs`); that emulation is gone, so
        // this combination has no implementation left. Refusing here -- before
        // any fork or confinement work -- is the only honest answer: letting it
        // through would run every workload verb in a child whose kernel root is
        // the host's, with nothing left to translate it.
        //
        // Every creation path reaches this function (the FFI clones the policy
        // straight into the Sandbox, and `sandlock-supervise` builds one from
        // the policy document), which is why the check lives here rather than
        // in `validate()` alone.
        if self.chroot.is_some() && !self.real_root {
            return Err(SandboxRuntimeError::Child(
                "a chroot root without real_root is refused: the emulated root is retired \
                 (N14 S5) and the real root is the only shape. Set real_root (CLI \
                 --real-root, FFI sandlock_sandbox_builder_real_root, policy \
                 \"real_root\": true)."
                    .into(),
            )
            .into());
        }

        // fd_inject_connect is a seccomp-supervisor feature: the supervisor
        // performs the host connect and ADDFD injection on its side. With
        // no_supervisor there is no listener to intercept connect(), so the
        // switch would be silently ignored — refuse the combination instead
        // of running with a quietly weaker network path.
        if self.fd_inject_connect && self.no_supervisor {
            return Err(SandboxRuntimeError::Child(
                "fd_inject_connect requires the seccomp supervisor and is \
                 incompatible with no_supervisor=true"
                    .into(),
            )
            .into());
        }

        // Resolve the chroot root eagerly, before any fork or confinement work:
        // a configured-but-missing chroot must be a hard error, never a silent
        // drop to "no confinement".
        let chroot_root = crate::chroot::resolve::resolve_chroot_root(self.chroot.as_deref())?;

        // Each --http-inject-ca target must exist in the sandbox's view, or the
        // CA cannot be spliced into it and TLS interception silently fails. A
        // configured-but-missing trust bundle is a hard error, resolved through
        // --fs-mount and chroot so the check matches the workload's view.
        if !self.http_inject_ca.is_empty() {
            let mounts = crate::chroot::resolve::resolve_chroot_mounts(&self.fs_mount);
            for p in &self.http_inject_ca {
                let host = resolve_sandbox_path_to_host(p, chroot_root.as_deref(), &mounts);
                if !host.exists() {
                    return Err(SandboxRuntimeError::Child(format!(
                        "--http-inject-ca {:?} not found in the sandbox view (resolved to {:?}); \
                         the CA cannot be injected into it. Point it at the trust bundle the \
                         workload actually reads (e.g. /etc/ssl/certs/ca-certificates.crt, or \
                         certifi's cacert.pem).",
                        p, host
                    ))
                    .into());
                }
            }
        }

        let c_cmd: Vec<CString> = cmd
            .iter()
            .map(|s| CString::new(*s).map_err(|_| SandboxRuntimeError::Child("invalid command string".into())))
            .collect::<Result<Vec<_>, _>>()?;

        let no_supervisor = self.no_supervisor;

        let pipes = PipePair::new().map_err(SandboxRuntimeError::Io)?;

        let resolved_net_allow = network::resolve_net_allow(&self.net_allow)
            .await
            .map_err(SandboxRuntimeError::Io)?;
        // Wildcard-domain rules are served by a per-sandbox DNS gateway on
        // `<gateway>:53` (resolv.conf cannot express a port, so each sandbox
        // gets its own 127.0.1.x loopback address). Under `net_isolation`
        // (S2.3) the gateway binds INSIDE the sandbox netns: the address is
        // allocated here, handed to the child through the dns pipe before
        // forking, and the child binds `<addr>:53` in its own netns — it is
        // root inside its user namespace, so CAP_NET_BIND_SERVICE applies and
        // the host `ip_unprivileged_port_start` sysctl is not involved — then
        // reports the socket back for the supervisor to serve (see the
        // gateway section below). The default shared-netns path is unchanged
        // (`net_isolation` defaults false): the parent binds the gateway in
        // the shared netns as before.
        let wildcard_suffixes: Vec<(String, crate::seccomp::notif::PortAllow)> =
            resolved_net_allow
                .tcp
                .wildcard_domains
                .iter()
                .chain(resolved_net_allow.udp.wildcard_domains.iter())
                .cloned()
                .collect();
        let need_gateway = !wildcard_suffixes.is_empty();
        let netns_gateway_ip: Option<std::net::Ipv4Addr> = if self.net_isolation {
            let ip = if need_gateway {
                Some(crate::network::dns_synth::allocate_gateway_addr().ok_or_else(|| {
                    SandboxRuntimeError::Child(
                        "per-sandbox DNS gateway pool exhausted (127.0.1.0/24)".into(),
                    )
                })?)
            } else {
                None
            };
            // 0.0.0.0 signals "no wildcard gateway requested" to the child.
            let encoded = ip.map(u32::from).unwrap_or(0);
            crate::context::write_u32_fd(pipes.dns_w.as_raw_fd(), encoded).map_err(|e| {
                SandboxRuntimeError::Child(format!("write DNS gateway address to child: {}", e))
            })?;
            ip
        } else {
            None
        };
        // In chroot/image mode, seed the synthetic /etc/hosts from the
        // rootfs's own file so entries baked into the image (private
        // registries, internal hostnames, etc.) survive virtualization.
        // Without a chroot, the helper returns the fixed loopback base.
        // Either way, concrete-host rules from `net_allow` are appended
        // on top.
        let virtual_etc_hosts = network::compose_virtual_etc_hosts(
            self.chroot.as_deref(),
            &resolved_net_allow.concrete_host_entries,
        );

        let mut ca_inject_pem: Option<std::sync::Arc<Vec<u8>>> = None;
        let http_acl_active = !self.http_allow.is_empty()
            || !self.http_deny.is_empty()
            || self.http_log_fn.is_some();
        let mut ca_cert_pem: Option<String> = None;
        let mut ca_key_pem: Option<String> = None;
        if http_acl_active {
            // Generate an ephemeral CA when injection is requested without BYO.
            let generate = !self.http_inject_ca.is_empty();
            let ca_material = crate::transparent_proxy::resolve_ca(
                self.http_ca.as_deref(),
                self.http_key.as_deref(),
                generate,
            )
            .map_err(SandboxRuntimeError::Io)?;

            // Export the public cert if requested.
            if let (Some(out), Some(cm)) = (self.http_ca_out.as_deref(), ca_material.as_ref()) {
                std::fs::write(out, cm.cert_pem.as_bytes()).map_err(SandboxRuntimeError::Io)?;
            }

            // Keep the public cert for trust injection (only when paths declared).
            if !self.http_inject_ca.is_empty() {
                if let Some(cm) = ca_material.as_ref() {
                    ca_inject_pem = Some(std::sync::Arc::new(cm.cert_pem.clone().into_bytes()));
                }
            }

            if let Some(cm) = ca_material.as_ref() {
                ca_cert_pem = Some(cm.cert_pem.clone());
                ca_key_pem = Some(cm.key_pem.clone());
            }
        }

        // Seccomp COW: create the branch before fork so the child's Landlock
        // ruleset can include the upper layer. Binaries created inside the
        // workdir live in the upper dir, and Landlock checks EXECUTE on the
        // file's real path at execve time — so the upper dir must be granted
        // read+execute (READ_ACCESS) or `./created-binary` fails with EACCES.
        // A transactional-pipeline stage reuses one shared upper across stages;
        // it must not build its own branch. Grant Landlock read+exec on the
        // shared upper so a binary created in the workdir stays executable.
        let shared_cow = self.rt().shared_cow.clone();
        let seccomp_cow_branch = if let Some(ref shared) = shared_cow {
            self.fs_readable.push(shared.upper_dir.clone());
            self.cow_upper = Some(shared.upper_dir.clone());
            None
        } else if !no_supervisor && self.workdir.is_some() {
            let workdir = self.workdir.as_ref().unwrap().clone();
            let storage = self.fs_storage.clone();
            let max_disk = self.max_disk.map(|b| b.0).unwrap_or(0);
            match crate::cow::seccomp::SeccompCowBranch::create(&workdir, storage.as_deref(), max_disk) {
                Ok(mut branch) => {
                    // `Keep` must survive a sandbox that is never `wait()`ed:
                    // the branch only reaches `Sandbox`'s own disposition after
                    // a completed `wait()`, and the branch's `Drop` would
                    // otherwise reclaim the upper the caller asked to keep.
                    // Commit and Abort are NOT carried over that way — an
                    // abandoned run has no exit status and merging its writes
                    // is not something it can ask for, so those keep the
                    // reclaiming default. With no exit status there is also no
                    // choice between the two actions, so either one asking for
                    // `Keep` preserves.
                    branch.set_keep_if_abandoned(
                        self.on_exit == BranchAction::Keep || self.on_error == BranchAction::Keep,
                    );
                    self.fs_readable.push(branch.upper_dir().to_path_buf());
                    self.cow_upper = Some(branch.upper_dir().to_path_buf());
                    Some(branch)
                }
                Err(e) => {
                    eprintln!("sandlock: seccomp COW branch creation failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let handler_syscalls: Vec<i64> = self.rt().handlers.iter().map(|(nr, _)| *nr).collect();
        let resolved_sandbox_name = self.rt().name.clone();
        let resolved = crate::resolved::ResolvedSandbox::from_sandbox(
            self,
            Some(resolved_sandbox_name.as_str()),
            &handler_syscalls,
        );

        // Per-stream stdio wiring. Each Piped stream gets a CLOEXEC pipe whose
        // parent-side end we keep: the caller writes the child's stdin and reads
        // its stdout/stderr (see `popen` / `Process`). `pipe2` returns
        // (read=fds[0], write=fds[1]); for stdin the child reads, so the parent
        // keeps the write end, and vice-versa for stdout/stderr.
        let stdin_p = if stdio.stdin == StdioMode::Piped {
            Some(make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?)
        } else {
            None
        };
        let stdout_p = if stdio.stdout == StdioMode::Piped {
            Some(make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?)
        } else {
            None
        };
        let stderr_p = if stdio.stderr == StdioMode::Piped {
            Some(make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?)
        } else {
            None
        };

        // Capture our PID before fork so the child can detect parent death
        // without assuming PID 1 is always init (wrong in containers).
        let parent_pid = unsafe { libc::getpid() };

        // Interactive (fully inherited) stdio on a terminal: the child will
        // take the tty foreground group, and this process must take it back
        // once the child is reaped.
        let foreground = stdio.all_inherit();
        let tty_foreground_taken = foreground && unsafe { libc::isatty(0) } == 1;

        // User-namespace map handshake pipes (privileged `--user` remap only).
        //
        // A `--user` remap to a *different* host identity requires the parent
        // to write the child's uid/gid maps: `unshare(CLONE_NEWUSER)` strips
        // the child's capabilities in the parent user namespace, so a child
        // can only ever map its own euid — the single-entry map `0 -> host_uid`
        // needs the parent to hold CAP_SETUID/CAP_SETGID there (euid 0, or a
        // non-root euid with effective CAP_SETUID/CAP_SETGID — route-B ③
        // file-cap launcher, F14).  The pipes exist exactly when `RunAs`
        // differs from our own identity and we are privileged.
        let real_uid = unsafe { libc::getuid() };
        let real_gid = unsafe { libc::getgid() };
        // F14: "can perform a privileged cross-uid remap" is a capability
        // question, not an euid question. euid 0 qualifies, and so does a
        // non-root euid holding effective CAP_SETUID/CAP_SETGID (the route-B
        // ③ file-cap launcher shape). A caps-free non-root supervisor stays
        // unprivileged: the single-entry map can only cover its own euid.
        let mediator_euid = unsafe { libc::geteuid() };
        let privileged_remap_caps = effective_caps_allow_privileged_remap();
        let privileged_userns = mediator_euid == 0 || privileged_remap_caps;
        let userns_remap =
            matches!(self.user, Some(run_as) if run_as.uid != real_uid || run_as.gid != real_gid);

        // Fail closed on unprivileged `RunAs` remaps.  A single-entry userns
        // map written by the child can only cover the caller's own euid (no
        // CAP_SETUID in the parent namespace), so an unprivileged supervisor
        // can never honor a *different* host uid: the sandbox would silently
        // run with the supervisor's host identity, per-sandbox isolation
        // would be absent, and the requested `RunAs` would be a lie.  Refuse
        // before fork so the caller gets an explicit error instead of a
        // sandbox that looks right but is not isolated.  Per-sandbox
        // independent uids require a privileged supervisor (root/CAP_SETUID
        // in the parent user namespace) or an equivalent mapping mechanism.
        if userns_remap && !privileged_userns {
            let run_as = self.user.expect("userns_remap implies a RunAs");
            return Err(SandboxRuntimeError::Child(format!(
                "RunAs({}, {}) refused: unprivileged supervisor (euid={}) cannot map an arbitrary \
                 host uid (single-entry userns map can only cover the caller's own euid); \
                 per-sandbox independent host uids require a privileged supervisor \
                 (root/CAP_SETUID in the parent user namespace) or an equivalent mechanism",
                run_as.uid, run_as.gid, real_uid,
            ))
            .into());
        }

        let map_pipes = if privileged_userns && userns_remap {
            // (ready: child writes / parent reads, done: parent writes /
            // child reads). `make_cloexec_pipe` returns (read, write).
            let ready = make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?;
            let done = make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?;
            Some((ready, done))
        } else {
            None
        };

        // The sandbox's effective HOST identity after the userns mapping —
        // the ids the kernel's DAC checks compare against file/socket
        // owners. On the privileged remap path these are the `RunAs` ids and
        // the child cleared its supplementary groups; otherwise they are the
        // supervisor's own ids (and groups), which the child inherits. The
        // named-unix on-behalf gate reproduces the child's permission check
        // with this identity, because the supervisor performs those syscalls
        // with root credentials that would otherwise bypass every per-uid
        // socket boundary.
        let (host_uid, host_gid, host_groups) = match self.user {
            Some(run_as) if userns_remap && privileged_userns => {
                (run_as.uid, run_as.gid, Vec::new())
            }
            _ => (
                real_uid,
                real_gid,
                crate::context::current_supplementary_groups(),
            ),
        };

        // C档 fail-closed (fork-plan F6.1 Step 3, SL-1 / P1+P2; F14 extends
        // the trigger from euid 0 to non-root effective CAP_SETUID/SETGID):
        // the seccomp-notify mediator runs in THIS process, so mediated path
        // operations carry this process's identity.  When this process can
        // remap the sandbox to a different host uid (`RunAs` through the
        // privileged userns map) and runs on-behalf path operations, the
        // mediated files would be created/modified as the mediator — the
        // SL-1 owner/chmod/sticky failure class.  There is no downgrade tier:
        // refuse before fork with the one remedy that is safe (run a
        // `sandlock-supervise` process as the sandbox's host uid, route B).
        let mediation_active = mediation_active_for(
            self.no_supervisor,
            resolved.features.fs_denies,
            resolved.features.chroot,
            resolved.features.cow,
            resolved.features.policy_fn,
        );
        if mediation_remap_is_refused(
            mediator_euid,
            host_uid,
            mediation_active,
            privileged_remap_caps,
        ) {
            // Distinguish the two privileged shapes for deployment
            // troubleshooting: euid 0 vs a non-root file-cap launcher
            // holding effective CAP_SETUID/CAP_SETGID.
            let privilege_clause = if mediator_euid == 0 {
                "as euid 0".to_string()
            } else {
                format!(
                    "as euid {} with effective CAP_SETUID/CAP_SETGID",
                    mediator_euid
                )
            };
            return Err(SandboxRuntimeError::Child(format!(
                "in-process path mediation refused: mediation would run {privilege_clause} \
                 while the sandbox's host uid is {host_uid}; on-behalf files would be owned \
                 by the mediator, not the sandbox (SL-1). Run sandlock-supervise as uid \
                 {host_uid} (route B)",
            ))
            .into());
        }

        // PID namespace: `clone3` creates the leader directly inside the new
        // user and PID namespaces. The calling thread must not enter a user
        // namespace itself — `unshare(CLONE_NEWUSER)` refuses a threaded
        // caller, and this supervisor owns a multi-threaded runtime — while
        // clone3 puts only the *child* in the new namespaces, so the
        // restriction does not apply. Without a PID namespace the plain fork
        // is unchanged.
        let pid = if self.pid_ns {
            // One call creates every namespace the sandbox needs: user and PID
            // always, mount when there is a real root to build, network when
            // the sandbox gets its own netns. The leader starts inside all of
            // them, so `confine_child` never has to unshare.
            let mut flags =
                crate::sys::structs::CLONE_NEWUSER | crate::sys::structs::CLONE_NEWPID;
            if self.real_root {
                flags |= crate::sys::structs::CLONE_NEWNS;
            }
            if self.net_isolation {
                flags |= crate::sys::structs::CLONE_NEWNET;
            }
            match unsafe {
                clone3_new_namespaces(flags, libc::SIGCHLD as u64)
            } {
                Ok(pid) => pid,
                Err(e) => return Err(SandboxRuntimeError::Fork(e).into()),
            }
        } else {
            unsafe { libc::fork() }
        };
        if pid < 0 {
            return Err(SandboxRuntimeError::Fork(std::io::Error::last_os_error()).into());
        }

        if pid == 0 {
            // ===== CHILD PROCESS =====
            // Keep the child-side handshake ends; drop the parent-side ends
            // of the post-fork copies.
            let (mut map_ready_w, mut map_done_r) = match map_pipes {
                Some((ready, done)) => {
                    let ready_w = ready.1;
                    let done_r = done.0;
                    drop(ready.0);
                    drop(done.1);
                    (Some(ready_w), Some(done_r))
                }
                None => (None, None),
            };

            if self.pid_ns {
                // === PID-namespace leader ===
                //
                // `clone3_new_namespaces` created this process directly inside
                // the new user and PID namespaces, so there is no intermediate
                // process any more: the identity mapping is written here,
                // before anything else runs.
                //
                // `real_uid`/`real_gid` come from the pre-clone capture in
                // `do_spawn`: inside the namespace `getuid()` already reports
                // the overflow id, and the single-entry map must name the
                // *host* identity.
                //
                // The pre-fork parent-death check is deliberately absent here:
                // this process is PID 1 in its own namespace and `getppid()`
                // is 0 there (the spawner lives outside it). PR_SET_PDEATHSIG
                // below plus the ready-pipe EOF inside `confine_child` carry
                // that case instead.
                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
                // The same three shapes `confine_child` chooses between
                // (`context.rs`, step 5) -- this process writes the maps for
                // the whole generation on the unprivileged path, so it must
                // not invent a fourth one:
                //
                //   * privileged remap: `RunAs` is a *different* host uid, so
                //     the supervisor writes `0 -> RunAs` over the handshake
                //     pipes (the `map_ready_w` branch below); the pair here is
                //     only the fallback for a remap that reached this process
                //     without pipes (defense in depth, refused before fork);
                //   * route-B self-map (F18): the requested identity *is*
                //     ours, so map `0 -> euid` -- root inside, sandbox uid
                //     outside. Without this branch the intermediate would map
                //     `euid -> euid` and a route-B guest would come up as its
                //     host uid instead of root, i.e. the one shape route B
                //     has and the non-pid-ns path already restores;
                //   * plain: map our own identity through unchanged
                //     (`net_isolation` needs the namespace, not a new uid).
                let remap = matches!(
                    self.user,
                    Some(run_as) if run_as.uid != real_uid || run_as.gid != real_gid
                );
                let self_map =
                    self.userns_self_map && !remap && self.user.is_some() && real_uid != 0;
                let (map_uid, map_gid) = if remap {
                    let run_as = self.user.expect("a remap implies RunAs");
                    (run_as.uid, run_as.gid)
                } else if self_map {
                    (0, 0)
                } else {
                    (real_uid, real_gid)
                };
                if map_ready_w.is_some() {
                    // Privileged: hand the namespace to the parent, which
                    // writes `0 -> RunAs` maps, then activate the mapped host
                    // identity from inside the namespace.
                    let ready_w = map_ready_w.take().expect("handshake ready pipe");
                    let done_r = map_done_r.take().expect("handshake done pipe");
                    if crate::context::write_byte_fd(ready_w.as_raw_fd(), b'R').is_err() {
                        let _ = writeln!(
                            std::io::stderr(),
                            "sandlock child: user-namespace map ready signal: {}",
                            std::io::Error::last_os_error(),
                        );
                        unsafe { libc::_exit(127) };
                    }
                    if crate::context::read_byte_fd(done_r.as_raw_fd()).is_err() {
                        let _ = writeln!(
                            std::io::stderr(),
                            "sandlock child: parent uid_map/gid_map write for pid namespace: {}",
                            std::io::Error::last_os_error(),
                        );
                        unsafe { libc::_exit(127) };
                    }
                    if unsafe { libc::setresgid(0, 0, 0) } != 0
                        || unsafe { libc::setgroups(0, std::ptr::null()) } != 0
                        || unsafe { libc::setresuid(0, 0, 0) } != 0
                    {
                        let _ = writeln!(
                            std::io::stderr(),
                            "sandlock child: activate mapped host identity for pid namespace: {}",
                            std::io::Error::last_os_error(),
                        );
                        unsafe { libc::_exit(127) };
                    }
                } else if crate::context::write_id_maps(real_uid, real_gid, map_uid, map_gid)
                    .is_err()
                {
                    let _ = writeln!(
                        std::io::stderr(),
                        "sandlock child: uid_map/gid_map write for pid namespace: {}",
                        std::io::Error::last_os_error(),
                    );
                    unsafe { libc::_exit(127) };
                }
            }

            let io_overrides = self.rt().io_overrides;
            if let Some((stdin_fd, stdout_fd, stderr_fd)) = io_overrides {
                if let Some(fd) = stdin_fd { unsafe { libc::dup2(fd, 0) }; }
                if let Some(fd) = stdout_fd { unsafe { libc::dup2(fd, 1) }; }
                if let Some(fd) = stderr_fd { unsafe { libc::dup2(fd, 2) }; }
            }

            let extra_fds_copy = self.rt().extra_fds.clone();
            // SL-4: fds mapped for an in-process control entrypoint
            // (`in_child_main`, e.g. the OCI sandlock-init control socket) are
            // control channels — a user process the entrypoint later fork+execs
            // must never inherit them. dup3 with O_CLOEXEC keeps the fd usable
            // in the entrypoint itself (it never execs) while closing it at any
            // descendant exec. Exec-path consumers that hand fds to the
            // exec'd program on purpose (Gather's source pipes, the restore
            // stub's CTRL/READY/GO fds) take the dup2 branch below, and
            // targets 0/1/2 always stay inheritable stdio.
            let control_entry = self.in_child_main.is_some();
            // The exec-fd delivery descriptor is needed *up to* the child's
            // `execveat` and must not survive it: measured 2026-09-23, without
            // this the stub image stayed open as fd 6 in the restored program.
            // The channel's fds (CTRL/READY/GO) are the opposite case -- the
            // stub reads them after its exec -- so they keep the inheritable
            // dup2.
            let exec_fd_target = self.rt().exec_fd;
            for &(target_fd, source_fd) in &extra_fds_copy {
                if (control_entry || Some(target_fd) == exec_fd_target) && target_fd >= 3 {
                    unsafe { libc::dup3(source_fd, target_fd, libc::O_CLOEXEC) };
                } else {
                    unsafe { libc::dup2(source_fd, target_fd) };
                }
            }

            // Wire stdin/stdout/stderr per their modes. This is a post-fork path
            // with a real class of fd hazards: when the supervisor was started
            // with a std fd (0/1/2) closed, `pipe2` can allocate a pipe end onto
            // that very fd, so a naive `dup2(end, std)` either aliases the target
            // or a sibling stream's later dup2 clobbers an end still needed, and a
            // raw-fd snapshot taken before the dup2s goes stale. To make wiring
            // order-independent, first relocate each Piped source to a fresh high
            // fd (>= 3, disjoint from the 0/1/2 targets), then dup2 it down.
            //
            // The original OwnedFd ends are O_CLOEXEC, so they close on their own
            // at execve; `mem::forget` them so their Drop cannot close a fd number
            // we have since reassigned to 0/1/2.
            let safe_in = if stdio.stdin == StdioMode::Piped {
                stdin_p.as_ref().map(|(r, _)| unsafe { relocate_high(r.as_raw_fd()) })
            } else {
                None
            };
            let safe_out = if stdio.stdout == StdioMode::Piped {
                stdout_p.as_ref().map(|(_, w)| unsafe { relocate_high(w.as_raw_fd()) })
            } else {
                None
            };
            let safe_err = if stdio.stderr == StdioMode::Piped {
                stderr_p.as_ref().map(|(_, w)| unsafe { relocate_high(w.as_raw_fd()) })
            } else {
                None
            };
            std::mem::forget(stdin_p);
            std::mem::forget(stdout_p);
            std::mem::forget(stderr_p);
            unsafe {
                wire_child_stdio(stdio.stdin, 0, safe_in, libc::O_RDONLY);
                wire_child_stdio(stdio.stdout, 1, safe_out, libc::O_WRONLY);
                wire_child_stdio(stdio.stderr, 2, safe_err, libc::O_WRONLY);
            }

            let gather_keep_fds: Vec<i32> = extra_fds_copy.iter().map(|&(target, _)| target).collect();

            let extra_syscalls: Vec<u32> = self.rt().handlers
                .iter()
                .map(|h| h.0 as u32)
                .collect();

            let sandbox_name = self.rt().name.clone();
            // In-process entrypoint (OCI PID-1) names the process from cmd[0];
            // otherwise execve the command.
            let entry = match (self.in_child_main, self.rt().exec_fd) {
                (Some(run), _) => {
                    context::ChildEntry::InProcess { name: c_cmd[0].as_c_str(), run }
                }
                (None, Some(fd)) => context::ChildEntry::ExecFd { fd, argv: &c_cmd },
                (None, None) => context::ChildEntry::Exec(&c_cmd),
            };
            // In a PID namespace the confined process's real parent (the
            // spawner) lives outside the namespace, so the kernel
            // reports `getppid()` as 0 there; pass 0 as the expected
            // parent so the death-check stays vacuous-but-true.
            let child_parent_pid = if self.pid_ns { 0 } else { parent_pid };
            context::confine_child(context::ChildSpawnArgs {
                sandbox: self,
                entry,
                pipes: &pipes,
                no_supervisor,
                keep_fds: &gather_keep_fds,
                sandbox_name: Some(sandbox_name.as_str()),
                extra_syscalls: &extra_syscalls,
                parent_pid: child_parent_pid,
                foreground,
                pid_ns: self.pid_ns,
                map_ready_w,
                map_done_r,
            });
        }

        // ===== PARENT PROCESS =====
        drop(pipes.notif_w);
        drop(pipes.ready_r);
        // The gateway address was written to the dns pipe before forking; the
        // parent only reads the child's fd number back on `dns_r`.
        drop(pipes.dns_w);

        // Privileged `--user` remap: wait for the child to enter its user
        // namespace, write the `0 -> host_uid` maps, then release it. Must
        // complete before the notif-fd read below — the child blocks on the
        // map-done pipe until the maps are written. On failure the child is
        // SIGKILL'd directly (it has not setpgid'd yet, so killpg could hit
        // the supervisor's own group) and the error is returned. `child_pid`
        // is only registered after this handshake, so Drop's killpg+waitpid
        // cannot reap this child — it is reaped explicitly below instead (a
        // SIGKILLed child would otherwise linger as a zombie until the
        // supervisor exits). The child is the leader in every shape now, so
        // waiting for it is sufficient.
        if let Some((ready, done)) = map_pipes {
            let ready_r = ready.0;
            let done_w = done.1;
            drop(ready.1);
            drop(done.0);
            let run_as = self.user.expect("map pipes imply a RunAs remap");
            let map_result = crate::context::read_byte_fd(ready_r.as_raw_fd())
                .and_then(|_| crate::context::write_privileged_id_maps(pid, run_as))
                .and_then(|_| crate::context::write_byte_fd(done_w.as_raw_fd(), b'P'));
            drop(ready_r);
            drop(done_w);
            if let Err(e) = map_result {
                eprintln!("sandlock: user-namespace map write for child {pid}: {e}");
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let mut status: i32 = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                return Err(SandboxRuntimeError::Child(format!(
                    "uid_map/gid_map write for sandbox child (is unprivileged userns \
                     restricted? e.g. kernel.apparmor_restrict_unprivileged_userns=1): {e}"
                ))
                .into());
            }
        }

        self.rt_mut()._stdin_write = stdin_p.map(|(_r, w)| w);
        self.rt_mut()._stdout_read = stdout_p.map(|(r, _w)| r);
        self.rt_mut()._stderr_read = stderr_p.map(|(r, _w)| r);

        self.rt_mut().child_pid = Some(pid);
        self.rt_mut().tty_foreground_taken = tty_foreground_taken;
        // State remains `Created` until `do_start` writes ready_w to release
        // the child to execve.

        // Read the seccomp notif fd number first: the leader writes it only
        // after its confinement (including setpgid) is installed, so an
        // error return from anything after this point is safe for Drop's
        // killpg+waitpid reaping.
        let notif_fd_num = read_u32_fd(pipes.notif_r.as_raw_fd())
            .map_err(|e| SandboxRuntimeError::Child(format!("read notif fd from child: {}", e)))?;

        if self.pid_ns {
            // clone3 created the leader itself, so the direct child *is* the
            // leader: its host pid is known here without a pipe hand-off.
            self.rt_mut().leader_pid = Some(pid);
        }

        let pidfd = match syscall::pidfd_open(pid as u32, 0) {
            Ok(fd) => Some(fd),
            Err(_) => None,
        };

        // Even for --no-supervisor sandboxes, write a pid file so sandlock ps
        // can discover and list them.  The control socket is only created when
        // a supervisor exists (inside the if-let below).  Honour the
        // control_socket opt-out knob.
        //
        // Use setup_runtime_dir_no_socket for the conflict check — a
        // no-supervisor sandbox with the same name as an existing sandbox
        // must refuse to start rather than preempt its runtime dir (SL-7
        // F1.3: an existing dir is only reclaimed when provably stale).
        //
        // This must stay after the notif-fd read above.  Any error return
        // from do_spawn relies on Drop's killpg to reap the child, which
        // only works once the child has setpgid'd into its own group; the
        // notif-fd write is the child's setup-complete signal, so returning
        // before it races killpg against setpgid and can deadlock Drop's
        // waitpid against a child parked on the ready pipe.
        if no_supervisor && self.control_socket {
            let sandbox_name = self.rt().name.clone();
            let supervisor_pid = std::process::id() as i32;
            match crate::control::setup_runtime_dir_no_socket(
                &sandbox_name,
                pid,
                supervisor_pid,
                self.mode.as_deref(),
            ) {
                Ok(dir) => {
                    self.rt_mut().control_dir = Some(dir);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Name collision with a live sandbox — hard-fail, same as
                    // the supervisor path.  Continuing would leave a second
                    // sandbox running invisible to ps.
                    return Err(SandboxRuntimeError::Child(format!(
                        "sandbox '{}' is already running: {}",
                        sandbox_name, e
                    ))
                    .into());
                }
                Err(e) => {
                    eprintln!(
                        "sandlock: runtime dir setup failed for '{}': {}",
                        sandbox_name, e
                    );
                }
            }
        }

        let is_nested_mode = notif_fd_num == 0;

        let notif_fd = if is_nested_mode {
            None
        } else if let Some(leader_pid) = self.rt().leader_pid {
            // PID-namespace sandbox: the seccomp listener lives in the
            // sandbox leader (ns pid 1), not in the intermediate child the
            // supervisor forked, so dup the notif fd from the leader.
            let lpfd = syscall::pidfd_open(leader_pid as u32, 0)
                .map_err(|e| SandboxRuntimeError::Child(format!("pidfd_open(leader): {}", e)))?;
            Some(syscall::pidfd_getfd(&lpfd, notif_fd_num as i32, 0)
                .map_err(|e| SandboxRuntimeError::Child(format!("pidfd_getfd: {}", e)))?)
        } else if let Some(ref pfd) = pidfd {
            Some(syscall::pidfd_getfd(pfd, notif_fd_num as i32, 0)
                .map_err(|e| SandboxRuntimeError::Child(format!("pidfd_getfd: {}", e)))?)
        } else {
            let path = format!("/proc/{}/fd/{}", pid, notif_fd_num);
            let cpath = CString::new(path).unwrap();
            let raw = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
            if raw < 0 {
                return Err(SandboxRuntimeError::Child("failed to open notif fd from /proc".into()).into());
            }
            Some(unsafe { OwnedFd::from_raw_fd(raw) })
        };

        // ---- DNS gateway (after the notif-fd read) ----
        //
        // Wildcard-domain rules are served by a per-sandbox DNS gateway on
        // `<gateway>:53`: a loopback address (`127.0.1.x`, since resolv.conf
        // cannot express a port). The gateway answers wildcard-suffix A
        // queries with synthetic IPs and forwards the rest upstream so
        // normal DNS keeps working; /etc/resolv.conf is virtualized to point
        // at it.
        let mut gateway_synthetic_dns: Option<crate::network::dns_synth::SyntheticDns> = None;
        let virtual_resolv_conf = if need_gateway {
            use crate::network::dns_gateway::{run_dns_gateway, worker_upstream_resolver};

            // S2.3 netns mode: the child bound the gateway inside the
            // sandbox's own netns and reported the socket's fd number; dup
            // it here and wrap it in a tokio UDP socket. Shared-netns mode
            // (default) keeps binding the gateway supervisor-side as before.
            let (gateway_ip, dns_sock) = if let Some(gateway_ip) = netns_gateway_ip {
                let dns_fd_num = read_u32_fd(pipes.dns_r.as_raw_fd()).map_err(|e| {
                    SandboxRuntimeError::Child(format!("read DNS gateway fd from child: {}", e))
                })?;
                let raw = dup_child_fd(
                    pidfd.as_ref(),
                    self.rt().leader_pid,
                    dns_fd_num as i32,
                    pid,
                    "DNS gateway",
                )
                .map_err(SandboxRuntimeError::Child)?;
                let std_sock =
                    unsafe { std::net::UdpSocket::from_raw_fd(raw.into_raw_fd()) };
                std_sock
                    .set_nonblocking(true)
                    .map_err(|e| {
                        SandboxRuntimeError::Child(format!(
                            "set nonblocking on in-netns DNS gateway: {}",
                            e
                        ))
                    })?;
                let dns_sock = tokio::net::UdpSocket::from_std(std_sock).map_err(|e| {
                    SandboxRuntimeError::Child(format!(
                        "wrap in-netns DNS gateway socket: {}",
                        e
                    ))
                })?;
                (gateway_ip, dns_sock)
            } else {
                // Shared-netns mode: this supervisor binds, and on a worker
                // that runs route-B slots the supervisor is one of *several*
                // processes -- each with its own allocator, each starting at
                // 127.0.1.1 (the counter is process-global because one process
                // used to serve one sandbox at a time). Two live sandboxes
                // that both need a wildcard gateway therefore collide: the
                // second supervisor dies at launch with EADDRINUSE, which is
                // what happened as soon as two route-B slots needed one
                // (measured 2026-09-25 -- reproduced by keeping the first
                // executor alive and starting a second wildcard sandbox).
                //
                // So probe instead of assuming: take the next candidate and
                // keep it only if the bind takes. `AddrInUse` means someone
                // else holds that address and the pool has another; anything
                // else is a real failure and is reported as such.
                let mut taken: Option<(std::net::Ipv4Addr, tokio::net::UdpSocket)> = None;
                let mut last_err: Option<std::io::Error> = None;
                while let Some(ip) = crate::network::dns_synth::allocate_gateway_addr() {
                    let gateway_addr = std::net::SocketAddr::from((ip, 53));
                    match tokio::net::UdpSocket::bind(gateway_addr).await {
                        Ok(sock) => {
                            taken = Some((ip, sock));
                            break;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                            last_err = Some(e);
                            continue;
                        }
                        Err(e) => {
                            return Err(SandboxRuntimeError::Child(format!(
                                "bind DNS gateway: {}",
                                e
                            ))
                            .into());
                        }
                    }
                }
                taken.ok_or_else(|| {
                    crate::error::SandlockError::Runtime(SandboxRuntimeError::Child(format!(
                        "no free per-sandbox DNS gateway address in 127.0.1.0/24{}",
                        last_err
                            .map(|e| format!(" (last: {e})"))
                            .unwrap_or_default()
                    )))
                })?
            };
            let dns = crate::network::dns_synth::SyntheticDns::new();
            gateway_synthetic_dns = Some(dns.clone());
            let upstream = worker_upstream_resolver();
            let gateway_handle =
                tokio::spawn(run_dns_gateway(dns_sock, wildcard_suffixes, dns, upstream));
            self.rt_mut().dns_gateway_handle = Some(gateway_handle);
            self.rt_mut().dns_gateway_addr = Some(gateway_ip);
            Some(format!(
                "nameserver {}\noptions ndots:0 timeout:1 attempts:1\n",
                gateway_ip
            ))
        } else {
            None
        };
        // The HTTP ACL proxy is spawned now; it binds loopback and the
        // sandbox's on-behalf connections (shared worker netns) reach it.
        if http_acl_active {
            let handle = crate::transparent_proxy::spawn_transparent_proxy(
                self.http_allow.clone(),
                self.http_deny.clone(),
                std::sync::Arc::clone(&self.inject),
                ca_cert_pem.as_deref(),
                ca_key_pem.as_deref(),
                self.http_log_fn.clone(),
                self.host_mask.as_deref(),
            )
            .await
            .map_err(SandboxRuntimeError::Io)?;
            self.rt_mut().http_acl_handle = Some(handle);
        }
        if let Some(notif_fd) = notif_fd {
            // Set up the per-sandbox runtime dir and control socket.  Must
            // happen before the notif supervisor is spawned so the socket
            // exists when the child is released.
            //
            // Best-effort: in nested sandboxes the control state root
            // (/tmp/sandlock-ctl-<uid> by default) may not be reachable from
            // the outer sandlock's Landlock policy.  Warn and continue
            // without a control socket rather than failing the sandbox.
            //
            // Honour the control_socket opt-out knob: when false, skip the
            // entire runtime dir + socket setup.
            let sandbox_name = self.rt().name.clone();
            let supervisor_pid = std::process::id() as i32;
            let control_listener: Option<std::os::unix::net::UnixListener>;
            if self.control_socket {
                match crate::control::setup_runtime_dir(
                    &sandbox_name,
                    pid,
                    supervisor_pid,
                    self.mode.as_deref(),
                ) {
                    Ok((listener, control_dir)) => {
                        self.rt_mut().control_dir = Some(control_dir);
                        control_listener = Some(listener);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        // Name collision with a live sandbox — hard-fail.
                        // A second sandbox with the same name would be
                        // invisible to ps and its Drop would remove the
                        // first one's runtime dir.
                        return Err(SandboxRuntimeError::Child(format!(
                            "sandbox '{}' is already running: {}",
                            sandbox_name, e
                        ))
                        .into());
                    }
                    Err(e) => {
                        // Best-effort: in nested sandboxes the control state
                        // root (/tmp/sandlock-ctl-<uid> by default) may be
                        // outside the outer sandlock's Landlock view.  Warn
                        // and continue without a control socket rather than
                        // failing the sandbox.
                        eprintln!(
                            "sandlock: control socket setup failed for '{}': {} \
                             (introspection unavailable for this sandbox)",
                            sandbox_name, e
                        );
                        control_listener = None;
                    }
                }
            } else {
                control_listener = None;
            }

            if self.time_start.is_some() || self.random_seed.is_some() {
                let time_offset = self.time_start.map(|t| crate::time::calculate_time_offset(t));
                if let Err(e) = crate::vdso::patch(pid, time_offset, self.random_seed.is_some()) {
                    eprintln!("sandlock: pre-exec vDSO patching failed (will retry after exec): {}", e);
                }
            }

            let time_offset_val = self.time_start
                .map(|t| crate::time::calculate_time_offset(t))
                .unwrap_or(0);

            let rt_name = self.rt().name.clone();
            let notif_policy = NotifPolicy {
                max_memory_bytes: self.max_memory.map(|m| m.0).unwrap_or(0),
                stat_metadata_mediated: resolved.features.stat_metadata_mediated,
                disk_stats_path: self.disk_stats_path.clone(),
                max_processes: self.max_processes,
                has_memory_limit: resolved.features.memory_limit,
                has_net_destination_policy: resolved.features.network_destination_policy,
                has_bind_denylist: resolved.features.bind_denylist,
                has_unix_fs_gate: resolved.features.unix_fs_gate,
                host_uid,
                host_gid,
                host_groups,
                has_random_seed: resolved.features.random_seed,
                has_time_start: resolved.features.time_start,
                argv_safety_required: resolved.features.argv_safety_required,
                time_offset: time_offset_val,
                num_cpus: self.num_cpus,
                port_remap: resolved.features.port_remap,
                fd_inject_connect: resolved.features.fd_inject_connect,
                net_isolation: resolved.features.net_isolation,
                inbound_port_map: resolved.features.inbound_port_map,
                net_bind_inject: resolved.features.net_bind_inject,
                cow_enabled: resolved.features.cow,
                chroot_root: chroot_root.clone(),
                chroot_readable: self.fs_readable.clone(),
                chroot_writable: self.fs_writable.clone(),
                chroot_denied: self.fs_denied.clone(),
                chroot_mounts: crate::chroot::resolve::resolve_chroot_mounts(&self.fs_mount),
                chroot_mount_ro: self.fs_mount_ro.clone(),
                deterministic_dirs: self.deterministic_dirs,
                virtual_hostname: Some(rt_name),
                has_http_acl: resolved.features.http_acl,
                virtual_etc_hosts,
                virtual_resolv_conf,
                ca_inject_paths: self.http_inject_ca.clone(),
                ca_inject_pem: ca_inject_pem.clone(),
                pid_ns: self.rt().leader_pid.map(|leader_pid| {
                    std::sync::Arc::new(std::sync::RwLock::new(
                        crate::procfs::PidNsMap::new(leader_pid),
                    ))
                }),
            };

            use rand::SeedableRng;
            use rand_chacha::ChaCha8Rng;

            let random_state = self.random_seed.map(|seed| ChaCha8Rng::seed_from_u64(seed));
            let time_offset = self.time_start.map(|t| crate::time::calculate_time_offset(t));

            let time_random_state = TimeRandomState::new(time_offset, random_state);

            let mut net_state = NetworkState::new();
            let has_deny = !self.net_deny.is_empty();
            if has_deny && self.net_allow.is_empty() {
                let resolved_deny = network::resolve_net_deny(&self.net_deny);
                net_state.tcp_policy = resolved_deny.tcp;
                net_state.udp_policy = resolved_deny.udp;
                net_state.icmp_policy = resolved_deny.icmp;
            } else {
                let no_rules = self.net_allow.is_empty();
                // `--net-allow` and `--net-deny` may be combined: the deny
                // set is then applied *on top of* the allowlist, deny
                // precedence. An allowlist entry that names a hostname is
                // matched against the name, so a destination the resolver
                // picks later (a name that answers with a protected address)
                // is only reachable if something filters the resolved
                // address -- that is what the deny set is for.
                let resolved_deny = if has_deny {
                    Some(network::resolve_net_deny(&self.net_deny))
                } else {
                    None
                };
                let policy_from = |resolved: &network::ResolvedNetAllow,
                                   deny: Option<&crate::seccomp::notif::NetworkPolicy>| {
                    if no_rules || resolved.any_ip_all_ports {
                        // Every port on every IP is allowed by the allowlist;
                        // with a deny set that is exactly the default-allow
                        // denylist policy.
                        return match deny {
                            Some(policy) => policy.clone(),
                            None => crate::seccomp::notif::NetworkPolicy::Unrestricted,
                        };
                    }
                    use crate::seccomp::notif::PortAllow;
                    let per_ip = resolved
                        .per_ip
                        .iter()
                        .map(|(ip, ports)| {
                            let allow = if resolved.per_ip_all_ports.contains(ip) {
                                PortAllow::Any
                            } else {
                                PortAllow::Specific(ports.clone())
                            };
                            (*ip, allow)
                        })
                        .collect();
                    crate::seccomp::notif::NetworkPolicy::AllowList {
                        per_ip,
                        cidrs: resolved.cidrs.clone(),
                        any_ip_ports: resolved.any_ip_ports.clone(),
                        wildcard_domains: resolved.wildcard_domains.clone(),
                        denied: deny
                            .map(network::denied_filter_from)
                            .unwrap_or_default(),
                    }
                };
                net_state.tcp_policy = policy_from(
                    &resolved_net_allow.tcp,
                    resolved_deny.as_ref().map(|d| &d.tcp),
                );
                net_state.udp_policy = policy_from(
                    &resolved_net_allow.udp,
                    resolved_deny.as_ref().map(|d| &d.udp),
                );
                net_state.icmp_policy = policy_from(
                    &resolved_net_allow.icmp,
                    resolved_deny.as_ref().map(|d| &d.icmp),
                );
            }
            net_state.http_acl_addr = self.rt().http_acl_handle.as_ref().map(|h| h.addr);
            net_state.http_acl_ports = self.http_ports.iter().copied().collect();
            net_state.http_acl_orig_dest = self.rt().http_acl_handle.as_ref().map(|h| h.orig_dest.clone());
            net_state.synthetic_dns =
                gateway_synthetic_dns
                    .unwrap_or_else(crate::network::dns_synth::SyntheticDns::new);
            net_state.dns_gateway_addr = self
                .rt()
                .dns_gateway_addr
                .map(|ip| std::net::SocketAddr::from((ip, 53)));
            net_state.egress_proxy = match &self.egress_proxy {
                Some(cfg) => Some(crate::network::egress::resolve_egress_proxy(
                    &cfg.address,
                    cfg.username.as_deref(),
                    cfg.password.as_deref(),
                )?),
                None => None,
            };
            net_state.bind_deny_ports = self.net_deny_bind.iter().copied().collect();
            net_state.inbound_map = self
                .net_bind_map
                .iter()
                .map(|&(host_port, sandbox_port)| (sandbox_port, host_port))
                .collect();
            if let Some(cb) = self.rt_mut().on_bind.take() {
                net_state.port_map.on_bind = Some(cb);
            }

            let procfs_state = ProcfsState::new();

            let mut res_state = ResourceState::new(
                notif_policy.max_memory_bytes,
                notif_policy.max_processes,
            );
            // The sandbox's root child is the baseline "1" (peak starts at 1
            // in `ResourceState::new` too). When argv safety is active every
            // counted fork child is birth-registered with a pidfd watcher, so
            // exits — not wait4 reaps — own the proc_count release; mirror
            // that mode into the state that `handle_wait` consults.
            res_state.proc_count = 1;
            res_state.pidfd_release_authoritative = notif_policy.argv_safety_required;

            let mut cow_state = CowState::new();
            cow_state.branch = seccomp_cow_branch;
            // A shared transactional-pipeline branch overrides the per-stage one:
            // reuse the coordinator's single COW state so every stage writes into
            // (and reads through) the same upper.
            let shared_cow_state = shared_cow.as_ref().map(|s| Arc::clone(&s.state));

            let mut policy_fn_state = PolicyFnState::new();

            for path in &self.fs_denied {
                // Captures the path prefix and the file's inode identity, so
                // the deny survives hardlinks/renames to a non-denied name.
                policy_fn_state.denied.deny(&path.to_string_lossy());
            }

            if let Some(ref callback) = self.policy_fn {
                let mut allowed_ips: std::collections::HashSet<std::net::IpAddr> =
                    std::collections::HashSet::new();
                for p in [&net_state.tcp_policy, &net_state.udp_policy, &net_state.icmp_policy] {
                    if let crate::seccomp::notif::NetworkPolicy::AllowList { per_ip, cidrs, .. } = p {
                        allowed_ips.extend(per_ip.keys().copied());
                        // IP literals resolve to single-host CIDRs (/32 or
                        // /128); surface them as concrete allowed IPs too.
                        for (net, _) in cidrs {
                            if net.is_single_host() {
                                allowed_ips.insert(net.addr);
                            }
                        }
                    }
                }
                let live = crate::policy_fn::LivePolicy {
                    allowed_ips,
                    max_memory_bytes: notif_policy.max_memory_bytes,
                    max_processes: notif_policy.max_processes,
                };
                let ceiling = live.clone();
                let live = std::sync::Arc::new(std::sync::RwLock::new(live));
                let denied = policy_fn_state.denied.clone();
                let pid_overrides = net_state.pid_ip_overrides.clone();
                policy_fn_state.live_policy = Some(live.clone());
                let worker = crate::policy_fn::spawn_policy_fn(
                    callback.clone(), live, ceiling, pid_overrides, denied,
                );
                policy_fn_state.event_tx = Some(worker.sender());
                self.rt_mut().policy_fn_worker = Some(worker);
            }

            let chroot_state = ChrootState::new();

            let notif_raw_fd = notif_fd.as_raw_fd();
            let child_pidfd_raw = pidfd.as_ref().map(|pfd| pfd.as_raw_fd());

            let res_state = Arc::new(tokio::sync::Mutex::new(res_state));
            self.rt_mut().supervisor_resource = Some(Arc::clone(&res_state));

            let cow_state = match shared_cow_state {
                Some(shared) => shared,
                None => Arc::new(tokio::sync::Mutex::new(cow_state)),
            };
            self.rt_mut().supervisor_cow = Some(Arc::clone(&cow_state));

            // N25/L2c: the written-directory ledger. Created here (the
            // supervisor side) and shared with the parent, so a consumer
            // outside the sandbox can drain it -- see `dirty::DirtyDirs`.
            let dirty_state = Arc::new(crate::dirty::DirtyDirs::new());
            self.rt_mut().supervisor_dirty = Some(Arc::clone(&dirty_state));
            // N25: the open-descriptor watch list, filled by the `openat`
            // handler and read by the append watch that supervise publishes.
            let write_fds_state = Arc::new(crate::dirty::WriteFds::new());
            self.rt_mut().supervisor_write_fds = Some(Arc::clone(&write_fds_state));

            let net_state = Arc::new(tokio::sync::Mutex::new(net_state));
            self.rt_mut().supervisor_network = Some(Arc::clone(&net_state));

            let procfs_state = Arc::new(tokio::sync::Mutex::new(procfs_state));
            let time_random_state = Arc::new(tokio::sync::Mutex::new(time_random_state));
            let policy_fn_state = Arc::new(tokio::sync::Mutex::new(policy_fn_state));
            let chroot_state = Arc::new(tokio::sync::Mutex::new(chroot_state));
            let processes = Arc::new(crate::seccomp::state::ProcessIndex::new());

            let netlink_state = Arc::new(crate::netlink::NetlinkState::new());
            self.rt_mut().supervisor_processes = Some(Arc::clone(&processes));
            let ctx = Arc::new(SupervisorCtx {
                resource: Arc::clone(&res_state),
                cow: Arc::clone(&cow_state),
                procfs: Arc::clone(&procfs_state),
                network: Arc::clone(&net_state),
                time_random: Arc::clone(&time_random_state),
                policy_fn: Arc::clone(&policy_fn_state),
                chroot: Arc::clone(&chroot_state),
                dirty: Arc::clone(&dirty_state),
                write_fds: Arc::clone(&write_fds_state),
                netlink: netlink_state,
                processes: Arc::clone(&processes),
                policy: Arc::new(notif_policy),
                child_pidfd: child_pidfd_raw,
                notif_fd: notif_raw_fd,
            });

            // Snapshot the sandbox config for the control-socket `config`
            // verb.  The control loop takes ownership; dynamic policy_fn
            // mutations are read from ctx.policy_fn at request time.
            let sandbox_snapshot = self.clone();

            let handlers = std::mem::take(&mut self.rt_mut().handlers);
            let (startup_tx, startup_rx) = tokio::sync::oneshot::channel();

            // Clone ctx for the control loop before moving the original into
            // the notif supervisor.  Only set up if the control dir was
            // successfully created above.
            let control_ctx = Arc::clone(&ctx);
            let control_dir_opt = self.rt().control_dir.clone();

            self.rt_mut().notif_handle = Some(tokio::spawn(
                notif::supervisor(
                    notif_fd,
                    ctx,
                    handlers,
                    startup_tx,
                    self.notify_rate_limit,
                ),
            ));
            // Wait for the supervisor to register the notif fd with the IO
            // driver before we release the child to execve. Otherwise an
            // early traced syscall would queue a notification on a fd no
            // one is polling, and the child would block until the next
            // `block_on` re-enters the runtime. Critical for current-thread
            // runtimes, harmless overhead for multi-thread.
            match startup_rx.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(SandboxRuntimeError::Io(e).into()),
                Err(_) => {
                    return Err(SandboxRuntimeError::Child(
                        "seccomp supervisor exited during startup".into(),
                    ).into());
                }
            }

            // Spawn the control-socket loop as a dedicated tokio task.
            // Independent of the seccomp-notify loop so accept() never adds
            // latency to syscall notification processing.
            if let (Some(listener), Some(dir_path)) =
                (control_listener, control_dir_opt)
            {
                self.rt_mut().control_handle = Some(
                    crate::control::spawn_control_loop(
                        listener,
                        control_ctx,
                        sandbox_snapshot,
                        dir_path,
                    )
                );
            }

            let la_resource = Arc::clone(&res_state);
            self.rt_mut().loadavg_handle = Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let mut rs = la_resource.lock().await;
                    let running = rs.proc_count;
                    rs.load_avg.sample(running);
                }
            }));
        }

        if let Some(cpu_pct) = self.max_cpu {
            if cpu_pct < 100 {
                let group_pid = self.rt().leader_pid.unwrap_or(pid);
                self.rt_mut().throttle_handle = Some(tokio::spawn(sandbox_throttle_cpu(group_pid, cpu_pct)));
            }
        }

        self.rt_mut().pidfd = pidfd;
        self.rt_mut().ready_w = Some(pipes.ready_w);

        Ok(())
    }

    // ================================================================
    // Internal: do_start (release the parked child to execve)
    // ================================================================

    pub(crate) fn do_start(&mut self) -> Result<(), crate::error::SandlockError> {
        use std::os::fd::AsRawFd;
        use crate::context::write_u32_fd;
        use crate::error::SandboxRuntimeError;

        if !matches!(self.rt().state, RuntimeState::Created) {
            return Err(SandboxRuntimeError::Child("start() requires a created sandbox".into()).into());
        }
        let ready_w = self.rt_mut().ready_w.take()
            .ok_or_else(|| SandboxRuntimeError::Child("start() called without a prior create()".into()))?;
        write_u32_fd(ready_w.as_raw_fd(), 1)
            .map_err(|e| SandboxRuntimeError::Child(format!("write ready signal: {}", e)))?;
        drop(ready_w);
        self.rt_mut().state = RuntimeState::Running;
        Ok(())
    }
}

// ================================================================
// ================================================================
// Process — a live process with caller-owned stdio (popen)
// ================================================================

/// A live sandboxed process with caller-owned stdio streams, returned by
/// [`Sandbox::popen`].
///
/// `take_stdin` / `take_stdout` / `take_stderr` move out the pipe end of each
/// stream opened with [`StdioMode::Piped`] (each available once); the caller
/// reads/writes those while the process runs. Unlike `std::process::Child`,
/// this *borrows* the originating [`Sandbox`] rather than owning the process:
/// the process is killed and reaped when that `Sandbox` is dropped, or eagerly
/// via [`Process::kill`].
///
/// A `Process` that is dropped without [`Process::wait`] leaves the child
/// running until the `Sandbox` is dropped — call `wait` (or `kill`) to end it.
#[must_use = "a Process is a live confined child; call wait() (or kill()) or it runs until the Sandbox is dropped"]
pub struct Process<'a> {
    sandbox: &'a mut Sandbox,
}

impl Process<'_> {
    /// Take the write end of a `Piped` stdin. The caller writes the child's
    /// input; closing this fd signals EOF. `None` if stdin was not piped or was
    /// already taken.
    ///
    /// Deadlock warning (as with `std::process::Child`): if you take stdin you
    /// own it — drop/close it before [`Process::wait`], or a child that reads to
    /// EOF (e.g. `cat`) never exits and `wait` blocks forever. (An *untaken*
    /// piped stdin is closed by `wait` for you.)
    pub fn take_stdin(&mut self) -> Option<std::os::fd::OwnedFd> {
        self.sandbox.rt_mut()._stdin_write.take()
    }

    /// Take the read end of a `Piped` stdout. `None` if stdout was not piped or
    /// was already taken.
    pub fn take_stdout(&mut self) -> Option<std::os::fd::OwnedFd> {
        self.sandbox.rt_mut()._stdout_read.take()
    }

    /// Take the read end of a `Piped` stderr. `None` if stderr was not piped or
    /// was already taken.
    pub fn take_stderr(&mut self) -> Option<std::os::fd::OwnedFd> {
        self.sandbox.rt_mut()._stderr_read.take()
    }

    /// The child PID, or `None` if not spawned. Remains `Some` after the child
    /// exits (until the `Sandbox` is dropped).
    pub fn pid(&self) -> Option<i32> {
        self.sandbox.pid()
    }

    /// Send SIGKILL to the child's *entire process group* (every process the
    /// workload spawned, not just the top-level child). Idempotent — a process
    /// that already exited is not an error.
    pub fn kill(&mut self) -> Result<(), crate::error::SandlockError> {
        self.sandbox.kill()
    }

    /// Wait for the child to exit. Any `Piped` stdout/stderr the caller did not
    /// take is drained into the returned `RunResult`; taken streams are `None`
    /// because the caller owns them. An untaken piped stdin is closed here so the
    /// child sees EOF; a *taken* stdin the caller must close itself first (see
    /// [`Process::take_stdin`]) or this blocks forever.
    pub async fn wait(self) -> Result<crate::result::RunResult, crate::error::SandlockError> {
        self.sandbox.wait().await
    }
}

// ================================================================
// Drop for Sandbox — the embedded session instance owns the teardown
// ================================================================

impl Drop for Sandbox {
    fn drop(&mut self) {
        // M0 lift (F2.1 review B-2): the session state is a `Box<SandboxInstance>`
        // field, and its own `Drop` runs `drop_teardown()` exactly once when
        // the box is dropped after this body. Historically this impl called
        // `drop_teardown()` inline *and* the box's `Drop` ran it again — a
        // double teardown that re-killed an already-dead group and re-disposed
        // the COW branch on the abandoned path. Delegating to the box's single
        // `Drop` preserves the historical kill + reap, task abort, control-dir
        // removal and disposition semantics with exactly one pass.
    }
}

// ================================================================
// CPU throttle
// ================================================================

async fn sandbox_throttle_cpu(pid: i32, cpu_pct: u8) {
    use std::time::Duration;
    let period = Duration::from_millis(100);
    let run_time = period * cpu_pct as u32 / 100;
    let stop_time = period - run_time;
    loop {
        tokio::time::sleep(run_time).await;
        if unsafe { libc::killpg(pid, libc::SIGSTOP) } < 0 { break; }
        tokio::time::sleep(stop_time).await;
        if unsafe { libc::killpg(pid, libc::SIGCONT) } < 0 { break; }
    }
}

// ================================================================
// Process name resolution
// ================================================================

static NEXT_SANDBOX_NAME: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn sandbox_resolve_name(name: Option<&str>) -> Result<String, crate::error::SandlockError> {
    match name {
        Some(n) => sandbox_validate_name(n.to_string()),
        None => Ok(format!("sandbox-{}", unique_instance_id())),
    }
}

/// A `<pid>-<counter>` suffix that makes an internally generated sandbox name
/// unique across processes and within one. The per-uid control state root is
/// claimed per name (hashed dir) and a collision with a non-provable-stale
/// dir is a hard error, so no internal caller may use a fixed name.
pub(crate) fn unique_instance_id() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        NEXT_SANDBOX_NAME.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    )
}

fn sandbox_validate_name(name: String) -> Result<String, crate::error::SandlockError> {
    use crate::error::SandboxRuntimeError;
    if name.is_empty() {
        return Err(SandboxRuntimeError::Child("sandbox name must not be empty".into()).into());
    }
    if name.len() > 64 {
        return Err(SandboxRuntimeError::Child("sandbox name must be at most 64 bytes".into()).into());
    }
    if name.as_bytes().contains(&0) {
        return Err(SandboxRuntimeError::Child("sandbox name must not contain NUL bytes".into()).into());
    }
    // The name is a uid-wide key: it hashes to the state-dir slot and is
    // written verbatim into the dir's `name` metadata and the ps display, so
    // it must stay a single token that cannot be confused with path syntax.
    if name.contains('/') {
        return Err(SandboxRuntimeError::Child("sandbox name must not contain '/'".into()).into());
    }
    if name == "." || name == ".." {
        return Err(SandboxRuntimeError::Child("sandbox name must not be '.' or '..'".into()).into());
    }
    Ok(name)
}

/// `clone3`'s argument block (`struct clone_args`): eleven `u64` fields.
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Create a child directly inside fresh namespaces with `clone3`.
///
/// The child returns 0 to its caller, exactly like `fork(2)`: with no
/// `CLONE_VM` a zero `stack` means the child gets a copy of the caller's
/// stack. `exit_signal` travels in its own field — the legacy `clone(2)`
/// packs it into the low byte of `flags`, where zero silently produces a
/// child the parent can never reap.
///
/// # Safety
/// Must be called exactly like `fork`: the caller handles both return paths,
/// and the child must not return into the parent's control flow.
unsafe fn clone3_new_namespaces(flags: u64, exit_signal: u64) -> std::io::Result<libc::pid_t> {
    let args = CloneArgs {
        flags,
        exit_signal,
        ..Default::default()
    };
    let pid = libc::syscall(
        libc::SYS_clone3,
        &args as *const CloneArgs,
        std::mem::size_of::<CloneArgs>(),
    );
    if pid < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            return Err(std::io::Error::new(
                err.kind(),
                "clone3 is not available on this kernel; the PID-namespace sandbox \
                 needs it to create the leader inside its own namespaces",
            ));
        }
        return Err(err);
    }
    Ok(pid as libc::pid_t)
}

/// Does an unprivileged process here get a usable user namespace?
///
/// Route B restores "root inside the sandbox, host uid outside" by having the
/// confined child self-map `0 -> its own euid` (see `Sandbox::userns_self_map`),
/// which needs an unprivileged user namespace *and* a map write. Kernels and
/// LSMs differ (`kernel.apparmor_restrict_unprivileged_userns=1` on Ubuntu
/// 24.04 makes the namespace appear and the map write fail), so probe once in
/// a throwaway child and run the generation with whichever shape actually
/// works -- reported through `stats.guest_uid` so the worker can log it.
///
/// The probe uses `clone3`, the same call the spawn path uses. An
/// `unshare(CLONE_NEWUSER)` probe would answer a question the deployment no
/// longer asks, and the worker's seccomp profile now denies `unshare` outright.
pub fn probe_userns_self_map() -> bool {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        // A privileged mediator needs none of this: it writes the child's maps
        // itself.
        return false;
    }
    let pid = match unsafe {
        clone3_new_namespaces(
            crate::sys::structs::CLONE_NEWUSER,
            libc::SIGCHLD as u64,
        )
    } {
        Ok(pid) => pid,
        Err(_) => return false,
    };
    if pid == 0 {
        // The probe child exits; it never returns into the supervisor.
        let ok = std::fs::write("/proc/self/uid_map", format!("0 {euid} 1\n")).is_ok()
            && std::fs::write("/proc/self/setgroups", "deny\n").is_ok()
            && std::fs::write("/proc/self/gid_map", format!("0 {euid} 1\n")).is_ok();
        unsafe { libc::_exit(i32::from(!ok)) };
    }
    let mut status: libc::c_int = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return false;
    }
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

// ================================================================
// I/O helpers (private)
// ================================================================

fn sandbox_read_exact(fd: i32, buf: &mut [u8]) {
    let mut off = 0;
    while off < buf.len() {
        let r = unsafe { libc::read(fd, buf[off..].as_mut_ptr() as *mut _, buf.len() - off) };
        if r <= 0 { break; }
        off += r as usize;
    }
}

/// Create a `O_CLOEXEC` pipe, returning `(read_end, write_end)` as owned fds.
/// `pipe2` yields `fds[0]` = read, `fds[1]` = write.
pub(crate) fn make_cloexec_pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), std::io::Error> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Duplicate `src` to a fresh fd `>= 3` with `O_CLOEXEC`, in the forked child.
/// Used to move a pipe end out of the 0/1/2 target range before wiring so that
/// `dup2(_, std)` can never alias the target or clobber a sibling stream's end.
/// Best-effort: returns the original `src` if the dup fails (caller still wires
/// it; a failure here only degrades to the legacy hazard, never a leak).
///
/// # Safety
/// Must run in the forked child; `src` must be a valid fd.
unsafe fn relocate_high(src: i32) -> i32 {
    let hi = libc::fcntl(src, libc::F_DUPFD_CLOEXEC, 3);
    if hi >= 0 {
        hi
    } else {
        src
    }
}

/// Open a child-side fd by number, using the same acquisition routes as the
/// seccomp notif fd: `pidfd_getfd` for pid-ns leaders / direct children, and
/// `/proc/<pid>/fd/<n>` otherwise. The child keeps the fd open (it is blocked
/// on the ready pipe) until this dup lands, so the two handles share the same
/// open file description — a socket created in the sandbox's netns stays bound
/// to that netns even though the supervisor serves it from the host netns.
fn dup_child_fd(
    pidfd: Option<&std::os::fd::OwnedFd>,
    leader_pid: Option<i32>,
    fd_num: i32,
    child_pid: i32,
    what: &str,
) -> Result<std::os::fd::OwnedFd, String> {
    use std::os::fd::FromRawFd;
    if let Some(leader_pid) = leader_pid {
        let lpfd = crate::sys::syscall::pidfd_open(leader_pid as u32, 0)
            .map_err(|e| format!("pidfd_open(leader): {}", e))?;
        return crate::sys::syscall::pidfd_getfd(&lpfd, fd_num, 0)
            .map_err(|e| format!("pidfd_getfd({}): {}", what, e));
    }
    if let Some(pfd) = pidfd {
        return crate::sys::syscall::pidfd_getfd(pfd, fd_num, 0)
            .map_err(|e| format!("pidfd_getfd({}): {}", what, e));
    }
    let path = format!("/proc/{}/fd/{}", child_pid, fd_num);
    let cpath = std::ffi::CString::new(path).unwrap();
    let raw = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
    if raw < 0 {
        return Err(format!(
            "open {} fd from /proc: {}",
            what,
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
}

/// Wire one of the child's std fds (`target` = 0/1/2) according to `mode`, in
/// the forked child just before execve. Single audited path for all three
/// streams (async-signal-safe: only open/dup2/close/fcntl).
///
/// For `Piped`, `pipe_src` is a relocated high fd (see `relocate_high`), so
/// `src != target` in the normal case and `dup2` clears `O_CLOEXEC` on the
/// target (it survives execve); the relocated copy is then closed. The
/// `src == target` arm is only reached if relocation failed (fd exhaustion).
///
/// # Safety
/// Must run in the forked child before execve; `pipe_src` (if any) must be a
/// valid fd. `devnull_flags` is `O_RDONLY` for stdin, `O_WRONLY` for stdout/err.
unsafe fn wire_child_stdio(mode: StdioMode, target: i32, pipe_src: Option<i32>, devnull_flags: i32) {
    match mode {
        StdioMode::Inherit => {}
        StdioMode::Piped => {
            if let Some(src) = pipe_src {
                if src == target {
                    // Relocation failed and the end sits on `target`; dup2 would
                    // no-op and leave O_CLOEXEC set, so clear it so the fd
                    // survives execve. Do not close it — it *is* the target.
                    let flags = libc::fcntl(target, libc::F_GETFD);
                    if flags >= 0 {
                        libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                    }
                } else if libc::dup2(src, target) < 0 {
                    // Fail closed (mirror Null): never leave the supervisor's fd.
                    libc::close(target);
                    libc::close(src);
                } else {
                    libc::close(src);
                }
            }
        }
        StdioMode::Null => {
            // Opened without O_CLOEXEC so it survives execve.
            let fd = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, devnull_flags);
            if fd < 0 {
                // Fail closed: workload gets EBADF, never the supervisor's fd.
                libc::close(target);
            } else if fd == target {
                // /dev/null landed on the (previously closed) target — done.
            } else if libc::dup2(fd, target) < 0 {
                libc::close(target);
                libc::close(fd);
            } else {
                libc::close(fd);
            }
        }
    }
}

fn sandbox_read_fd_to_end(fd: std::os::fd::OwnedFd) -> Vec<u8> {
    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::io::FromRawFd;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) };
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf);
    buf
}

fn sandbox_collect_handlers<I, S, H>(
    handlers: I,
    sandbox: &Sandbox,
) -> Result<Vec<(i64, Arc<dyn crate::seccomp::dispatch::Handler>)>, crate::error::SandlockError>
where
    I: IntoIterator<Item = (S, H)>,
    S: TryInto<crate::seccomp::syscall::Syscall, Error = crate::seccomp::syscall::SyscallError>,
    H: crate::seccomp::dispatch::Handler,
{
    use crate::seccomp::dispatch::{Handler, HandlerError};

    let pending: Vec<(i64, Arc<dyn Handler>)> = handlers
        .into_iter()
        .map(|(syscall, handler)| {
            let nr = syscall.try_into().map_err(HandlerError::from)?.raw();
            let h: Arc<dyn Handler> = Arc::new(handler);
            Ok::<_, HandlerError>((nr, h))
        })
        .collect::<Result<_, _>>()?;

    let nrs: Vec<i64> = pending.iter().map(|(nr, _)| *nr).collect();
    crate::seccomp::dispatch::validate_handler_syscalls_against_policy(&nrs, sandbox)
        .map_err(|syscall_nr| HandlerError::OnDenySyscall { syscall_nr })?;

    Ok(pending)
}

fn validate_syscall_names(names: &[String]) -> Result<(), SandboxError> {
    let unknown: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| {
            crate::sys::structs::syscall_group(name).is_none()
                && crate::seccomp::syscall::syscall_name_to_nr(name).is_none()
        })
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(SandboxError::Invalid(format!(
            "unknown syscall or group name(s): {}",
            unknown.join(", ")
        )))
    }
}

fn known_group_names() -> String {
    crate::sys::structs::SYSCALL_GROUPS
        .iter()
        .map(|(group, _)| *group)
        .collect::<Vec<_>>()
        .join(", ")
}

fn validate_allow_groups(names: &[String]) -> Result<(), SandboxError> {
    let unknown: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| crate::sys::structs::syscall_group(name).is_none())
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(SandboxError::Invalid(format!(
            "unknown syscall group name(s): {} (known groups: {}); \
             individual syscalls cannot be re-allowed",
            unknown.join(", "),
            known_group_names()
        )))
    }
}

/// Reject a syscall appearing on both sides. The BPF layout places notif
/// JEQs before deny JEQs, so a syscall that an allowed group routes to
/// notif would silently bypass a kernel-level deny of the same syscall.
fn validate_allow_deny_disjoint(
    allow_groups: &[String],
    deny: &[String],
) -> Result<(), SandboxError> {
    let denied: std::collections::HashSet<&str> = deny
        .iter()
        .flat_map(|name| match crate::sys::structs::syscall_group(name) {
            Some(members) => members.iter().copied().collect::<Vec<_>>(),
            None => vec![name.as_str()],
        })
        .collect();
    for group in allow_groups {
        if deny.iter().any(|d| d == group) {
            return Err(SandboxError::Invalid(format!(
                "syscall group `{}` is both allowed and denied",
                group
            )));
        }
        if let Some(members) = crate::sys::structs::syscall_group(group) {
            if let Some(overlap) = members.iter().find(|m| denied.contains(**m)) {
                return Err(SandboxError::Invalid(format!(
                    "syscall `{}` is denied but belongs to allowed group `{}`",
                    overlap, group
                )));
            }
        }
    }
    Ok(())
}

/// Parse `--net-allow-bind` specs. Accepts the `*` wildcard (any port),
/// which cannot be combined with port lists; repeating the bare wildcard
/// is idempotent.
fn parse_allow_bind_ports(specs: &[String], label: &str) -> Result<BindPorts, SandboxError> {
    let mut parts = specs.iter().flat_map(|s| s.split(',')).map(str::trim);
    if !parts.clone().any(|part| part == "*") {
        return Ok(BindPorts::Ports(parse_bind_ports(specs, label)?));
    }
    if !parts.all(|part| part == "*") {
        return Err(SandboxError::Invalid(format!(
            "{}: wildcard `*` cannot be combined with port lists",
            label
        )));
    }
    Ok(BindPorts::All)
}

/// Expand `--net-allow-bind` specs into a sorted, deduplicated port list.
/// Each spec is a comma-separated list of single ports (`8080`) or inclusive
/// `lo-hi` ranges (`8000-8010`). Mirrors the Python SDK's `parse_ports`.
fn parse_bind_ports(specs: &[String], label: &str) -> Result<Vec<u16>, SandboxError> {
    let mut ports: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    for spec in specs {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(SandboxError::Invalid(format!(
                    "{}: empty port in `{}`",
                    label, spec
                )));
            }
            if part == "*" {
                return Err(SandboxError::Invalid(format!(
                    "{}: wildcard `*` is only supported for --net-allow-bind",
                    label
                )));
            }
            match part.split_once('-') {
                Some((lo, hi)) => {
                    let lo: u16 = lo.trim().parse().map_err(|_| {
                        SandboxError::Invalid(format!("{}: invalid port range `{}`", label, part))
                    })?;
                    let hi: u16 = hi.trim().parse().map_err(|_| {
                        SandboxError::Invalid(format!("{}: invalid port range `{}`", label, part))
                    })?;
                    if lo > hi {
                        return Err(SandboxError::Invalid(format!(
                            "{}: reversed port range `{}` (lo > hi)",
                            label, part
                        )));
                    }
                    ports.extend(lo..=hi);
                }
                None => {
                    let p: u16 = part.parse().map_err(|_| {
                        SandboxError::Invalid(format!("{}: invalid port `{}`", label, part))
                    })?;
                    ports.insert(p);
                }
            }
        }
    }
    Ok(ports.into_iter().collect())
}

/// Resolve a path as seen inside the sandbox to its host-side location, so its
/// existence can be checked before spawn. Honors `--fs-mount` (virtual:host)
/// mappings (which take precedence) and chroot. Used to validate
/// `--http-inject-ca` targets.
fn resolve_sandbox_path_to_host(
    child_path: &std::path::Path,
    chroot_root: Option<&std::path::Path>,
    mounts: &[(std::path::PathBuf, std::path::PathBuf)],
) -> std::path::PathBuf {
    for (virt, host) in mounts {
        if let Ok(rest) = child_path.strip_prefix(virt) {
            return host.join(rest);
        }
    }
    if let Some(root) = chroot_root {
        if let Ok(rest) = child_path.strip_prefix("/") {
            return root.join(rest);
        }
    }
    child_path.to_path_buf()
}

#[cfg(test)]
mod tests;
