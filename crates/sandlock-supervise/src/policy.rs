//! Full-field supervise policy: wire schema, parse, apply, and per-field
//! read-back (fork-plan F2b.1, task brief "design requirement 2").
//!
//! ## Wire format
//!
//! The policy is a single flat JSON object. Every key is one semantic policy
//! field from the union of the Python `Sandbox`/`Policy` dataclass field list
//! (`python/src/sandlock/_sdk.py::_NativePolicy._HANDLED_FIELDS`,
//! `python/src/sandlock/sandbox.py::Sandbox`) and the Rust
//! [`SandboxBuilder`] support set (`crates/sandlock-core/src/sandbox/builder.rs`).
//! Keys are named after the Python dataclass where Python has the field, and
//! after the builder field where it is Rust-only. Value grammars follow the
//! fork-native profile grammars where one exists (mount specs, byte sizes,
//! branch actions, RFC3339 timestamps, port specs, protection names).
//!
//! Per-field reconciliation (reported in full in `tmp/sdd/f2b.1-report.md`):
//!
//! | wire key | profile.rs | builder | python |
//! |---|---|---|---|
//! | `fs_readable`/`fs_writable`/`fs_denied` | `[filesystem].read/write/deny` | `fs_readable`/`fs_writable`/`fs_denied` | same names |
//! | `extra_allow_syscalls`/`extra_deny_syscalls` | `[syscalls].extra_allow/deny` | same | same |
//! | `net_allow`/`net_deny` | `[network].allow/deny` | same | same |
//! | `net_allow_bind`/`net_deny_bind` | `[network].allow_bind/deny_bind` | same | same |
//! | `http_allow`/`http_deny`/`http_ports` | `[http].allow/deny/ports` | same | same |
//! | `http_ca`/`http_key`/`http_inject_ca`/`http_ca_out`/`host_mask` | `[config].http_ca/http_key/http_inject_ca/http_ca_out`; `[http].host_mask` | same | same |
//! | `egress_proxy` (object) | not in profile (password never serialized) | `egress_proxy`+`egress_proxy_username`+`egress_proxy_password` | `egress_proxy` dict |
//! | `http_inject` (dict list) | not in profile | `credentials`+`http_auth` | `http_inject` dict list |
//! | `max_memory`/`max_disk` | `[limits].memory/disk` (size strings) | `max_memory`/`max_disk` | `max_memory`/`max_disk` (str/int) |
//! | `max_processes`/`max_open_files`/`max_cpu`/`notify_rate_limit` | `[limits].processes/open_files/cpu`; rl not in profile | same; `notify_rate_limit` | same |
//! | `max_file_size` (RLIMIT_FSIZE) | `[limits].file_size` (size string) | `max_file_size` | same (str/int) |
//! | `cpu_cores`/`num_cpus`/`gpu_devices` | `[limits]` | same | same |
//! | `port_remap` | `[network].port_remap` | same | same |
//! | `pid_ns`/`net_isolation`/`fd_inject_connect` | not in profile | same | same |
//! | `port_mappings` (object) | not in profile | `net_bind_map` | `port_mappings` dict |
//! | `net_bind_inject` (bool) | not in profile | same | same |
//! | `random_seed`/`time_start` | `[determinism]` | same | same |
//! | `no_randomize_memory`/`no_huge_pages`/`no_coredump`/`deterministic_dirs` | `[determinism]` + `[program].no_*` | same | same |
//! | `chroot`/`fs_mount` (spec list `VIRTUAL:HOST[:ro]`) | `[filesystem].chroot/mount` | `chroot`/`fs_mount`+`fs_mount_ro` | `chroot`/`fs_mount` (rw dict only) |
//! | `clean_env`/`env` | `[program].clean_env/env` | same | same |
//! | `uid`/`gid` | `[program].uid/gid` | `user` (`RunAs`) | same |
//! | `workdir`/`cwd`/`fs_storage` | `[config].workdir/fs_storage`; `[program].cwd` | same | same |
//! | `on_exit`/`on_error` | `[filesystem].on_exit/on_error` | `on_exit`/`on_error` | same |
//! | `allow_degraded`/`disable` | not in profile | `protection_policy` | same |
//!
//! Deliberately **not** wire fields (each would be rejected by name as
//! unknown if sent, which is the fail-closed direction):
//!
//! * Python runtime kwargs / callbacks: `name`, `policy_fn`, `init_fn`,
//!   `work_fn` (Python marks them `runtime=True`; closures cannot be
//!   serialized; `name` is auto-generated for the single sandbox).
//! * `notif_policy` — Python-side only, not sent to the native builder.
//! * Builder shape/callback fields: `credentials`/`http_auth` (wire spelling
//!   is `http_inject`), `net_bind_map` (wire spelling `port_mappings`),
//!   `fs_mount_ro` (wire spelling `:ro` suffix in `fs_mount`),
//!   `egress_proxy_username`/`egress_proxy_password` (inside the
//!   `egress_proxy` object), `http_log_fn`, `policy_fn`, `init_fn`,
//!   `work_fn` (closures), `no_supervisor` (contradicts the supervise role),
//!   `control_socket` (infrastructure knob, default-on, wired in F2b.2),
//!   `name`/`mode` (runtime metadata).
//!
//! ## Provided-vs-defaulted and un-landed-field detection
//!
//! The JSON key set is captured *before* typed deserialization, so an
//! explicitly provided `false`/empty value is never confused with an omitted
//! field (no serde `default` ambiguity). Every provided field must then
//! (a) be in [`POLICY_FIELDS`] (unknown keys fail by name), (b) have an apply
//! step, and (c) read back equal to the provided value from the built
//! [`Sandbox`] — otherwise startup fails naming the field. This is the
//! Rust-side `_HANDLED_FIELDS` equivalent: a parsed-but-unlanded field
//! (the P3 `notify_rate_limit` class) cannot pass silently.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sandlock_core::http::HttpRule;
use sandlock_core::profile::parse_mount_spec;
use sandlock_core::sandbox::{
    BindPorts, BranchAction, ByteSize, NetRule, RunAs, Sandbox, SandboxBuilder,
};
use sandlock_core::{Protection, ProtectionPolicy, ProtectionState};
use serde::Deserialize;

/// Canonical wire field list (sorted, one entry per semantic union field).
/// Keep in sync with `SupervisePolicy` below and with the reconciliation
/// table above. A policy field added to `SandboxBuilder` /
/// Python `Policy` / `_HANDLED_FIELDS` must land here, in `SupervisePolicy`,
/// in `apply`, and in `verify` — the F2b.1 acceptance test drives a JSON
/// document containing every entry and fails startup if any one is dropped.
pub const POLICY_FIELDS: &[&str] = &[
    "allow_degraded",
    "chroot",
    "clean_env",
    "cpu_cores",
    "cwd",
    "deterministic_dirs",
    "disable",
    "disk_stats_path",
    "egress_proxy",
    "env",
    "extra_allow_syscalls",
    "extra_deny_syscalls",
    "fd_inject_connect",
    "fs_denied",
    "fs_mount",
    "fs_readable",
    "fs_storage",
    "fs_writable",
    "gid",
    "gpu_devices",
    "host_mask",
    "http_allow",
    "http_ca",
    "http_ca_out",
    "http_deny",
    "http_inject",
    "http_inject_ca",
    "http_key",
    "http_ports",
    "kernel_enforced_limits",
    "max_cpu",
    "max_disk",
    "max_file_size",
    "max_memory",
    "max_open_files",
    "max_processes",
    "net_allow",
    "net_allow_bind",
    "net_bind_inject",
    "net_deny",
    "net_deny_bind",
    "net_isolation",
    "no_coredump",
    "no_huge_pages",
    "no_randomize_memory",
    "notify_rate_limit",
    "num_cpus",
    "on_error",
    "on_exit",
    "pid_ns",
    "port_mappings",
    "port_remap",
    "random_seed",
    "real_root",
    "time_start",
    "uid",
    "workdir",
];

/// Parsed policy plus the set of keys the document actually provided.
#[derive(Debug, Clone)]
pub struct ParsedPolicy {
    pub policy: SupervisePolicy,
    pub provided: BTreeSet<&'static str>,
}

/// Flat full-field policy schema. Every field is optional; presence is
/// tracked separately from the raw JSON key set (see module docs).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SupervisePolicy {
    pub fs_writable: Vec<PathBuf>,
    pub fs_readable: Vec<PathBuf>,
    pub fs_denied: Vec<PathBuf>,
    pub extra_deny_syscalls: Vec<String>,
    pub extra_allow_syscalls: Vec<String>,
    pub net_allow: Vec<String>,
    pub net_deny: Vec<String>,
    pub net_allow_bind: Vec<BindEntry>,
    pub net_deny_bind: Vec<BindEntry>,
    pub http_allow: Vec<String>,
    pub http_deny: Vec<String>,
    pub http_ports: Vec<u16>,
    pub http_ca: Option<PathBuf>,
    pub http_key: Option<PathBuf>,
    pub http_inject_ca: Vec<PathBuf>,
    pub http_ca_out: Option<PathBuf>,
    /// Host-maintained ``<total_bytes> <used_bytes>`` accounting for
    /// ``statfs(2)``; see the fork's `Builder::disk_stats_path`.
    pub disk_stats_path: Option<PathBuf>,
    pub host_mask: Option<String>,
    pub egress_proxy: Option<EgressProxyWire>,
    pub http_inject: Vec<InjectRuleWire>,
    pub max_memory: Option<ByteSpec>,
    pub max_processes: Option<u32>,
    pub max_open_files: Option<u32>,
    /// Per-file size ceiling (RLIMIT_FSIZE); same `ByteSpec` shape as
    /// `max_memory`/`max_disk` so a caller can say `"1G"` or a byte count.
    pub max_file_size: Option<ByteSpec>,
    pub max_cpu: Option<u8>,
    pub max_disk: Option<ByteSpec>,
    pub notify_rate_limit: Option<u32>,
    /// The deployment enforces this sandbox's memory and task budgets in the
    /// kernel (a per-sandbox cgroup v2), so the mediator retires the
    /// notifications that exist only for its own ledger. See
    /// `Sandbox::kernel_enforced_limits`.
    #[serde(default)]
    pub kernel_enforced_limits: bool,
    pub cpu_cores: Option<Vec<u32>>,
    pub num_cpus: Option<u32>,
    pub gpu_devices: Option<Vec<u32>>,
    pub port_remap: bool,
    pub pid_ns: bool,
    /// Build a real root instead of emulating one (see `Sandbox::real_root`).
    /// The slot does the mounts itself, as the sandbox's uid, and then gives up
    /// `CAP_SYS_ADMIN` before the workload starts.
    #[serde(default)]
    pub real_root: bool,
    pub net_isolation: bool,
    pub fd_inject_connect: bool,
    /// S2.5 bind injection: mapped ports are answered by replacing the
    /// sandbox's socket with a host-loopback one at `bind()` time, instead of
    /// serving `accept()` from a host listener with readiness synthesis.
    #[serde(default)]
    pub net_bind_inject: bool,
    pub port_mappings: Option<BTreeMap<u16, u16>>,
    pub random_seed: Option<u64>,
    pub time_start: Option<TimeSpec>,
    pub no_randomize_memory: bool,
    pub no_huge_pages: bool,
    pub no_coredump: bool,
    pub deterministic_dirs: bool,
    pub chroot: Option<PathBuf>,
    pub fs_mount: Vec<String>,
    pub clean_env: bool,
    pub env: HashMap<String, String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub workdir: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub fs_storage: Option<PathBuf>,
    pub on_exit: Option<BranchActionWire>,
    pub on_error: Option<BranchActionWire>,
    pub allow_degraded: Vec<ProtectionEntry>,
    pub disable: Vec<ProtectionEntry>,
}

/// One `net_allow_bind`/`net_deny_bind` entry: a bare port or a port/range
/// spec string (mirrors `profile::PortSpec`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BindEntry {
    Port(u16),
    Spec(String),
}

/// `egress_proxy` wire value: the Python dataclass dict shape.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EgressProxyWire {
    pub address: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// One `http_inject` wire rule (the Python dataclass dict shape).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct InjectRuleWire {
    pub matcher: Option<String>,
    pub auth: Option<String>,
    pub secret: Option<String>,
    pub name: Option<String>,
    pub on_existing: Option<String>,
}

/// Protection opt-out entry: Python `IntEnum` discriminant or a name
/// (kebab-case CLI name, Python enum name, or Rust serde variant name).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ProtectionEntry {
    Discriminant(u32),
    Name(String),
}

/// Byte-size entry: integer bytes or a size string (`ByteSize` grammar).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ByteSpec {
    Bytes(u64),
    Size(String),
}

/// Timestamp entry: RFC3339 string or epoch seconds.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TimeSpec {
    Epoch(u64),
    Rfc3339(String),
}

/// Branch action wire value (`"commit" | "abort" | "keep"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchActionWire {
    Commit,
    Abort,
    Keep,
}

impl<'de> Deserialize<'de> for BranchActionWire {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "commit" => Ok(BranchActionWire::Commit),
            "abort" => Ok(BranchActionWire::Abort),
            "keep" => Ok(BranchActionWire::Keep),
            other => Err(serde::de::Error::custom(format!(
                "invalid branch action {other:?}; expected \"commit\" | \"abort\" | \"keep\""
            ))),
        }
    }
}

impl BranchActionWire {
    fn into_branch(self) -> BranchAction {
        match self {
            BranchActionWire::Commit => BranchAction::Commit,
            BranchActionWire::Abort => BranchAction::Abort,
            BranchActionWire::Keep => BranchAction::Keep,
        }
    }
}

/// Parse a full-field policy document. Fails by field name on unknown keys
/// and on any schema/type error.
pub fn parse(bytes: &[u8]) -> Result<ParsedPolicy, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("policy JSON parse error: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "policy must be a JSON object".to_string())?;

    let known: BTreeSet<&str> = POLICY_FIELDS.iter().copied().collect();
    let unknown: Vec<&String> = obj.keys().filter(|k| !known.contains(k.as_str())).collect();
    if !unknown.is_empty() {
        return Err(format!(
            "policy contains unknown field(s): {}",
            unknown
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let policy: SupervisePolicy = serde_json::from_value(serde_json::Value::Object(obj.clone()))
        .map_err(|e| format!("policy schema error: {e}"))?;
    // An explicit `null` means "unset" (a Python `dataclasses.asdict()` dump
    // emits every `None` field), so null-valued keys are not "provided":
    // provided-vs-defaulted is decided on non-null presence only.
    let provided: BTreeSet<&'static str> = obj
        .iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, _)| intern(k))
        .collect();
    Ok(ParsedPolicy { policy, provided })
}

/// Intern a wire key to its `&'static str` identity (all keys are known by
/// construction after the unknown-key check above).
fn intern(key: &str) -> &'static str {
    POLICY_FIELDS
        .iter()
        .copied()
        .find(|f| *f == key)
        .expect("unknown policy key already rejected")
}

/// Full parse → apply → read-back pipeline. Startup entry for the binary and
/// the acceptance tests: any unknown, un-landed, or un-equal field fails by
/// name, as does any build-time policy error.
pub fn validate(bytes: &[u8]) -> Result<Sandbox, String> {
    let parsed = parse(bytes)?;
    let builder = apply(&parsed)?;
    let sandbox = builder
        .build()
        .map_err(|e| format!("policy invalid: {e}"))?;
    verify(&sandbox, &parsed)?;
    Ok(sandbox)
}

/// Apply every *provided* field onto a fresh `SandboxBuilder`. Fields whose
/// effect is not readable back from the built `Sandbox` (egress credentials,
/// `http_inject`) are asserted on the builder itself here (the equivalent
/// "landing marker" check the F2b.1 brief allows).
fn apply(parsed: &ParsedPolicy) -> Result<SandboxBuilder, String> {
    let p = &parsed.policy;
    let prov = &parsed.provided;
    let mut b = Sandbox::builder();

    if prov.contains("fs_writable") {
        for path in &p.fs_writable {
            b = b.fs_write(path.clone());
        }
    }
    if prov.contains("fs_readable") {
        for path in &p.fs_readable {
            b = b.fs_read(path.clone());
        }
    }
    if prov.contains("fs_denied") {
        for path in &p.fs_denied {
            b = b.fs_deny(path.clone());
        }
    }
    if prov.contains("extra_deny_syscalls") {
        b = b.extra_deny_syscalls(p.extra_deny_syscalls.clone());
    }
    if prov.contains("extra_allow_syscalls") {
        b = b.extra_allow_syscalls(p.extra_allow_syscalls.clone());
    }
    if prov.contains("net_allow") {
        for spec in &p.net_allow {
            b = b.net_allow(spec.clone());
        }
    }
    if prov.contains("net_deny") {
        for spec in &p.net_deny {
            b = b.net_deny(spec.clone());
        }
    }
    if prov.contains("net_allow_bind") {
        for entry in bind_specs(&p.net_allow_bind) {
            b = b.net_allow_bind(entry);
        }
    }
    if prov.contains("net_deny_bind") {
        for entry in bind_specs(&p.net_deny_bind) {
            b = b.net_deny_bind(entry);
        }
    }
    if prov.contains("http_allow") {
        for rule in &p.http_allow {
            b = b.http_allow(rule);
        }
    }
    if prov.contains("disk_stats_path") {
        if let Some(path) = p.disk_stats_path.as_ref() {
            b = b.disk_stats_path(path.clone());
        }
    }
    if prov.contains("http_deny") {
        for rule in &p.http_deny {
            b = b.http_deny(rule);
        }
    }
    if prov.contains("http_ports") {
        for port in &p.http_ports {
            b = b.http_port(*port);
        }
    }
    if prov.contains("http_ca") {
        if let Some(ca) = &p.http_ca {
            b = b.http_ca(ca.clone());
        }
    }
    if prov.contains("http_key") {
        if let Some(key) = &p.http_key {
            b = b.http_key(key.clone());
        }
    }
    if prov.contains("http_inject_ca") {
        for ca in &p.http_inject_ca {
            b = b.http_inject_ca(ca.clone());
        }
    }
    if prov.contains("http_ca_out") {
        if let Some(out) = &p.http_ca_out {
            b = b.http_ca_out(out.clone());
        }
    }
    if prov.contains("host_mask") {
        if let Some(mask) = &p.host_mask {
            b = b.host_mask(mask.clone());
        }
    }
    if prov.contains("egress_proxy") {
        if let Some(proxy) = &p.egress_proxy {
            if proxy.address.is_empty() {
                return Err("egress_proxy.address must be a non-empty string".into());
            }
            let username = proxy.username.clone().unwrap_or_default();
            let password = proxy.password.clone().unwrap_or_default();
            if (proxy.username.is_some() || proxy.password.is_some())
                && (proxy.username.is_none() || proxy.password.is_none())
            {
                return Err("egress_proxy.username and password must both be set".into());
            }
            b = b.egress_proxy(proxy.address.clone());
            if proxy.username.is_some() || proxy.password.is_some() {
                b = b.egress_proxy_credentials(username, password);
            }
            // Landing marker: the builder must carry exactly the provided
            // config (Sandbox::egress_proxy is opaque outside core).
            if b.egress_proxy.as_deref() != Some(proxy.address.as_str())
                || b.egress_proxy_username != proxy.username
                || b.egress_proxy_password != proxy.password
            {
                return Err("policy field `egress_proxy` did not land on the builder".into());
            }
        }
    }
    if prov.contains("http_inject") {
        let mut creds: Vec<String> = Vec::new();
        let mut auth: Vec<String> = Vec::new();
        for (i, rule) in p.http_inject.iter().enumerate() {
            let (name, secret, auth_rule) = serialize_http_inject(rule, i)?;
            creds.push(format!("{name}={secret}"));
            auth.push(auth_rule);
        }
        for entry in &creds {
            let (name, source) = entry.split_once('=').expect("credential has =");
            b = b.credential(name, source);
        }
        for rule in &auth {
            b = b.http_auth(rule);
        }
        // Landing marker: the builder must carry exactly the serialized
        // credentials + auth rules (resolved inject rules are not public).
        if b.credentials != creds || b.http_auth != auth {
            return Err("policy field `http_inject` did not land on the builder".into());
        }
    }
    if prov.contains("max_memory") {
        if let Some(spec) = &p.max_memory {
            b = b.max_memory(bytes_of(spec, "max_memory")?);
        }
    }
    if prov.contains("max_processes") {
        if let Some(n) = p.max_processes {
            b = b.max_processes(n);
        }
    }
    if prov.contains("max_open_files") {
        if let Some(n) = p.max_open_files {
            b = b.max_open_files(n);
        }
    }
    if prov.contains("max_file_size") {
        if let Some(spec) = &p.max_file_size {
            b = b.max_file_size(bytes_of(spec, "max_file_size")?);
        }
    }
    if prov.contains("max_cpu") {
        if let Some(n) = p.max_cpu {
            b = b.max_cpu(n);
        }
    }
    if prov.contains("max_disk") {
        if let Some(spec) = &p.max_disk {
            b = b.max_disk(bytes_of(spec, "max_disk")?);
        }
    }
    if prov.contains("notify_rate_limit") {
        if let Some(n) = p.notify_rate_limit {
            b = b.notify_rate_limit(n);
        }
    }
    if prov.contains("kernel_enforced_limits") {
        b = b.kernel_enforced_limits(p.kernel_enforced_limits);
    }
    if prov.contains("cpu_cores") {
        if let Some(cores) = &p.cpu_cores {
            b = b.cpu_cores(cores.clone());
        }
    }
    if prov.contains("num_cpus") {
        if let Some(n) = p.num_cpus {
            b = b.num_cpus(n);
        }
    }
    if prov.contains("gpu_devices") {
        if let Some(devices) = &p.gpu_devices {
            b = b.gpu_devices(devices.clone());
        }
    }
    if prov.contains("port_remap") && p.port_remap {
        b = b.port_remap(true);
    }
    if prov.contains("pid_ns") && p.pid_ns {
        b = b.pid_ns(true);
    }
    if prov.contains("real_root") && p.real_root {
        b = b.real_root(true);
    }
    if prov.contains("net_isolation") && p.net_isolation {
        b = b.net_isolation(true);
    }
    if prov.contains("fd_inject_connect") && p.fd_inject_connect {
        b = b.fd_inject_connect(true);
    }
    if prov.contains("net_bind_inject") && p.net_bind_inject {
        b = b.net_bind_inject(true);
    }
    if prov.contains("port_mappings") {
        if let Some(map) = &p.port_mappings {
            for (host_port, sandbox_port) in map {
                b = b.net_bind_map(*host_port, *sandbox_port);
            }
        }
    }
    if prov.contains("random_seed") {
        if let Some(seed) = p.random_seed {
            b = b.random_seed(seed);
        }
    }
    if prov.contains("time_start") {
        if let Some(spec) = &p.time_start {
            b = b.time_start(time_of(spec, "time_start")?);
        }
    }
    if prov.contains("no_randomize_memory") && p.no_randomize_memory {
        b = b.no_randomize_memory(true);
    }
    if prov.contains("no_huge_pages") && p.no_huge_pages {
        b = b.no_huge_pages(true);
    }
    if prov.contains("no_coredump") && p.no_coredump {
        b = b.no_coredump(true);
    }
    if prov.contains("deterministic_dirs") && p.deterministic_dirs {
        b = b.deterministic_dirs(true);
    }
    if prov.contains("chroot") {
        if let Some(chroot) = &p.chroot {
            b = b.chroot(chroot.clone());
        }
    }
    if prov.contains("fs_mount") {
        for spec in &p.fs_mount {
            let (virt, host, ro) = parse_mount_spec(spec)
                .map_err(|e| format!("policy field `fs_mount` entry {spec:?}: {e}"))?;
            b = if ro {
                b.fs_mount_ro(virt, host)
            } else {
                b.fs_mount(virt, host)
            };
        }
    }
    if prov.contains("clean_env") && p.clean_env {
        b = b.clean_env(true);
    }
    if prov.contains("env") {
        for (k, v) in &p.env {
            b = b.env_var(k, v);
        }
    }
    if prov.contains("uid") || prov.contains("gid") {
        match (p.uid, p.gid) {
            (Some(uid), Some(gid)) => b = b.user(uid, gid),
            _ => return Err("uid and gid must both be set (or both unset) in the policy".into()),
        }
    }
    if prov.contains("workdir") {
        if let Some(w) = &p.workdir {
            b = b.workdir(w.clone());
        }
    }
    if prov.contains("cwd") {
        if let Some(c) = &p.cwd {
            b = b.cwd(c.clone());
        }
    }
    if prov.contains("fs_storage") {
        if let Some(s) = &p.fs_storage {
            b = b.fs_storage(s.clone());
        }
    }
    if prov.contains("on_exit") {
        if let Some(a) = p.on_exit {
            b = b.on_exit(a.into_branch());
        }
    }
    if prov.contains("on_error") {
        if let Some(a) = p.on_error {
            b = b.on_error(a.into_branch());
        }
    }
    if prov.contains("allow_degraded") {
        for entry in &p.allow_degraded {
            b = b.allow_degraded(protection_of(entry, "allow_degraded")?);
        }
    }
    if prov.contains("disable") {
        for entry in &p.disable {
            b = b.disable(protection_of(entry, "disable")?);
        }
    }

    Ok(b)
}

/// Render a `Vec<BindEntry>` back to the builder's `Vec<String>` vocabulary.
fn bind_specs(entries: &[BindEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| match e {
            BindEntry::Port(p) => p.to_string(),
            BindEntry::Spec(s) => s.clone(),
        })
        .collect()
}

/// Byte-size normalization shared by apply and verify.
fn bytes_of(spec: &ByteSpec, field: &str) -> Result<ByteSize, String> {
    match spec {
        ByteSpec::Bytes(n) => Ok(ByteSize(*n)),
        ByteSpec::Size(s) => ByteSize::parse(s).map_err(|e| format!("policy field `{field}`: {e}")),
    }
}

/// Timestamp normalization shared by apply and verify.
fn time_of(spec: &TimeSpec, field: &str) -> Result<SystemTime, String> {
    match spec {
        TimeSpec::Epoch(secs) => Ok(SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(*secs))
            .ok_or_else(|| format!("policy field `{field}`: epoch out of range"))?),
        TimeSpec::Rfc3339(s) => s
            .parse::<jiff::Timestamp>()
            .map(SystemTime::from)
            .map_err(|e| format!("policy field `{field}`: invalid RFC3339 timestamp {s:?}: {e}")),
    }
}

/// Protection discriminant/name normalization.
fn protection_of(entry: &ProtectionEntry, field: &str) -> Result<Protection, String> {
    let p = match entry {
        ProtectionEntry::Discriminant(n) => match n {
            0 => Protection::FsRefer,
            1 => Protection::FsTruncate,
            2 => Protection::NetTcp,
            3 => Protection::FsIoctlDev,
            4 => Protection::SignalScope,
            5 => Protection::AbstractUnixSocketScope,
            other => {
                return Err(format!(
                    "policy field `{field}`: {other} is not a known Protection discriminant \
                     (valid: 0..=5)"
                ))
            }
        },
        ProtectionEntry::Name(name) => {
            let norm: String = name
                .chars()
                .filter(|c| *c != '_' && *c != '-')
                .flat_map(char::to_lowercase)
                .collect();
            match norm.as_str() {
                "fsrefer" => Protection::FsRefer,
                "fstruncate" => Protection::FsTruncate,
                "nettcp" => Protection::NetTcp,
                "fsioctldev" => Protection::FsIoctlDev,
                "signalscope" => Protection::SignalScope,
                "abstractunixsocketscope" => Protection::AbstractUnixSocketScope,
                _ => {
                    return Err(format!(
                        "policy field `{field}`: unknown protection name {name:?} \
                         (valid: fs-refer, fs-truncate, net-tcp, fs-ioctl-dev, \
                         signal-scope, abstract-unix-socket-scope)"
                    ))
                }
            }
        }
    };
    Ok(p)
}

/// Mirror of the Python `_serialize_http_inject` (name, secret, auth-rule)
/// normalization, so a Python `Policy.http_inject` dict round-trips through
/// the wire unchanged. Returns `(name, secret_source, http_auth_rule)`.
pub fn serialize_http_inject(
    rule: &InjectRuleWire,
    index: usize,
) -> Result<(String, String, String), String> {
    let bad = |what: &str| {
        format!(
            "policy field `http_inject[{index}].{what}`: {}",
            what_hint(what, index)
        )
    };
    let matcher_raw = rule.matcher.as_deref().ok_or_else(|| bad("matcher"))?;
    let matcher = matcher_raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if matcher.is_empty() {
        return Err(format!(
            "policy field `http_inject[{index}].matcher` must be a non-empty string \
             (\"HOST\", \"HOST/PATH\", or \"METHOD HOST/PATH\")"
        ));
    }
    let tokens: Vec<&str> = matcher.split_whitespace().collect();
    let matcher = match tokens.len() {
        1 => {
            let host_path = tokens[0];
            if host_path.contains('/') {
                format!("* {host_path}")
            } else {
                format!("* {host_path}/*")
            }
        }
        2 => matcher,
        _ => {
            return Err(format!(
                "policy field `http_inject[{index}].matcher` must be \
                 \"HOST\", \"HOST/PATH\", or \"METHOD HOST/PATH\", got {matcher:?}"
            ))
        }
    };

    let auth = rule.auth.as_deref().ok_or_else(|| bad("auth"))?.trim();
    if auth.is_empty() {
        return Err(format!(
            "policy field `http_inject[{index}].auth` must be a non-empty string"
        ));
    }
    let valid_auth = auth == "bearer"
        || ["basic:", "header:", "apikey:", "query:"]
            .iter()
            .any(|prefix| auth.starts_with(prefix) && auth.len() > prefix.len());
    if !valid_auth {
        return Err(format!(
            "policy field `http_inject[{index}].auth` must be one of \
             \"bearer\", \"basic:<user>\", \"header:<name>\", \"apikey:<name>\", \
             \"query:<param>\", got {auth:?}"
        ));
    }

    let secret = rule.secret.as_deref().ok_or_else(|| bad("secret"))?.trim();
    if secret.starts_with("literal:") {
        return Err(format!(
            "policy field `http_inject[{index}].secret` 'literal:' is rejected \
             (it leaks via ps / shell history); use env:VAR, file:/path, or fd:N"
        ));
    }
    let (kind, val) = secret
        .split_once(':')
        .ok_or_else(|| format!("policy field `http_inject[{index}].secret` must be env:VAR, file:/path, or fd:N, got {secret:?}"))?;
    if !matches!(kind, "env" | "file" | "fd") || val.is_empty() {
        return Err(format!(
            "policy field `http_inject[{index}].secret` must be env:VAR, file:/path, \
             or fd:N, got {secret:?}"
        ));
    }

    let name = match &rule.name {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        Some(_) => {
            return Err(format!(
                "policy field `http_inject[{index}].name` must be a non-empty string"
            ))
        }
        None => format!("inject{index}"),
    };

    let on_existing = rule.on_existing.as_deref().unwrap_or("replace");
    if !matches!(on_existing, "replace" | "add-only") {
        return Err(format!(
            "policy field `http_inject[{index}].on_existing` must be \
             'replace' or 'add-only', got {on_existing:?}"
        ));
    }

    let mut auth_rule = format!("{matcher} {auth} {name}");
    if on_existing == "add-only" {
        auth_rule.push_str(" add-only");
    }
    Ok((name, secret.to_string(), auth_rule))
}

fn what_hint(what: &str, _index: usize) -> &'static str {
    match what {
        "matcher" => "required",
        "auth" => "required",
        "secret" => "required",
        "name" => "defaults to inject<index>",
        "on_existing" => "defaults to replace",
        _ => "invalid",
    }
}

/// Expand a net-bind spec list into the canonical effective form, mirroring
/// `sandbox-core`'s (private) `parse_allow_bind_ports`/`parse_bind_ports`.
/// Mirrored here only to compute the expected read-back; the builder's own
/// parser remains authoritative for validity.
fn expand_allow_bind(entries: &[BindEntry]) -> Result<BindPorts, String> {
    let specs = bind_specs(entries);
    let parts: Vec<&str> = specs
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .collect();
    if parts.iter().any(|p| *p == "*") {
        if parts.iter().all(|p| *p == "*") {
            return Ok(BindPorts::All);
        }
        return Err("net_allow_bind: wildcard `*` cannot be combined with port lists".into());
    }
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    for spec in &specs {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err("net_allow_bind: empty port".into());
            }
            match part.split_once('-') {
                Some((lo, hi)) => {
                    let lo: u16 = lo
                        .trim()
                        .parse()
                        .map_err(|_| format!("net_allow_bind: invalid port range `{part}`"))?;
                    let hi: u16 = hi
                        .trim()
                        .parse()
                        .map_err(|_| format!("net_allow_bind: invalid port range `{part}`"))?;
                    if lo > hi {
                        return Err(format!(
                            "net_allow_bind: reversed port range `{part}` (lo > hi)"
                        ));
                    }
                    ports.extend(lo..=hi);
                }
                None => {
                    let port: u16 = part
                        .parse()
                        .map_err(|_| format!("net_allow_bind: invalid port `{part}`"))?;
                    ports.insert(port);
                }
            }
        }
    }
    Ok(BindPorts::Ports(ports.into_iter().collect()))
}

/// Deny-bind expansion (mirrors `parse_bind_ports`; `*` is not legal here).
fn expand_deny_bind(entries: &[BindEntry]) -> Result<Vec<u16>, String> {
    let specs = bind_specs(entries);
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    for spec in &specs {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err("net_deny_bind: empty port".into());
            }
            if part == "*" {
                return Err(
                    "net_deny_bind: wildcard `*` is only supported for net_allow_bind".into(),
                );
            }
            match part.split_once('-') {
                Some((lo, hi)) => {
                    let lo: u16 = lo
                        .trim()
                        .parse()
                        .map_err(|_| format!("net_deny_bind: invalid port range `{part}`"))?;
                    let hi: u16 = hi
                        .trim()
                        .parse()
                        .map_err(|_| format!("net_deny_bind: invalid port range `{part}`"))?;
                    if lo > hi {
                        return Err(format!(
                            "net_deny_bind: reversed port range `{part}` (lo > hi)"
                        ));
                    }
                    ports.extend(lo..=hi);
                }
                None => {
                    let port: u16 = part
                        .parse()
                        .map_err(|_| format!("net_deny_bind: invalid port `{part}`"))?;
                    ports.insert(port);
                }
            }
        }
    }
    Ok(ports.into_iter().collect())
}

/// Per-field read-back verification against the built `Sandbox`. Every
/// provided field must read back equal to its provided value.
fn verify(sandbox: &Sandbox, parsed: &ParsedPolicy) -> Result<(), String> {
    let p = &parsed.policy;
    let prov = &parsed.provided;
    let fail = |field: &str, provided: &dyn std::fmt::Debug, effective: &dyn std::fmt::Debug| {
        Err(format!(
            "policy field `{field}` did not land: provided {provided:?}, effective {effective:?}"
        ))
    };

    macro_rules! check {
        ($field:literal, $provided:expr, $effective:expr) => {
            if prov.contains($field) {
                let provided = $provided;
                let effective = $effective;
                if provided != effective {
                    return Err(format!(
                        "policy field `{}` did not land: provided {:?}, effective {:?}",
                        $field, provided, effective
                    ));
                }
            }
        };
    }

    check!("fs_writable", &p.fs_writable, &sandbox.fs_writable);
    check!("fs_readable", &p.fs_readable, &sandbox.fs_readable);
    check!("fs_denied", &p.fs_denied, &sandbox.fs_denied);
    check!(
        "extra_deny_syscalls",
        &p.extra_deny_syscalls,
        &sandbox.extra_deny_syscalls
    );
    check!(
        "extra_allow_syscalls",
        &p.extra_allow_syscalls,
        &sandbox.extra_allow_syscalls
    );

    if prov.contains("net_allow") {
        let mut expected: Vec<NetRule> = Vec::new();
        for spec in &p.net_allow {
            expected.extend(
                NetRule::parse_allow(spec)
                    .map_err(|e| format!("policy field `net_allow` entry {spec:?}: {e}"))?,
            );
        }
        for rule in &expected {
            if !sandbox.net_allow.contains(rule) {
                return Err(format!(
                    "policy field `net_allow` did not land: provided {expected:?}, \
                     effective {:?}",
                    sandbox.net_allow
                ));
            }
        }
    }
    if prov.contains("net_deny") {
        let mut expected: Vec<NetRule> = Vec::new();
        for spec in &p.net_deny {
            expected.extend(
                NetRule::parse_deny(spec)
                    .map_err(|e| format!("policy field `net_deny` entry {spec:?}: {e}"))?,
            );
        }
        for rule in &expected {
            if !sandbox.net_deny.contains(rule) {
                return Err(format!(
                    "policy field `net_deny` did not land: provided {expected:?}, \
                     effective {:?}",
                    sandbox.net_deny
                ));
            }
        }
    }
    if prov.contains("net_allow_bind") {
        let expected = expand_allow_bind(&p.net_allow_bind)?;
        if expected != sandbox.net_allow_bind {
            return Err(format!(
                "policy field `net_allow_bind` did not land: provided {:?}, effective {:?}",
                expected, sandbox.net_allow_bind
            ));
        }
    }
    if prov.contains("net_deny_bind") {
        let expected = expand_deny_bind(&p.net_deny_bind)?;
        if expected != sandbox.net_deny_bind {
            return Err(format!(
                "policy field `net_deny_bind` did not land: provided {:?}, effective {:?}",
                expected, sandbox.net_deny_bind
            ));
        }
    }
    if prov.contains("http_allow") {
        let expected: Vec<HttpRule> = p
            .http_allow
            .iter()
            .map(|s| {
                HttpRule::parse(s)
                    .map_err(|e| format!("policy field `http_allow` entry {s:?}: {e}"))
            })
            .collect::<Result<_, _>>()?;
        if expected != sandbox.http_allow {
            return Err(format!(
                "policy field `http_allow` did not land: provided {expected:?}, effective {:?}",
                sandbox.http_allow
            ));
        }
    }
    if prov.contains("http_deny") {
        let expected: Vec<HttpRule> = p
            .http_deny
            .iter()
            .map(|s| {
                HttpRule::parse(s).map_err(|e| format!("policy field `http_deny` entry {s:?}: {e}"))
            })
            .collect::<Result<_, _>>()?;
        if expected != sandbox.http_deny {
            return Err(format!(
                "policy field `http_deny` did not land: provided {expected:?}, effective {:?}",
                sandbox.http_deny
            ));
        }
    }
    if prov.contains("http_ports") {
        // The builder derives default ports only when the field was provided
        // as an *empty* list next to http rules; mirror that derivation so an
        // explicitly-empty value still reads back truthfully.
        let expected =
            if p.http_ports.is_empty() && (!p.http_allow.is_empty() || !p.http_deny.is_empty()) {
                let mut ports = vec![80];
                if p.http_ca.is_some() || !p.http_inject_ca.is_empty() {
                    ports.push(443);
                }
                ports
            } else {
                p.http_ports.clone()
            };
        if expected != sandbox.http_ports {
            return Err(format!(
                "policy field `http_ports` did not land: provided {expected:?}, effective {:?}",
                sandbox.http_ports
            ));
        }
    }
    check!("http_ca", &p.http_ca, &sandbox.http_ca);
    check!("http_key", &p.http_key, &sandbox.http_key);
    check!("http_inject_ca", &p.http_inject_ca, &sandbox.http_inject_ca);
    check!("http_ca_out", &p.http_ca_out, &sandbox.http_ca_out);
    check!("host_mask", &p.host_mask, &sandbox.host_mask);

    if prov.contains("egress_proxy") {
        // Full post-build read-back: `Sandbox::egress_proxy` is public (the
        // F2b.1 report listed it as builder-level only, but the config struct
        // — address/username/password — is part of the crate's public
        // surface), so verify field-for-field equality instead of an is_some
        // marker.
        let expected = p.egress_proxy.as_ref().map(|proxy| {
            (
                proxy.address.clone(),
                proxy.username.clone(),
                proxy.password.clone(),
            )
        });
        let effective = sandbox.egress_proxy.as_ref().map(|cfg| {
            (
                cfg.address.clone(),
                cfg.username.clone(),
                cfg.password.clone(),
            )
        });
        if expected != effective {
            return fail("egress_proxy", &expected, &effective);
        }
    }
    if prov.contains("max_memory") {
        let expected = bytes_of(
            p.max_memory
                .as_ref()
                .expect("provided max_memory has a value"),
            "max_memory",
        )?;
        if sandbox.max_memory != Some(expected) {
            return Err(format!(
                "policy field `max_memory` did not land: provided {expected:?}, effective {:?}",
                sandbox.max_memory
            ));
        }
    }
    if prov.contains("max_processes") {
        let expected = p.max_processes.expect("provided max_processes has a value");
        if sandbox.max_processes != expected {
            return Err(format!(
                "policy field `max_processes` did not land: provided {expected:?}, effective {:?}",
                sandbox.max_processes
            ));
        }
    }
    if prov.contains("max_open_files") {
        check!("max_open_files", &p.max_open_files, &sandbox.max_open_files);
    }
    if prov.contains("max_file_size") {
        let expected = bytes_of(
            p.max_file_size
                .as_ref()
                .expect("provided max_file_size has a value"),
            "max_file_size",
        )?;
        if sandbox.max_file_size != Some(expected) {
            return Err(format!(
                "policy field `max_file_size` did not land: provided {expected:?}, \
                 effective {:?}",
                sandbox.max_file_size
            ));
        }
    }
    if prov.contains("max_cpu") {
        check!("max_cpu", &p.max_cpu, &sandbox.max_cpu);
    }
    if prov.contains("max_disk") {
        let expected = bytes_of(
            p.max_disk.as_ref().expect("provided max_disk has a value"),
            "max_disk",
        )?;
        if sandbox.max_disk != Some(expected) {
            return Err(format!(
                "policy field `max_disk` did not land: provided {expected:?}, effective {:?}",
                sandbox.max_disk
            ));
        }
    }
    if prov.contains("notify_rate_limit") {
        check!(
            "notify_rate_limit",
            &p.notify_rate_limit,
            &sandbox.notify_rate_limit
        );
    }
    if prov.contains("kernel_enforced_limits") {
        check!(
            "kernel_enforced_limits",
            &p.kernel_enforced_limits,
            &sandbox.kernel_enforced_limits
        );
    }
    if prov.contains("cpu_cores") {
        check!("cpu_cores", &p.cpu_cores, &sandbox.cpu_cores);
    }
    if prov.contains("num_cpus") {
        check!("num_cpus", &p.num_cpus, &sandbox.num_cpus);
    }
    if prov.contains("gpu_devices") {
        check!("gpu_devices", &p.gpu_devices, &sandbox.gpu_devices);
    }
    if prov.contains("port_remap") {
        check!("port_remap", &p.port_remap, &sandbox.port_remap);
    }
    if prov.contains("pid_ns") {
        check!("pid_ns", &p.pid_ns, &sandbox.pid_ns);
    }
    if prov.contains("real_root") {
        check!("real_root", &p.real_root, &sandbox.real_root);
    }
    if prov.contains("net_isolation") {
        check!("net_isolation", &p.net_isolation, &sandbox.net_isolation);
    }
    if prov.contains("fd_inject_connect") {
        check!(
            "fd_inject_connect",
            &p.fd_inject_connect,
            &sandbox.fd_inject_connect
        );
    }
    if prov.contains("net_bind_inject") {
        check!(
            "net_bind_inject",
            &p.net_bind_inject,
            &sandbox.net_bind_inject
        );
    }
    if prov.contains("port_mappings") {
        let expected: Vec<(u16, u16)> = p
            .port_mappings
            .iter()
            .flat_map(|m| m.iter().map(|(h, s)| (*h, *s)))
            .collect();
        if expected != sandbox.net_bind_map {
            return Err(format!(
                "policy field `port_mappings` did not land: provided {expected:?}, \
                 effective {:?}",
                sandbox.net_bind_map
            ));
        }
    }
    if prov.contains("random_seed") {
        check!("random_seed", &p.random_seed, &sandbox.random_seed);
    }
    if prov.contains("time_start") {
        let expected = time_of(
            p.time_start
                .as_ref()
                .expect("provided time_start has a value"),
            "time_start",
        )?;
        if sandbox.time_start != Some(expected) {
            return Err(format!(
                "policy field `time_start` did not land: provided {expected:?}, effective {:?}",
                sandbox.time_start
            ));
        }
    }
    if prov.contains("no_randomize_memory") {
        check!(
            "no_randomize_memory",
            &p.no_randomize_memory,
            &sandbox.no_randomize_memory
        );
    }
    if prov.contains("no_huge_pages") {
        check!("no_huge_pages", &p.no_huge_pages, &sandbox.no_huge_pages);
    }
    if prov.contains("no_coredump") {
        check!("no_coredump", &p.no_coredump, &sandbox.no_coredump);
    }
    if prov.contains("deterministic_dirs") {
        check!(
            "deterministic_dirs",
            &p.deterministic_dirs,
            &sandbox.deterministic_dirs
        );
    }
    check!("chroot", &p.chroot, &sandbox.chroot);
    if prov.contains("fs_mount") {
        let mut expected: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut expected_ro: Vec<PathBuf> = Vec::new();
        for spec in &p.fs_mount {
            let (virt, host, ro) = parse_mount_spec(spec)
                .map_err(|e| format!("policy field `fs_mount` entry {spec:?}: {e}"))?;
            if ro {
                expected_ro.push(virt.clone());
            }
            expected.push((virt, host));
        }
        if expected != sandbox.fs_mount || expected_ro != sandbox.fs_mount_ro {
            return Err(format!(
                "policy field `fs_mount` did not land: provided {expected:?} ro {expected_ro:?}, \
                 effective {:?} ro {:?}",
                sandbox.fs_mount, sandbox.fs_mount_ro
            ));
        }
    }
    if prov.contains("clean_env") {
        check!("clean_env", &p.clean_env, &sandbox.clean_env);
    }
    if prov.contains("env") {
        check!("env", &p.env, &sandbox.env);
    }
    if prov.contains("uid") || prov.contains("gid") {
        let expected = RunAs {
            uid: p.uid.expect("uid provided"),
            gid: p.gid.expect("gid provided"),
        };
        if sandbox.user != Some(expected) {
            return Err(format!(
                "policy fields `uid`/`gid` did not land: provided {expected:?}, effective {:?}",
                sandbox.user
            ));
        }
    }
    check!("workdir", &p.workdir, &sandbox.workdir);
    check!("cwd", &p.cwd, &sandbox.cwd);
    check!("fs_storage", &p.fs_storage, &sandbox.fs_storage);
    if prov.contains("on_exit") {
        let expected = p.on_exit.expect("provided on_exit").into_branch();
        if sandbox.on_exit != expected {
            return Err(format!(
                "policy field `on_exit` did not land: provided {expected:?}, effective {:?}",
                sandbox.on_exit
            ));
        }
    }
    if prov.contains("on_error") {
        let expected = p.on_error.expect("provided on_error").into_branch();
        if sandbox.on_error != expected {
            return Err(format!(
                "policy field `on_error` did not land: provided {expected:?}, effective {:?}",
                sandbox.on_error
            ));
        }
    }
    if prov.contains("allow_degraded") || prov.contains("disable") {
        let mut expected_policy = ProtectionPolicy::default();
        for entry in &p.allow_degraded {
            expected_policy.set(
                protection_of(entry, "allow_degraded")?,
                ProtectionState::Degradable,
            );
        }
        for entry in &p.disable {
            expected_policy.set(protection_of(entry, "disable")?, ProtectionState::Disabled);
        }
        for protection in Protection::all() {
            if expected_policy.state(protection) != sandbox.protection_policy.state(protection) {
                return Err(format!(
                    "policy fields `allow_degraded`/`disable` did not land: \
                     provided {expected_policy:?}, effective {:?}",
                    sandbox.protection_policy
                ));
            }
        }
    }
    Ok(())
}

/// A full-field example policy document for tests: one distinctive value per
/// [`POLICY_FIELDS`] entry (except the four fields that cannot coexist with
/// their counterpart — `net_deny`, `net_deny_bind`, `port_remap`, plus the
/// always-compatible subset — which the unit probes below exercise
/// separately). `secret_path` backs the `http_inject` entry and must point
/// at an existing file (secrets resolve at build time).
pub fn example_policy_json(secret_path: &Path) -> String {
    let secret = format!("file:{}", secret_path.display());
    serde_json::json!({
        "fs_writable": ["/tmp/w"],
        "fs_readable": ["/usr/lib", "/etc"],
        "fs_denied": ["/proc/sys"],
        "extra_deny_syscalls": ["ptrace"],
        "extra_allow_syscalls": ["sysv_ipc"],
        "net_allow": ["tcp://1.1.1.1:443", "udp://1.1.1.1:53"],
        "net_deny": [],
        "net_allow_bind": [8080, "9000-9002"],
        "net_deny_bind": [],
        "http_allow": ["GET api.example.com/v1/*"],
        "http_deny": ["* */admin/*"],
        "http_ports": [80, 8443],
        "http_ca": "/etc/sandlock-ca.pem",
        "http_key": "/etc/sandlock-ca.key",
        "http_inject_ca": ["/etc/ssl/certs/ca-certificates.crt"],
        "http_ca_out": "/etc/sandlock-ca-out.pem",
        "host_mask": "localhost:${PORT}",
        "egress_proxy": {
            "address": "127.0.0.1:1080",
            "username": "socksuser",
            "password": "sockspass"
        },
        "http_inject": [{
            "matcher": "api.example.com",
            "auth": "bearer",
            "secret": secret,
            "name": "apikey",
            "on_existing": "add-only"
        }],
        "max_memory": "512M",
        "max_processes": 7,
        "max_open_files": 256,
        "max_file_size": "48M",
        "max_cpu": 42,
        "max_disk": "64M",
        "notify_rate_limit": 1000,
        "kernel_enforced_limits": true,
        "cpu_cores": [0, 2],
        "num_cpus": 4,
        "gpu_devices": [0],
        "port_remap": false,
        "pid_ns": true,
        // N35: the image-rootfs shape builds a real root instead of emulating
        // one. It belongs in this example for the same reason every other
        // manifest field does: `example_policy_json_covers_every_manifest_field`
        // and `full_field_policy_roundtrips` fail the moment the wire grows a
        // field the example does not carry (measured: these three tests were
        // red from the realroot commit until this line existed).
        "real_root": true,
        "net_isolation": true,
        "fd_inject_connect": true,
        "port_mappings": {"50005": 8080},
        "net_bind_inject": true,
        "random_seed": 42,
        "time_start": "2026-01-01T00:00:00Z",
        "no_randomize_memory": true,
        "no_huge_pages": true,
        "no_coredump": true,
        "deterministic_dirs": true,
        "chroot": "/jail",
        "fs_mount": ["/work:/host/work", "/data:/host/data:ro"],
        "clean_env": true,
        "env": {"SUPERVISE_TEST": "1"},
        "uid": 1234,
        "gid": 1234,
        "workdir": "/workdir",
        "cwd": "/cwd",
        "fs_storage": "/storage",
        "disk_stats_path": "/tmp/e2b-disk-stats",
        "on_exit": "abort",
        "on_error": "keep",
        "allow_degraded": ["fs-refer", "fs-truncate"],
        "disable": ["signal-scope"]
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Repo-local tmp dir (dev norm: no system /tmp).
    fn repo_tmp_dir() -> PathBuf {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let dir = manifest.join("../../tmp");
        std::fs::create_dir_all(&dir).expect("create repo tmp dir");
        dir
    }

    fn write_secret(name: &str) -> PathBuf {
        let path = repo_tmp_dir().join(format!("supervise-{name}-{}.secret", std::process::id()));
        std::fs::write(&path, "s3cret\n").expect("write test secret");
        path
    }

    #[test]
    fn example_policy_json_covers_every_manifest_field() {
        let secret = write_secret("manifest");
        let doc: serde_json::Value = serde_json::from_str(&example_policy_json(&secret)).unwrap();
        let keys: BTreeSet<&str> = doc
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let manifest: BTreeSet<&str> = POLICY_FIELDS.iter().copied().collect();
        assert_eq!(
            keys, manifest,
            "example policy must cover every manifest field"
        );
        let _ = std::fs::remove_file(&secret);
    }

    #[test]
    fn manifest_is_sorted_and_unique() {
        for pair in POLICY_FIELDS.windows(2) {
            assert!(pair[0] < pair[1], "POLICY_FIELDS must be sorted");
        }
    }

    #[test]
    fn full_field_policy_roundtrips() {
        let secret = write_secret("full");
        let json = example_policy_json(&secret);
        let parsed = parse(json.as_bytes()).expect("full-field policy parses");
        assert_eq!(
            parsed.provided.len(),
            POLICY_FIELDS.len(),
            "every manifest field must be provided in the example"
        );
        let sandbox = validate(json.as_bytes()).expect("full-field policy validates");

        // Spot-read a few read-back values so the error path is proven to
        // compare against the built Sandbox, not just to run.
        assert_eq!(
            sandbox.notify_rate_limit,
            Some(1000),
            "notify_rate_limit read-back"
        );
        assert_eq!(
            sandbox.kernel_enforced_limits,
            true,
            "kernel_enforced_limits read-back"
        );
        assert_eq!(sandbox.pid_ns, true);
        assert_eq!(sandbox.net_isolation, true);
        assert_eq!(sandbox.net_bind_map, vec![(50005, 8080)]);
        assert_eq!(
            sandbox.user,
            Some(RunAs {
                uid: 1234,
                gid: 1234
            })
        );
        assert_eq!(sandbox.on_exit, BranchAction::Abort);
        assert_eq!(sandbox.on_error, BranchAction::Keep);
        assert_eq!(sandbox.max_processes, 7);
        assert_eq!(
            sandbox.protection_policy.state(Protection::FsRefer),
            ProtectionState::Degradable
        );
        assert_eq!(
            sandbox.protection_policy.state(Protection::SignalScope),
            ProtectionState::Disabled
        );
        let _ = std::fs::remove_file(&secret);
    }

    #[test]
    fn exclusive_fields_land_in_isolation() {
        let deny_only = r#"{
            "net_deny": ["10.0.0.0/8", "169.254.169.254:80"]
        }"#;
        let sb = validate(deny_only.as_bytes()).expect("net_deny-only policy validates");
        assert!(!sb.net_deny.is_empty());

        let deny_bind_only = r#"{
            "net_deny_bind": [53, "8000-8002"]
        }"#;
        let sb = validate(deny_bind_only.as_bytes()).expect("net_deny_bind-only validates");
        assert_eq!(sb.net_deny_bind, vec![53, 8000, 8001, 8002]);

        let remap_only = r#"{
            "port_remap": true
        }"#;
        let sb = validate(remap_only.as_bytes()).expect("port_remap-only validates");
        assert!(sb.port_remap);
    }

    #[test]
    fn unknown_field_fails_by_name() {
        let err = validate(br#"{"fs_readable": ["/usr"], "bogus": 1}"#).unwrap_err();
        assert!(
            err.contains("`bogus`"),
            "unknown field must be named, got: {err}"
        );
    }

    #[test]
    fn explicitly_provided_default_is_distinguished_from_omitted() {
        // `max_processes: 64` and `clean_env: false` are explicitly provided
        // and must land (presence tracked from the key set, not value type).
        let doc = r#"{
            "max_processes": 64,
            "clean_env": false,
            "http_ports": [],
            "http_allow": ["GET a.example.com/*"]
        }"#;
        let parsed = parse(doc.as_bytes()).unwrap();
        assert!(parsed.provided.contains("max_processes"));
        assert!(parsed.provided.contains("clean_env"));
        let sb = validate(doc.as_bytes()).expect("explicit defaults validate");
        assert_eq!(sb.max_processes, 64);
        assert!(!sb.clean_env);
        // Empty http_ports next to http rules derives the builder default.
        assert_eq!(sb.http_ports, vec![80]);
    }

    #[test]
    fn explicit_null_is_unset_not_provided() {
        // A Python dataclass dump emits None fields as null; those must not
        // enter the provided set (and must not trip verify()).
        let doc = r#"{
            "fs_readable": ["/usr"],
            "max_memory": null,
            "egress_proxy": null,
            "time_start": null
        }"#;
        let parsed = parse(doc.as_bytes()).unwrap();
        assert!(parsed.provided.contains("fs_readable"));
        assert!(!parsed.provided.contains("max_memory"));
        assert!(!parsed.provided.contains("egress_proxy"));
        assert!(!parsed.provided.contains("time_start"));
        validate(doc.as_bytes()).expect("null fields must validate as unset");

        // Unknown keys still fail by name even when null.
        let err = validate(br#"{"bogus": null}"#).unwrap_err();
        assert!(err.contains("`bogus`"), "got: {err}");
    }

    #[test]
    fn http_inject_serializer_mirrors_python() {
        let rule = InjectRuleWire {
            matcher: Some("api.example.com".into()),
            auth: Some("bearer".into()),
            secret: Some("env:TOKEN".into()),
            name: Some("apikey".into()),
            on_existing: Some("add-only".into()),
        };
        let (name, secret, auth_rule) = serialize_http_inject(&rule, 0).unwrap();
        assert_eq!(name, "apikey");
        assert_eq!(secret, "env:TOKEN");
        assert_eq!(auth_rule, "* api.example.com/* bearer apikey add-only");

        let default_name = InjectRuleWire {
            matcher: Some("POST api.example.com/v1/*".into()),
            auth: Some("header:x-key".into()),
            secret: Some("file:/secret".into()),
            name: None,
            on_existing: None,
        };
        let (name, _, auth_rule) = serialize_http_inject(&default_name, 3).unwrap();
        assert_eq!(name, "inject3");
        assert_eq!(auth_rule, "POST api.example.com/v1/* header:x-key inject3");

        let bad = InjectRuleWire {
            matcher: Some("api.example.com".into()),
            auth: Some("basic:".into()),
            secret: Some("literal:sekrit".into()),
            name: None,
            on_existing: None,
        };
        assert!(serialize_http_inject(&bad, 0).is_err());
    }

    #[test]
    fn protection_names_and_discriminants_normalize() {
        let doc = r#"{
            "allow_degraded": ["net-tcp", "FS_TRUNCATE", 3],
            "disable": ["abstract-unix-socket-scope"]
        }"#;
        let sb = validate(doc.as_bytes()).expect("protection policy validates");
        assert_eq!(
            sb.protection_policy.state(Protection::NetTcp),
            ProtectionState::Degradable
        );
        assert_eq!(
            sb.protection_policy.state(Protection::FsTruncate),
            ProtectionState::Degradable
        );
        assert_eq!(
            sb.protection_policy.state(Protection::FsIoctlDev),
            ProtectionState::Degradable
        );
        assert_eq!(
            sb.protection_policy
                .state(Protection::AbstractUnixSocketScope),
            ProtectionState::Disabled
        );
        assert_eq!(
            sb.protection_policy.state(Protection::FsRefer),
            ProtectionState::Strict
        );
    }

    #[test]
    fn invalid_time_start_fails_by_field() {
        let err = validate(br#"{"time_start": "not-a-time"}"#).unwrap_err();
        assert!(
            err.contains("time_start"),
            "error must name time_start, got: {err}"
        );
    }

    #[test]
    fn invalid_bind_spec_fails_at_build_not_silently() {
        let err = validate(br#"{"net_deny_bind": ["9000-9002", "*"]}"#).unwrap_err();
        assert!(err.contains("policy"), "got: {err}");
    }

    #[test]
    fn egress_proxy_requires_both_credentials() {
        let err = validate(br#"{"egress_proxy": {"address": "127.0.0.1:1080", "username": "u"}}"#)
            .unwrap_err();
        assert!(err.contains("username and password"), "got: {err}");
    }

    #[test]
    fn egress_proxy_full_config_reads_back_equal() {
        // The post-build read-back is full-equality (address/username/
        // password), not an is_some marker: a password that lands on the
        // Sandbox differently from the provided wire value fails by name.
        let ok = validate(
            br#"{"egress_proxy": {
                "address": "127.0.0.1:1080",
                "username": "socksuser",
                "password": "sockspass"
            }}"#,
        )
        .expect("full egress config validates");
        let cfg = ok.egress_proxy.clone().expect("egress config landed");
        assert_eq!(cfg.address, "127.0.0.1:1080");
        assert_eq!(cfg.username.as_deref(), Some("socksuser"));
        assert_eq!(cfg.password.as_deref(), Some("sockspass"));

        // The F2b.1 gap was an is_some marker that could not see field drift
        // *inside* the config.  A post-build mismatch is structurally
        // impossible via the public apply path (the Sandbox stores the
        // literal config), so the negative pins verify()'s comparison
        // directly: a config whose password drifted after apply must fail
        // the read-back by name.
        let parsed = parse(
            br#"{"egress_proxy": {
                "address": "127.0.0.1:1080",
                "username": "u",
                "password": "p"
            }}"#,
        )
        .expect("parse");
        let mut sandbox = apply(&parsed).expect("apply").build().expect("build");
        sandbox.egress_proxy.as_mut().unwrap().password = Some("tampered".into());
        let err = verify(&sandbox, &parsed).unwrap_err();
        assert!(
            err.contains("egress_proxy"),
            "egress_proxy field drift must fail verify by name, got: {err}"
        );
    }

    /// SEC-K0S-006: the slot's own path -- a `--policy` document through
    /// parse/apply/build -- must land the disk accounting *and* put `statfs`
    /// in the notify list. If this passes and the deployment shape still shows
    /// host numbers, the gap is above the slot, not in it.
    #[test]
    fn disk_stats_path_lands_and_traps_statfs() {
        let doc = br#"{"disk_stats_path": "/tmp/e2b-disk-stats"}"#;
        let sandbox = validate(doc).expect("validate");
        assert_eq!(
            sandbox.disk_stats_path.as_deref(),
            Some(std::path::Path::new("/tmp/e2b-disk-stats"))
        );
        let nrs = sandlock_core::context::notif_syscalls(&sandbox, None);
        assert!(
            nrs.contains(&(libc::SYS_statfs as u32)),
            "SYS_statfs must be trapped when the accounting file is configured"
        );
        assert!(
            nrs.contains(&(libc::SYS_fstatfs as u32)),
            "SYS_fstatfs must be trapped too: `os.fstatvfs(fd)` takes the \
             fd-based sibling, which a path-only trap never sees"
        );
    }

    #[test]
    fn uid_and_gid_must_be_a_pair() {
        let err = validate(br#"{"uid": 1234}"#).unwrap_err();
        assert!(err.contains("uid and gid"), "got: {err}");
    }
}
