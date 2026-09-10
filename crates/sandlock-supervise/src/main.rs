//! `sandlock-supervise` — single-generation supervisor entry (fork route B).
//!
//! Startup contract (fork-plan F2b.1/F2b.3):
//!
//! ```text
//! sandlock-supervise --policy <fd|path.json> --uid <X> \
//!     (--control-fd <N> [--serve [--token TOKEN]]) | \
//!     (--serve-path NAME --token TOKEN [--peer-uid UID]...) \
//!     [--program <fd|path.json>]
//! ```
//!
//! 1. **uid self-check first**: the process refuses to start unless
//!    `geteuid() == X`, so a launcher that forgot to drop privileges cannot
//!    silently run the sandbox in the wrong identity class (route-B C-grade
//!    fallback).  This is the fork's whole identity boundary: *how* the
//!    process became uid X is the deployer's business (root launcher /
//!    file-cap launcher / pooled slot), never this binary's — it contains no
//!    setuid bit, no CAP_SETUID code, and no runtime uid re-map (see
//!    [`serve`](sandlock_supervise::serve) and
//!    `docs/supervise-identity-handoff.md`).
//! 2. **full-field policy**: the JSON policy (fd or path) is parsed and every
//!    provided field is applied and read back field-by-field; unknown,
//!    missing, or un-landed fields fail startup by name (see
//!    [`sandlock_supervise::policy`]).
//! 3. **serve transport — exactly one or none**:
//!    * `--control-fd N [--serve]`: the fd-handoff transport (transport 1).
//!      Without `--serve` the binary keeps the F2b.1 validate-and-exit
//!      behaviour (the control fd must still be an open AF_UNIX SOCK_STREAM,
//!      so a misconfigured launcher fails by name).
//!    * `--serve-path NAME --token TOKEN [--peer-uid UID]...`: the
//!      registered-path transport (transport 2) for a pooled slot.  The slot
//!      binds a hashed socket in the shared registry under its own uid and
//!      serves until a `shutdown` verb.
//! 4. **workload (F2b.3)**: `--program <fd|path.json>` provisions the
//!    generation's first process (`{"argv": [...]}`); when present the
//!    instance is launched from the full-field policy at serve start
//!    (launch-first) and instance-level verbs (`config`/`stats`/`ports`/
//!    `run`/`shutdown`) are served against the live
//!    [`SandboxInstance`](sandlock_core::SandboxInstance).

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::process::ExitCode;

use sandlock_core::control::RegisteredPathChannel;
use sandlock_supervise::serve::ProgramSpec;

#[derive(Debug, Clone)]
enum PolicySource {
    Fd(RawFd),
    Path(PathBuf),
}

impl std::str::FromStr for PolicySource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(fd) = s.parse::<RawFd>() {
            if fd < 0 {
                return Err("--policy fd must be a non-negative descriptor".into());
            }
            return Ok(PolicySource::Fd(fd));
        }
        let path = PathBuf::from(s);
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            Ok(PolicySource::Path(path))
        } else {
            Err("--policy must be an fd number or a path ending in .json".into())
        }
    }
}

#[derive(Parser)]
#[command(
    name = "sandlock-supervise",
    about = "Single-generation supervisor for one pre-provisioned sandlock sandbox",
    version
)]
struct Cli {
    /// Policy source: an already-open fd number or a path to a .json file.
    #[arg(long, value_name = "FD|PATH.json")]
    policy: PolicySource,

    /// Host uid this process must be running as. Startup is refused unless
    /// geteuid() == X (the launcher is responsible for dropping privileges).
    #[arg(long, value_name = "X")]
    uid: u32,

    /// Control-channel descriptor handed over by the launcher (F2b.2 fd
    /// transport). Required unless --serve-path is used.
    #[arg(long = "control-fd", value_name = "N")]
    control_fd: Option<RawFd>,

    /// Serve the fd-handoff control channel until a shutdown verb ends the
    /// generation (single-generation lifecycle).  Without this flag (and
    /// without --serve-path) the binary validates and exits (F2b.1
    /// behaviour).
    #[arg(long)]
    serve: bool,

    /// Serve the registered-path channel for a pooled slot (transport 2):
    /// bind a hashed socket in the shared registry and accept worker
    /// connections until a shutdown verb.  Requires --token.
    #[arg(long = "serve-path", value_name = "NAME")]
    serve_path: Option<String>,

    /// Per-generation channel token for the fd transport (the belt over the
    /// fd credential) — and REQUIRED for --serve-path, where the worker must
    /// have been provisioned with the same token out-of-band.
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,

    /// Registered-path worker peer uid allowlist (repeatable).  Empty =
    /// same-uid-only special case (single-machine mode); route B slots pass
    /// the worker uid (conventionally 65534) here.
    #[arg(long = "peer-uid", value_name = "UID")]
    peer_uid: Vec<u32>,

    /// Workload program spec (F2b.3 launch-first): an already-open fd number
    /// or a path to a .json file containing `{"argv": [...]}`.
    #[arg(long, value_name = "FD|PATH.json")]
    program: Option<PolicySource>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sandlock-supervise: {err:#}");
            // Return (rather than process::exit) so destructors run — a
            // registered-path slot must clean its socket/dir even on error.
            ExitCode::FAILURE
        }
    }
}

/// Which serve transport (if any) this invocation uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServeMode {
    /// F2b.1 validate-and-exit.
    None,
    /// Transport 1: serve the handed-over control fd.
    Fd,
    /// Transport 2: serve a registered-path slot.
    Path,
}

fn run(cli: Cli) -> Result<()> {
    // 1. Identity self-check — before touching the policy transport.
    let euid = unsafe { libc::geteuid() };
    if euid != cli.uid {
        bail!(
            "refusing to start: euid {} does not match --uid {}; \
             the launcher must drop privileges before exec (otherwise the \
             sandbox would silently run in the wrong identity class)",
            euid,
            cli.uid
        );
    }

    // Serve mode validation (mutually exclusive transports).
    let mode = match (cli.serve, cli.serve_path.as_deref()) {
        (false, None) => ServeMode::None,
        (true, None) => ServeMode::Fd,
        (false, Some(_)) => ServeMode::Path,
        (true, Some(_)) => {
            bail!("refusing to start: --serve and --serve-path are mutually exclusive")
        }
    };
    if mode == ServeMode::Path && cli.control_fd.is_some() {
        bail!(
            "refusing to start: --serve-path uses the registered path transport; \
             --control-fd belongs to the fd-handoff transport"
        );
    }
    if mode != ServeMode::Path && cli.control_fd.is_none() {
        bail!("refusing to start: --control-fd N is required unless --serve-path NAME is used");
    }
    if mode == ServeMode::Path {
        let token = cli.token.as_deref().unwrap_or_default();
        if token.is_empty() {
            bail!(
                "refusing to start: --serve-path requires --token (the worker must have been \
                 provisioned with the same token out-of-band; supervise never prints a \
                 generated one)"
            );
        }
    }

    // 2. Full-field policy read + validate (parse → apply → field-by-field
    //    read-back; failures name the offending field).  The fd transport
    //    applies a timeout and a hard size cap so a stuck or oversized
    //    startup document cannot hang or silently truncate.
    let bytes = read_document(&cli.policy).context("policy read failed")?;
    let mut sandbox = sandlock_supervise::policy::validate(&bytes)
        .map_err(|e| anyhow::anyhow!("policy rejected: {e}"))?;

    // 3. Optional workload program spec (launch-first; parse failures name
    //    the field, same fail-closed posture as the policy).
    let program = match &cli.program {
        Some(source) => {
            let bytes = read_document(source).context("program read failed")?;
            Some(
                ProgramSpec::from_json(&bytes)
                    .map_err(|e| anyhow::anyhow!("program rejected: {e}"))?,
            )
        }
        None => None,
    };
    // F18: an unprivileged mediator *is* the sandbox uid, so the privileged
    // `0 -> host_uid` map cannot be written for the child. Self-map instead --
    // the same in-guest identity a privileged supervisor produces -- and only
    // when the kernel actually allows an unprivileged userns. Logged, because
    // it changes what a workload can do inside (`apt-get`, `chown`, low ports);
    // the worker sees the same answer in `stats.guest_uid`.
    if euid != 0 && sandbox.user.is_some() {
        sandbox.userns_self_map = sandlock_supervise::serve::probe_userns_self_map();
    }
    // Which shape the guest got is reported through `stats.guest_uid`
    // (`uid-0-in-userns` / `host-uid`) rather than stderr: a clean startup must
    // stay silent (`test_policy_roundtrip_covers_every_field` pins that), and
    // the worker is the party that needs to know -- it logs the value with the
    // lease.
    let policy = std::sync::Arc::new(sandbox);

    match mode {
        ServeMode::None => {
            // F2b.1 validate-and-exit: the handed-over control descriptor
            // must at least be an open AF_UNIX SOCK_STREAM (a misconfigured
            // launcher fails by name instead of silently exiting 0).
            check_control_fd(cli.control_fd.expect("required outside path mode"))?;
            Ok(())
        }
        ServeMode::Fd => {
            let control_fd = cli.control_fd.expect("required in fd mode");
            check_control_fd(control_fd)?;
            sandlock_supervise::serve::serve_control_fd(
                control_fd,
                policy,
                program,
                cli.token.as_deref(),
            )
            .map_err(anyhow::Error::msg)
        }
        ServeMode::Path => {
            let name = cli.serve_path.as_deref().expect("path mode has a name");
            let token = cli.token.as_deref().expect("required in path mode");
            // Route B pooled slot: bind the registered channel FIRST so the
            // worker can connect while the instance is being launched; the
            // channel's Drop (process exit, either way) removes socket+dir.
            let channel = RegisteredPathChannel::bind_with_token(name, cli.peer_uid.clone(), token)
                .with_context(|| format!("bind registered path channel {name:?}"))?;
            let listener = channel.listener();
            sandlock_supervise::serve::serve_registered_path(
                &listener,
                token,
                &cli.peer_uid,
                policy,
                program,
            )
            .map_err(anyhow::Error::msg)
        }
    }
}

/// Validate the handed-over control descriptor: it must be open, a
/// `SOCK_STREAM` socket, and — the F2b.3 fail-safe — an `AF_UNIX` socket.
/// An AF_INET/AF_INET6 stream socket would otherwise pass the SO_TYPE check
/// and be served as if it were the unix control channel.
fn check_control_fd(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        bail!(
            "control fd {} is not open: {}",
            fd,
            std::io::Error::last_os_error()
        );
    }
    {
        let mut sock_type: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut sock_type as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            bail!(
                "control fd {} is not a socket: {}",
                fd,
                std::io::Error::last_os_error()
            );
        }
        if sock_type != libc::SOCK_STREAM {
            bail!(
                "control fd {} is a {} socket, not SOCK_STREAM: \
                 the fd transport serves a connected stream socketpair end",
                fd,
                sock_type
            );
        }
    }
    {
        let mut domain: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                &mut domain as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            bail!(
                "control fd {}: SO_DOMAIN unavailable: {}",
                fd,
                std::io::Error::last_os_error()
            );
        }
        if domain != libc::AF_UNIX {
            bail!(
                "control fd {} is an AF_{} stream socket, not AF_UNIX: \
                 the fd transport serves the unix control socketpair end",
                fd,
                domain_name(domain)
            );
        }
    }
    Ok(())
}

fn domain_name(domain: libc::c_int) -> String {
    match domain {
        libc::AF_INET => "INET".to_string(),
        libc::AF_INET6 => "INET6".to_string(),
        libc::AF_UNIX => "UNIX".to_string(),
        other => format!("{other}"),
    }
}

fn read_document(source: &PolicySource) -> Result<Vec<u8>> {
    match source {
        PolicySource::Fd(fd) => {
            // Test hook: the fd-policy deadline is overridable so the timeout
            // path is exercised in milliseconds, not seconds.
            let timeout_ms = std::env::var("SANDBOX_SUPERVISE_POLICY_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or_else(|| sandlock_supervise::serve::POLICY_FD_TIMEOUT.as_millis() as u64);
            sandlock_supervise::serve::read_policy_fd(
                *fd,
                std::time::Duration::from_millis(timeout_ms),
            )
            .map_err(anyhow::Error::msg)
        }
        PolicySource::Path(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("read policy file {}", path.display()))?;
            Ok(bytes)
        }
    }
}
