//! `sandlock-supervise` — single-generation supervisor entry (fork route B).
//!
//! Startup contract (fork-plan F2b.1):
//!
//! ```text
//! sandlock-supervise --policy <fd|path.json> --uid <X> --control-fd <N>
//! ```
//!
//! 1. **uid self-check first**: the process refuses to start unless
//!    `geteuid() == X`, so a launcher that forgot to drop privileges cannot
//!    silently run the sandbox in the wrong identity class (route-B C-grade
//!    fallback).
//! 2. **full-field policy**: the JSON policy (fd or path) is parsed and every
//!    provided field is applied and read back field-by-field; unknown,
//!    missing, or un-landed fields fail startup by name (see
//!    [`sandlock_supervise::policy`]).
//! 3. **control fd**: `--control-fd N` must name an open descriptor (the
//!    launcher's side of the F2b.2 control socketpair).
//!
//! F2b.2 (single generation): with `--serve` the validated policy is kept
//! and the handed-over control fd is served until a `shutdown` verb ends the
//! generation (exit 0).  Without `--serve` the binary keeps the F2b.1
//! validate-and-exit behaviour.

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

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

    /// Control-channel descriptor handed over by the launcher (F2b.2).
    #[arg(long = "control-fd", value_name = "N")]
    control_fd: RawFd,

    /// Serve the control channel until a shutdown verb ends the generation
    /// (single-generation lifecycle).  Without this flag the binary
    /// validates and exits (F2b.1 behaviour).
    #[arg(long)]
    serve: bool,

    /// Optional per-generation channel token for the fd transport (the belt
    /// over the fd credential).  When set, every control verb must carry it.
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("sandlock-supervise: {err:#}");
        std::process::exit(1);
    }
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

    // 2. Full-field policy read + validate (parse → apply → field-by-field
    //    read-back; failures name the offending field).  The fd transport
    //    applies a timeout and a hard size cap so a stuck or oversized
    //    startup document cannot hang or silently truncate.
    let bytes = read_policy(&cli.policy).context("policy read failed")?;
    let sandbox = sandlock_supervise::policy::validate(&bytes)
        .map_err(|e| anyhow::anyhow!("policy rejected: {e}"))?;

    // 3. Control descriptor must be open.
    let flags = unsafe { libc::fcntl(cli.control_fd, libc::F_GETFD) };
    if flags == -1 {
        bail!(
            "control fd {} is not open: {}",
            cli.control_fd,
            std::io::Error::last_os_error()
        );
    }

    // F2b.2: single generation.  Serve the control channel (fd handoff
    // transport) until shutdown; then the process exits 0.
    if cli.serve {
        let outcome = sandlock_supervise::serve::serve_control_fd(
            cli.control_fd,
            &sandbox,
            cli.token.as_deref(),
        );
        if outcome == sandlock_core::control::ServeOutcome::Shutdown {
            return Ok(());
        }
        bail!("control channel ended without a shutdown verb");
    }

    // F2b.1 validate-and-exit behaviour (kept for callers that only want the
    // startup gate).
    Ok(())
}

fn read_policy(source: &PolicySource) -> Result<Vec<u8>> {
    match source {
        PolicySource::Fd(fd) => {
            // Test hook: the fd-policy deadline is overridable so the timeout
            // path is exercised in milliseconds, not seconds.
            let timeout_ms = std::env::var("SANDBOX_SUPERVISE_POLICY_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or_else(|| {
                    sandlock_supervise::serve::POLICY_FD_TIMEOUT.as_millis() as u64
                });
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
