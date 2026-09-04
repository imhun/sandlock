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
//! F2b.1 validates and stands ready; the actual serve loop (and this
//! process staying alive to serve it) lands with F2b.2/F2b.3.

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::io::Read;
use std::os::fd::FromRawFd;
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
    //    read-back; failures name the offending field).
    let bytes = read_policy(&cli.policy).context("policy read failed")?;
    sandlock_supervise::policy::validate(&bytes)
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

    // F2b.1: validated and standing ready; serve lands in F2b.2/F2b.3.
    Ok(())
}

fn read_policy(source: &PolicySource) -> Result<Vec<u8>> {
    match source {
        PolicySource::Fd(fd) => {
            let file = unsafe { std::fs::File::from_raw_fd(*fd) };
            let mut bytes = Vec::new();
            file.take(16 * 1024 * 1024)
                .read_to_end(&mut bytes)
                .with_context(|| format!("read policy from fd {fd}"))?;
            Ok(bytes)
        }
        PolicySource::Path(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("read policy file {}", path.display()))?;
            Ok(bytes)
        }
    }
}
