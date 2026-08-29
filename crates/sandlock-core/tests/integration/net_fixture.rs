//! Shared network fixtures for the integration suite.
//!
//! The wildcard/egress tests need a hostname that deterministically resolves
//! to a local address without touching external DNS. Two setups are
//! supported:
//!
//! 1. **Privileged** (root + `CAP_NET_ADMIN`): allocate a fresh `198.18.0.x`
//!    address, put it on loopback and append a `/etc/hosts` line; Drop
//!    removes exactly that entry (concurrency-safe).
//! 2. **Unprivileged**: the container entrypoint pre-seeds the fixture
//!    hostnames + loopback addresses once as root; this fixture then *reads*
//!    the pre-seeded mapping instead of mutating the system. This is what
//!    keeps the whole suite runnable as a normal uid — sandlock's own
//!    unprivileged principle.

use std::net::Ipv4Addr;
use std::sync::Mutex;

static HOST_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

/// Worker-side fixture: map `host` to a `198.18.0.x` loopback address
/// (benchmarking range, allowed by the SSRF guard).
pub struct WorkerLocalHost {
    ip: Ipv4Addr,
    host: String,
    owned: bool,
}

impl WorkerLocalHost {
    /// Return the fixture for `host`, reusing a pre-seeded `/etc/hosts`
    /// mapping when present (unprivileged mode) or allocating + registering
    /// one when the environment is privileged.
    pub fn setup(host: &str) -> Self {
        let _g = HOST_FIXTURE_LOCK.lock().unwrap();

        // 1. Pre-seeded mapping (container entrypoint, root): reuse as-is.
        if let Some(ip) = existing_mapping(host) {
            return WorkerLocalHost {
                ip,
                host: host.to_string(),
                owned: false,
            };
        }

        // 2. Privileged path: allocate the first free 198.18.0.x and register
        //    it (address on lo + /etc/hosts line). Drop undoes exactly this.
        let mut ip = Ipv4Addr::new(198, 18, 0, 99);
        loop {
            let ip_str = format!("{}/32", ip);
            let ok = std::process::Command::new("ip")
                .args(["addr", "add", ip_str.as_str(), "dev", "lo"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                break;
            }
            let o = ip.octets();
            assert!(
                o[3] < 254,
                "no free 198.18.0.x address for {host} and no pre-seeded \
                 /etc/hosts entry — run the test container entrypoint (root \
                 prep) so the unprivileged fixtures exist"
            );
            ip = Ipv4Addr::new(198, 18, 0, o[3] + 1);
        }
        let mut hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
        hosts.push_str(&format!("{} {}\n", ip, host));
        std::fs::write("/etc/hosts", hosts)
            .expect("write /etc/hosts (privileged fixture)");
        WorkerLocalHost {
            ip,
            host: host.to_string(),
            owned: true,
        }
    }

    pub fn addr(&self) -> Ipv4Addr {
        self.ip
    }
}

impl Drop for WorkerLocalHost {
    fn drop(&mut self) {
        if !self.owned {
            // Pre-seeded entry: shared with the container, leave it alone.
            return;
        }
        let _g = HOST_FIXTURE_LOCK.lock().unwrap();
        if let Ok(hosts) = std::fs::read_to_string("/etc/hosts") {
            let filtered: Vec<&str> = hosts
                .lines()
                .filter(|l| !l.trim().ends_with(self.host.as_str()))
                .collect();
            let _ = std::fs::write("/etc/hosts", filtered.join("\n") + "\n");
        }
        let ip_str = format!("{}/32", self.ip);
        let _ = std::process::Command::new("ip")
            .args(["addr", "del", ip_str.as_str(), "dev", "lo"])
            .status();
    }
}

/// The first `198.18.0.x <host>` line in `/etc/hosts`, if any.
fn existing_mapping(host: &str) -> Option<Ipv4Addr> {
    let hosts = std::fs::read_to_string("/etc/hosts").ok()?;
    for line in hosts.lines() {
        let mut it = line.split_whitespace();
        let (addr, name) = (it.next()?, it.next()?);
        if name == host {
            if let Ok(ip) = addr.parse::<Ipv4Addr>() {
                return Some(ip);
            }
        }
    }
    None
}

/// Whether the environment can create veth/links (per-sandbox netns tests).
/// Requires `CAP_NET_ADMIN` — the one privileged, opt-in feature set.
pub fn net_admin_available() -> bool {
    let ok = std::process::Command::new("ip")
        .args(["link", "add", "slk-probe0", "type", "dummy"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        let _ = std::process::Command::new("ip")
            .args(["link", "del", "slk-probe0"])
            .status();
    }
    ok
}
