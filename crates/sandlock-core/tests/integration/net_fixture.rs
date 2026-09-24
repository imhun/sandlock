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
    mapping_in(&std::fs::read_to_string("/etc/hosts").ok()?, host)
}

/// The `host` -> address mapping in an `/etc/hosts` body, if any.
///
/// Every line that does not carry at least two whitespace-separated fields is
/// *skipped*. It used to end the scan instead (`it.next()?` returned `None`
/// from the whole function), and a stock Ubuntu `/etc/hosts` has a blank line
/// right after `127.0.0.1 localhost` -- measured on the aarch64 lane
/// (2026-09-24): the pre-seeded entry was present and parseable, yet the
/// fixture still reported "no pre-seeded /etc/hosts entry" and fell back to
/// the privileged path, where a non-root run then dies on `ip addr add` with
/// EPERM.
fn mapping_in(hosts: &str, host: &str) -> Option<Ipv4Addr> {
    for line in hosts.lines() {
        let mut it = line.split_whitespace();
        let (Some(addr), Some(name)) = (it.next(), it.next()) else {
            continue;
        };
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

#[cfg(test)]
mod tests {
    use super::mapping_in;
    use std::net::Ipv4Addr;

    /// The stock Ubuntu `/etc/hosts`: a blank line right after the localhost
    /// entry (and a comment block), then the pre-seeded benchmarking-range
    /// mappings the container entrypoint appends.
    const UBUNTU_STYLE: &str = "\
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
198.18.0.99 conn.example.com
198.18.0.100 api.egress.test
";

    #[test]
    fn mapping_rides_over_blank_lines() {
        assert_eq!(
            mapping_in(UBUNTU_STYLE, "conn.example.com"),
            Some(Ipv4Addr::new(198, 18, 0, 99))
        );
        assert_eq!(
            mapping_in(UBUNTU_STYLE, "api.egress.test"),
            Some(Ipv4Addr::new(198, 18, 0, 100))
        );
    }

    #[test]
    fn mapping_ignores_a_host_that_is_not_there() {
        assert_eq!(mapping_in(UBUNTU_STYLE, "other.example.com"), None);
    }

    #[test]
    fn mapping_ignores_an_unparsable_address() {
        assert_eq!(
            mapping_in("not-an-ip  conn.example.com\n", "conn.example.com"),
            None
        );
    }
}
