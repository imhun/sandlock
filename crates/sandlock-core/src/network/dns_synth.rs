//! Synthetic DNS: hostname ↔ synthetic-IP mapping for wildcard-domain
//! rules (`*.example.com`).
//!
//! The sandbox's DNS path resolves a wildcard subdomain to a synthetic
//! loopback IP; the on-behalf connect handler reverse-looks the hostname
//! and matches it against the wildcard rules, then resolves the real
//! address supervisor-side. This module owns the mapping table and the
//! synthetic-address range; it contains no syscall handling so the
//! allocation and LRU behavior is unit-testable.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tokio::sync::RwLock;

/// Default maximum number of hostname→IP mappings per sandbox. Bounds the
/// supervisor memory a sandbox can force through unique-hostname lookups.
pub const DEFAULT_CAPACITY: usize = 4096;

/// First synthetic address (inclusive): `127.0.0.2`. The `127.0.0.2/8`
/// block is reserved for synthetic DNS; `127.0.0.1` stays the plain
/// loopback address. This is the same range the (to-be-retired)
/// LD_PRELOAD egress library used, so one semantic applies across both
/// enforcement paths.
const SYNTHETIC_BASE: u32 = 0x7f00_0002;
/// Last usable synthetic address (inclusive): `127.255.255.254`
/// (`127.255.255.255` is the broadcast address).
const SYNTHETIC_END: u32 = 0x7fff_fffe;

/// One mapping entry: the hostname plus the generation counter of its
/// last use, for LRU eviction.
struct Entry {
    hostname: String,
    last_used: u64,
}

struct State {
    by_ip: HashMap<IpAddr, Entry>,
    by_hostname: HashMap<String, IpAddr>,
    next: u32,
    generation: u64,
}

/// Thread-safe hostname ↔ synthetic-IP mapping with an LRU cap.
///
/// `resolve` allocates addresses from the synthetic range and records the
/// hostname; `hostname_for` reverse-looks an address (and refreshes its
/// recency). When the table is full, the least-recently-used entry is
/// evicted first, so a sandbox cannot pin the supervisor's memory.
#[derive(Clone)]
pub struct SyntheticDns {
    inner: Arc<RwLock<State>>,
    capacity: usize,
}

impl SyntheticDns {
    /// A mapping table with [`DEFAULT_CAPACITY`] entries.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// A mapping table with a custom LRU cap (clamped to at least 1).
    pub fn with_capacity(capacity: usize) -> Self {
        SyntheticDns {
            inner: Arc::new(RwLock::new(State {
                by_ip: HashMap::new(),
                by_hostname: HashMap::new(),
                next: SYNTHETIC_BASE,
                generation: 0,
            })),
            capacity: capacity.max(1),
        }
    }

    /// The configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of live mappings.
    pub async fn len(&self) -> usize {
        self.inner.read().await.by_ip.len()
    }

    /// True iff there are no live mappings.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Return the synthetic IP for `hostname`, allocating and recording a
    /// fresh mapping when this is the first sighting. Returns `None` only
    /// when the synthetic range is exhausted (fail closed — callers must
    /// refuse the lookup rather than fall back to real DNS).
    pub async fn resolve(&self, hostname: &str) -> Option<IpAddr> {
        let hostname = hostname.to_ascii_lowercase();
        let mut st = self.inner.write().await;
        if let Some(&ip) = st.by_hostname.get(&hostname) {
            let gen = st.generation;
            st.by_ip
                .get_mut(&ip)
                .expect("by_ip/by_hostname out of sync")
                .last_used = gen;
            st.generation = gen.wrapping_add(1);
            return Some(ip);
        }
        if st.by_ip.len() >= self.capacity {
            evict_lru(&mut st);
        }
        if st.next > SYNTHETIC_END {
            return None;
        }
        let ip = IpAddr::V4(Ipv4Addr::from(st.next));
        st.next += 1;
        let gen = st.generation;
        st.by_ip.insert(
            ip,
            Entry {
                hostname: hostname.clone(),
                last_used: gen,
            },
        );
        st.by_hostname.insert(hostname, ip);
        st.generation = gen.wrapping_add(1);
        Some(ip)
    }

    /// Reverse-lookup the hostname for a synthetic address. Returns `None`
    /// when the address is unknown — the caller must treat a direct
    /// connect to an unregistered synthetic address as a refusal, so the
    /// synthetic range can never be used to bypass literal rules.
    pub async fn hostname_for(&self, ip: IpAddr) -> Option<String> {
        let mut st = self.inner.write().await;
        let (gen, hostname) = {
            let gen = st.generation;
            let entry = st.by_ip.get_mut(&ip)?;
            entry.last_used = gen;
            (gen, entry.hostname.clone())
        };
        st.generation = gen.wrapping_add(1);
        Some(hostname)
    }

    /// True iff `ip` lies in the reserved synthetic range
    /// (`127.0.0.2/8`).
    pub fn is_synthetic_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let n = u32::from(v4);
                (SYNTHETIC_BASE..=SYNTHETIC_END).contains(&n)
            }
            IpAddr::V6(_) => false,
        }
    }
}

/// Evict the least-recently-used mapping (lowest `last_used`).
fn evict_lru(st: &mut State) {
    let victim = st
        .by_ip
        .iter()
        .min_by_key(|(_, e)| e.last_used)
        .map(|(ip, e)| (*ip, e.hostname.clone()));
    if let Some((ip, hostname)) = victim {
        st.by_ip.remove(&ip);
        st.by_hostname.remove(&hostname);
    }
}

/// Match `hostname` against a `*.suffix` wildcard rule: any subdomain of
/// `suffix` matches, the bare `suffix` itself does not, and a name that
/// merely ends in the suffix characters (e.g. `badexample.com` for
/// `example.com`) does not either. DNS names are case-insensitive.
pub fn wildcard_suffix_matches(hostname: &str, suffix: &str) -> bool {
    let hostname = hostname.to_ascii_lowercase();
    let suffix = suffix.to_ascii_lowercase();
    if hostname.len() <= suffix.len() {
        return false;
    }
    let before = hostname.len() - suffix.len() - 1;
    hostname.ends_with(&suffix)
        && hostname.as_bytes().get(before) == Some(&b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_allocates_unique_addresses_in_range() {
        let dns = SyntheticDns::new();
        let a = dns.resolve("api.example.com").await.unwrap();
        let b = dns.resolve("b.example.com").await.unwrap();
        assert!(SyntheticDns::is_synthetic_ip(a));
        assert!(SyntheticDns::is_synthetic_ip(b));
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn resolve_is_idempotent_per_hostname() {
        let dns = SyntheticDns::new();
        let a = dns.resolve("api.example.com").await.unwrap();
        let b = dns.resolve("api.example.com").await.unwrap();
        assert_eq!(a, b);
        assert_eq!(dns.len().await, 1);
    }

    #[tokio::test]
    async fn hostname_for_reverse_lookup_roundtrip() {
        let dns = SyntheticDns::new();
        let ip = dns.resolve("a.b.example.com").await.unwrap();
        assert_eq!(
            dns.hostname_for(ip).await.as_deref(),
            Some("a.b.example.com")
        );
        assert_eq!(dns.hostname_for("8.8.8.8".parse().unwrap()).await, None);
    }

    #[tokio::test]
    async fn lru_evicts_least_recently_used() {
        let dns = SyntheticDns::with_capacity(2);
        let a = dns.resolve("a.example.com").await.unwrap();
        let b = dns.resolve("b.example.com").await.unwrap();
        // Touch `a` so `b` becomes the least-recently-used entry.
        dns.hostname_for(a).await;
        let c = dns.resolve("c.example.com").await.unwrap();
        assert!(SyntheticDns::is_synthetic_ip(c));
        assert_eq!(dns.len().await, 2);
        assert_eq!(dns.hostname_for(b).await, None, "b should be evicted");
        assert_eq!(dns.hostname_for(a).await.as_deref(), Some("a.example.com"));
        assert_eq!(dns.hostname_for(c).await.as_deref(), Some("c.example.com"));
    }

    #[test]
    fn is_synthetic_ip_boundaries() {
        assert!(SyntheticDns::is_synthetic_ip("127.0.0.2".parse().unwrap()));
        assert!(SyntheticDns::is_synthetic_ip("127.255.255.254".parse().unwrap()));
        assert!(!SyntheticDns::is_synthetic_ip("127.0.0.1".parse().unwrap()));
        assert!(!SyntheticDns::is_synthetic_ip("127.255.255.255".parse().unwrap()));
        assert!(!SyntheticDns::is_synthetic_ip("8.8.8.8".parse().unwrap()));
        assert!(!SyntheticDns::is_synthetic_ip("::1".parse().unwrap()));
    }

    #[test]
    fn wildcard_suffix_matches_subdomains_but_not_bare_or_partial() {
        let suffix = "example.com";
        assert!(wildcard_suffix_matches("api.example.com", suffix));
        assert!(wildcard_suffix_matches("a.b.example.com", suffix));
        assert!(!wildcard_suffix_matches("example.com", suffix), "bare domain excluded");
        assert!(!wildcard_suffix_matches("badexample.com", suffix), "partial suffix must not match");
        assert!(!wildcard_suffix_matches("other.org", suffix));
    }

    #[test]
    fn wildcard_suffix_matches_is_case_insensitive() {
        assert!(wildcard_suffix_matches("API.Example.COM", "example.com"));
        assert!(wildcard_suffix_matches("api.example.com", "EXAMPLE.com"));
    }
}
