//! Per-sandbox DNS gateway.
//!
//! The sandbox's virtual `/etc/resolv.conf` points at the gateway address
//! (a per-sandbox loopback `127.0.1.x`). The gateway answers A queries for
//! wildcard-domain suffixes with a synthetic IP from the sandbox's
//! [`SyntheticDns`] map; every other query gets a REFUSED so the sandbox
//! fails fast instead of leaking DNS or hanging. Refusing non-wildcard names
//! also means the sandbox never performs real DNS for
//! destinations it is not allowed to reach — the resolver only ever learns
//! of hostnames that match an explicit allow rule.
//!
//! The wire handling is deliberately tiny (RFC 1035 header + one question,
//! A-record answers, no compression on the query side, a name pointer in
//! the answer), which keeps it unit-testable without a DNS crate.

use crate::seccomp::notif::PortAllow;

use super::dns_synth::{wildcard_suffix_matches, SyntheticDns};

/// Maximum UDP DNS payload we accept/emit (RFC 1035 classic limit; a
/// single A record fits comfortably).
const MAX_DNS_PACKET: usize = 512;

const DNS_HEADER_LEN: usize = 12;
const QTYPE_A: u16 = 1;
const QCLASS_IN: u16 = 1;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
const RCODE_REFUSED: u16 = 5;
const FLAG_QR: u16 = 0x8000;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;

/// One parsed A query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub id: u16,
    /// Lowercased query name without the trailing root dot.
    pub qname: String,
}

/// Parse an RFC 1035 query with exactly one question. Returns `None` for
/// multi-question, malformed, or non-A/IN questions.
pub fn parse_query(buf: &[u8]) -> Option<DnsQuery> {
    if buf.len() < DNS_HEADER_LEN + 5 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount != 1 {
        return None;
    }
    let mut pos = DNS_HEADER_LEN;
    let mut labels = Vec::new();
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 || pos + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[pos..pos + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        pos += len;
    }
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    if qtype != QTYPE_A || qclass != QCLASS_IN {
        return None;
    }
    Some(DnsQuery {
        id,
        qname: labels.join("."),
    })
}

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Build a response that echoes the question and answers with an A record
/// for `ip`. TTL is 0 so clients never cache the synthetic mapping past the
/// lookup (network-rule updates take effect on the next query).
pub fn build_a_response(query: &DnsQuery, ip: std::net::Ipv4Addr) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_DNS_PACKET);
    push_u16(&mut out, query.id);
    push_u16(&mut out, FLAG_QR | FLAG_RD | FLAG_RA); // QR + RD + RA; NOERROR
    push_u16(&mut out, 1); // QDCOUNT
    push_u16(&mut out, 1); // ANCOUNT
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    // Question (echo).
    for label in query.qname.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    push_u16(&mut out, QTYPE_A);
    push_u16(&mut out, QCLASS_IN);
    // Answer: name pointer to offset 12, A record, TTL 0.
    push_u16(&mut out, 0xC00C);
    push_u16(&mut out, TYPE_A);
    push_u16(&mut out, CLASS_IN);
    push_u32(&mut out, 60);
    push_u16(&mut out, 4);
    out.extend_from_slice(&ip.octets());
    out
}

/// Build a minimal REFUSED response for `id`.
pub fn build_refused(id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(DNS_HEADER_LEN);
    push_u16(&mut out, id);
    push_u16(&mut out, FLAG_QR | RCODE_REFUSED);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    out
}

/// Handle one datagram against the sandbox's wildcard suffixes: matched A
/// queries get a synthetic-IP answer, everything else gets REFUSED.
pub async fn handle_query(
    buf: &[u8],
    suffixes: &[(String, PortAllow)],
    dns: &SyntheticDns,
) -> Vec<u8> {
    let Some(query) = parse_query(buf) else {
        return build_refused(id_of_or_zero(buf));
    };
    let matched = suffixes
        .iter()
        .any(|(suffix, _)| wildcard_suffix_matches(&query.qname, suffix));
    if !matched {
        return build_refused(query.id);
    }
    match dns.resolve(&query.qname).await {
        Some(std::net::IpAddr::V4(v4)) => build_a_response(&query, v4),
        Some(std::net::IpAddr::V6(_)) => build_refused(query.id),
        None => build_refused(query.id),
    }
}

fn id_of_or_zero(buf: &[u8]) -> u16 {
    if buf.len() >= 2 {
        u16::from_be_bytes([buf[0], buf[1]])
    } else {
        0
    }
}

/// Serve the gateway loop until the socket is closed.
pub async fn run_dns_gateway(
    socket: tokio::net::UdpSocket,
    suffixes: Vec<(String, PortAllow)>,
    dns: SyntheticDns,
    upstream: Option<std::net::SocketAddr>,
) {
    let mut buf = [0u8; MAX_DNS_PACKET];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let matched = parse_query(&buf[..n]).map_or(false, |q| {
            suffixes
                .iter()
                .any(|(suffix, _)| wildcard_suffix_matches(&q.qname, suffix))
        });
        let resp = if matched {
            handle_query(&buf[..n], &suffixes, &dns).await
        } else if let Some(up) = upstream {
            match forward_query(up, &buf[..n]).await {
                Some(relayed) => relayed,
                None => build_refused(id_of_or_zero(&buf[..n])),
            }
        } else {
            build_refused(id_of_or_zero(&buf[..n]))
        };
        let _ = socket.send_to(&resp, peer).await;
    }
}

/// Relay one DNS query to `upstream` and return the response, or `None` on
/// timeout/error (the sandbox then gets a REFUSED, fail closed).
async fn forward_query(upstream: std::net::SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    let sock = tokio::net::UdpSocket::bind(
        std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
    )
    .await
    .ok()?;
    sock.send_to(query, upstream).await.ok()?;
    let mut buf = [0u8; MAX_DNS_PACKET];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(buf[..n].to_vec())
}

/// Read the worker's upstream resolver from `/etc/resolv.conf` (first IPv4
/// `nameserver` line). The gateway forwards non-wildcard queries here so a
/// netns-isolated sandbox keeps normal DNS.
pub fn worker_upstream_resolver() -> Option<std::net::SocketAddr> {
    let content = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut parts = line.split_whitespace();
        if parts.next() == Some("nameserver") {
            if let Some(ip) = parts.next() {
                if let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() {
                    return Some(std::net::SocketAddr::from((ip, 53)));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_bytes(id: u16, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        push_u16(&mut out, id);
        push_u16(&mut out, 0x0100); // RD
        push_u16(&mut out, 1);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        push_u16(&mut out, QTYPE_A);
        push_u16(&mut out, QCLASS_IN);
        out
    }

    #[test]
    fn parse_query_extracts_id_and_lowercased_name() {
        let q = parse_query(&query_bytes(0x1234, "API.Example.COM")).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.qname, "api.example.com");
    }

    #[test]
    fn parse_query_rejects_multi_question_and_aaaa() {
        let mut multi = query_bytes(1, "a.example.com");
        multi[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert!(parse_query(&multi).is_none());
        let mut aaaa = query_bytes(1, "a.example.com");
        let qtype_off = aaaa.len() - 4;
        aaaa[qtype_off..qtype_off + 2].copy_from_slice(&28u16.to_be_bytes()); // AAAA
        assert!(parse_query(&aaaa).is_none());
    }

    #[test]
    fn a_response_echoes_question_and_ip() {
        let q = DnsQuery { id: 7, qname: "api.example.com".into() };
        let ip: std::net::Ipv4Addr = "10.250.0.2".parse().unwrap();
        let resp = build_a_response(&q, ip);
        assert_eq!(&resp[0..2], &7u16.to_be_bytes());
        assert!(resp.windows(4).any(|w| w == ip.octets()));
        // ANCOUNT == 1.
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
    }

    #[test]
    fn refused_has_rcode_five() {
        let resp = build_refused(9);
        assert_eq!(resp.len(), DNS_HEADER_LEN);
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]) & 0x000F, RCODE_REFUSED);
    }

    #[tokio::test]
    async fn handle_query_answers_matched_and_refuses_unmatched() {
        let suffixes = vec![("example.com".to_string(), PortAllow::Any)];
        let dns = SyntheticDns::new();
        let q = query_bytes(1, "api.example.com");
        let resp = handle_query(&q, &suffixes, &dns).await;
        assert!(
            resp.windows(4)
                .any(|w| w == "10.250.0.2".parse::<std::net::Ipv4Addr>().unwrap().octets())
        );
        let q2 = query_bytes(2, "other.org");
        let resp2 = handle_query(&q2, &suffixes, &dns).await;
        assert_eq!(
            u16::from_be_bytes([resp2[2], resp2[3]]) & 0x000F,
            RCODE_REFUSED
        );
    }
}
