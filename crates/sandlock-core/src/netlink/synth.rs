use super::proto::*;

const IFI_LO_INDEX: i32 = 1;
const IFI_LO_TYPE:  u16 = 772; // ARPHRD_LOOPBACK
const IFF_UP:        u32 = 0x1;
const IFF_LOOPBACK:  u32 = 0x8;
const IFF_RUNNING:   u32 = 0x40;
const LO_FLAGS: u32 = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
const LO_MTU: u32 = 65536;

// A fixed virtual non-loopback interface shown to sandboxes that have no
// real veth (the default unprivileged shared-netns mode). glibc's
// `__check_pf` / AI_ADDRCONFIG refuses to resolve anything when the only
// addresses it sees are loopback, so the synthesized view needs one
// non-loopback IPv4 address. The address is TEST-NET-1 (192.0.2.0/24,
// RFC 5737) — reserved for documentation, never routed, and unreachable,
// so it leaks nothing about the host and cannot be used as an egress.
const VIRTUAL_IF_INDEX: i32 = 2;
const VIRTUAL_IF_NAME: &[u8] = b"eth0\0";
const VIRTUAL_IF_IP: [u8; 4] = [192, 0, 2, 1];
const VIRTUAL_IF_PREFIX: u8 = 24;
/// Documentation-only IPv6 (RFC 3849 2001:db8::/32), so AI_ADDRCONFIG sees a
/// configured non-loopback IPv6 too.
const VIRTUAL_IF_IP6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const VIRTUAL_IF_PREFIX6: u8 = 64;

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_TXQLEN: u16 = 13;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;

/// Synthesize a kernel-side reply as a sequence of datagrams.  Each Vec<u8>
/// in the returned list is one netlink datagram that should be delivered via
/// a single recvmsg call (netlink is datagram-oriented).
///
/// `reply_pid` is the Linux pid of the sandboxed process (used as the
/// `nlmsg_pid` field so glibc's pid-matching check on replies accepts them).
pub fn synthesize_reply(
    req: &ParsedRequest,
    reply_pid: u32,
    veth: Option<&super::state::VethView>,
) -> Vec<Vec<u8>> {
    match req.nlmsg_type {
        RTM_GETLINK if req.nlmsg_flags & NLM_F_DUMP != 0 =>
            build_link_dump(req.nlmsg_seq, reply_pid, veth),
        RTM_GETADDR if req.nlmsg_flags & NLM_F_DUMP != 0 =>
            build_addr_dump(req.nlmsg_seq, reply_pid, veth),
        _ => vec![build_error(req, -libc::EOPNOTSUPP)],
    }
}

/// Encode a single nlmsghdr + payload closure into one datagram.
fn encode_one<F: FnOnce(&mut Writer)>(
    nlmsg_type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
    body: F,
) -> Vec<u8> {
    let mut w = Writer::new();
    let start = w.begin_msg(nlmsg_type, flags, seq, pid);
    body(&mut w);
    w.finish_msg(start);
    w.into_vec()
}

fn done_datagram(seq: u32, pid: u32) -> Vec<u8> {
    encode_one(NLMSG_DONE, NLM_F_MULTI, seq, pid, |w| {
        w.write_aligned(&0i32.to_ne_bytes());
    })
}

fn build_link_dump(
    seq: u32,
    pid: u32,
    veth: Option<&super::state::VethView>,
) -> Vec<Vec<u8>> {
    let link = encode_one(RTM_NEWLINK, NLM_F_MULTI, seq, pid, |w| {
        let ifi = IfInfoMsg {
            ifi_family: libc::AF_UNSPEC as u8, _pad: 0,
            ifi_type: IFI_LO_TYPE, ifi_index: IFI_LO_INDEX,
            ifi_flags: LO_FLAGS, ifi_change: 0,
        };
        let ifi_bytes = unsafe {
            std::slice::from_raw_parts(&ifi as *const _ as *const u8, std::mem::size_of::<IfInfoMsg>())
        };
        w.write_aligned(ifi_bytes);
        w.write_attr(IFLA_IFNAME, b"lo\0");
        w.write_attr(IFLA_MTU, &LO_MTU.to_ne_bytes());
        w.write_attr(IFLA_TXQLEN, &1000u32.to_ne_bytes());
        w.write_attr(IFLA_ADDRESS, &[0u8; 6]);
        w.write_attr(IFLA_BROADCAST, &[0u8; 6]);
    });
    let mut out = vec![link];
    let extra = veth.map(|v| (v.ifindex, v.name.as_str(), 1500u32))
        .unwrap_or((VIRTUAL_IF_INDEX, "eth0", 1500u32));
    out.push(encode_one(RTM_NEWLINK, NLM_F_MULTI, seq, pid, |w| {
        let ifi = IfInfoMsg {
            ifi_family: libc::AF_UNSPEC as u8, _pad: 0,
            ifi_type: 1, // ARPHRD_ETHER
            ifi_index: extra.0,
            ifi_flags: IFF_UP | IFF_RUNNING,
            ifi_change: 0,
        };
        let ifi_bytes = unsafe {
            std::slice::from_raw_parts(&ifi as *const _ as *const u8, std::mem::size_of::<IfInfoMsg>())
        };
        w.write_aligned(ifi_bytes);
        let mut name = extra.1.as_bytes().to_vec();
        name.push(0);
        w.write_attr(IFLA_IFNAME, &name);
        w.write_attr(IFLA_MTU, &extra.2.to_ne_bytes());
        w.write_attr(IFLA_TXQLEN, &1000u32.to_ne_bytes());
        w.write_attr(IFLA_ADDRESS, &[0u8; 6]);
        w.write_attr(IFLA_BROADCAST, &[0u8; 6]);
    }));
    out.push(done_datagram(seq, pid));
    out
}

fn build_addr_dump(
    seq: u32,
    pid: u32,
    veth: Option<&super::state::VethView>,
) -> Vec<Vec<u8>> {
    let v4 = encode_one(RTM_NEWADDR, NLM_F_MULTI, seq, pid, |w| {
        let ifa = IfAddrMsg {
            ifa_family: libc::AF_INET as u8, ifa_prefixlen: 8,
            ifa_flags: 0, ifa_scope: 254,
            ifa_index: IFI_LO_INDEX as u32,
        };
        let ifa_bytes = unsafe {
            std::slice::from_raw_parts(&ifa as *const _ as *const u8, std::mem::size_of::<IfAddrMsg>())
        };
        w.write_aligned(ifa_bytes);
        w.write_attr(IFA_ADDRESS, &[127, 0, 0, 1]);
        w.write_attr(IFA_LOCAL,   &[127, 0, 0, 1]);
        w.write_attr(IFA_LABEL,   b"lo\0");
    });
    let v6 = encode_one(RTM_NEWADDR, NLM_F_MULTI, seq, pid, |w| {
        let ifa = IfAddrMsg {
            ifa_family: libc::AF_INET6 as u8, ifa_prefixlen: 128,
            ifa_flags: 0, ifa_scope: 254,
            ifa_index: IFI_LO_INDEX as u32,
        };
        let ifa_bytes = unsafe {
            std::slice::from_raw_parts(&ifa as *const _ as *const u8, std::mem::size_of::<IfAddrMsg>())
        };
        w.write_aligned(ifa_bytes);
        let mut v6addr = [0u8; 16]; v6addr[15] = 1;
        w.write_attr(IFA_ADDRESS, &v6addr);
        w.write_attr(IFA_LOCAL,   &v6addr);
    });
    let mut out = vec![v4, v6];
    let (index, name, ip, prefix) = veth
        .map(|v| (v.ifindex, v.name.as_str(), v.ip.octets(), v.prefix_len))
        .unwrap_or((VIRTUAL_IF_INDEX, "eth0", VIRTUAL_IF_IP, VIRTUAL_IF_PREFIX));
    let ip6 = veth.map(|_| None::<[u8; 16]>).unwrap_or(Some(VIRTUAL_IF_IP6));
    let addr = encode_one(RTM_NEWADDR, NLM_F_MULTI, seq, pid, |w| {
        let ifa = IfAddrMsg {
            ifa_family: libc::AF_INET as u8, ifa_prefixlen: prefix,
            ifa_flags: 0, ifa_scope: 0,
            ifa_index: index as u32,
        };
        let ifa_bytes = unsafe {
            std::slice::from_raw_parts(&ifa as *const _ as *const u8, std::mem::size_of::<IfAddrMsg>())
        };
        w.write_aligned(ifa_bytes);
        w.write_attr(IFA_ADDRESS, &ip);
        w.write_attr(IFA_LOCAL, &ip);
        let mut label = name.as_bytes().to_vec();
        label.push(0);
        w.write_attr(IFA_LABEL, &label);
    });
    out.push(addr);
    if let Some(ip6) = ip6 {
        let addr6 = encode_one(RTM_NEWADDR, NLM_F_MULTI, seq, pid, |w| {
            let ifa = IfAddrMsg {
                ifa_family: libc::AF_INET6 as u8, ifa_prefixlen: VIRTUAL_IF_PREFIX6,
                ifa_flags: 0, ifa_scope: 0,
                ifa_index: index as u32,
            };
            let ifa_bytes = unsafe {
                std::slice::from_raw_parts(&ifa as *const _ as *const u8, std::mem::size_of::<IfAddrMsg>())
            };
            w.write_aligned(ifa_bytes);
            w.write_attr(IFA_ADDRESS, &ip6);
            w.write_attr(IFA_LOCAL, &ip6);
            let mut label = name.as_bytes().to_vec();
            label.push(0);
            w.write_attr(IFA_LABEL, &label);
        });
        out.push(addr6);
    }
    out.push(done_datagram(seq, pid));
    out
}

fn build_error(req: &ParsedRequest, err: i32) -> Vec<u8> {
    encode_one(NLMSG_ERROR, 0, req.nlmsg_seq, req.nlmsg_pid, |w| {
        w.write_aligned(&err.to_ne_bytes());
        let orig = NlMsgHdr {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: req.nlmsg_type,
            nlmsg_flags: req.nlmsg_flags,
            nlmsg_seq: req.nlmsg_seq,
            nlmsg_pid: req.nlmsg_pid,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(&orig as *const _ as *const u8, NLMSG_HDRLEN)
        };
        w.write_aligned(bytes);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_dump_is_lo_virtual_eth0_then_done() {
        let req = ParsedRequest {
            nlmsg_type: RTM_GETLINK, nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
            nlmsg_seq: 1, nlmsg_pid: 0,
        };
        let reply = synthesize_reply(&req, 1234, None);
        assert_eq!(reply.len(), 3, "expected 3 datagrams (lo, eth0, DONE)");
        let t0 = u16::from_ne_bytes(reply[0][4..6].try_into().unwrap());
        assert_eq!(t0, RTM_NEWLINK);
        assert!(reply[0].windows(3).any(|w| w == b"lo\0"));
        assert!(reply[1].windows(5).any(|w| w == b"eth0\0"));
        let t2 = u16::from_ne_bytes(reply[2][4..6].try_into().unwrap());
        assert_eq!(t2, NLMSG_DONE);
    }

    #[test]
    fn addr_dump_is_lo_v4_lo_v6_virtual_eth0_done() {
        let req = ParsedRequest {
            nlmsg_type: RTM_GETADDR, nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
            nlmsg_seq: 1, nlmsg_pid: 0,
        };
        let reply = synthesize_reply(&req, 1234, None);
        assert_eq!(reply.len(), 5, "expected 5 datagrams (lo v4, lo v6, eth0 v4, eth0 v6, DONE)");
        assert!(reply[0].windows(4).any(|w| w == [127, 0, 0, 1]));
        let mut v6 = [0u8; 16]; v6[15] = 1;
        assert!(reply[1].windows(16).any(|w| w == v6));
        assert!(reply[2].windows(4).any(|w| w == VIRTUAL_IF_IP));
        assert!(reply[3].windows(16).any(|w| w == VIRTUAL_IF_IP6));
        let t4 = u16::from_ne_bytes(reply[4][4..6].try_into().unwrap());
        assert_eq!(t4, NLMSG_DONE);
    }

    #[test]
    fn unknown_type_returns_eopnotsupp() {
        let req = ParsedRequest {
            nlmsg_type: 999, nlmsg_flags: NLM_F_REQUEST,
            nlmsg_seq: 7, nlmsg_pid: 0,
        };
        let reply = synthesize_reply(&req, 1234, None);
        assert_eq!(reply.len(), 1);
        let t = u16::from_ne_bytes(reply[0][4..6].try_into().unwrap());
        assert_eq!(t, NLMSG_ERROR);
        let err = i32::from_ne_bytes(reply[0][16..20].try_into().unwrap());
        assert_eq!(err, -libc::EOPNOTSUPP);
    }

    #[test]
    fn netns_veth_appears_in_link_and_addr_dumps() {
        let veth = crate::netlink::state::VethView {
            ifindex: 2,
            name: "veth42p".into(),
            ip: "10.200.0.2".parse().unwrap(),
            prefix_len: 30,
        };
        let req = ParsedRequest {
            nlmsg_type: RTM_GETLINK, nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
            nlmsg_seq: 1, nlmsg_pid: 0,
        };
        let links = synthesize_reply(&req, 1234, Some(&veth));
        assert_eq!(links.len(), 3, "lo, veth, DONE");
        assert!(links[1].windows(8).any(|w| w == b"veth42p\0"));

        let req = ParsedRequest {
            nlmsg_type: RTM_GETADDR, nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
            nlmsg_seq: 2, nlmsg_pid: 0,
        };
        let addrs = synthesize_reply(&req, 1234, Some(&veth));
        assert_eq!(addrs.len(), 4, "lo v4, lo v6, veth v4, DONE");
        assert!(addrs[2].windows(4).any(|w| w == [10, 200, 0, 2]));
    }
}
