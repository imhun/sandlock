//! Netlink request builders and blocking send helpers for per-sandbox
//! network namespaces.
//!
//! All request builders are pure (bytes out), so the wire shape is
//! unit-testable. The send/`in_netns` helpers are blocking and Linux-only;
//! the sandbox-end configuration runs on a dedicated thread that `setns`es
//! into the sandbox netns and exits, so the async runtime's threads are
//! never migrated between namespaces.

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

use super::proto::{
    IfAddrMsg, IfInfoMsg, NlMsgHdr, Writer, NLM_F_REQUEST, NLMSG_ERROR, NLMSG_HDRLEN,
    RTM_NEWADDR, RTM_NEWLINK,
};

// ---- rtnetlink constants used for requests (not present in proto.rs) ----

pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELLINK: u16 = 17;

pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_CREATE: u16 = 0x0400;
pub const NLM_F_EXCL: u16 = 0x0200;

pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_INFO_KIND: u16 = 1;
pub const IFLA_INFO_DATA: u16 = 2;
pub const IFLA_NET_NS_FD: u16 = 28;
pub const VETH_INFO_PEER: u16 = 1;

pub const IFA_LOCAL: u16 = 2;
pub const IFA_ADDRESS: u16 = 1;

pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;

pub const RT_TABLE_MAIN: u8 = 254;
pub const RTPROT_STATIC: u8 = 4;
pub const RTN_UNICAST: u8 = 1;

pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;

fn ifinfomsg_bytes(ifi_index: i32) -> Vec<u8> {
    let m = IfInfoMsg {
        ifi_family: AF_UNSPEC,
        _pad: 0,
        ifi_type: 0,
        ifi_index,
        ifi_flags: 0,
        ifi_change: 0,
    };
    unsafe {
        std::slice::from_raw_parts(&m as *const _ as *const u8, std::mem::size_of::<IfInfoMsg>())
    }
    .to_vec()
}

fn ifaddrmsg_bytes(prefix_len: u8, ifindex: u32) -> Vec<u8> {
    let m = IfAddrMsg {
        ifa_family: AF_INET,
        ifa_prefixlen: prefix_len,
        ifa_flags: 0,
        ifa_scope: 0,
        ifa_index: ifindex,
    };
    unsafe {
        std::slice::from_raw_parts(&m as *const _ as *const u8, std::mem::size_of::<IfAddrMsg>())
    }
    .to_vec()
}

fn ipv4_bytes(ip: std::net::Ipv4Addr) -> [u8; 4] {
    ip.octets()
}

/// Build a `RTM_NEWLINK` request that creates a veth pair: `host_name` in
/// the caller's netns and `sandbox_name` inside the netns referenced by
/// `sandbox_netns_fd`.
pub fn build_veth_create(
    host_name: &str,
    sandbox_name: &str,
    sandbox_netns_fd: RawFd,
    seq: u32,
) -> Vec<u8> {
    let mut w = Writer::new();
    let start = w.begin_msg(RTM_NEWLINK as u16, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, seq, 0);
    w.write_aligned(&ifinfomsg_bytes(0));
    w.write_attr(IFLA_IFNAME, host_name.as_bytes());
    // IFLA_LINKINFO -> IFLA_INFO_DATA -> VETH_INFO_PEER { ifinfomsg,
    // IFLA_IFNAME, IFLA_NET_NS_FD }. The VETH_INFO_PEER header is a nested
    // rtattr whose payload starts with a struct ifinfomsg followed by the
    // peer's attributes.
    let mut peer = Writer::new();
    peer.write_aligned(&ifinfomsg_bytes(0));
    peer.write_attr(IFLA_IFNAME, sandbox_name.as_bytes());
    peer.write_attr(IFLA_NET_NS_FD, &(sandbox_netns_fd as u32).to_ne_bytes());
    let peer_payload = peer.into_vec();

    let mut data = Writer::new();
    data.write_attr(VETH_INFO_PEER, &peer_payload);
    let data_payload = data.into_vec();

    let mut linkinfo = Writer::new();
    linkinfo.write_attr(IFLA_INFO_KIND, b"veth");
    linkinfo.write_attr(IFLA_INFO_DATA, &data_payload);
    let linkinfo_payload = linkinfo.into_vec();
    w.write_attr(IFLA_LINKINFO, &linkinfo_payload);
    w.finish_msg(start);
    w.into_vec()
}

/// Build a `RTM_NEWADDR` request adding `ip/prefix_len` to `ifindex`.
pub fn build_addr_add(ifindex: i32, ip: std::net::Ipv4Addr, prefix_len: u8, seq: u32) -> Vec<u8> {
    let mut w = Writer::new();
    let start = w.begin_msg(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, seq, 0);
    w.write_aligned(&ifaddrmsg_bytes(prefix_len, ifindex as u32));
    w.write_attr(IFA_LOCAL, &ipv4_bytes(ip));
    w.write_attr(IFA_ADDRESS, &ipv4_bytes(ip));
    w.finish_msg(start);
    w.into_vec()
}

/// Build a `RTM_NEWROUTE` request adding the default route via `gateway`
/// on `ifindex`.
pub fn build_route_add_default(gateway: std::net::Ipv4Addr, ifindex: i32, seq: u32) -> Vec<u8> {
    let mut w = Writer::new();
    let start = w.begin_msg(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, seq, 0);
    // rtmsg (struct rtmsg, 12 bytes).
    let rtmsg = [
        AF_INET, // rtm_family
        0,       // rtm_dst_len (default route)
        0,       // rtm_src_len
        0,       // rtm_tos
        RT_TABLE_MAIN,
        RTPROT_STATIC,
        0, // rtm_scope
        RTN_UNICAST,
        0, 0, 0, 0, // rtm_flags + pad
    ];
    w.write_aligned(&rtmsg);
    w.write_attr(RTA_OIF, &(ifindex as u32).to_ne_bytes());
    w.write_attr(RTA_GATEWAY, &ipv4_bytes(gateway));
    w.finish_msg(start);
    w.into_vec()
}

/// Build a `RTM_DELLINK` request removing the link with `ifindex`.
pub fn build_link_del(ifindex: i32, seq: u32) -> Vec<u8> {
    let mut w = Writer::new();
    let start = w.begin_msg(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, seq, 0);
    w.write_aligned(&ifinfomsg_bytes(ifindex));
    w.finish_msg(start);
    w.into_vec()
}

/// Look up an interface index by name in the *caller's current netns*.
pub fn ifindex_by_name(name: &str) -> io::Result<i32> {
    // SAFETY: socket with valid domain/type/protocol.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let cname = CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad ifname"))?;
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_slice = &mut ifr.ifr_name;
    let bytes = cname.as_bytes();
    if bytes.len() >= name_slice.len() {
        unsafe { libc::close(fd) };
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "ifname too long"));
    }
    let cbytes: Vec<libc::c_char> = bytes.iter().map(|&b| b as libc::c_char).collect();
    name_slice[..bytes.len()].copy_from_slice(&cbytes);
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX, &mut ifr) };
    unsafe { libc::close(fd) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ifr_ifru.ifru_ifindex is the index field after a successful
    // SIOCGIFINDEX.
    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}

/// Send a netlink request and wait for the `NLMSG_ERROR` ack. The socket is
/// created in the calling thread's current netns, so callers that need the
/// sandbox netns must run inside [`in_netns`].
pub fn send_netlink_request(req: &[u8]) -> io::Result<()> {
    // SAFETY: socket(2) with valid arguments.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: bind(2) with a sockaddr_nl sized buffer.
        let rc = unsafe {
            libc::bind(
                fd,
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: send(2) with a valid buffer; the kernel copies it.
        let sent = unsafe {
            libc::send(
                fd,
                req.as_ptr() as *const libc::c_void,
                req.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = [0u8; 8192];
        loop {
            // SAFETY: recv(2) into a valid buffer.
            let n = unsafe {
                libc::recv(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            if n < NLMSG_HDRLEN {
                continue;
            }
            // SAFETY: header at offset 0, length checked.
            let hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const NlMsgHdr) };
            if hdr.nlmsg_type == NLMSG_ERROR {
                if n < NLMSG_HDRLEN + 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "short NLMSG_ERROR"));
                }
                // SAFETY: error field is the first i32 after the header.
                let err = i32::from_ne_bytes(unsafe { *(buf.as_ptr().add(NLMSG_HDRLEN) as *const [u8; 4]) });
                if err == 0 {
                    return Ok(());
                }
                return Err(io::Error::from_raw_os_error(-err));
            }
            if hdr.nlmsg_len as usize > n {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated netlink reply"));
            }
        }
    })();
    unsafe { libc::close(fd) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::proto::parse_request;

    /// Walk one level of rtnetlink attrs starting at `start`.
    /// Returns `(rta_type, payload_start, payload_end)` triples.
    fn attrs_of(buf: &[u8], start: usize, end: usize) -> Vec<(u16, usize, usize)> {
        let mut out = Vec::new();
        let mut pos = start;
        while pos + crate::netlink::proto::RTA_HDRLEN <= end {
            let len = u16::from_ne_bytes([buf[pos], buf[pos + 1]]) as usize;
            let ty = u16::from_ne_bytes([buf[pos + 2], buf[pos + 3]]);
            if len < crate::netlink::proto::RTA_HDRLEN || pos + len > end {
                break;
            }
            out.push((ty, pos + crate::netlink::proto::RTA_HDRLEN, pos + len));
            pos += crate::netlink::proto::nlmsg_align(len);
        }
        out
    }

    fn find_attr<'a>(attrs: &'a [(u16, usize, usize)], ty: u16) -> Option<(usize, usize)> {
        attrs
            .iter()
            .find(|(t, _, _)| *t == ty)
            .map(|(_, s, e)| (*s, *e))
    }

    fn u32_at(buf: &[u8], pos: usize) -> u32 {
        u32::from_ne_bytes(buf[pos..pos + 4].try_into().unwrap())
    }

    fn header_of(req: &[u8]) -> (u16, u16) {
        let h = parse_request(req).unwrap();
        (h.nlmsg_type, h.nlmsg_flags)
    }

    #[test]
    fn veth_create_request_shape() {
        let req = build_veth_create("veth1234", "veth1234p", 42, 7);
        assert_eq!(header_of(&req), (RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));
        let s = String::from_utf8_lossy(&req).into_owned();
        assert!(s.contains("veth1234"));
        assert!(s.contains("veth1234p"));
        assert!(s.contains("veth"));
        // The sandbox netns fd rides as a u32 attribute.
        assert!(req.windows(4).any(|w| w == &42u32.to_ne_bytes()));
    }

    #[test]
    fn veth_create_peer_attrs_are_structural() {
        let req = build_veth_create("veth1234", "veth1234p", 42, 7);
        // Top level: ifinfomsg (16 bytes) then attrs; find IFLA_LINKINFO.
        let top = attrs_of(&req, NLMSG_HDRLEN + 16, req.len());
        let (ls, le) = find_attr(&top, IFLA_LINKINFO).expect("IFLA_LINKINFO");
        let linkinfo = attrs_of(&req, ls, le);
        assert!(find_attr(&linkinfo, IFLA_INFO_KIND).is_some());
        let (ds, de) = find_attr(&linkinfo, IFLA_INFO_DATA).expect("IFLA_INFO_DATA");
        let data = attrs_of(&req, ds, de);
        let (ps, pe) = find_attr(&data, VETH_INFO_PEER).expect("VETH_INFO_PEER");
        // Peer payload: struct ifinfomsg then attrs.
        assert!(pe - ps >= 16, "peer payload must start with ifinfomsg");
        let peer = attrs_of(&req, ps + 16, pe);
        let (ns, ne) = find_attr(&peer, IFLA_IFNAME).expect("peer IFLA_IFNAME");
        assert_eq!(&req[ns..ne], b"veth1234p");
        let (fs, fe) = find_attr(&peer, IFLA_NET_NS_FD).expect("peer IFLA_NET_NS_FD");
        assert_eq!(fe - fs, 4);
        assert_eq!(u32_at(&req, fs), 42);
    }

    #[test]
    fn addr_add_request_shape() {
        let ip: std::net::Ipv4Addr = "10.200.0.2".parse().unwrap();
        let req = build_addr_add(7, ip, 30, 8);
        assert_eq!(header_of(&req), (RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));
        assert!(req.windows(4).any(|w| w == ip.octets()));
        assert!(req.contains(&30));
    }

    #[test]
    fn route_add_default_shape() {
        let gw: std::net::Ipv4Addr = "10.200.0.1".parse().unwrap();
        let req = build_route_add_default(gw, 7, 9);
        assert_eq!(header_of(&req), (RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));
        assert!(req.windows(4).any(|w| w == gw.octets()));
        assert!(req.windows(4).any(|w| w == 7u32.to_ne_bytes()));
    }

    #[test]
    fn link_del_request_shape() {
        let req = build_link_del(11, 10);
        assert_eq!(header_of(&req), (RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK));
    }

}
