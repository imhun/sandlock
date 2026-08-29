//! Per-sandbox network namespaces: IPAM, veth naming, and the
//! supervisor-side veth/link/route plumbing.
//!
//! Model: the sandbox child calls `unshare(CLONE_NEWNET)` *before* any
//! user-namespace remap, so the fresh netns is owned by the supervisor's
//! user namespace and the supervisor keeps `CAP_NET_ADMIN` inside it.
//! The supervisor then creates a veth pair (host end in the worker netns,
//! sandbox end inside the child's netns via `IFLA_NET_NS_FD`), assigns the
//! gateway address to the host end and — through a dedicated `setns`
//! thread, so the async runtime is never migrated — the sandbox address
//! plus default route to the sandbox end, and runs the per-sandbox DNS
//! gateway on the gateway address. Cleanup deletes the host-end veth; the
//! sandbox netns dies with its last process.
//!
//! This module is deliberately syscall-light at the type level: the pure
//! allocation/naming logic lives here and is unit-tested; the netlink
//! requests that create/configure links live in `netlink` helpers and are
//! exercised by integration tests in a privileged container.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::os::fd::RawFd;

/// Default pool for per-sandbox veth subnets: `10.200.0.0/16`, carved into
/// `/30` pairs (sandbox address = base + 4n, gateway = base + 4n + 1).
pub const DEFAULT_POOL_BASE: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 0);
/// `/30` prefix for each sandbox's veth link.
pub const VETH_PREFIX_LEN: u8 = 30;

/// Names for one sandbox's veth pair. Both fit in `IFNAMSIZ` (15 chars).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VethNames {
    /// End kept in the worker netns (the gateway side).
    pub host: String,
    /// End moved into the sandbox's netns.
    pub sandbox: String,
}

/// One `/30` allocation: the sandbox's own address and the gateway address
/// (the worker-side veth end). Layout within each /30: `+0` network
/// address, `+1` gateway, `+2` sandbox host, `+3` broadcast.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetnsAllocation {
    pub sandbox_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub prefix_len: u8,
}

/// Allocates `/30` subnets from the reserved pool for every sandbox that
/// enables per-sandbox netns. One allocator per worker process; the
/// counter is atomic so sandboxes spawned concurrently never collide.
#[derive(Debug)]
pub struct NetnsPool {
    base: Ipv4Addr,
    next: AtomicU32,
}

impl NetnsPool {
    /// A pool anchored at [`DEFAULT_POOL_BASE`].
    pub fn new() -> Self {
        Self::with_base(DEFAULT_POOL_BASE)
    }

    /// A pool anchored at `base` (must be inside `10.200.0.0/16`; used by
    /// tests to exercise the boundary).
    pub fn with_base(base: Ipv4Addr) -> Self {
        NetnsPool {
            base,
            next: AtomicU32::new(0),
        }
    }

    /// Allocate the next `/30` pair, or `None` when the pool is exhausted.
    ///
    /// `base + 4n + 1` is the gateway and `base + 4n + 2` the sandbox host
    /// (the /30 network/broadcast addresses are never handed out). The pool
    /// is bounded by the `10.200.0.0/16` reservation: the last usable
    /// sandbox address is `10.200.255.254`, after which allocation fails
    /// closed rather than escaping into another subnet.
    pub fn allocate(&self) -> Option<NetnsAllocation> {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let base = u32::from(self.base);
        let gateway = base.checked_add(n.checked_mul(4)?)?.checked_add(1)?;
        let sandbox = gateway.checked_add(1)?;
        // Keep the whole /30 inside 10.200.0.0/16 (0x0ac8_0000 ..= 0x0ac8_ffff).
        if (sandbox & 0xffff_0000) != 0x0ac8_0000 || sandbox > 0x0ac8_ffff {
            return None;
        }
        Some(NetnsAllocation {
            sandbox_ip: Ipv4Addr::from(sandbox),
            gateway_ip: Ipv4Addr::from(gateway),
            prefix_len: VETH_PREFIX_LEN,
        })
    }
}

impl Default for NetnsPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic, collision-free veth names for a sandbox identified by
/// its supervisor-side pid: `veth<pid>` on the host and `veth<pid>p` in
/// the sandbox. Both names stay within `IFNAMSIZ` (15 bytes).
pub fn veth_names(pid: u32) -> VethNames {
    VethNames {
        host: format!("veth{}", pid),
        sandbox: format!("veth{}p", pid),
    }
}

/// The process-wide allocator: all sandboxes spawned by this process share
/// one pool so their `/30` subnets never collide.
static NETNS_POOL: std::sync::LazyLock<NetnsPool> = std::sync::LazyLock::new(NetnsPool::new);

/// Allocate the next subnet from the process-wide pool.
pub(crate) fn allocate_subnet() -> Option<NetnsAllocation> {
    NETNS_POOL.allocate()
}

/// Per-sandbox netns state held by the supervisor between `create()` and
/// cleanup. The netns fd itself is closed right after configuration, so the
/// namespace lives exactly as long as the sandbox's processes; the veth
/// host end is deleted explicitly at teardown (a veth peer is not removed
/// automatically when the far netns dies).
#[derive(Debug)]
pub struct SandboxNetns {
    pub names: VethNames,
    pub alloc: NetnsAllocation,
    /// Interface index of the host-end veth (for deletion).
    pub host_ifindex: i32,
    /// Interface index of the sandbox-end veth (reported by the child, used
    /// for the synthesized netlink view).
    pub sandbox_ifindex: i32,
}

/// Bring the loopback device up inside the caller's current netns. Called
/// by the sandbox child right after `unshare(CLONE_NEWNET)` (and before any
/// user-namespace remap, so the child still holds `CAP_NET_ADMIN` in the
/// fresh namespace).
pub fn child_bring_up_loopback() -> std::io::Result<()> {
    set_link_up("lo")
}

/// Set `IFF_UP` on a link in the caller's current netns.
pub fn set_link_up(name: &str) -> std::io::Result<()> {
    // SAFETY: socket(2) with valid arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = (|| {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_slice = &mut ifr.ifr_name;
        let cbytes: Vec<libc::c_char> = name.bytes().map(|b| b as libc::c_char).collect();
        if cbytes.len() >= name_slice.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ifname too long",
            ));
        }
        name_slice[..cbytes.len()].copy_from_slice(&cbytes);
        // SAFETY: ioctl(2) with a valid ifreq.
        let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the flags live in ifr_ifru.ifru_flags after SIOCGIFFLAGS.
        let flags = unsafe { ifr.ifr_ifru.ifru_flags };
        ifr.ifr_ifru.ifru_flags = flags | (libc::IFF_UP as i16) | (libc::IFF_RUNNING as i16);
        let rc = unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    })();
    unsafe { libc::close(fd) };
    result
}

/// Configure the sandbox end of the veth pair from *inside* the sandbox
/// netns: assign `sandbox_ip/prefix_len` and add the default route via
/// `gateway_ip`. Called by the child after the parent has created the pair
/// and moved the sandbox end into this netns. The child owns the netns
/// (it unshared it), so it holds `CAP_NET_ADMIN` here regardless of any
/// later user-namespace remap.
pub fn child_configure_sandbox_end(
    sandbox_ifname: &str,
    sandbox_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    prefix_len: u8,
) -> std::io::Result<i32> {
    use crate::netlink::ops::{
        build_addr_add, build_route_add_default, ifindex_by_name, send_netlink_request,
    };
    let idx = match ifindex_by_name(sandbox_ifname) {
        Ok(i) => i,
        Err(e) => {
            return Err(e);
        }
    };
    send_netlink_request(&build_addr_add(idx, sandbox_ip, prefix_len, 1))?;
    set_link_up(sandbox_ifname)?;
    send_netlink_request(&build_route_add_default(gateway_ip, idx, 2))?;
    Ok(idx)
}

/// Open the netns of a sandbox child (`/proc/<pid>/ns/net`).
pub fn open_child_netns(pid: i32) -> std::io::Result<RawFd> {
    let path = std::ffi::CString::new(format!("/proc/{}/ns/net", pid))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "pid path"))?;
    // SAFETY: open(2) with a valid path.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_allocates_sequential_pairs() {
        let pool = NetnsPool::new();
        let a = pool.allocate().unwrap();
        let b = pool.allocate().unwrap();
        assert_eq!(a.sandbox_ip, Ipv4Addr::new(10, 200, 0, 2));
        assert_eq!(a.gateway_ip, Ipv4Addr::new(10, 200, 0, 1));
        assert_eq!(a.prefix_len, 30);
        assert_eq!(b.sandbox_ip, Ipv4Addr::new(10, 200, 0, 6));
        assert_eq!(b.gateway_ip, Ipv4Addr::new(10, 200, 0, 5));
    }

    #[test]
    fn pool_exhaustion_returns_none() {
        let pool = NetnsPool::with_base(Ipv4Addr::new(10, 200, 255, 252));
        assert!(pool.allocate().is_some());
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn pool_cannot_escape_the_reserved_subnet() {
        let pool = NetnsPool::with_base(Ipv4Addr::new(10, 200, 254, 248));
        let mut last = None;
        while let Some(a) = pool.allocate() {
            last = Some(a);
        }
        // 10.200.255.254 is the last usable sandbox address inside
        // 10.200.0.0/16; the allocator must refuse to walk past it.
        assert_eq!(last.unwrap().sandbox_ip, Ipv4Addr::new(10, 200, 255, 254));
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn veth_names_are_bounded_and_unique_per_pid() {
        let a = veth_names(1234);
        let b = veth_names(1235);
        assert_ne!(a, b);
        assert!(a.host.len() <= 15);
        assert!(a.sandbox.len() <= 15);
        assert!(a.sandbox.starts_with(&a.host));
    }
}
