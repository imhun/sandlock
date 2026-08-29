use std::collections::HashSet;
use std::sync::Mutex;

/// Optional per-sandbox veth interface to include in the synthesized
/// netlink view. Present only in per-sandbox netns mode: without it,
/// glibc's `AI_ADDRCONFIG` sees only loopback and refuses to resolve
/// anything (it concludes there is no usable IPv4 address).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VethView {
    /// Interface index of the sandbox end (as seen inside the sandbox).
    pub ifindex: i32,
    /// Interface name of the sandbox end (e.g. `veth1234p`).
    pub name: String,
    /// The sandbox's assigned address on the veth.
    pub ip: std::net::Ipv4Addr,
    /// Prefix length of the /30.
    pub prefix_len: u8,
}

/// Per-sandbox registry of virtualized netlink cookie fds.
///
/// Keyed by `(pid, fd)` — the exact fd number allocated in the child
/// when our `socket(AF_NETLINK, ..., NETLINK_ROUTE)` handler returned
/// `InjectFdSendTracked`.  Using the fd number directly (instead of
/// comparing `/proc/<pid>/fd/<fd>` inodes against a set of injected
/// inodes) avoids TOCTOU: once we record `(pid, fd)`, no other thread
/// can redirect that fd slot without our `close` handler observing it
/// and removing the entry first.
#[derive(Default)]
pub struct NetlinkState {
    cookies: Mutex<HashSet<(i32, i32)>>,
    veth: Mutex<Option<VethView>>,
}

impl NetlinkState {
    pub fn new() -> Self {
        Self {
            cookies: Mutex::new(HashSet::new()),
            veth: Mutex::new(None),
        }
    }

    /// Record the sandbox's veth interface for the synthesized view.
    pub fn set_veth(&self, view: VethView) {
        *self.veth.lock().unwrap() = Some(view);
    }

    /// The current veth view, if netns mode is active.
    pub fn veth(&self) -> Option<VethView> {
        self.veth.lock().unwrap().clone()
    }

    /// Register a new cookie fd injected into the child.
    pub fn register(&self, pid: i32, fd: i32) {
        self.cookies.lock().unwrap().insert((pid, fd));
    }

    /// Remove a cookie entry.  Called from the close handler when the
    /// child closes a tracked fd.
    pub fn unregister(&self, pid: i32, fd: i32) {
        self.cookies.lock().unwrap().remove(&(pid, fd));
    }

    /// Is this (pid, fd) one of our injected netlink cookies?
    pub fn is_cookie(&self, pid: i32, fd: i32) -> bool {
        self.cookies.lock().unwrap().contains(&(pid, fd))
    }
}
