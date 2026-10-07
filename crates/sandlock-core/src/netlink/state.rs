use std::collections::HashMap;
use std::sync::Mutex;

/// Per-sandbox registry of virtualized netlink cookie fds.
///
/// Keyed by `(pid, fd)` — the exact fd number allocated in the child
/// when our `socket(AF_NETLINK, ..., NETLINK_ROUTE)` handler returned
/// `InjectFdSendTracked`.  The key stays the fd *number* (not an inode
/// lookup) so that the entry is usable without racing the child: it lands
/// in the map from the `ADDFD` success callback, before the child's
/// syscall unblocks.
///
/// The **value** is what keeps the entry honest.  Until 2026-10-07 `close`
/// sat in `NETLINK_NOTIF_SYSCALLS` for one reason only — to remove the
/// entry when the child closed the fd, because otherwise a reused fd
/// number would inherit it and `getsockname`/`recvfrom`/`recvmsg` would
/// answer for a socket that is no longer there. That notification costs a
/// supervisor round trip per `close` in the whole sandbox (the hottest
/// syscall there is), so it is gone; the same guarantee is now read from
/// `/proc/<pid>/fd/<fd>` **at use time**: a closed fd (the path is gone)
/// or a slot handed to something else (a different identity, or not a
/// socket at all) evicts the entry and the caller treats the fd as plain.
///
/// The map is bounded without a knob of its own: its key carries the fd
/// number, and fd numbers are allocated from the sandbox's own
/// `RLIMIT_NOFILE` range, so a process can only ever contribute that many
/// keys.
#[derive(Default)]
pub struct NetlinkState {
    cookies: Mutex<HashMap<(i32, i32), Option<String>>>,
}

impl NetlinkState {
    pub fn new() -> Self {
        Self {
            cookies: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new cookie fd injected into the child, recording the identity
    /// of the injected socket (`/proc/<pid>/fd/<fd>` -> `socket:[<inode>]`) so
    /// that later uses can tell it apart from whatever the slot holds now.
    pub fn register(&self, pid: i32, fd: i32) {
        let identity = socket_identity(pid, fd);
        self.cookies.lock().unwrap().insert((pid, fd), identity);
    }

    /// Is `(pid, fd)` still one of our injected netlink cookies?
    ///
    /// Re-validates against procfs on every use (see the struct comment), and
    /// evicts the entry the moment the answer is no: a closed fd, a slot that
    /// was handed to another file, or a process that is gone.
    pub fn is_cookie(&self, pid: i32, fd: i32) -> bool {
        let mut cookies = self.cookies.lock().unwrap();
        let Some(recorded) = cookies.get(&(pid, fd)).cloned() else {
            return false;
        };
        let current = socket_identity(pid, fd);
        match (recorded, current) {
            // Same socket: still our cookie.
            (Some(recorded), Some(current)) if recorded == current => true,
            // The identity could not be read at registration time (the fd was
            // already gone, or procfs was momentarily unreadable). Take the
            // first successful read as the reference rather than refusing a
            // cookie that is very likely live.
            (None, Some(current)) => {
                cookies.insert((pid, fd), Some(current));
                true
            }
            // Closed, reused, or unreadable: the entry is stale either way, and
            // keeping it would answer for a socket that is not there.
            _ => {
                cookies.remove(&(pid, fd));
                false
            }
        }
    }
}

/// The identity of the socket at `(pid, fd)`, read straight from procfs.
///
/// `None` means "not a socket, or nothing is there any more" — the two cases
/// the caller must treat as "this is not our cookie".
fn socket_identity(pid: i32, fd: i32) -> Option<String> {
    let target = std::fs::read_link(format!("/proc/{}/fd/{}", pid, fd)).ok()?;
    let text = target.to_string_lossy().into_owned();
    text.starts_with("socket:[").then_some(text)
}
