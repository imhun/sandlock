// Fork + confinement sequence: child-side Landlock + seccomp application
// and parent-child pipe synchronization.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::resolved::ResolvedSandbox;
use crate::sandbox::Sandbox;
use crate::seccomp::bpf;

#[cfg(test)]
use crate::arch;
#[cfg(test)]
use crate::sys::structs::{
    AF_INET, AF_INET6, CLONE_NS_FLAGS, DEFAULT_BLOCKLIST_SYSCALLS, PR_SET_DUMPABLE,
    SIOCGIFCONF, SIOCETHTOOL, SOCK_RAW, SOCK_TYPE_MASK, TIOCLINUX, TIOCSTI,
};

// ============================================================
// Pipe pair for parent-child synchronization
// ============================================================

/// Pipes for parent-child communication after fork().
pub struct PipePair {
    /// Parent reads the notif fd number written by the child.
    pub notif_r: OwnedFd,
    /// Child writes the notif fd number to the parent.
    pub notif_w: OwnedFd,
    /// Child reads the "supervisor ready" signal from the parent.
    pub ready_r: OwnedFd,
    /// Parent writes the "supervisor ready" signal to the child.
    pub ready_w: OwnedFd,
    /// Parent reads the sandbox leader's host pid (pid-ns mode only).
    ///
    /// This is a *separate* pipe from the notif pipe on purpose: in pid-ns
    /// mode the intermediate process writes the leader's host pid while the
    /// leader itself writes the notif fd number, and two writers on one pipe
    /// have no inter-writer ordering guarantee (the leader can win the race
    /// and the parent would read the fd number as the pid). One writer per
    /// pipe makes each 4-byte write unambiguous.
    pub leader_pid_r: OwnedFd,
    /// Intermediate process writes the leader's host pid to the parent.
    pub leader_pid_w: OwnedFd,
    /// Parent reads the in-netns DNS gateway socket fd number (net_isolation
    /// + wildcard rules only). The parent writes the allocated gateway
    /// address to `dns_w` before forking; the child binds it in the sandbox
    /// netns and writes the socket's fd number back. One writer at a time on
    /// each direction, so the two messages never interleave.
    pub dns_r: OwnedFd,
    /// Parent writes the DNS gateway address, child writes the socket fd.
    pub dns_w: OwnedFd,
}

impl PipePair {
    /// Create four pipe pairs using `pipe2(O_CLOEXEC)`.
    pub fn new() -> io::Result<Self> {
        let mut notif_fds = [0i32; 2];
        let mut ready_fds = [0i32; 2];
        let mut leader_pid_fds = [0i32; 2];
        let mut dns_fds = [0i32; 2];

        // SAFETY: pipe2 with valid pointers and O_CLOEXEC
        let ret = unsafe { libc::pipe2(notif_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let ret = unsafe { libc::pipe2(ready_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret < 0 {
            // Close the first pair on failure
            unsafe {
                libc::close(notif_fds[0]);
                libc::close(notif_fds[1]);
            }
            return Err(io::Error::last_os_error());
        }

        let ret = unsafe { libc::pipe2(leader_pid_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret < 0 {
            unsafe {
                libc::close(notif_fds[0]);
                libc::close(notif_fds[1]);
                libc::close(ready_fds[0]);
                libc::close(ready_fds[1]);
            }
            return Err(io::Error::last_os_error());
        }

        let ret = unsafe { libc::pipe2(dns_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret < 0 {
            unsafe {
                libc::close(notif_fds[0]);
                libc::close(notif_fds[1]);
                libc::close(ready_fds[0]);
                libc::close(ready_fds[1]);
                libc::close(leader_pid_fds[0]);
                libc::close(leader_pid_fds[1]);
            }
            return Err(io::Error::last_os_error());
        }

        // SAFETY: pipe2 returned valid fds
        Ok(PipePair {
            notif_r: unsafe { OwnedFd::from_raw_fd(notif_fds[0]) },
            notif_w: unsafe { OwnedFd::from_raw_fd(notif_fds[1]) },
            ready_r: unsafe { OwnedFd::from_raw_fd(ready_fds[0]) },
            ready_w: unsafe { OwnedFd::from_raw_fd(ready_fds[1]) },
            leader_pid_r: unsafe { OwnedFd::from_raw_fd(leader_pid_fds[0]) },
            leader_pid_w: unsafe { OwnedFd::from_raw_fd(leader_pid_fds[1]) },
            dns_r: unsafe { OwnedFd::from_raw_fd(dns_fds[0]) },
            dns_w: unsafe { OwnedFd::from_raw_fd(dns_fds[1]) },
        })
    }
}

// ============================================================
// Pipe I/O helpers
// ============================================================

/// Write a `u32` as 4 little-endian bytes to a raw fd.
pub(crate) fn write_u32_fd(fd: RawFd, val: u32) -> io::Result<()> {
    let buf = val.to_le_bytes();
    let mut written = 0usize;
    while written < 4 {
        let ret = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr() as *const libc::c_void,
                4 - written,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        written += ret as usize;
    }
    Ok(())
}

/// Read a `u32` (4 little-endian bytes, blocking) from a raw fd.
pub(crate) fn read_u32_fd(fd: RawFd) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    let mut total = 0usize;
    while total < 4 {
        let ret = unsafe {
            libc::read(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                4 - total,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "pipe closed before 4 bytes read",
            ));
        }
        total += ret as usize;
    }
    Ok(u32::from_le_bytes(buf))
}

/// Write a single byte (blocking) to a raw fd.
pub(crate) fn write_byte_fd(fd: RawFd, b: u8) -> io::Result<()> {
    let buf = [b];
    let mut written = 0usize;
    while written < buf.len() {
        let ret = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr() as *const libc::c_void,
                buf.len() - written,
            )
        };
        if ret < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        written += ret as usize;
    }
    Ok(())
}

/// Read a single byte (blocking) from a raw fd.
pub(crate) fn read_byte_fd(fd: RawFd) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    let mut total = 0usize;
    while total < buf.len() {
        let ret = unsafe {
            libc::read(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
            )
        };
        if ret < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "pipe closed before 1 byte read",
            ));
        }
        total += ret as usize;
    }
    Ok(buf[0])
}

#[cfg(test)]
use crate::seccomp::syscall::syscall_name_to_nr;

// ============================================================
// Sandbox -> seccomp plan
// ============================================================

pub(crate) use crate::seccomp_plan::{arg_filters_resolved, notif_syscalls_resolved};

pub fn notif_syscalls(policy: &Sandbox, sandbox_name: Option<&str>) -> Vec<u32> {
    crate::seccomp_plan::notif_syscalls(policy, sandbox_name)
}

pub fn no_supervisor_blocklist_syscall_numbers(policy: &Sandbox) -> Vec<u32> {
    crate::seccomp_plan::no_supervisor_blocklist_syscall_numbers(policy)
}

pub fn blocklist_syscall_numbers(policy: &Sandbox) -> Vec<u32> {
    crate::seccomp_plan::blocklist_syscall_numbers(policy)
}

pub fn arg_filters(policy: &Sandbox) -> Vec<crate::sys::structs::SockFilter> {
    crate::seccomp_plan::arg_filters(policy)
}

// ============================================================
// Close fds above threshold
// ============================================================

/// Close all file descriptors above `min_fd`, except those in `keep`.
///
/// Must not touch /proc: this runs after confinement is installed, which
/// denies that read under chroot and silently turned the sweep into a no-op.
fn close_fds_above(min_fd: RawFd, keep: &[RawFd]) {
    let mut kept: Vec<RawFd> = keep.iter().copied().filter(|&fd| fd > min_fd).collect();
    kept.sort_unstable();
    kept.dedup();

    let close_span = |first: RawFd, last: libc::c_uint| {
        unsafe { libc::syscall(libc::SYS_close_range, first as libc::c_uint, last, 0) };
    };
    let mut next = min_fd + 1;
    for fd in kept {
        if fd > next {
            close_span(next, (fd - 1) as libc::c_uint);
        }
        next = fd + 1;
    }
    close_span(next, libc::c_uint::MAX);
}

// ============================================================
// User-namespace uid/gid mapping helpers
// ============================================================

/// Write uid/gid maps for an unprivileged user namespace.
/// `real_uid`/`real_gid` must be captured *before* unshare(CLONE_NEWUSER),
/// since getuid()/getgid() return the overflow id (65534) after unshare.
/// `target_uid`/`target_gid` are the UIDs visible inside the namespace.
///
/// Errors must reach the caller: mapping only happens when the caller asked
/// for a specific identity, and a failed write would otherwise leave the
/// child running as the overflow uid (65534) with no indication. Ubuntu
/// 24.04's default AppArmor restriction on unprivileged user namespaces
/// produces exactly that: unshare succeeds, the map write fails.
pub(crate) fn write_id_maps(
    real_uid: u32,
    real_gid: u32,
    target_uid: u32,
    target_gid: u32,
) -> std::io::Result<()> {
    std::fs::write("/proc/self/uid_map", format!("{} {} 1\n", target_uid, real_uid))?;
    std::fs::write("/proc/self/setgroups", "deny\n")?;
    std::fs::write("/proc/self/gid_map", format!("{} {} 1\n", target_gid, real_gid))?;
    Ok(())
}

/// Write the uid/gid maps of a *child* that has unshared a fresh user
/// namespace, mapping inside-id 0 to the requested host identity
/// (`RunAs` = host uid/gid; inside the namespace the sandbox sees uid 0).
///
/// This runs in the parent (supervisor), not the child: unshare(CLONE_NEWUSER)
/// strips every capability the caller had in the *parent* namespace, so a
/// child can only ever map its own euid — the single-entry map `0 -> uid`
/// with an arbitrary host uid requires the parent to hold CAP_SETUID /
/// CAP_SETGID in the parent namespace (root).  The child is synchronized via
/// the map-ready / map-done pipes: it signals after unsharing, the parent
/// writes the maps, then releases the child to `setresuid(0)` inside the
/// namespace (which re-points its host identity at the mapped uid).
pub(crate) fn write_privileged_id_maps(
    child_pid: libc::pid_t,
    run_as: crate::sandbox::RunAs,
) -> std::io::Result<()> {
    std::fs::write(format!("/proc/{child_pid}/uid_map"), format!("0 {} 1\n", run_as.uid))?;
    std::fs::write(format!("/proc/{child_pid}/gid_map"), format!("0 {} 1\n", run_as.gid))?;
    Ok(())
}

/// Current supplementary group ids of this process (host gids). The sandbox
/// child inherits them across fork (and keeps them in the unprivileged
/// single-entry userns, where `setgroups` is denied), so they are part of the
/// identity the kernel's DAC checks use for the sandbox's file/socket access.
pub(crate) fn current_supplementary_groups() -> Vec<u32> {
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n <= 0 {
        return Vec::new();
    }
    let mut groups = vec![0 as libc::gid_t; n as usize];
    let got = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
    if got <= 0 {
        return Vec::new();
    }
    groups.truncate(got as usize);
    groups.into_iter().map(|g| g as u32).collect()
}

// ============================================================
// Child-side confinement (never returns)
// ============================================================

/// Arguments threaded from the parent's `do_spawn` into the child-side
/// `confine_child`.  Packed into a struct because `confine_child` historically
/// grew to seven positional parameters and a struct keeps the call site
/// readable when new flags get added (e.g. `extra_syscalls` for user
/// handlers).  Lifetimes tie everything to the parent's stack frame — the
/// child never outlives the fork point because `confine_child` either execs
/// or exits.
/// The terminal action `confine_child` performs after confinement is installed.
/// Exactly one of the two: there is no longer a "command plus optional override".
pub(crate) enum ChildEntry<'a> {
    /// `execve` this command (the normal path). argv[0] becomes the process name.
    Exec(&'a [CString]),
    /// Run this function in-process, with the process named `name`. Used for the
    /// OCI in-sandbox PID-1: the child is a fork of the supervisor so the code is
    /// already mapped, nothing is exec'd, and Landlock has no execve to
    /// authorize. `run` must not return; `confine_child` `_exit(0)`s if it does.
    InProcess { name: &'a CStr, run: fn() },
}

pub(crate) struct ChildSpawnArgs<'a> {
    pub sandbox: &'a Sandbox,
    /// Terminal action after confinement: `execve` a command or run a fn
    /// in-process. See [`ChildEntry`].
    pub entry: ChildEntry<'a>,
    pub pipes: &'a PipePair,
    /// Skip the user-notification supervisor: child installs a kernel-only
    /// deny filter, parent reads `notif_fd_num = 0` and never starts a
    /// supervisor. Mirrors `Sandbox::no_supervisor`.
    pub no_supervisor: bool,
    pub keep_fds: &'a [RawFd],
    /// Sandbox instance name. When set, it is also exposed as the
    /// sandbox's virtual hostname.
    pub sandbox_name: Option<&'a str>,
    /// Syscall numbers for which the parent registered user `Handler`s.
    /// Merged into the child's BPF notif list so the kernel actually
    /// raises USER_NOTIF for them.
    pub extra_syscalls: &'a [u32],
    /// PID of the parent process captured before fork. Used to detect
    /// parent death in the child without assuming PID 1 is always init
    /// (incorrect in containers where the entrypoint runs as PID 1).
    pub parent_pid: libc::pid_t,
    /// Make the child the terminal's foreground process group before exec.
    /// Only interactive (fully inherited) stdio wants this; a captured or
    /// piped run taking the foreground demotes the embedding process to a
    /// background job, and its next tty read stops it with SIGTTIN.
    pub foreground: bool,
    /// The child runs as the first process of a fresh PID namespace
    /// (`Sandbox::pid_ns`): the user namespace (and any uid/gid mapping)
    /// was already created by the intermediate process before the final
    /// fork, so `confine_child` must not unshare another one, and the
    /// parent-death check compares against `getppid() == 0` (the real
    /// parent lives outside the namespace).
    pub pid_ns: bool,
    /// Child-side write end of the "user namespace created" pipe. `Some`
    /// only when the supervisor is privileged and `RunAs` differs from its
    /// own identity: the child unshares a user namespace, signals the
    /// parent, and waits for the parent to write the `0 -> host_uid` maps
    /// (a child alone cannot map an arbitrary host uid — unshare strips its
    /// parent-namespace capabilities, leaving only a self-euid mapping).
    pub map_ready_w: Option<OwnedFd>,
    /// Child-side read end of the "maps written" pipe (parent -> child).
    /// Paired with `map_ready_w`; the byte received is the release signal
    /// after the parent wrote the privileged maps.
    pub map_done_r: Option<OwnedFd>,
}

/// Set the calling thread/process name (`/proc/<pid>/comm`, shown by `ps`). The
/// kernel truncates to 15 bytes + NUL. Used for the in-process PID-1, which has
/// no `execve` to set its name from argv[0].
fn set_proc_name(name: &CStr) {
    unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0) };
}

/// The `RLIMIT_NOFILE` value a `max_open_files` request of `requested` yields,
/// given the limits sandlock itself inherited.
///
/// Clamped against *both* inherited bounds, for two different reasons:
///
/// * the hard bound is a kernel requirement: raising a hard limit needs
///   `CAP_SYS_RESOURCE`, so a larger request would fail with `EPERM` and abort
///   the child;
/// * the soft bound is the contract: `max_open_files` is a cap, not a grant.
///   Without this clamp a request between the inherited soft and hard limits
///   would *widen* the guest's descriptor budget past what the same command
///   gets unsandboxed (soft 1024 / hard 1048576 is the distro default, so
///   `max_open_files(65536)` would hand the guest 64x the usual budget under a
///   setting named "max").
///
/// Callers who genuinely need a bigger budget raise it on sandlock itself
/// (`prlimit`, systemd `LimitNOFILE=`); the guest then inherits the higher soft
/// limit and this clamp stops constraining.
fn effective_nofile(requested: u32, inherited: &libc::rlimit) -> libc::rlim_t {
    (requested as libc::rlim_t).min(inherited.rlim_cur).min(inherited.rlim_max)
}

/// Minimal Linux `struct ifreq` for the loopback ioctls: `ifr_name` plus the
/// flags slot of the `ifru` union, padded to the kernel's 40-byte struct.
/// (`libc` does not expose `ifreq` on Linux, so we carry the layout we need.)
#[repr(C)]
struct Ifreq {
    ifr_name: [libc::c_char; 16],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

/// Bring the loopback interface up in the caller's current network
/// namespace (`ioctl(SIOCSIFFLAGS)` on an AF_INET socket, preserving the
/// kernel's existing flags). Runs in the child before confinement: it
/// requires CAP_NET_ADMIN in the current netns, which the sandbox holds
/// because its userns owns the fresh netns created for `net_isolation`
/// (S2.2) — no privilege in the parent namespace.
fn bring_loopback_up() -> Result<(), String> {
    let sock = unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
    };
    if sock < 0 {
        return Err(format!(
            "socket(AF_INET, SOCK_DGRAM): {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in b"lo".iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    if unsafe { libc::ioctl(sock, crate::sys::structs::SIOCGIFFLAGS as libc::c_ulong, &mut ifr) } < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(format!("ioctl(SIOCGIFFLAGS, lo): {}", err));
    }
    ifr.ifr_flags |= libc::IFF_UP as libc::c_short;
    let rc = unsafe { libc::ioctl(sock, crate::sys::structs::SIOCSIFFLAGS as libc::c_ulong, &ifr) };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(sock) };
    if rc < 0 {
        return Err(format!("ioctl(SIOCSIFFLAGS, lo): {}", err));
    }
    Ok(())
}

/// Apply irreversible confinement (Landlock + seccomp), then either `execve` the
/// command or run an in-process entrypoint, per [`ChildEntry`].
///
/// This function **never returns**: on success it execs or runs the entrypoint
/// (which `_exit`s); on any error it `_exit(127)`s.
pub(crate) fn confine_child(args: ChildSpawnArgs<'_>) -> ! {
    let ChildSpawnArgs {
        sandbox,
        entry,
        pipes,
        no_supervisor,
        keep_fds,
        sandbox_name,
        extra_syscalls,
        parent_pid,
        foreground,
        pid_ns,
        map_ready_w,
        map_done_r,
    } = args;
    // Helper: abort child on error. Includes the OS error automatically.
    macro_rules! fail {
        ($msg:expr) => {{
            let err = std::io::Error::last_os_error();
            let _ = write!(std::io::stderr(), "sandlock child: {}: {}\n", $msg, err);
            unsafe { libc::_exit(127) };
        }};
    }

    use std::io::Write;

    // 1. New process group
    if unsafe { libc::setpgid(0, 0) } != 0 {
        fail!("setpgid");
    }

    // 1b. Interactive runs only: if stdin is a terminal, become the
    //     foreground process group so interactive shells can read from the
    //     TTY. Captured/piped runs must not: the embedding process keeps
    //     the terminal (issue #164).
    //     Must ignore SIGTTOU first — a background pgrp calling tcsetpgrp
    //     gets stopped by SIGTTOU otherwise.
    if foreground && unsafe { libc::isatty(0) } == 1 {
        unsafe {
            libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            libc::tcsetpgrp(0, libc::getpgrp());
            libc::signal(libc::SIGTTOU, libc::SIG_DFL);
        }
    }

    // 2. Die if parent exits
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        fail!("prctl(PR_SET_PDEATHSIG)");
    }

    // 3. Check parent didn't die between fork and prctl.
    // Compare against the actual parent PID captured before fork rather than
    // hardcoding 1, since containers often run the entrypoint as PID 1 and a
    // child forked from it legitimately has getppid() == 1.
    if unsafe { libc::getppid() } != parent_pid {
        fail!("parent died before confinement");
    }

    // 4. Optional: disable ASLR
    if sandbox.no_randomize_memory {
        const ADDR_NO_RANDOMIZE: libc::c_ulong = 0x0040000;
        // Read current personality first (0xffffffff = query), then OR in the flag.
        let current = unsafe { libc::personality(0xffffffff) };
        if current == -1 {
            fail!("personality(query)");
        }
        if unsafe { libc::personality(current as libc::c_ulong | ADDR_NO_RANDOMIZE) } == -1 {
            fail!("personality(ADDR_NO_RANDOMIZE)");
        }
    }

    // 4b. Optional: CPU core binding
    if let Some(ref cores) = sandbox.cpu_cores {
        if !cores.is_empty() {
            let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
            unsafe { libc::CPU_ZERO(&mut set) };
            for &core in cores {
                unsafe { libc::CPU_SET(core as usize, &mut set) };
            }
            if unsafe {
                libc::sched_setaffinity(
                    0,
                    std::mem::size_of::<libc::cpu_set_t>(),
                    &set,
                )
            } != 0
            {
                fail!("sched_setaffinity");
            }
        }
    }

    // 5. Optional: disable THP
    if sandbox.no_huge_pages {
        if unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0) } != 0 {
            fail!("prctl(PR_SET_THP_DISABLE)");
        }
    }

    // 5c. Optional: disable core dumps
    if sandbox.no_coredump {
        // Set RLIMIT_CORE to 0 — the kernel will not write a core file.
        // We intentionally do NOT call prctl(PR_SET_DUMPABLE, 0) because
        // that would break pidfd_getfd which the supervisor needs.
        // The seccomp filter already blocks the child from calling
        // prctl(PR_SET_DUMPABLE, ...) so it can't re-enable it.
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) } != 0 {
            fail!("setrlimit(RLIMIT_CORE, 0)");
        }
    }

    // 5d. Detect the privileged `RunAs` remap *before* the steps below:
    // when the child will be remapped to a different host uid, the parent
    // writes the maps and the child re-points its identity via `setresuid`,
    // after which rootfs host paths (image caches under mode-0700
    // root-owned directories) are no longer traversable.  The real chdir and
    // the Landlock *rule build* therefore happen pre-remap for this shape
    // only; enforcement (`landlock_restrict_self`) still happens post-remap,
    // where it always has — restricting from a descendant userns with an
    // ancestor ruleset is supported and no namespace transition follows.
    let privileged_remap = if pid_ns {
        false
    } else {
        let real_uid = unsafe { libc::getuid() };
        let real_gid = unsafe { libc::getgid() };
        matches!(sandbox.user, Some(run_as) if run_as.uid != real_uid || run_as.gid != real_gid)
    };

    // 6. Optional: change working directory
    // cwd controls where the child starts; workdir is only for COW.
    //
    // This MUST run before the user-namespace remap below drops this child
    // to the sandbox's host uid: the chdir target is the *host* path of the
    // configured cwd (under a chroot, inside the rootfs), and a rootfs tree
    // is frequently only traversable by the privileged holder (image caches
    // under mode-0700 root-owned directories).  Chroot path mediation does
    // not exist yet at this point — seccomp is installed later — so the real
    // chdir must succeed with the holder's credentials, before
    // `setresuid(0)` activates the mapped identity (fork-plan F10).
    let effective_cwd = if let Some(ref cwd) = sandbox.cwd {
        if let Some(ref chroot_root) = sandbox.chroot {
            Some(chroot_root.join(cwd.strip_prefix("/").unwrap_or(cwd)))
        } else {
            Some(cwd.clone())
        }
    } else if let Some(ref chroot_root) = sandbox.chroot {
        // Default to chroot root
        Some(chroot_root.to_path_buf())
    } else if let Some(ref workdir) = sandbox.workdir {
        // Default to workdir when set (COW working directory)
        Some(workdir.clone())
    } else {
        None
    };

    if let Some(ref cwd) = effective_cwd {
        let c_path = match CString::new(cwd.as_os_str().as_encoded_bytes()) {
            Ok(c) => c,
            Err(_) => fail!("invalid cwd path"),
        };
        if unsafe { libc::chdir(c_path.as_ptr()) } != 0 {
            fail!("chdir");
        }
    }

    // 7. Set NO_NEW_PRIVS + build the Landlock ruleset (privileged-remap
    // arm).  `landlock_restrict_self` needs no_new_privs once the child is
    // no longer privileged over the ruleset's user namespace, and the rule
    // build opens the chroot-translated host paths (`exists()` probes and
    // the path_beneath parent fds) — which must happen while the holder's
    // credentials still make an image cache under mode-0700 root-owned
    // directories traversable.  Enforcement is deferred to step 8b below,
    // after the remap (fork-plan F10).
    let mut prebuilt_ruleset: Option<std::os::fd::OwnedFd> = None;
    if privileged_remap {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            fail!("prctl(PR_SET_NO_NEW_PRIVS)");
        }
        match crate::landlock::build_ruleset(sandbox, true) {
            Ok(ruleset) => prebuilt_ruleset = Some(ruleset),
            Err(e) => fail!(format!("landlock: {}", e)),
        }
    }

    // 5. User namespace for --user (run-as uid/gid) mapping.
    //
    // Skipped entirely when the sandbox runs in its own PID namespace:
    // the intermediate process created the user namespace (required for
    // unprivileged CLONE_NEWPID) and wrote the mapping before the final
    // fork, so this child already has its target identity.
    //
    // Otherwise skip when the requested identity already matches the
    // current uid/gid AND no netns isolation is requested: there's no point
    // unsharing a user namespace to map an identity the process already has,
    // and skipping avoids imposing an unprivileged-userns requirement on
    // callers that don't need one. `net_isolation` (S2.2) explicitly opts in:
    // `unshare(CLONE_NEWNET)` needs CAP_SYS_ADMIN, which an unprivileged
    // process only has inside its own user namespace (rootless-container
    // pattern), so the userns is created even without a `RunAs` remap.
    if !pid_ns {
        // Capture real uid/gid before any unshare (after unshare they become 65534)
        let real_uid = unsafe { libc::getuid() };
        let real_gid = unsafe { libc::getgid() };
        let remap = matches!(sandbox.user, Some(run_as) if run_as.uid != real_uid || run_as.gid != real_gid);
        // F18 (route B): when the requested identity is *already* ours, the
        // privileged path (parent writes `0 -> host_uid`) cannot apply, and
        // without a namespace the guest would see its host uid instead of root
        // -- a visible difference from a sandbox confined by a privileged
        // supervisor (`apt-get`, `chown`, low ports). Self-map `0 -> euid`
        // instead, which needs no privilege (rootless-container pattern).
        let self_map =
            sandbox.userns_self_map && !remap && sandbox.user.is_some() && real_uid != 0;
        let userns_needed = sandbox.net_isolation || remap || self_map;

        if userns_needed {
            // The self-map is the only *optional* namespace: if the kernel or
            // AppArmor denies unprivileged user namespaces, continuing without
            // one leaves the sandbox with strictly less privilege than
            // requested (host uid inside), so it must not fail the generation
            // -- `sandlock-supervise` probes this and logs which shape it got.
            // Every other case needs its namespace or the identity/netns
            // contract would silently be a lie.
            let unshared = unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0;
            if !unshared && !(self_map && !sandbox.net_isolation && !remap) {
                fail!("unshare(CLONE_NEWUSER)");
            }
            match sandbox.user {
                Some(run_as) if run_as.uid != real_uid || run_as.gid != real_gid => {
                    if let (Some(ready_w), Some(done_r)) = (map_ready_w, map_done_r) {
                        // Privileged path: the parent writes the `0 -> run_as`
                        // maps (only it still has CAP_SETUID in the parent
                        // namespace), then we re-point our host identity at the
                        // mapped uid/gid from inside the namespace. `RunAs` is
                        // the *host* uid; inside we see uid 0.
                        if write_byte_fd(ready_w.as_raw_fd(), b'R').is_err() {
                            fail!("user-namespace map ready signal");
                        }
                        if read_byte_fd(done_r.as_raw_fd()).is_err() {
                            fail!(
                                "parent uid_map/gid_map write (is unprivileged userns restricted? \
                                 e.g. kernel.apparmor_restrict_unprivileged_userns=1)"
                            );
                        }
                        if unsafe { libc::setresgid(0, 0, 0) } != 0 {
                            fail!("setresgid(0) to activate mapped host gid");
                        }
                        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
                            fail!("setgroups to drop supplementary groups");
                        }
                        if unsafe { libc::setresuid(0, 0, 0) } != 0 {
                            fail!("setresuid(0) to activate mapped host uid");
                        }
                    } else {
                        // Defense-in-depth only: `do_create_stdio` refuses an
                        // unprivileged `RunAs` remap *before* forking, because a
                        // single-entry map can only cover the caller's own euid
                        // (no CAP_SETUID in the parent namespace) — the sandbox
                        // would silently keep the supervisor's host uid and
                        // per-sandbox isolation would be absent.  If this branch
                        // is ever reached outside that path, self-map the
                        // requested uid inside the namespace as a last resort
                        // rather than running as the overflow uid (65534).
                        if write_id_maps(real_uid, real_gid, run_as.uid, run_as.gid).is_err() {
                            fail!(
                                "uid_map/gid_map write (is unprivileged userns restricted? \
                                 e.g. kernel.apparmor_restrict_unprivileged_userns=1)"
                            );
                        }
                    }
                }
                Some(_) if self_map => {
                    // `0 -> our own host uid`: inside the namespace we are uid 0;
                    // outside, every file and socket we touch is still owned by
                    // the sandbox's host uid (the kernel compares the *kuid*, so
                    // DAC against other tenants is unchanged). When there is no
                    // namespace to map, the sandbox keeps its host uid inside as
                    // well -- less privilege than requested, never more.
                    if unshared && write_id_maps(real_uid, real_gid, 0, 0).is_err() {
                        fail!(
                            "uid_map/gid_map write for the route-B self-map \
                             (is unprivileged userns restricted? e.g. \
                             kernel.apparmor_restrict_unprivileged_userns=1)"
                        );
                    }
                }
                _ => {
                    // `net_isolation` without a `RunAs` remap: self-map our
                    // own identity so the fresh user namespace grants us a
                    // full capability set (writing a map that covers the
                    // caller's own euid is allowed unprivileged; a child can
                    // never map an arbitrary host uid). The capabilities are
                    // what `unshare(CLONE_NEWNET)` and `lo up` below rely on.
                    if write_id_maps(real_uid, real_gid, real_uid, real_gid).is_err() {
                        fail!(
                            "uid_map/gid_map write for net_isolation (is unprivileged userns \
                             restricted? e.g. kernel.apparmor_restrict_unprivileged_userns=1)"
                        );
                    }
                }
            }
        }
    }

    // 5b. Per-sandbox network namespace isolation (S2.2).
    //
    // Runs after the user namespace (created above, or by the pid-ns
    // intermediate): unshare(CLONE_NEWNET) puts the sandbox in a fresh netns
    // owned by its own userns, so the sandbox has CAP_NET_ADMIN there with no
    // privilege in the parent namespace. The fresh netns contains only
    // loopback; bring lo up from inside the userns. Must run before
    // Landlock/seccomp: the interface ioctls are only needed at setup and the
    // netns switch must precede any network confinement. The wildcard DNS
    // gateway for net_isolation sandboxes is bound in this netns right below
    // (S2.3), so the sandbox never depends on shared-netns supervisor
    // services.
    if sandbox.net_isolation {
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            fail!("unshare(CLONE_NEWNET)");
        }
        if let Err(e) = bring_loopback_up() {
            fail!(format!("bring loopback up in netns: {}", e));
        }

        // 5c. In-netns wildcard DNS gateway (S2.3): when the parent allocated
        // a gateway address for this sandbox it wrote it to the dns pipe
        // before forking (0.0.0.0 means "no wildcard gateway requested").
        // Bind a UDP socket at `<addr>:53` in the sandbox's OWN netns — we
        // are root inside our user namespace, so CAP_NET_BIND_SERVICE covers
        // port 53 and the host `ip_unprivileged_port_start` sysctl is
        // irrelevant — then report the socket's fd number to the parent,
        // which dups it and runs the gateway task supervisor-side. The
        // socket stays bound to this netns for its whole lifetime, so the
        // supervisor answers queries without entering the namespace. Must
        // run before Landlock/seccomp: socket()/bind() happen unconfined and
        // only the fd number crosses the confinement boundary. We keep the
        // fd open until the parent dups it (we block on the ready pipe
        // below); `close_fds_above` drops our copy at exec.
        match read_u32_fd(pipes.dns_r.as_raw_fd()) {
            Ok(0) => {}
            Ok(ip_bits) => {
                let addr = std::net::Ipv4Addr::from(ip_bits);
                let sock = unsafe {
                    libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
                };
                if sock < 0 {
                    fail!("socket(AF_INET, SOCK_DGRAM) for in-netns DNS gateway");
                }
                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 53u16.to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(addr.octets()),
                    },
                    sin_zero: [0; 8],
                };
                if unsafe {
                    libc::bind(
                        sock,
                        &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                } < 0
                {
                    unsafe { libc::close(sock) };
                    fail!("bind in-netns DNS gateway");
                }
                if write_u32_fd(pipes.dns_w.as_raw_fd(), sock as u32).is_err() {
                    unsafe { libc::close(sock) };
                    fail!("write in-netns DNS gateway fd");
                }
            }
            Err(e) => fail!(format!("read DNS gateway address: {}", e)),
        }
    }

    // 8b. Enforce Landlock (IRREVERSIBLE).
    //
    // Privileged-remap arm: the ruleset was built pre-remap (step 7); apply
    // it now that the child is inside its own user namespace — the historical
    // enforcement point, with no namespace transition afterwards.  Every
    // other arm (no remap, net_isolation self-map, pid-ns) keeps the
    // historical single-step `confine()` here: the unprivileged self-map
    // must still write its own `/proc/self/uid_map` before Landlock closes
    // the filesystem view.
    if let Some(ruleset) = prebuilt_ruleset.take() {
        if let Err(e) = crate::landlock::restrict_ruleset(&ruleset) {
            fail!(format!("landlock: {}", e));
        }
    } else {
        // 7b. NO_NEW_PRIVS (required for Landlock/seccomp without CAP_SYS_ADMIN)
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            fail!("prctl(PR_SET_NO_NEW_PRIVS)");
        }
        if let Err(e) = crate::landlock::confine(sandbox) {
            fail!(format!("landlock: {}", e));
        }
    }

    // 9. Assemble and install seccomp filter (IRREVERSIBLE)
    let handler_syscalls: Vec<i64> = extra_syscalls.iter().map(|&nr| nr as i64).collect();
    let resolved = ResolvedSandbox::from_sandbox(sandbox, sandbox_name, &handler_syscalls);
    let args = arg_filters_resolved(&resolved);
    let mut keep_fd: i32 = -1;

    if no_supervisor {
        // No-supervisor mode: deny-only kernel filter, no NEW_LISTENER.
        // BPF filters are ANDed by the kernel, so an outer filter (from a
        // wrapping sandbox) keeps tightening this layer too.
        //
        // Uses the relaxed `no_supervisor_blocklist_syscall_numbers` deny
        // list (which leaves `ptrace`, `unshare`, `process_vm_*`, etc.
        // alone) so an inner full-supervisor sandlock nested under this
        // one still has the syscalls its supervisor needs.
        let deny = no_supervisor_blocklist_syscall_numbers(sandbox);
        let filter = match bpf::assemble_filter(&[], &deny, &args) {
            Ok(f) => f,
            Err(e) => fail!(format!("seccomp assemble: {}", e)),
        };
        if let Err(e) = bpf::install_deny_filter(&filter) {
            fail!(format!("seccomp deny filter: {}", e));
        }
        // fd=0 tells the parent there's no supervisor to attach to.
        if let Err(e) = write_u32_fd(pipes.notif_w.as_raw_fd(), 0) {
            fail!(format!("write no-supervisor signal: {}", e));
        }
    } else {
        let deny = blocklist_syscall_numbers(sandbox);
        // First-level sandbox: notif + deny filter with NEW_LISTENER.
        //
        // Caller-supplied handlers must have their syscalls registered in
        // the BPF filter, otherwise the kernel never raises a notification for
        // them and the handler silently never fires.  We merge `extra_syscalls`
        // into the notif list and dedup so each syscall produces exactly one
        // JEQ in the assembled program.
        let mut notif = notif_syscalls_resolved(&resolved);
        if !extra_syscalls.is_empty() {
            notif.extend_from_slice(extra_syscalls);
        }
        notif.sort_unstable();
        notif.dedup();
        let filter = match bpf::assemble_filter(&notif, &deny, &args) {
            Ok(f) => f,
            Err(e) => fail!(format!("seccomp assemble: {}", e)),
        };
        let notif_fd = match bpf::install_filter(&filter) {
            Ok(fd) => fd,
            Err(e) => {
                // EBUSY here means another seccomp filter on this task already
                // owns the SECCOMP_FILTER_FLAG_NEW_LISTENER slot. The kernel
                // permits at most one listener per task — to nest, opt this
                // sandbox out of the supervisor via `Sandbox::no_supervisor`
                // (or the CLI's `--no-supervisor` flag).
                if e.raw_os_error() == Some(libc::EBUSY) {
                    let _ = write!(
                        std::io::stderr(),
                        "sandlock child: seccomp install: {} (an outer sandbox already owns the \
                         seccomp listener; pass --no-supervisor or Sandbox::no_supervisor(true) \
                         on this sandbox to nest)\n",
                        e,
                    );
                    unsafe { libc::_exit(127) };
                }
                fail!(format!("seccomp install: {}", e));
            }
        };
        keep_fd = notif_fd.as_raw_fd();
        if let Err(e) = write_u32_fd(pipes.notif_w.as_raw_fd(), keep_fd as u32) {
            fail!(format!("write notif fd: {}", e));
        }
        std::mem::forget(notif_fd);
    }

    // 10. Wait for parent to signal ready
    match read_u32_fd(pipes.ready_r.as_raw_fd()) {
        Ok(_) => {}
        Err(e) => fail!(format!("read ready signal: {}", e)),
    }

    // 12. Close all fds above stderr (always on for isolation)
    let mut fds_to_keep: Vec<RawFd> = keep_fds.to_vec();
    if keep_fd >= 0 {
        fds_to_keep.push(keep_fd);
    }
    close_fds_above(2, &fds_to_keep);

    // 13. Apply environment
    if sandbox.clean_env {
        // Clear all env vars first
        for (key, _) in std::env::vars_os() {
            std::env::remove_var(&key);
        }
    }
    // Remove env vars whose value was loaded into the supervisor as a credential
    // source, so the agent can't read the real secret straight from its own
    // environment (this is the child; the mutation is process-local and post-fork).
    // This runs *before* applying `sandbox.env`, so the inherited real secret is
    // dropped but a deliberate placeholder the user passes (e.g.
    // `--env OPENAI_API_KEY=dummy`, which SDKs need set to start) still survives.
    for name in &sandbox.inject_env_strip {
        std::env::remove_var(name);
    }
    for (key, value) in &sandbox.env {
        std::env::set_var(key, value);
    }

    // 13b. GPU device visibility
    if let Some(ref devices) = sandbox.gpu_devices {
        if !devices.is_empty() {
            let vis = devices.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(",");
            std::env::set_var("CUDA_VISIBLE_DEVICES", &vis);
            std::env::set_var("ROCR_VISIBLE_DEVICES", &vis);
        }
        // Empty list = all GPUs visible, don't set env vars
    }

    // 13c. Optional: cap the file-descriptor table.
    //
    // Deliberately the last confinement step: Landlock (step 8) and seccomp
    // (step 9) still need to open fds, so an earlier cap kills the child with
    // a misleading EMFILE. Before the `entry` match so the in-process
    // entrypoint is capped too.
    if let Some(n) = sandbox.max_open_files {
        // Lower both the soft and the hard limit. setrlimit/prlimit64 are not
        // blocked by the seccomp filter, so a soft-only cap would be advisory:
        // the sandboxed process could raise it straight back to the hard limit.
        // Raising a hard limit needs CAP_SYS_RESOURCE, so an *unprivileged*
        // sandlock makes this one-way. It is not one-way when sandlock itself
        // runs privileged: nothing here drops CAP_SYS_RESOURCE, so a root child
        // can setrlimit the cap straight back up. Treat the limit as a resource
        // budget, not as confinement, unlike Landlock (step 8) and seccomp
        // (step 9), which stay irreversible for root too.
        let mut inherited = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut inherited) } != 0 {
            fail!("getrlimit(RLIMIT_NOFILE)");
        }
        let target = effective_nofile(n, &inherited);
        let rlim = libc::rlimit { rlim_cur: target, rlim_max: target };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
            fail!(format!("setrlimit(RLIMIT_NOFILE, {})", target));
        }
    }

    // 14. Terminal action: run the in-process entrypoint, or fall through to
    // execve the command. The in-process arm diverges (`_exit`), so the match
    // yields the command slice only on the `Exec` path.
    let cmd: &[CString] = match entry {
        ChildEntry::InProcess { name, run } => {
            // Name the PID-1 so ps / /proc/<pid>/comm read correctly: there is
            // no execve here to set argv[0]. The child is a fork of the
            // supervisor, so `run`'s code is already mapped; running it directly
            // avoids an execve that Landlock would otherwise have to authorize.
            set_proc_name(name);
            run();
            unsafe { libc::_exit(0) };
        }
        ChildEntry::Exec(cmd) => cmd,
    };

    // 14. exec
    //
    // Restore SIGPIPE first: the Rust runtime ignores it process-wide, and an
    // ignored disposition survives execve, so without this every sandboxed
    // program sees write() fail with EPIPE instead of dying silently the way
    // it would under a shell (std::process::Command does the same reset).
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    debug_assert!(!cmd.is_empty(), "cmd must not be empty");
    let argv_ptrs: Vec<*const libc::c_char> = cmd
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    if sandbox.chroot.is_some() {
        // With chroot the seccomp handler rewrites the filename to a host path
        // (or /proc/self/fd/N).  Pass a separate PATH_MAX buffer as the `file`
        // argument so the rewrite does not corrupt argv[0] — which must stay as
        // the original command name (e.g. busybox uses argv[0] for applet
        // detection).  execvp still handles PATH lookup for bare command names.
        let mut exec_path = vec![0u8; libc::PATH_MAX as usize];
        let orig = cmd[0].as_bytes_with_nul();
        exec_path[..orig.len()].copy_from_slice(orig);

        unsafe {
            libc::execvp(
                exec_path.as_ptr() as *const libc::c_char,
                argv_ptrs.as_ptr(),
            )
        };
    } else {
        unsafe { libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr()) };
    }

    // If we get here, exec failed
    fail!(format!("execvp '{}'", cmd[0].to_string_lossy()));
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;
