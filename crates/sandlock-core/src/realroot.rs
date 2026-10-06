//! A real root for the image-rootfs shape: mount namespace, the sandbox's own
//! mounts, `pivot_root`.
//!
//! Without this the image-rootfs shape only *emulates* a root: the child stays
//! in the host root and the mediator rewrites every path syscall it handles.
//! That is enough for everything the mediator sees, and fails for everything
//! the kernel resolves on its own -- a `#!` interpreter, a static binary, any
//! future kernel-side lookup (measured 2026-09-23; the E2B side writes this up
//! in `docs/chroot-workspace-exec.md`).
//!
//! This module builds the real thing. It must run
//!
//!   * **after** the sandbox's user namespace exists -- the mount namespace is
//!     owned by that user namespace, and CAP_SYS_ADMIN inside it is what
//!     authorises every step (and what the caller must drop afterwards);
//!   * **before** Landlock and seccomp are installed -- so the workload
//!     inherits a process that has already been sealed, and the mount-family
//!     syscalls this module needs are gone from it.
//!
//! The mounts it performs are the policy's own `fs_mount` table: the same
//! (virtual, host) pairs the mediator would otherwise resolve on the child's
//! behalf. The mount *points* must exist inside the rootfs beforehand -- the
//! caller that builds the policy creates them (`envd` does, next to
//! `chroot`), and a missing one is an error here rather than a silently absent
//! path.

use std::ffi::CString;
use std::path::{Path, PathBuf};

/// `mount(2)` flags. Defined here rather than taken from `libc` so the meaning
/// is local to the one place that uses them.
const MS_BIND: libc::c_ulong = 4096;
const MS_REC: libc::c_ulong = 16384;
const MS_PRIVATE: libc::c_ulong = 1 << 18;
const MNT_DETACH: libc::c_int = 2;

/// CAP_SYS_ADMIN — the capability this module needs and then gives up.
const CAP_SYS_ADMIN: u32 = 21;

/// `_LINUX_CAPABILITY_VERSION_3`: two 32-bit words of capability data, which is
/// what every kernel since 2.6.26 expects.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn mount(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), String> {
    let source_c = match source {
        Some(p) => Some(CString::new(p.as_os_str().as_encoded_bytes()).map_err(|_| {
            format!("mount source is not a valid C string: {}", p.display())
        })?),
        None => None,
    };
    let target_c = CString::new(target.as_os_str().as_encoded_bytes())
        .map_err(|_| format!("mount target is not a valid C string: {}", target.display()))?;
    let fstype_c = match fstype {
        Some(t) => Some(CString::new(t).map_err(|_| format!("invalid fs type {:?}", t))?),
        None => None,
    };
    let data_c = match data {
        Some(d) => Some(CString::new(d).map_err(|_| "invalid mount data".to_string())?),
        None => None,
    };
    let rc = unsafe {
        libc::mount(
            source_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            target_c.as_ptr(),
            fstype_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            flags,
            data_c
                .as_ref()
                .map_or(std::ptr::null(), |c| c.as_ptr() as *const libc::c_void),
        )
    };
    if rc != 0 {
        return Err(format!(
            "mount({:?} -> {}, flags={:#x}): {}",
            source.map(|p| p.display().to_string()),
            target.display(),
            flags,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Where the breadcrumbs go, opened **once and kept as a descriptor**.
///
/// The path cannot be re-resolved later: from `pivot_root` onwards the process
/// sees the image rootfs as `/`, so a path like `<repo>/tmp/...` or even
/// `/tmp/...` no longer names the host file it named a moment ago. A descriptor
/// opened before the pivot keeps writing to the same file regardless -- which is
/// exactly what makes a failure *after* the pivot visible at all.
static TRACE: std::sync::OnceLock<std::sync::Mutex<Option<std::fs::File>>> =
    std::sync::OnceLock::new();

fn trace_enabled() -> bool {
    std::env::var("SANLOCK_REALROOT_TRACE").is_ok()
}

fn trace_path() -> String {
    std::env::var("SANLOCK_REALROOT_TRACE")
        .unwrap_or_else(|_| "/tmp/sandlock-real-root-error".to_string())
}

fn write_trace(line: &str) {
    use std::io::Write;
    let slot = TRACE.get_or_init(|| {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(trace_path())
            .ok();
        if let Some(handle) = file.as_ref() {
            // Close-on-exec, explicitly. Measured 2026-09-23: the descriptor
            // was inherited by the workload (`/proc/<pid>/fd` showed the trace
            // file), which hands the sandbox a write handle into the worker's
            // filesystem -- exactly the kind of cross-boundary handle this
            // module exists to avoid. A *failed* exec never applies the flag,
            // which is the one case the post-exec failure breadcrumb needs it.
            unsafe {
                use std::os::fd::AsRawFd;
                libc::fcntl(handle.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
        std::sync::Mutex::new(file)
    });
    if let Ok(mut guard) = slot.lock() {
        if let Some(file) = guard.as_mut() {
            let _ = writeln!(file, "{}", line);
        }
    }
}

/// Record why the root could not be built.
///
/// The child's stderr is not a reliable channel here: in the slot shapes it is
/// the sandbox's own stdio, which is not connected yet when setup fails -- the
/// operator sees "instance is closed" and nothing else. So the reason goes to
/// the trace file (see [`TRACE`]).
pub(crate) fn record_failure(message: &str) {
    write_trace(&format!("FAILURE: {message}"));
}

/// Append a step to the trace file, when `SANLOCK_REALROOT_TRACE` names one.
///
/// Success is as invisible as failure in the slot shapes, so a setup that dies
/// somewhere after the root is built needs the same breadcrumbs a failing mount
/// gets. Off unless asked for: this appends a line per sandbox creation.
pub fn note(step: &str) {
    if trace_enabled() {
        write_trace(&format!("step: {step}"));
    }
}

/// The trace file's descriptor, if one is open.
///
/// `confine_child` closes every descriptor above stderr before exec'ing the
/// workload; the trace has to be in its keep list, or the breadcrumbs written
/// after that point (the exec, and any failure it reports) go to a closed fd.
pub fn trace_fd() -> Option<std::os::fd::RawFd> {
    use std::os::fd::AsRawFd;
    let slot = TRACE.get()?;
    let guard = slot.lock().ok()?;
    guard.as_ref().map(|file| file.as_raw_fd())
}

fn chdir(path: &Path) -> Result<(), String> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| format!("path is not a valid C string: {}", path.display()))?;
    if unsafe { libc::chdir(c.as_ptr()) } != 0 {
        return Err(format!(
            "chdir({}): {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// `chdir` to a path **as the sandbox sees it** (i.e. after `pivot_root`).
///
/// The caller uses this for the configured working directory: under a chroot
/// the policy spells that directory in the sandbox's own namespace, and this is
/// the point in the sequence where that spelling is finally the real one.
pub fn enter_guest_cwd(path: &Path) -> Result<(), String> {
    chdir(path)
}

/// Build the real root: a private mount namespace owned by this user
/// namespace, the image rootfs as its root, the policy's mounts inside it, and
/// `pivot_root` into it.
///
/// `root` is the host path of the image rootfs; `mounts` are the policy's
/// (virtual, host) pairs, the same shape `Sandbox::fs_mount` carries.
///
/// `mount_ns_ready` says the calling process already lives in its own mount
/// namespace — a PID-namespace sandbox gets one from the same `clone3` call
/// that created it — so `build` only unshares for the other shapes.
pub fn real_root(
    root: &Path,
    mounts: &[(PathBuf, PathBuf)],
    mount_ns_ready: bool,
) -> Result<(), String> {
    let outcome = build(root, mounts, mount_ns_ready);
    if let Err(ref e) = outcome {
        record_failure(e);
    }
    outcome
}

fn build(root: &Path, mounts: &[(PathBuf, PathBuf)], mount_ns_ready: bool) -> Result<(), String> {
    // 1. Our own mount namespace, owned by our own user namespace: every mount
    //    below is invisible to the host and dies with this process, and no
    //    propagation can leak them outward.
    if !mount_ns_ready && unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(format!(
            "unshare(CLONE_NEWNS): {}",
            std::io::Error::last_os_error()
        ));
    }
    if !mount_ns_ready {
        note("unshare(CLONE_NEWNS)");
    }
    // 2. Nothing propagates into (or out of) the host's mount tree.
    mount(None, Path::new("/"), None, MS_REC | MS_PRIVATE, None)?;
    note("make-private");
    // 3. The policy's mounts, inside the rootfs.
    for (virtual_path, host_path) in mounts {
        if !host_path.exists() {
            // Same rule the Landlock side applies: a declared mount whose
            // source is gone contributes nothing (and is not fatal) -- the
            // alternative is failing every sandbox on a stale policy entry.
            continue;
        }
        let target = root.join(virtual_path.strip_prefix("/").unwrap_or(virtual_path));
        if !target.exists() {
            return Err(format!(
                "mount point {} does not exist inside the rootfs {} (the policy's \
                 fs_mount destination has to be created before the sandbox starts)",
                target.display(),
                root.display()
            ));
        }
        let is_dir = host_path.is_dir();
        let flags = if is_dir { MS_BIND | MS_REC } else { MS_BIND };
        mount(Some(host_path), &target, None, flags, None)?;
        note(&format!("bind {} -> {}", host_path.display(), target.display()));
    }
    // 4. The new root has to be a mount point for `pivot_root`, and it has to be
    //    the mount that *carries* the policy mounts just created. A recursive
    //    self-bind taken after them does both: `MS_BIND|MS_REC` replicates the
    //    subtree, so the mounts come along into the mount the pivot moves, and
    //    the old root (with the original tree) is the one detached below.
    //
    //    Order matters and was measured: binding the rootfs onto itself *first*
    //    leaves the later mounts attached to the original mount, and after the
    //    pivot the sandbox sees the empty mount-point directories instead of the
    //    bound content (`pivot_root` moved the other mount). The symptom was a
    //    relative-path exec answering ENOENT while absolute paths worked.
    mount(Some(root), root, None, MS_BIND | MS_REC, None)?;
    note("self-bind rootfs (recursive, carries the mounts)");
    // 5. pivot_root with the "." idiom (see pivot_root(2) NOTES): chdir to the
    //    new root first, pivot with both arguments ".", then detach the old
    //    root -- which leaves no reachable path back to the host filesystem.
    chdir(root)?;
    note("chdir rootfs");
    if unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            c".".as_ptr(),
            c".".as_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "pivot_root(\".\", \".\"): {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe {
        libc::umount2(c".".as_ptr(), MNT_DETACH)
    } != 0
    {
        return Err(format!(
            "umount2(\".\", MNT_DETACH) of the old root: {}",
            std::io::Error::last_os_error()
        ));
    }
    note("pivot_root + detach old root");
    chdir(Path::new("/"))?;
    note("chdir /");
    Ok(())
}

/// Give up `CAP_SYS_ADMIN`, keeping every other capability.
///
/// The sandbox runs as uid 0 *inside its own user namespace*, and that
/// namespace is what makes `CHOWN`/`DAC_OVERRIDE`/`FOWNER`/`SETUID` meaningful
/// for it -- dropping all capabilities would change what "root in the sandbox"
/// means for the workload. `CAP_SYS_ADMIN` is different: it is the one this
/// module needed to build the root, the sandbox has no legitimate use for it
/// (the mediator's own filter already refuses `mount`/`pivot_root`/`chroot`
/// from the workload), and dropping it means the seal does not rest on the
/// container's seccomp profile alone.
pub fn drop_cap_sys_admin() -> Result<(), String> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data: [CapData; 2] = [
        CapData { effective: 0, permitted: 0, inheritable: 0 },
        CapData { effective: 0, permitted: 0, inheritable: 0 },
    ];
    if unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!("capget: {}", std::io::Error::last_os_error()));
    }
    let bit = 1u32 << CAP_SYS_ADMIN;
    for entry in data.iter_mut() {
        entry.effective &= !bit;
        entry.permitted &= !bit;
        entry.inheritable &= !bit;
    }
    if unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapHeader,
            data.as_ptr(),
        )
    } != 0
    {
        return Err(format!("capset: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sys_admin_bit_matches_the_kernel_constant() {
        // The bit we clear has to be CAP_SYS_ADMIN; a silent mismatch here
        // would leave the sandbox with the capability the whole module exists
        // to give up.
        assert_eq!(CAP_SYS_ADMIN, 21);
        assert_eq!(1u32 << CAP_SYS_ADMIN, 0x20_0000);
    }

    #[test]
    fn mount_flags_match_the_linux_values() {
        assert_eq!(MS_BIND, 4096);
        assert_eq!(MS_REC, 16384);
        assert_eq!(MS_PRIVATE, 262144);
        assert_eq!(MNT_DETACH, 2);
    }
}
