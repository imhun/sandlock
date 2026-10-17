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
/// Where the COW branch's upper is bind-mounted inside the sandbox's root.
///
/// One path component, deliberately: `handle_chroot_exec` rewrites a staged
/// binary's exec path to `<this>/<rel>` and the rewrite happens *inside the
/// child's own path buffer*, so every character it adds is a character the
/// argv/envp layout may not have room for (`plan_exec_rewrite` refuses rather
/// than corrupt the pointer arrays). `/.u` is the shortest spelling that is
/// still a directory of its own.
///
/// Read-only: the sandbox reaches its layer through the mediator, never by
/// name.
pub const EXEC_ALIAS_DIR: &str = "/.u";

/// `mount_ns_ready` says the calling process already lives in its own mount
/// namespace — a PID-namespace sandbox gets one from the same `clone3` call
/// that created it — so `build` only unshares for the other shapes.
pub fn real_root(
    root: &Path,
    mounts: &[(PathBuf, PathBuf)],
    mount_ns_ready: bool,
    cow_upper: Option<&Path>,
    overlay_layer: Option<&Path>,
    overlay_landlock: Option<(&std::os::fd::OwnedFd, &crate::sandbox::Sandbox)>,
) -> Result<(), String> {
    let outcome = build(
        root,
        mounts,
        mount_ns_ready,
        cow_upper,
        overlay_layer,
        overlay_landlock,
    );
    if let Err(ref e) = outcome {
        record_failure(e);
    }
    outcome
}

fn build(
    root: &Path,
    mounts: &[(PathBuf, PathBuf)],
    mount_ns_ready: bool,
    cow_upper: Option<&Path>,
    overlay_layer: Option<&Path>,
    overlay_landlock: Option<(&std::os::fd::OwnedFd, &crate::sandbox::Sandbox)>,
) -> Result<(), String> {
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
    // 2b. The overlay root is mounted over the rootfs path itself, before the
    //     policy mounts, so those binds land in the merged view. The kernel
    //     resolves lowerdir before attaching this mount; the lower inode and
    //     bytes are never modified.
    if let Some(layer) = overlay_layer {
        let upper = layer.join("upper");
        let work = layer.join("work");
        validate_overlay_layer(root, layer, &upper, &work)?;
        build_overlay_dir_skeleton(root, &upper)?;
        restore_overlay_whiteouts(layer)?;
        let lower = overlay_option_path("lower", root)?;
        let upper = overlay_option_path("upper", &upper)?;
        let work = overlay_option_path("work", &work)?;
        let data = format!(
            "lowerdir={lower},upperdir={upper},workdir={work},userxattr"
        );
        mount(
            Some(Path::new("overlay")),
            root,
            Some("overlay"),
            0,
            Some(&data),
        )
        .map_err(|e| {
            format!(
                "overlay rootfs mount over {} with layer {}: {e}",
                root.display(),
                layer.display()
            )
        })?;
        if let Some((ruleset, policy)) = overlay_landlock {
            crate::landlock::add_overlay_root_rule(ruleset, root, policy)
                .map_err(|e| format!("overlay root Landlock rule: {e}"))?;
        }
        note(&format!(
            "overlay rootfs lower={} upper={} work={}",
            root.display(),
            layer.join("upper").display(),
            layer.join("work").display()
        ));
    }
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
    // 3b. The COW branch's upper, read-only, at `EXEC_ALIAS_DIR`. It is what
    //     lets the mediator name a staged binary with a path the *child* can
    //     resolve (see `handle_chroot_exec`): the kernel resolves an exec path
    //     itself, and a file the branch staged exists nowhere in the rootfs.
    //     Taken *before* the self-bind below, so it travels into the mount the
    //     pivot moves.
    //
    //     A read-only bind needs the remount: the kernel ignores the access
    //     flags of the initial `MS_BIND`. Read-only so the sandbox cannot reach
    //     its own layer by name -- writes there go through the mediator, which
    //     is the invariant Task 2 pinned.
    if let Some(upper) = cow_upper {
        let target = root.join(EXEC_ALIAS_DIR.trim_start_matches('/'));
        if target.is_dir() {
            mount(Some(upper), &target, None, MS_BIND | MS_REC, None)?;
            mount(
                None,
                &target,
                None,
                MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                None,
            )?;
            note(&format!(
                "bind (ro) {} -> {}",
                upper.display(),
                target.display()
            ));
        }
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
    if let Some((ruleset, policy)) = overlay_landlock {
        crate::landlock::add_overlay_root_rule(ruleset, root, policy)
            .map_err(|e| format!("overlay self-bind Landlock rule: {e}"))?;
    }
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

fn validate_overlay_layer(
    root: &Path,
    layer: &Path,
    upper: &Path,
    work: &Path,
) -> Result<(), String> {
    if !root.is_dir() {
        return Err(format!(
            "overlay lower is missing or not a directory: {}",
            root.display()
        ));
    }
    if !layer.is_dir() {
        return Err(format!(
            "overlay layer is missing or not a directory: {}",
            layer.display()
        ));
    }
    for (name, path) in [("upper", upper), ("work", work)] {
        if !path.is_dir() {
            return Err(format!(
                "overlay {name} is missing or not a directory: {}",
                path.display()
            ));
        }
    }
    let mut entries = std::fs::read_dir(work).map_err(|e| {
        format!(
            "overlay work is not readable: {}: {e}",
            work.display()
        )
    })?;
    if entries.next().is_some() {
        return Err(format!(
            "overlay work must be empty at mount time: {}",
            work.display()
        ));
    }
    Ok(())
}

/// Create the lower's directory tree in the upper **before** the overlay is
/// mounted.
///
/// Creating a parent directory in the upper after the overlay is mounted makes
/// the kernel answer `ENOTEMPTY` for the next create in the merged directory
/// (measured 2026-10-17 on a tmpfs: `mkdir upper/usr/local` after the mount,
/// then `touch merged/usr/local/new`). The files themselves stay lazy: the
/// mediator reflinks one only when the sandbox writes it.
fn build_overlay_dir_skeleton(lower: &Path, upper: &Path) -> Result<(), String> {
    // The create-time prewarm (worker -> a slot child as the sandbox uid)
    // writes this marker after the same set of directories has been built.
    // Checking it first turns every later command's build into one `stat`
    // instead of ~11 k `mkdirat` calls that all answer EEXIST.
    if overlay_skeleton_is_current(lower, upper) {
        note("overlay dir skeleton: ready marker");
        return Ok(());
    }
    // `mkdirat(..., 0755)` goes through the umask; the old path chmod-ed every
    // directory afterwards. Pin the mask for the walk and put the workload's
    // own mask back before it inherits this process.
    let previous_umask = unsafe { libc::umask(0o022) };
    let outcome = match build_overlay_dir_skeleton_from_manifest(lower, upper) {
        Ok(()) => {
            note("overlay dir skeleton: manifest");
            Ok(())
        }
        Err(_) => {
            // No manifest (an entry published before the sidecar existed, or a
            // test rootfs) is the normal fallback, not a failure: the walk is
            // what every sandbox did before this cache.
            note("overlay dir skeleton: walk");
            walk_overlay_dir_skeleton(lower, upper)
        }
    };
    unsafe { libc::umask(previous_umask) };
    if outcome.is_ok() {
        write_overlay_skeleton_marker(lower, upper);
    }
    outcome
}

const OVERLAY_DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// The image resolver writes this next to `<entry>/rootfs` (see
/// `envd_service/runtime/image_resolver.py::_write_dir_manifest`).
const DIR_MANIFEST_NAME: &str = ".dirs";
const DIR_MANIFEST_HEADER: &[u8] = b"sandlock-dirs-v1\n";
const DIR_MANIFEST_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Written next to `upper` after a complete skeleton build.
///
/// Format (whitespace separated, one line):
/// `sandlock-skeleton-v1 <top-level entries> <manifest bytes> <manifest
/// mtime_ns>`. The two manifest fields tie the marker to the immutable image
/// entry; the top-level count catches a sandbox that deleted or added a
/// top-level entry through its own tree. A marker that does not parse is a
/// miss, never a reason to fail: the walk simply runs.
const OVERLAY_SKELETON_MARKER_NAME: &str = ".skeleton-ready";
const OVERLAY_SKELETON_MARKER_HEADER: &str = "sandlock-skeleton-v1";

/// Snapshot/migration sidecar written by
/// `gateway_common/overlay_whiteouts.py`: NUL-separated paths relative to
/// `upper`, each one a char 0/0 the archive could not carry.
const OVERLAY_WHITEOUTS_NAME: &str = "whiteouts";
const OVERLAY_WHITEOUTS_HEADER: &[u8] = b"sandlock-whiteouts-v1\n";

fn is_safe_relative(path: &Path) -> bool {
    use std::path::Component;

    let mut saw = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => saw = true,
            _ => return false,
        }
    }
    saw
}

/// Rebuild the char 0/0 whiteouts a snapshot/migration payload could not carry.
///
/// Runs as the sandbox's user-namespace root, which is the one identity that
/// may `mknod` a 0/0 whiteout without host privilege (measured in the design's
/// whiteout prototype). Every component is walked with `O_NOFOLLOW`, so a
/// restored upper cannot steer a whiteout through a symlink. A failed rebuild
/// fails the start: silently losing a whiteout would resurrect a deleted file.
fn restore_overlay_whiteouts(layer: &Path) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let manifest = layer.join(OVERLAY_WHITEOUTS_NAME);
    let data = match std::fs::read(&manifest) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "overlay whiteouts {}: {e}",
                manifest.display()
            ))
        }
    };
    let body = data.strip_prefix(OVERLAY_WHITEOUTS_HEADER).ok_or_else(|| {
        format!("overlay whiteouts {}: bad header", manifest.display())
    })?;
    let upper = layer.join("upper");
    let upper_root = open_overlay_dir(&upper).map_err(|e| {
        format!("overlay whiteouts upper {}: {e}", upper.display())
    })?;
    for raw in body.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        let relative = Path::new(std::ffi::OsStr::from_bytes(raw));
        if !is_safe_relative(relative) {
            return Err(format!(
                "overlay whiteouts {}: unsafe path {:?}",
                manifest.display(),
                relative
            ));
        }
        let components: Vec<_> = relative
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        let Some((last, parents)) = components.split_last() else {
            continue;
        };
        let mut parent = upper_root.as_raw_fd();
        let mut opened: Vec<std::fs::File> = Vec::new();
        let mut missing = false;
        for component in parents {
            let name = std::ffi::CString::new(component.as_bytes()).map_err(|_| {
                format!("overlay whiteouts {}: NUL in a path", manifest.display())
            })?;
            let fd = unsafe {
                libc::openat(parent, name.as_ptr(), OVERLAY_DIR_FLAGS)
            };
            if fd < 0 {
                missing = true;
                break;
            }
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            parent = file.as_raw_fd();
            opened.push(file);
        }
        if missing {
            return Err(format!(
                "overlay whiteouts {}: parent of {:?} is missing",
                manifest.display(),
                relative
            ));
        }
        let name = std::ffi::CString::new(last.as_bytes()).map_err(|_| {
            format!("overlay whiteouts {}: NUL in a path", manifest.display())
        })?;
        let mut info: libc::stat = unsafe { std::mem::zeroed() };
        let exists = unsafe {
            libc::fstatat(
                parent,
                name.as_ptr(),
                &mut info,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        if exists {
            if info.st_mode & libc::S_IFMT == libc::S_IFCHR && info.st_rdev == 0 {
                continue;
            }
            // A real entry now lives there: the manifest is stale for this
            // path and the entry must win.
            continue;
        }
        if unsafe {
            libc::mknodat(
                parent,
                name.as_ptr(),
                libc::S_IFCHR | 0o600,
                0,
            )
        } != 0
        {
            return Err(format!(
                "overlay whiteouts {}: cannot create {:?}: {}",
                manifest.display(),
                relative,
                std::io::Error::last_os_error()
            ));
        }
    }
    let _ = std::fs::remove_file(&manifest);
    Ok(())
}

fn overlay_manifest_identity(lower: &Path) -> (u64, i128) {
    use std::os::unix::fs::MetadataExt;

    let Some(entry) = lower.parent() else {
        return (0, 0);
    };
    let manifest = entry.join(DIR_MANIFEST_NAME);
    let Ok(metadata) = std::fs::symlink_metadata(&manifest) else {
        return (0, 0);
    };
    if !metadata.file_type().is_file() {
        return (0, 0);
    }
    (
        metadata.len(),
        metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128,
    )
}

fn overlay_skeleton_top_level(upper: &Path) -> usize {
    std::fs::read_dir(upper)
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn overlay_skeleton_is_current(lower: &Path, upper: &Path) -> bool {
    let Some(layer) = upper.parent() else {
        return false;
    };
    let Ok(text) = std::fs::read_to_string(layer.join(OVERLAY_SKELETON_MARKER_NAME))
    else {
        return false;
    };
    let mut fields = text.split_whitespace();
    if fields.next() != Some(OVERLAY_SKELETON_MARKER_HEADER) {
        return false;
    }
    let (Some(count), Some(len), Some(mtime)) =
        (fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    if fields.next().is_some() {
        return false;
    }
    let (Ok(count), Ok(len), Ok(mtime)) = (
        count.parse::<usize>(),
        len.parse::<u64>(),
        mtime.parse::<i128>(),
    ) else {
        return false;
    };
    if overlay_manifest_identity(lower) != (len, mtime) {
        return false;
    }
    overlay_skeleton_top_level(upper) == count
}

fn write_overlay_skeleton_marker(lower: &Path, upper: &Path) {
    let Some(layer) = upper.parent() else {
        return;
    };
    let (len, mtime) = overlay_manifest_identity(lower);
    let count = overlay_skeleton_top_level(upper);
    // Best effort: a layer whose marker cannot be written (or a restored tree
    // whose marker is stale) only costs the next command a rebuild.
    let _ = std::fs::write(
        layer.join(OVERLAY_SKELETON_MARKER_NAME),
        format!("{OVERLAY_SKELETON_MARKER_HEADER} {count} {len} {mtime}\n"),
    );
}

fn open_overlay_dir(path: &Path) -> Result<std::fs::File, std::io::Error> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let fd = unsafe { libc::openat(libc::AT_FDCWD, c.as_ptr(), OVERLAY_DIR_FLAGS) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Build the upper's directory skeleton from the image resolver's sidecar.
///
/// The file is a strict preorder of `(depth, name)` pairs, depth 1 being the
/// root's children. A descriptor stack mirrors the current path, so the walk
/// costs one `openat` + one `mkdirat` per directory and never re-reads the
/// lower; `O_NOFOLLOW` everywhere keeps a restored upper from steering a
/// component elsewhere. Any malformed row returns `Err` and the caller falls
/// back to the live walk, so a missing or truncated sidecar is never fatal.
fn build_overlay_dir_skeleton_from_manifest(
    lower: &Path,
    upper: &Path,
) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let entry = lower.parent().ok_or_else(|| {
        format!("overlay dir manifest: {} has no parent entry", lower.display())
    })?;
    let manifest = entry.join(DIR_MANIFEST_NAME);
    let metadata = std::fs::symlink_metadata(&manifest)
        .map_err(|e| format!("overlay dir manifest {}: {e}", manifest.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "overlay dir manifest {} is not a regular file",
            manifest.display()
        ));
    }
    if metadata.len() > DIR_MANIFEST_MAX_BYTES {
        return Err(format!(
            "overlay dir manifest {} is {} bytes, over the {} limit",
            manifest.display(),
            metadata.len(),
            DIR_MANIFEST_MAX_BYTES
        ));
    }
    let data = std::fs::read(&manifest)
        .map_err(|e| format!("overlay dir manifest {}: {e}", manifest.display()))?;
    let body = data.strip_prefix(DIR_MANIFEST_HEADER).ok_or_else(|| {
        format!("overlay dir manifest {}: bad header", manifest.display())
    })?;

    let upper_root = open_overlay_dir(upper).map_err(|e| {
        format!("overlay dir manifest upper {}: {e}", upper.display())
    })?;
    // First pass: row slices only. The second pass peeks at the next depth to
    // decide whether this directory needs a descriptor at all -- 6 k of the
    // base image's 11 k directories are leaves, and a leaf is created without
    // ever being reopened.
    let mut rows: Vec<(usize, &[u8])> = Vec::new();
    let mut offset = 0usize;
    while offset < body.len() {
        if body.len() - offset < 4 {
            return Err(format!(
                "overlay dir manifest {}: truncated row",
                manifest.display()
            ));
        }
        let depth =
            u16::from_le_bytes([body[offset], body[offset + 1]]) as usize;
        let name_len =
            u16::from_le_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;
        if depth == 0 || depth > 4096 {
            return Err(format!(
                "overlay dir manifest {}: depth {depth} out of range",
                manifest.display()
            ));
        }
        let end = offset
            .checked_add(name_len)
            .ok_or_else(|| "overlay dir manifest: length overflow".to_string())?;
        if end > body.len() {
            return Err(format!(
                "overlay dir manifest {}: truncated name",
                manifest.display()
            ));
        }
        let name = &body[offset..end];
        offset = end;
        if name.is_empty()
            || name.contains(&b'/')
            || name == b"."
            || name == b".."
        {
            return Err(format!(
                "overlay dir manifest {}: bad name at byte {offset}",
                manifest.display()
            ));
        }
        rows.push((depth, name));
    }
    if rows.is_empty() {
        return Err(format!(
            "overlay dir manifest {} lists no directories",
            manifest.display()
        ));
    }

    let mut stack: Vec<std::fs::File> = Vec::new();
    for (index, &(depth, name)) in rows.iter().enumerate() {
        if stack.len() + 1 < depth {
            return Err(format!(
                "overlay dir manifest {}: depth {depth} skips a parent",
                manifest.display()
            ));
        }
        stack.truncate(depth - 1);
        let parent_fd = stack
            .last()
            .map(|file| file.as_raw_fd())
            .unwrap_or_else(|| upper_root.as_raw_fd());
        let name_c = std::ffi::CString::new(name).map_err(|_| {
            format!(
                "overlay dir manifest {}: NUL in a name",
                manifest.display()
            )
        })?;
        if unsafe { libc::mkdirat(parent_fd, name_c.as_ptr(), 0o755) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EEXIST) {
                return Err(format!(
                    "overlay dir manifest {}: {e}",
                    manifest.display()
                ));
            }
        }
        let has_child = rows
            .get(index + 1)
            .map(|&(next, _)| next == depth + 1)
            .unwrap_or(false);
        if has_child {
            let child = unsafe {
                libc::openat(parent_fd, name_c.as_ptr(), OVERLAY_DIR_FLAGS)
            };
            if child < 0 {
                return Err(format!(
                    "overlay dir manifest {}: cannot open a directory with \
                     children: {}",
                    manifest.display(),
                    std::io::Error::last_os_error()
                ));
            }
            stack.push(unsafe { std::fs::File::from_raw_fd(child) });
        }
    }
    Ok(())
}

/// The walk itself, one `openat`/`mkdirat` per directory and no per-directory
/// `chmod`.
///
/// The path-shaped version (`create_dir(upper.join(rel))` +
/// `set_permissions`) resolves the whole relative path twice for every one of
/// the base image's ~11 k directories. Holding the parent's descriptor and
/// naming the child once cuts that to one lookup, and the mode comes from the
/// pinned umask instead of a second syscall. Descending through descriptors
/// also refuses to follow a component the upper may have grown (a restored
/// tree can carry a symlink where the lower has a directory); the path shape
/// would have followed it.
fn walk_overlay_dir_skeleton(lower: &Path, upper: &Path) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    use std::os::unix::ffi::OsStrExt;

    /// Owns the `DIR*` `fdopendir` took the descriptor for.
    struct DirStream(*mut libc::DIR);

    impl DirStream {
        fn from_fd(fd: std::os::fd::RawFd) -> Option<Self> {
            let dir = unsafe { libc::fdopendir(fd) };
            if dir.is_null() {
                unsafe { libc::close(fd) };
                return None;
            }
            Some(Self(dir))
        }

        fn fd(&self) -> std::os::fd::RawFd {
            unsafe { libc::dirfd(self.0) }
        }
    }

    impl Drop for DirStream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }

    /// Depth-first, one directory at a time: two descriptors per depth level,
    /// never one per pending sibling (`/opt/venv/...` has thousands of
    /// package directories in one level).
    fn walk(
        src: &DirStream,
        dst: std::os::fd::RawFd,
        dst_path: &Path,
        depth: usize,
    ) -> Result<(), String> {
        if depth > 4096 {
            return Err(format!(
                "overlay dir skeleton is deeper than 4096 levels at {}",
                dst_path.display()
            ));
        }
        loop {
            let entry = unsafe { libc::readdir(src.0) };
            if entry.is_null() {
                break;
            }
            let d_type = unsafe { (*entry).d_type };
            if d_type != libc::DT_DIR && d_type != libc::DT_UNKNOWN {
                continue;
            }
            // `d_name` is only valid until the next `readdir`; everything that
            // needs it happens before that call.
            let name_c = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            // `readdir` hands back `.` and `..`; `std::fs::read_dir` filtered
            // them, and following `..` would walk the tree forever.
            if matches!(name_c.to_bytes(), b"." | b"..") {
                continue;
            }
            if d_type == libc::DT_UNKNOWN {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let rc = unsafe {
                    libc::fstatat(
                        src.fd(),
                        name_c.as_ptr(),
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if rc != 0 || st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                    continue;
                }
            }
            let name = std::ffi::OsStr::from_bytes(name_c.to_bytes());
            let dest = dst_path.join(name);
            if unsafe { libc::mkdirat(dst, name_c.as_ptr(), 0o755) } != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(format!(
                        "overlay dir skeleton {}: {e}",
                        dest.display()
                    ));
                }
            }
            let child_src =
                unsafe { libc::openat(src.fd(), name_c.as_ptr(), OVERLAY_DIR_FLAGS) };
            if child_src < 0 {
                continue;
            }
            let child_dst =
                unsafe { libc::openat(dst, name_c.as_ptr(), OVERLAY_DIR_FLAGS) };
            if child_dst < 0 {
                unsafe { libc::close(child_src) };
                continue;
            }
            let child_src = match DirStream::from_fd(child_src) {
                Some(child) => child,
                None => {
                    unsafe { libc::close(child_dst) };
                    continue;
                }
            };
            let child_dst = unsafe { std::fs::File::from_raw_fd(child_dst) };
            walk(&child_src, child_dst.as_raw_fd(), &dest, depth + 1)?;
        }
        Ok(())
    }

    let lower_root = open_overlay_dir(lower).map_err(|e| {
        format!("overlay dir skeleton lower {}: {e}", lower.display())
    })?;
    let upper_root = open_overlay_dir(upper).map_err(|e| {
        format!("overlay dir skeleton upper {}: {e}", upper.display())
    })?;
    let lower_root = DirStream::from_fd(lower_root.into_raw_fd()).ok_or_else(|| {
        format!("overlay dir skeleton lower {}: fdopendir", lower.display())
    })?;
    walk(&lower_root, upper_root.as_raw_fd(), upper, 0)
}

fn overlay_option_path(role: &str, path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("overlay {role} path is not valid UTF-8: {}", path.display()))?;
    if value.contains(',') {
        return Err(format!(
            "overlay {role} path contains ',', which cannot be represented in mount options: {}",
            path.display()
        ));
    }
    Ok(value.to_string())
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

    fn manifest(rows: &[(u16, &[u8])]) -> Vec<u8> {
        let mut out = DIR_MANIFEST_HEADER.to_vec();
        for (depth, name) in rows {
            out.extend_from_slice(&depth.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name);
        }
        out
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sandlock-realroot-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("lower/usr/lib")).unwrap();
        std::fs::create_dir_all(path.join("lower/opt/one/two")).unwrap();
        std::fs::create_dir_all(path.join("upper")).unwrap();
        path
    }

    #[test]
    fn the_manifest_builds_every_directory_without_reading_the_lower() {
        let root = scratch("manifest-ok");
        std::fs::write(
            root.join(".dirs"),
            manifest(&[
                (1, b"usr"),
                (2, b"lib"),
                (1, b"opt"),
                (2, b"one"),
                (3, b"two"),
            ]),
        )
        .unwrap();
        build_overlay_dir_skeleton(&root.join("lower"), &root.join("upper"))
            .expect("the manifest walk must succeed");
        for relative in ["usr", "usr/lib", "opt", "opt/one", "opt/one/two"] {
            assert!(
                root.join("upper").join(relative).is_dir(),
                "{relative} must exist in the upper"
            );
        }
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(root.join("upper/usr"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_truncated_manifest_falls_back_to_the_lower_walk() {
        let root = scratch("manifest-truncated");
        let mut bytes = manifest(&[(1, b"usr"), (2, b"lib")]);
        bytes.truncate(bytes.len() - 1);
        std::fs::write(root.join(".dirs"), bytes).unwrap();
        build_overlay_dir_skeleton(&root.join("lower"), &root.join("upper"))
            .expect("the walk must still build the tree");
        assert!(root.join("upper/usr/lib").is_dir());
        assert!(root.join("upper/opt/one/two").is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_manifest_that_skips_a_parent_is_refused() {
        let root = scratch("manifest-depth");
        std::fs::write(root.join(".dirs"), manifest(&[(2, b"lib")])).unwrap();
        assert!(build_overlay_dir_skeleton_from_manifest(
            &root.join("lower"),
            &root.join("upper")
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_ready_marker_expires_when_a_top_level_directory_disappears() {
        let root = scratch("ready-marker");
        std::fs::write(
            root.join(".dirs"),
            manifest(&[
                (1, b"usr"),
                (2, b"lib"),
                (1, b"opt"),
                (2, b"one"),
                (3, b"two"),
            ]),
        )
        .unwrap();
        let lower = root.join("lower");
        let upper = root.join("upper");
        build_overlay_dir_skeleton(&lower, &upper).unwrap();
        assert!(root.join(".skeleton-ready").is_file());
        assert!(overlay_skeleton_is_current(&lower, &upper));

        // A sandbox that removes a top-level entry through its own tree must
        // get it back on the next command; the marker's count catches that.
        std::fs::remove_dir_all(upper.join("usr")).unwrap();
        assert!(!overlay_skeleton_is_current(&lower, &upper));
        build_overlay_dir_skeleton(&lower, &upper).unwrap();
        assert!(upper.join("usr/lib").is_dir());
        assert!(overlay_skeleton_is_current(&lower, &upper));

        std::fs::write(root.join(".skeleton-ready"), "not a marker\n").unwrap();
        assert!(!overlay_skeleton_is_current(&lower, &upper));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_whiteout_manifest_skips_a_real_entry_and_is_removed() {
        let root = scratch("whiteouts-real");
        std::fs::create_dir_all(root.join("upper/dir")).unwrap();
        std::fs::write(root.join("upper/dir/kept"), b"x").unwrap();
        let mut data = OVERLAY_WHITEOUTS_HEADER.to_vec();
        data.extend_from_slice(b"dir/kept\0");
        std::fs::write(root.join("whiteouts"), data).unwrap();

        restore_overlay_whiteouts(&root).unwrap();
        assert!(!root.join("whiteouts").exists());
        assert_eq!(
            std::fs::read(root.join("upper/dir/kept")).unwrap(),
            b"x"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_whiteout_path_that_escapes_and_a_missing_parent_are_refused() {
        let root = scratch("whiteouts-bad");
        let mut escape = OVERLAY_WHITEOUTS_HEADER.to_vec();
        escape.extend_from_slice(b"../escape\0");
        std::fs::write(root.join("whiteouts"), escape).unwrap();
        assert!(restore_overlay_whiteouts(&root).is_err());

        let mut missing = OVERLAY_WHITEOUTS_HEADER.to_vec();
        missing.extend_from_slice(b"missing/child\0");
        std::fs::write(root.join("whiteouts"), missing).unwrap();
        assert!(restore_overlay_whiteouts(&root).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
