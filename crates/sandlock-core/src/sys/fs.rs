//! Filesystem syscall helpers shared by the chroot and COW supervisors.
//!
//! `openat2_in_root` is the single confined-open primitive: it asks the
//! kernel to resolve a path with `RESOLVE_IN_ROOT`, so symlinks and `..`
//! cannot escape the given root. Both supervisors route child-controlled
//! path opens through it (see issue #112).

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::Path;

/// openat2 syscall number, sourced from the `syscalls` crate via `arch`.
const SYS_OPENAT2: libc::c_long = crate::arch::SYS_OPENAT2 as libc::c_long;

/// RESOLVE_IN_ROOT: treat the dirfd as the filesystem root for resolution.
const RESOLVE_IN_ROOT: u64 = 0x10;

/// Extra `openat2` attempts allowed after the kernel answers `EAGAIN`.
///
/// `EAGAIN` is the kernel saying "I could not *prove* the `..` I just walked
/// stayed inside the root" -- openat2(2): "how.resolve contains either
/// RESOLVE_IN_ROOT or RESOLVE_BENEATH, and the kernel could not ensure that a
/// ".." component didn't escape (due to a race condition or potential
/// attack). The caller may choose to retry the openat2() call." It is a
/// statement about the *walk*, not about the path: the racing rename/mount
/// operation that made the walk unverifiable completes, and the retry
/// succeeds. Measured in a container while a neighbouring directory was being
/// renamed in a loop: 3-5% of `..`-resolving opens return `EAGAIN`, and no
/// call in ~5e5 sampled attempts ever exhausted 4 immediate retries.
///
/// The budget is deliberately *bounded* rather than a `while EAGAIN` loop:
///
///  * the racing actor can be the sandboxed child itself. Every attempt is a
///    syscall the supervisor performs on the child's behalf, so an unbounded
///    loop lets a hostile workload keep the mediator spinning (a livelock in
///    the single-threaded dispatch that one sandbox shares with every other
///    syscall it makes);
///  * each retry is immediate (no sleep, just a `sched_yield`), so the budget
///    is what keeps a lookup's added latency bounded and predictable;
///  * once the budget is spent the *retryable* errno is returned unchanged --
///    never rewritten into `ENOENT` -- so the caller (and, for a mediated
///    open, the child) still learns "EAGAIN, try again" instead of the false
///    "does not exist" that turned this into a silent exit 127 (FUP-26).
const EAGAIN_RETRY_BUDGET: u32 = 4;

/// Kernel `struct open_how` for openat2().
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn last_errno(fallback: i32) -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(fallback)
}

/// Open a path confined within `root` using `openat2(RESOLVE_IN_ROOT)`.
///
/// The kernel handles symlink resolution, `..` traversal, and prevents
/// escapes above the root, eliminating TOCTOU races and the edge cases
/// inherent in userspace path walking.
pub(crate) fn openat2_in_root(
    root: &Path,
    path: &str,
    flags: i32,
    mode: u32,
) -> Result<RawFd, i32> {
    openat2_in_root_with_resolve(root, path, flags, mode, 0)
}

/// As [`openat2_in_root`], plus the caller's own `RESOLVE_*` flags.
///
/// Used when servicing an `openat2` on behalf of a child: the child chose
/// those flags to make the kernel refuse something (a symlink, a mount
/// crossing), and performing the open for it must not quietly grant what it
/// declined. The union with `RESOLVE_IN_ROOT` can only be stricter, never
/// looser, so the sandbox's own confinement still holds whatever is added.
pub(crate) fn openat2_in_root_with_resolve(
    root: &Path,
    path: &str,
    flags: i32,
    mode: u32,
    extra_resolve: u64,
) -> Result<RawFd, i32> {
    let c_root = CString::new(root.to_str().unwrap_or("")).map_err(|_| libc::EINVAL)?;
    let root_fd = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(last_errno(libc::EIO));
    }

    let rel_path = path.strip_prefix('/').unwrap_or(path);
    let rel_path = if rel_path.is_empty() { "." } else { rel_path };
    let c_path = CString::new(rel_path).map_err(|_| {
        unsafe { libc::close(root_fd) };
        libc::EINVAL
    })?;

    let how = OpenHow {
        flags: flags as u64,
        mode: mode as u64,
        resolve: RESOLVE_IN_ROOT | extra_resolve,
    };

    // `EAGAIN` here is not a verdict about the path (see
    // `EAGAIN_RETRY_BUDGET`): retry the identical open a bounded number of
    // times before handing the retryable errno back. Everything that is not
    // `EAGAIN` -- and an `EAGAIN` whose budget is spent -- is returned as the
    // kernel reported it, so "no such file" and "the kernel could not
    // guarantee this `..`" stay distinguishable to the caller.
    let mut retries = 0u32;
    let fd = loop {
        match openat2_once(root_fd, &c_path, &how) {
            Ok(fd) => break fd,
            Err(libc::EAGAIN) if retries < EAGAIN_RETRY_BUDGET => {
                retries += 1;
                // Give the racing rename/mount operation a chance to finish;
                // the retry is otherwise byte-identical to the first attempt.
                unsafe { libc::sched_yield() };
            }
            Err(errno) => {
                unsafe { libc::close(root_fd) };
                return Err(errno);
            }
        }
    };

    unsafe { libc::close(root_fd) };
    Ok(fd)
}

/// One `openat2` attempt, with the unit-test fault seam.
///
/// Kept separate from the retry loop so a test can make a *deterministic*
/// `EAGAIN` (the real one needs a racing rename on the walked path) and count
/// both attempts and observed `EAGAIN`s exactly.
fn openat2_once(root_fd: RawFd, path: &CString, how: &OpenHow) -> Result<RawFd, i32> {
    test_faults::note_attempt();
    if test_faults::take_injected_eagain() {
        test_faults::note_eagain();
        return Err(libc::EAGAIN);
    }
    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            root_fd,
            path.as_ptr(),
            how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;
    if fd < 0 {
        let errno = last_errno(libc::ENOENT);
        if errno == libc::EAGAIN {
            test_faults::note_eagain();
        }
        Err(errno)
    } else {
        Ok(fd)
    }
}

/// Observation / fault-injection seam for the retry loop's unit tests.
///
/// Only the counters exist in a test build; the real fault the product has to
/// absorb is a race with a rename of a directory the `..` walk passes through,
/// which cannot be made deterministic from a test. Injecting the kernel's
/// answer keeps the *product* code path under test (the retry loop, its
/// budget and its errno classification) instead of testing a copy of it.
#[cfg(test)]
pub(crate) mod test_faults {
    use std::cell::Cell;

    // Thread-local, not process-global: `cargo test` runs each test on its own
    // thread, and the other tests in this module call `openat2_in_root`
    // concurrently. A global counter would be stamped by their attempts and
    // the exact-count assertions below could not hold.
    thread_local! {
        static INJECTED_EAGAIN: Cell<usize> = const { Cell::new(0) };
        static ATTEMPTS: Cell<usize> = const { Cell::new(0) };
        static EAGAIN_SEEN: Cell<usize> = const { Cell::new(0) };
    }

    /// Make the next `n` attempts answer `EAGAIN` without calling the kernel.
    pub(crate) fn inject_eagain(n: usize) {
        INJECTED_EAGAIN.with(|c| c.set(n));
    }

    /// Forget the previous injection and zero both counters.
    pub(crate) fn reset() {
        INJECTED_EAGAIN.with(|c| c.set(0));
        ATTEMPTS.with(|c| c.set(0));
        EAGAIN_SEEN.with(|c| c.set(0));
    }

    pub(crate) fn attempts() -> usize {
        ATTEMPTS.with(|c| c.get())
    }

    pub(crate) fn eagain_seen() -> usize {
        EAGAIN_SEEN.with(|c| c.get())
    }

    pub(crate) fn note_attempt() {
        ATTEMPTS.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn note_eagain() {
        EAGAIN_SEEN.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn take_injected_eagain() -> bool {
        INJECTED_EAGAIN.with(|c| match c.get() {
            0 => false,
            n => {
                c.set(n - 1);
                true
            }
        })
    }
}

#[cfg(not(test))]
pub(crate) mod test_faults {
    /// Never injects anything; the retry loop must be free of test-only state
    /// in a product build.
    #[inline]
    pub(crate) fn note_attempt() {}

    #[inline]
    pub(crate) fn note_eagain() {}

    #[inline]
    pub(crate) fn take_injected_eagain() -> bool {
        false
    }
}

/// Empty C string for the `AT_EMPTY_PATH` family of calls (operate on the fd).
const EMPTY: *const libc::c_char = b"\0".as_ptr() as *const libc::c_char;

/// Open a confined `O_PATH` handle to `path` under `root`.
///
/// `O_PATH` needs no read permission and does no I/O, so it is the right
/// handle for metadata operations. `RESOLVE_IN_ROOT` confines every component
/// of the walk to `root`. When `follow` is false the final component is opened
/// with `O_NOFOLLOW`, yielding a handle to the symlink itself (lstat
/// semantics); when true the final symlink is followed, but still confined.
fn opath_in_root(root: &Path, path: &str, follow: bool) -> Result<RawFd, i32> {
    let mut flags = libc::O_PATH | libc::O_CLOEXEC;
    if !follow {
        flags |= libc::O_NOFOLLOW;
    }
    openat2_in_root(root, path, flags, 0)
}

/// `stat`/`lstat` a path confined within `root`.
///
/// `follow` selects `stat` (follow the final symlink) vs `lstat` (stat the
/// link itself) semantics for the final component; intermediate components are
/// always confined to `root`.
pub(crate) fn statat_in_root(root: &Path, path: &str, follow: bool) -> Result<libc::stat, i32> {
    let fd = opath_in_root(root, path, follow)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(fd, EMPTY, &mut st, libc::AT_EMPTY_PATH) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(st)
    }
}

/// `statx` a path confined within `root`, writing the raw `struct statx` into
/// `buf` (must be at least `sizeof(struct statx)`, 256 bytes). The child's
/// `AT_SYMLINK_NOFOLLOW` in `flags` selects follow vs nofollow; other `flags`
/// bits (sync hints) are preserved.
pub(crate) fn statx_in_root(
    root: &Path,
    path: &str,
    flags: i32,
    mask: u32,
    buf: &mut [u8],
) -> Result<(), i32> {
    // The kernel writes sizeof(struct statx) = 256 bytes; refuse a short buffer
    // rather than risk a heap overflow if a future caller passes a smaller one.
    if buf.len() < 256 {
        return Err(libc::EINVAL);
    }
    let follow = (flags & libc::AT_SYMLINK_NOFOLLOW) == 0;
    let fd = opath_in_root(root, path, follow)?;
    // statx the handle itself via AT_EMPTY_PATH; follow/nofollow is already
    // baked into how the fd was opened, so drop AT_SYMLINK_NOFOLLOW here.
    let stx_flags = (flags & !libc::AT_SYMLINK_NOFOLLOW) | libc::AT_EMPTY_PATH;
    let rc = unsafe {
        libc::syscall(libc::SYS_statx, fd, EMPTY, stx_flags, mask, buf.as_mut_ptr())
    };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Set timestamps on a path confined within `root`.
///
/// Resolves a confined `O_PATH` handle, then stamps it through its
/// `/proc/self/fd/N` magic link. The kernel cannot take an `O_PATH` fd
/// directly for `utimensat` (EBADF), but the magic link jumps straight to the
/// already-confined inode, so resolution cannot escape. `follow` selects
/// whether the final symlink is followed or stamped in place (baked into how
/// the handle is opened).
pub(crate) fn utimensat_in_root(
    root: &Path,
    path: &str,
    times: *const libc::timespec,
    follow: bool,
) -> Result<(), i32> {
    let fd = opath_in_root(root, path, follow)?;
    let proc = CString::new(format!("/proc/self/fd/{}", fd)).map_err(|_| {
        unsafe { libc::close(fd) };
        libc::EINVAL
    })?;
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, proc.as_ptr(), times, 0) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Read a symlink's target confined within `root`. Returns the raw target
/// bytes. `Err(EINVAL)` means the final component is not a symlink.
pub(crate) fn readlink_in_root(root: &Path, path: &str) -> Result<Vec<u8>, i32> {
    // O_PATH|O_NOFOLLOW opens the link itself; readlinkat with an empty path
    // then reads its target. The parent walk is confined to root.
    let fd = opath_in_root(root, path, false)?;
    let mut buf = vec![0u8; 4096];
    let n = unsafe {
        libc::readlinkat(fd, EMPTY, buf.as_mut_ptr() as *mut libc::c_char, buf.len())
    };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if n < 0 {
        return Err(err);
    }
    buf.truncate(n as usize);
    Ok(buf)
}

// ============================================================
// Confined mutating operations (write side, issue #112)
//
// Every upper-layer mutation must resolve its target's PARENT confined to the
// layer root, then act via an `*at` call on the basename. A verbatim-copied
// symlink in upper must never let `create_dir_all`/`File::create`/`symlink`/
// `rename`/`unlink` follow out of the tree and write/delete on the host.
// ============================================================

/// Split a relative path into (parent, basename). Parent is "" when `rel` is a
/// single component (meaning the root itself).
fn split_rel(rel: &str) -> (&str, &str) {
    let rel = rel.trim_matches('/');
    match rel.rfind('/') {
        Some(i) => (&rel[..i], &rel[i + 1..]),
        None => ("", rel),
    }
}

/// Open a confined `O_PATH|O_DIRECTORY` handle to the PARENT of `rel` under
/// `root`, returning (parent_fd, basename). The parent must already exist;
/// `RESOLVE_IN_ROOT` clamps any symlink/`..` in the parent walk to `root`.
fn parent_dir_in_root(root: &Path, rel: &str) -> Result<(RawFd, String), i32> {
    let (parent, base) = split_rel(rel);
    if base.is_empty() || base == "." || base == ".." {
        return Err(libc::EINVAL);
    }
    let parent = if parent.is_empty() { "." } else { parent };
    let fd = openat2_in_root(root, parent, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC, 0)?;
    Ok((fd, base.to_string()))
}

/// `mkdir` a single component confined within `root` (parent must exist).
pub(crate) fn mkdir_in_root(root: &Path, rel: &str, mode: u32) -> Result<(), i32> {
    let (pfd, base) = parent_dir_in_root(root, rel)?;
    let cbase = CString::new(base).map_err(|_| {
        unsafe { libc::close(pfd) };
        libc::EINVAL
    })?;
    let rc = unsafe { libc::mkdirat(pfd, cbase.as_ptr(), mode as libc::mode_t) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(pfd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// `mkdir -p` confined within `root`. Each level is created via `mkdir_in_root`,
/// so a symlinked parent component is clamped to the root and cannot escape.
pub(crate) fn mkdirp_in_root(root: &Path, rel: &str, mode: u32) -> Result<(), i32> {
    let mut prefix = String::new();
    for comp in rel.split('/').filter(|c| !c.is_empty() && *c != ".") {
        if comp == ".." {
            return Err(libc::EINVAL);
        }
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(comp);
        match mkdir_in_root(root, &prefix, mode) {
            Ok(()) | Err(libc::EEXIST) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Create a file-system node `rel` confined within `root` (parent must exist).
/// `mode` must include the type bits (e.g. `S_IFIFO | 0o600`); `dev` is only
/// meaningful for `S_IFBLK`/`S_IFCHR` nodes.
pub(crate) fn mknod_in_root(root: &Path, rel: &str, mode: u32, dev: u64) -> Result<(), i32> {
    let (pfd, base) = parent_dir_in_root(root, rel)?;
    let cbase = CString::new(base).map_err(|_| {
        unsafe { libc::close(pfd) };
        libc::EINVAL
    })?;
    let rc = unsafe { libc::mknodat(pfd, cbase.as_ptr(), mode as libc::mode_t, dev as libc::dev_t) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(pfd) };
    if rc < 0 { Err(err) } else { Ok(()) }
}

/// Create a symlink `rel -> target` confined within `root` (parent must exist).
pub(crate) fn symlinkat_in_root(root: &Path, rel: &str, target: &str) -> Result<(), i32> {
    let (pfd, base) = parent_dir_in_root(root, rel)?;
    let cbase = CString::new(base).ok();
    let ctarget = CString::new(target).ok();
    let (cbase, ctarget) = match (cbase, ctarget) {
        (Some(b), Some(t)) => (b, t),
        _ => {
            unsafe { libc::close(pfd) };
            return Err(libc::EINVAL);
        }
    };
    let rc = unsafe { libc::symlinkat(ctarget.as_ptr(), pfd, cbase.as_ptr()) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(pfd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Unlink a file (or rmdir an empty dir) confined within `root`.
pub(crate) fn unlinkat_in_root(root: &Path, rel: &str, remove_dir: bool) -> Result<(), i32> {
    let (pfd, base) = parent_dir_in_root(root, rel)?;
    let cbase = CString::new(base).map_err(|_| {
        unsafe { libc::close(pfd) };
        libc::EINVAL
    })?;
    let flag = if remove_dir { libc::AT_REMOVEDIR } else { 0 };
    let rc = unsafe { libc::unlinkat(pfd, cbase.as_ptr(), flag) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(pfd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Recursively remove a directory tree confined within `root`. Each descent
/// uses `O_NOFOLLOW`, so a symlink entry is unlinked (never traversed).
pub(crate) fn remove_dir_all_in_root(root: &Path, rel: &str) -> Result<(), i32> {
    // Open the target directory itself confined, without following a final
    // symlink, then empty it via the dirfd before removing the now-empty dir.
    let dir_fd = openat2_in_root(
        root,
        rel,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    remove_dir_contents(dir_fd); // consumes/closes dir_fd
    unlinkat_in_root(root, rel, true)
}

/// Empty a directory referred to by `dir_fd` (which this function takes
/// ownership of and closes), recursing into subdirectories via `O_NOFOLLOW`.
fn remove_dir_contents(dir_fd: RawFd) {
    // fdopendir takes ownership of dir_fd; closedir closes it.
    let dirp = unsafe { libc::fdopendir(dir_fd) };
    if dirp.is_null() {
        unsafe { libc::close(dir_fd) };
        return;
    }
    loop {
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        let name_ptr = unsafe { (*ent).d_name.as_ptr() };
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        // Is this entry a directory (without following a symlink)?
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let is_dir = unsafe {
            libc::fstatat(
                libc::dirfd(dirp),
                name_ptr,
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            ) == 0
        } && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        if is_dir {
            let child = unsafe {
                libc::openat(
                    libc::dirfd(dirp),
                    name_ptr,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if child >= 0 {
                remove_dir_contents(child);
            }
            unsafe { libc::unlinkat(libc::dirfd(dirp), name_ptr, libc::AT_REMOVEDIR) };
        } else {
            unsafe { libc::unlinkat(libc::dirfd(dirp), name_ptr, 0) };
        }
    }
    unsafe { libc::closedir(dirp) };
}

/// Rename `old_rel` to `new_rel`, both confined within `root`.
pub(crate) fn renameat_in_root(root: &Path, old_rel: &str, new_rel: &str) -> Result<(), i32> {
    let (opfd, ob) = parent_dir_in_root(root, old_rel)?;
    let (npfd, nb) = match parent_dir_in_root(root, new_rel) {
        Ok(v) => v,
        Err(e) => {
            unsafe { libc::close(opfd) };
            return Err(e);
        }
    };
    let close_both = || unsafe {
        libc::close(opfd);
        libc::close(npfd);
    };
    let (cob, cnb) = match (CString::new(ob), CString::new(nb)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => {
            close_both();
            return Err(libc::EINVAL);
        }
    };
    let rc = unsafe { libc::renameat(opfd, cob.as_ptr(), npfd, cnb.as_ptr()) };
    let err = last_errno(libc::EIO);
    close_both();
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Create a hard link `new_rel -> old_rel` confined within `root`. The old path
/// is not dereferenced (no `AT_SYMLINK_FOLLOW`).
pub(crate) fn linkat_in_root(root: &Path, old_rel: &str, new_rel: &str) -> Result<(), i32> {
    let (opfd, ob) = parent_dir_in_root(root, old_rel)?;
    let (npfd, nb) = match parent_dir_in_root(root, new_rel) {
        Ok(v) => v,
        Err(e) => {
            unsafe { libc::close(opfd) };
            return Err(e);
        }
    };
    let close_both = || unsafe {
        libc::close(opfd);
        libc::close(npfd);
    };
    let (cob, cnb) = match (CString::new(ob), CString::new(nb)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => {
            close_both();
            return Err(libc::EINVAL);
        }
    };
    let rc = unsafe { libc::linkat(opfd, cob.as_ptr(), npfd, cnb.as_ptr(), 0) };
    let err = last_errno(libc::EIO);
    close_both();
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// `chmod` a path confined within `root`, following the final symlink (as
/// `chmod` does) but never escaping the root. Operates through the confined
/// `O_PATH` handle's `/proc/self/fd` magic link.
pub(crate) fn chmod_in_root(root: &Path, rel: &str, mode: u32) -> Result<(), i32> {
    let fd = opath_in_root(root, rel, true)?;
    let proc = CString::new(format!("/proc/self/fd/{}", fd)).map_err(|_| {
        unsafe { libc::close(fd) };
        libc::EINVAL
    })?;
    let rc = unsafe { libc::chmod(proc.as_ptr(), mode as libc::mode_t) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// `chown` a path confined within `root`, following the final symlink (as
/// `chown` does) but never escaping the root, via the confined `O_PATH`
/// handle's `/proc/self/fd` magic link.
pub(crate) fn chown_in_root(root: &Path, rel: &str, uid: u32, gid: u32) -> Result<(), i32> {
    let fd = opath_in_root(root, rel, true)?;
    let proc = CString::new(format!("/proc/self/fd/{}", fd)).map_err(|_| {
        unsafe { libc::close(fd) };
        libc::EINVAL
    })?;
    let rc = unsafe { libc::chown(proc.as_ptr(), uid, gid) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

// ============================================================
// File-handle identity (non-chroot fs-deny path)
// ============================================================

/// `AT_HANDLE_FID` (Linux 6.5+): request an identity-only file handle that
/// "may not be usable with open_by_handle_at". Not in libc 0.2.x. The kernel
/// can encode this for essentially every filesystem, including those without
/// NFS-export ops (it falls back to a generic inode FID).
const AT_HANDLE_FID: libc::c_int = 0x200;

/// Encode a file's stable identity via `name_to_handle_at`: returns
/// `(handle_type, handle_bytes)`, a token that travels with the file's inode
/// (plus a generation number) rather than the path used to reach it.
/// `dirfd`/`path`/`base_flags` follow the syscall: `(AT_FDCWD, path,
/// AT_SYMLINK_FOLLOW)` for a path, or `(fd, "", AT_EMPTY_PATH)` for an fd.
///
/// Prefers `AT_HANDLE_FID` for the widest filesystem coverage; on a pre-6.5
/// kernel that flag is rejected with `EINVAL`, so we retry without it (a plain
/// decodeable handle, supported by every export-capable filesystem). `None` if
/// no handle can be encoded — the caller then relies on a path-based fallback.
pub(crate) fn file_handle(
    dirfd: RawFd,
    path: &std::ffi::CStr,
    base_flags: libc::c_int,
) -> Option<(i32, Vec<u8>)> {
    match encode_fh(dirfd, path, base_flags | AT_HANDLE_FID) {
        Ok(h) => Some(h),
        Err(libc::EINVAL) => encode_fh(dirfd, path, base_flags).ok(),
        Err(_) => None,
    }
}

fn encode_fh(dirfd: RawFd, path: &std::ffi::CStr, flags: libc::c_int) -> Result<(i32, Vec<u8>), i32> {
    // `struct file_handle` is variable length; keep the header and a
    // MAX_HANDLE_SZ payload contiguous and 4-byte aligned (c_uint first).
    #[repr(C)]
    struct HandleBuf {
        handle_bytes: u32,
        handle_type: i32,
        f_handle: [u8; libc::MAX_HANDLE_SZ as usize],
    }
    let mut hb = HandleBuf {
        handle_bytes: libc::MAX_HANDLE_SZ as u32,
        handle_type: 0,
        f_handle: [0u8; libc::MAX_HANDLE_SZ as usize],
    };
    let mut mount_id: libc::c_int = 0;
    let r = unsafe {
        libc::name_to_handle_at(
            dirfd,
            path.as_ptr(),
            &mut hb as *mut HandleBuf as *mut libc::file_handle,
            &mut mount_id,
            flags,
        )
    };
    if r != 0 {
        return Err(last_errno(libc::EIO));
    }
    let n = (hb.handle_bytes as usize).min(libc::MAX_HANDLE_SZ as usize);
    Ok((hb.handle_type, hb.f_handle[..n].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    /// A rootfs file the `..`-retry tests open for real.
    fn retry_fixture() -> (TempDir, std::path::PathBuf) {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("plain"), "x").unwrap();
        let root = tmp.path().to_path_buf();
        (tmp, root)
    }

    // ── FUP-26: `EAGAIN` from openat2(RESOLVE_IN_ROOT) is retried ─────────

    /// The kernel's retryable answer must not become a failed open: two
    /// injected `EAGAIN`s are absorbed and the third attempt returns the fd.
    #[test]
    fn eagain_is_retried_until_the_open_succeeds() {
        let (_tmp, root) = retry_fixture();
        test_faults::reset();
        test_faults::inject_eagain(2);
        let fd = openat2_in_root(&root, "plain", libc::O_RDONLY, 0)
            .expect("two EAGAINs must be retried into a successful open");
        unsafe { libc::close(fd) };
        assert_eq!(test_faults::attempts(), 3, "two retries after the first attempt");
        assert_eq!(test_faults::eagain_seen(), 2, "both EAGAINs were observed");
        assert!(!test_faults::take_injected_eagain(), "injection drained");
    }

    /// The retry is bounded *and* the errno classification survives it: a
    /// permanent `EAGAIN` costs exactly `EAGAIN_RETRY_BUDGET` extra attempts
    /// and is reported as `EAGAIN` (retryable), never as `ENOENT`.
    #[test]
    fn permanent_eagain_is_bounded_and_still_eagain() {
        let (_tmp, root) = retry_fixture();
        test_faults::reset();
        test_faults::inject_eagain(usize::MAX);
        let err = openat2_in_root(&root, "plain", libc::O_RDONLY, 0)
            .expect_err("a permanent EAGAIN must end as an error, not a hang");
        assert_eq!(err, libc::EAGAIN, "the retryable errno is handed back as-is");
        // Pinned literally: the budget is the documented bound, so shrinking
        // it (or dropping the retry) is a visible, deliberate change.
        assert_eq!(EAGAIN_RETRY_BUDGET, 4, "documented retry budget");
        assert_eq!(
            test_faults::attempts(),
            5,
            "one attempt plus the four bounded retries"
        );
        assert_eq!(
            test_faults::eagain_seen(),
            5,
            "every attempt observed the kernel's answer"
        );
    }

    /// Every other errno is returned immediately: `ENOENT` is a verdict about
    /// the path, and re-issuing the identical syscall cannot change it.
    #[test]
    fn non_retryable_errno_is_not_retried() {
        let (_tmp, root) = retry_fixture();
        test_faults::reset();
        let err = openat2_in_root(&root, "absent", libc::O_RDONLY, 0)
            .expect_err("a missing file must still be ENOENT");
        assert_eq!(err, libc::ENOENT);
        assert_eq!(test_faults::attempts(), 1, "no retry for a non-EAGAIN errno");
        assert_eq!(test_faults::eagain_seen(), 0);
    }

    /// The seam must not hide the real syscall: with nothing injected, a
    /// `..`-free open inside the tree still works and costs one attempt.
    #[test]
    fn the_uninjected_path_still_calls_the_kernel_once() {
        let (_tmp, root) = retry_fixture();
        test_faults::reset();
        let fd = openat2_in_root(&root, "plain", libc::O_RDONLY, 0).unwrap();
        unsafe { libc::close(fd) };
        assert_eq!(test_faults::attempts(), 1);
        assert_eq!(test_faults::eagain_seen(), 0);
    }

    #[test]
    fn openat2_in_root_confines_absolute_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/shadow"), "confined").unwrap();
        // Absolute symlink to the host /etc/shadow: kernel keeps it in root.
        symlink("/etc/shadow", root.join("evil")).unwrap();

        match openat2_in_root(root, "/evil", libc::O_PATH, 0) {
            Ok(fd) => {
                let resolved =
                    std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
                unsafe { libc::close(fd) };
                assert!(resolved.starts_with(root), "escaped root: {:?}", resolved);
            }
            Err(libc::ENOSYS) => {} // kernel without openat2
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn openat2_in_root_clamps_parent_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        match openat2_in_root(root, "/../../../etc/group", libc::O_PATH, 0) {
            Err(libc::ENOENT) => {} // clamped to <root>/etc/group, absent
            Err(libc::ENOSYS) => {}
            Ok(fd) => {
                let resolved =
                    std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
                unsafe { libc::close(fd) };
                assert!(resolved.starts_with(root), "escaped root: {:?}", resolved);
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    // Skip a test body cleanly on kernels without openat2.
    macro_rules! skip_if_nosys {
        ($e:expr) => {
            match $e {
                Err(libc::ENOSYS) => return,
                other => other,
            }
        };
    }

    #[test]
    fn statat_lstat_does_not_follow_escaping_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        symlink("/etc/group", root.join("evil")).unwrap();

        // lstat: stat the link itself, confined; must report a symlink, never
        // the host /etc/group it points at.
        let st = skip_if_nosys!(statat_in_root(root, "evil", false)).unwrap();
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFLNK, "expected a symlink");

        // stat (follow): the absolute target is clamped to <root>/etc/group,
        // which does not exist, so the host file is never reached.
        assert_eq!(statat_in_root(root, "evil", true), Err(libc::ENOENT));
    }

    #[test]
    fn statat_confines_symlinked_parent() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        symlink("/etc", root.join("dirlink")).unwrap();
        // dirlink/group would be /etc/group on the host; confined it is absent.
        assert_eq!(
            skip_if_nosys!(statat_in_root(root, "dirlink/group", true)),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn readlink_confined_reads_in_tree_link_but_not_through_escaping_parent() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        symlink("/etc/group", root.join("evil")).unwrap();
        symlink("/etc", root.join("dirlink")).unwrap();

        // The link's own target string is the child's data: returning it is fine.
        let target = skip_if_nosys!(readlink_in_root(root, "evil")).unwrap();
        assert_eq!(target, b"/etc/group");

        // But a link reached through an escaping parent is not visible.
        assert_eq!(readlink_in_root(root, "dirlink/group"), Err(libc::ENOENT));
    }

    #[test]
    fn utimensat_confined_stamps_in_tree_and_refuses_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("f"), "x").unwrap();
        symlink("/etc", root.join("dirlink")).unwrap();

        let times = [
            libc::timespec { tv_sec: 1_000_000, tv_nsec: 0 },
            libc::timespec { tv_sec: 1_000_000, tv_nsec: 0 },
        ];
        // In-tree file: stamp succeeds and takes effect.
        skip_if_nosys!(utimensat_in_root(root, "f", times.as_ptr(), true)).unwrap();
        let meta = std::fs::metadata(root.join("f")).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(meta.mtime(), 1_000_000);

        // Escaping parent: refused, so the host /etc/group is never stamped.
        assert_eq!(
            utimensat_in_root(root, "dirlink/group", times.as_ptr(), true),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn statx_confines_symlinked_parent() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("f"), "data").unwrap();
        symlink("/etc", root.join("dirlink")).unwrap();
        let mut buf = vec![0u8; 256];

        // In-tree file resolves; escaping parent does not.
        skip_if_nosys!(statx_in_root(root, "f", 0, libc::STATX_BASIC_STATS, &mut buf)).unwrap();
        assert_eq!(
            statx_in_root(root, "dirlink/group", 0, libc::STATX_BASIC_STATS, &mut buf),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn mkdirp_creates_in_tree_and_refuses_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        if mkdirp_in_root(root, "a/b/c", 0o755) == Err(libc::ENOSYS) {
            return;
        }
        assert!(root.join("a/b/c").is_dir());

        // Under an escaping symlinked parent: refused, and nothing created on host.
        symlink("/etc", root.join("evil")).unwrap();
        let r = mkdirp_in_root(root, "evil/sandlock_escape_probe", 0o755);
        assert!(matches!(r, Err(libc::ENOENT)), "got {:?}", r);
        assert!(!std::path::Path::new("/etc/sandlock_escape_probe").exists());
    }

    #[test]
    fn symlinkat_creates_in_tree_and_refuses_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        if mkdirp_in_root(root, "d", 0o755) == Err(libc::ENOSYS) {
            return;
        }
        symlinkat_in_root(root, "d/link", "target").unwrap();
        assert_eq!(
            std::fs::read_link(root.join("d/link")).unwrap(),
            std::path::Path::new("target")
        );

        symlink("/etc", root.join("evil")).unwrap();
        let r = symlinkat_in_root(root, "evil/sandlock_escape_link", "x");
        assert!(matches!(r, Err(libc::ENOENT)), "got {:?}", r);
        assert!(!std::path::Path::new("/etc/sandlock_escape_link").is_symlink());
    }

    #[test]
    fn unlinkat_and_rename_in_tree() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        if mkdirp_in_root(root, "d", 0o755) == Err(libc::ENOSYS) {
            return;
        }
        std::fs::write(root.join("d/old"), "v").unwrap();
        renameat_in_root(root, "d/old", "d/new").unwrap();
        assert!(!root.join("d/old").exists());
        assert_eq!(std::fs::read_to_string(root.join("d/new")).unwrap(), "v");
        unlinkat_in_root(root, "d/new", false).unwrap();
        assert!(!root.join("d/new").exists());
    }

    #[test]
    fn remove_dir_all_does_not_follow_symlink_entries() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("keep.txt"), "important").unwrap();
        if mkdirp_in_root(root, "a", 0o755) == Err(libc::ENOSYS) {
            return;
        }
        std::fs::write(root.join("a/file.txt"), "x").unwrap();
        symlink(outside.path(), root.join("a/lnk")).unwrap();

        remove_dir_all_in_root(root, "a").unwrap();
        assert!(!root.join("a").exists(), "tree not removed");
        // The symlink entry was unlinked, never traversed: outside survives.
        assert!(
            outside.path().join("keep.txt").exists(),
            "recursive remove followed a symlink out of the tree"
        );
    }

    #[test]
    fn chmod_in_tree_and_refuses_escape() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("f"), "x").unwrap();
        if chmod_in_root(root, "f", 0o600) == Err(libc::ENOSYS) {
            return;
        }
        assert_eq!(
            std::fs::metadata(root.join("f")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        symlink("/etc", root.join("evil")).unwrap();
        assert!(matches!(
            chmod_in_root(root, "evil/group", 0o777),
            Err(libc::ENOENT)
        ));
    }
}
