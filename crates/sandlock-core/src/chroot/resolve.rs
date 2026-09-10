use std::path::{Path, PathBuf};

use crate::sys::fs::openat2_in_root;

/// Collapse `..` components clamping at `/` (pivot_root semantics).
/// Always returns an absolute path under `/`.
pub fn confine(virtual_path: &str) -> PathBuf {
    let mut components: Vec<&str> = Vec::new();

    // Split on '/' and process each component
    for part in virtual_path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            other => {
                components.push(other);
            }
        }
    }

    let mut result = PathBuf::from("/");
    for c in components {
        result.push(c);
    }
    result
}

/// Strip chroot root prefix from host path.
/// Returns None if host path is not under chroot root.
pub fn to_virtual_path(chroot_root: &Path, host_path: &Path) -> Option<PathBuf> {
    host_path
        .strip_prefix(chroot_root)
        .ok()
        .map(|rel| PathBuf::from("/").join(rel))
}

/// Inverse of mount/chroot resolution: map a real host path back to the
/// sandbox's virtual path.
///
/// The chroot root is just the virtual `/` mount, so this is a single
/// most-specific-prefix lookup over `{ "/" => chroot_root } ∪ mounts` —
/// the same rule the kernel uses to pick among overlapping mounts. Returns
/// None when the host path is under neither the root nor any mount.
///
/// Ties between sources of equal length go to *declaration order*: the first
/// mount declared in the policy wins. That matters because one host directory
/// can be mounted at several virtual paths (E2B's `/workspace` and
/// `/home/user` are the same directory), so the question "which virtual path
/// is this host path?" has more than one true answer and the sandbox has to
/// pick one deterministically. The previous `max_by_key(…len())` kept the
/// *last* of the tied mounts, so a policy that declared `/workspace` before
/// `/home/user` still got `/home/user` back for the shared directory — and
/// every caller that walks from that answer (cwd identity, the mount-alias
/// walk in `chroot::dispatch`) then missed whatever was declared under the
/// other alias.
pub fn host_to_virtual(
    chroot_root: &Path,
    mounts: &[(PathBuf, PathBuf)],
    host_path: &Path,
) -> Option<PathBuf> {
    std::iter::once((Path::new("/"), chroot_root))
        .chain(mounts.iter().map(|(v, h)| (v.as_path(), h.as_path())))
        .filter(|(_, source)| host_path.starts_with(source))
        .enumerate()
        // Longest host source wins; ties fall back to *declaration order*
        // (the first mount in the policy wins). The old `max_by_key` kept
        // the last of equal-length sources, so a caller that declared
        // /workspace before /home/user still got /home/user back for the
        // shared workspace directory -- and every relative path resolved
        // from that cwd then missed the sub-mounts declared under
        // /workspace.
        .max_by_key(|(idx, (_, source))| (source.as_os_str().len(), std::cmp::Reverse(*idx)))
        .map(|(_, (virtual_base, source))| {
            // strip_prefix cannot fail: the filter above already matched it.
            let rest = host_path.strip_prefix(source).expect("prefix matched");
            // join("") appends a separator, so the mount point itself would
            // render as "/proc/" and reach the child that way through getcwd.
            if rest.as_os_str().is_empty() {
                virtual_base.to_path_buf()
            } else {
                virtual_base.join(rest)
            }
        })
}

/// Where a virtual path lands on the host, following the mount table one step:
/// the source of the most specific declared mount plus the part below its
/// destination, or the chroot root for a path no mount covers.
///
/// `host_of` + [`host_to_virtual`] is what turns one alias of a shared host
/// directory into another; `mount_walk_path` iterates the pair and the policy
/// verdicts in `chroot::dispatch` use it directly to fold deny / read-only
/// checks across every alias spelling of the same object.
pub fn host_of(chroot_root: &Path, mounts: &[(PathBuf, PathBuf)], virtual_path: &Path) -> PathBuf {
    let mut best: Option<(&Path, &Path)> = None;
    for (vp, hp) in mounts {
        if virtual_path.starts_with(vp) {
            if best.is_none() || vp.as_os_str().len() > best.unwrap().0.as_os_str().len() {
                best = Some((vp.as_path(), hp.as_path()));
            }
        }
    }
    match best {
        Some((mount_vp, mount_hp)) => {
            let sub = virtual_path.strip_prefix(mount_vp).unwrap_or(Path::new(""));
            mount_hp.join(sub)
        }
        None => {
            let rel = virtual_path.strip_prefix("/").unwrap_or(virtual_path);
            chroot_root.join(rel)
        }
    }
}

/// Rounds [`mount_walk_path`] may take before it gives up.
const MOUNT_WALK_ROUNDS: usize = 4;

/// The spelling the mount table must be walked with for `virtual_path`.
///
/// Mounts are keyed by *virtual* destination, but one host directory may be
/// mounted at several of them: E2B's `/workspace` and `/home/user` are the same
/// directory. A sub-mount declared under one alias
/// (`/workspace/mnt/data -> <volume>`) is therefore invisible from the other,
/// even though both name the same host directory — a relative open from a
/// `/home/user` cwd asked for `/home/user/mnt/data/...`, matched the
/// `/home/user` alias, and got EACCES on the workspace copy instead of reaching
/// the volume.
///
/// Realize the path on the host (`host_of`) and map it back
/// (`host_to_virtual`), repeating while the spelling keeps changing: the second
/// round then finds the deeper mount. `host_to_virtual` breaks host-source ties
/// by declaration order, so the walk is deterministic and the first-declared
/// alias stays canonical.
///
/// The result is a *lookup key only*. Policy verdicts (deny, read-only) are
/// folded over both the requested and the walked spelling by the caller, so
/// folding an alias here can never widen what the policy allows.
pub fn mount_walk_path(
    chroot_root: &Path,
    mounts: &[(PathBuf, PathBuf)],
    virtual_path: &Path,
) -> PathBuf {
    mount_walk_path_bounded(chroot_root, mounts, virtual_path, MOUNT_WALK_ROUNDS)
}

/// [`mount_walk_path`] with an explicit round bound, so a unit test can drive
/// the non-convergence fallback deterministically.
pub fn mount_walk_path_bounded(
    chroot_root: &Path,
    mounts: &[(PathBuf, PathBuf)],
    virtual_path: &Path,
    max_rounds: usize,
) -> PathBuf {
    let mut current = virtual_path.to_path_buf();
    for _ in 0..max_rounds {
        let host = host_of(chroot_root, mounts, &current);
        match host_to_virtual(chroot_root, mounts, &host) {
            Some(next) if next != current => current = next,
            // The spelling is a fixed point (or has no host realization at
            // all): that is the answer.
            _ => return current,
        }
    }
    // Still moving after `max_rounds`. A table whose aliases and sub-mounts
    // nest into each other can in principle keep re-anchoring, and a spelling
    // that never settles must not be handed out as if it were canonical. Fall
    // back to the caller's spelling: that is the pre-alias-walk behaviour, it
    // is deterministic, and it never invents a path the caller did not name.
    virtual_path.to_path_buf()
}

/// Resolve a virtual path within the chroot using `openat2(RESOLVE_IN_ROOT)`.
///
/// The kernel resolves all symlinks and `..` components, keeping the result
/// confined to `chroot_root`.  Returns `(host_path, virtual_path)`.
///
/// For paths whose final component does not yet exist (e.g. `O_CREAT` targets),
/// the parent directory is resolved and the filename is appended.
///
/// Self-referential symlinks (e.g. `rootfs/bin → /bin`) return `ELOOP` and
/// are treated as resolution failures — such rootfs layouts are unsupported.
pub fn resolve_in_root(chroot_root: &Path, child_path: &str) -> Option<(PathBuf, PathBuf)> {
    if let Some(result) = resolve_existing_in_root(chroot_root, child_path) {
        return Some(result);
    }

    // Full path doesn't exist — resolve the parent and append the missing
    // filename.  This is needed for O_CREAT targets where the final
    // component will be created.
    resolve_in_root_nofollow(chroot_root, child_path)
}

/// Resolve a virtual path *without* following a final symlink.
///
/// The parent is resolved by the kernel (following intermediate symlinks,
/// confined to `chroot_root`) and the final component is appended verbatim,
/// so the caller acts on the last component itself.
///
/// This is what the no-follow family needs. `lstat` must describe the link,
/// `unlink` and `rename` must remove and move the link, and `lchown` must own
/// it: resolving through the final component would silently redirect every
/// one of them onto the target. It is also how an `O_CREAT` target resolves,
/// since a name that does not exist yet cannot be walked to.
pub fn resolve_in_root_nofollow(
    chroot_root: &Path,
    child_path: &str,
) -> Option<(PathBuf, PathBuf)> {
    let confined = confine(child_path);
    // "/" has no final component to leave unresolved.
    let Some(file_name) = confined.file_name() else {
        return resolve_existing_in_root(chroot_root, child_path);
    };
    let parent = confined.parent().unwrap_or(Path::new("/"));

    match openat2_in_root(
        chroot_root,
        parent.to_str()?,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    ) {
        Ok(fd) => {
            let parent_host = std::fs::read_link(format!("/proc/self/fd/{}", fd)).ok();
            unsafe { libc::close(fd) };
            let parent_host = parent_host?;
            let host_path = parent_host.join(file_name);
            let parent_virtual = to_virtual_path(chroot_root, &parent_host)?;
            let virtual_path = parent_virtual.join(file_name);
            Some((host_path, virtual_path))
        }
        Err(_) => None,
    }
}

/// Resolve a virtual path that must already exist within the chroot.
///
/// Unlike [`resolve_in_root`], this does NOT fall back to parent resolution
/// when the path doesn't exist. The kernel resolves all symlinks confined to
/// `chroot_root`, so the returned host path is always fully resolved — no
/// dangling symlinks that could escape the chroot when followed by the host.
///
/// Use this for read-only lookups (stat, access, readlink) where the file
/// must already exist.
pub fn resolve_existing_in_root(chroot_root: &Path, child_path: &str) -> Option<(PathBuf, PathBuf)> {
    match openat2_in_root(
        chroot_root,
        child_path,
        libc::O_PATH | libc::O_CLOEXEC,
        0,
    ) {
        Ok(fd) => {
            let host_path = std::fs::read_link(format!("/proc/self/fd/{}", fd)).ok();
            unsafe { libc::close(fd) };
            let host_path = host_path?;
            let virtual_path = to_virtual_path(chroot_root, &host_path)?;
            Some((host_path, virtual_path))
        }
        Err(_) => None,
    }
}

/// Resolve the configured chroot root to a canonical, on-disk path.
///
/// `None` chroot yields `Ok(None)`. A configured chroot path that cannot be
/// canonicalized (missing or inaccessible) is a hard error: silently dropping
/// it would disable the seccomp-notify chroot mediation without telling the
/// caller, leaving the workload effectively unconfined.
pub fn resolve_chroot_root(
    chroot: Option<&Path>,
) -> Result<Option<PathBuf>, crate::error::SandboxError> {
    match chroot {
        Some(p) => match std::fs::canonicalize(p) {
            Ok(resolved) => Ok(Some(resolved)),
            Err(source) => Err(crate::error::SandboxError::ChrootNotFound {
                path: p.to_path_buf(),
                source,
            }),
        },
        None => Ok(None),
    }
}

/// Canonicalize the host source of each bind mount, preserving the virtual
/// destination unchanged.
///
/// A host path that cannot be canonicalized falls back to the path as given:
/// unlike the chroot root (which gates confinement), a mount source may be
/// created later or resolved relative to another mount, so a missing source is
/// not treated as fatal here.
pub fn resolve_chroot_mounts(mounts: &[(PathBuf, PathBuf)]) -> Vec<(PathBuf, PathBuf)> {
    mounts
        .iter()
        .map(|(virtual_path, host_path)| {
            (
                virtual_path.clone(),
                std::fs::canonicalize(host_path).unwrap_or_else(|_| host_path.clone()),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn resolve_chroot_root_none_is_ok_none() {
        assert!(resolve_chroot_root(None).unwrap().is_none());
    }

    #[test]
    fn resolve_chroot_root_existing_canonicalizes() {
        // /tmp exists on every supported target.
        let resolved = resolve_chroot_root(Some(Path::new("/tmp")))
            .unwrap()
            .expect("an existing chroot path should resolve to Some");
        assert!(resolved.is_absolute());
    }

    #[test]
    fn resolve_chroot_root_missing_path_errors() {
        // A configured chroot that does not exist must error rather than
        // silently disabling confinement. Regression: the old
        // `canonicalize(p).ok()` swallowed this into `None`, turning off the
        // seccomp-notify chroot mediation without telling the caller.
        let err = resolve_chroot_root(Some(Path::new(
            "/nonexistent/sandlock/rootfs/does-not-exist",
        )))
        .unwrap_err();
        assert!(
            matches!(err, crate::error::SandboxError::ChrootNotFound { .. }),
            "expected ChrootNotFound, got: {err:?}"
        );
    }

    #[test]
    fn resolve_chroot_mounts_canonicalizes_existing_and_falls_back_on_missing() {
        let dir = TempDir::new().unwrap();
        let existing = dir.path().join("src");
        std::fs::create_dir(&existing).unwrap();
        let missing = PathBuf::from("/nonexistent/sandlock/mount-src");

        let resolved = resolve_chroot_mounts(&[
            (PathBuf::from("/data"), existing.clone()),
            (PathBuf::from("/cache"), missing.clone()),
        ]);

        // Virtual destinations are preserved verbatim.
        assert_eq!(resolved[0].0, PathBuf::from("/data"));
        assert_eq!(resolved[1].0, PathBuf::from("/cache"));
        // Existing source is canonicalized; missing source falls back as-is.
        assert_eq!(resolved[0].1, existing.canonicalize().unwrap());
        assert_eq!(resolved[1].1, missing);
    }

    #[test]
    fn test_confine_absolute() {
        assert_eq!(confine("/etc/group"), PathBuf::from("/etc/group"));
    }

    #[test]
    fn test_confine_dotdot_at_root() {
        assert_eq!(confine("/../../etc/group"), PathBuf::from("/etc/group"));
    }

    #[test]
    fn test_confine_many_dotdots() {
        assert_eq!(confine("/../../../../../.."), PathBuf::from("/"));
    }

    #[test]
    fn test_confine_relative() {
        assert_eq!(confine("usr/bin/python"), PathBuf::from("/usr/bin/python"));
    }

    #[test]
    fn test_confine_dot() {
        assert_eq!(confine("/usr/./bin/../lib"), PathBuf::from("/usr/lib"));
    }

    #[test]
    fn test_to_virtual_path() {
        assert_eq!(
            to_virtual_path(Path::new("/rootfs"), Path::new("/rootfs/etc/group")),
            Some(PathBuf::from("/etc/group"))
        );
    }

    #[test]
    fn test_to_virtual_path_outside() {
        assert_eq!(
            to_virtual_path(Path::new("/rootfs"), Path::new("/other/path")),
            None
        );
    }

    #[test]
    fn host_to_virtual_at_a_mount_point_renders_without_a_trailing_slash() {
        // The rendered bytes matter, not just Path equality (which ignores a
        // trailing separator): getcwd copies this string into the child, and a
        // child sitting exactly on a mount point saw "/proc/".
        let mounts = vec![(PathBuf::from("/proc"), PathBuf::from("/proc"))];
        let virtual_path = host_to_virtual(Path::new("/rootfs"), &mounts, Path::new("/proc"))
            .expect("a mount point maps to its own virtual path");
        assert_eq!(virtual_path.to_string_lossy(), "/proc");
    }

    #[test]
    fn host_to_virtual_tie_breaks_on_declaration_order() {
        let host = PathBuf::from("/srv/ws");
        let mounts = vec![
            (PathBuf::from("/workspace"), host.clone()),
            (PathBuf::from("/home/user"), host.clone()),
        ];
        assert_eq!(
            host_to_virtual(Path::new("/rootfs"), &mounts, &host.join("a.txt")),
            Some(PathBuf::from("/workspace/a.txt")),
            "first-declared alias must win the tie"
        );
        // Same source, opposite declaration order: the *other* alias is now
        // the canonical one. The rule is "first declared", not "prefer this
        // particular name".
        let mounts = vec![
            (PathBuf::from("/home/user"), host.clone()),
            (PathBuf::from("/workspace"), host.clone()),
        ];
        assert_eq!(
            host_to_virtual(Path::new("/rootfs"), &mounts, &host.join("a.txt")),
            Some(PathBuf::from("/home/user/a.txt")),
            "declaration order decides, not the alias name"
        );
    }

    #[test]
    fn test_confine_escape_attempt() {
        // Deeply nested .. should always clamp at /
        assert_eq!(
            confine("/a/b/c/../../../../../../../../etc/shadow"),
            PathBuf::from("/etc/shadow")
        );
    }

    #[test]
    fn mount_walk_folds_a_shared_directory_submount_onto_the_canonical_alias() {
        // `/workspace` and `/home/user` are one host directory; the volume is
        // mounted under `/workspace` only. Walking the `/home/user` spelling
        // must reach the volume (that is what makes a relative open from a
        // `/home/user` cwd find `/workspace/mnt/data`).
        let mounts = vec![
            (PathBuf::from("/workspace"), PathBuf::from("/srv/ws")),
            (PathBuf::from("/workspace/mnt/data"), PathBuf::from("/srv/vol")),
            (PathBuf::from("/home/user"), PathBuf::from("/srv/ws")),
        ];
        assert_eq!(
            mount_walk_path(Path::new("/rootfs"), &mounts, Path::new("/home/user/mnt/data/x")),
            PathBuf::from("/workspace/mnt/data/x")
        );
        // A spelling no mount and no alias covers is its own fixed point.
        assert_eq!(
            mount_walk_path(Path::new("/rootfs"), &mounts, Path::new("/etc/hosts")),
            PathBuf::from("/etc/hosts")
        );
        // Non-alias mount: the walk returns the same spelling it was given.
        assert_eq!(
            mount_walk_path(Path::new("/rootfs"), &mounts, Path::new("/workspace/plain")),
            PathBuf::from("/workspace/plain")
        );
    }

    #[test]
    fn mount_walk_falls_back_to_the_input_when_it_cannot_converge() {
        // The same shared-directory table, but with a bound of one round: the
        // walk is still moving when it runs out (one more round is what finds
        // the volume), so the fallback must hand back the *input* spelling —
        // never a half-finished intermediate one.
        let mounts = vec![
            (PathBuf::from("/workspace"), PathBuf::from("/srv/ws")),
            (PathBuf::from("/workspace/mnt/data"), PathBuf::from("/srv/vol")),
            (PathBuf::from("/home/user"), PathBuf::from("/srv/ws")),
        ];
        let requested = PathBuf::from("/home/user/mnt/data/x");
        assert_eq!(
            mount_walk_path_bounded(Path::new("/rootfs"), &mounts, &requested, 1),
            requested,
            "an unconverged walk must fall back to the caller's spelling"
        );
        assert_eq!(
            mount_walk_path_bounded(Path::new("/rootfs"), &mounts, &requested, 0),
            requested,
            "a zero-round walk is the identity"
        );
        assert_eq!(
            mount_walk_path(Path::new("/rootfs"), &mounts, &requested),
            PathBuf::from("/workspace/mnt/data/x"),
            "the real bound converges on the same table"
        );
    }

    // ============================================================
    // openat2 / resolve_in_root tests
    // ============================================================

    #[test]
    fn test_openat2_in_root_regular_file() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/group"), "root:x:0:\n").unwrap();

        let fd = openat2_in_root(root, "/etc/group", libc::O_RDONLY, 0);
        match fd {
            Ok(fd) => unsafe { libc::close(fd) },
            Err(libc::ENOSYS) => return, // kernel too old
            Err(e) => panic!("unexpected error: {}", e),
        };
    }

    #[test]
    fn test_openat2_in_root_blocks_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("a")).unwrap();

        let fd = openat2_in_root(root, "/../../../etc/group", libc::O_PATH, 0);
        match fd {
            // RESOLVE_IN_ROOT clamps ".." at the root, so this resolves
            // to <root>/etc/group which doesn't exist → ENOENT.
            Err(libc::ENOENT) => {}
            Err(libc::ENOSYS) => return,
            Ok(fd) => {
                // If it succeeds, the resolved path must be under root.
                let resolved = std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
                unsafe { libc::close(fd) };
                assert!(
                    resolved.starts_with(root),
                    "escaped chroot: {:?}",
                    resolved
                );
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn test_openat2_in_root_symlink_confined() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/shadow"), "confined").unwrap();
        // Absolute symlink pointing to /etc/shadow — kernel keeps it
        // confined to root.
        symlink("/etc/shadow", root.join("evil")).unwrap();

        let fd = openat2_in_root(root, "/evil", libc::O_PATH, 0);
        match fd {
            Ok(fd) => {
                let resolved = std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
                unsafe { libc::close(fd) };
                assert!(resolved.starts_with(root));
                assert!(resolved.ends_with("etc/shadow"));
            }
            Err(libc::ENOSYS) => return,
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn test_resolve_in_root_no_symlinks() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/hello"), "").unwrap();

        let result = resolve_in_root(root, "/usr/bin/hello");
        assert!(result.is_some());
        let (host, virt) = result.unwrap();
        assert_eq!(virt, PathBuf::from("/usr/bin/hello"));
        assert!(host.starts_with(root));
    }

    #[test]
    fn test_resolve_in_root_with_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("usr/lib64")).unwrap();
        std::fs::write(root.join("usr/lib64/foo"), "").unwrap();
        symlink("/usr/lib64", root.join("lib")).unwrap();

        let result = resolve_in_root(root, "/lib/foo");
        assert!(result.is_some());
        let (host, virt) = result.unwrap();
        assert_eq!(virt, PathBuf::from("/usr/lib64/foo"));
        assert!(host.starts_with(root));
    }

    #[test]
    fn test_resolve_in_root_nonexistent_file() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("tmp")).unwrap();

        // File doesn't exist but parent does — should resolve via parent.
        let result = resolve_in_root(root, "/tmp/newfile");
        assert!(result.is_some());
        let (host, virt) = result.unwrap();
        assert_eq!(virt, PathBuf::from("/tmp/newfile"));
        assert!(host.ends_with("tmp/newfile"));
    }

    #[test]
    fn test_resolve_in_root_escape_via_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/shadow"), "confined").unwrap();
        // Symlink to absolute path — must stay confined.
        symlink("/etc/shadow", root.join("evil")).unwrap();

        let result = resolve_in_root(root, "/evil");
        assert!(result.is_some());
        let (host, virt) = result.unwrap();
        assert_eq!(virt, PathBuf::from("/etc/shadow"));
        assert!(host.starts_with(root));
    }

    #[test]
    fn test_resolve_in_root_dotdot_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("a")).unwrap();

        let result = resolve_in_root(root, "/a/../../etc/group");
        // Either resolves within root or returns None — never escapes.
        if let Some((host, _)) = result {
            assert!(host.starts_with(root));
        }
    }

    #[test]
    fn test_resolve_in_root_root_path() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let result = resolve_in_root(root, "/");
        assert!(result.is_some());
        let (host, virt) = result.unwrap();
        assert_eq!(virt, PathBuf::from("/"));
        assert_eq!(host, root);
    }

    #[test]
    fn test_resolve_existing_follows_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("usr/local/bin")).unwrap();
        std::fs::write(root.join("usr/local/bin/python3.12"), "binary").unwrap();
        symlink("python3.12", root.join("usr/local/bin/python3")).unwrap();

        // resolve_existing_in_root should follow the symlink and return
        // the resolved target path, not the symlink itself.
        let result = resolve_existing_in_root(root, "/usr/local/bin/python3");
        match result {
            Some((host, virt)) => {
                assert!(host.starts_with(root));
                assert!(host.ends_with("python3.12"),
                    "host path should be resolved through symlink: {:?}", host);
                assert_eq!(virt, PathBuf::from("/usr/local/bin/python3.12"));
            }
            None => {
                // openat2 not available on this kernel — skip
            }
        }
    }

    #[test]
    fn test_resolve_existing_absolute_symlink_confined() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/python3.12"), "binary").unwrap();
        std::fs::create_dir_all(root.join("usr/local/bin")).unwrap();
        // Absolute symlink — must stay confined to chroot root.
        symlink("/usr/bin/python3.12", root.join("usr/local/bin/python3")).unwrap();

        let result = resolve_existing_in_root(root, "/usr/local/bin/python3");
        match result {
            Some((host, virt)) => {
                assert!(host.starts_with(root),
                    "absolute symlink must not escape chroot: {:?}", host);
                assert!(host.ends_with("usr/bin/python3.12"));
                assert_eq!(virt, PathBuf::from("/usr/bin/python3.12"));
            }
            None => {
                // openat2 not available — skip
            }
        }
    }

    #[test]
    fn test_resolve_existing_returns_none_for_missing() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();

        let result = resolve_existing_in_root(root, "/usr/bin/nonexistent");
        // openat2 may not be available, but if it is, missing file → None
        if resolve_existing_in_root(root, "/usr/bin").is_some() {
            assert!(result.is_none());
        }
    }
}
