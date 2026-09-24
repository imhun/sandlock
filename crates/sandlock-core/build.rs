use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../..").canonicalize().unwrap();

    // rootfs-helper: an ordinary static-libc test fixture (chroot tests). It
    // lives in tests/ and its binary sits beside it (a git-ignored artifact).
    if !build_static(
        &repo_root.join("tests/rootfs-helper.c"),
        &repo_root.join("tests/rootfs-helper"),
        &["musl-gcc", "cc"],
        &["-static", "-O2"],
    ) {
        println!(
            "cargo:warning=cannot compile tests/rootfs-helper: chroot tests will \
             fail. Install musl-tools or static libc."
        );
    }

    // restore-stub: a core component of the restore engine (the supervisor execs
    // it to reconstruct a checkpoint), freestanding, no libc, no PIE. It lives
    // next to the checkpoint code that owns it; its binary is built into OUT_DIR
    // and its path is handed to the crate via the RESTORE_STUB_PATH env var.
    //
    // The fixed load address must match `checkpoint::restore_blob::STUB_BASE`:
    // the stub reconstructs the checkpoint's layout around itself, so its own
    // text and stack have to sit outside the address range programs occupy. The
    // default -no-pie base (0x400000) is exactly where a static ET_EXEC workload
    // loads, so the checkpoint's own text would be mapped over the running stub.
    //
    // Cross-compilation: when TARGET is riscv64gc-unknown-linux-gnu (or any
    // riscv64* variant), look for a riscv64 cross-compiler. aarch64 likewise.
    // In both cases `CC_<target with underscores>` wins when it is set: that is
    // how the wheel builder hands the stub to zig (`CC_aarch64_unknown_linux_gnu=zigcc`),
    // and a zig-based toolchain has no `aarch64-linux-gnu-gcc` alias to find.
    let stub_src = manifest_dir.join("src/checkpoint/restore-stub.c");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let stub_bin = out_dir.join("restore-stub");
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    let is_riscv64 = target.starts_with("riscv64");
    let is_aarch64 = target.starts_with("aarch64");
    // Checkpoint restore is claimed on x86_64, aarch64 and riscv64 (see
    // `restore_interactive`); on those arches a stub build failure is fatal, not
    // a silent skip — a green build with no stub is how regressions slip past CI.
    //
    // The stub is a Linux freestanding binary: it needs GCC-only flags
    // (`-fno-tree-loop-distribute-patterns`, `-Ttext-segment`) and a
    // `-static -nostdlib` link, none of which clang/ld on macOS provide. The
    // restore engine itself is exercised only inside Linux sandboxes, so on a
    // non-Linux host a stub build failure downgrades to a warning instead of
    // aborting the build (mirroring the rootfs-helper behavior above).
    let is_restore_arch = target.starts_with("x86_64") || is_aarch64 || is_riscv64;
    let on_linux = std::env::var("CARGO_CFG_TARGET_OS").map(|os| os == "linux").unwrap_or(false);
    let stub_failure_is_fatal = is_restore_arch && on_linux;
    // A cross build is the one case where the environment's compiler has to win:
    // the host `cc` cannot produce the target's freestanding stub, and the
    // builder images that do cross-compile name their toolchain only through
    // `CC_<target>`. Naming it is the `cc` crate's convention, so honoring it
    // keeps this build script compatible with the lane and the wheel recipe.
    let cross_cc = if is_restore_arch && arch_of(&target) != arch_of(&host) {
        env_cc_for(&target)
    } else {
        None
    };
    let (ccs, fail_msg) = if is_riscv64 {
        let mut ccs = Vec::new();
        ccs.extend(cross_cc.iter().map(String::as_str));
        if host.starts_with("riscv64") {
            ccs.push("cc");
        } else {
            ccs.push("riscv64-linux-gnu-gcc");
            ccs.push("riscv64-unknown-linux-gnu-gcc");
        }
        let fail_msg = if host.starts_with("riscv64") {
            "failed to compile restore-stub for riscv64: no working C compiler \
             (install gcc); checkpoint restore is unavailable"
        } else {
            "failed to compile restore-stub for riscv64: no working cross-compiler \
             (install riscv64-linux-gnu-gcc); checkpoint restore is unavailable"
        };
        (ccs, fail_msg)
    } else if is_aarch64 {
        let mut ccs = Vec::new();
        ccs.extend(cross_cc.iter().map(String::as_str));
        if host.starts_with("aarch64") {
            ccs.push("cc");
        } else {
            ccs.push("aarch64-linux-gnu-gcc");
            ccs.push("aarch64-unknown-linux-gnu-gcc");
        }
        let fail_msg = if host.starts_with("aarch64") {
            "failed to compile restore-stub for aarch64: no working C compiler \
             (install gcc); checkpoint restore is unavailable"
        } else {
            "failed to compile restore-stub for aarch64: no working cross-compiler \
             (install aarch64-linux-gnu-gcc, or set CC_aarch64_unknown_linux_gnu); \
             checkpoint restore is unavailable"
        };
        (ccs, fail_msg)
    } else {
        (vec!["cc"], "failed to compile restore-stub: no working C compiler \
             (install cc/gcc); checkpoint restore is unavailable")
    };
    // The link address must match restore_blob::STUB_BASE and must sit below
    // the Sv39 user ceiling (256 GiB) on riscv64; x86_64 and aarch64 use
    // 0x300_0000_0000. The *spelling* is per linker: GNU ld calls it
    // -Ttext-segment, lld calls it --image-base, and zig's driver rejects the
    // GNU spelling before lld ever sees it -- so the two forms travel as GCC
    // and non-GCC arguments below. `stub_links_at_the_reserved_base` is what
    // catches a linker that accepted the flag and placed the image elsewhere.
    let stub_base = if is_riscv64 { "0x3000000000" } else { "0x30000000000" };
    // x86_64 only: newer binutils (e.g. RHEL gcc-toolset, used by the pypa
    // manylinux builder) lay out .bss beyond the 32-bit signed reach of the
    // default small code model at the 3 TiB text segment, failing with
    // "relocation truncated to fit: R_X86_64_32S". The large model keeps the
    // freestanding stub toolchain-agnostic. riscv64 has no large model and its
    // default (medany) is already fine; aarch64's small model reaches +/-4 GiB
    // from the text segment, which covers this stub's few pages, and the large
    // model is a kernel-oriented mode that would only widen the relocations.
    let mut stub_args: Vec<&str> = vec![
        "-static",
        "-nostdlib",
        "-no-pie",
        "-O2",
        "-ffreestanding",
    ];
    if target.starts_with("x86_64") {
        stub_args.push("-mcmodel=large");
    }
    // GNU C gets -Ttext-segment plus a flag clang rejects: loop-idiom
    // recognition would otherwise rewrite the stub's own memset/memcpy bodies
    // into calls to themselves (the bodies also carry a barrier, for the LLVM
    // pass in a zig/clang toolchain).
    let gcc_extra = [
        format!("-Wl,-Ttext-segment={stub_base}"),
        "-fno-tree-loop-distribute-patterns".to_string(),
    ];
    let non_gcc_extra = [format!("-Wl,--image-base={stub_base}")];
    let gcc_extra_refs: Vec<&str> = gcc_extra.iter().map(String::as_str).collect();
    let non_gcc_extra_refs: Vec<&str> = non_gcc_extra.iter().map(String::as_str).collect();
    if !build_static_with(
        &stub_src,
        &stub_bin,
        &ccs,
        &stub_args,
        &gcc_extra_refs,
        &non_gcc_extra_refs,
    ) {
        if stub_failure_is_fatal {
            panic!("{fail_msg}");
        }
        println!("cargo:warning={fail_msg}");
    }
    // Emit the path every run (rustc-env is not cached across build-script runs),
    // whether or not the binary was just (re)built.
    println!("cargo:rustc-env=RESTORE_STUB_PATH={}", stub_bin.display());
}

/// Compile `src` to `bin` with the first working compiler in `ccs`, skipping the
/// work when `bin` is newer than `src`. Returns `false` only when the source is
/// present, newer than `bin`, and no compiler in `ccs` succeeded; a missing
/// source (a packaged crate) or an up-to-date `bin` reports success. The caller
/// decides whether that failure is a hard error or a warning.
///
/// A 0-byte `bin` never counts as up-to-date (I1/P5 review): a stale empty
/// artifact (e.g. an interrupted cross-filesystem copy) would otherwise skip
/// the rebuild and hand every chroot/ffi/python test an "Exec format error".
fn build_static(src: &Path, bin: &Path, ccs: &[&str], args: &[&str]) -> bool {
    build_static_with(src, bin, ccs, args, &[], &[])
}

/// Whether `cc` is GNU C. `--version` is the only portable probe: GCC prints
/// "cc (GCC) ...", clang and zig print something else. An unidentifiable
/// compiler simply does not get the GCC-only flags.
fn is_gnu_c(cc: &str) -> bool {
    Command::new(cc)
        .arg("--version")
        .output()
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout).to_lowercase();
            out.contains("(gcc)") || out.contains("free software foundation")
        })
        .unwrap_or(false)
}

/// `gcc_args` are appended only for a compiler [`is_gnu_c`] recognises, and
/// `other_args` only for the others (the two toolchains spell the load address
/// differently).
fn build_static_with(
    src: &Path,
    bin: &Path,
    ccs: &[&str],
    args: &[&str],
    gcc_args: &[&str],
    other_args: &[&str],
) -> bool {
    println!("cargo:rerun-if-changed={}", src.display());
    if !src.exists() {
        return true;
    }
    let bin_nonempty = bin
        .metadata()
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    if bin.exists() && bin_nonempty {
        if let (Ok(s), Ok(b)) = (src.metadata(), bin.metadata()) {
            if let (Ok(st), Ok(bt)) = (s.modified(), b.modified()) {
                if bt >= st {
                    return true;
                }
            }
        }
    }
    // Compile to a sibling temp path and publish with a rename, never in
    // place: the artifact is hard-linked into test fixtures that outlive the
    // build (they live under `CARGO_TARGET_TMPDIR` = `target-linux/tmp`), and
    // an in-place rewrite is visible to every one of those links at once. A
    // failed or interrupted `cc` then leaves a zero-byte artifact behind and
    // each fixture execs `ENOEXEC` -- measured 2026-09-22, where a leftover
    // fixture made a test's `fs::copy` fallback truncate the shared
    // `tests/rootfs-helper` and the whole chroot family went red with
    // `execvp 'rootfs-helper': Exec format error`. A rename swaps the
    // directory entry, so an existing link keeps the previous (complete)
    // inode.
    let tmp = bin.with_file_name(format!(
        "{}.tmp-{}",
        bin.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "artifact".to_string()),
        std::process::id()
    ));
    for cc in ccs {
        let mut cmd = Command::new(cc);
        cmd.args(args);
        if is_gnu_c(cc) {
            cmd.args(gcc_args);
        } else {
            cmd.args(other_args);
        }
        let ok = cmd
            .arg("-o")
            .arg(&tmp)
            .arg(src)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return match std::fs::rename(&tmp, bin) {
                Ok(()) => true,
                Err(e) => {
                    println!(
                        "cargo:warning=cannot publish {}: {e}",
                        bin.display()
                    );
                    let _ = std::fs::remove_file(&tmp);
                    false
                }
            };
        }
    }
    let _ = std::fs::remove_file(&tmp);
    false
}

/// The architecture part of a Rust target triple (`aarch64-unknown-linux-gnu`
/// -> `aarch64`).
fn arch_of(triple: &str) -> &str {
    triple.split('-').next().unwrap_or("")
}

/// `CC_<target>` with the target's dashes underscored, as the `cc` crate (and
/// the wheel recipe) spell it: `CC_aarch64_unknown_linux_gnu`.
fn env_cc_for(target: &str) -> Option<String> {
    let key = format!("CC_{}", target.replace('-', "_"));
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}
