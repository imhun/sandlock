//! No-exec restore: map the stub image from a descriptor and jump into it.
//!
//! Why this exists: the exec route (`checkpoint::resume`) hands the stub to the
//! sandbox *by path*, so the sandbox has to be able to resolve that path
//! (`execvp` inside the rootfs) and Landlock has to grant EXECUTE on it. A
//! chroot root -- emulated or real -- can do neither: the stub is a host build
//! artifact and the workload's path space is the rootfs (measured 2026-09-23,
//! docs/chroot-workspace-exec.md §9.7.9 and §11).
//!
//! This module is the alternative the same document sketches as "B": the
//! supervisor writes the *same* stub binary into a memfd, the confined child --
//! a fork of the supervisor, running `ChildEntry::InProcess` so nothing is
//! exec'd and Landlock has no execution to authorize -- maps the stub's PT_LOAD
//! segments at their linked addresses (`STUB_BASE`), synthesizes the initial
//! stack the stub's `_start` expects (argc/argv/envp/auxv with
//! `AT_SYSINFO_EHDR`), and jumps to its entry point. From there the protocol is
//! byte-for-byte the one `resume` drives: same control blob, same CTRL/READY/GO
//! descriptors, same sweep list, same `rt_sigreturn` into the checkpoint's
//! register context.
//!
//! Two properties change on purpose, and both are the price of dropping the
//! exec:
//!
//! * **No grant needed.** Nothing is resolved by path (`mmap` of an anonymous
//!   inode has no path for a ruleset to judge) and nothing is executed by path,
//!   so the policy carries no extra rule for the stub.
//! * **The address space is the fork's.** Instead of a fresh, two-mapping
//!   process, the payload starts inside a copy-on-write copy of the supervisor
//!   (libc, runtime, heap, its own stack). Everything the checkpoint does not
//!   record is swept afterwards -- `restore_blob::plan_sweep` already computes
//!   exactly that diff from the child's live maps -- but the sweep list is much
//!   longer than in the exec shape, and this payload runs on the only thread
//!   `fork` left in a multi-threaded supervisor: **no allocation, no locks, no
//!   `std` buffering**, only pre-sized buffers and raw syscalls.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

/// Fixed child descriptor carrying the stub image. The stub's own control
/// descriptors are CTRL/READY/GO = 3/4/5 (`checkpoint::CTRL_FD` and friends);
/// this one is next.
pub(crate) const STUB_IMAGE_FD: RawFd = 6;

const PT_LOAD: u32 = 1;

const MAP_PRIVATE: i32 = 0x02;
const MAP_FIXED: i32 = 0x10;
const MAP_ANONYMOUS: i32 = 0x20;

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 = 0x4;

/// `AT_SYSINFO_EHDR`: the vDSO base `restore-stub.c::_start_c` looks for.
const AT_SYSINFO_EHDR: libc::c_ulong = 33;
const AT_NULL: u64 = 0;

/// Payload stack size: the stub switches to its own `.bss` stack immediately, so
/// this only has to hold the synthesized argc/argv/envp/auxv vector.
const PAYLOAD_STACK: usize = 0x2000;

/// Load the stub binary into a memfd.
///
/// The child must not need a path: a ruleset judges files by their path, and an
/// anonymous inode has none. This is the same trick the chroot mediator uses for
/// the ELF binaries it injects.
pub(crate) fn memfd_with_file(path: &Path) -> io::Result<OwnedFd> {
    let bytes = std::fs::read(path)?;
    let name = c"sandlock-restore-stub";
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut written = 0usize;
    while written < bytes.len() {
        let n = unsafe {
            libc::write(
                owned.as_raw_fd(),
                bytes[written..].as_ptr() as *const libc::c_void,
                bytes.len() - written,
            )
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        written += n as usize;
    }
    Ok(owned)
}

/// `lseek` + `read`, because the install payload must not assume any syscall the
/// sandbox's own filter might not carry (`pread64` is not in every policy's
/// allowlist; `read`/`lseek` are, since the stub itself uses them).
fn read_exact_at(fd: RawFd, offset: u64, buf: &mut [u8]) -> bool {
    if unsafe { libc::lseek(fd, offset as libc::off_t, libc::SEEK_SET) } < 0 {
        return false;
    }
    let mut done = 0usize;
    while done < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf[done..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - done,
            )
        };
        if n <= 0 {
            return false;
        }
        done += n as usize;
    }
    true
}

fn prot_from(flags: u32) -> i32 {
    (if flags & PROT_READ as u32 != 0 { PROT_READ } else { 0 })
        | (if flags & PROT_WRITE as u32 != 0 { PROT_WRITE } else { 0 })
        | (if flags & PROT_EXEC as u32 != 0 { PROT_EXEC } else { 0 })
}

/// The confined child's entry point: install the stub image and jump into it.
///
/// Runs after `real_root`/Landlock/seccomp, on the post-`fork` thread, and never
/// returns: either the stub takes over (`rt_sigreturn` into the checkpoint's
/// context) or this `_exit`s with a diagnostic code.
///
/// [`install_and_jump_entry`] is the `fn()`-typed adapter the launch path wants
/// (`ChildEntry::InProcess` carries `fn()`; this payload diverges).
pub(crate) fn install_and_jump_entry() {
    install_and_jump()
}

pub(crate) fn install_and_jump() -> ! {
    unsafe {
        let fd = STUB_IMAGE_FD;
        let mut ehdr = [0u8; 64];
        if !read_exact_at(fd, 0, &mut ehdr) || ehdr[0..4] != *b"\x7fELF" {
            libc::_exit(90);
        }
        let entry = u64::from_le_bytes(ehdr[24..32].try_into().unwrap());
        let phoff = u64::from_le_bytes(ehdr[32..40].try_into().unwrap());
        let phentsize = u16::from_le_bytes(ehdr[54..56].try_into().unwrap()) as u64;
        let phnum = u16::from_le_bytes(ehdr[56..58].try_into().unwrap()) as u64;
        if phnum == 0 || phnum > 64 {
            libc::_exit(91);
        }

        for i in 0..phnum {
            let mut ph = [0u8; 56];
            if !read_exact_at(fd, phoff + i * phentsize, &mut ph) {
                libc::_exit(91);
            }
            if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != PT_LOAD {
                continue;
            }
            let flags = u32::from_le_bytes(ph[4..8].try_into().unwrap());
            let offset = u64::from_le_bytes(ph[8..16].try_into().unwrap());
            let vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap());
            let filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap());
            let memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());
            let prot = prot_from(flags);

            // The file-backed part, page-aligned on both ends (the stub's RW
            // segment starts mid-page, so the first page comes from the file).
            let map_start = vaddr & !0xfff;
            let map_len = ((vaddr & 0xfff) + filesz + 0xfff) & !0xfff;
            if map_len > 0 {
                let rc = libc::mmap(
                    map_start as *mut libc::c_void,
                    map_len as usize,
                    prot,
                    MAP_PRIVATE | MAP_FIXED,
                    fd,
                    (offset & !0xfff) as libc::off_t,
                );
                if rc == libc::MAP_FAILED {
                    libc::_exit(92);
                }
            }
            // `.bss`: the stub reads its control blob and runs on the stack in
            // here, so it has to exist and be writable before we jump.
            let tail_start = (vaddr + filesz + 0xfff) & !0xfff;
            let tail_end = (vaddr + memsz + 0xfff) & !0xfff;
            if tail_end > tail_start {
                let rc = libc::mmap(
                    tail_start as *mut libc::c_void,
                    (tail_end - tail_start) as usize,
                    prot,
                    MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if rc == libc::MAP_FAILED {
                    libc::_exit(93);
                }
            }
        }

        // The initial stack `_start` expects: argc, argv[], NULL, envp[], NULL,
        // auxv pairs, AT_NULL. Its only use is finding the *current* vDSO base
        // (the stub then relocates [vvar]/[vdso] onto the checkpoint's bases).
        let stack = libc::mmap(
            std::ptr::null_mut(),
            PAYLOAD_STACK,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        if stack == libc::MAP_FAILED {
            libc::_exit(94);
        }
        let vdso = libc::getauxval(AT_SYSINFO_EHDR);

        // `fork` hands us the supervisor's *per-task kernel state*, and `execve`
        // is what would normally have reset it. Two pieces of it make the sweep
        // fatal instead of cosmetic:
        //   * rseq: glibc registers a per-thread rseq area inside its own
        //     mappings and the kernel writes to that address on the next context
        //     switch, so unmapping it (the sweep does) faults in *kernel* mode.
        //     Measured 2026-09-23: the restored program died with SIGSEGV before
        //     its first instruction, and the same run passed outright with
        //     `GLIBC_TUNABLES=glibc.pthread.rseq=0`. The checkpoint never records
        //     a registration, so clearing it costs the restored program nothing:
        //     a kernel registration was never part of the image.
        //   * the signal altstack, which can point into a swept mapping and would
        //     turn the next delivered signal into a second fault.
        unsafe {
            libc::syscall(libc::SYS_rseq, 0usize, 0usize, 0u32);
            let disable = libc::stack_t {
                ss_sp: std::ptr::null_mut(),
                ss_flags: libc::SS_DISABLE,
                ss_size: 0,
            };
            libc::sigaltstack(&disable, std::ptr::null_mut());
        }

        let sp = ((stack as u64 + PAYLOAD_STACK as u64 - 16) & !0xf) as *mut u64;
        let words: [u64; 7] = [
            0,               // argc
            0,               // argv[0] = NULL
            0,               // envp[0] = NULL
            AT_SYSINFO_EHDR, // auxv: vDSO base
            vdso,
            AT_NULL, // auxv terminator
            0,
        ];
        std::ptr::copy_nonoverlapping(words.as_ptr(), sp, words.len());

        // The jump is the only architecture-specific part: the payload runs on
        // the stack it just built and never returns. Same engine support as the
        // restore itself (x86_64/riscv64); other targets keep the crate
        // building (the wheels ship aarch64 too) and exit instead.
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov rdi, {sp}",
            "mov rsp, rdi",
            "jmp {entry}",
            sp = in(reg) sp as u64,
            entry = in(reg) entry,
            options(noreturn)
        );
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!(
            "mv sp, {sp}",
            "jr {entry}",
            sp = in(reg) sp as u64,
            entry = in(reg) entry,
            options(noreturn)
        );
        #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
        {
            libc::_exit(95);
        }
    }
}
