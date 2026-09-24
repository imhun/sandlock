/*
 * arm64 checkpoint/restore S0b spike -- the thread pointer (TPIDR_EL0).
 *
 * The capture side reads TLS through PTRACE_GETREGSET(NT_ARM_TLS) and the
 * restore side writes it back, because arm64 keeps the thread pointer in a
 * system register that a signal frame does *not* carry. Three questions, all
 * answered here on the target kernel:
 *
 *   1. Can EL0 write TPIDR_EL0 at all? (SCTLR_EL1.TIDCP traps it on some
 *      hardened kernels; the trap is a SIGILL, so the attempt runs in a child.)
 *   2. Does PTRACE_GETREGSET/SETREGSET(NT_ARM_TLS) round-trip the value, and
 *      does the process actually see the value the tracer wrote after resume?
 *   3. What does NT_PRSTATUS look like mid-syscall (does regs[8] still hold the
 *      syscall number -- the fact `rearm_restartable_syscall` needs), what is
 *      the size of NT_PRFPREG, and which arch regsets (SVE / tagged-addr /
 *      PAC / hw-break / system-call) exist on this kernel?
 *
 * Build: gcc -O1 -mgeneral-regs-only -fno-stack-protector -o s0b-tls s0b-tls.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>

#ifndef NT_ARM_TLS
#define NT_ARM_TLS 0x401
#endif
#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x403
#endif
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif
#ifndef NT_ARM_SVE
#define NT_ARM_SVE 0x405
#endif
#ifndef NT_ARM_PAC_MASK
#define NT_ARM_PAC_MASK 0x406
#endif
#ifndef NT_ARM_TAGGED_ADDR_CTRL
#define NT_ARM_TAGGED_ADDR_CTRL 0x409
#endif

#define TLS_SENT 0x7e1557a100000000UL
#define NT_PRSTATUS_ 1
#define NT_PRFPREG_ 2
#ifndef SYS_kill
#define SYS_kill 129
#endif
#ifndef SYS_write
#define SYS_write 64
#endif
#ifndef SYS_exit_group
#define SYS_exit_group 94
#endif

static long raw_sys3(long n, long a, long b, long c)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
	return x0;
}

/* TPIDR_EL0 round trip: returns the value read back, restores the original. */
__asm__(
".text\n"
".globl tls_roundtrip_\n"
".type tls_roundtrip_, %function\n"
"tls_roundtrip_:\n"
"	mrs x17, tpidr_el0\n"
"	msr tpidr_el0, x0\n"
"	mrs x0, tpidr_el0\n"
"	msr tpidr_el0, x17\n"
"	ret\n"
);

unsigned long g_resume_buf[2] __attribute__((used)); /* asm-only reference */

/* Runs after the tracer wrote a new TPIDR_EL0 and resumed us: report the value
 * we now see with a raw `write`, then exit -- no libc, because glibc's own TLS
 * pointer is exactly what the tracer just replaced. */
__asm__(
".text\n"
".globl tls_report_after_resume_\n"
".type tls_report_after_resume_, %function\n"
"tls_report_after_resume_:\n"
"	adrp x16, g_resume_buf\n"
"	add  x16, x16, :lo12:g_resume_buf\n"
"	mrs  x17, tpidr_el0\n"
"	str  x17, [x16]\n"
"	mov  x1, x16\n"
"	mov  x2, #8\n"
"	mov  x8, #64\n"          /* write; x0 is the fd argument */
"	svc  #0\n"
"	mov  x0, #0x11\n"
"	mov  x8, #94\n"          /* exit_group */
"	svc  #0\n"
"	ret\n"
);

extern unsigned long tls_roundtrip_(unsigned long v);
extern void tls_report_after_resume_(long fd);

static void show_regset(pid_t pid, const char *name, int which, size_t maxlen)
{
	unsigned char *buf = calloc(1, maxlen);
	struct iovec iov = { .iov_base = buf, .iov_len = maxlen };
	errno = 0;
	long r = ptrace(PTRACE_GETREGSET, pid, (void *)(long)which, &iov);
	printf("  %-24s GETREGSET rc=%ld errno=%d size=%zu:", name, r, errno, (size_t)iov.iov_len);
	if (r == 0) {
		for (size_t i = 0; i < iov.iov_len && i < 24; i++) printf(" %02x", buf[i]);
		printf("%s\n", iov.iov_len > 24 ? " ..." : "");
	} else {
		printf(" %s\n", strerror(errno));
	}
	free(buf);
}

static void child_el0_write_probe(void)
{
	pid_t pid = fork();
	if (pid == 0) {
		unsigned long got = tls_roundtrip_(TLS_SENT);
		/* the asm put the original value back, so libc is safe again */
		_exit(got == TLS_SENT ? 0 : 42);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	if (WIFSIGNALED(status)) {
		printf("  EL0 msr tpidr_el0      -> killed by signal %d (%s)\n",
		       WTERMSIG(status), strsignal(WTERMSIG(status)));
		return;
	}
	printf("  EL0 msr/mrs tpidr_el0  -> %s (child exit %d)\n",
	       WEXITSTATUS(status) == 0 ? "round-trips, no trap" : "VALUE MISMATCH",
	       WEXITSTATUS(status));
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[s0b] arm64 TPIDR_EL0 / ptrace-regset spike\n");

	unsigned long tls_now = 0;
	__asm__ volatile("mrs %0, tpidr_el0" : "=r"(tls_now));
	printf("[s0b] live TPIDR_EL0 = 0x%lx\n", tls_now);

	child_el0_write_probe();

	/* ---- ptrace regsets on a stopped child ---- */
	int from_child[2];
	if (pipe(from_child)) { perror("pipe"); return 1; }

	pid_t pid = fork();
	if (pid == 0) {
		close(from_child[0]);
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) _exit(90);
		unsigned long v = 0;
		__asm__ volatile("mrs %0, tpidr_el0" : "=r"(v));
		if (write(from_child[1], &v, 8) != 8) _exit(91);
		/* Group-stop from a syscall, with the tracer watching: the point is to
		 * stop with a syscall in flight so x8 can be inspected. */
		raw_sys3(SYS_kill, (long)getpid(), 19 /* SIGSTOP */, 0);
		tls_report_after_resume_(from_child[1]); /* raw-publish TLS + exit 0x11 */
		_exit(92);
	}

	close(from_child[1]);
	unsigned long child_tls = 0;
	if (read(from_child[0], &child_tls, 8) != 8) { perror("read"); return 1; }
	printf("[s0b] child reported TPIDR_EL0 = 0x%lx before stopping\n", child_tls);

	int status = 0;
	if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 1; }
	printf("[s0b] child stop status=0x%x (stopped=%d sig=%d)\n", status,
	       WIFSTOPPED(status), WIFSTOPPED(status) ? WSTOPSIG(status) : -1);

	unsigned long long regs[40];
	struct iovec riov = { .iov_base = regs, .iov_len = sizeof regs };
	errno = 0;
	long r = ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS_, &riov);
	printf("[s0b] NT_PRSTATUS GETREGSET rc=%ld errno=%d size=%zu (expect 34*8=%d)\n",
	       r, errno, (size_t)riov.iov_len, 34 * 8);
	if (r == 0) {
		printf("      x0=0x%llx x1=0x%llx x8(=nr)=%llu pc=0x%llx sp=0x%llx pstate=0x%llx\n",
		       regs[0], regs[1], regs[8], regs[32], regs[31], regs[33]);
		printf("      syscall number at the stop = %llu (kill=%d)\n", regs[8], SYS_kill);
	}

	unsigned long tls_regset = 0;
	struct iovec tiov = { .iov_base = &tls_regset, .iov_len = sizeof tls_regset };
	errno = 0;
	r = ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_ARM_TLS, &tiov);
	printf("[s0b] NT_ARM_TLS GETREGSET rc=%ld errno=%d value=0x%lx (child said 0x%lx) size=%zu\n",
	       r, errno, tls_regset, child_tls, (size_t)tiov.iov_len);
	printf("      matches the child's own mrs: %s\n",
	       (r == 0 && tls_regset == child_tls) ? "yes" : "NO");

	unsigned long set_val = TLS_SENT;
	struct iovec siov = { .iov_base = &set_val, .iov_len = sizeof set_val };
	errno = 0;
	r = ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_ARM_TLS, &siov);
	printf("[s0b] NT_ARM_TLS SETREGSET rc=%ld errno=%d (wrote 0x%lx)\n", r, errno, set_val);

	unsigned long reread = 0;
	struct iovec riov2 = { .iov_base = &reread, .iov_len = sizeof reread };
	errno = 0;
	r = ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_ARM_TLS, &riov2);
	printf("[s0b] NT_ARM_TLS GETREGSET#2 rc=%ld errno=%d value=0x%lx -> %s\n", r, errno,
	       reread, (r == 0 && reread == set_val) ? "round-trips" : "MISMATCH");

	/* the other arch regsets capture/restore would have to know about */
	show_regset(pid, "NT_PRFPREG", NT_PRFPREG_, 4096);
	show_regset(pid, "NT_ARM_SVE", NT_ARM_SVE, 4096);
	show_regset(pid, "NT_ARM_SSVE", 0x40a, 4096);
	show_regset(pid, "NT_ARM_ZA", 0x40b, 4096);
	show_regset(pid, "NT_ARM_ZT", 0x40c, 4096);
	show_regset(pid, "NT_ARM_FPMR", 0x40e, 64);
	show_regset(pid, "NT_ARM_TAGGED_ADDR_CTRL", NT_ARM_TAGGED_ADDR_CTRL, 64);
	show_regset(pid, "NT_ARM_PAC_MASK", NT_ARM_PAC_MASK, 64);
	show_regset(pid, "NT_ARM_PACA_KEYS", 0x407, 64);
	show_regset(pid, "NT_ARM_PACG_KEYS", 0x408, 64);
	show_regset(pid, "NT_ARM_HW_BREAK", NT_ARM_HW_BREAK, 64);
	show_regset(pid, "NT_ARM_HW_WATCH", NT_ARM_HW_WATCH, 64);
	show_regset(pid, "NT_ARM_SYSTEM_CALL", NT_ARM_SYSTEM_CALL, 64);

	/* SVE on this silicon: does an ordinary glibc process already carry SVE
	 * state (VL set), or is the regset merely present?  The plan's fail-closed
	 * rule turns on exactly this. */
	{
		unsigned char *hdr = calloc(1, 4096);
		struct iovec hv = { .iov_base = hdr, .iov_len = 4096 };
		errno = 0;
		long hr = ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_ARM_SVE, &hv);
		if (hr == 0 && hv.iov_len >= 16) {
			unsigned size, max_size; unsigned short vl, max_vl, flags;
			memcpy(&size, hdr + 0, 4); memcpy(&max_size, hdr + 4, 4);
			memcpy(&vl, hdr + 8, 2); memcpy(&max_vl, hdr + 10, 2);
			memcpy(&flags, hdr + 12, 2);
			printf("      SVE header: size=%u max_size=%u vl=%u bytes max_vl=%u flags=%#x "
			       "(VL=%u bits)\n", size, max_size, vl, max_vl, flags, vl * 8);
		}
		free(hdr);
	}


	/* resume: the child must observe the value the tracer wrote */
	if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) perror("[s0b] PTRACE_CONT");
	unsigned long resumed = 0;
	ssize_t got = read(from_child[0], &resumed, 8);
	printf("[s0b] after PTRACE_CONT the child sees TPIDR_EL0 = 0x%lx (read %zd) -> %s\n",
	       resumed, got, (got == 8 && resumed == TLS_SENT) ? "restore channel works" : "NO");

	waitpid(pid, &status, 0);
	printf("[s0b] child final status=0x%x exit=%d\n", status,
	       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	return 0;
}
