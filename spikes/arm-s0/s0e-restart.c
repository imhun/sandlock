/*
 * arm-s0/s0e-restart.c -- S2 pre-measurement (aarch64): what does the kernel
 * leave in the register file at a PTRACE_INTERRUPT stop inside a *restartable*
 * syscall?
 *
 * Why it matters. `restore_blob::rearm_restartable_syscall` exists because a
 * checkpoint taken while the workload sat in a syscall resumes *past* that
 * syscall unless the engine puts the register file back into a "re-execute the
 * syscall" shape. The two existing architectures disagree about how much the
 * kernel has already done by the time the tracer sees the stop:
 *
 *   x86_64  the stop happens BEFORE the restart fixup: `rax` holds a restart
 *           sentinel (-512..-516) and `rip` points 2 bytes past `syscall`, so
 *           the engine rewinds `rip` and reloads `rax` from `orig_rax`.
 *   riscv64 >= 6.6 (per the engine's comment) the fixup has already run: `a0` is
 *           the original first argument again. ptrace does not expose
 *           `orig_a0`, so the engine can only reject a visible sentinel.
 *
 * aarch64 is a third case: `x0` is BOTH the first argument and the return value
 * (like riscv64's `a0`), but `x8` carries the syscall number and survives the
 * return (unlike x86_64's `rax`), and `orig_x0` is not in the ptrace-exposed
 * `user_pt_regs` either. So the question decides whether the arm64 rearm can be
 * a no-op (kernel already fixed up) or has to fail closed.
 *
 * Measurements, all at one PTRACE_INTERRUPT stop while the tracee blocks in a
 * `read()` on an empty pipe:
 *
 *   1. `x0` -- the original fd, or a restart sentinel?
 *   2. `pc` -- at the `svc` instruction, or 4 bytes past it? (The tracee
 *      publishes the address of that exact instruction through a shared page,
 *      so this is a byte comparison, not an inference.)
 *   3. `x8` -- the syscall number (202 = read)?
 *   4. what the kernel's own views say: `/proc/<pid>/syscall`,
 *      `NT_ARM_SYSTEM_CALL`, `PTRACE_GET_SYSCALL_INFO`.
 *   5. after PTRACE_CONT with a byte available in the pipe: does the syscall
 *      re-execute and return 1, or does userspace see -EINTR / a raw sentinel?
 *
 * The same five measurements are then repeated for a syscall that restarts
 * through the kernel's `restart_block` (`nanosleep`, -ERESTART_RESTARTBLOCK)
 * rather than the plain -ERESTART* path. That distinction matters: x86_64's
 * fixup replaces the syscall NUMBER for this case (the engine turns it back into
 * a re-run of the original syscall using the captured `orig_rax`), while aarch64
 * carries the number in `x8` and exposes no `orig_x8`. If the kernel has already
 * swapped x8 for `__NR_restart_syscall` at the stop, a restored process would
 * execute `restart_syscall` against an empty restart_block and get ENOSYS, so
 * the engine has to know about it.
 *
 * Build (on the aarch64 target): gcc -O1 -o s0e-restart s0e-restart.c
 * No -mgeneral-regs-only here: unlike s0a this spike never needs to hold FP
 * state across a context switch.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#define NT_ARM_SYSTEM_CALL 0x404

#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420c
#endif

/* aarch64 __NR_read. Not 202: polling /proc/<pid>/syscall for the x86_64-era
 * number silently never matches (learned on the first run of this spike). */
#define NR_READ 63
#define NR_NANOSLEEP 101
#define NR_RESTART_SYSCALL 128

/* user_pt_regs: x0..x30, sp, pc, pstate. */
enum { R_X0 = 0, R_X1, R_X2, R_X8 = 8, R_SP = 31, R_PC = 32, R_PSTATE = 33 };
#define NREGS 34

/* Shared page, set up before fork so both sides see the same numbers. */
struct shared {
	unsigned long arg0;      /* [0] the fd / timespec the child passed in x0 */
	unsigned long svc_addr;  /* [1] address of the child's `svc` instruction */
	unsigned long ret;       /* [2] what the child's syscall eventually returned */
	unsigned long marker;    /* [3] set once the child resumed past the stop */
};

/*
 * read(fd, buf, n) with the address of its own `svc` instruction reported back
 * through *svc_out (x3 is the 4th argument register). The label sits exactly on
 * the svc, so the tracer can compare the stopped pc against it byte for byte
 * instead of guessing where the compiler put it.
 */
extern long raw_read_blocking_(int fd, void *buf, unsigned long n,
			       unsigned long *svc_out);
__asm__(
".text\n"
".globl raw_read_blocking_\n"
".type raw_read_blocking_, %function\n"
"raw_read_blocking_:\n"
"	adr	x9, svc_site_\n"
"	str	x9, [x3]\n"
"	mov	x8, #63\n"
"svc_site_:\n"
"	svc	#0\n"
"	ret\n"
);

/* nanosleep(ts, NULL) with the same svc-address report. */
extern long raw_nanosleep_blocking_(void *ts, unsigned long *svc_out);
__asm__(
".text\n"
".globl raw_nanosleep_blocking_\n"
".type raw_nanosleep_blocking_, %function\n"
"raw_nanosleep_blocking_:\n"
"\tadr\tx9, sleep_site_\n"
"\tstr\tx9, [x1]\n"
"\tmov\tx1, #0\n"
"\tmov\tx8, #101\n"
"sleep_site_:\n"
"\tsvc\t#0\n"
"\tret\n"
);

static void die(const char *what)
{
	fprintf(stderr, "fatal: %s: %s\n", what, strerror(errno));
	exit(2);
}

static long getregset(pid_t pid, int set, void *buf, size_t len)
{
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	return ptrace(PTRACE_GETREGSET, pid, (void *)(long)set, &iov);
}

/* Wait until the tracee is actually blocked inside read(2), or give up. */
static void read_line_file(const char *path, char *out, size_t n, const char *fallback)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		snprintf(out, n, "%s", fallback);
		return;
	}
	if (fgets(out, (int)n, f))
		out[strcspn(out, "\n")] = 0;
	else
		snprintf(out, n, "(empty)");
	fclose(f);
}

/* Wait until the tracee is actually blocked in the syscall named by `expect`
 * (a decimal prefix of /proc/<pid>/syscall), or give up. Reports *why* it gave
 * up -- a tracee that died on the way here and a tracee that is simply
 * somewhere else look identical from a bare timeout, and an early run of this
 * spike wasted a round trip on exactly that. */
static int wait_until_in_syscall(pid_t pid, const char *expect, int *status_out,
				 const char **why)
{
	char path[64], line[256], stat[256], state;
	snprintf(path, sizeof path, "/proc/%d/syscall", pid);
	for (int i = 0; i < 200; i++) {
		pid_t w = waitpid(pid, status_out, WNOHANG);
		if (w == pid) {
			*why = WIFEXITED(*status_out) ? "the tracee exited before entering its syscall" :
			       WIFSIGNALED(*status_out) ? "the tracee was killed by a signal before entering its syscall" :
			       "the tracee stopped before entering its syscall";
			return 0;
		}
		read_line_file(path, line, sizeof line, "(unreadable)");
		if (!strncmp(line, expect, strlen(expect)))
			return 1;
		usleep(10000);
	}
	read_line_file(path, line, sizeof line, "(unreadable)");
	snprintf(path, sizeof path, "/proc/%d/stat", pid);
	read_line_file(path, stat, sizeof stat, "(unreadable)");
	state = strrchr(stat, ')') ? strrchr(stat, ')')[2] : '?';
	fprintf(stderr, "diagnostic: /proc/%d/syscall = %s ; stat state = %c\n", pid, line, state);
	*why = "the tracee never showed up blocked in the syscall";
	return 0;
}

static unsigned long dump_long(pid_t pid)
{
	unsigned long v = 0;
	getregset(pid, NT_ARM_SYSTEM_CALL, &v, sizeof v);
	return v;
}

struct syscall_info { /* struct ptrace_syscall_info, 88 bytes */
	__u8 op;
	__u8 pad[3];
	__u32 arch;
	__u64 instruction_pointer;
	__u64 stack_pointer;
	union {
		struct { __u64 nr; __u64 args[6]; } entry;
		struct { __s64 rval; __u8 is_error; } exit;
	} u;
};

static int measure(int mode)
{
	const int is_sleep = (mode == 1);
	const int nr = is_sleep ? NR_NANOSLEEP : NR_READ;
	const char *name = is_sleep ? "nanosleep" : "read";
	char expect[16];
	snprintf(expect, sizeof expect, "%d ", nr);

	struct shared *sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED)
		die("mmap");

	int fds[2];
	if (pipe(fds) != 0)
		die("pipe");

	printf("\n[s0e] ======== blocked in %s (%d) ========\n", name, nr);

	pid_t pid = fork();
	if (pid < 0)
		die("fork");

	if (pid == 0) {
		if (!is_sleep) {
			sh->arg0 = (unsigned long)fds[0];
			sh->ret = (unsigned long)raw_read_blocking_(fds[0], sh, 8,
								   &sh->svc_addr);
		} else {
			struct { long sec; long nsec; } ts = { 3600, 0 };
			sh->arg0 = (unsigned long)&ts;
			sh->ret = (unsigned long)raw_nanosleep_blocking_(&ts,
									&sh->svc_addr);
		}
		sh->marker = 0x5151;
		_exit(0x42);
	}

	/* Attach the way the engine's capture() does: PTRACE_SEIZE, then
	 * PTRACE_INTERRUPT. PTRACE_INTERRUPT is refused with EIO on a
	 * PTRACE_TRACEME-attached tracee (measured on the first run of this
	 * spike), so this is not a stylistic choice. */
	if (ptrace(PTRACE_SEIZE, pid, 0, 0) != 0)
		die("PTRACE_SEIZE");

	int status = 0;
	const char *why = "";
	if (!wait_until_in_syscall(pid, expect, &status, &why)) {
		fprintf(stderr, "fatal: %s (status=%#x)\n", why, status);
		kill(pid, SIGKILL);
		return 2;
	}
	printf("[s0e] child is blocked in %s\n", name);

	if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) != 0)
		die("PTRACE_INTERRUPT");
	if (waitpid(pid, &status, 0) != pid)
		die("waitpid(interrupt stop)");
	printf("[s0e] interrupt stop status=%#x (WSTOPSIG=%d, event byte=%#x, %s)\n",
	       status, WSTOPSIG(status), (status >> 8) & 0xff,
	       WIFSTOPPED(status) ? "stopped" : "NOT stopped");
	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "fatal: tracee did not stop\n");
		return 2;
	}

	unsigned long regs[NREGS];
	memset(regs, 0, sizeof regs);
	if (getregset(pid, NT_PRSTATUS, regs, sizeof regs) != 0)
		die("GETREGSET(NT_PRSTATUS)");

	char syscall_line[256], path[64];
	snprintf(path, sizeof path, "/proc/%d/syscall", pid);
	read_line_file(path, syscall_line, sizeof syscall_line, "(unreadable)");

	struct syscall_info si;
	memset(&si, 0, sizeof si);
	long si_ret = ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof si, &si);

	printf("[s0e] ---- register file at the stop (NT_PRSTATUS) ----\n");
	printf("[s0e]  x0  (arg0/retval) = %#lx  (%s)\n", regs[R_X0],
	       regs[R_X0] == sh->arg0 ? "original argument intact" :
	       (long)regs[R_X0] >= -516 && (long)regs[R_X0] <= -512 ?
	       "RESTART SENTINEL" : "neither the argument nor a sentinel");
	printf("[s0e]  x0 as signed      = %ld\n", (long)regs[R_X0]);
	printf("[s0e]  x1  (arg1)        = %#lx\n", regs[R_X1]);
	printf("[s0e]  x2  (arg2)        = %#lx\n", regs[R_X2]);
	printf("[s0e]  x8  (syscall nr)  = %#lx  (%s)%s\n", regs[R_X8],
	       regs[R_X8] == (unsigned long)nr ? "the original syscall number" :
	       regs[R_X8] == NR_RESTART_SYSCALL ?
	       "REPLACED by __NR_restart_syscall (128)" : "unexpected",
	       regs[R_X8] == NR_RESTART_SYSCALL ? "  <-- restore would run restart_syscall" : "");
	printf("[s0e]  sp / pc / pstate  = %#lx %#lx %#lx\n",
	       regs[R_SP], regs[R_PC], regs[R_PSTATE]);
	printf("[s0e]  child svc addr    = %#lx\n", sh->svc_addr);
	printf("[s0e]  pc - svc          = %ld  (%s)\n",
	       (long)(regs[R_PC] - sh->svc_addr),
	       regs[R_PC] == sh->svc_addr ? "at the svc: fixup already applied" :
	       regs[R_PC] == sh->svc_addr + 4 ? "past the svc: not fixed up" :
	       "unexpected");
	printf("[s0e]  /proc syscall     = %s\n", syscall_line);
	printf("[s0e]  NT_ARM_SYSCALL    = %#lx\n", dump_long(pid));
	printf("[s0e]  GETSYSCALLINFO    = %ld (op=%u)  [NONE=0 ENTRY=1 EXIT=2 SECCOMP=3]\n",
	       si_ret, si.op);

	printf("[s0e] ---- after resume ----\n");
	if (!is_sleep) {
		/* Give the restarted read something to return. */
		if (write(fds[1], "X", 1) != 1)
			die("write to pipe");
	}
	if (ptrace(PTRACE_CONT, pid, 0, 0) != 0)
		die("PTRACE_CONT(resume)");
	usleep(200000);
	read_line_file(path, syscall_line, sizeof syscall_line, "(unreadable)");
	printf("[s0e]  %s\n", is_sleep ?
	       (strncmp(syscall_line, expect, strlen(expect)) == 0 ?
		"syscall re-entered after the stop (restarted, still sleeping)" :
		"syscall did NOT come back -- it returned to userspace with an error") :
	       "resuming the read");
	if (!is_sleep) {
		int exited = 0;
		for (int i = 0; i < 200 && !exited; i++) {
			pid_t w = waitpid(pid, &status, WNOHANG);
			if (w == pid)
				exited = 1;
			else
				usleep(10000);
		}
		printf("[s0e]  child exited     = %s (status=%#x)\n",
		       exited ? "yes" : "no, still stopped/blocked", status);
		printf("[s0e]  read() returned  = %ld\n", (long)sh->ret);
		printf("[s0e]  child_ran marker = %#lx\n", sh->marker);
	} else {
		printf("[s0e]  /proc syscall    = %s\n", syscall_line);
	}
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	close(fds[0]);
	close(fds[1]);
	munmap(sh, 4096);
	return 0;
}

int main(int argc, char **argv)
{
	const char *which = argc > 1 ? argv[1] : "both";
	int rc = 0;
	if (!strcmp(which, "both") || !strcmp(which, "read"))
		rc |= measure(0);
	if (!strcmp(which, "both") || !strcmp(which, "nanosleep"))
		rc |= measure(1);
	printf("\n[s0e] done (rc=%d)\n", rc);
	return rc;
}
