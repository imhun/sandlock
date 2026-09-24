/*
 * arm64 checkpoint/restore S0c spike, second half -- why does a relocated vDSO
 * stop working?
 *
 * s0c-vaddr showed that `mremap [vdso] alone` and `mremap [vvar]+[vdso] by one
 * delta` both return success, and that the next call through a pointer cached
 * before the move dies with SIGSEGV. This program asks the kernel where:
 *
 *   - a SIGSEGV handler reports si_addr *and* the faulting pc out of the signal
 *     frame (the layout s0a pinned: sigcontext at sp+0x130, pc at sc+0x108);
 *   - the vDSO text is scanned for ADRP/LDR-literal targets that leave the
 *     [vdso] mapping, i.e. how the code reaches its data page;
 *   - four child scenarios isolate which move breaks what:
 *       A  move [vdso] only                (data page left behind)
 *       B  move [vvar]+[vdso] by one delta (adjacency kept)
 *       C  move [vvar] alone, then read it (does a movable special map fault?)
 *       D  move both, then take a signal   (is the kernel's sigtramp stale?)
 *
 * Build: gcc -O1 -fno-stack-protector -o s0d-vdso s0d-vdso.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <elf.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/wait.h>

#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#define MREMAP_MAYMOVE 1
#endif

#define SC_OFF_FROM_SP 0x130UL   /* pinned by s0a on this kernel */
#define SC_PC_OFF      0x108UL
#define PAGE 4096UL

static unsigned long g_vdso, g_vdso_end, g_vvar, g_vvar_end;
static unsigned long g_moved_vdso = 0x10000000UL;   /* 256 MiB */
static unsigned long g_moved_vvar;
static unsigned long g_clk_fn;                     /* raw __kernel_clock_gettime */

static void raw_write(const char *s, size_t n)
{
	register long x8 __asm__("x8") = 64;
	register long x0 __asm__("x0") = 2;
	register long x1 __asm__("x1") = (long)s;
	register long x2 __asm__("x2") = (long)n;
	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
}

static void hx(unsigned long v, char *out)
{
	static const char d[] = "0123456789abcdef";
	out[0] = '0'; out[1] = 'x';
	for (int i = 0; i < 16; i++) out[2 + i] = d[(v >> (60 - 4 * i)) & 0xf];
}

static void segv_report(int sig, siginfo_t *info, void *uc)
{
	unsigned long sp, *sc;
	char buf[320];
	int k = 0;
	const char *p;

	__asm__ volatile("mov %0, sp" : "=r"(sp));
	/* the ucontext argument is frame+0x80, so sigcontext is uc+0xb0; using sp
	 * would be wrong by whatever this function's own prologue pushed */
	sc = (unsigned long *)((unsigned long)uc + 0xb0);

	p = "[s0d]     FAULT sig="; while (*p) buf[k++] = *p++;
	hx((unsigned long)sig, buf + k); k += 18;
	p = " uc-sp="; while (*p) buf[k++] = *p++;
	hx((unsigned long)uc - sp, buf + k); k += 18;
	p = " pc="; while (*p) buf[k++] = *p++;
	hx(sc[SC_PC_OFF / 8], buf + k); k += 18;
	p = "\n[s0d]       frame fault_address="; while (*p) buf[k++] = *p++;
	hx(sc[0], buf + k); k += 18;
	p = " si_addr="; while (*p) buf[k++] = *p++;
	hx((unsigned long)info->si_addr, buf + k); k += 18;
	p = " si_code="; while (*p) buf[k++] = *p++;
	hx((unsigned long)info->si_code, buf + k); k += 18;
	buf[k++] = '\n';
	raw_write(buf, (size_t)k);
	_exit(42);
}

static void install_segv_handler(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = segv_report;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
}

static int maps_find(const char *name, unsigned long *s, unsigned long *e)
{
	FILE *f = fopen("/proc/self/maps", "r");
	char line[512];
	int hit = 0;
	if (!f) return 0;
	while (fgets(line, sizeof line, f)) {
		unsigned long a, b;
		char perms[8], path[256];
		path[0] = 0;
		if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %255s", &a, &b, perms, path) < 3) continue;
		if (strcmp(path, name) == 0) { *s = a; *e = b; hit = 1; break; }
	}
	fclose(f);
	return hit;
}

static unsigned long deref_ptr(unsigned long ptr)
{
	if (ptr >= g_vdso && ptr < g_vdso_end) return ptr;
	return g_vdso + ptr;
}

static unsigned long vdso_lookup(const char *name)
{
	Elf64_Ehdr *eh = (Elf64_Ehdr *)g_vdso;
	Elf64_Phdr *ph;
	unsigned long dyn = 0, symtab = 0, strtab = 0, hash = 0, nchain = 0;

	if (memcmp(eh->e_ident, ELFMAG, 4) != 0) return 0;
	ph = (Elf64_Phdr *)(g_vdso + eh->e_phoff);
	for (int i = 0; i < eh->e_phnum; i++) {
		if (ph[i].p_type == PT_DYNAMIC) dyn = deref_ptr(ph[i].p_vaddr);
		printf("[s0d]   PT_LOAD off=%#lx vaddr=%#lx filesz=%#lx memsz=%#lx flags=%#x\n",
		       (unsigned long)ph[i].p_offset, (unsigned long)ph[i].p_vaddr,
		       (unsigned long)ph[i].p_filesz, (unsigned long)ph[i].p_memsz,
		       ph[i].p_flags);
	}
	if (!dyn) return 0;
	for (Elf64_Dyn *d = (Elf64_Dyn *)dyn; d->d_tag != DT_NULL; d++) {
		if (d->d_tag == DT_SYMTAB) symtab = deref_ptr(d->d_un.d_ptr);
		else if (d->d_tag == DT_STRTAB) strtab = deref_ptr(d->d_un.d_ptr);
		else if (d->d_tag == DT_HASH) hash = deref_ptr(d->d_un.d_ptr);
	}
	if (!symtab || !strtab) return 0;
	if (hash) nchain = ((uint32_t *)hash)[1];
	if (!nchain) nchain = 512;
	for (unsigned long i = 0; i < nchain; i++) {
		Elf64_Sym *s = (Elf64_Sym *)(symtab + i * sizeof(Elf64_Sym));
		const char *n = (const char *)(strtab + s->st_name);
		if (n[0] && strcmp(n, name) == 0 && s->st_value) return g_vdso + s->st_value;
	}
	return 0;
}

/* how does the vDSO reach anything outside its own mapping? */
static void scan_vdso(void)
{
	unsigned long n = (g_vdso_end - g_vdso) / 4;
	int adrp_out = 0, adrp_in = 0, adr_out = 0, adr_in = 0, ldr_out = 0;

	printf("[s0d] scanning %lu KiB of vDSO text for PC-relative escapes\n", n * 4 / 1024);
	for (unsigned long i = 0; i < n; i++) {
		unsigned w;
		unsigned long pc = g_vdso + i * 4;
		memcpy(&w, (void *)pc, 4);
		if ((w & 0x9f000000U) == 0x90000000U || (w & 0x9f000000U) == 0x10000000U) {
			int is_adrp = (w & 0x80000000U) != 0;
			long immhi = (long)((w >> 5) & 0x7ffff);
			long immlo = (long)((w >> 29) & 0x3);
			long imm = (immhi << 2) | immlo;
			unsigned long tgt;
			imm = (imm << 43) >> 43;                       /* sign-extend 21 bits */
			if (is_adrp) { imm <<= 12; tgt = (pc & ~0xfffUL) + (unsigned long)imm; }
			else { tgt = pc + (unsigned long)imm; }
			if (tgt >= g_vdso && tgt < g_vdso_end) {
				if (is_adrp) adrp_in++; else adr_in++;
			} else {
				int *out = is_adrp ? &adrp_out : &adr_out;
				if (*out < 10)
					printf("      %s @+%#06lx -> %#lx (delta %+ld)%s\n",
					       is_adrp ? "adrp" : "adr ", i * 4, tgt,
					       (long)tgt - (long)pc,
					       (tgt >= g_vvar && tgt < g_vvar_end) ? "  [vvar]" : "");
				(*out)++;
			}
		} else if ((w & 0xff000000U) == 0x58000000U) {       /* LDR (literal) */
			long imm = (long)((w >> 5) & 0x7ffff);
			unsigned long tgt = pc + (unsigned long)(((imm << 45) >> 45) * 4);
			if (tgt < g_vdso || tgt >= g_vdso_end) {
				if (ldr_out < 8)
					printf("      ldr  @+%#06lx -> %#lx (delta %+ld)%s\n",
					       i * 4, tgt, (long)tgt - (long)pc,
					       (tgt >= g_vvar && tgt < g_vvar_end) ? "  [vvar]" : "");
				ldr_out++;
			}
		}
	}
	printf("[s0d]   adrp %d in/%d out, adr %d in/%d out, ldr-literal out %d\n",
	       adrp_in, adrp_out, adr_in, adr_out, ldr_out);
}

static void run_child(const char *what, void (*fn)(void))
{
	pid_t pid = fork();
	int st = 0;

	if (pid == 0) { install_segv_handler(); fn(); _exit(0); }
	waitpid(pid, &st, 0);
	if (WIFSIGNALED(st))
		printf("[s0d]   %-42s died with signal %d (%s)\n", what, WTERMSIG(st),
		       strsignal(WTERMSIG(st)));
	else
		printf("[s0d]   %-42s exit %d\n", what, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
}

static void move_vvar(void)
{
	void *r = mremap((void *)g_vvar, g_vvar_end - g_vvar, g_vvar_end - g_vvar,
			 MREMAP_MAYMOVE | MREMAP_FIXED, (void *)g_moved_vvar);
	if (r == MAP_FAILED) { printf("[s0d]     (mremap [vvar] failed: %s)\n", strerror(errno)); _exit(3); }
}
static void move_vdso(void)
{
	void *r = mremap((void *)g_vdso, g_vdso_end - g_vdso, g_vdso_end - g_vdso,
			 MREMAP_MAYMOVE | MREMAP_FIXED, (void *)g_moved_vdso);
	if (r == MAP_FAILED) { printf("[s0d]     (mremap [vdso] failed: %s)\n", strerror(errno)); _exit(3); }
}

static unsigned long fn_at(unsigned long base_now)
{
	/* the checkpointed process holds pointers at the *recorded* base; the engine
	 * puts the fresh vDSO there, so a relocated vDSO must be called through the
	 * translated address, not the stale one. */
	return g_clk_fn - g_vdso + base_now;
}

static void report_maps(void)
{
	unsigned long a = 0, b = 0, c = 0, d = 0;
	int have_vdso = maps_find("[vdso]", &a, &b);
	int have_vvar = maps_find("[vvar]", &c, &d);
	printf("[s0d]     after: [vvar] %s%#lx-%#lx  [vdso] %s%#lx-%#lx\n",
	       have_vvar ? "" : "GONE ", c, d, have_vdso ? "" : "GONE ", a, b);
}

static void scenario_C(void)   /* control: read [vvar] where the kernel put it */
{
	unsigned long sum = 0;
	for (unsigned long i = 0; i < g_vvar_end - g_vvar; i += PAGE)
		sum += *(volatile unsigned long *)(g_vvar + i);
	printf("[s0d]     C: unmoved [vvar] reads back fine, sum=%#lx\n", sum);
}

static void scenario_A(void)   /* [vdso] alone -> call the translated address */
{
	struct timespec ts;
	unsigned long fn;
	move_vdso();
	report_maps();
	fn = fn_at(g_moved_vdso);
	printf("[s0d]     calling relocated __kernel_clock_gettime at %#lx\n", fn);
	((int (*)(int, struct timespec *))fn)(1, &ts);
	printf("[s0d]     A: call SURVIVED  tv_sec=%ld\n", (long)ts.tv_sec);
}

static void scenario_B(void)   /* both, one delta -> call translated address */
{
	struct timespec ts;
	unsigned long fn;
	move_vvar();
	move_vdso();
	report_maps();
	fn = fn_at(g_moved_vdso);
	printf("[s0d]     calling relocated __kernel_clock_gettime at %#lx\n", fn);
	((int (*)(int, struct timespec *))fn)(1, &ts);
	printf("[s0d]     B: call SURVIVED  tv_sec=%ld nsec=%ld\n",
	       (long)ts.tv_sec, (long)ts.tv_nsec);
}

static void scenario_C2(void)  /* move [vvar] alone, then read the moved pages */
{
	unsigned long sum = 0;
	move_vvar();
	report_maps();
	for (unsigned long i = 0; i < g_vvar_end - g_vvar; i += PAGE) {
		printf("[s0d]     reading moved [vvar]+%#lx\n", i);
		sum += *(volatile unsigned long *)(g_moved_vvar + i);
	}
	printf("[s0d]     C2: moved [vvar] reads back fine, sum=%#lx\n", sum);
}

static void usr1_handler(int sig) { (void)sig; }

static void scenario_D(void)   /* both, then take and return from a signal */
{
	signal(SIGUSR1, usr1_handler);
	move_vvar();
	move_vdso();
	raise(SIGUSR1);
	raw_write("[s0d]     D: signal round trip SURVIVED\n", 36);
}

static void scenario_E(void)   /* both, then glibc's own (stale) cached pointer */
{
	struct timespec ts;
	move_vvar();
	move_vdso();
	clock_gettime(CLOCK_MONOTONIC, &ts);
	printf("[s0d]     E: glibc clock_gettime returned %ld.%09ld\n",
	       (long)ts.tv_sec, (long)ts.tv_nsec);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	install_segv_handler();

	printf("[s0d] arm64 vDSO relocation spike\n");
	printf("[s0d] AT_SYSINFO_EHDR=%#lx\n", getauxval(AT_SYSINFO_EHDR));
	if (!maps_find("[vdso]", &g_vdso, &g_vdso_end) || !maps_find("[vvar]", &g_vvar, &g_vvar_end)) {
		printf("[s0d] no [vdso]/[vvar]; aborting\n");
		return 1;
	}
	printf("[s0d] [vvar] %#lx-%#lx   [vdso] %#lx-%#lx   gap=%#lx\n",
	       g_vvar, g_vvar_end, g_vdso, g_vdso_end, g_vdso - g_vvar_end);
	g_moved_vvar = g_moved_vdso - (g_vdso - g_vvar);

	g_clk_fn = vdso_lookup("__kernel_clock_gettime");
	printf("[s0d] raw __kernel_clock_gettime = %#lx\n", g_clk_fn);
	if (!g_clk_fn) return 1;
	scan_vdso();

	printf("[s0d] relocation scenarios (each in its own child)\n");
	run_child("C  [vvar] read where the kernel put it", scenario_C);
	run_child("A  move [vdso], call the new address", scenario_A);
	run_child("B  move both, call the new address", scenario_B);
	run_child("C2 move [vvar], read the moved pages", scenario_C2);
	run_child("D  move both, signal round trip", scenario_D);
	run_child("E  move both, glibc clock_gettime", scenario_E);
	return 0;
}
