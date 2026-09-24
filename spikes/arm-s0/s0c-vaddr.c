/*
 * arm64 checkpoint/restore S0c spike -- STUB_BASE, the user VA ceiling and the
 * vDSO/vvar relocation.
 *
 * The restore engine maps the stub at a fixed high address and then moves the
 * kernel's fresh [vdso]/[vvar] onto the addresses the checkpoint recorded. Both
 * need facts from the target kernel (plan:
 * third_party/sandlock/docs/fork-plan-2026-09-aarch64-restore.md, stage S0c):
 *
 *   1. Is the x86_64 STUB_BASE (3 TiB) inside this kernel's user VA, and does it
 *      collide with the process's mmap_base / stack?
 *   2. Where is the user VA ceiling actually (39/48/52-bit VA)?
 *   3. Does `mremap(old, len, len, MREMAP_FIXED|MREMAP_MAYMOVE, target)` -- the
 *      exact call restore-stub.c makes -- work on arm64's [vdso] and [vvar], and
 *      does a pointer cached from before the move still work afterwards?
 *
 * Build: gcc -O1 -fno-stack-protector -o s0c-vaddr s0c-vaddr.c
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/wait.h>

#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#define MREMAP_MAYMOVE 1
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define S0C_PAGE 4096UL

static unsigned long g_vdso;
static unsigned long g_vdso_end;

static void show_maps(const char *what)
{
	FILE *f = fopen("/proc/self/maps", "r");
	if (!f) return;
	char line[512];
	char last[4][512];
	int n = 0;
	while (fgets(line, sizeof line, f)) {
		memcpy(last[n % 4], line, sizeof last[0]);
		n++;
	}
	fclose(f);
	printf("  %s: last %d of %d maps entries\n", what, n < 4 ? n : 4, n);
	for (int i = 0; i < 4 && i < n; i++) {
		int idx = (n - 1 - i + 8) % 4;
		printf("      %s", last[idx]);
	}
}

/* Find a named mapping's start,end in /proc/self/maps. */
static int maps_find(const char *name, unsigned long *start, unsigned long *end)
{
	FILE *f = fopen("/proc/self/maps", "r");
	if (!f) return 0;
	char line[512];
	int hit = 0;
	while (fgets(line, sizeof line, f)) {
		unsigned long a, b;
		char perms[8], path[256];
		path[0] = 0;
		if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %255s", &a, &b, perms, path) < 3) continue;
		if (strcmp(path, name) == 0) { *start = a; *end = b; hit = 1; break; }
	}
	fclose(f);
	return hit;
}

/* vDSO dynamic-table pointers are absolute on some kernel versions, and
 * offsets from the mapping on others -- accept both. */
static unsigned long deref(unsigned long ptr)
{
	if (ptr >= g_vdso && ptr < g_vdso_end) return ptr;
	return g_vdso + ptr;
}

static unsigned long vdso_lookup(const char *name)
{
	Elf64_Ehdr *eh = (Elf64_Ehdr *)g_vdso;
	if (memcmp(eh->e_ident, ELFMAG, 4) != 0) return 0;
	Elf64_Phdr *ph = (Elf64_Phdr *)(g_vdso + eh->e_phoff);
	unsigned long dyn = 0;
	for (int i = 0; i < eh->e_phnum; i++)
		if (ph[i].p_type == PT_DYNAMIC) dyn = deref(ph[i].p_vaddr);
	if (!dyn) return 0;

	unsigned long symtab = 0, strtab = 0, hash = 0, nchain = 0;
	for (Elf64_Dyn *d = (Elf64_Dyn *)dyn; d->d_tag != DT_NULL; d++) {
		switch (d->d_tag) {
		case DT_SYMTAB: symtab = deref(d->d_un.d_ptr); break;
		case DT_STRTAB: strtab = deref(d->d_un.d_ptr); break;
		case DT_HASH:   hash = deref(d->d_un.d_ptr); break;
		default: break;
		}
	}
	if (!symtab || !strtab) return 0;
	if (hash) nchain = ((uint32_t *)hash)[1];
	if (!nchain) nchain = 512;
	for (unsigned long i = 0; i < nchain; i++) {
		Elf64_Sym *s = (Elf64_Sym *)(symtab + i * sizeof(Elf64_Sym));
		const char *n = (const char *)(strtab + s->st_name);
		if (n[0] && strcmp(n, name) == 0 && s->st_value)
			return g_vdso + s->st_value;
	}
	return 0;
}

static void probe_fixed(const char *what, unsigned long addr, size_t len)
{
	errno = 0;
	void *p = mmap((void *)addr, len, PROT_NONE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	printf("  %-34s %#14lx -> %s (errno %d %s)\n", what, addr,
	       p == MAP_FAILED ? "FAILED" : "ok",
	       p == MAP_FAILED ? errno : 0,
	       p == MAP_FAILED ? strerror(errno) : "");
	if (p != MAP_FAILED) munmap(p, len);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[s0c] arm64 address-space / vDSO spike\n");
	printf("[s0c] getpagesize=%ld\n", sysconf(_SC_PAGESIZE));
	{
		FILE *f = fopen("/proc/sys/vm/max_map_count", "r");
		char b[64] = "?";
		if (f) { if (fgets(b, sizeof b, f)) b[strcspn(b, "\n")] = 0; fclose(f); }
		printf("[s0c] vm.max_map_count=%s ", b);
		f = fopen("/proc/sys/vm/mmap_min_addr", "r");
		strcpy(b, "?");
		if (f) { if (fgets(b, sizeof b, f)) b[strcspn(b, "\n")] = 0; fclose(f); }
		printf("vm.mmap_min_addr=%s\n", b);
	}

	printf("[s0c] AT_SYSINFO_EHDR=%#lx AT_PAGESZ=%lu AT_HWCAP=%#lx AT_HWCAP2=%#lx\n",
	       getauxval(AT_SYSINFO_EHDR), getauxval(AT_PAGESZ),
	       getauxval(AT_HWCAP), getauxval(AT_HWCAP2));

	unsigned long vs = 0, ve = 0, vvars = 0, vvare = 0;
	if (maps_find("[vdso]", &vs, &ve)) {
		g_vdso = vs; g_vdso_end = ve;
		printf("[s0c] [vdso]  %#lx-%#lx (%lu KiB, %lu pages)\n",
		       vs, ve, (ve - vs) / 1024, (ve - vs) / S0C_PAGE);
		printf("      AT_SYSINFO_EHDR matches [vdso] base: %s\n",
		       getauxval(AT_SYSINFO_EHDR) == vs ? "yes" : "NO");
	}
	if (maps_find("[vvar]", &vvars, &vvare))
		printf("[s0c] [vvar]  %#lx-%#lx (%lu KiB)\n", vvars, vvare, (vvare - vvars) / 1024);
	show_maps("before");

	/* ---- fixed-address probes: is 3 TiB (x86_64's STUB_BASE) usable? ---- */
	printf("[s0c] fixed-address mmap probes (MAP_FIXED_NOREPLACE, 4 MiB window)\n");
	probe_fixed("192 GiB (riscv64 STUB_BASE)", 0x30UL << 32, 0x400000);
	probe_fixed("1 TiB", 1UL << 40, 0x400000);
	probe_fixed("3 TiB (x86_64 STUB_BASE)", 0x300UL << 32, 0x400000);
	probe_fixed("16 TiB", 0x1000UL << 32, 0x400000);
	probe_fixed("64 TiB", 0x4000UL << 32, 0x400000);
	probe_fixed("128 TiB", 0x8000UL << 32, 0x400000);
	probe_fixed("255 TiB", 0xff00UL << 32, 0x400000);
	probe_fixed("256 TiB (2^48)", 1UL << 48, 0x400000);

	/* ---- find the user VA ceiling by bisection ---- */
	unsigned long lo = 0x1000, hi = 1UL << 52;
	while (hi - lo > 0x1000) {
		unsigned long mid = (lo + hi) / 2 & ~(S0C_PAGE - 1);
		if (!mid) break;
		void *p = mmap((void *)mid, S0C_PAGE, PROT_NONE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
		if (p == MAP_FAILED) hi = mid; else { lo = mid; munmap(p, S0C_PAGE); }
	}
	printf("  highest mmap-able page = %#lx = %lu TiB + %lu GiB\n",
	       lo, lo >> 40, (lo & ((1UL << 40) - 1)) >> 30);

	/* ---- the stub's exact relocation calls ---- */
	if (!g_vdso) { printf("[s0c] no [vdso]; skipping relocation\n"); return 0; }

	printf("[s0c] [vvar] %#lx-%#lx is immediately before [vdso] %#lx-%#lx: %s\n",
	       vvars, vvare, vs, ve, vvare == vs ? "yes" : "NO");

	unsigned long fn_before = vdso_lookup("__kernel_clock_gettime");
	printf("[s0c] __kernel_clock_gettime resolved at %#lx (in [vdso]: %s)\n",
	       fn_before, (fn_before >= g_vdso && fn_before < g_vdso_end) ? "yes" : "NO");
	if (!fn_before) return 0;
	int (*clk)(int, struct timespec *) = (int (*)(int, struct timespec *))fn_before;
	struct timespec t0 = { 0, 0 }, t1 = { 0, 0 };
	int rc0 = clk(1 /* CLOCK_MONOTONIC */, &t0);
	printf("[s0c]   before move: rc=%d tv_sec=%ld tv_nsec=%ld\n", rc0, t0.tv_sec, t0.tv_nsec);

	unsigned long vdso_len = ve - vs;
	unsigned long gap = vs - vvars;          /* bytes of [vvar] in front of [vdso] */
	unsigned long target_vdso = 0x10000000UL; /* 256 MiB */
	unsigned long target_vvar = target_vdso - gap;

	void *probe = mmap((void *)target_vvar, gap, PROT_NONE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	printf("[s0c] target slots free: [vvar] %#lx-%#lx %s, [vdso] %#lx-%#lx %s\n",
	       target_vvar, target_vdso, probe == MAP_FAILED ? "NO" : "yes",
	       target_vdso, target_vdso + vdso_len, probe == MAP_FAILED ? "unknown" : "yes");
	if (probe == MAP_FAILED) return 0;
	munmap(probe, gap);

	/* A: child moves [vdso] alone, so the two mappings lose their link-time
	 * relationship -- the question is whether that is what breaks the call. */
	printf("[s0c] A: child moves ONLY [vdso] to %#lx, leaving [vvar] behind\n", target_vdso);
	pid_t pid = fork();
	if (pid == 0) {
		void *r = mremap((void *)vs, vdso_len, vdso_len,
				 MREMAP_MAYMOVE | MREMAP_FIXED, (void *)target_vdso);
		if (r == MAP_FAILED) _exit(3);
		(void)clk(1, &t1);
		static const char msg[] = "[s0c]   A: the call SURVIVED the [vdso]-only move\n";
		ssize_t w = write(1, msg, sizeof msg - 1); (void)w;
		_exit(0);
	}
	int st = 0;
	waitpid(pid, &st, 0);
	if (WIFSIGNALED(st))
		printf("[s0c]   A: the call DIED with signal %d (%s)\n",
		       WTERMSIG(st), strsignal(WTERMSIG(st)));
	else
		printf("[s0c]   A: child exit %d (no crash)\n",
		       WIFEXITED(st) ? WEXITSTATUS(st) : -1);

	/* B: move both by the same delta, which is what plan_vdso_moves hands the
	 * stub (every move shares one shift, so the adjacency is preserved). */
	printf("[s0c] B: moving both by the same delta (keeps %lu bytes of [vvar] in front)\n", gap);
	errno = 0;
	void *rv = mremap((void *)vvars, gap, gap, MREMAP_MAYMOVE | MREMAP_FIXED,
			  (void *)target_vvar);
	printf("[s0c]   mremap [vvar] %#lx -> %#lx: %s (errno %d %s)\n", vvars, target_vvar,
	       rv == MAP_FAILED ? "FAILED" : "ok", rv == MAP_FAILED ? errno : 0,
	       rv == MAP_FAILED ? strerror(errno) : "");
	errno = 0;
	void *r = mremap((void *)vs, vdso_len, vdso_len, MREMAP_MAYMOVE | MREMAP_FIXED,
			 (void *)target_vdso);
	printf("[s0c]   mremap [vdso] %#lx -> %#lx: %s (errno %d %s) return=%p\n", vs, target_vdso,
	       r == MAP_FAILED ? "FAILED" : "ok", r == MAP_FAILED ? errno : 0,
	       r == MAP_FAILED ? strerror(errno) : "", r);

	int rc1 = clk(1, &t1);
	printf("[s0c]   after the same-delta move (pointer cached before it): rc=%d "
	       "tv_sec=%ld tv_nsec=%ld -> %s\n", rc1, t1.tv_sec, t1.tv_nsec,
	       (rc1 == 0 && (t1.tv_sec > t0.tv_sec || t1.tv_nsec >= t0.tv_nsec))
		       ? "STILL WORKS" : "BROKEN");

	unsigned long vs2 = 0, ve2 = 0, v2s = 0, v2e = 0;
	if (maps_find("[vdso]", &vs2, &ve2))
		printf("[s0c]   [vdso] now %#lx-%#lx (asked %#lx) -> %s\n", vs2, ve2, target_vdso,
		       vs2 == target_vdso ? "at the requested base" : "ELSEWHERE");
	if (maps_find("[vvar]", &v2s, &v2e))
		printf("[s0c]   [vvar] now %#lx-%#lx (asked %#lx) -> %s\n", v2s, v2e, target_vvar,
		       v2s == target_vvar ? "at the requested base" : "ELSEWHERE");

	/* C: a library that cached a pointer into the OLD [vdso] address at startup.
	 * The restore engine's whole reason for moving the vdso back to the recorded
	 * base is that a checkpointed process carries exactly such pointers. */
	printf("[s0c] C: child calls glibc clock_gettime, whose vDSO pointer predates the move\n");
	pid = fork();
	if (pid == 0) {
		struct timespec t3 = { 0, 0 };
		int rc = clock_gettime(CLOCK_MONOTONIC, &t3);
		static const char msg[] = "[s0c]   C: glibc still returned a time\n";
		ssize_t w = write(1, msg, sizeof msg - 1); (void)w;
		_exit(rc == 0 && t3.tv_sec > 0 ? 0 : 4);
	}
	st = 0;
	waitpid(pid, &st, 0);
	if (WIFSIGNALED(st))
		printf("[s0c]   C: died with signal %d (%s) -- the stale cached pointer is "
		       "why restore must land the vdso back at the recorded base\n",
		       WTERMSIG(st), strsignal(WTERMSIG(st)));
	else
		printf("[s0c]   C: child exit %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
	show_maps("after");
	return 0;
}
