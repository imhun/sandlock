/*
 * arm64 checkpoint/restore S0a spike -- the signal-frame ABI.
 *
 * Answers two questions with evidence instead of ABI recall (plan:
 * third_party/sandlock/docs/fork-plan-2026-09-aarch64-restore.md, stage S0a):
 *
 *   1. What does the kernel's rt_sigframe actually look like on this kernel?
 *      Dump a kernel-built frame (SA_SIGINFO handler), then locate every field
 *      by sentinel: general registers, sp/pc/pstate, the FP record, and whether
 *      TPIDR_EL0 shows up anywhere in it.
 *   2. Can a hand-built frame drive rt_sigreturn into a chosen register/stack
 *      state? Build one, `svc` rt_sigreturn, and check the pc we land on, sp,
 *      the FP image and the flags on arrival.
 *
 * Not freestanding: Rocky has gcc but no glibc-static, and the frame layout is
 * laid down by the *kernel*, not by libc -- so the harness may use libc. Every
 * register the kernel is asked to restore is set from a global by hand-written
 * asm, and the post-restore report uses raw `svc` only.
 *
 * Build: gcc -O1 -mgeneral-regs-only -fno-stack-protector \
 *            -o s0a-sigframe s0a-sigframe.c
 * (-mgeneral-regs-only keeps the compiler out of v0-v31: the spike deliberately
 *  clobbers the whole FP/SIMD file, which breaks the v8-v15 callee-saved rule.)
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define FRAME_WINDOW 0x1800UL
#ifndef SYS_write
#define SYS_write 64
#endif
#ifndef SYS_exit_group
#define SYS_exit_group 94
#endif
#ifndef SYS_rt_sigreturn
#define SYS_rt_sigreturn 139
#endif
#define SIG_FOR_SPIKE 10 /* SIGUSR1 */

/* raw syscall: no TLS, no errno -- usable after TPIDR_EL0 points at a sentinel
 * and on the hand-made stack after rt_sigreturn. */
static long raw_sys(long n, long a, long b, long c)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
	return x0;
}

static size_t raw_len(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
static void raw_puts(const char *s) { raw_sys(SYS_write, 1, (long)s, (long)raw_len(s)); }
static void raw_hex(unsigned long v)
{
	char b[19];
	b[0] = '0'; b[1] = 'x';
	for (int i = 0; i < 16; i++) {
		unsigned d = (unsigned)((v >> (60 - 4 * i)) & 0xf);
		b[2 + i] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
	}
	b[18] = '\n';
	raw_sys(SYS_write, 1, (long)b, 19);
}
static void raw_num(unsigned long v)
{
	char b[24]; int i = 23;
	if (!v) b[i--] = '0';
	while (v) { b[i--] = (char)('0' + (v % 10)); v /= 10; }
	raw_sys(SYS_write, 1, (long)(b + i + 1), (long)(23 - i));
}
static void raw_dec(unsigned long v)
{
	char b[24]; int i = 23; b[i--] = '\n';
	if (!v) b[i--] = '0';
	while (v) { b[i--] = (char)('0' + (v % 10)); v /= 10; }
	raw_sys(SYS_write, 1, (long)(b + i + 1), (long)(23 - i));
}

/* ---- sentinels ---------------------------------------------------------- */
/* One distinct value per general register, so the dump tells us the exact
 * offset of regs[i] instead of us trusting a struct definition. */
/* read only from the hand-written asm below: `used` stops -O1 from deleting the
 * storage, which is what made the first build link-fail on both symbols */
unsigned long g_sent[32] __attribute__((aligned(16), used));
volatile unsigned long g_tls_sent __attribute__((used));
unsigned long g_tls_saved __attribute__((used));
unsigned long g_fp[64] __attribute__((aligned(16), used));
static unsigned long fp_lo(int i) { return 0xf0f0000000000000UL | (unsigned long)i; }
static unsigned long fp_hi(int i) { return 0xf1f1000000000000UL | (unsigned long)i; }
static unsigned long sentinel(int i)
{
	return 0xacc0000000000000UL | ((unsigned long)i << 8) | 0x5aUL;
}
#define TLS_SENT 0x7e1557a100000000UL
#ifndef FPSIMD_MAGIC
#define FPSIMD_MAGIC 0x46508001U
#endif
#define FPSIMD_SIZE 0x210U

/* ---- kernel-built frame ------------------------------------------------- */
static volatile unsigned long g_sp, g_info, g_uc, g_sig, g_ran;

/* not named sa_handler: glibc defines that as a macro into the sigaction union */
static void spike_handler(int sig, siginfo_t *info, void *uc)
{
	unsigned long sp;
	__asm__ volatile("mov %0, sp" : "=r"(sp));
	g_sp = sp;
	g_info = (unsigned long)info;
	g_uc = (unsigned long)uc;
	g_sig = (unsigned long)sig;
	g_ran = 1;
}

/* Load the FP patterns, set the general-register sentinels and raise SIGUSR1 --
 * all in one asm function so nothing between the setup and the `svc` can
 * clobber what we are about to observe. x18 is the platform register and is
 * deliberately left alone; x16/x17 carry the table bases. */
__asm__(
".text\n"
".globl fp_and_fire_\n"
".type fp_and_fire_, %function\n"
"fp_and_fire_:\n"
"	adrp x16, g_saved\n"
"	add  x16, x16, :lo12:g_saved\n"
"	stp x19, x20, [x16, #0]\n"
"	stp x21, x22, [x16, #16]\n"
"	stp x23, x24, [x16, #32]\n"
"	stp x25, x26, [x16, #48]\n"
"	stp x27, x28, [x16, #64]\n"
"	str q8,  [x16, #80]\n"
"	str q9,  [x16, #96]\n"
"	str q10, [x16, #112]\n"
"	str q11, [x16, #128]\n"
"	str q12, [x16, #144]\n"
"	str q13, [x16, #160]\n"
"	str q14, [x16, #176]\n"
"	str q15, [x16, #192]\n"
"	mrs x17, fpcr\n"
"	str x17, [x16, #208]\n"
"	mrs x17, fpsr\n"
"	str x17, [x16, #216]\n"
"	adrp x16, g_fp\n"
"	add  x16, x16, :lo12:g_fp\n"
"	ldp q0, q1, [x16, #0]\n"
"	ldp q2, q3, [x16, #32]\n"
"	ldp q4, q5, [x16, #64]\n"
"	ldp q6, q7, [x16, #96]\n"
"	ldp q16, q17, [x16, #256]\n"
"	ldp q18, q19, [x16, #288]\n"
"	ldp q20, q21, [x16, #320]\n"
"	ldp q22, q23, [x16, #352]\n"
"	ldp q24, q25, [x16, #384]\n"
"	ldp q26, q27, [x16, #416]\n"
"	ldp q28, q29, [x16, #448]\n"
"	ldp q30, q31, [x16, #480]\n"
"	msr fpcr, xzr\n"
"	msr fpsr, xzr\n"
"	mov x2, #10\n"
"	mov x8, #131\n"
"	adrp x16, g_sent\n"
"	add  x16, x16, :lo12:g_sent\n"
"	ldp x9,  x10, [x16, #72]\n"
"	ldp x11, x12, [x16, #88]\n"
"	ldp x13, x14, [x16, #104]\n"
"	ldr x15, [x16, #120]\n"
"	adrp x17, g_sent\n"
"	add  x17, x17, :lo12:g_sent\n"
"	ldp x19, x20, [x17, #152]\n"
"	ldp x21, x22, [x17, #168]\n"
"	ldp x23, x24, [x17, #184]\n"
"	ldp x25, x26, [x17, #200]\n"
"	ldp x27, x28, [x17, #216]\n"
"	svc #0\n"
"	adrp x16, g_saved\n"
"	add  x16, x16, :lo12:g_saved\n"
"	ldr x17, [x16, #216]\n"
"	msr fpsr, x17\n"
"	ldr x17, [x16, #208]\n"
"	msr fpcr, x17\n"
"	ldr q8,  [x16, #80]\n"
"	ldr q9,  [x16, #96]\n"
"	ldr q10, [x16, #112]\n"
"	ldr q11, [x16, #128]\n"
"	ldr q12, [x16, #144]\n"
"	ldr q13, [x16, #160]\n"
"	ldr q14, [x16, #176]\n"
"	ldr q15, [x16, #192]\n"
"	ldp x19, x20, [x16, #0]\n"
"	ldp x21, x22, [x16, #16]\n"
"	ldp x23, x24, [x16, #32]\n"
"	ldp x25, x26, [x16, #48]\n"
"	ldp x27, x28, [x16, #64]\n"
"	ret\n"
);

/* Set TPIDR_EL0 to a sentinel, raise SIGUSR1 with raw `svc`, then put it back.
 * The sentinel is *derived at run time* from the live thread pointer and both
 * scratch registers are cleared before the `svc`: the value then exists only in
 * memory and in TPIDR_EL0, so finding it in the frame really does mean the
 * kernel saved TLS. (Two earlier versions passed it in a register / as a
 * constant and the compiler kept a copy in x24, which made every run "yes".) */
__asm__(
".text\n"
".globl tls_and_fire_\n"
".type tls_and_fire_, %function\n"
"tls_and_fire_:\n"
"	adrp x16, g_tls_saved\n"
"	add  x16, x16, :lo12:g_tls_saved\n"
"	mrs  x17, tpidr_el0\n"
"	str  x17, [x16]\n"
"	mov  x16, #0x3f\n"
"	eor  x16, x17, x16\n"
"	adrp x17, g_tls_sent\n"
"	add  x17, x17, :lo12:g_tls_sent\n"
"	str  x16, [x17]\n"
"	msr  tpidr_el0, x16\n"
"	mov  x16, #0\n"
"	mov  x17, #0\n"
"	mov  x2, #10\n"
"	mov  x8, #131\n"
"	svc #0\n"
"	adrp x16, g_tls_saved\n"
"	add  x16, x16, :lo12:g_tls_saved\n"
"	ldr  x17, [x16]\n"
"	msr  tpidr_el0, x17\n"
"	ret\n"
);

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

/* stash for the callee-saved registers the sentinel pass overwrites: the kernel
 * hands the sentinels back after the handler returns, so without this the
 * *caller's* x19-x28 and v8-v15 would come back as our markers (that, and not
 * anything the kernel did, is why the first run died in main with SIGSEGV) */
unsigned long g_saved[32] __attribute__((aligned(16), used));

extern void fp_and_fire_(long pid, long tid);
extern void tls_and_fire_(long pid, long tid);
extern unsigned long tls_roundtrip_(unsigned long v);
extern void hb_entry_(void);

/* ---- dump analysis ------------------------------------------------------ */
static long find_u64(const unsigned char *buf, size_t len, unsigned long v)
{
	for (size_t o = 0; o + 8 <= len; o += 8) {
		unsigned long x;
		memcpy(&x, buf + o, 8);
		if (x == v) return (long)o;
	}
	return -1;
}
static long find_u32(const unsigned char *buf, size_t len, unsigned int v)
{
	for (size_t o = 0; o + 4 <= len; o += 4) {
		unsigned int x;
		memcpy(&x, buf + o, 4);
		if (x == v) return (long)o;
	}
	return -1;
}
static unsigned rd32(const unsigned char *p) { unsigned v; memcpy(&v, p, 4); return v; }
static unsigned long rd64(const unsigned char *p) { unsigned long v; memcpy(&v, p, 8); return v; }

static void dump_rows(const unsigned char *buf, const char *label, long from, long n)
{
	char line[64];
	raw_puts(label);
	for (long r = 0; r < n; r += 16) {
		const unsigned char *p = buf + from + r;
		int k = 0;
		line[k++] = ' '; line[k++] = '+';
		unsigned long off = (unsigned long)(from + r);
		for (int i = 0; i < 12; i++) {
			unsigned d = (unsigned)((off >> (44 - 4 * i)) & 0xf);
			line[k++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
		}
		line[k++] = ':';
		for (int i = 0; i < 16; i++) {
			line[k++] = ' ';
			unsigned b = p[i];
			line[k++] = (char)((b >> 4) < 10 ? '0' + (b >> 4) : 'a' + (b >> 4) - 10);
			line[k++] = (char)((b & 0xf) < 10 ? '0' + (b & 0xf) : 'a' + (b & 0xf) - 10);
		}
		line[k++] = '\n';
		raw_sys(SYS_write, 1, (long)line, k);
	}
}

/* Analyse one dumped frame; returns the sigcontext offset from the frame base
 * (or -1 when the sentinels were not found). */
static long analyse(const unsigned char *buf, size_t len, int verbose)
{
	long reg9 = find_u64(buf, len, sentinel(9));
	long sc = reg9 < 0 ? -1 : reg9 - (8 + 9 * 8);

	raw_puts("  regs[9] offset  : ");
	if (reg9 < 0) raw_puts("NOT FOUND\n"); else raw_hex((unsigned long)reg9);
	raw_puts("  => sigcontext at: ");
	if (sc < 0) raw_puts("NOT FOUND\n"); else raw_hex((unsigned long)sc);

	if (sc >= 0) {
		int ok = 1, checked = 0;
		for (int i = 0; i < 31; i++) {
			/* only x9-x15 and x19-x28 carry sentinels (x16/x17 held the table
			 * bases, x18 is the platform register, x29/x30 are the frame) */
			if (i < 9 || (i > 15 && i < 19) || i > 28) continue;
			long o = find_u64(buf, len, sentinel(i));
			if (o != sc + 8 + i * 8) ok = 0;
			checked++;
		}
		raw_puts("  sentinels checked: "); raw_dec((unsigned long)checked);
		raw_puts("  regs[] linear   : ");
		raw_puts(ok ? "yes (every sentinel at sc+8+8*i)\n"
			    : "NO -- per-register offsets follow\n");
		if (!ok) {
			for (int i = 0; i < 31; i++) {
				if (i < 9 || (i > 15 && i < 19) || i > 28) continue;
				long o = find_u64(buf, len, sentinel(i));
				raw_puts("    regs["); raw_num((unsigned long)i); raw_puts("] -> ");
				if (o < 0) raw_puts("NOT FOUND\n"); else raw_hex((unsigned long)o);
			}
		} else {
			raw_puts("    x9  -> "); raw_hex((unsigned long)(sc + 8 + 9 * 8));
			raw_puts("    x28 -> "); raw_hex((unsigned long)(sc + 8 + 28 * 8));
		}
	}

	if (sc >= 0) {
		raw_puts("  sc.fault_address: "); raw_hex(rd64(buf + sc + 0x000));
		raw_puts("  sc.regs[8] (nr) : "); raw_hex(rd64(buf + sc + 0x048));
		raw_puts("  sc.sp           : "); raw_hex(rd64(buf + sc + 0x100));
		raw_puts("  sc.pc           : "); raw_hex(rd64(buf + sc + 0x108));
		raw_puts("  sc.pstate       : "); raw_hex(rd64(buf + sc + 0x110));
	}

	long magic = find_u32(buf, len, FPSIMD_MAGIC);
	raw_puts("  fpsimd magic    : ");
	if (magic < 0) {
		raw_puts("NOT FOUND\n");
	} else {
		raw_hex((unsigned long)magic);
		raw_puts("  fpsimd size     : "); raw_hex(rd32(buf + magic + 4));
		raw_puts("  fpsr            : "); raw_hex(rd32(buf + magic + 8));
		raw_puts("  fpcr            : "); raw_hex(rd32(buf + magic + 12));
		long v0 = find_u64(buf, len, fp_lo(0));
		raw_puts("  v0 lo pattern   : ");
		if (v0 < 0) raw_puts("NOT FOUND\n");
		else {
			raw_hex((unsigned long)v0);
			raw_puts("  vregs offset in record: ");
			raw_dec((unsigned long)(v0 - magic));
		}
		long v31 = find_u64(buf, len, fp_lo(31));
		raw_puts("  v31 lo pattern  : ");
		if (v31 < 0) raw_puts("NOT FOUND\n"); else raw_hex((unsigned long)v31);
		if (sc >= 0) {
			raw_puts("  magic - sigcontext: ");
			raw_dec((unsigned long)(magic - sc));
		}
	}

	long tls = find_u64(buf, len, TLS_SENT);
	raw_puts("  TPIDR_EL0 sentinel inside frame: ");
	if (tls < 0) raw_puts("NO\n"); else { raw_puts("yes at "); raw_hex((unsigned long)tls); }

	unsigned long tls_now = 0;
	__asm__ volatile("mrs %0, tpidr_el0" : "=r"(tls_now));
	raw_puts("  live TPIDR_EL0 now : "); raw_hex(tls_now);

	if (verbose && sc >= 0) {
		dump_rows(buf, "  sigcontext rows:\n", sc, 0x120);
		if (magic >= 0) dump_rows(buf, "  fpsimd record rows:\n", magic, 0x40);
	}
	return sc;
}

/* ---- hand-built frame + rt_sigreturn ------------------------------------ */
static unsigned char g_hb[0x2000] __attribute__((aligned(16)));
static unsigned char g_hb_stack[0x4000] __attribute__((aligned(16)));

__asm__(
".text\n"
".globl hb_entry_\n"
".type hb_entry_, %function\n"
"hb_entry_:\n"
"	mov x1, sp\n"
"	fmov x2, d0\n"
"	mov x3, x19\n"
"	mrs x4, nzcv\n"
"	fmov x5, d31\n"
"	b hb_report\n"
);

void hb_report(unsigned long r0, unsigned long sp, unsigned long v0lo,
	       unsigned long x19, unsigned long nzcv, unsigned long v31lo)
{
	raw_puts("[s0a/B] landed after rt_sigreturn on the hand-built frame\n");
	raw_puts("  x0  (frame regs[0]) : "); raw_hex(r0);
	raw_puts("  sp  (frame sp)      : "); raw_hex(sp);
	raw_puts("  x19 (frame regs[19]): "); raw_hex(x19);
	raw_puts("  v0.d[0]  (fpsimd)   : "); raw_hex(v0lo);
	raw_puts("  v31.d[0] (fpsimd)   : "); raw_hex(v31lo);
	raw_puts("  nzcv    (pstate)    : "); raw_hex(nzcv);
	raw_puts("  TPIDR_EL0 unchanged : ");
	unsigned long tls_now = 0;
	__asm__ volatile("mrs %0, tpidr_el0" : "=r"(tls_now));
	raw_hex(tls_now);
	raw_puts("[s0a/B] marker exit(0x5a)\n");
	raw_sys(SYS_exit_group, 0x5a, 0, 0);
	for (;;) { }
}

static void put64(unsigned char *p, unsigned long v) { memcpy(p, &v, 8); }
static void put32(unsigned char *p, unsigned int v) { memcpy(p, &v, 4); }

static void build_and_jump(long uc_off, long sc_off_in_uc, long reserved_off)
{
	unsigned char *base = g_hb;
	unsigned char *sc = base + uc_off + sc_off_in_uc;

	memset(g_hb, 0, sizeof g_hb);
	memset(g_hb_stack, 0, sizeof g_hb_stack);

	put64(sc + 0x000, 0);			/* fault_address */
	for (int i = 0; i < 31; i++)
		put64(sc + 0x008 + i * 8, 0xbb00000000000000UL | (unsigned long)i);
	put64(sc + 0x008 + 0 * 8, 0xc0ffeeUL);				/* x0 */
	put64(sc + 0x008 + 19 * 8, 0xdeadbeefcafef00dUL);		/* x19 */
	put64(sc + 0x100, (unsigned long)(g_hb_stack + sizeof g_hb_stack - 32)); /* sp */
	put64(sc + 0x108, (unsigned long)&hb_entry_);			/* pc */
	put64(sc + 0x110, 0);						/* pstate */

	unsigned char *res = sc + reserved_off;
	put32(res + 0, FPSIMD_MAGIC);
	put32(res + 4, FPSIMD_SIZE);
	put32(res + 8, 0);			/* fpsr */
	put32(res + 12, 0);			/* fpcr */
	for (int i = 0; i < 32; i++) {
		put64(res + 16 + i * 16, fp_lo(i));
		put64(res + 24 + i * 16, fp_hi(i));
	}

	printf("[s0a/B] hand-built frame %p: uc_off=%ld sc_off_in_uc=%ld sigcontext=%p\n",
	       (void *)base, uc_off, sc_off_in_uc, (void *)sc);
	printf("[s0a/B] pc=%p sp=%p fpsimd record=%p (reserved_off=%ld)\n",
	       (void *)&hb_entry_, (void *)(g_hb_stack + sizeof g_hb_stack - 32),
	       (void *)res, reserved_off);
	printf("[s0a/B] jumping: x8=rt_sigreturn(%d), sp=frame\n", SYS_rt_sigreturn);
	fflush(stdout);

	__asm__ volatile(
		"mov sp, %0\n"
		"mov x8, %1\n"
		"svc #0\n"
		: : "r"((unsigned long)g_hb), "i"(SYS_rt_sigreturn)
		: "x8", "memory");
	raw_puts("[s0a/B] rt_sigreturn returned -- the kernel rejected the frame\n");
	raw_sys(SYS_exit_group, 0x5b, 0, 0);
	for (;;) { }
}

/* ---- the TLS-in-the-frame child ---------------------------------------- */
static unsigned char g_child_frame[FRAME_WINDOW];

static void child_main(void)
{
	unsigned long sp, info, uc, want, tls_orig;

	/* Poison TPIDR_EL0 only for the window the handler is inside. */
	__asm__ volatile("mrs %0, tpidr_el0" : "=r"(tls_orig));
	tls_and_fire_(syscall(SYS_getpid), syscall(SYS_gettid));

	sp = g_sp; info = g_info; uc = g_uc;
	memcpy(g_child_frame, (void *)sp, FRAME_WINDOW);

	printf("[s0a/TLS] child: ran=%lu sp=0x%lx info=0x%lx uc=0x%lx info-sp=%ld uc-info=%ld\n",
	       g_ran, sp, info, uc, (long)(info - sp), (long)(uc - info));
	want = g_tls_sent;   /* volatile: the value the asm derived and used */
	printf("[s0a/TLS] poisoned TPIDR_EL0 with 0x%lx (original 0x%lx)\n", want, tls_orig);
	long o = find_u64(g_child_frame, FRAME_WINDOW, want);
	printf("[s0a/TLS] TPIDR_EL0 sentinel inside the kernel's frame: %s\n",
	       o < 0 ? "NO" : "yes");
	if (o >= 0) printf("[s0a/TLS]   at frame+0x%lx\n", (unsigned long)o);

	int fd = open("/tmp/arm-cr-s0/s0a-frame-child.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) { ssize_t w = write(fd, g_child_frame, FRAME_WINDOW); (void)w; close(fd); }
	_exit(0);
}

int main(void)
{
	static unsigned char frame[FRAME_WINDOW];
	unsigned long tls_now = 0;
	struct sigaction sa;
	long sc_a, uc_off, sc_off_in_uc, reserved_off;
	pid_t pid;
	int status;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("[s0a] arm64 signal-frame spike on %s\n", "linux/aarch64");
	printf("[s0a] sizeof(siginfo_t)=%zu sizeof(ucontext_t)=%zu sizeof(mcontext_t)=%zu\n",
	       sizeof(siginfo_t), sizeof(ucontext_t), sizeof(mcontext_t));
	__asm__ volatile("mrs %0, tpidr_el0" : "=r"(tls_now));
	printf("[s0a] live TPIDR_EL0 = 0x%lx\n", tls_now);
	(void)tls_now;

	for (int i = 0; i < 32; i++) g_sent[i] = sentinel(i);
	for (int i = 0; i < 32; i++) { g_fp[2 * i] = fp_lo(i); g_fp[2 * i + 1] = fp_hi(i); }

	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = spike_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIG_FOR_SPIKE, &sa, NULL) != 0) {
		perror("[s0a] sigaction");
		return 1;
	}
	printf("[s0a] handler installed (SA_SIGINFO, glibc builds the kernel struct)\n");

	/* S0b's user-space half: can EL0 write TPIDR_EL0 at all? */
	unsigned long got = tls_roundtrip_(TLS_SENT);
	printf("[s0a] TPIDR_EL0 write/read round trip: wrote 0x%lx read 0x%lx -> %s\n",
	       TLS_SENT, got, got == TLS_SENT ? "ok" : "MISMATCH");

	/* ---- phase A: let the kernel build the frame, then dissect it ---- */
	g_ran = 0;
	fp_and_fire_(syscall(SYS_getpid), syscall(SYS_gettid));
	printf("[s0a/A] handler ran=%lu sig=%lu\n", g_ran, g_sig);
	printf("[s0a/A] sp(frame base)=0x%lx info=0x%lx uc=0x%lx\n", g_sp, g_info, g_uc);
	printf("[s0a/A] info-sp=%ld uc-info=%ld\n", (long)(g_info - g_sp), (long)(g_uc - g_info));
	if (!g_ran || !g_sp) { printf("[s0a/A] handler did not run -- aborting\n"); return 2; }

	memcpy(frame, (void *)g_sp, FRAME_WINDOW);
	sc_a = analyse(frame, FRAME_WINDOW, 1);

	int fd = open("/tmp/arm-cr-s0/s0a-frame-parent.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) { ssize_t w = write(fd, frame, FRAME_WINDOW); (void)w; close(fd); }

	/* ---- the same question, with TPIDR_EL0 poisoned ---- */
	pid = fork();
	if (pid == 0) child_main();
	if (pid > 0) { waitpid(pid, &status, 0);
		printf("[s0a/TLS] child exit status: %d (signalled=%d sig=%d)\n",
		       status, WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : 0); }

	/* ---- phase B: hand-build the frame and rt_sigreturn into it ---- */
	uc_off = (long)(g_uc - g_sp);
	sc_off_in_uc = sc_a - uc_off;
	reserved_off = 0x120;
	if (sc_a < 0) {
		printf("[s0a/B] sentinels were not found; falling back to the textbook "
		       "offsets (uc_off=128 sc_off_in_uc=0xa8 reserved=0x120)\n");
		uc_off = 128; sc_off_in_uc = 0xa8;
	} else {
		printf("[s0a/B] derived offsets: uc_off=%ld sigcontext_in_uc=0x%lx "
		       "reserved_in_sigcontext=0x%lx\n",
		       uc_off, (unsigned long)sc_off_in_uc, (unsigned long)reserved_off);
	}
	build_and_jump(uc_off, sc_off_in_uc, reserved_off);
	return 0;
}
