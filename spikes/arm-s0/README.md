# arm-s0 — aarch64 checkpoint/restore S0 spikes

Five throwaway programs that answer the three questions stage **S0** of
[`docs/fork-plan-2026-09-aarch64-restore.md`](../../docs/fork-plan-2026-09-aarch64-restore.md)
says must be settled *before* any product code changes. They are not a test
suite: nothing runs them, and `run.sh` is the only entry point.

| file | question |
|---|---|
| `s0a-sigframe.c` | what does the kernel's `rt_sigframe` look like on this kernel (field by field), and can a **hand-built** frame drive `rt_sigreturn` into a chosen register/stack state? |
| `s0b-tls.c` | can EL0 write `TPIDR_EL0`; does `PTRACE_*(NT_ARM_TLS)` round-trip it and does the process see the tracer's value after resume; what sizes/regsets exist (`NT_PRSTATUS`, `NT_PRFPREG`, SVE, PAC, tagged-addr)? |
| `s0c-vaddr.c` | is 3 TiB (x86_64's `STUB_BASE`) usable here, where is the user VA ceiling, and can `mremap` relocate `[vvar]`/`[vdso]` the way `restore-stub.c` does? |
| `s0d-vdso.c` | when a relocation kills the vDSO, exactly which address and instruction faulted (the signal handler reads `fault_address`/`pc` out of the frame `s0a` pinned), how does the vDSO reach its data page, and which move is legal? |
| `s0e-restart.c` | at a `PTRACE_INTERRUPT` stop inside a restartable syscall, has the kernel already rewritten `pc`/`x0` -- i.e. can the arm64 `rearm_restartable_syscall` be a no-op, or must it fail closed? (Added later, for **S2**.) |

`s0e-restart.c` is the one probe that is not S0: it was written while S2 was
being implemented, to settle whether the arm64 rearm can be a no-op. It answers
both restart paths (`-ERESTART*` via `read`, `-ERESTART_RESTARTBLOCK` via
`nanosleep`); the answer is in
[`docs/arm-cr-s0-evidence.md`](../../docs/arm-cr-s0-evidence.md) and in the S2
section of the plan. The other four are the S0 spikes.

Results (two aarch64 nodes, kernel `6.12.0-211.34.1.el10_2.aarch64`) are written
up in [`docs/arm-cr-s0-evidence.md`](../../docs/arm-cr-s0-evidence.md).

## Running

```sh
# on the target (aarch64) host, with the sources in /tmp/arm-cr-s0:
gcc -O1 -mgeneral-regs-only -fno-stack-protector -o s0a-sigframe s0a-sigframe.c
./run.sh          # builds and runs all four, printing dmesg after each
```

`s0e` is built and run on its own (it traces a child through a pipe):

```sh
gcc -O1 -o s0e-restart s0e-restart.c && ./s0e-restart
```

`s0c`/`s0d` move the vDSO out from under themselves and fork children that are
expected to die (that is the measurement), so run them in a throwaway shell.
