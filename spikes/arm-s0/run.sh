#!/bin/sh
# Run the aarch64 S0 spikes on a target node. Sources are pushed alongside this
# script into /tmp/arm-cr-s0 (nothing outside that directory is touched).
set -u
DIR=/tmp/arm-cr-s0
cd "$DIR" || exit 1
echo "== node: $(hostname) $(uname -m) $(uname -r)"
echo "== gcc: $(gcc --version | head -1)"

build() {
	src="$1"; out="$2"
	printf '\n===== build %s\n' "$out"
	if gcc -O1 -mgeneral-regs-only -fno-stack-protector -Wall -o "$out" "$src" 2>&1; then
		echo "build ok: $(ls -l "$out" | awk '{print $5" bytes"}')"
	else
		echo "BUILD FAILED: $src"
	fi
}

build s0a-sigframe.c s0a-sigframe
build s0b-tls.c s0b-tls
build s0c-vaddr.c s0c-vaddr
build s0d-vdso.c s0d-vdso

run() {
	bin="$1"; shift
	printf '\n===== run %s %s\n' "$bin" "$*"
	if [ -x "$bin" ]; then
		"./$bin" "$@" 2>&1
		echo "----- exit $?"
		echo "----- dmesg tail:"
		dmesg | tail -3
	else
		echo "missing binary"
	fi
}

run s0a-sigframe
run s0b-tls
run s0c-vaddr
run s0d-vdso
printf '\n===== second run of s0c (ASLR comparison)\n'
run s0c-vaddr

echo
echo "== artifacts in $DIR"
ls -l "$DIR"
