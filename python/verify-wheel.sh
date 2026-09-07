#!/bin/sh
# Prove the wheels produced by python/build-wheels.sh are the CURRENT TIP's
# build: each wheel's libsandlock_ffi*.so must export EXACTLY the defined
# dynamic symbols of target/release/libsandlock_ffi.so built from this
# working tree. Every missing symbol is named and fails the run (a new FFI
# export with an un-rebuilt wheel goes red immediately); extras are also
# named and fail, so the equality check runs in both directions.
#
# F2b.5 supervise self-proof, same spirit: every wheel must carry
# sandlock/bin/sandlock-supervise whose sha256 equals the fingerprint
# python/build-wheels.sh recorded in SHA256SUMS.supervise (the same bytes as
# the standalone supervise/<arch>/sandlock-supervise copies). The manifest is
# HEAD-pinned: verifying a stale manifest (wheels built at an older commit)
# is red and names both commits. The extracted binary is then exercised with
# a --uid self-check smoke: starting it with a --uid that does not match the
# process euid must refuse with exit != 0 and stderr naming both uids. The
# smoke needs an executable of the verify host's arch, so a foreign-arch
# wheel is verified structurally (presence, ELF machine, fingerprint) instead.
#
# Runs inside the Linux dev container — nm -D reads ELF and the release lib is
# built in-container. When the repo is a submodule mounted at /src, its .git
# pointer is relative to the OUTER repo and git cannot resolve HEAD inside the
# mount; pass the host hash via HEAD=... in that case (the script refuses to
# guess). The release lib is built first:
#   cargo build --offline --release -p sandlock-ffi
# Then:
#   docker run --rm -v "$PWD":/src -w /src --entrypoint bash \
#     -e HEAD="$(git rev-parse HEAD)" \
#     sandlock-dev:latest -c 'python/verify-wheel.sh'
# Usage:
#   HEAD=<sha> python/verify-wheel.sh [wheel...]     (default: wheels/*.whl)
set -eu

cd "$(dirname "$0")/.."

RELEASE_SO="target/release/libsandlock_ffi.so"
if [ ! -f "$RELEASE_SO" ]; then
    echo "verify-wheel: $RELEASE_SO not found -- build the tip release lib first:" >&2
    echo "  CARGO_HOME=\$PWD/tmp/cargo-home cargo build --offline --release -p sandlock-ffi" >&2
    exit 1
fi

if [ -z "${HEAD:-}" ]; then
    HEAD="$(git rev-parse HEAD 2>/dev/null || true)"
    if [ -z "$HEAD" ]; then
        echo "verify-wheel: cannot resolve git HEAD here (submodule .git pointer" >&2
        echo "  is relative to the outer repo and breaks under a /src mount);" >&2
        echo "  export HEAD=<sha> when running inside the container" >&2
        exit 1
    fi
fi
echo "==> verifying wheel(s) against tip $HEAD ($RELEASE_SO)"

if [ "$#" -eq 0 ]; then
    set -- wheels/*.whl
fi
if [ "$#" -eq 0 ] || [ ! -f "$1" ]; then
    echo "verify-wheel: no wheels to verify (wheels/*.whl)" >&2
    exit 1
fi

# F2b.5: the fingerprint manifest and the standalone supervise copies live
# next to the wheels (python/build-wheels.sh emits SHA256SUMS.supervise into
# the same directory as the wheels it verifies against).
wheel_dir="$(dirname "$1")"
manifest="$wheel_dir/SHA256SUMS.supervise"
if [ ! -f "$manifest" ]; then
    echo "verify-wheel: $manifest not found -- supervise fingerprint manifest missing;" >&2
    echo "  rerun python/build-wheels.sh at the tip (it writes the manifest next to the wheels)" >&2
    exit 1
fi
manifest_head="$(sed -n 's/^# HEAD=//p' "$manifest" | head -1)"
if [ -z "$manifest_head" ]; then
    echo "verify-wheel: $manifest has no '# HEAD=<sha>' record" >&2
    exit 1
fi
if [ "$manifest_head" != "$HEAD" ]; then
    echo "FAIL -- supervise fingerprint manifest is for commit $manifest_head" >&2
    echo "  but current tip is $HEAD; rebuild the wheels from the tip before verifying" >&2
    exit 1
fi
echo "==> supervise fingerprint manifest: $manifest (HEAD $manifest_head matches current tip)"

case "$(uname -m)" in
    x86_64) host_arch=x86_64 ;;
    aarch64 | arm64) host_arch=aarch64 ;;
    *) host_arch=unknown ;;
esac
if ! command -v readelf >/dev/null 2>&1; then
    echo "verify-wheel: readelf required for the supervise ELF-arch check" >&2
    exit 1
fi

work="tmp/wheel-verify"
rm -rf "$work"
mkdir -p "$work"

# sandlock-dev has no unzip; python3 -m zipfile extracts the same structure.
if command -v unzip >/dev/null 2>&1; then
    unpack() { unzip -q "$1" -d "$2"; }
else
    unpack() { python3 -m zipfile -e "$1" "$2"; }
fi

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "verify-wheel: no sha256sum/shasum available" >&2
        exit 1
    fi
}

manifest_hash_for() {  # manifest_hash_for <arch>
    awk -v a="$1" '$2 == "supervise/" a "/sandlock-supervise" { print $1 }' \
        "$manifest" | head -1
}

wheel_arch() {  # wheel_arch <wheel-filename>
    case "$1" in
        *x86_64*) echo x86_64 ;;
        *aarch64*) echo aarch64 ;;
        *) echo unknown ;;
    esac
}

elf_arch() {  # elf_arch <file> — readelf machine line of the ELF header
    case "$(readelf -h "$1" 2>/dev/null)" in
        *X86-64*) echo x86_64 ;;
        *AArch64*) echo aarch64 ;;
        *) echo unknown ;;
    esac
}

# F2b.5 --uid self-check smoke: refuse to start when euid != --uid. The
# startup check runs before the policy transport is touched, so only the
# required --policy/--uid args are needed.
uid_smoke() {
    bin="$1"
    euid="$(id -u)"
    if [ "$euid" -eq 0 ]; then wrong=65534; else wrong=0; fi
    smoke_rc=0
    "$bin" --policy 3 --uid "$wrong" >"$work/uid-smoke.out" 2>"$work/uid-smoke.err" \
        || smoke_rc=$?
    if [ "$smoke_rc" -eq 0 ]; then
        echo "  FAIL -- supervise --uid refusal smoke: exited 0 with --uid $wrong (euid $euid)" >&2
        return 1
    fi
    # FUP-16: the smoke grep must name BOTH uids (the real euid and the
    # requested --uid), not just the requested one.
    if ! grep -q "refusing to start: euid $euid does not match --uid $wrong" "$work/uid-smoke.err"; then
        echo "  FAIL -- supervise --uid refusal smoke: exit $smoke_rc but stderr does not name euid $euid vs --uid $wrong:" >&2
        sed 's/^/    /' "$work/uid-smoke.err" >&2
        return 1
    fi
    echo "  --uid refusal smoke: euid $euid with --uid $wrong refused (exit $smoke_rc), stderr names both uids"
}

# FUP-16: the wheel RECORD must carry exactly one row for the injected
# supervise binary and that row must match the extracted bytes (a duplicate
# or stale row would break pip's install-time verification).
record_ok() {  # record_ok <RECORD-path> <supervise-path>
    python3 - "$1" "$2" <<'PY'
import base64
import csv
import hashlib
import sys

rows = []
with open(sys.argv[1], newline="", encoding="utf-8") as fh:
    for row in csv.reader(fh):
        if row and row[0] == "sandlock/bin/sandlock-supervise":
            rows.append(row)
if len(rows) != 1:
    sys.exit(f"expected exactly one RECORD row for sandlock/bin/sandlock-supervise, found {len(rows)}")
data = open(sys.argv[2], "rb").read()
want = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
if rows[0][1] != want or rows[0][2] != str(len(data)):
    sys.exit(f"RECORD row mismatch for sandlock/bin/sandlock-supervise: {rows[0]!r}")
PY
}

# Release symbol set (same for every wheel under test).
nm -D --defined-only "$RELEASE_SO" | awk '{print $NF}' | sort -u > "$work/release.syms"
release_count=$(wc -l < "$work/release.syms" | tr -d ' ')

rc=0
for wheel in "$@"; do
    if [ ! -f "$wheel" ]; then
        echo "verify-wheel: no such wheel: $wheel" >&2
        exit 1
    fi
    if [ "$(dirname "$wheel")" != "$wheel_dir" ]; then
        echo "verify-wheel: all wheels under verification must share one directory" >&2
        echo "  (the supervise manifest and standalone copies are resolved next to the wheels):" >&2
        echo "  first wheel dir: $wheel_dir" >&2
        echo "  offending wheel: $wheel" >&2
        exit 1
    fi
    echo
    echo "==> $wheel"

    dir="$work/$(basename "$wheel").d"
    mkdir -p "$dir"
    unpack "$wheel" "$dir"

    so_count=$(find "$dir" -type f -name '*libsandlock_ffi*.so' | wc -l | tr -d ' ')
    if [ "$so_count" -ne 1 ]; then
        echo "FAIL: expected exactly one libsandlock_ffi .so in $wheel (found $so_count)" >&2
        exit 1
    fi
    so=$(find "$dir" -type f -name '*libsandlock_ffi*.so')
    if [ -z "$so" ]; then
        echo "FAIL: no libsandlock_ffi .so inside $wheel" >&2
        exit 1
    fi
    echo "  .so: ${so#"$dir"/}"

    nm -D --defined-only "$so" | awk '{print $NF}' | sort -u > "$work/wheel.syms"
    wheel_count=$(wc -l < "$work/wheel.syms" | tr -d ' ')

    # missing = in release lib but not in wheel; extra = in wheel but not in
    # release lib (sets compared both directions via comm).
    comm -23 "$work/release.syms" "$work/wheel.syms" > "$work/missing.syms"
    comm -13 "$work/release.syms" "$work/wheel.syms" > "$work/extra.syms"

    echo "  release lib defined dynamic symbols: $release_count"
    echo "  wheel defined dynamic symbols:        $wheel_count"

    equal=1
    if [ -s "$work/missing.syms" ]; then
        equal=0
        echo "  FAIL -- symbol(s) in tip release lib MISSING from wheel:"
        sed 's/^/    MISSING: /' "$work/missing.syms"
    fi
    if [ -s "$work/extra.syms" ]; then
        equal=0
        echo "  FAIL -- symbol(s) in wheel NOT in tip release lib:"
        sed 's/^/    EXTRA: /' "$work/extra.syms"
    fi
    if [ "$equal" -eq 1 ]; then
        echo "  symbol sets equal (both directions): yes"
    else
        echo "  symbol sets equal (both directions): no"
        rc=1
    fi

    # F2b.5 supervise: presence, ELF arch, sha256 vs manifest, standalone
    # twin, then the --uid refusal smoke on the host-arch binary.
    sup="$dir/sandlock/bin/sandlock-supervise"
    want_arch="$(wheel_arch "$(basename "$wheel")")"
    if [ ! -f "$sup" ]; then
        echo "  FAIL -- supervise binary MISSING from wheel: sandlock/bin/sandlock-supervise" >&2
        rc=1
    else
        extracted_mode="$(python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$sup")"
        if [ "$extracted_mode" != "755" ]; then
            echo "  FAIL -- supervise extracted mode is $extracted_mode, expected 755 (pip installs the wheel binary as 0755)" >&2
            rc=1
        fi
        chmod +x "$sup"
        got_arch="$(elf_arch "$sup")"
        echo "  supervise: sandlock/bin/sandlock-supervise (present, ELF $got_arch)"
        record="$(find "$dir" -path '*.dist-info/RECORD' -type f | head -1)"
        if [ -z "$record" ]; then
            echo "  FAIL -- no RECORD inside $(basename "$wheel")" >&2
            rc=1
        elif ! record_ok "$record" "$sup"; then
            echo "  FAIL -- RECORD validation for sandlock/bin/sandlock-supervise" >&2
            rc=1
        else
            echo "  RECORD row for sandlock/bin/sandlock-supervise: exact match"
        fi
        if [ "$got_arch" != "$want_arch" ]; then
            echo "  FAIL -- supervise ELF machine is $got_arch but wheel is $want_arch" >&2
            rc=1
        fi
        wheel_hash="$(hash_file "$sup")"
        man_hash="$(manifest_hash_for "$want_arch")"
        if [ -z "$man_hash" ]; then
            echo "  FAIL -- no supervise fingerprint entry for $want_arch in $manifest" >&2
            rc=1
        else
            echo "  supervise sha256 (wheel):     $wheel_hash"
            echo "  supervise sha256 (manifest):  $man_hash"
            if [ "$wheel_hash" != "$man_hash" ]; then
                echo "  FAIL -- supervise fingerprint MISMATCH in $(basename "$wheel"):" >&2
                echo "    wheel sandlock/bin/sandlock-supervise sha256 $wheel_hash" >&2
                echo "    manifest ($manifest) expects              $man_hash" >&2
                rc=1
            else
                echo "  supervise fingerprint matches manifest: yes"
            fi
        fi
        companion="$wheel_dir/supervise/$want_arch/sandlock-supervise"
        if [ ! -f "$companion" ]; then
            echo "  FAIL -- standalone supervise MISSING: $companion" >&2
            rc=1
        elif [ -n "$man_hash" ]; then
            comp_hash="$(hash_file "$companion")"
            if [ "$comp_hash" != "$man_hash" ]; then
                echo "  FAIL -- standalone supervise fingerprint MISMATCH:" >&2
                echo "    $companion sha256 $comp_hash" >&2
                echo "    manifest expects   $man_hash" >&2
                rc=1
            else
                echo "  standalone supervise ($want_arch) matches manifest: yes"
            fi
        fi
        if [ "$want_arch" = "$host_arch" ]; then
            if ! uid_smoke "$sup"; then
                rc=1
            fi
        else
            echo "  --uid refusal smoke: not run for $want_arch ELF on $host_arch verify host (exec format)"
        fi
    fi

    echo "  git HEAD: $HEAD"
    echo "  sandlock/_version.py from wheel:"
    sed 's/^/    /' "$dir/sandlock/_version.py"
done

rm -rf "$work"
exit "$rc"
