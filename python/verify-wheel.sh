#!/bin/sh
# Prove the wheels produced by python/build-wheels.sh are the CURRENT TIP's
# build: each wheel's libsandlock_ffi*.so must export EXACTLY the defined
# dynamic symbols of target/release/libsandlock_ffi.so built from this
# working tree. Every missing symbol is named and fails the run (a new FFI
# export with an un-rebuilt wheel goes red immediately); extras are also
# named and fail, so the equality check runs in both directions.
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

work="tmp/wheel-verify"
rm -rf "$work"
mkdir -p "$work"

# sandlock-dev has no unzip; python3 -m zipfile extracts the same structure.
if command -v unzip >/dev/null 2>&1; then
    unpack() { unzip -q "$1" -d "$2"; }
else
    unpack() { python3 -m zipfile -e "$1" "$2"; }
fi

# Release symbol set (same for every wheel under test).
nm -D --defined-only "$RELEASE_SO" | awk '{print $NF}' | sort -u > "$work/release.syms"
release_count=$(wc -l < "$work/release.syms" | tr -d ' ')

rc=0
for wheel in "$@"; do
    if [ ! -f "$wheel" ]; then
        echo "verify-wheel: no such wheel: $wheel" >&2
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

    echo "  git HEAD: $HEAD"
    echo "  sandlock/_version.py from wheel:"
    sed 's/^/    /' "$dir/sandlock/_version.py"
done

rm -rf "$work"
exit "$rc"
