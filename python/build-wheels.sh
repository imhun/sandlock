#!/bin/sh
# Cross-compile the sandlock fork wheel (cp314, manylinux_2_34) for BOTH
# linux/amd64 and linux/arm64 inside a pypa manylinux_2_34 builder and land
# the two repaired wheels in wheels/ (git-ignored) under the fork root. zig is
# the Rust cross-linker, so the whole compile runs in ONE native builder —
# no QEMU for the Rust build, no native arm64 node. Builder assets live with
# the fork under python/wheel-builder/; build context is a lean mirror of the
# fork root (Cargo.toml/Cargo.lock/crates/python only) so the GB-scale
# tmp/ and target-linux/ artifacts never enter the build.
#
# Usage:
#   ./python/build-wheels.sh
#
# Environment:
#   PLATFORM     buildx platform for the native builder (default: host arch)
#   BUILDER      buildx builder name (default: multiarch)
#   BASE_IMAGE   manylinux builder image (default: host-arch manylinux_2_34)
#   OUT_DIR      wheel output dir (default: wheels/ under the fork root)
#   CONTEXT_DIR  staged build context dir (default: tmp/wheel-context)
set -eu

cd "$(dirname "$0")/.."   # fork root: build inputs, wheels/, tmp/ all live here

BUILDER="${BUILDER:-multiarch}"
OUT_DIR="${OUT_DIR:-wheels}"
CONTEXT_DIR="${CONTEXT_DIR:-tmp/wheel-context}"

case "$(uname -m)" in
    x86_64)
        PLATFORM="${PLATFORM:-linux/amd64}"
        BASE_IMAGE="${BASE_IMAGE:-quay.io/pypa/manylinux_2_34_x86_64}" ;;
    arm64 | aarch64)
        PLATFORM="${PLATFORM:-linux/arm64}"
        BASE_IMAGE="${BASE_IMAGE:-quay.io/pypa/manylinux_2_34_aarch64}" ;;
    *)
        PLATFORM="${PLATFORM:-linux/amd64}"
        BASE_IMAGE="${BASE_IMAGE:-quay.io/pypa/manylinux_2_28_x86_64}" ;;
esac

# Stage a lean context that mirrors the fork root for exactly the COPY inputs
# in python/wheel-builder/Dockerfile. Copying the raw root would stream the
# multi-GB tmp/ and target-linux/ trees into every build for no benefit.
echo "==> staging lean build context at $CONTEXT_DIR (Cargo.toml Cargo.lock crates python)"
rm -rf "$CONTEXT_DIR"
mkdir -p "$CONTEXT_DIR"
cp Cargo.toml Cargo.lock "$CONTEXT_DIR/"
cp -R crates "$CONTEXT_DIR/"
cp -R python "$CONTEXT_DIR/"

mkdir -p "$OUT_DIR"

echo "==> cross-building sandlock wheels ($PLATFORM builder, targets amd64+arm64, manylinux_2_34)"
docker buildx build --builder "$BUILDER" --platform "$PLATFORM" \
    --build-arg BASE_IMAGE="$BASE_IMAGE" \
    -f python/wheel-builder/Dockerfile \
    -o type=local,dest="$OUT_DIR" \
    "$CONTEXT_DIR"

echo "==> wheels in $OUT_DIR/:"
ls -lh "$OUT_DIR"/*.whl
