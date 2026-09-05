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
# F2b.5: each arch's sandlock-supervise release binary is cross-built in the
# same builder (same zig target/linker config as the FFI .so) and lands here
# three ways from ONE source of bytes:
#   wheels/supervise/<arch>/sandlock-supervise     standalone (COPY-friendly)
#   wheels/<arch>.whl  ->  sandlock/bin/sandlock-supervise   (injected after
#     auditwheel repair, RECORD updated, so pip installs the binary too)
#   wheels/SHA256SUMS.supervise                    HEAD-pinned sha256 manifest
# python/verify-wheel.sh checks the wheel-embedded and standalone copies
# against the manifest and runs the --uid refusal smoke.
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

for arch in x86_64 aarch64; do
    if [ ! -f "$OUT_DIR/supervise/$arch/sandlock-supervise" ]; then
        echo "build-wheels: supervise/$arch/sandlock-supervise missing from $OUT_DIR/" >&2
        echo "  (docker export stage must carry /supervise/<arch>/sandlock-supervise)" >&2
        exit 1
    fi
done

if ! command -v python3 >/dev/null 2>&1; then
    echo "build-wheels: python3 required to inject sandlock-supervise into the wheels" >&2
    exit 1
fi

# Inject the same bytes into each wheel (sandlock/bin/sandlock-supervise) and
# rewrite RECORD so pip keeps the binary; then write the HEAD-pinned manifest
# that python/verify-wheel.sh compares against.
SUPERVISE_OUT="$OUT_DIR" SUPERVISE_HEAD="$(git rev-parse HEAD)" python3 - <<'PY'
import base64
import hashlib
import os
import zipfile

out = os.environ["SUPERVISE_OUT"]
head = os.environ["SUPERVISE_HEAD"]


wheel_by_arch = {}
for name in sorted(os.listdir(out)):
    if not name.endswith(".whl"):
        continue
    if "x86_64" in name:
        arch = "x86_64"
    elif "aarch64" in name:
        arch = "aarch64"
    else:
        raise SystemExit(
            f"build-wheels: cannot map wheel {name!r} to x86_64/aarch64"
        )
    if arch in wheel_by_arch:
        raise SystemExit(f"build-wheels: more than one {arch} wheel in {out}")
    wheel_by_arch[arch] = os.path.join(out, name)

missing = sorted(set(("x86_64", "aarch64")) - set(wheel_by_arch))
if missing:
    raise SystemExit(
        "build-wheels: no wheel for arch(es) %s in %s" % (", ".join(missing), out)
    )

manifest_lines = [
    "# sandlock-supervise release fingerprint (fork-plan F2b.5).",
    "# Wheel-embedded (sandlock/bin/sandlock-supervise) and standalone",
    "# (supervise/<arch>/sandlock-supervise) copies are the same bytes;",
    "# python/verify-wheel.sh compares both against this manifest and refuses",
    "# to verify against a different tip (HEAD mismatch).",
    f"# HEAD={head}",
]
for arch in ("x86_64", "aarch64"):
    sup = os.path.join(out, "supervise", arch, "sandlock-supervise")
    data = open(sup, "rb").read()
    digest = hashlib.sha256(data).digest()
    manifest_lines.append(f"{digest.hex()}  supervise/{arch}/sandlock-supervise")

    wheel = wheel_by_arch[arch]
    target = "sandlock/bin/sandlock-supervise"
    infos = {}
    entries = {}
    with zipfile.ZipFile(wheel) as zin:
        for info in zin.infolist():
            infos[info.filename] = info
            entries[info.filename] = zin.read(info.filename)
    records = [n for n in entries if n.endswith(".dist-info/RECORD")]
    if len(records) != 1:
        raise SystemExit(
            f"build-wheels: expected one RECORD in {wheel}, found {records}"
        )
    record_name = records[0]
    if entries.get(target) != data:
        entries[target] = data
        b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        entries[record_name] = (
            entries[record_name].decode() + f"{target},sha256={b64},{len(data)}\n"
        ).encode()
        tmp = wheel + ".inject-tmp"
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for name in entries:
                info = infos.get(name)
                if info is None:
                    # Newly injected supervise: mark it executable so pip
                    # installs it as 0755 and E2B can exec it directly.
                    info = zipfile.ZipInfo(target)
                    info.external_attr = 0o100755 << 16
                zout.writestr(info, entries[name])
        os.replace(tmp, wheel)
        print(f"  supervise injected into {wheel} ({arch})")
    else:
        print(f"  supervise already present in {wheel} ({arch})")

with open(os.path.join(out, "SHA256SUMS.supervise"), "w") as f:
    f.write("\n".join(manifest_lines) + "\n")
print(f"  supervise manifest written ({head})")
PY

echo "==> wheels + supervise in $OUT_DIR/:"
ls -lh "$OUT_DIR"/*.whl
ls -lh "$OUT_DIR/supervise"/*/sandlock-supervise
ls -lh "$OUT_DIR/SHA256SUMS.supervise"
