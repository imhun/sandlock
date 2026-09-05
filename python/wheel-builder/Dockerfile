# Cross-compile the sandlock fork wheel (0.9.0-beta) for BOTH linux/amd64 and
# linux/arm64 inside a pypa manylinux_2_34 builder, then auditwheel-repair
# both wheels to manylinux_2_34_* tags. zig is the Rust cross-linker, so the
# whole compile runs in ONE native builder (no QEMU / no native arm64 node);
# only the short aarch64 auditwheel-repack stage runs under emulation.
#
# Usage (build context = THIS fork's root, with COPY paths relative to it;
# --platform must match the host arch):
#   docker buildx build --builder multiarch --platform linux/amd64 \
#     -f python/wheel-builder/Dockerfile -o type=local,dest=wheels .
# Or use the wrapper: ./python/build-wheels.sh
#
# BASE_IMAGE defaults to the pypa manylinux_2_34 x86_64 image (glibc 2.34
# baseline + patchelf/auditwheel toolchain); on an arm64 host override with
# quay.io/pypa/manylinux_2_34_aarch64.
ARG BASE_IMAGE=quay.io/pypa/manylinux_2_34_x86_64
FROM --platform=$BUILDPLATFORM ${BASE_IMAGE} AS build

# CN-fast mirrors first (same family as the sandlock-dev container), plus the
# cp314 interpreter from the manylinux image on PATH so `python` = 3.14.
ENV RUSTUP_DIST_SERVER=https://rsproxy.cn \
    RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PATH="/root/.cargo/bin:/opt/python/cp314-cp314/bin:/usr/local/bin:${PATH}"

# manylinux images already ship curl/gcc/patchelf. rustup via rsproxy.
RUN curl --proto '=https' --tlsv1.2 -sSf https://rsproxy.cn/rustup-init.sh | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path \
    && rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
    && rustup --version >/dev/null

# pip toolchain into the cp314 interpreter: setuptools-rust + wheel + ziglang
# (bundles the host zig binary; symlink it onto PATH) + auditwheel for the
# manylinux repack/verify step.
RUN python -m pip install --no-cache-dir setuptools-rust wheel ziglang auditwheel \
    && ln -sf "$(python -c 'import ziglang, os; print(os.path.join(os.path.dirname(ziglang.__file__), "zig"))')" /usr/local/bin/zig \
    && zig version

# rsproxy crates mirror + per-target zig linkers (builder assets travel with
# the fork under python/wheel-builder/).
COPY python/wheel-builder/cargo-config.toml /root/.cargo/config.toml

COPY python/wheel-builder/zigcc /usr/local/bin/zigcc
RUN chmod +x /usr/local/bin/zigcc

# Selective copy: only what setuptools-rust needs. The fork tree carries a
# `target -> /src/target-linux` symlink and GB-scale tmp/target-linux
# artifacts; copying them would break cargo's target dir creation and bloat
# the build (python/build-wheels.sh therefore stages a lean context that
# mirrors the fork root with exactly these inputs).
COPY Cargo.toml Cargo.lock /src/sandlock-src/
COPY crates /src/sandlock-src/crates
COPY python /src/sandlock-src/python
WORKDIR /src/sandlock-src/python

# Build each arch with zig (intermediate linux_* wheels). ZIG_TARGET pins
# glibc 2.34 so the binaries run on the manylinux_2_34 image itself (glibc
# 2.34) and pass the policy check. The x86_64 wheel is auditwheel-repaired
# here; auditwheel refuses to repair a foreign-arch wheel, so the aarch64
# repack happens in the arm64 stage below. F2b.5: each arch's
# sandlock-supervise release binary is cross-built the same way (same zig
# target/linker config) and staged under /tmp/supervise/<arch>/ — the export
# stage lands it next to the wheels and python/build-wheels.sh injects the
# same bytes into the matching wheel (sandlock/bin/sandlock-supervise).
RUN set -eu; \
    for spec in "x86_64-unknown-linux-gnu x86_64-linux-gnu.2.34 linux_x86_64 x86_64" \
                "aarch64-unknown-linux-gnu aarch64-linux-gnu.2.34 linux_aarch64 aarch64"; do \
        set -- $spec; \
        triple=$1; plat=$2; whlplat=$3; archdir=$4; \
        echo "==> cross-building sandlock-supervise ($triple)"; \
        mkdir -p src/sandlock/bin /tmp/supervise/$archdir; \
        CARGO_BUILD_TARGET="$triple" ZIG_TARGET="$plat" \
            CC_x86_64_unknown_linux_gnu="zigcc" \
            CC_aarch64_unknown_linux_gnu="zigcc" \
            cargo build --release --target "$triple" -p sandlock-supervise; \
        # cargo puts the artifact in the workspace root's target/ (this WORKDIR
        # is python/, one level below Cargo.toml).
        install -m755 "../target/$triple/release/sandlock-supervise" \
            src/sandlock/bin/sandlock-supervise; \
        cp -p src/sandlock/bin/sandlock-supervise \
            "/tmp/supervise/$archdir/sandlock-supervise"; \
        rm -rf build src/sandlock.egg-info; \
        echo "==> cross-building $triple"; \
        CARGO_BUILD_TARGET="$triple" ZIG_TARGET="$plat" \
            CC_x86_64_unknown_linux_gnu="zigcc" \
            CC_aarch64_unknown_linux_gnu="zigcc" \
            python setup.py bdist_wheel --plat-name "$whlplat" -d "/tmp/linux/$plat"; \
    done
RUN echo "==> auditwheel-repairing (x86_64)" \
    && auditwheel repair --plat manylinux_2_34_x86_64 -w /out/x86_64 /tmp/linux/x86_64-linux-gnu.2.34/*.whl

# The aarch64 manylinux repack runs as aarch64 (QEMU on x86 hosts): auditwheel
# only inspects ELF symbol versions and repacks the zip, so this stage is a
# few seconds — all compilation happened cross-compiled in the build stage.
FROM --platform=linux/arm64 python:3.14-slim AS repair-arm
RUN sed -i \
        's|http://deb.debian.org/debian|https://mirrors.tuna.tsinghua.edu.cn/debian|g; s|http://security.debian.org/debian-security|https://mirrors.tuna.tsinghua.edu.cn/debian-security|g' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends patchelf \
    && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple auditwheel
COPY --from=build /tmp/linux/aarch64-linux-gnu.2.34/*.whl /in/
RUN auditwheel repair --plat manylinux_2_34_aarch64 -w /out /in/*.whl

# Export stage: `-o type=local,dest=wheels` copies the wheels straight into
# the target directory (rootfs paths map 1:1 onto dest).
FROM scratch AS export
COPY --from=build /out/x86_64/*.whl /
COPY --from=repair-arm /out/*.whl /
COPY --from=build /tmp/supervise/x86_64/ /supervise/x86_64/
COPY --from=build /tmp/supervise/aarch64/ /supervise/aarch64/
