#!/bin/sh
# Run every sandlock suite in one shot and fail on ANY drift from the recorded
# baseline -- including a suite that quietly runs fewer tests than last time.
#
# Usage: scripts/test-all.sh            (non-root suites; logs land in ./tmp/)
#        scripts/test-all.sh --wheels   (also cross-build + verify wheel symbols)
#        scripts/test-all.sh --oci-root (root-mode oci suite only; must run as root)
#        scripts/test-all.sh --supervise-root (root-mode foreign-uid supervise
#              suite only; must run as root)
#        scripts/test-all.sh --mediation-2uid (root-mode F6.1 B档 two-uid +
#              C档 suite only; must run as root)
#
# Path discipline (2026-09-08, measured): run the gate from a checkout mounted at
# a SHORT path (/src). A registered-path fixture builds its registry socket under
# `<ctl_root>-registry/<hash>.d/control.sock`, and the 108-byte sun_path limit is
# spent on whatever prefix the fixture's root carries. The non-root `supervise.rs`
# suite used to root that under `<repo>/tmp` (2026-09-08: nested worktrees like
# /src/tmp/wt-fixN/ timed out on `test_supervise_path_serve_...`); since
# 2026-09-21 its override is `/tmp/sandlock-ctl-test-<pid>` (69-byte socket path,
# mirroring the `/tmp/sandlock-ctl-<uid>` production default) and is
# path-independent. The root-mode `supervise_root.rs` suite still derives its
# ctl root from `CARGO_MANIFEST_DIR` (canonicalized, which is why the checkout
# path there costs ~30 bytes fewer), so a long checkout or a nested worktree can
# still make that one time out — a false red that looks exactly like a real
# supervise regression. Always confirm against the repo root before believing
# that failure.
#
# Canonical full-gate procedure (sandlock-dev:latest, repo mounted at /src):
#   chmod -R a+rwX tmp
#   docker run --privileged --rm -v "$PWD":/src -w /src \
#     sandlock-dev:latest sh scripts/test-all.sh
#   docker run --privileged --rm -v "$PWD":/src -w /src --entrypoint bash \
#     sandlock-dev:latest -c 'sh scripts/test-all.sh --oci-root'
#   docker run --privileged --rm -v "$PWD":/src -w /src --entrypoint bash \
#     sandlock-dev:latest -c 'sh scripts/test-all.sh --supervise-root'
#   docker run --privileged --rm -v "$PWD":/src -w /src --entrypoint bash \
#     sandlock-dev:latest -c 'sh scripts/test-all.sh --mediation-2uid'
#
# FUP-09 gate-evidence discipline: when a suite flakes (external-egress
# `cli learn`, control-dir timing), NEVER rerun over the same log. Keep the
# first red log as <label>-r1.log and the rerun green log as <label>-final.log
# (both under tmp/), and say in the report what the red run showed and why the
# final run is the evidence. The default (no-arg) mode is a non-root suite and
# refuses to run as root; root-only phases are selected by their own flags.
#
# The oci suite is root-mode by design: sandlock-oci e2e supervises OCI-default
# root containers, and S1.2 fail-closes RunAs(0,0) for non-root supervisors
# (a tested feature, not a regression). The supervise_root suite is
# root-mode by design too: constructing a genuine foreign-uid peer pair
# (supervise as uid X = 65533, worker as 65534) needs CAP_SETUID, which the
# root container phase provides via setpriv. The default (entrypoint drops
# to uid 65534) run covers every other suite. The mediation_2uid suite is
# root-mode the same way: two genuine distinct-uid supervise mediators (B档)
# and the root in-process C档 refusal/leak controls need CAP_SETUID + the
# privileged userns map, which the root container phase provides via setpriv.
set -eu
cd "$(dirname "$0")/.."
mkdir -p tmp
BASELINE="docs/test-baseline.md"

# The canonical image defaults CARGO_HOME to /opt/cargo, whose cache misses
# crates (e.g. bincode). The repo-local rsproxy mirror cache is complete, so
# pin CARGO_HOME here to make the --offline suites resolve.
export CARGO_HOME="$PWD/tmp/cargo-home"

# The canonical image runs as uid 65534 with HOME=/root (root-owned, 0700), so
# tests that create ${HOME}/.config probes fail with EACCES. Fall back to a
# writable repo-local home only when the caller's HOME is unusable.
if [ -z "${HOME:-}" ] || [ ! -d "$HOME" ] || [ ! -w "$HOME" ]; then
    export HOME="$PWD/tmp/home"
    mkdir -p "$HOME"
fi

expect() {  # exact expected pass count for a suite label
    sed -n "s|^$1[[:space:]]*=[[:space:]]*\([0-9]\+\).*|\1|p" "$BASELINE" | head -1
}
# Hard per-suite budgets, in seconds. A suite that overruns is a *hang*, not
# slowness: on 2026-10-05 `core_integ` stopped inside
# `test_instance_exec::test_a_child_restored_into_a_session_keeps_the_session_executable`
# and sat there for ~35 minutes (test binary blocked in `futex_wait`, the
# `restore-stub` child parked in `nanosleep`, the log frozen) -- this script had
# no timeout at all, so the gate could hang forever. The budgets are ~10x the
# measured warm runtimes, which leaves room for a cold target directory on a slow
# host; override every label with `SANLOCK_SUITE_TIMEOUT_S=<seconds>`.
suite_timeout() {
    if [ -n "${SANLOCK_SUITE_TIMEOUT_S:-}" ]; then
        printf '%s' "$SANLOCK_SUITE_TIMEOUT_S"
        return
    fi
    case "$1" in
        core_lib)       printf 1200 ;;  # ~4 s warm, but the lib is built here
        core_integ)     printf 1800 ;;  # ~90 s warm (--test-threads=1)
        ffi)            printf 900 ;;
        cli)            printf 900 ;;
        supervise)      printf 900 ;;
        supervise_cost) printf 2400 ;;  # release build + the cost cases
        cli_build)      printf 2400 ;;  # release workspace build
        python)         printf 900 ;;
        oci)            printf 1200 ;;
        supervise_root) printf 600 ;;
        mediation_2uid) printf 900 ;;
        *)              printf 1200 ;;
    esac
}
rust_count() {  # sum "test result: ok. N passed" across all targets of a suite
    sed -n "s/.*test result: ok\. \([0-9]\+\) passed.*/\1/p" "$1" | awk '{s+=$1} END {print s+0}'
}
py_count() {  # pytest -q summary is the last log line, e.g. "431 passed in 12.3s"
    tail -1 "$1" | awk '{
        for (i = 2; i <= NF; i++)
            if ($i == "passed") { gsub(/[^0-9]/, "", $(i - 1)); print $(i - 1); exit }
    }'
}

run() {  # run <label> <command...>
    label="$1"; shift
    log="tmp/test-all-$label.log"
    rcfile="tmp/test-all-$label.rc"
    printf '==> %s\n' "$label"
    # FUP-09: keep the first red log. Rerunning over the same name would make
    # the discipline (`-r1.log` then `-final.log`) a memory; rotate instead.
    n=1
    while [ -e "tmp/$label-r$n.log" ]; do n=$((n + 1)); done
    if [ -e "$log" ]; then
        mv "$log" "tmp/$label-r$n.log"
        printf '    previous %s log archived as tmp/%s-r%s.log\n' "$label" "$label" "$n"
    fi
    # sandlock's checkpoint/restore reopens a checkpointed child's stdio by
    # path, so a suite whose stdout is a plain file would hand that file to the
    # sandboxed child; the restored process then cannot reopen it (outside the
    # sandbox fs policy) and dies in the restore stub. Tee the suite through an
    # anonymous pipe so the child's stdio reads as pipe:[...] (skipped by the
    # restore fd plan) while the exact bytes still land in the log file. POSIX
    # sh cannot read a pipeline's first command status, so the suite records it
    # in a temp file before the pipe closes.
    budget="$(suite_timeout "$label")"
    rm -f "$rcfile"
    # The python suite's per-test watchdog writes its stack dump here (pytest's
    # fd capture would swallow a dump written to stderr), so clear it and print
    # it on any failure below.
    if [ -n "${SANLOCK_TEST_TIMEOUT_LOG:-}" ]; then
        rm -f "$SANLOCK_TEST_TIMEOUT_LOG"
    fi
    # `|| rc_cmd=$?` is load-bearing: this script runs under `set -e`, and a bare
    # failing command inside the brace group terminated the group *before* the
    # status was written -- the rcfile was always missing, the fallback below
    # reported `1`, and every failure (including a timeout) read as a plain
    # FAILED. Putting the command in a `||` list exempts it from errexit.
    rc_cmd=0
    { timeout --signal=TERM --kill-after=15 "$budget" "$@" 2>&1 || rc_cmd=$?; \
        printf '%s' "$rc_cmd" >"$rcfile"; } | tee "$log" >/dev/null
    rc="$(cat "$rcfile" 2>/dev/null || echo 1)"
    rm -f "$rcfile"
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        printf '%s: suite TIMED OUT after %ss -- treat it as a hang, not slowness (see %s)\n' \
            "$label" "$budget" "$log"
        if [ -n "${SANLOCK_TEST_TIMEOUT_LOG:-}" ] && [ -s "$SANLOCK_TEST_TIMEOUT_LOG" ]; then
            printf '    per-test watchdog dump (%s):\n' "$SANLOCK_TEST_TIMEOUT_LOG"
            tail -60 "$SANLOCK_TEST_TIMEOUT_LOG"
        fi
        tail -40 "$log"
        exit 1
    fi
    if [ "$rc" -ne 0 ]; then
        printf '%s: suite FAILED (see %s)\n' "$label" "$log"
        if [ -n "${SANLOCK_TEST_TIMEOUT_LOG:-}" ] && [ -s "$SANLOCK_TEST_TIMEOUT_LOG" ]; then
            printf '    per-test watchdog dump (%s):\n' "$SANLOCK_TEST_TIMEOUT_LOG"
            tail -60 "$SANLOCK_TEST_TIMEOUT_LOG"
        fi
        tail -40 "$log"; exit 1
    fi
    want="$(expect "$label")"
    if [ -z "$want" ]; then
        printf 'no baseline entry for %s in %s\n' "$label" "$BASELINE"; exit 1
    fi
    case "$label" in
        python) got="$(py_count "$log")" ;;
        *)      got="$(rust_count "$log")" ;;
    esac
    if [ "$want" != "$got" ]; then
        printf '%s: baseline says %s passed, run produced %s\n' "$label" "$want" "$got"
        tail -40 "$log"; exit 1
    fi
    # Cargo prints "0 ignored" on every passing target line, so the gate only
    # fires on nonzero skipped/ignored counts.
    if grep -Eq '[1-9][0-9]* (skipped|ignored)' "$log"; then
        printf '%s: skipped/ignored tests are not allowed -- fix the environment or the test\n' "$label"
        grep -En '[1-9][0-9]* (skipped|ignored)|^test .* ... SKIPPED' "$log" | head -20
        exit 1
    fi
    printf '    %s passed -- matches baseline\n' "$got"
}

mode="${1:-}"
case "$mode" in
    ""|--wheels|--oci-root|--supervise-root|--mediation-2uid) ;;
    *) printf 'usage: %s [--wheels|--oci-root|--supervise-root|--mediation-2uid]\n' "$0" >&2; exit 2 ;;
esac

# FUP-17: the root phases share target-linux with the uid-65534 phase. Cargo's
# incremental artifacts are owned by the uid that produced them, so a root run
# either cannot rewrite them or reads an index the other uid wrote -- a stale-cache
# false red that looks exactly like a code regression. Dropping incremental
# compilation for the root phases costs only our own crates' re-codegen (deps
# still come from the shared cache) and removes that whole class.
case "$mode" in
    --oci-root|--supervise-root|--mediation-2uid) export CARGO_INCREMENTAL=0 ;;
esac

if [ "${SANDBOX_TEST_ALL_ALLOW_ROOT:-0}" != "1" ]; then
    if [ "$mode" = "" ] || [ "$mode" = "--wheels" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            printf '%s\n' \
                'default and --wheels modes are NON-ROOT suites: they must run as' \
                'uid 65534 (the canonical sandlock-dev entrypoint drops to nobody' \
                'after its root prep, or setpriv --reuid 65534 --regid 65534' \
                '--clear-groups sh scripts/test-all.sh). Root phases are selected' \
                'explicitly: --oci-root / --supervise-root / --mediation-2uid.' \
                'Set SANDBOX_TEST_ALL_ALLOW_ROOT=1 to force non-root suites as root.' >&2
            exit 1
        fi
    fi
fi

if [ "$mode" = "--oci-root" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        printf '%s\n' \
            'oci is root-mode (sandlock-oci e2e supervises OCI-default root containers):' \
            'run scripts/test-all.sh --oci-root as root in the same privileged container' >&2
        exit 1
    fi
    run oci cargo test -p sandlock-oci --offline -- --test-threads=1
    exit 0
fi

if [ "$mode" = "--supervise-root" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        printf '%s\n' \
            'supervise_root is root-mode (the foreign-uid acceptance spawns' \
            'supervise as uid 65533 and the worker as uid 65534 via setpriv):' \
            'run scripts/test-all.sh --supervise-root as root in the same' \
            'privileged container' >&2
        exit 1
    fi
    # The test's workload (uid 65533) and worker (65534) write into the
    # repo-mounted tmp; the non-root phase normally chmods it before entry.
    chmod -R a+rwX tmp
    run supervise_root cargo test -p sandlock-supervise --offline --test supervise_root -- --test-threads=1
    exit 0
fi

if [ "$mode" = "--mediation-2uid" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        printf '%s\n' \
            'mediation_2uid is root-mode (the F6.1 B档 two-supervisor pair' \
            'spawns supervise as uid X/Y = 65531/65532 via setpriv, and the' \
            'C档 root in-process refusal/leak controls need the privileged' \
            'userns map): run scripts/test-all.sh --mediation-2uid as root in' \
            'the same privileged container' >&2
        exit 1
    fi
    # The non-root phase wrote test files; keep every uid able to use them.
    chmod -R a+rwX tmp
    # The CLI wiring test inside this suite drives the built sandlock binary.
    if ! cargo build -p sandlock-cli --offline >tmp/test-all-mediation-build.log 2>&1; then
        printf 'mediation_2uid: sandlock CLI build failed (see tmp/test-all-mediation-build.log)\n'
        tail -40 tmp/test-all-mediation-build.log
        exit 1
    fi
    run mediation_2uid cargo test -p sandlock-supervise --offline --test mediation_2uid -- --test-threads=1
    exit 0
fi

run core_lib   cargo test -p sandlock-core --offline --lib
run core_integ cargo test -p sandlock-core --offline --test integration -- --test-threads=1
run ffi        cargo test -p sandlock-ffi --offline
run cli        cargo test -p sandlock-cli --offline
# The supervise crate's root-mode target (tests/supervise_root.rs) must NOT
# run in the non-root phase: it constructs genuine cross-uid kernel peers via
# setpriv and fails loudly without root.  Run the lib units + the non-root
# integration target here; --supervise-root covers the rest.
run supervise  cargo test -p sandlock-supervise --offline --lib --test supervise
# F2b.4 cost target: the three supervise cost tests must run against the
# RELEASE binary (CARGO_BIN_EXE_sandlock-supervise is the release build under
# --release) and measure PSS/latency with no parallel-test noise, hence the
# separate label and --test-threads=1.
run supervise_cost cargo test -p sandlock-supervise --offline --release --test supervise_cost -- --test-threads=1
# Workspace release build gate (the F0.4 build-break class: a CLI face that
# only `cargo test -p X` misses). No test binaries, so baseline count is 0.
run cli_build  cargo build --release --workspace --locked

# Python needs the FFI debug lib built by the ffi suite above. The image's
# site-packages are root-owned, so import via PYTHONPATH + LD_LIBRARY_PATH
# (F0.3-proven path) instead of `pip install -e .`.
export PYTHONPATH="$PWD/python/src${PYTHONPATH:+:$PYTHONPATH}"
export LD_LIBRARY_PATH="$PWD/target-linux/debug${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
SANLOCK_TEST_TIMEOUT_LOG="$PWD/tmp/pytest-timeout.log"
export SANLOCK_TEST_TIMEOUT_LOG
run python python3 -m pytest -p no:cacheprovider python/tests -q

printf '%s\n' \
    'oci is root-mode: run `sh scripts/test-all.sh --oci-root` as root to verify the oci baseline;' \
    'supervise_root is root-mode: run `sh scripts/test-all.sh --supervise-root` as root to verify' \
    'the foreign-uid acceptance; mediation_2uid is root-mode: run `sh scripts/test-all.sh' \
    '--mediation-2uid` as root to verify the F6.1 two-uid / C档 acceptance'

if [ "$mode" = "--wheels" ]; then
    ./python/build-wheels.sh && ./python/verify-wheel.sh
fi
