# SPDX-License-Identifier: Apache-2.0
"""Shared test fixtures for Sandlock tests."""

from __future__ import annotations

import faulthandler
import os
import shutil
import tempfile
import time
from pathlib import Path

import pytest

_FORK_ROOT = Path(__file__).resolve().parents[2]

#: Per-test deadline. No test may block forever: on 2026-10-05 a restore test
#: wedged (the sandbox's restore handshake never completed) and the suite sat
#: there until it was killed by hand. A SIGALRM-style watchdog cannot help --
#: the hang is inside a native call, so the interpreter never gets back to run
#: a Python-level handler. `faulthandler`'s watcher runs on its own thread, so it
#: fires anyway: it dumps every thread's stack into the log and exits the
#: process, which turns "hung forever" into a named, diagnosable failure.
_TEST_TIMEOUT_S = int(os.environ.get("SANLOCK_TEST_TIMEOUT_S", "300"))

#: Where the watchdog's stack dump goes. pytest's default capture mode redirects
#: fd 2 per test, so a dump written to stderr is swallowed together with the
#: captured output when the watchdog `_exit()`s -- and the stack is the whole
#: point. `SANLOCK_TEST_TIMEOUT_LOG` is the capture-proof channel (the gate sets
#: it and prints the file when a suite fails); without it we fall back to a dup
#: of fd 2 taken at import time, which is right whenever capture is off.
_TIMEOUT_LOG = os.environ.get("SANLOCK_TEST_TIMEOUT_LOG")
if _TIMEOUT_LOG:
    _DUMP_TARGET = open(_TIMEOUT_LOG, "a", buffering=1)
else:
    _DUMP_TARGET = os.fdopen(os.dup(2), "w", buffering=1)


@pytest.fixture(autouse=True)
def _per_test_deadline():
    if _TEST_TIMEOUT_S > 0:
        faulthandler.dump_traceback_later(
            _TEST_TIMEOUT_S, exit=True, file=_DUMP_TARGET
        )
    try:
        yield
    finally:
        if _TEST_TIMEOUT_S > 0:
            faulthandler.cancel_dump_traceback_later()


@pytest.fixture
def tmp_dir():
    """Create a temporary directory for test use."""
    d = tempfile.mkdtemp(prefix="sandlock-test-")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def _ffi_is_newer_than_its_sources():
    """Refuse to test a stale engine.

    The SDK loads whichever `libsandlock_ffi.so` is on disk, and nothing
    rebuilds it for a bare `pytest` run. On 2026-10-05 that turned a *stale*
    library into what looked like a deterministic product failure
    (`test_restore_resumes_counter`: "checkpoint restore failed", reproduced
    four times); rebuilding with `cargo build -p sandlock-ffi` moved the suite
    from 464 passed / 1 failed to 465 passed / 0 failed with no source change.
    `scripts/test-all.sh` runs the ffi suite before this one, so the gate is
    unaffected -- this fires when someone runs pytest straight against a build
    that predates the tree.
    """
    from sandlock._sdk import _lib

    lib = Path(_lib._name).resolve()
    sources = list(_FORK_ROOT.glob("crates/**/*.rs"))
    sources += list(_FORK_ROOT.glob("crates/**/Cargo.toml"))
    sources += [_FORK_ROOT / "Cargo.toml", _FORK_ROOT / "Cargo.lock"]
    newest = max((p.stat().st_mtime for p in sources if p.exists()), default=0.0)
    if lib.stat().st_mtime < newest:
        pytest.fail(
            f"{lib} is older than the newest Rust source "
            f"({time.ctime(lib.stat().st_mtime)} vs {time.ctime(newest)}): "
            "run `cargo build -p sandlock-ffi` first, otherwise this suite tests "
            "the previous engine and its failures are not about today's tree.",
            pytrace=False,
        )
