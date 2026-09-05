# SPDX-License-Identifier: Apache-2.0
"""F3.3 Python surface: `SandboxInstance.exec(...) -> ExecProcess` (self-owned
child handles of an exec-capable session)."""

from __future__ import annotations

import os
import time

import pytest

from sandlock import ExecProcess, ExecStdio, Sandbox, SandboxInstance


_BIN_READABLE = [
    p
    for p in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"]
    if os.path.exists(p)
]


def _policy():
    return Sandbox(fs_readable=_BIN_READABLE)


def test_exec_returns_self_owned_process():
    """Two exec children on one instance each own their process handle and
    keep fully independent stdio — the self-owned (non-borrowing) shape."""
    with SandboxInstance(_policy()) as inst:
        first = inst.exec(["sh", "-c", "printf alpha"])
        second = inst.exec(["sh", "-c", "printf beta"])

        assert isinstance(first, ExecProcess)
        assert isinstance(second, ExecProcess)
        assert first.pid is not None and second.pid is not None
        assert first.pid != second.pid, "each exec gets its own child"
        assert first.stdout is not None and first.stderr is not None
        assert first.stdin is not None

        assert first.stdout.read() == b"alpha"
        assert second.stdout.read() == b"beta"

        r1 = first.wait()
        r2 = second.wait()
        assert r1.exit_code == 0
        assert r2.exit_code == 0
        assert r1.success and r2.success

        # wait is idempotent and cached.
        assert first.wait() is r1
        assert second.wait() is r2


def test_exec_after_close_returns_same_error():
    """After the instance is closed every exec raises the same unified error
    (the F5.4 S5 closed-instance code surfaced in Python), and close() is
    idempotent."""
    inst = SandboxInstance(_policy())
    inst.close()
    inst.close()  # idempotent

    with pytest.raises(RuntimeError) as e1:
        inst.exec(["true"])
    with pytest.raises(RuntimeError) as e2:
        inst.exec(["true"])
    assert str(e1.value) == str(e2.value)
    assert "closed" in str(e1.value)


def test_exec_process_context_manager_reaps_on_error():
    """`with inst.exec(...)` kills and reaps a child that was not waited on,
    like the one-shot Process context manager."""
    inst = SandboxInstance(_policy())
    with pytest.raises(RuntimeError):
        with inst.exec(["sleep", "30"]) as proc:
            assert proc.pid is not None
            raise RuntimeError("boom")
    # The context manager's kill+wait reaped it: the instance can still exec.
    with inst.exec(["sh", "-c", "exit 0"]) as proc2:
        result = proc2.wait()
    assert result.exit_code == 0
    inst.close()


def test_exec_pty_returns_master_and_resize():
    """ExecStdio.PTY returns a pty master file object and resize works."""
    with SandboxInstance(_policy()) as inst:
        with inst.exec(["sh", "-c", "exit 0"], stdio=ExecStdio.PTY) as proc:
            assert proc.pty is not None
            proc.resize(40, 120)
            result = proc.wait()
        assert result.exit_code == 0


def test_dropped_exec_process_is_reaped_on_del():
    """Drop contract pin: an ExecProcess dropped without wait()/context is
    killed and reaped by __del__ immediately (CPython refcounting), mirroring
    the one-shot Process — a discarded handle never leaves a running child."""
    import gc
    import warnings

    inst = SandboxInstance(_policy())
    proc = inst.exec(["sleep", "30"])
    pid = proc.pid
    assert pid is not None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        del proc
        gc.collect()

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        raise AssertionError(f"dropped ExecProcess child {pid} was not reaped")

    # The instance itself is still usable for another exec.
    with inst.exec(["sh", "-c", "exit 0"]) as proc2:
        result = proc2.wait()
    assert result.exit_code == 0
    inst.close()
