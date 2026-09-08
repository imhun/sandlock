# SPDX-License-Identifier: Apache-2.0
"""F16: the Python ``SuperviseChannel`` face of the registered-path client.

Drives a real ``sandlock-supervise --serve-path`` slot (same uid, the
single-machine special case) from Python: ``exec`` with SCM_RIGHTS stdio,
``wait_child``, ``stats``, and ``shutdown``.  This is the route-B worker
surface envd (E2B) needs; the cross-uid kernel facts stay in the Rust
root-phase suites (``mediation_2uid`` / ``supervise_root``).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from sandlock.supervise import SuperviseChannel


REPO_ROOT = Path(__file__).resolve().parents[2]
SUPERVISE_BIN = REPO_ROOT / "target" / "debug" / "sandlock-supervise"


def _fnv1a_hex(name: str) -> str:
    h = 0xCBF29CE484222325
    for b in name.encode("utf-8"):
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"


def _read_until_eof(fd: int, deadline: float) -> bytes:
    out = bytearray()
    while time.monotonic() < deadline:
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            time.sleep(0.02)
            continue
        if not chunk:
            return bytes(out)
        out.extend(chunk)
    raise AssertionError(f"timed out reading fd {fd}; got {bytes(out)!r}")


def _wait_for_socket(path: Path, proc: subprocess.Popen, deadline: float) -> None:
    while time.monotonic() < deadline:
        if path.exists():
            return
        if proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else b""
            raise AssertionError(
                f"supervise exited (rc={proc.returncode}) before binding {path}: {err!r}"
            )
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for registered slot socket {path}")


def test_supervise_channel_exec_and_shutdown_same_uid(tmp_path: Path) -> None:
    assert SUPERVISE_BIN.exists(), f"missing {SUPERVISE_BIN} (build the supervise crate first)"

    base = tmp_path / "ctl"
    base.mkdir(parents=True, exist_ok=True)
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)

    policy = {
        "fs_readable": [
            "/usr",
            "/usr/local",
            "/lib",
            "/bin",
            "/etc",
            "/proc",
            "/dev",
            "/tmp",
        ],
        "fs_writable": [str(work)],
        "env": {"PATH": "/usr/local/bin:/usr/bin:/bin"},
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    program_path = tmp_path / "program.json"
    program_path.write_text(
        json.dumps({"argv": ["python3", "-B", "-c", "import time; time.sleep(300)"]}),
        encoding="utf-8",
    )

    name = f"py-client-{os.getpid()}"
    token = "py-client-token"
    sock_path = Path(f"{base}-registry/{_fnv1a_hex(name)}.d/control.sock")
    env = dict(os.environ)
    env["SANDBOX_CTL_ROOT"] = str(base)
    proc = subprocess.Popen(
        [
            str(SUPERVISE_BIN),
            "--policy",
            str(policy_path),
            "--uid",
            str(os.geteuid()),
            "--serve-path",
            name,
            "--token",
            token,
            "--program",
            str(program_path),
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_socket(sock_path, proc, time.monotonic() + 30)

        with SuperviseChannel(str(sock_path), token) as channel:
            stats = channel.request("stats")
            assert stats["instance_state"] == "Live", stats
            assert stats["children_live"] == 1, stats  # the parking main

            r_in, w_in = os.pipe()
            r_out, w_out = os.pipe()
            r_err, w_err = os.pipe()
            try:
                started = channel.request(
                    "exec",
                    {"argv": ["python3", "-B", "-c", "import sys; sys.stdout.write('exec-ok\\n')"]},
                    fds=[r_in, w_out, w_err],
                )
            finally:
                # The server dup'd the three handed-over ends and nobody will
                # write stdin: drop those copies plus our stdin writer, and
                # keep the two read ends open until the child is reaped.
                for fd in (w_in, r_in, w_out, w_err):
                    os.close(fd)
            child_id = started["child_id"]
            assert isinstance(child_id, int), started

            status = channel.request("wait_child", {"child_id": child_id})
            assert status.get("code") == 0, status

            # The exec child's stdout is our pipe: exact bytes or nothing.
            out = _read_until_eof(r_out, time.monotonic() + 30)
            err = _read_until_eof(r_err, time.monotonic() + 5)
            assert out == b"exec-ok\n", out
            assert err == b"", err
            os.close(r_out)
            os.close(r_err)

            stats = channel.request("stats")
            assert stats["children_live"] == 1, stats  # only the parking main

            channel.request("shutdown")

        rc = proc.wait(timeout=30)
        assert rc == 0, f"supervise must exit 0 after shutdown; rc={rc}"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
