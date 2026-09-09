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

import pytest

from sandlock.exceptions import SandlockError
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


# ---------------------------------------------------------------- F17: transport 1
#
# The fd handoff is the transport a pooled-slot deployment should use: the
# launcher's `socketpair()` end *is* the credential, so no channel token has to
# travel through the slot's argv (world-readable `/proc/<pid>/cmdline`) or a
# shared registry path (108-byte `sun_path`, 1777 directory).


def _write_slot_documents(tmp_path: Path, work: Path) -> tuple[Path, Path]:
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
    return policy_path, program_path


def _spawn_fd_slot(
    tmp_path: Path, token: str | None = None, program_argv: list[str] | None = None
):
    """Start `sandlock-supervise --control-fd N --serve` over a socketpair.

    Returns ``(process, worker_end)``: the worker end stays open here (that is
    the client), and the slot holds the other one, handed over as an inherited
    descriptor the same way ``mediation_2uid`` does with ``pre_exec``.
    """
    import socket

    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    policy_path, program_path = _write_slot_documents(tmp_path, work)
    if program_argv is not None:
        program_path.write_text(
            json.dumps({"argv": program_argv}), encoding="utf-8"
        )
    worker, server = socket.socketpair()
    argv = [
        str(SUPERVISE_BIN),
        "--policy",
        str(policy_path),
        "--uid",
        str(os.geteuid()),
        "--control-fd",
        str(server.fileno()),
        "--serve",
        "--program",
        str(program_path),
    ]
    if token is not None:
        argv[argv.index("--serve") + 1 : argv.index("--serve") + 1] = [
            "--token",
            token,
        ]
    proc = subprocess.Popen(
        argv,
        pass_fds=(server.fileno(),),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    server.close()
    return proc, worker


def _exec_and_drain(channel, code: str) -> tuple[dict, bytes, bytes]:
    r_in, w_in = os.pipe()
    r_out, w_out = os.pipe()
    r_err, w_err = os.pipe()
    started = channel.request(
        "exec", {"argv": ["python3", "-B", "-c", code]}, fds=[r_in, w_out, w_err]
    )
    # The slot holds dups of the child ends now; keeping our copies open would
    # mean our own pipes never report EOF.
    for fd in (r_in, w_out, w_err, w_in):
        os.close(fd)
    status = channel.request("wait_child", {"child_id": started["child_id"]})
    out = _read_until_eof(r_out, time.monotonic() + 30)
    err = _read_until_eof(r_err, time.monotonic() + 5)
    os.close(r_out)
    os.close(r_err)
    return status, out, err


def test_fd_handoff_channel_runs_verbs_with_no_path_no_token(tmp_path: Path) -> None:
    """The SL-10 closure: the descriptor alone authenticates the worker."""
    assert SUPERVISE_BIN.exists(), f"missing {SUPERVISE_BIN}"
    proc, worker = _spawn_fd_slot(tmp_path)
    try:
        channel = SuperviseChannel(fd=worker.fileno())
        stats = channel.request("stats")
        assert stats["instance_state"] == "Live", stats
        assert stats["children_live"] == 1, stats  # the parking main
        assert channel.is_handed_over is True

        status, out, err = _exec_and_drain(
            channel, "import sys; sys.stdout.write('fd-exec-ok\\n')"
        )
        assert status.get("code") == 0, status
        assert out == b"fd-exec-ok\n", out
        assert err == b"", err

        # Nothing secret travelled through argv, and no registry path exists.
        cmdline = Path(f"/proc/{proc.pid}/cmdline")
        if cmdline.exists():
            argv_text = cmdline.read_bytes().replace(b"\0", b" ").decode(errors="replace")
            assert "--token" not in argv_text, argv_text
            assert "--serve-path" not in argv_text, argv_text

        channel.request("shutdown")
        channel.close()
        assert proc.wait(timeout=30) == 0
    finally:
        worker.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_control_fd_does_not_leak_into_the_confined_tree(tmp_path: Path) -> None:
    """Invariant: the confined `sandlock-init` must not hold the supervisor's
    control endpoint.

    Why it matters: a workload-visible copy of that socket could read the
    frames addressed to the worker (including the SCM_RIGHTS stdio ends) and
    would pin the connection open past a dead worker -- the SL-4 class of
    inherited-control-fd bugs. Supervise now re-sets `FD_CLOEXEC` on the
    handed-over descriptor before launching (serve.rs), so the property holds
    regardless of how the launcher cleared it. Measured 2026-09-09: the fd
    table was already clean before that change (core hands `sandlock-init` an
    explicit fd set), so this test is a *guard*, not a bug reproduction; it
    pins the property so neither side can regress into the leak silently.

    Both ends of a `socketpair()` share one socket inode, which is what makes
    the check exact.
    """
    proc, worker = _spawn_fd_slot(tmp_path)
    inode = os.fstat(worker.fileno()).st_ino
    try:
        with SuperviseChannel(fd=worker.fileno()) as channel:
            stats = channel.request("stats")
            assert stats["launched"] is True, stats
            init_pid = stats["pid"]
            leaked = []
            fd_dir = Path(f"/proc/{init_pid}/fd")
            for entry in fd_dir.iterdir():
                try:
                    target = os.readlink(fd_dir / entry.name)
                except OSError:
                    continue
                if target == f"socket:[{inode}]":
                    leaked.append(entry.name)
            assert leaked == [], (
                f"the confined init (pid {init_pid}) inherited the control "
                f"socket on fd(s) {leaked}"
            )
            # The instance control dir must still be functional: the leak fix
            # must not cost the session its own init channel.
            assert channel.request("stats")["instance_state"] == "Live"
    finally:
        worker.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_fd_handoff_token_belt_refuses_a_mismatch(tmp_path: Path) -> None:
    """A token is optional on this transport, but when the slot was given one
    the belt still has to hold: a client that presents a different token is
    refused rather than admitted because it happens to own the descriptor."""
    proc, worker = _spawn_fd_slot(tmp_path, token="belt-token")
    try:
        with SuperviseChannel(fd=worker.fileno(), token="not-the-belt-token") as channel:
            with pytest.raises(Exception) as refused:
                channel.request("stats")
            assert "valid channel token" in str(refused.value), str(refused.value)
    finally:
        worker.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_wait_child_can_park_past_the_default_deadline(tmp_path: Path) -> None:
    """One stream carries instant verbs and a `wait_child` that outlives the
    2-second default: with the deadline lifted the status still comes back."""
    # M0 keeps the generation alive (its exit would collapse the container);
    # the *child* below is what outlives the 2-second default deadline.
    proc, worker = _spawn_fd_slot(tmp_path)
    try:
        with SuperviseChannel(fd=worker.fileno()) as channel:
            channel.set_timeout(0)  # block until the slot answers
            status, out, err = _exec_and_drain(
                channel, "import time; time.sleep(3); print('slow-ok')"
            )
            assert status.get("code") == 0, status
            assert out == b"slow-ok\n", out
    finally:
        worker.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_failed_verb_retires_the_persistent_session(tmp_path: Path) -> None:
    """A half-finished frame must never be answered by the *next* request: any
    transport failure closes the session, and SL-9 guarantees the caller sees
    `SandlockError` (with text) rather than an unclassifiable Python error."""
    proc, worker = _spawn_fd_slot(tmp_path)
    try:
        channel = SuperviseChannel(fd=worker.fileno(), timeout_ms=300)
        assert channel.request("stats")["instance_state"] == "Live"
        proc.kill()
        proc.wait(timeout=30)
        with pytest.raises(SandlockError) as first:
            channel.request("stats")
        assert str(first.value), "the transport error must carry a message"
        with pytest.raises(SandlockError) as second:
            channel.request("stats")
        assert "frame alignment" in str(second.value), str(second.value)
    finally:
        worker.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_check_control_fd_names_a_bad_descriptor(tmp_path: Path) -> None:
    """The handoff is pre-flightable: a pipe is not a control channel."""
    import socket

    from sandlock.supervise import check_control_fd

    r, w = os.pipe()
    try:
        reason = check_control_fd(r)
        assert reason is not None and "not a socket" in reason, reason
    finally:
        os.close(r)
        os.close(w)
    a, b = socket.socketpair()
    try:
        assert check_control_fd(a.fileno()) is None
    finally:
        a.close()
        b.close()
