# SPDX-License-Identifier: Apache-2.0
"""F4 (M2) Python surface: per-exec parameters, S9 subset rejection,
update_network staleness and per-exec bind ports on `SandboxInstance.exec`."""

from __future__ import annotations

import os
import socket
import tempfile
import threading
import time

import pytest

from sandlock import Sandbox, SandboxInstance


_BIN_READABLE = [
    p
    for p in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"]
    if os.path.exists(p)
]


def _policy(**kw):
    base = dict(fs_readable=_BIN_READABLE, fs_writable=["/tmp"])
    base.update(kw)
    return Sandbox(**base)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def test_per_exec_cwd_and_env_apply():
    """cwd/env/clean_env are applied per exec before execve."""
    work = tempfile.mkdtemp(prefix="sandlock-f4-py-cwd-")
    with SandboxInstance(_policy(cwd="/tmp")) as inst:
        proc = inst.exec(
            ["sh", "-c", "/bin/pwd; printf '%s' \"$F4_MARKER\""],
            cwd=work,
            env={"F4_MARKER": "alpha"},
        )
        result = proc.wait()
        assert result.exit_code == 0, result
        out = proc.stdout.read().decode()
        pwd_line, marker = out.split("\n", 1)
        assert pwd_line == work, f"per-exec cwd must apply: {out!r}"
        assert marker == "alpha", f"per-exec env must apply: {out!r}"
        proc.stdout.close()

        # No params: session cwd (/tmp), session env (no F4_MARKER).
        proc = inst.exec(["sh", "-c", "/bin/pwd"])
        assert proc.wait().exit_code == 0
        assert proc.stdout.read().decode().strip() == "/tmp"
        proc.stdout.close()

        # clean_env per exec: /usr/bin/env sees only the requested pair.
        proc = inst.exec(
            ["/usr/bin/env"],
            clean_env=True,
            env={"F4_ONLY": "1"},
        )
        assert proc.wait().exit_code == 0, "clean_env exec must succeed"
        assert proc.stdout.read() == b"F4_ONLY=1\n"
        proc.stdout.close()


def test_wider_policy_is_rejected():
    """S9: an exec wider than the instance ceiling raises PermissionError
    (EPERM-class) and never widens the instance."""
    allowed_port = _free_port()
    denied = tempfile.mkdtemp(prefix="sandlock-f4-py-denied-")
    policy = _policy(net_allow_bind=[allowed_port], fs_denied=[denied])
    with SandboxInstance(policy) as inst:
        with pytest.raises(PermissionError) as e:
            inst.exec(["true"], extra_writable=["/etc"])
        msg = str(e.value)
        assert "ceiling" in msg and "EPERM" in msg, msg

        with pytest.raises(PermissionError):
            inst.exec(["true"], cwd="/root")

        other_port = _free_port()
        while other_port == allowed_port:
            other_port = _free_port()
        with pytest.raises(PermissionError):
            inst.exec(["true"], bind_ports=[other_port])

        with pytest.raises(PermissionError):
            inst.exec(["true"], extra_writable=[denied])

        # In-ceiling requests still work.
        proc = inst.exec(["true"], bind_ports=[allowed_port])
        assert proc.wait().exit_code == 0


def _sink_listener(ip: str):
    """Accept one TCP connection per client and count them."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, 0))
    port = s.getsockname()[1]
    s.listen(8)
    s.settimeout(30)
    seen = []

    def run():
        try:
            while True:
                conn, _ = s.accept()
                seen.append(True)
                conn.close()
        except socket.timeout:
            pass
        finally:
            s.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port, seen


def test_update_network_applies_to_new_exec_only_and_reports_staleness():
    """update_network binds to new execs only; running children keep their
    exec-time policy and are reported stale; siblings cannot bleed."""
    port_lo, seen_lo = _sink_listener("127.0.0.1")
    port_hi, seen_hi = _sink_listener("127.0.0.2")
    work = tempfile.mkdtemp(prefix="sandlock-f4-py-net-")

    with SandboxInstance(_policy(cwd="/tmp", net_allow=["*"])) as inst:
        a_go1 = os.path.join(work, "a-go1")
        a_go2 = os.path.join(work, "a-go2")
        a_out = os.path.join(work, "a-out")
        b_out = os.path.join(work, "b-out")
        os.mkdir(a_out)
        os.mkdir(b_out)

        def probe(ip, port, out):
            return (
                "import socket\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.settimeout(3)\n"
                "try:\n"
                "    s.connect(('{ip}', {port}))\n"
                "    open('{out}', 'w').write('OK')\n"
                "except OSError as e:\n"
                "    open('{out}', 'w').write('ERR%d' % e.errno)\n"
                "finally:\n"
                "    s.close()\n"
            ).format(ip=ip, port=port, out=out)

        a_script = (
            "import os, time\n"
            "def wait(f):\n"
            "    while not os.path.exists(f):\n"
            "        time.sleep(0.05)\n"
            f"wait('{a_go1}')\n"
            + probe("127.0.0.1", port_lo, os.path.join(a_out, "lo"))
            + f"wait('{a_go2}')\n"
            + probe("127.0.0.2", port_hi, os.path.join(a_out, "hi"))
        )
        a = inst.exec(["/usr/bin/python3", "-c", a_script])
        assert a.pid is not None

        stale = inst.update_network(["127.0.0.1"])
        assert a.child_id in stale, f"running pre-update child A must be stale: {stale}"

        b_script = probe("127.0.0.1", port_lo, os.path.join(b_out, "lo")) + probe(
            "127.0.0.2", port_hi, os.path.join(b_out, "hi")
        )
        b = inst.exec(["/usr/bin/python3", "-c", b_script])
        assert b.wait().exit_code == 0
        with open(os.path.join(b_out, "lo")) as f:
            assert f.read() == "OK", "post-update child B reaches its bound IP"
        with open(os.path.join(b_out, "hi")) as f:
            assert f.read() == "ERR111", "post-update child B is denied the wide IP"

        with open(a_go1, "w") as f:
            f.write("go")
        with open(a_go2, "w") as f:
            f.write("go")
        assert a.wait().exit_code == 0
        with open(os.path.join(a_out, "lo")) as f:
            assert f.read() == "OK", "pre-update child A keeps its low grant"
        with open(os.path.join(a_out, "hi")) as f:
            assert f.read() == "OK", "pre-update child A keeps its wide grant"

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if len(seen_lo) == 2 and len(seen_hi) == 1:
                break
            time.sleep(0.05)
        assert len(seen_lo) == 2, f"low listener: A + B, saw {len(seen_lo)}"
        assert len(seen_hi) == 1, f"high listener: A only, saw {len(seen_hi)}"


def test_per_exec_bind_port_reaches_listener():
    """A per-exec bind_ports grant inside the ceiling lets the child bind the
    port and a host client reaches the in-sandbox listener."""
    port = _free_port()
    with SandboxInstance(_policy(cwd="/tmp", net_allow_bind=[port])) as inst:
        script = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            f"s.bind(('127.0.0.1', {port}))\n"
            "s.listen(1)\n"
            "conn, _ = s.accept()\n"
            "conn.sendall(b'PONG')\n"
            "conn.close()\n"
            "s.close()\n"
        )
        proc = inst.exec(
            ["/usr/bin/python3", "-c", script],
            bind_ports=[port],
        )
        assert proc.pid is not None
        deadline = time.monotonic() + 15
        data = b""
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1) as conn:
                    data = conn.recv(4)
                break
            except OSError:
                time.sleep(0.05)
        assert data == b"PONG", "host client must reach the in-sandbox listener"
        assert proc.wait().exit_code == 0
