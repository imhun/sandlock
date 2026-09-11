# SPDX-License-Identifier: Apache-2.0
"""SL-12 (Task B1): create/launch failures must carry the core's reason.

The FFI boundary used to drop the Rust-side error text, so the SDK face saw
only ``RuntimeError("sandlock_create failed")`` /
``RuntimeError("sandlock_instance_launch failed")`` — the refusal's own words
(the remedy, and the uid it names) never reached the caller.  These tests pin
the *whole* Python exception text to the core error's ``Display`` string
(``SandlockError`` renders as
``process error: child process error: <reason>``), so the reason cannot
silently degrade back into a generic message.

The refusal under test is picked by privilege, so the file runs in both
phases of the gate with no soft skip:

* **unprivileged** (the gate's uid 65534 phase): a ``RunAs`` to a uid the
  single-entry user-namespace map cannot cover is refused before fork —
  ``crates/sandlock-core/src/sandbox.rs`` (``userns_remap && !privileged``);
* **root**: the C档 shape (in-process privileged mediator + path mediation +
  non-zero host uid) is refused with the route-B remedy —
  ``crates/sandlock-core/src/sandbox.rs`` (``in-process path mediation
  refused:`` ... ``(route B)``); the E2B worker hits exactly this text when
  an in-process chroot create is attempted on a privileged worker without a
  slot.  Run pytest as root to exercise that branch (``docker run --user
  root`` / the B1 root runner).

Every assertion is whole-string equality against the core text; a substring
or ``match=`` assertion would accept a truncated or reordered reason.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from sandlock import (
    InstanceClosedError,
    InstanceDeadError,
    Sandbox,
    SandboxInstance,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PY_SRC = REPO_ROOT / "python" / "src"


# The sandbox host uid/gid the policies request: far from any real caller and
# from 0, so the refusal is the same wherever the suite runs.  The failure
# fixtures are uid/gid-only; nothing below forks a child.
_TARGET_UID = 4242
_TARGET_GID = 4242


def _core_error_display() -> str:
    """The refusal's ``SandlockError`` ``Display`` text, verbatim.

    Kept in lockstep with the implementation like the Rust-side helpers
    (``crates/sandlock-core/tests/integration/test_uid_isolation.rs``
    ``run_as_refused_msg`` and
    ``crates/sandlock-supervise/tests/mediation_2uid.rs`` ``refusal_msg``).
    """
    if os.geteuid() == 0:
        # C档 (root in-process remap, path mediation).
        return (
            "process error: child process error: "
            "in-process path mediation refused: mediation would run as euid 0 "
            f"while the sandbox's host uid is {_TARGET_UID}; on-behalf files "
            "would be owned by the mediator, not the sandbox (SL-1). Run "
            f"sandlock-supervise as uid {_TARGET_UID} (route B)"
        )
    # Unprivileged RunAs remap: the single-entry map cannot cover this uid.
    return (
        "process error: child process error: "
        f"RunAs({_TARGET_UID}, {_TARGET_GID}) refused: unprivileged supervisor "
        f"(euid={os.getuid()}) cannot map an arbitrary host uid (single-entry "
        "userns map can only cover the caller's own euid); per-sandbox "
        "independent host uids require a privileged supervisor "
        "(root/CAP_SETUID in the parent user namespace) or an equivalent "
        "mechanism"
    )


def _refused_policy() -> Sandbox:
    """A policy whose *spawn* is refused (nothing is forked)."""
    if os.geteuid() == 0:
        # Path mediation is what makes the root in-process remap the C档
        # shape; a deny rule is the cheapest way to switch it on.
        return Sandbox(
            uid=_TARGET_UID,
            gid=_TARGET_GID,
            fs_denied=["/sandlock-sl12-refused"],
        )
    return Sandbox(uid=_TARGET_UID, gid=_TARGET_GID)


def test_create_failure_carries_the_core_reason():
    """``Sandbox.create`` reports *why* the spawn failed, not just that it did."""
    sandbox = _refused_policy()
    expected = f"sandlock_create failed: {_core_error_display()}"
    with pytest.raises(RuntimeError) as excinfo:
        sandbox.create(["true"])
    assert type(excinfo.value) is RuntimeError
    assert str(excinfo.value) == expected


def test_instance_launch_failure_carries_the_core_reason():
    """``SandboxInstance`` launch reports the same core reason verbatim."""
    sandbox = _refused_policy()
    expected = f"sandlock_instance_launch failed: {_core_error_display()}"
    with pytest.raises(RuntimeError) as excinfo:
        SandboxInstance(sandbox)
    assert type(excinfo.value) is RuntimeError
    assert str(excinfo.value) == expected


# ----------------------------------------------------------------
# Fix round 1 (B1 review): the reason-carrying exports are *required*
# ----------------------------------------------------------------
#
# A Python package newer than the `.so` it loads (stale `target/`, partially
# upgraded image, wheel built against an older library) used to die with a bare
# `AttributeError` at `import sandlock`. Launcher-level guards catch broadly
# (E2B's `_sandlock_available()` used `except Exception`), so that read as
# "sandlock is unavailable" and the worker silently lost the sandbox
# confinement. It must be a named RuntimeError instead -- and never a silent
# fall back to the reason-less symbols.


def test_missing_reason_export_is_named_not_attributeerror():
    """The guard names the missing symbol and the remedy."""
    from sandlock import _sdk

    for symbol in (
        _sdk._CREATE_WITH_ERR_EXPORT,
        _sdk._INSTANCE_LAUNCH_WITH_ERR_EXPORT,
    ):
        with pytest.raises(RuntimeError) as excinfo:
            _sdk._require_export(symbol, None)
        assert type(excinfo.value) is RuntimeError
        message = str(excinfo.value)
        assert symbol in message
        assert "LD_LIBRARY_PATH" in message
        assert "cargo build -p sandlock-ffi" in message


_STALE_LIB_PROBE = """
import ctypes
import ctypes.util
import sys

sys.path.insert(0, {py_src!r})

# A real C function pointer to stand in for the symbols an old build *does*
# export: `_sdk` sets `.restype`/`.argtypes` on them (and casts one to
# `c_void_p`), so a plain Python object would not survive the import.
_real_cdll = ctypes.CDLL
_placeholder = _real_cdll(ctypes.util.find_library("c") or "libc.so.6").getpid

MISSING = ("sandlock_create_with_err", "sandlock_instance_launch_with_err")


class _StaleLib:
    # A pre-SL-12 build: every symbol dlsyms to a dummy except the create and
    # launch reason exports, which answer AttributeError exactly like the real
    # `dlsym` miss.
    _name = "/stale/libsandlock_ffi.so"

    def __getattr__(self, name):
        if name in MISSING:
            raise AttributeError(name)
        return _placeholder


ctypes.CDLL = lambda *args, **kwargs: _StaleLib()

try:
    import sandlock  # noqa: F401
except BaseException as exc:  # noqa: BLE001 - the probe reports the type
    print(type(exc).__module__ + "." + type(exc).__name__)
    print(exc)
    raise SystemExit(0)
raise SystemExit("import sandlock unexpectedly succeeded")
"""


def test_stale_library_fails_loudly_instead_of_importing_unusable(tmp_path):
    """New Python package + old `.so`: a RuntimeError that names the symbol.

    The stub is a *faithful* old library as far as `_sdk` can tell, so this
    covers the import path itself (not just the guard helper): the package must
    not import in a state where it would silently lose the failure reason.
    """
    probe = tmp_path / "stale_so_probe.py"
    probe.write_text(textwrap.dedent(_STALE_LIB_PROBE).format(py_src=str(PY_SRC)))
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PY_SRC)
    proc = subprocess.run(
        [sys.executable, str(probe)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.strip().splitlines()
    assert lines[0] == "builtins.RuntimeError", lines
    assert "AttributeError" not in proc.stdout
    assert lines[1].startswith(
        "sandlock_create_with_err is missing from the loaded sandlock library"
    )
    assert "libsandlock_ffi.so" in lines[1]
    assert "LD_LIBRARY_PATH" in lines[1]


# ----------------------------------------------------------------
# Fix round 1 (B1 review, minor-3): closed/dead are typed, not text
# ----------------------------------------------------------------


def _launchable_policy() -> Sandbox:
    readable = [
        p
        for p in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"]
        if os.path.exists(p)
    ]
    return Sandbox(fs_readable=readable)


def test_closed_instance_raises_a_typed_error():
    """A verb on a shut-down session is `InstanceClosedError`.

    Hosts (E2B) decide "rebuild once" from this type; the message now carries
    the core's prose, so matching text is not a sound classifier.
    """
    instance = SandboxInstance(_launchable_policy())
    try:
        instance.close()
        with pytest.raises(InstanceClosedError) as excinfo:
            instance.exec(["true"])
        # Compatibility: every existing `except RuntimeError` still catches it.
        assert isinstance(excinfo.value, RuntimeError)
        assert str(excinfo.value) == SandboxInstance._closed_message()
    finally:
        instance.close()


def test_launch_error_codes_map_to_typed_session_gone_errors():
    """The FFI reports the stable instance code, so launch failures type too."""
    reason = "sandlock_instance_launch failed: process error: whatever"
    closed = SandboxInstance._error_for_code(1, "launch", reason)
    dead = SandboxInstance._error_for_code(6, "launch", reason)
    plain = SandboxInstance._error_for_code(3, "launch", reason)
    assert type(closed) is InstanceClosedError
    assert type(dead) is InstanceDeadError
    assert type(plain) is RuntimeError
    # The launch reason is preserved verbatim, whatever the class.
    assert str(closed) == reason
    assert str(dead) == reason
    assert str(plain) == reason
