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
* **root**: the C档 shape (default ``mediation_run_as=caller`` + path
  mediation + non-zero host uid) is refused with the route-B remedy —
  ``crates/sandlock-core/src/sandbox.rs`` (``mediation_run_as=caller
  refused:`` ... ``(route B)``); the E2B worker hits exactly this text when
  an in-process supervisor-tier downgrade is attempted.  Run pytest as root
  to exercise that branch (``docker run --user root`` / the B1 root runner).

Every assertion is whole-string equality against the core text; a substring
or ``match=`` assertion would accept a truncated or reordered reason.
"""

from __future__ import annotations

import os

import pytest

from sandlock import Sandbox, SandboxInstance


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
        # C档 (mediation_run_as=caller, root in-process remap, path mediation).
        return (
            "process error: child process error: "
            "mediation_run_as=caller refused: in-process path mediation would run "
            f"as euid 0 while the sandbox's host uid is {_TARGET_UID}; on-behalf "
            "files would be owned by the mediator, not the sandbox (SL-1). Run "
            f"sandlock-supervise as uid {_TARGET_UID} (route B), or pass "
            "mediation_run_as=supervisor to explicitly accept the downgrade"
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
