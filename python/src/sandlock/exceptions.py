# SPDX-License-Identifier: Apache-2.0
"""Exception hierarchy for Sandlock sandbox operations."""


class SandlockError(Exception):
    """Base exception for all Sandlock errors."""

    pass


class PolicyError(SandlockError):
    """Invalid policy configuration."""

    pass


class SandboxError(SandlockError):
    """Sandbox lifecycle errors."""

    pass


class ForkError(SandboxError):
    """os.fork() failed."""

    pass


class ConfinementError(SandboxError):
    """Landlock/seccomp/chroot confinement failed."""

    pass


class LandlockUnavailableError(ConfinementError):
    """Landlock LSM not available on this kernel."""

    pass


class SeccompError(ConfinementError):
    """seccomp-bpf filter installation failed."""

    pass


class NotifError(SeccompError):
    """Seccomp user notification supervisor error."""

    pass




class ChildError(SandboxError):
    """Child process exited abnormally."""

    pass


class BranchError(SandboxError):
    """COW branch operation failed."""

    pass


class BranchConflictError(BranchError):
    """Commit rejected — a sibling branch already committed (ESTALE)."""

    pass


class MemoryProtectError(SandlockError):
    """mprotect(2) failed."""

    pass


class InstanceClosedError(RuntimeError):
    """The sandbox instance session is closed.

    Raised when a verb runs on an instance that has shut down, was reclaimed
    (idle-15min / 24h) or whose init channel closed after the main-exit
    container end. Subclasses :class:`RuntimeError`, so existing
    ``except RuntimeError`` handlers keep working — but a *typed* catch is how
    a host tells "the session is gone, build a new one" apart from any other
    failure (SL-12 fix round 1: the message now carries the core's free text,
    so substring matching it is unsafe).
    """

    pass


class InstanceDeadError(RuntimeError):
    """The sandbox instance machinery died (listener/reaper/control channel).

    Distinct from :class:`InstanceClosedError` (a clean close): a dead session
    is never silently relaunched, and the same code is reported by every later
    verb. Also a :class:`RuntimeError` subclass, for the same compatibility
    reason.
    """

    pass


class SlotRefusal(SandboxError):
    """A ``sandlock-supervise`` slot answered ``ok: false`` for a verb.

    This is the *served* refusal of route B: the slot process is a separate
    process, so the native exception types (:class:`InstanceClosedError` /
    :class:`InstanceDeadError`) cannot survive the channel — the frame
    carries prose plus a **stable code** instead, and this class is that pair
    on the Python side.

    :attr:`code` is one of the fork's ``RefusalCode`` wire strings
    (``sandlock-core/src/error.rs``), or ``None`` when the answer came from a
    wheel older than the one that introduced the field::

        generation_closed   the session is closed (shutdown, or the init
                            channel closed after the main-exit container end)
        generation_dead     the session machinery failed (listener / reaper /
                            control-channel failure)
        policy_denied       a Live session refused a request wider than the
                            instance-time policy ceiling (EPERM)
        verb_refused        a Live session refused for any other reason

    A host must branch on :attr:`code`, never on the message: the message
    carries the core's own free text (a refusal's remedy, a confinement
    errno), so substring matching it is unsound. ``None`` means "cannot tell
    from this answer" — it is *not* a synonym for any of the four values.

    A :class:`SandboxError` subclass, so every existing handler that catches
    ``SandboxError`` / ``SandlockError`` keeps working unchanged.
    """

    #: The four stable wires values, for callers that would rather not spell
    #: them out (``sandlock-core/src/error.rs::RefusalCode``).
    GENERATION_CLOSED = "generation_closed"
    GENERATION_DEAD = "generation_dead"
    POLICY_DENIED = "policy_denied"
    VERB_REFUSED = "verb_refused"

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code
