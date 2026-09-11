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
