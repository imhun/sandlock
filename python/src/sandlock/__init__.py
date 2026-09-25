# SPDX-License-Identifier: Apache-2.0
"""Sandlock: Lightweight process sandbox.

Uses Landlock and seccomp for process confinement
without root or namespaces.
"""

from ._version import __version__

# F2b.5b: point the engine at the restore stub that travels *inside* the wheel.
# `build.rs` compiles the stub into its OUT_DIR, i.e. a path under the build
# container's `target/`, which does not exist where a wheel is installed -- a
# restore from an installed wheel therefore failed with "restore-stub was not
# built" (measured on the deployment 2026-09-25). `sandlock/bin/` carries the
# same bytes as `sandlock/bin/sandlock-supervise`, so the slot finds it beside
# itself too; this covers the in-process (FFI) path and anything the process
# spawns, since the environment is inherited. `setdefault`: an operator who
# shipped the stub elsewhere wins.
def _point_at_the_wheel_restore_stub() -> None:
    import os
    from pathlib import Path

    stub = Path(__file__).resolve().parent / "bin" / "restore-stub"
    if stub.is_file():
        os.environ.setdefault("SANDLOCK_RESTORE_STUB", str(stub))


_point_at_the_wheel_restore_stub()
del _point_at_the_wheel_restore_stub

from ._sdk import (
    Stage, Pipeline, Result, ExitReason, SyscallEvent, PolicyContext, Checkpoint, SkippedFd,
    NamedStage, Gather, GatherPipeline,
    Protection,
    landlock_abi_version, min_landlock_abi, confine,
)
from .inputs import inputs
from .handler import Handler, NotifAction, HandlerCtx, ExceptionPolicy
from .sandbox import (
    Sandbox, BranchAction, minimal_dev, parse_ports, Change, DryRunResult, StdioMode, Process,
    SandboxInstance, ExecProcess, ExecStdio,
)
from ._profile import load_profile, list_profiles
from .exceptions import (
    SandlockError,
    PolicyError,
    SandboxError,
    ForkError,
    ConfinementError,
    LandlockUnavailableError,
    SeccompError,
    ChildError,
    MemoryProtectError,
    NotifError,
    BranchError,
    BranchConflictError,
    InstanceClosedError,
    InstanceDeadError,
    SlotRefusal,
)

__all__ = [
    "__version__",
    # Core API
    "Sandbox",
    "Stage",
    "Pipeline",
    "Result",
    "ExitReason",
    "SyscallEvent",
    "PolicyContext",
    "Checkpoint",
    "SkippedFd",
    "NamedStage",
    "Gather",
    "GatherPipeline",
    "inputs",
    "BranchAction",
    "minimal_dev",
    "parse_ports",
    "Change",
    "DryRunResult",
    "StdioMode",
    "Process",
    "SandboxInstance",
    "ExecProcess",
    "ExecStdio",
    "Protection",
    # Handler ABI
    "Handler",
    "NotifAction",
    "HandlerCtx",
    "ExceptionPolicy",
    # Platform
    "landlock_abi_version",
    "min_landlock_abi",
    "confine",
    # Profiles
    "load_profile",
    "list_profiles",
    # Exceptions
    "SandlockError",
    "PolicyError",
    "SandboxError",
    "ForkError",
    "ConfinementError",
    "LandlockUnavailableError",
    "SeccompError",
    "ChildError",
    "MemoryProtectError",
    "NotifError",
    "BranchError",
    "BranchConflictError",
    "InstanceClosedError",
    "InstanceDeadError",
    "SlotRefusal",
]
