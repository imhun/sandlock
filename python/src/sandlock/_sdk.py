"""Python SDK for sandlock — ctypes bindings to libsandlock_ffi.so."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import signal
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, NamedTuple, Sequence

from .sandbox import Sandbox as PolicyDataclass

# ----------------------------------------------------------------
# Load the shared library
# ----------------------------------------------------------------

def _find_lib() -> str:
    """Find libsandlock_ffi.so."""
    pkg_dir = Path(__file__).parent

    # 1. Dev build from cargo — pick the most recently built profile.
    target_dir = pkg_dir / ".." / ".." / ".." / "target"
    candidates = [target_dir / p / "libsandlock_ffi.so" for p in ("debug", "release")]
    candidates = [c for c in candidates if c.exists()]
    if candidates:
        return str(max(candidates, key=lambda c: c.stat().st_mtime).resolve())

    # 2. Next to this file (installed via pip/setuptools-rust)
    for candidate in sorted(pkg_dir.glob("libsandlock_ffi*.so"), reverse=True):
        return str(candidate.resolve())

    # 3. System library path
    found = ctypes.util.find_library("sandlock_ffi")
    if found:
        return found

    # 4. LD_LIBRARY_PATH
    for d in os.environ.get("LD_LIBRARY_PATH", "").split(":"):
        p = os.path.join(d, "libsandlock_ffi.so")
        if os.path.isfile(p):
            return p

    raise RuntimeError(
        "libsandlock_ffi.so not found. Build with: "
        "cd sandlock-rs && cargo build --release"
    )

_lib = ctypes.CDLL(_find_lib())

# ----------------------------------------------------------------
# C function signatures
# ----------------------------------------------------------------

# Types
_c_policy_p = ctypes.c_void_p
_c_builder_p = ctypes.c_void_p
_c_result_p = ctypes.c_void_p
_c_pipeline_p = ctypes.c_void_p

# Sandbox builder
_lib.sandlock_sandbox_builder_new.restype = _c_builder_p
_lib.sandlock_sandbox_builder_new.argtypes = []

def _builder_fn(name, *extra_args):
    fn = getattr(_lib, name)
    fn.restype = _c_builder_p
    fn.argtypes = [_c_builder_p] + list(extra_args)
    return fn


_SECRET_PREFIXES = ("env:", "file:", "fd:")


def _serialize_http_inject(rule, index: int) -> tuple[str, str, str]:
    """Validate one ``http_inject`` dict and serialize it to the native
    ``(name, source)`` credential + ``METHOD HOST/PATH AUTHSPEC NAME`` rule.

    Returns ``(name, secret_source, http_auth_rule)``; raises ``ValueError``
    with a precise message for any malformed entry.
    """
    if not isinstance(rule, dict):
        raise ValueError(
            f"http_inject[{index}] must be a dict, got {type(rule).__name__}"
        )
    unknown = set(rule) - {"matcher", "auth", "secret", "name", "on_existing"}
    if unknown:
        raise ValueError(
            f"http_inject[{index}] unknown field(s): {sorted(unknown)}"
        )

    matcher = rule.get("matcher")
    if not isinstance(matcher, str) or not matcher.strip():
        raise ValueError(
            f"http_inject[{index}].matcher must be a non-empty string "
            f'("HOST", "HOST/PATH", or "METHOD HOST/PATH")'
        )
    matcher = " ".join(matcher.split())
    tokens = matcher.split()
    if len(tokens) == 1:
        # Bare host (optionally with path): default method `*`.
        host_path = tokens[0]
        matcher = f"* {host_path}" if "/" in host_path else f"* {host_path}/*"
    elif len(tokens) == 2:
        pass  # already "METHOD HOST/PATH"
    else:
        raise ValueError(
            f"http_inject[{index}].matcher must be "
            f'"HOST", "HOST/PATH", or "METHOD HOST/PATH", got {matcher!r}'
        )

    auth = rule.get("auth")
    if not isinstance(auth, str) or not auth.strip():
        raise ValueError(f"http_inject[{index}].auth must be a non-empty string")
    auth = auth.strip()
    if auth == "bearer":
        pass
    elif auth.startswith(("basic:", "header:", "apikey:", "query:")):
        _, _, arg = auth.partition(":")
        if not arg:
            raise ValueError(
                f"http_inject[{index}].auth {auth!r} requires a non-empty argument"
            )
    else:
        raise ValueError(
            f"http_inject[{index}].auth must be one of "
            '"bearer", "basic:<user>", "header:<name>", "apikey:<name>", '
            f'"query:<param>", got {auth!r}'
        )

    secret = rule.get("secret")
    if not isinstance(secret, str):
        raise ValueError(f"http_inject[{index}].secret must be a string")
    secret = secret.strip()
    if secret.startswith("literal:"):
        raise ValueError(
            f"http_inject[{index}].secret 'literal:' is rejected (it leaks via "
            "ps / shell history); use env:VAR, file:/path, or fd:N"
        )
    kind, _, val = secret.partition(":")
    if kind not in ("env", "file", "fd") or not val:
        raise ValueError(
            f"http_inject[{index}].secret must be env:VAR, file:/path, or "
            f"fd:N, got {secret!r}"
        )

    name = rule.get("name")
    if name is None:
        name = f"inject{index}"
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"http_inject[{index}].name must be a non-empty string")
    name = name.strip()

    on_existing = rule.get("on_existing", "replace")
    if on_existing not in ("replace", "add-only"):
        raise ValueError(
            f"http_inject[{index}].on_existing must be "
            f"'replace' or 'add-only', got {on_existing!r}"
        )

    rule_str = f"{matcher} {auth} {name}"
    if on_existing == "add-only":
        rule_str = f"{rule_str} add-only"
    return name, secret, rule_str


_b_fs_read = _builder_fn("sandlock_sandbox_builder_fs_read", ctypes.c_char_p)
_b_fs_write = _builder_fn("sandlock_sandbox_builder_fs_write", ctypes.c_char_p)
_b_fs_deny = _builder_fn("sandlock_sandbox_builder_fs_deny", ctypes.c_char_p)
_b_fs_storage = _builder_fn("sandlock_sandbox_builder_fs_storage", ctypes.c_char_p)
_b_gpu_devices = _builder_fn("sandlock_sandbox_builder_gpu_devices", ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32)
_b_workdir = _builder_fn("sandlock_sandbox_builder_workdir", ctypes.c_char_p)
_b_cwd = _builder_fn("sandlock_sandbox_builder_cwd", ctypes.c_char_p)
_b_chroot = _builder_fn("sandlock_sandbox_builder_chroot", ctypes.c_char_p)
_b_fs_mount = _builder_fn("sandlock_sandbox_builder_fs_mount", ctypes.c_char_p, ctypes.c_char_p)
_b_on_exit = _builder_fn("sandlock_sandbox_builder_on_exit", ctypes.c_uint8)
_b_on_error = _builder_fn("sandlock_sandbox_builder_on_error", ctypes.c_uint8)
_b_max_memory = _builder_fn("sandlock_sandbox_builder_max_memory", ctypes.c_uint64)
_b_max_disk = _builder_fn("sandlock_sandbox_builder_max_disk", ctypes.c_uint64)
_b_max_processes = _builder_fn("sandlock_sandbox_builder_max_processes", ctypes.c_uint32)
_b_max_cpu = _builder_fn("sandlock_sandbox_builder_max_cpu", ctypes.c_uint8)
_b_notify_rate_limit = _builder_fn(
    "sandlock_sandbox_builder_notify_rate_limit", ctypes.c_uint32
)
_b_num_cpus = _builder_fn("sandlock_sandbox_builder_num_cpus", ctypes.c_uint32)
_b_net_allow = _builder_fn("sandlock_sandbox_builder_net_allow", ctypes.c_char_p)
_b_net_deny = _builder_fn("sandlock_sandbox_builder_net_deny", ctypes.c_char_p)
_b_net_allow_bind = _builder_fn("sandlock_sandbox_builder_net_allow_bind", ctypes.c_char_p)
_b_net_deny_bind = _builder_fn("sandlock_sandbox_builder_net_deny_bind", ctypes.c_char_p)
_b_port_remap = _builder_fn("sandlock_sandbox_builder_port_remap", ctypes.c_bool)
_b_pid_ns = _builder_fn("sandlock_sandbox_builder_pid_ns", ctypes.c_bool)
_b_net_isolation = _builder_fn("sandlock_sandbox_builder_net_isolation", ctypes.c_bool)
_b_fd_inject_connect = _builder_fn(
    "sandlock_sandbox_builder_fd_inject_connect", ctypes.c_bool
)
_b_net_bind_map = _builder_fn(
    "sandlock_sandbox_builder_net_bind_map", ctypes.c_uint16, ctypes.c_uint16
)
_b_http_allow = _builder_fn("sandlock_sandbox_builder_http_allow", ctypes.c_char_p)
_b_http_deny = _builder_fn("sandlock_sandbox_builder_http_deny", ctypes.c_char_p)
_b_credential = _builder_fn(
    "sandlock_sandbox_builder_credential", ctypes.c_char_p, ctypes.c_char_p
)
_b_http_auth = _builder_fn("sandlock_sandbox_builder_http_auth", ctypes.c_char_p)
_b_http_port = _builder_fn("sandlock_sandbox_builder_http_port", ctypes.c_uint16)
_b_http_ca = _builder_fn("sandlock_sandbox_builder_http_ca", ctypes.c_char_p)
_b_http_key = _builder_fn("sandlock_sandbox_builder_http_key", ctypes.c_char_p)
_b_http_inject_ca = _builder_fn("sandlock_sandbox_builder_http_inject_ca", ctypes.c_char_p)
_b_http_ca_out = _builder_fn("sandlock_sandbox_builder_http_ca_out", ctypes.c_char_p)
_b_host_mask = _builder_fn("sandlock_sandbox_builder_host_mask", ctypes.c_char_p)
_b_egress_proxy = _builder_fn("sandlock_sandbox_builder_egress_proxy", ctypes.c_char_p)
_b_egress_proxy_credentials = _builder_fn(
    "sandlock_sandbox_builder_egress_proxy_credentials", ctypes.c_char_p, ctypes.c_char_p
)
_b_user = _builder_fn("sandlock_sandbox_builder_user", ctypes.c_uint32, ctypes.c_uint32)
_b_mediation_run_as = _builder_fn(
    "sandlock_sandbox_builder_mediation_run_as", ctypes.c_uint8
)
_b_random_seed = _builder_fn("sandlock_sandbox_builder_random_seed", ctypes.c_uint64)
_b_clean_env = _builder_fn("sandlock_sandbox_builder_clean_env", ctypes.c_bool)
_b_env_var = _builder_fn("sandlock_sandbox_builder_env_var", ctypes.c_char_p, ctypes.c_char_p)
_b_time_start = _builder_fn("sandlock_sandbox_builder_time_start", ctypes.c_uint64)
_b_extra_deny_syscalls = _builder_fn("sandlock_sandbox_builder_extra_deny_syscalls", ctypes.c_char_p)
_b_extra_allow_syscalls = _builder_fn("sandlock_sandbox_builder_extra_allow_syscalls", ctypes.c_char_p)
_b_max_open_files = _builder_fn("sandlock_sandbox_builder_max_open_files", ctypes.c_uint32)
_b_no_randomize_memory = _builder_fn("sandlock_sandbox_builder_no_randomize_memory", ctypes.c_bool)
_b_no_huge_pages = _builder_fn("sandlock_sandbox_builder_no_huge_pages", ctypes.c_bool)
_b_no_coredump = _builder_fn("sandlock_sandbox_builder_no_coredump", ctypes.c_bool)
_b_deterministic_dirs = _builder_fn("sandlock_sandbox_builder_deterministic_dirs", ctypes.c_bool)
_b_cpu_cores = _builder_fn("sandlock_sandbox_builder_cpu_cores", ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32)

# Protection opt-out — mirror of the C ABI `sandlock_protection_t`.
# Discriminant values must stay in sync with `sandlock_core::Protection`
# and `sandlock_protection_t` in `crates/sandlock-ffi/include/sandlock.h`.
class Protection(IntEnum):
    """Per-protection Landlock feature identifier.

    Pass values from this enum to ``Sandbox(allow_degraded=...)`` or
    ``Sandbox(disable=...)`` to opt out of strict enforcement for the
    named protection. See the C header for kernel ABI requirements.
    """

    FS_REFER = 0
    FS_TRUNCATE = 1
    NET_TCP = 2
    FS_IOCTL_DEV = 3
    SIGNAL_SCOPE = 4
    ABSTRACT_UNIX_SOCKET_SCOPE = 5


_lib.sandlock_protection_min_abi.restype = ctypes.c_uint32
_lib.sandlock_protection_min_abi.argtypes = [ctypes.c_uint32]

# Move-semantics setters: each returns the (possibly relocated) builder
# pointer, mirroring the convention of the other `_builder_fn` setters.
# The C ABI accepts the protection as a `uint32_t` so an out-of-range
# value is rejected at the FFI boundary (no `#[repr(C)]` enum cast).
_b_allow_degraded = _builder_fn(
    "sandlock_sandbox_builder_allow_degraded", ctypes.c_uint32
)
_b_disable = _builder_fn(
    "sandlock_sandbox_builder_disable", ctypes.c_uint32
)


def _validate_protection(p: int, *, field: str) -> int:
    """Coerce a caller-supplied protection value to a known discriminant
    or raise :class:`ValueError`. Centralises the range check so the FFI
    is never invoked with an unknown integer (the Rust setters silently
    no-op on bad input, which is the wrong UX for the Python caller —
    we want a loud failure at the SDK boundary instead).
    """
    try:
        return int(Protection(int(p)))
    except (ValueError, TypeError) as e:
        valid = ", ".join(f"{m.name}={int(m)}" for m in Protection)
        raise ValueError(
            f"{field}: {p!r} is not a known Protection discriminant "
            f"(valid: {valid})"
        ) from e

# Policy callback (policy_fn).
# Path strings absent (issue #27 — path-based control belongs in Landlock).
# argv is populated for execve only; TOCTOU-safe via sibling freeze.
class _CEvent(ctypes.Structure):
    _fields_ = [
        ("syscall", ctypes.c_char_p),
        ("category", ctypes.c_uint8),
        ("pid", ctypes.c_uint32),
        ("parent_pid", ctypes.c_uint32),
        ("host", ctypes.c_char_p),
        ("port", ctypes.c_uint16),
        ("denied", ctypes.c_bool),
        ("argv", ctypes.POINTER(ctypes.c_char_p)),
        ("argc", ctypes.c_uint32),
    ]

_c_ctx_p = ctypes.c_void_p
_POLICY_FN_TYPE = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.POINTER(_CEvent),
    _c_ctx_p,
    ctypes.c_void_p,
)

_lib.sandlock_sandbox_builder_policy_fn.restype = _c_builder_p
_lib.sandlock_sandbox_builder_policy_fn.argtypes = [
    _c_builder_p,
    _POLICY_FN_TYPE,
    ctypes.c_void_p,
    ctypes.c_void_p,
]

_lib.sandlock_ctx_restrict_network.restype = None
_lib.sandlock_ctx_restrict_network.argtypes = [_c_ctx_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint32]

_lib.sandlock_ctx_grant_network.restype = None
_lib.sandlock_ctx_grant_network.argtypes = [_c_ctx_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint32]

_lib.sandlock_ctx_restrict_max_memory.restype = None
_lib.sandlock_ctx_restrict_max_memory.argtypes = [_c_ctx_p, ctypes.c_uint64]

_lib.sandlock_ctx_restrict_max_processes.restype = None
_lib.sandlock_ctx_restrict_max_processes.argtypes = [_c_ctx_p, ctypes.c_uint32]

_lib.sandlock_ctx_restrict_pid_network.restype = None
_lib.sandlock_ctx_restrict_pid_network.argtypes = [_c_ctx_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint32]

_lib.sandlock_ctx_deny_path.restype = None
_lib.sandlock_ctx_deny_path.argtypes = [_c_ctx_p, ctypes.c_char_p]

_lib.sandlock_ctx_allow_path.restype = None
_lib.sandlock_ctx_allow_path.argtypes = [_c_ctx_p, ctypes.c_char_p]

# Platform query
_lib.sandlock_landlock_abi_version.restype = ctypes.c_int
_lib.sandlock_landlock_abi_version.argtypes = []

_lib.sandlock_min_landlock_abi.restype = ctypes.c_int
_lib.sandlock_min_landlock_abi.argtypes = []

# Confine current process
_lib.sandlock_confine.restype = ctypes.c_int
_lib.sandlock_confine.argtypes = [ctypes.c_void_p]


def landlock_abi_version() -> int:
    """Return the Landlock ABI version supported by the running kernel.

    Returns -1 if Landlock is unavailable.
    """
    return _lib.sandlock_landlock_abi_version()


def min_landlock_abi() -> int:
    """Return the minimum Landlock ABI version required by sandlock."""
    return _lib.sandlock_min_landlock_abi()


def confine(policy: "PolicyDataclass") -> None:
    """Confine the calling process with Landlock restrictions.

    Applies PR_SET_NO_NEW_PRIVS and Landlock rules from the policy's
    filesystem fields. IPC and signal isolation are always enabled. The
    confinement is **irreversible**.

    Only filesystem paths are accepted. Policies containing supervisor,
    seccomp, network, resource, environment, or COW settings are rejected
    rather than silently ignored.

    This does NOT fork or exec — it confines the current process in-place.

    Args:
        policy: Policy with Landlock rules to apply.

    Raises:
        SandlockError: If confinement fails.
    """
    native = _NativePolicy.from_dataclass(policy)
    ret = _lib.sandlock_confine(native.ptr)
    if ret != 0:
        from .exceptions import ConfinementError
        raise ConfinementError("confine failed")


_lib.sandlock_sandbox_build.restype = _c_policy_p
_lib.sandlock_sandbox_build.argtypes = [
    _c_builder_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_char_p),
]

_lib.sandlock_sandbox_free.restype = None
_lib.sandlock_sandbox_free.argtypes = [_c_policy_p]

# String-out-param release. The FFI returns CString::into_raw pointers
# for error messages from sandlock_sandbox_build; we must free them via
# this function rather than ctypes' own deallocator.
_lib.sandlock_string_free.restype = None
_lib.sandlock_string_free.argtypes = [ctypes.c_char_p]

# Freeing a raw address read out of a `char **` out-parameter goes through a
# `c_void_p`-typed wrapper: handing ctypes the *bytes* would copy them and free
# the copy (the same fix `supervise._free_string` needed for fork issue SL-9).
_free_native_string = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(
    ctypes.cast(_lib.sandlock_string_free, ctypes.c_void_p).value
)


def _take_err_msg(err_msg: ctypes.c_void_p) -> str | None:
    """Return and free the native message written into ``err_msg``.

    ``err_msg`` is the ``c_void_p`` whose address went to the C call as the
    ``char **`` out-parameter: the message is read from the returned *address*
    and released with ``sandlock_string_free``, never through ctypes' own
    deallocator and never by handing the bytes back (which would free a copy).
    """
    address = err_msg.value
    if not address:
        return None
    try:
        return ctypes.string_at(address).decode("utf-8", "replace")
    finally:
        _free_native_string(address)
        err_msg.value = None


def _failure_text(what: str, err_msg: ctypes.c_void_p) -> str:
    """``<what> failed: <native reason>`` — the reason when the FFI carried one.

    SL-12: the create/launch entry points used to drop the core's own error
    text, leaving the SDK face with a bare ``<what> failed``. The core text is
    what a caller can act on (a fail-closed refusal names its remedy; a
    confinement failure names its errno), so it is appended verbatim, and the
    generic message is kept as the fallback for a reason-less failure.
    """
    reason = _take_err_msg(err_msg)
    return f"{what} failed: {reason}" if reason else f"{what} failed"


# Run
_lib.sandlock_run.restype = _c_result_p
_lib.sandlock_run.argtypes = [_c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_run_interactive.restype = ctypes.c_int
_lib.sandlock_run_interactive.argtypes = [_c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

# Sandbox handle (create / start / wait)
_c_handle_p = ctypes.c_void_p

_lib.sandlock_create.restype = _c_handle_p
_lib.sandlock_create.argtypes = [_c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

# SL-12 fix round 1 (security review): the create/launch exports that carry a
# failure reason are *required* by this package, but the `.so` it loads is a
# separate artifact — a stale `target/`, a partially upgraded image or a wheel
# built against an older library can predate them. Two failure modes must be
# avoided:
#
#   * silently falling back to the reason-less symbols (a sandbox failure
#     would then be reported without its cause), and
#   * a bare `AttributeError` at `import sandlock` — launcher-level guards
#     (E2B's `_sandlock_available()`) catch broadly, so an AttributeError reads
#     as "sandlock is unavailable" and the worker quietly loses confinement.
#
# So: probe with `hasattr` (ctypes answers a missing symbol from dlsym with
# AttributeError, which must not escape), bind what exists, and fail by name
# with the remedy when an export is missing.
_CREATE_WITH_ERR_EXPORT = "sandlock_create_with_err"
_INSTANCE_LAUNCH_WITH_ERR_EXPORT = "sandlock_instance_launch_with_err"


def _bind_export(name: str, restype, argtypes):
    """Bind `name` when the loaded library exports it; else return None."""
    if not hasattr(_lib, name):
        return None
    fn = getattr(_lib, name)
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


def _require_export(name: str, fn):
    """The bound export, or a `RuntimeError` naming the symbol and the fix."""
    if fn is None:
        raise RuntimeError(
            f"{name} is missing from the loaded sandlock library "
            f"({_lib._name!s}). This Python package requires the create/launch "
            "exports that carry a failure reason: without them a sandbox "
            "failure would be reported without its cause, so this is refused "
            "rather than silently degraded. Install the matching sandlock "
            "wheel, or rebuild the native library "
            "(cargo build -p sandlock-ffi) and point LD_LIBRARY_PATH at it."
        )
    return fn


_create_with_err = _bind_export(
    _CREATE_WITH_ERR_EXPORT,
    _c_handle_p,
    [
        _c_policy_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.c_uint,
        ctypes.POINTER(ctypes.c_int),      # err
        ctypes.POINTER(ctypes.c_void_p),   # err_msg (char **)
    ],
)
# Import-time refusal, by name: a newer SDK must never run against a library
# that cannot report why a sandbox failed.
_require_export(_CREATE_WITH_ERR_EXPORT, _create_with_err)

_lib.sandlock_create_for_run.restype = _c_handle_p
_lib.sandlock_create_for_run.argtypes = [_c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_start.restype = ctypes.c_int
_lib.sandlock_start.argtypes = [_c_handle_p]

_lib.sandlock_handle_pid.restype = ctypes.c_int
_lib.sandlock_handle_pid.argtypes = [_c_handle_p]

_lib.sandlock_handle_wait.restype = _c_result_p
_lib.sandlock_handle_wait.argtypes = [_c_handle_p]

_lib.sandlock_handle_wait_timeout.restype = _c_result_p
_lib.sandlock_handle_wait_timeout.argtypes = [_c_handle_p, ctypes.c_uint64]

_lib.sandlock_handle_free.restype = None
_lib.sandlock_handle_free.argtypes = [_c_handle_p]

_lib.sandlock_handle_port_mappings.restype = ctypes.c_char_p
_lib.sandlock_handle_port_mappings.argtypes = [_c_handle_p]

# Streaming-stdio popen (RFC #67): create+start a live handle with per-stream
# StdioMode; each piped stream's owned fd is returned through its out pointer.
_lib.sandlock_popen.restype = _c_handle_p
_lib.sandlock_popen.argtypes = [
    _c_policy_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_uint,
    ctypes.c_uint32,  # stdin_mode
    ctypes.c_uint32,  # stdout_mode
    ctypes.c_uint32,  # stderr_mode
    ctypes.POINTER(ctypes.c_int),  # out_stdin_fd
    ctypes.POINTER(ctypes.c_int),  # out_stdout_fd
    ctypes.POINTER(ctypes.c_int),  # out_stderr_fd
]

# SandboxInstance (F3.3): exec-capable session handle + per-child verbs
_c_instance_p = ctypes.c_void_p

class _SandlockInstanceExecResult(ctypes.Structure):
    """Mirror of `sandlock_instance_exec_result_t` in sandlock.h."""

    _fields_ = [
        ("child_id", ctypes.c_uint64),
        ("pid", ctypes.c_int32),
        ("stdin_fd", ctypes.c_int32),
        ("stdout_fd", ctypes.c_int32),
        ("stderr_fd", ctypes.c_int32),
        ("pty_fd", ctypes.c_int32),
    ]


class _SandlockInstanceExecParams(ctypes.Structure):
    """Mirror of `sandlock_instance_exec_params_t` in sandlock.h (F4.1)."""

    _fields_ = [
        ("cwd", ctypes.c_char_p),
        ("clean_env", ctypes.c_uint8),
        ("env", ctypes.POINTER(ctypes.c_char_p)),
        ("env_count", ctypes.c_size_t),
        ("extra_writable", ctypes.POINTER(ctypes.c_char_p)),
        ("extra_writable_count", ctypes.c_size_t),
        ("bind_ports", ctypes.POINTER(ctypes.c_uint16)),
        ("bind_ports_count", ctypes.c_size_t),
    ]


_lib.sandlock_instance_launch.restype = _c_instance_p
_lib.sandlock_instance_launch.argtypes = [_c_policy_p, ctypes.c_char_p]
_instance_launch_with_err = _bind_export(
    _INSTANCE_LAUNCH_WITH_ERR_EXPORT,
    _c_instance_p,
    [
        _c_policy_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),      # err
        ctypes.POINTER(ctypes.c_void_p),   # err_msg (char **)
    ],
)
_require_export(_INSTANCE_LAUNCH_WITH_ERR_EXPORT, _instance_launch_with_err)
_lib.sandlock_instance_exec.restype = ctypes.c_int
_lib.sandlock_instance_exec.argtypes = [
    _c_instance_p,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_uint,
    ctypes.c_uint32,
    ctypes.POINTER(_SandlockInstanceExecResult),
]
_lib.sandlock_instance_exec_params.restype = ctypes.c_int
_lib.sandlock_instance_exec_params.argtypes = [
    _c_instance_p,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_uint,
    ctypes.c_uint32,
    ctypes.POINTER(_SandlockInstanceExecParams),
    ctypes.POINTER(_SandlockInstanceExecResult),
]
_lib.sandlock_instance_update_network.restype = ctypes.c_int
_lib.sandlock_instance_update_network.argtypes = [
    _c_instance_p,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.sandlock_instance_wait_child.restype = _c_result_p
_lib.sandlock_instance_wait_child.argtypes = [
    _c_instance_p,
    ctypes.c_uint64,
    ctypes.c_uint64,
]
_lib.sandlock_instance_kill_child.restype = ctypes.c_int
_lib.sandlock_instance_kill_child.argtypes = [_c_instance_p, ctypes.c_uint64, ctypes.c_int32]
_lib.sandlock_instance_resize_child.restype = ctypes.c_int
_lib.sandlock_instance_resize_child.argtypes = [
    _c_instance_p,
    ctypes.c_uint64,
    ctypes.c_uint16,
    ctypes.c_uint16,
]
_lib.sandlock_instance_free.restype = None
_lib.sandlock_instance_free.argtypes = [_c_instance_p]

# Result
_lib.sandlock_result_exit_code.restype = ctypes.c_int
_lib.sandlock_result_exit_code.argtypes = [_c_result_p]

_lib.sandlock_result_success.restype = ctypes.c_bool
_lib.sandlock_result_success.argtypes = [_c_result_p]

_lib.sandlock_result_reason.restype = ctypes.c_uint  # sandlock_exit_reason (repr u32)
_lib.sandlock_result_reason.argtypes = [_c_result_p]

_lib.sandlock_result_signal.restype = ctypes.c_int
_lib.sandlock_result_signal.argtypes = [_c_result_p]

_lib.sandlock_result_stdout_bytes.restype = ctypes.c_void_p
_lib.sandlock_result_stdout_bytes.argtypes = [_c_result_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_result_stderr_bytes.restype = ctypes.c_void_p
_lib.sandlock_result_stderr_bytes.argtypes = [_c_result_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_result_free.restype = None
_lib.sandlock_result_free.argtypes = [_c_result_p]

# Dry-run
_c_dry_run_p = ctypes.c_void_p

_lib.sandlock_dry_run.restype = _c_dry_run_p
_lib.sandlock_dry_run.argtypes = [_c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_dry_run_result_exit_code.restype = ctypes.c_int
_lib.sandlock_dry_run_result_exit_code.argtypes = [_c_dry_run_p]

_lib.sandlock_dry_run_result_reason.restype = ctypes.c_uint
_lib.sandlock_dry_run_result_reason.argtypes = [_c_dry_run_p]

_lib.sandlock_dry_run_result_signal.restype = ctypes.c_int
_lib.sandlock_dry_run_result_signal.argtypes = [_c_dry_run_p]

_lib.sandlock_dry_run_result_success.restype = ctypes.c_bool
_lib.sandlock_dry_run_result_success.argtypes = [_c_dry_run_p]

_lib.sandlock_dry_run_result_stdout_bytes.restype = ctypes.c_void_p
_lib.sandlock_dry_run_result_stdout_bytes.argtypes = [_c_dry_run_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_dry_run_result_stderr_bytes.restype = ctypes.c_void_p
_lib.sandlock_dry_run_result_stderr_bytes.argtypes = [_c_dry_run_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_dry_run_result_changes_len.restype = ctypes.c_size_t
_lib.sandlock_dry_run_result_changes_len.argtypes = [_c_dry_run_p]

_lib.sandlock_dry_run_result_change_kind.restype = ctypes.c_char
_lib.sandlock_dry_run_result_change_kind.argtypes = [_c_dry_run_p, ctypes.c_size_t]

_lib.sandlock_dry_run_result_change_path.restype = ctypes.c_void_p
_lib.sandlock_dry_run_result_change_path.argtypes = [_c_dry_run_p, ctypes.c_size_t]

_lib.sandlock_dry_run_result_free.restype = None
_lib.sandlock_dry_run_result_free.argtypes = [_c_dry_run_p]

# Pipeline
_lib.sandlock_pipeline_new.restype = _c_pipeline_p
_lib.sandlock_pipeline_new.argtypes = []

_lib.sandlock_pipeline_add_stage.restype = None
_lib.sandlock_pipeline_add_stage.argtypes = [
    _c_pipeline_p, _c_policy_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint,
]

_lib.sandlock_pipeline_run.restype = _c_result_p
_lib.sandlock_pipeline_run.argtypes = [_c_pipeline_p, ctypes.c_uint64]

_lib.sandlock_pipeline_free.restype = None
_lib.sandlock_pipeline_free.argtypes = [_c_pipeline_p]

# Gather
_c_gather_p = ctypes.c_void_p

_lib.sandlock_gather_new.restype = _c_gather_p
_lib.sandlock_gather_new.argtypes = []

_lib.sandlock_gather_add_source.restype = None
_lib.sandlock_gather_add_source.argtypes = [
    _c_gather_p, ctypes.c_char_p, _c_policy_p,
    ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint,
]

_lib.sandlock_gather_set_consumer.restype = None
_lib.sandlock_gather_set_consumer.argtypes = [
    _c_gather_p, _c_policy_p,
    ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint,
]

_lib.sandlock_gather_run.restype = _c_result_p
_lib.sandlock_gather_run.argtypes = [_c_gather_p, ctypes.c_uint64]

_lib.sandlock_gather_free.restype = None
_lib.sandlock_gather_free.argtypes = [_c_gather_p]

_lib.sandlock_string_free.restype = None
_lib.sandlock_string_free.argtypes = [ctypes.c_char_p]

# Fork
_INIT_FN_TYPE = ctypes.CFUNCTYPE(None)
_WORK_FN_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_uint32)

_c_sandbox_p = ctypes.c_void_p

_lib.sandlock_new_with_fns.restype = _c_sandbox_p
_lib.sandlock_new_with_fns.argtypes = [_c_policy_p, ctypes.c_char_p, _INIT_FN_TYPE, _WORK_FN_TYPE]

_c_fork_result_p = ctypes.c_void_p

_lib.sandlock_fork.restype = _c_fork_result_p
_lib.sandlock_fork.argtypes = [_c_sandbox_p, ctypes.c_uint32]

_lib.sandlock_fork_result_count.restype = ctypes.c_uint32
_lib.sandlock_fork_result_count.argtypes = [_c_fork_result_p]

_lib.sandlock_fork_result_pid.restype = ctypes.c_int32
_lib.sandlock_fork_result_pid.argtypes = [_c_fork_result_p, ctypes.c_uint32]

_lib.sandlock_reduce.restype = _c_result_p
_lib.sandlock_reduce.argtypes = [_c_fork_result_p, _c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_fork_result_free.restype = None
_lib.sandlock_fork_result_free.argtypes = [_c_fork_result_p]

_lib.sandlock_wait.restype = ctypes.c_int
_lib.sandlock_wait.argtypes = [_c_sandbox_p]

_lib.sandlock_sandbox_free.restype = None
_lib.sandlock_sandbox_free.argtypes = [_c_sandbox_p]

# Checkpoint
_c_checkpoint_p = ctypes.c_void_p

_lib.sandlock_handle_checkpoint.restype = _c_checkpoint_p
_lib.sandlock_handle_checkpoint.argtypes = [_c_handle_p]

_lib.sandlock_checkpoint_save.restype = ctypes.c_int
_lib.sandlock_checkpoint_save.argtypes = [_c_checkpoint_p, ctypes.c_char_p]

_lib.sandlock_checkpoint_load.restype = _c_checkpoint_p
_lib.sandlock_checkpoint_load.argtypes = [ctypes.c_char_p]

_lib.sandlock_checkpoint_set_name.restype = None
_lib.sandlock_checkpoint_set_name.argtypes = [_c_checkpoint_p, ctypes.c_char_p]

_lib.sandlock_checkpoint_name.restype = ctypes.c_void_p
_lib.sandlock_checkpoint_name.argtypes = [_c_checkpoint_p]

_lib.sandlock_checkpoint_set_app_state.restype = None
_lib.sandlock_checkpoint_set_app_state.argtypes = [_c_checkpoint_p, ctypes.c_void_p, ctypes.c_size_t]

_lib.sandlock_checkpoint_app_state.restype = ctypes.c_void_p
_lib.sandlock_checkpoint_app_state.argtypes = [_c_checkpoint_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_checkpoint_free.restype = None
_lib.sandlock_checkpoint_free.argtypes = [_c_checkpoint_p]

_lib.sandlock_restore_interactive.restype = _c_handle_p
_lib.sandlock_restore_interactive.argtypes = [_c_policy_p, ctypes.c_char_p, _c_checkpoint_p]

_lib.sandlock_handle_restore_skipped_len.restype = ctypes.c_size_t
_lib.sandlock_handle_restore_skipped_len.argtypes = [_c_handle_p]

_lib.sandlock_handle_restore_skipped_fd.restype = ctypes.c_int
_lib.sandlock_handle_restore_skipped_fd.argtypes = [_c_handle_p, ctypes.c_size_t]

_lib.sandlock_handle_restore_skipped_path.restype = ctypes.c_void_p
_lib.sandlock_handle_restore_skipped_path.argtypes = [_c_handle_p, ctypes.c_size_t]


# ----------------------------------------------------------------
# Handler ABI — extension handlers for seccomp-notif syscalls.
#
# Structures mirror the C ABI in crates/sandlock-ffi/include/sandlock.h;
# the trampoline that drives these bindings lives in _handler_ffi.py.
# ----------------------------------------------------------------

# sandlock_notif_data_t — kernel seccomp-notification snapshot. The
# `args` array is fixed at 6 entries (the syscall ABI maximum).
class _SandlockNotifData(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("syscall_nr", ctypes.c_int32),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]


# sandlock_action_payload_t — the tagged union the setters fill in. The
# trampoline never reads these fields directly (it only ever calls the
# setters), but the layout must match so the struct is sized correctly.
class _SandlockActionPayload(ctypes.Union):
    _fields_ = [
        ("none", ctypes.c_uint64),
        ("errno_value", ctypes.c_int32),
        ("return_value", ctypes.c_int64),
        # inject_send: { int32 srcfd; uint32 newfd_flags; }
        ("inject_send", ctypes.c_uint32 * 2),
        # inject_send_tracked: { int32; uint32; uint64; } — reserved.
        ("inject_send_tracked", ctypes.c_uint64 * 2),
        # kill: { int32 sig; int32 pgid; }
        ("kill", ctypes.c_int32 * 2),
    ]


# sandlock_action_out_t — the slot a handler writes its decision into.
class _SandlockActionOut(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint32),
        ("payload", _SandlockActionPayload),
    ]


# sandlock_handler_registration_t — one (syscall_nr, handler) pair.
class _SandlockHandlerRegistration(ctypes.Structure):
    _fields_ = [
        ("syscall_nr", ctypes.c_int64),
        ("handler", ctypes.c_void_p),
    ]


_c_mem_handle_p = ctypes.c_void_p

# C handler signature:
#   int (*)(void *ud, const sandlock_notif_data_t *notif,
#           sandlock_mem_handle_t *mem, sandlock_action_out_t *out)
_HANDLER_FN_TYPE = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_void_p,                          # ud
    ctypes.POINTER(_SandlockNotifData),       # notif
    _c_mem_handle_p,                          # mem
    ctypes.POINTER(_SandlockActionOut),       # out
)

# void (*)(void *ud)
_UD_DROP_FN_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_void_p)

_c_handler_p = ctypes.c_void_p

_lib.sandlock_handler_new.restype = _c_handler_p
_lib.sandlock_handler_new.argtypes = [
    _HANDLER_FN_TYPE, ctypes.c_void_p, _UD_DROP_FN_TYPE, ctypes.c_uint32,
]

_lib.sandlock_handler_free.restype = None
_lib.sandlock_handler_free.argtypes = [_c_handler_p]

_lib.sandlock_handler_set_deferred.restype = None
_lib.sandlock_handler_set_deferred.argtypes = [_c_handler_p, ctypes.c_bool]

_lib.sandlock_run_with_handlers.restype = _c_result_p
_lib.sandlock_run_with_handlers.argtypes = [
    _c_policy_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint,
    ctypes.POINTER(_SandlockHandlerRegistration), ctypes.c_size_t,
]

_lib.sandlock_run_interactive_with_handlers.restype = _c_result_p
_lib.sandlock_run_interactive_with_handlers.argtypes = [
    _c_policy_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint,
    ctypes.POINTER(_SandlockHandlerRegistration), ctypes.c_size_t,
]

# Resolve a syscall name to its host-arch number; -1 on unknown/NULL.
_lib.sandlock_syscall_nr.restype = ctypes.c_int64
_lib.sandlock_syscall_nr.argtypes = [ctypes.c_char_p]

# Action setters — exactly one per action, called from the trampoline.
_lib.sandlock_action_set_continue.restype = None
_lib.sandlock_action_set_continue.argtypes = [ctypes.POINTER(_SandlockActionOut)]

_lib.sandlock_action_set_errno.restype = None
_lib.sandlock_action_set_errno.argtypes = [
    ctypes.POINTER(_SandlockActionOut), ctypes.c_int32,
]

_lib.sandlock_action_set_return_value.restype = None
_lib.sandlock_action_set_return_value.argtypes = [
    ctypes.POINTER(_SandlockActionOut), ctypes.c_int64,
]

_lib.sandlock_action_set_inject_fd_send.restype = None
_lib.sandlock_action_set_inject_fd_send.argtypes = [
    ctypes.POINTER(_SandlockActionOut), ctypes.c_int32, ctypes.c_uint32,
]

_lib.sandlock_action_set_hold.restype = None
_lib.sandlock_action_set_hold.argtypes = [ctypes.POINTER(_SandlockActionOut)]

_lib.sandlock_action_set_kill.restype = None
_lib.sandlock_action_set_kill.argtypes = [
    ctypes.POINTER(_SandlockActionOut), ctypes.c_int32, ctypes.c_int32,
]

# Child-memory accessors — valid only for the duration of a callback.
_lib.sandlock_mem_read_cstr.restype = ctypes.c_int
_lib.sandlock_mem_read_cstr.argtypes = [
    _c_mem_handle_p, ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

_lib.sandlock_mem_read.restype = ctypes.c_int
_lib.sandlock_mem_read.argtypes = [
    _c_mem_handle_p, ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

_lib.sandlock_mem_write.restype = ctypes.c_int
_lib.sandlock_mem_write.argtypes = [
    _c_mem_handle_p, ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
]


# ----------------------------------------------------------------
# SyscallEvent & PolicyContext (Python wrappers for policy_fn)
# ----------------------------------------------------------------

@dataclass(frozen=True)
class SyscallEvent:
    """An intercepted syscall event.

    Path strings are intentionally absent: the kernel re-reads user-memory
    pointers after a Continue response, so any path-string-based decision
    is racy (issue #27). Path-based access control belongs in static
    Landlock rules (``fs_readable``, ``fs_writable``, ``fs_denied``).

    ``argv`` *is* exposed for execve/execveat events and is TOCTOU-safe:
    the supervisor freezes the calling process's sibling threads via
    PTRACE_INTERRUPT before returning Continue, so the kernel's re-read
    sees the same memory the supervisor inspected. Siblings die during
    execve's de_thread step regardless, so the freeze has no observable
    cost.
    """
    syscall: str
    category: str  # "file", "network", "process", "memory"
    pid: int
    parent_pid: int = 0
    host: str | None = None
    port: int = 0
    argv: tuple[str, ...] | None = None
    denied: bool = False

    def argv_contains(self, s: str) -> bool:
        """Returns True if any argv element contains ``s``.

        Only meaningful for execve/execveat events.
        """
        return self.argv is not None and any(s in a for a in self.argv)


class PolicyContext:
    """Context for modifying sandbox policy from a callback."""

    def __init__(self, ctx_ptr):
        self._ptr = ctx_ptr

    def restrict_network(self, ips: list[str]) -> None:
        arr = (ctypes.c_char_p * len(ips))(*[_encode(ip) for ip in ips])
        _lib.sandlock_ctx_restrict_network(self._ptr, arr, len(ips))

    def grant_network(self, ips: list[str]) -> None:
        arr = (ctypes.c_char_p * len(ips))(*[_encode(ip) for ip in ips])
        _lib.sandlock_ctx_grant_network(self._ptr, arr, len(ips))

    def restrict_max_memory(self, bytes: int) -> None:
        _lib.sandlock_ctx_restrict_max_memory(self._ptr, bytes)

    def restrict_max_processes(self, n: int) -> None:
        _lib.sandlock_ctx_restrict_max_processes(self._ptr, n)

    def restrict_pid_network(self, pid: int, ips: list[str]) -> None:
        arr = (ctypes.c_char_p * len(ips))(*[_encode(ip) for ip in ips])
        _lib.sandlock_ctx_restrict_pid_network(self._ptr, pid, arr, len(ips))

    def deny_path(self, path: str) -> None:
        """Deny access to a path (checked on openat)."""
        _lib.sandlock_ctx_deny_path(self._ptr, _encode(path))

    def allow_path(self, path: str) -> None:
        """Remove a previously denied path."""
        _lib.sandlock_ctx_allow_path(self._ptr, _encode(path))


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _encode(s: str) -> bytes:
    if isinstance(s, str):
        result = s.encode("utf-8")
    elif isinstance(s, bytes):
        result = s
    else:
        result = str(s).encode("utf-8")
    if b'\x00' in result:
        raise ValueError(f"NUL byte in string argument: {result!r}")
    return result

def _make_argv(cmd: Sequence[str]):
    """Create a (c_char_p array, argc) pair from a list of strings."""
    argc = len(cmd)
    argv_type = ctypes.c_char_p * argc
    argv = argv_type(*[_encode(a) for a in cmd])
    return argv, ctypes.c_uint(argc)

def _read_result_bytes(result_p, fn) -> bytes:
    """Read stdout or stderr bytes from a result pointer."""
    length = ctypes.c_size_t(0)
    ptr = fn(result_p, ctypes.byref(length))
    if not ptr or length.value == 0:
        return b""
    return ctypes.string_at(ptr, length.value)


# ----------------------------------------------------------------
# Result
# ----------------------------------------------------------------

class ExitReason(IntEnum):
    """Why a sandboxed process terminated (mirrors the C ``sandlock_exit_reason``).

    Linux bottoms both a timeout and an OOM kill out in ``SIGKILL``, so there is
    no distinct OOM reason: a timeout sandlock enforced is ``TIMEOUT``, any other
    kill is ``KILLED``.
    """
    EXITED = 0
    """Exited normally with a code (see ``Result.exit_code``)."""
    SIGNALED = 1
    """Terminated by a signal (see ``Result.signal``)."""
    KILLED = 2
    """Killed with no recoverable signal number."""
    TIMEOUT = 3
    """Killed by sandlock because it exceeded its timeout."""


@dataclass
class Result:
    """Result of a sandboxed command."""
    success: bool
    exit_code: int = 0
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)
    error: str | None = None
    # Appended after the original fields so positional construction is unchanged.
    reason: ExitReason | None = None
    """Why the process terminated (timeout / signal / kill / normal exit);
    ``None`` on an error raised before a native result was produced."""
    signal: int = -1
    """Signal number for a ``SIGNALED`` result, else ``-1``."""


# ----------------------------------------------------------------
# Checkpoint
# ----------------------------------------------------------------

_DEFAULT_STORE = Path.home() / ".sandlock" / "checkpoints"


class SkippedFd(NamedTuple):
    """An fd that ``Sandbox.restore_interactive`` could not transparently
    recreate (socket, pipe, memfd, deleted or pseudo-filesystem path). The
    restored process runs without it; such resources fall to the
    ``app_state`` hatch."""

    fd: int
    """The fd number in the checkpointed process."""
    path: str
    """The resource the fd pointed at (e.g. ``pipe:[12345]``)."""


class Checkpoint:
    """A frozen snapshot of sandbox state (registers, memory, fds).

    Wraps a native checkpoint captured via ptrace + /proc.

    Usage::

        sb = Sandbox(fs_readable=["/usr", "/lib"])
        sb.spawn(["sleep", "60"])
        cp = sb.checkpoint()
        cp.save("my-checkpoint")

        # Later:
        cp2 = Checkpoint.load("my-checkpoint")
    """

    @staticmethod
    def _validate_name(name: str) -> None:
        """Reject checkpoint names that could escape the storage directory."""
        if not name or '/' in name or os.sep in name or name.startswith('.'):
            raise ValueError(
                f"Invalid checkpoint name: {name!r}. "
                "Use a simple name without path separators."
            )

    def __init__(self, ptr: int):
        self._ptr = ptr

    @property
    def name(self) -> str:
        """Checkpoint name."""
        raw = _lib.sandlock_checkpoint_name(self._ptr)
        if not raw:
            return ""
        # raw is a void pointer to a malloc'd C string
        c_str = ctypes.cast(raw, ctypes.c_char_p)
        name = c_str.value.decode("utf-8", errors="replace") if c_str.value else ""
        _lib.sandlock_string_free(c_str)
        return name

    @name.setter
    def name(self, value: str) -> None:
        _lib.sandlock_checkpoint_set_name(self._ptr, _encode(value))

    @property
    def app_state(self) -> bytes | None:
        """Optional application-level state bytes."""
        length = ctypes.c_size_t(0)
        ptr = _lib.sandlock_checkpoint_app_state(self._ptr, ctypes.byref(length))
        if not ptr or length.value == 0:
            return None
        return ctypes.string_at(ptr, length.value)

    @app_state.setter
    def app_state(self, data: bytes | None) -> None:
        if data is None:
            _lib.sandlock_checkpoint_set_app_state(self._ptr, None, 0)
        else:
            buf = ctypes.create_string_buffer(data)
            _lib.sandlock_checkpoint_set_app_state(
                self._ptr, ctypes.cast(buf, ctypes.c_void_p), len(data),
            )

    def save(self, name: str, *, store: Path | str | None = None) -> Path:
        """Persist this checkpoint under a named store.

        Storage layout::

            <store>/<name>/
            ├── meta.json
            ├── policy.dat
            ├── app_state.bin      (optional)
            └── process/
                ├── info.json
                ├── fds.json
                ├── memory_map.json
                ├── threads/0.bin
                └── memory/<i>.bin

        Args:
            name: Checkpoint name (used as directory name).
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Returns:
            Path to the checkpoint directory.
        """
        self._validate_name(name)
        root = Path(store) if store is not None else _DEFAULT_STORE
        root.mkdir(parents=True, exist_ok=True)
        cp_dir = root / name
        self.name = name
        rc = _lib.sandlock_checkpoint_save(self._ptr, _encode(str(cp_dir)))
        if rc != 0:
            raise RuntimeError(f"Failed to save checkpoint to {cp_dir}")
        return cp_dir

    @classmethod
    def load(
        cls,
        name: str,
        *,
        store: Path | str | None = None,
        restore_fn: "Callable[[bytes], None] | None" = None,
    ) -> "Checkpoint":
        """Load a named checkpoint from disk.

        ``restore_fn`` mirrors ``save_fn`` on ``Sandbox.checkpoint``: use it
        to rebuild application-level state that ptrace cannot capture (caches,
        session data, etc.). Neither is mandatory, and they need not be
        paired: ``restore_fn`` is called with ``cp.app_state`` only when the
        checkpoint carries app state, and app state left unconsumed here
        remains readable via ``cp.app_state``. Restoring the OS-level process
        image is separate: see ``Sandbox.restore_interactive``.

        Args:
            name: Checkpoint name.
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.
            restore_fn: Optional callback receiving the saved
                application-level state bytes; not called if the checkpoint
                has no app state.

        Returns:
            The loaded Checkpoint.

        Raises:
            FileNotFoundError: If the checkpoint does not exist.
        """
        cls._validate_name(name)
        root = Path(store) if store is not None else _DEFAULT_STORE
        cp_dir = root / name
        if not cp_dir.is_dir():
            raise FileNotFoundError(f"Checkpoint not found: {cp_dir}")
        ptr = _lib.sandlock_checkpoint_load(_encode(str(cp_dir)))
        if not ptr:
            raise RuntimeError(f"Failed to load checkpoint from {cp_dir}")
        cp = cls(ptr)
        if restore_fn is not None:
            state = cp.app_state
            if state is not None:
                restore_fn(state)
        return cp

    @classmethod
    def list(cls, *, store: Path | str | None = None) -> list[str]:
        """List all named checkpoints.

        Args:
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Returns:
            Sorted list of checkpoint names.
        """
        root = Path(store) if store is not None else _DEFAULT_STORE
        if not root.is_dir():
            return []
        return sorted(
            d.name for d in root.iterdir()
            if d.is_dir() and (d / "meta.json").exists()
        )

    @classmethod
    def delete(cls, name: str, *, store: Path | str | None = None) -> None:
        """Delete a named checkpoint.

        Args:
            name: Checkpoint name.
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Raises:
            FileNotFoundError: If the checkpoint does not exist.
        """
        import shutil
        cls._validate_name(name)
        root = Path(store) if store is not None else _DEFAULT_STORE
        cp_dir = root / name
        if not cp_dir.is_dir():
            raise FileNotFoundError(f"Checkpoint not found: {cp_dir}")
        shutil.rmtree(cp_dir)

    def __del__(self):
        if getattr(self, "_ptr", None):
            _lib.sandlock_checkpoint_free(self._ptr)
            self._ptr = None


# ----------------------------------------------------------------
# Policy (native handle)
# ----------------------------------------------------------------

class _NativePolicy:
    """Wraps a native sandlock_policy_t (Sandbox config) pointer."""

    def __init__(self, ptr: int):
        self._ptr = ptr

    @property
    def ptr(self):
        return self._ptr

    def __del__(self):
        if self._ptr:
            _lib.sandlock_sandbox_free(self._ptr)
            self._ptr = None

    # Fields handled by _build_from_policy (sent to FFI) or intentionally
    # managed outside it (policy_fn is wired in from_dataclass; notif_policy
    # is Python-side only; no_coredump is a Python convenience alias).
    _HANDLED_FIELDS: set[str] = {
        "fs_writable", "fs_readable", "fs_denied", "fs_storage",
        "workdir", "cwd", "chroot", "fs_mount", "on_exit", "on_error",
        "max_memory", "max_disk", "max_processes", "max_cpu", "num_cpus",
        "cpu_cores", "gpu_devices",
        "net_allow", "net_deny", "net_allow_bind", "net_deny_bind",
        "port_remap",
        "pid_ns", "net_isolation", "fd_inject_connect", "port_mappings",
        "http_allow", "http_deny", "http_ports", "http_ca", "http_key",
        "http_inject_ca", "http_ca_out", "http_inject", "host_mask",
        "egress_proxy", "uid", "gid", "mediation_run_as",
        "notify_rate_limit",
        "random_seed", "time_start", "clean_env", "env",
        "extra_deny_syscalls", "extra_allow_syscalls", "max_open_files",
        "no_randomize_memory", "no_huge_pages", "no_coredump", "deterministic_dirs",
        # Landlock protection opt-out (see Protection IntEnum):
        "allow_degraded", "disable",
        # Managed outside _build_from_policy:
        "notif_policy",
        # Runtime-only kwargs — not sent to FFI:
        "name", "policy_fn", "init_fn", "work_fn",
    }

    @staticmethod
    def _build_from_policy(policy: PolicyDataclass):
        """Build a native builder from a Python Sandbox dataclass. Returns builder pointer."""
        from .sandbox import parse_memory_size

        b = _lib.sandlock_sandbox_builder_new()

        for p in (policy.fs_readable or []):
            if str(p) == "/lib64" and not os.path.exists("/lib64"):
                continue
            b = _b_fs_read(b, _encode(str(p)))
        for p in (policy.fs_writable or []):
            b = _b_fs_write(b, _encode(str(p)))
        for p in (policy.fs_denied or []):
            b = _b_fs_deny(b, _encode(str(p)))

        if policy.fs_storage:
            b = _b_fs_storage(b, _encode(str(policy.fs_storage)))

        if policy.gpu_devices is not None:
            arr = (ctypes.c_uint32 * len(policy.gpu_devices))(*policy.gpu_devices)
            b = _b_gpu_devices(b, arr, len(policy.gpu_devices))

        if policy.workdir:
            b = _b_workdir(b, _encode(str(policy.workdir)))
        if policy.cwd:
            b = _b_cwd(b, _encode(str(policy.cwd)))
        if policy.chroot:
            b = _b_chroot(b, _encode(str(policy.chroot)))
        for vp, hp in (policy.fs_mount or {}).items():
            b = _b_fs_mount(b, _encode(str(vp)), _encode(str(hp)))

        # COW branch actions (0=Commit, 1=Abort, 2=Keep)
        _action_map = {"commit": 0, "abort": 1, "keep": 2}
        on_exit_val = policy.on_exit.value if hasattr(policy.on_exit, 'value') else str(policy.on_exit)
        on_error_val = policy.on_error.value if hasattr(policy.on_error, 'value') else str(policy.on_error)
        b = _b_on_exit(b, _action_map.get(on_exit_val, 0))
        b = _b_on_error(b, _action_map.get(on_error_val, 1))

        if policy.max_memory is not None:
            if isinstance(policy.max_memory, str):
                mem_bytes = parse_memory_size(policy.max_memory)
            else:
                mem_bytes = int(policy.max_memory)
            b = _b_max_memory(b, mem_bytes)

        if policy.max_disk is not None:
            if isinstance(policy.max_disk, str):
                disk_bytes = parse_memory_size(policy.max_disk)
            else:
                disk_bytes = int(policy.max_disk)
            b = _b_max_disk(b, disk_bytes)

        if policy.max_processes != 256:
            b = _b_max_processes(b, policy.max_processes)
        if policy.max_cpu is not None:
            b = _b_max_cpu(b, policy.max_cpu)
        if policy.notify_rate_limit is not None:
            b = _b_notify_rate_limit(b, policy.notify_rate_limit)
        if policy.num_cpus is not None:
            b = _b_num_cpus(b, policy.num_cpus)
        if policy.cpu_cores is not None:
            arr = (ctypes.c_uint32 * len(policy.cpu_cores))(*policy.cpu_cores)
            b = _b_cpu_cores(b, arr, len(policy.cpu_cores))

        # net_allow: list of endpoint specs. Bare `host:port` means TCP
        # and UDP; `tcp://`/`udp://`/`icmp://` schemes pin one protocol.
        # Empty = deny all outbound. net_deny is the inverse (default-allow
        # denylist of IP/CIDR/port specs); the two are mutually exclusive.
        # Validation of each spec happens in the native build().
        for spec in (policy.net_allow or []):
            b = _b_net_allow(b, _encode(str(spec)))
        for spec in (policy.net_deny or []):
            b = _b_net_deny(b, _encode(str(spec)))
        for spec in (policy.net_allow_bind or []):
            b = _b_net_allow_bind(b, _encode(str(spec)))
        for spec in (policy.net_deny_bind or []):
            b = _b_net_deny_bind(b, _encode(str(spec)))
        for rule in (policy.http_allow or []):
            b = _b_http_allow(b, _encode(str(rule)))
        for rule in (policy.http_deny or []):
            b = _b_http_deny(b, _encode(str(rule)))
        for port in (policy.http_ports or []):
            b = _b_http_port(b, int(port))
        if policy.http_ca:
            b = _b_http_ca(b, _encode(str(policy.http_ca)))
        if policy.http_key:
            b = _b_http_key(b, _encode(str(policy.http_key)))
        for path in (policy.http_inject_ca or []):
            b = _b_http_inject_ca(b, _encode(str(path)))
        if policy.http_ca_out:
            b = _b_http_ca_out(b, _encode(str(policy.http_ca_out)))
        for index, rule in enumerate(policy.http_inject or []):
            name, secret, auth_rule = _serialize_http_inject(rule, index)
            b = _b_credential(b, _encode(name), _encode(secret))
            b = _b_http_auth(b, _encode(auth_rule))
        if policy.host_mask:
            b = _b_host_mask(b, _encode(str(policy.host_mask)))
        if policy.egress_proxy:
            if not isinstance(policy.egress_proxy, dict):
                raise ValueError("egress_proxy must be a dict")
            unknown = set(policy.egress_proxy) - {"address", "username", "password"}
            if unknown:
                raise ValueError(
                    f"egress_proxy unknown field(s): {sorted(unknown)}"
                )
            address = policy.egress_proxy.get("address")
            if not isinstance(address, str) or not address:
                raise ValueError("egress_proxy.address must be a non-empty string")
            b = _b_egress_proxy(b, _encode(address))
            username = policy.egress_proxy.get("username")
            password = policy.egress_proxy.get("password")
            if username is not None or password is not None:
                if not isinstance(username, str) or not isinstance(password, str):
                    raise ValueError(
                        "egress_proxy.username/password must be strings"
                    )
                b = _b_egress_proxy_credentials(
                    b, _encode(username), _encode(password)
                )

        if policy.port_remap:
            b = _b_port_remap(b, True)

        if policy.pid_ns:
            b = _b_pid_ns(b, True)
        if policy.net_isolation:
            b = _b_net_isolation(b, True)
        if policy.fd_inject_connect:
            b = _b_fd_inject_connect(b, True)
        for host_port, sandbox_port in sorted((policy.port_mappings or {}).items()):
            b = _b_net_bind_map(b, int(host_port), int(sandbox_port))

        if policy.uid is not None or policy.gid is not None:
            if policy.uid is None or policy.gid is None:
                raise ValueError("uid and gid must both be set (or both unset)")
            b = _b_user(b, policy.uid, policy.gid)

        if policy.mediation_run_as != "caller":
            # 1 = supervisor (explicit downgrade tier); 0 = caller (default).
            b = _b_mediation_run_as(b, 1)

        if policy.random_seed is not None:
            b = _b_random_seed(b, policy.random_seed)
        if policy.time_start is not None:
            epoch_secs = int(policy.time_start.timestamp()) if hasattr(policy.time_start, 'timestamp') else int(policy.time_start)
            b = _b_time_start(b, epoch_secs)
        if policy.clean_env:
            b = _b_clean_env(b, True)
        for k, v in (policy.env or {}).items():
            b = _b_env_var(b, _encode(k), _encode(v))

        if policy.extra_deny_syscalls:
            b = _b_extra_deny_syscalls(b, _encode(",".join(policy.extra_deny_syscalls or [])))
        if policy.extra_allow_syscalls:
            b = _b_extra_allow_syscalls(b, _encode(",".join(policy.extra_allow_syscalls or [])))
        if policy.max_open_files is not None:
            b = _b_max_open_files(b, policy.max_open_files)

        if policy.no_randomize_memory:
            b = _b_no_randomize_memory(b, True)
        if policy.no_huge_pages:
            b = _b_no_huge_pages(b, True)
        if policy.no_coredump:
            b = _b_no_coredump(b, True)
        if policy.deterministic_dirs:
            b = _b_deterministic_dirs(b, True)

        # Landlock protection opt-out. The C ABI setters use move-semantics
        # and return the (possibly relocated) builder pointer — mirror that
        # by rebinding `b` on each call. Idempotent / last-wins: if the
        # same Protection appears in both lists, the later call wins
        # (matching the underlying `ProtectionPolicy::set` semantics).
        for p in (policy.allow_degraded or ()):
            b = _b_allow_degraded(b, _validate_protection(p, field="allow_degraded"))
        for p in (policy.disable or ()):
            b = _b_disable(b, _validate_protection(p, field="disable"))

        # Guard: warn if any dataclass field was set to a non-default value
        # but is not in _HANDLED_FIELDS (i.e. silently dropped).
        import dataclasses as _dc
        import warnings as _w
        from .sandbox import Sandbox as _Sandbox
        _defaults = _Sandbox()
        for f in _dc.fields(policy):
            if f.name in _NativePolicy._HANDLED_FIELDS:
                continue
            val = getattr(policy, f.name)
            default_val = getattr(_defaults, f.name)
            if val != default_val:
                _w.warn(
                    f"Policy field {f.name!r} is set but not wired through "
                    f"FFI — it will have no effect (value: {val!r})",
                    stacklevel=3,
                )

        return b

    @classmethod
    def from_dataclass(cls, policy: PolicyDataclass, policy_fn=None) -> _NativePolicy:
        """Build a native policy from a Python Policy dataclass."""
        b = _NativePolicy._build_from_policy(policy)

        # Store callback reference to prevent GC
        c_callback = None
        if policy_fn is not None:
            def _c_callback(event_p, ctx_p, _user_data):
                ev = event_p.contents
                py_argv = None
                if ev.argv and ev.argc > 0:
                    py_argv = tuple(
                        ev.argv[i].decode("utf-8", errors="replace")
                        for i in range(ev.argc)
                        if ev.argv[i]
                    )
                _CATEGORIES = {0: "file", 1: "network", 2: "process", 3: "memory"}
                py_event = SyscallEvent(
                    syscall=ev.syscall.decode("utf-8") if ev.syscall else "",
                    category=_CATEGORIES.get(ev.category, "file"),
                    pid=ev.pid,
                    parent_pid=ev.parent_pid,
                    host=ev.host.decode("utf-8") if ev.host else None,
                    port=ev.port,
                    argv=py_argv,
                    denied=ev.denied,
                )
                py_ctx = PolicyContext(ctx_p)
                result = policy_fn(py_event, py_ctx)
                # Return: 0=allow, -1=deny, -2=audit, positive=deny with errno
                # Python callback can return:
                #   None/False/0  → allow
                #   True/-1       → deny (EPERM)
                #   positive int  → deny with that errno
                #   "audit"/-2    → audit (allow + flag)
                if result is None or result is False or result == 0:
                    return 0
                if result is True or result == -1:
                    return -1
                if result == "audit" or result == -2:
                    return -2
                if isinstance(result, int) and result > 0:
                    return result
                # Unrecognized return values fail closed (deny) rather than
                # silently allowing the syscall.
                return -1

            c_callback = _POLICY_FN_TYPE(_c_callback)
            b = _lib.sandlock_sandbox_builder_policy_fn(b, c_callback, None, None)

        err = ctypes.c_int(0)
        err_msg = ctypes.c_char_p()
        ptr = _lib.sandlock_sandbox_build(b, ctypes.byref(err), ctypes.byref(err_msg))
        if not ptr or err.value != 0:
            # err_msg.value is a copy of the C string's bytes; the
            # underlying allocation still needs releasing afterwards.
            # When the FFI leaves err_msg null (e.g. internal binding
            # bug), raise without a message rather than inventing one.
            msg = err_msg.value.decode("utf-8", "replace") if err_msg.value else None
            if err_msg.value:
                _lib.sandlock_string_free(err_msg)
            raise RuntimeError(msg) if msg else RuntimeError()
        native = _NativePolicy(ptr)
        native._c_callback = c_callback  # prevent GC
        return native


# ----------------------------------------------------------------
# ForkResult (holds clone handles with pipes for reduce)
# ----------------------------------------------------------------

class ForkResult:
    """Result of fork() — holds clone handles and stdout pipes.

    Pass to reducer.reduce() to pipe clone output to the reducer.
    Can also iterate clones via indexing or len().
    """

    def __init__(self, ptr, pids: list[int], native_policy):
        self._ptr = ptr  # sandlock_fork_result_t (owns pipes)
        self.pids = pids
        self._native_policy = native_policy

    def __len__(self):
        return len(self.pids)

    def __getitem__(self, i):
        return self.pids[i]

    def __del__(self):
        if self._ptr is not None:
            _lib.sandlock_fork_result_free(self._ptr)
            self._ptr = None


# ----------------------------------------------------------------
# Stage & Pipeline
# ----------------------------------------------------------------

class Stage:
    """A lazy command bound to a Sandbox. Not executed until .run()."""

    def __init__(self, sandbox: PolicyDataclass, args: list[str]):
        self.sandbox = sandbox
        self.args = args

    def as_(self, name: str) -> NamedStage:
        """Label this stage's output for use in a gather pattern."""
        return NamedStage(self, name)

    def run(self, timeout: float | None = None) -> Result:
        """Run this single stage."""
        return self.sandbox.run(self.args)

    def __or__(self, other: Stage | Pipeline) -> Pipeline:
        if isinstance(other, Pipeline):
            return Pipeline([self] + other.stages)
        return Pipeline([self, other])


class NamedStage:
    """A Stage with a named output for gather patterns."""

    def __init__(self, stage: Stage, name: str):
        self.stage = stage
        self.name = name

    def __add__(self, other: NamedStage | Gather) -> Gather:
        if isinstance(other, Gather):
            return Gather([(self.name, self.stage)] + other.sources)
        return Gather([(self.name, self.stage), (other.name, other.stage)])


class Gather:
    """A set of named stages to be gathered into a consumer.

    Usage::

        result = (
            Sandbox(...).cmd(["produce_code"]).as_("code")
            + Sandbox(...).cmd(["produce_data"]).as_("data")
            | Sandbox(...).cmd(["python3", "consume.py"])
        ).run()

    The consumer script imports ``from sandlock import inputs`` to read
    producer outputs by name.
    """

    def __init__(self, sources: list[tuple[str, Stage]]):
        self.sources = sources

    def __add__(self, other: NamedStage | Gather) -> Gather:
        if isinstance(other, Gather):
            return Gather(self.sources + other.sources)
        return Gather(self.sources + [(other.name, other.stage)])

    def __or__(self, other: Stage) -> GatherPipeline:
        return GatherPipeline(self.sources, other)


class GatherPipeline:
    """Fan-in pipeline: multiple producers → one consumer via pipes.

    Producer outputs are available in the consumer via
    ``from sandlock import inputs``.
    """

    def __init__(self, sources: list[tuple[str, Stage]], consumer: Stage):
        self.sources = sources
        self.consumer = consumer

    def run(self, timeout: float | None = None) -> Result:
        """Run all producers in parallel, pipe outputs to consumer.

        Each producer's stdout is connected to the consumer via a Unix pipe.
        The last source maps to stdin (fd 0), others to fd 3, 4, 5, ...
        The consumer reads them via ``from sandlock import inputs``.
        """
        # Build the gather via FFI
        gather_p = _lib.sandlock_gather_new()

        for name, stage in self.sources:
            name_b = name.encode("utf-8") + b"\x00"
            argv, argc = _make_argv(stage.args)
            _lib.sandlock_gather_add_source(
                gather_p,
                ctypes.c_char_p(name_b),
                stage.sandbox._ensure_native().ptr,
                argv, argc,
            )

        consumer_argv, consumer_argc = _make_argv(self.consumer.args)
        _lib.sandlock_gather_set_consumer(
            gather_p,
            self.consumer.sandbox._ensure_native().ptr,
            consumer_argv, consumer_argc,
        )

        timeout_ms = int(timeout * 1000) if timeout else 0
        result_p = _lib.sandlock_gather_run(gather_p, timeout_ms)

        if not result_p:
            error = "Gather timed out" if timeout else "Gather failed"
            return Result(success=False, exit_code=-1, error=error)

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        reason = ExitReason(_lib.sandlock_result_reason(result_p))
        signal = _lib.sandlock_result_signal(result_p)
        out_bytes = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        error = None
        if reason == ExitReason.TIMEOUT:
            error = "Gather timed out"

        return Result(
            success=bool(success),
            exit_code=exit_code,
            reason=reason,
            signal=signal,
            stdout=out_bytes,
            stderr=stderr,
            error=error,
        )


class Pipeline:
    """A chain of stages connected by pipes.

    Usage::

        result = (
            Sandbox(...).cmd(["echo", "hello"])
            | Sandbox(...).cmd(["tr", "a-z", "A-Z"])
        ).run()
        assert b"HELLO" in result.stdout
    """

    def __init__(self, stages: list[Stage]):
        if len(stages) < 2:
            raise ValueError("Pipeline requires at least 2 stages")
        self.stages = stages

    def __or__(self, other: Stage | Pipeline) -> Pipeline:
        if isinstance(other, Pipeline):
            return Pipeline(self.stages + other.stages)
        return Pipeline(self.stages + [other])

    def run(
        self,
        stdout: int | None = None,
        timeout: float | None = None,
    ) -> Result:
        """Run the pipeline. Returns the last stage's result.

        If ``stdout`` is a file descriptor, the last stage's stdout is
        redirected there and ``result.stdout`` will be empty.
        """
        pipe_p = _lib.sandlock_pipeline_new()

        for stage in self.stages:
            argv, argc = _make_argv(stage.args)
            _lib.sandlock_pipeline_add_stage(
                pipe_p, stage.sandbox._ensure_native().ptr, argv, argc,
            )

        timeout_ms = int(timeout * 1000) if timeout else 0
        # pipeline_run consumes pipe_p
        result_p = _lib.sandlock_pipeline_run(pipe_p, timeout_ms)

        if not result_p:
            error = "Pipeline timed out" if timeout else "Pipeline failed"
            return Result(success=False, exit_code=-1, error=error)

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        reason = ExitReason(_lib.sandlock_result_reason(result_p))
        signal = _lib.sandlock_result_signal(result_p)
        out_bytes = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        # Handle stdout fd redirection
        if stdout is not None and out_bytes:
            os.write(stdout, out_bytes)
            out_bytes = b""

        error = None
        if reason == ExitReason.TIMEOUT:
            error = "Pipeline timed out"

        return Result(
            success=bool(success),
            exit_code=exit_code,
            reason=reason,
            signal=signal,
            stdout=out_bytes,
            stderr=stderr,
            error=error,
        )
