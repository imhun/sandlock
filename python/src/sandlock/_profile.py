# SPDX-License-Identifier: Apache-2.0
"""TOML profile loading for Sandlock.

Profiles use the sectioned policy schema (the same one parsed by the
Rust CLI). Each section maps to a subset of ``Sandbox`` fields:

    [config]      → http_ca, http_key, fs_storage, workdir
    [determinism] → random_seed, time_start, deterministic_dirs,
                    no_randomize_memory
    [program]     → env, cwd, uid, clean_env, no_coredump, no_huge_pages
                    (``exec`` and ``args`` are runtime program identity
                    and are silently ignored — pass them to
                    ``sandbox.run(cmd)`` instead)
    [filesystem]  → fs_readable (read), fs_writable (write),
                    fs_denied (deny), chroot,
                    fs_mount (mount), on_exit, on_error
                    (mount entries are ``"VIRTUAL:HOST"`` only; a trailing
                    ``:ro``/``:rw`` is part of the CLI's grammar, not this
                    one, and is rejected; ``:ro`` because this mapping
                    cannot express a read-only mount at all)
    [network]     → net_allow_bind (allow_bind), net_deny_bind (deny_bind), net_allow (allow), net_deny (deny), port_remap
    [http]        → http_ports (ports), http_allow (allow),
                    http_deny (deny), http_inject (inject), host_mask
                    (host_mask)
    [syscalls]    → extra_allow_syscalls (extra_allow),
                    extra_deny_syscalls (extra_deny)
    [limits]      → max_memory (memory), max_processes (processes),
                    max_open_files (open_files), max_cpu (cpu),
                    max_disk (disk), gpu_devices, cpu_cores, num_cpus
"""

from __future__ import annotations

import os
import pwd
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from pathlib import Path
from typing import Any

from .exceptions import PolicyError
from .sandbox import BranchAction, Sandbox


_PROFILES_DIR = Path("~/.config/sandlock/profiles").expanduser()


# Per-section schema. Each entry maps a TOML field name to
# (sandbox-attribute name, expected python type).  A sandbox-attribute
# name of ``None`` means the field is recognised but silently ignored
# (used for [program].exec and [program].args, which are runtime
# program identity, not Sandbox config).
_SECTIONS: dict[str, dict[str, tuple[str | None, type]]] = {
    "config": {
        "http_ca":    ("http_ca",    str),
        "http_key":   ("http_key",   str),
        "http_inject_ca": ("http_inject_ca", list),
        "http_ca_out":    ("http_ca_out",    str),
        "fs_storage": ("fs_storage", str),
        "workdir":    ("workdir",    str),
    },
    "determinism": {
        "random_seed":         ("random_seed",         int),
        "time_start":          ("time_start",          str),
        "deterministic_dirs":  ("deterministic_dirs",  bool),
        "no_randomize_memory": ("no_randomize_memory", bool),
    },
    "program": {
        "exec":          (None,            str),
        "args":          (None,            list),
        "env":           ("env",           dict),
        "cwd":           ("cwd",           str),
        "uid":           ("uid",           int),
        "clean_env":     ("clean_env",     bool),
        "no_coredump":   ("no_coredump",   bool),
        "no_huge_pages": ("no_huge_pages", bool),
    },
    "filesystem": {
        "read":      ("fs_readable",  list),
        "write":     ("fs_writable",  list),
        "deny":      ("fs_denied",    list),
        "chroot":    ("chroot",       str),
        "mount":     ("fs_mount",     list),
        "on_exit":   ("on_exit",      str),
        "on_error":  ("on_error",     str),
    },
    "network": {
        "allow_bind": ("net_allow_bind", list),
        "deny_bind":  ("net_deny_bind", list),
        "allow":      ("net_allow",  list),
        "deny":       ("net_deny",   list),
        "port_remap": ("port_remap", bool),
        "netns":      ("netns",      bool),
    },
    "http": {
        "ports":     ("http_ports", list),
        "allow":     ("http_allow", list),
        "deny":      ("http_deny",  list),
        "inject":    ("http_inject", list),
        "host_mask": ("host_mask",  str),
    },
    "syscalls": {
        "extra_allow": ("extra_allow_syscalls", list),
        "extra_deny":  ("extra_deny_syscalls",  list),
    },
    "limits": {
        "memory":      ("max_memory",     str),
        "processes":   ("max_processes",  int),
        "open_files":  ("max_open_files", int),
        "cpu":         ("max_cpu",        int),
        "disk":        ("max_disk",       str),
        "gpu_devices": ("gpu_devices",    list),
        "cpu_cores":   ("cpu_cores",      list),
        "num_cpus":    ("num_cpus",       int),
    },
}


_VARS = ("HOME",)

# Sandbox attribute names whose values are paths. Program args and env are
# data belonging to the sandboxed program and are never expanded.
_PATH_KEYS = frozenset({
    "http_ca", "http_key", "http_ca_out", "fs_storage", "workdir", "cwd", "chroot",
})
_PATH_LIST_KEYS = frozenset({
    "http_inject_ca", "fs_readable", "fs_writable", "fs_denied",
})


def _resolve_home() -> str:
    """Resolve ``${HOME}``.

    The environment wins over passwd because the sandboxed program resolves
    its own ``~`` through ``$HOME``.
    """
    env = os.environ.get("HOME")
    if env and _usable_home(env):
        return env
    try:
        entry = pwd.getpwuid(os.getuid())
    except KeyError:
        entry = None
    if entry is not None and _usable_home(entry.pw_dir):
        return entry.pw_dir
    raise PolicyError(
        "cannot resolve ${HOME}: $HOME is unset, not absolute, or is the "
        "filesystem root, and this uid has no passwd entry with a usable "
        "home directory"
    )


def _usable_home(directory: str) -> bool:
    """Reject ``/`` alongside the relative and empty cases.

    It is nobody's home, and expanding it would turn ``write = ["${HOME}"]``
    into a grant over the entire filesystem, which is the one thing a sandbox
    must never hand out by accident.
    """
    return directory.startswith("/") and directory.rstrip("/") != ""


def _well_formed(name: str) -> bool:
    if not name or not (name[0].isascii() and (name[0].isalpha() or name[0] == "_")):
        return False
    return all(c.isascii() and (c.isalnum() or c == "_") for c in name[1:])


def _lookup(name: str, home: str, value: str) -> str:
    if not _well_formed(name):
        raise PolicyError(
            f"{value!r}: malformed variable name ${{{name}}}; "
            "names match [A-Za-z_][A-Za-z0-9_]*"
        )
    if name == "HOME":
        return home
    suggestion = ""
    for known in _VARS:
        if known.lower() == name.lower():
            suggestion = f"; did you mean ${{{known}}}?"
            break
    supported = ", ".join(f"${{{v}}}" for v in _VARS)
    raise PolicyError(
        f"{value!r}: unknown variable ${{{name}}}{suggestion}; supported: {supported}"
    )


def _expand(value: str, home: str) -> str:
    """Expand ``${HOME}`` in one profile path value.

    Every unrecognised form raises, so adding a variable later cannot
    silently reinterpret a grant written today.
    """
    if value.startswith("~"):
        raise PolicyError(
            f"{value!r}: tilde is not expanded in profiles; write ${{HOME}} instead"
        )
    out: list[str] = []
    rest = value
    while True:
        pos = rest.find("$")
        if pos < 0:
            out.append(rest)
            return "".join(out)
        out.append(rest[:pos])
        after = rest[pos + 1:]
        if after.startswith("{"):
            tail = after[1:]
            end = tail.find("}")
            if end < 0:
                raise PolicyError(f"{value!r}: unterminated ${{")
            out.append(_lookup(tail[:end], home, value))
            rest = tail[end + 1:]
        else:
            name = ""
            for c in after:
                if c.isascii() and (c.isalnum() or c == "_"):
                    name += c
                else:
                    break
            if name:
                raise PolicyError(
                    f"{value!r}: bare $ is not a variable; write ${{{name}}} "
                    "for a variable"
                )
            raise PolicyError(
                f"{value!r}: bare $ is not allowed; a literal $ cannot appear "
                "in a profile path"
            )


def profiles_dir() -> Path:
    """Return the profiles directory path."""
    return _PROFILES_DIR


def list_profiles() -> list[str]:
    """Return sorted names of available profiles."""
    if not _PROFILES_DIR.is_dir():
        return []
    return sorted(
        p.stem for p in _PROFILES_DIR.glob("*.toml") if p.is_file()
    )


def load_profile(name: str) -> Sandbox:
    """Load a named profile and return a Sandbox.

    Raises:
        PolicyError: If the profile doesn't exist or has invalid fields.
    """
    path = _PROFILES_DIR / f"{name}.toml"
    if not path.is_file():
        raise PolicyError(f"profile not found: {path}")
    return load_profile_path(path)


def load_profile_path(path: Path) -> Sandbox:
    """Load a profile from a file path and return a Sandbox.

    Raises:
        PolicyError: If the file can't be parsed or has invalid fields.
    """
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"invalid TOML in {path}: {e}") from e

    return policy_from_dict(data, source=str(path))


def policy_from_dict(data: dict, source: str = "<dict>") -> Sandbox:
    """Construct a Sandbox from a parsed sectioned-TOML dict.

    Each top-level key must be a known schema section (``config``,
    ``determinism``, ``program``, ``filesystem``, ``network``, ``http``,
    ``syscalls``, ``limits``).  Within each section, only the documented
    fields are accepted.

    Raises:
        PolicyError: If unknown section / field names appear or types mismatch.
    """
    if not isinstance(data, dict):
        raise PolicyError(
            f"{source}: expected a TOML table at the top level, "
            f"got {type(data).__name__}"
        )

    unknown_sections = set(data.keys()) - set(_SECTIONS.keys())
    if unknown_sections:
        raise PolicyError(
            f"{source}: unknown section(s): "
            f"{', '.join(sorted(unknown_sections))}"
        )

    kwargs: dict[str, Any] = {}
    # One-element cache so a profile with no variables never resolves home.
    home: list[str] = []
    filesystem = data.get("filesystem")
    chroot = isinstance(filesystem, dict) and "chroot" in filesystem

    for section_name, section_data in data.items():
        if not isinstance(section_data, dict):
            raise PolicyError(
                f"{source}: [{section_name}] must be a TOML table, "
                f"got {type(section_data).__name__}"
            )
        schema = _SECTIONS[section_name]
        unknown_fields = set(section_data.keys()) - set(schema.keys())
        if unknown_fields:
            raise PolicyError(
                f"{source}: unknown field(s) in [{section_name}]: "
                f"{', '.join(sorted(unknown_fields))}"
            )
        for toml_key, value in section_data.items():
            sandbox_key, expected_type = schema[toml_key]
            if sandbox_key is None:
                # [program].exec / [program].args — silently ignored.
                continue
            if not isinstance(value, expected_type):
                raise PolicyError(
                    f"{source}: [{section_name}].{toml_key} expected "
                    f"{expected_type.__name__}, got {type(value).__name__}"
                )
            value = _coerce(
                section_name, toml_key, sandbox_key, value, source, home, chroot
            )
            kwargs[sandbox_key] = value

    return Sandbox(**kwargs)


def _coerce(
    section: str, toml_key: str, sandbox_key: str, value: Any, source: str,
    home: list[str], chroot: bool,
) -> Any:
    """Per-field value coercion (enums, mount-spec parsing, port lists)."""

    def expand(text: str) -> str:
        if "$" not in text and not text.startswith("~"):
            return text
        if chroot:
            # Expanding anyway builds the rule from a host path that does not
            # exist in the jail, and Landlock then skips it in silence.
            raise PolicyError(
                f"{source}: [{section}].{toml_key}: {text!r}: ${{HOME}} cannot "
                "be expanded under [filesystem].chroot, where paths name the "
                "jail rather than the host. Write the path as it exists inside "
                "the jail"
            )
        if not home:
            home.append(_resolve_home())
        try:
            return _expand(text, home[0])
        except PolicyError as e:
            raise PolicyError(f"{source}: [{section}].{toml_key}: {e}") from None

    if sandbox_key in _PATH_KEYS:
        return expand(value)
    if sandbox_key in _PATH_LIST_KEYS:
        return [expand(v) for v in value]
    if sandbox_key in ("on_exit", "on_error"):
        try:
            return BranchAction(value)
        except ValueError:
            raise PolicyError(
                f"{source}: [{section}].{toml_key} must be "
                f"'commit', 'abort', or 'keep', got {value!r}"
            )
    if sandbox_key == "fs_mount":
        # TOML form is ``["VIRTUAL:HOST", ...]``;
        # Sandbox.fs_mount is dict[str, str].
        mount: dict[str, str] = {}
        for spec in value:
            if not isinstance(spec, str):
                raise PolicyError(
                    f"{source}: [{section}].{toml_key} entries must be "
                    f"'VIRTUAL:HOST' strings, got {type(spec).__name__}"
                )
            if ":" not in spec:
                raise PolicyError(
                    f"{source}: [{section}].{toml_key} entry {spec!r} "
                    "must be 'VIRTUAL:HOST'"
                )
            # The Rust CLI strips a trailing ':ro'/':rw' before splitting on
            # the first colon; this parser does not, so the suffix would end
            # up baked into the host path. Both forms are refused, but for
            # different reasons, so the message must say which.
            if spec.endswith(":ro"):
                # Dropping ':ro' would be worse than refusing: Sandbox.fs_mount
                # is a plain virtual -> host mapping with no read-only channel,
                # so the target would be mounted read-write instead.
                raise PolicyError(
                    f"{source}: [{section}].{toml_key} entry {spec!r} uses a "
                    "':ro' suffix, which the Python SDK cannot honour: its "
                    "mount mapping cannot express a read-only mount, and "
                    "dropping the suffix would silently mount the host path "
                    "read-write. Run this profile with the sandlock CLI "
                    "('sandlock run --profile-file <path>' or "
                    "'sandlock run -p <name>'), which honours ':ro', or drop "
                    "the suffix and accept a read-write mount"
                )
            if spec.endswith(":rw"):
                # ':rw' is the CLI's explicit default and means exactly what
                # this mapping already does, but the suffix is not part of the
                # grammar this parser accepts, so it must not be swallowed.
                raise PolicyError(
                    f"{source}: [{section}].{toml_key} entry {spec!r} uses a "
                    "':rw' suffix, which is the sandlock CLI's default and is "
                    "not part of this parser's 'VIRTUAL:HOST' grammar; remove "
                    "it: the mount is read-write already. To keep the suffix, "
                    "run the profile with the sandlock CLI "
                    "('sandlock run --profile-file <path>' or "
                    "'sandlock run -p <name>')"
                )
            virt, host = spec.split(":", 1)
            if not virt or not host:
                raise PolicyError(
                    f"{source}: [{section}].{toml_key} entry {spec!r} "
                    "requires both VIRTUAL and HOST to be non-empty"
                )
            # Expand after the split so a resolved value containing a colon
            # cannot be read as a spec separator.
            mount[expand(virt)] = expand(host)
        return mount
    if sandbox_key == "net_allow_bind":
        # Coerce TOML integers to strings for port specs (existing behaviour).
        return [str(v) if isinstance(v, int) else v for v in value]
    return value


def merge_cli_overrides(policy: Sandbox, overrides: dict) -> Sandbox:
    """Return a new Sandbox with CLI overrides applied on top of a profile.

    List fields from the CLI are appended to profile values.
    Scalar fields from the CLI replace profile values.
    """
    import dataclasses

    merged: dict[str, Any] = {}
    for key, value in overrides.items():
        current = getattr(policy, key, None)
        if isinstance(current, (list, tuple)) and isinstance(value, list):
            merged[key] = list(current) + value
        else:
            merged[key] = value

    return dataclasses.replace(policy, **merged)
