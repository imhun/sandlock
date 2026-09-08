# SPDX-License-Identifier: Apache-2.0
"""Worker-side client for a registered ``sandlock-supervise`` slot (route B).

``sandlock-supervise --serve-path NAME --token T [--peer-uid UID]...`` binds a
hashed socket in the shared registry and serves **one request per
connection** until a ``shutdown`` verb ends the generation.  This module is
the Python face of that transport (F16): a thin ctypes wrapper over the
``sandlock_supervise_*`` C exports, so the caller keeps the exact JSON verb
contract documented in ``docs/supervise-identity-handoff.md`` §4/§10.

The class deliberately adds **no instance semantics**: ``exec`` /
``wait_child`` / ``kill_child`` / ``update_network`` / ``shutdown`` mean what
the slot's ``Generation`` handler says they mean.  ``exec`` is the only verb
that needs ``fds`` — exactly three child-side stdio ends (``[stdin, stdout,
stderr]``) ride the same ``sendmsg`` as the request frame.
"""

from __future__ import annotations

import ctypes
import json
from typing import Any, Dict, Sequence

from . import _sdk
from .exceptions import SandboxError, SandlockError


_lib = _sdk._lib

_lib.sandlock_supervise_connect.restype = ctypes.c_void_p
_lib.sandlock_supervise_connect.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_char_p),
]
_lib.sandlock_supervise_request.restype = ctypes.c_void_p
_lib.sandlock_supervise_request.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_char_p),
]
_lib.sandlock_supervise_free.restype = None
_lib.sandlock_supervise_free.argtypes = [ctypes.c_void_p]

# ``sandlock_string_free`` is declared in ``_sdk`` with ``c_char_p``; freeing
# a raw pointer must go through a ``c_void_p``-typed alias so ctypes does not
# copy the bytes into a new C string and free the copy.
_free_string = _lib.sandlock_string_free
_free_string.restype = None
_free_string.argtypes = [ctypes.c_void_p]


def _take_err_msg(err_msg: ctypes.POINTER(ctypes.c_char_p)) -> str | None:
    """Return and free the native error message, if any."""
    raw = err_msg.contents
    if not raw:
        return None
    try:
        return raw.decode("utf-8", "replace")
    finally:
        _free_string(ctypes.cast(raw, ctypes.c_void_p))
        err_msg.contents = None


class SuperviseChannel:
    """A registered-slot client handle.

    ``connect`` stores the slot identity (registry socket path + channel
    token); every :meth:`request` opens a fresh unix connection, attaches the
    token, hands over any descriptors, and returns the response ``data``.
    A transport/refusal error raises :class:`SandlockError`; a served
    ``ok:false`` response raises :class:`SandboxError` with the server's
    error text.
    """

    def __init__(self, path: str, token: str) -> None:
        self._path = path
        err = ctypes.c_int(0)
        err_msg = ctypes.c_char_p()
        handle = _lib.sandlock_supervise_connect(
            path.encode("utf-8"),
            token.encode("utf-8"),
            ctypes.byref(err),
            ctypes.byref(err_msg),
        )
        if not handle:
            raise SandlockError(
                _take_err_msg(ctypes.byref(err_msg))
                or f"supervise connect {path!r} failed"
            )
        self._h = handle
        self._closed = False

    def request(
        self,
        verb: str,
        args: Dict[str, Any] | None = None,
        fds: Sequence[int] = (),
    ) -> Any:
        """Issue one verb and return the response ``data`` (``ok:true``)."""
        if self._closed:
            raise SandlockError("SuperviseChannel is closed")
        payload = json.dumps({} if args is None else args).encode("utf-8")
        fd_array = None
        n_fds = len(fds)
        if n_fds:
            fd_array = (ctypes.c_int * n_fds)(*(int(fd) for fd in fds))
        err = ctypes.c_int(0)
        err_msg = ctypes.c_char_p()
        resp_p = _lib.sandlock_supervise_request(
            self._h,
            verb.encode("utf-8"),
            payload,
            fd_array,
            n_fds,
            ctypes.byref(err),
            ctypes.byref(err_msg),
        )
        if not resp_p:
            raise SandlockError(
                _take_err_msg(ctypes.byref(err_msg))
                or f"supervise verb {verb!r} failed"
            )
        try:
            raw = ctypes.string_at(resp_p)
            response = json.loads(raw.decode("utf-8"))
        finally:
            _free_string(ctypes.c_void_p(resp_p))
        if not response.get("ok"):
            raise SandboxError(
                response.get("err") or f"supervise verb {verb!r} refused"
            )
        return response.get("data")

    def shutdown(self) -> Any:
        """End the generation (the slot answers, then tears down and exits)."""
        try:
            return self.request("shutdown")
        finally:
            self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            _lib.sandlock_supervise_free(self._h)

    def __enter__(self) -> "SuperviseChannel":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - defensive only
        try:
            self.close()
        except Exception:
            pass
