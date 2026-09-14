# SPDX-License-Identifier: Apache-2.0
"""Worker-side client for a ``sandlock-supervise`` slot (route B).

Both registered transports of §4 are covered here:

* **transport 2** -- ``sandlock-supervise --serve-path NAME --token T
  [--peer-uid UID]...`` binds a hashed socket in the shared registry and serves
  **one request per connection** until a ``shutdown`` verb ends the generation
  (F16).  ``SuperviseChannel(path, token)`` is its face: every
  :meth:`SuperviseChannel.request` opens a fresh connection, so no client state
  survives a verb and the slot's accept loop serialises them.
* **transport 1** -- ``sandlock-supervise --control-fd N --serve``: the
  launcher creates a ``socketpair()``, hands one end to the slot as an
  inherited descriptor and keeps the other.  ``SuperviseChannel(fd=...)`` is
  its face (F17): one **persistent** session, the descriptor *is* the
  credential and the token is an optional belt -- so a deployment never puts a
  secret in the slot's argv or on a filesystem path.  Because one stream
  carries every verb, requests are serialised Rust-side, a request that fails
  mid flight retires the session instead of risking a misaligned frame, and
  ``wait_child`` (which may park for the life of a child) needs the deadline a
  registered connection's fixed 2 s would not allow: see
  :meth:`SuperviseChannel.set_timeout`.

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
from .exceptions import SlotRefusal, SandlockError


_lib = _sdk._lib

# A ``char**`` out-parameter held in a ``c_void_p`` slot: the message is read
# as an address and freed by hand, so ctypes never copies it or mis-dereferences
# the pointer itself.
_ErrMsg = ctypes.POINTER(ctypes.c_void_p)

_lib.sandlock_supervise_connect.restype = ctypes.c_void_p
_lib.sandlock_supervise_connect.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
    _ErrMsg,
]
_lib.sandlock_supervise_connect_fd.restype = ctypes.c_void_p
_lib.sandlock_supervise_connect_fd.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
    _ErrMsg,
]
_lib.sandlock_supervise_check_fd.restype = ctypes.c_void_p
_lib.sandlock_supervise_check_fd.argtypes = [ctypes.c_int]
_lib.sandlock_supervise_set_timeout.restype = ctypes.c_int
_lib.sandlock_supervise_set_timeout.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_int),
    _ErrMsg,
]
_lib.sandlock_supervise_request.restype = ctypes.c_void_p
_lib.sandlock_supervise_request.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_int),
    _ErrMsg,
]
_lib.sandlock_supervise_free.restype = None
_lib.sandlock_supervise_free.argtypes = [ctypes.c_void_p]

# ``sandlock_string_free`` is declared in ``_sdk`` with ``c_char_p``; freeing
# a raw pointer must go through a ``c_void_p``-typed alias so ctypes does not
# copy the bytes into a new C string and free the copy.
_free_string = _lib.sandlock_string_free
_free_string.restype = None
_free_string.argtypes = [ctypes.c_void_p]


def _take_err_msg(slot: ctypes.c_void_p) -> str | None:
    """Return and free the native error message written into ``slot``.

    ``slot`` is the ``c_void_p`` whose address went to the C call as the
    ``char**`` out-parameter, so the message must be read as an *address*
    (``slot.value``) and released through ``sandlock_string_free``.

    This used to dereference ``.contents`` on a ``byref(...)`` argument, which
    raised ``AttributeError: '_ctypes.CArgObject' object has no attribute
    'contents'`` on **every** transport failure -- swallowing the slot's own
    error text and turning a refusal into an unclassifiable Python error
    (fork issue SL-9, found wiring the E2B worker onto route B).
    """
    address = slot.value
    if not address:
        return None
    try:
        return ctypes.string_at(address).decode("utf-8", "replace")
    finally:
        _free_string(ctypes.c_void_p(address))
        slot.value = None


def check_control_fd(fd: int) -> str | None:
    """Pre-flight a transport-1 control descriptor.

    Returns ``None`` when ``fd`` may be handed to
    ``sandlock-supervise --control-fd``; otherwise the reason it may not (not
    open / not a stream socket / not ``AF_UNIX``).
    """
    raw = _lib.sandlock_supervise_check_fd(ctypes.c_int(int(fd)))
    if not raw:
        return None
    try:
        return ctypes.string_at(raw).decode("utf-8", "replace")
    finally:
        _free_string(ctypes.c_void_p(raw))


class SuperviseChannel:
    """Client handle for one supervise generation (either transport).

    ``SuperviseChannel(path, token)`` is transport 2: the identity is stored
    and every :meth:`request` opens a fresh connection.
    ``SuperviseChannel(fd=..., token=...)`` is transport 1: the descriptor is
    the credential (``token`` may be empty), no path exists, and one
    connection carries every verb until it is closed.  A transport/refusal
    error raises :class:`SandlockError`; a served ``ok:false`` response raises
    :class:`SlotRefusal` (a :class:`SandboxError`) with the server's error
    text *and* its stable refusal code.
    """

    def __init__(
        self,
        path: str | None = None,
        token: str = "",
        *,
        fd: int | None = None,
        timeout_ms: int | None = None,
    ) -> None:
        if (path is None) == (fd is None):
            raise ValueError(
                "SuperviseChannel takes exactly one of path= (registered "
                "transport) or fd= (handed-over control descriptor)"
            )
        err = ctypes.c_int(0)
        err_msg = ctypes.c_void_p()
        if fd is None:
            if not token:
                raise ValueError("the registered transport needs a channel token")
            handle = _lib.sandlock_supervise_connect(
                str(path).encode("utf-8"),
                token.encode("utf-8"),
                ctypes.byref(err),
                ctypes.byref(err_msg),
            )
            what = f"supervise connect {path!r}"
        else:
            handle = _lib.sandlock_supervise_connect_fd(
                ctypes.c_int(int(fd)),
                token.encode("utf-8") if token else None,
                ctypes.byref(err),
                ctypes.byref(err_msg),
            )
            what = f"supervise control fd {fd}"
        if not handle:
            raise SandlockError(_take_err_msg(err_msg) or f"{what} failed")
        self._h = handle
        self._path = path
        self._fd = fd
        self._closed = False
        if timeout_ms is not None:
            self.set_timeout(timeout_ms)

    @property
    def is_handed_over(self) -> bool:
        """True on transport 1: one persistent stream, no registry path."""
        return self._fd is not None

    def set_timeout(self, timeout_ms: int) -> None:
        """Response deadline for later verbs on this session (0 = block).

        Transport 1 only -- one stream carries both the instant verbs and a
        ``wait_child`` that may park for as long as its child runs, so the
        holder chooses the deadline. The registered transport rejects it: it
        opens a fresh connection per verb under the fixed default.
        """
        err = ctypes.c_int(0)
        err_msg = ctypes.c_void_p()
        rc = _lib.sandlock_supervise_set_timeout(
            self._h,
            ctypes.c_uint64(int(timeout_ms)),
            ctypes.byref(err),
            ctypes.byref(err_msg),
        )
        if rc != 0:
            raise SandlockError(
                _take_err_msg(err_msg) or "sandlock_supervise_set_timeout failed"
            )

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
        err_msg = ctypes.c_void_p()
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
            raise SandlockError(_take_err_msg(err_msg) or f"supervise verb {verb!r} failed")
        try:
            raw = ctypes.string_at(resp_p)
            response = json.loads(raw.decode("utf-8"))
        finally:
            _free_string(ctypes.c_void_p(resp_p))
        if not response.get("ok"):
            # F19/SL-13: the refusal's stable code rides the same frame as its
            # prose, so a host can branch on "the generation is over" without
            # parsing the sentence. `code` is None only for a slot older than
            # the field; it is never guessed from the message.
            raise SlotRefusal(
                response.get("err") or f"supervise verb {verb!r} refused",
                code=response.get("code"),
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
