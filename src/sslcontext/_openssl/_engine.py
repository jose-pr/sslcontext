"""OpenSSL 1.1 and LibreSSL: keys bound to an in-process engine whose ``sign``
is a :class:`Signer`.

A key is the certificate's public key with the engine attached
(``EVP_PKEY_set1_engine``). The engine supplies RSA and EC pkey methods
copied from OpenSSL's own, with only ``sign`` replaced, so padding and digest
handling stay OpenSSL's and the signer receives the finished digest.

LibreSSL 2.x exports neither ``EVP_PKEY_set1_engine`` nor
``EVP_PKEY_meth_get_sign``; their fields are reached in the structures, whose
layout (OpenSSL 1.0's) is checked against the library before anything is
written.

The engine, its methods and the callbacks are never freed: OpenSSL may reach
them until the process exits.
"""

from __future__ import annotations

import ctypes
import functools
import logging
import threading
from ctypes import CFUNCTYPE, POINTER, c_int, c_size_t, c_void_p
from typing import Any, Callable

from .._identity import Padding
from ..exceptions import UnsupportedOpenSSLError
from . import _keys
from ._api import OpenSSL
from ._errors import drain_errors
from ._signing import hash_name, salt_length

__all__ = ["make_key"]

_log = logging.getLogger("sslcontext")

_EVP_PKEY_RSA, _EVP_PKEY_EC = 6, 408
# evp.h / rsa.h control commands
_CTRL_GET_MD = 13
_CTRL_GET_RSA_PADDING = 0x1006
_CTRL_GET_RSA_PSS_SALTLEN = 0x1007
_RSA_PKCS1_PSS_PADDING = 6

_PKEY_METHS = CFUNCTYPE(
    c_int, c_void_p, POINTER(c_void_p), POINTER(POINTER(c_int)), c_int
)
_SIGN = CFUNCTYPE(c_int, c_void_p, c_void_p, POINTER(c_size_t), c_void_p, c_size_t)


def _guard(failure: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(function)
        def wrapper(*args: Any) -> Any:
            try:
                return function(*args)
            except BaseException:  # noqa: BLE001 - must not cross the C boundary
                _log.warning(
                    "sslcontext engine: %s failed", function.__name__, exc_info=True
                )
                return failure

        return wrapper

    return decorate


class _Engine:
    def __init__(self, lib: OpenSSL) -> None:
        self.lib = lib
        self._lock = threading.Lock()
        self._keys: dict[int, int] = {}  # EVP_PKEY * -> record handle
        self._nids = (c_int * 2)(_EVP_PKEY_RSA, _EVP_PKEY_EC)
        self._sign_callback = _SIGN(self._sign)
        self._meths_callback = _PKEY_METHS(self._pkey_meths)
        self._methods = {
            nid: self._method(nid) for nid in (_EVP_PKEY_RSA, _EVP_PKEY_EC)
        }
        engine = lib.ENGINE_new()
        if not engine:
            raise UnsupportedOpenSSLError(f"ENGINE_new failed: {drain_errors(lib)}")
        if not (
            lib.ENGINE_set_id(engine, b"sslcontext")
            and lib.ENGINE_set_name(engine, b"keys signed through sslcontext")
            and lib.ENGINE_set_pkey_meths(engine, self._meths_callback)
        ):
            raise UnsupportedOpenSSLError(
                f"cannot set up the engine: {drain_errors(lib)}"
            )
        self.engine = engine

    def _method(self, nid: int) -> int:
        lib = self.lib
        source = lib.EVP_PKEY_meth_find(nid)
        method = lib.EVP_PKEY_meth_new(nid, 0)
        if not source or not method:
            raise UnsupportedOpenSSLError(
                f"no pkey method for {nid}: {drain_errors(lib)}"
            )
        lib.EVP_PKEY_meth_copy(method, source)
        sign_init, sign = c_void_p(), c_void_p()
        if lib.is_libressl:
            sign_init.value = _method_sign_init(lib, source)
        else:
            lib.EVP_PKEY_meth_get_sign(
                source, ctypes.byref(sign_init), ctypes.byref(sign)
            )
        lib.EVP_PKEY_meth_set_sign(
            method, sign_init.value, ctypes.cast(self._sign_callback, c_void_p).value
        )
        return method

    @_guard(0)
    def _pkey_meths(self, engine: int, method: Any, nids: Any, nid: int) -> int:
        if not method:
            nids[0] = self._nids
            return len(self._nids)
        if nid not in self._methods:
            method[0] = None
            return 0
        method[0] = self._methods[nid]
        return 1

    def _ctrl(self, context: int, command: int, out: Any) -> None:
        if (
            self.lib.EVP_PKEY_CTX_ctrl(context, -1, -1, command, 0, ctypes.byref(out))
            <= 0
        ):
            raise ValueError(
                f"EVP_PKEY_CTX_ctrl({command:#x}) failed: {drain_errors(self.lib)}"
            )

    @_guard(0)
    def _sign(
        self, context: int, signature: int, length: Any, data: int, size: int
    ) -> int:
        lib = self.lib
        with self._lock:
            handle = self._keys.get(lib.EVP_PKEY_CTX_get0_pkey(context) or 0)
        record = _keys.lookup(handle) if handle else None
        if record is None:
            return 0
        if not signature:
            length[0] = record.max_size
            return 1
        md = c_void_p()
        if (
            lib.EVP_PKEY_CTX_ctrl(context, -1, -1, _CTRL_GET_MD, 0, ctypes.byref(md))
            <= 0
        ):
            # LibreSSL does not answer it; the digest's size names the hash.
            lib.ERR_clear_error()
            md.value = None
        if md.value:
            name = hash_name(lib.OBJ_nid2sn(lib.EVP_MD_type(md.value)).decode())
        else:
            name = {20: "sha1", 28: "sha224", 32: "sha256", 48: "sha384", 64: "sha512"}[
                size
            ]
        digest = ctypes.string_at(data, size)
        padding: Padding | None = None
        salt: int | None = None
        if record.key_type == "rsa":
            mode = c_int()
            self._ctrl(context, _CTRL_GET_RSA_PADDING, mode)
            if mode.value == _RSA_PKCS1_PSS_PADDING:
                spec = c_int()
                self._ctrl(context, _CTRL_GET_RSA_PSS_SALTLEN, spec)
                padding, salt = Padding.PSS, salt_length(spec.value, size, record.bits)
            else:
                padding = Padding.PKCS1V15
        result = record.signer.sign(
            digest, hash=name, padding=padding, salt_length=salt
        )
        if not isinstance(result, (bytes, bytearray)) or len(result) > length[0]:
            raise ValueError(
                f"signer returned {len(result)} bytes, room for {length[0]}"
            )
        ctypes.memmove(signature, bytes(result), len(result))
        length[0] = len(result)
        return 1

    def key(self, handle: int) -> int:
        """A fresh copy of the record's public key, bound to the engine."""
        lib = self.lib
        record = _keys.lookup(handle)
        encoded = c_void_p()
        size = lib.i2d_PUBKEY(record.public, ctypes.byref(encoded))
        if size <= 0:
            raise UnsupportedOpenSSLError(
                f"cannot copy the public key: {drain_errors(lib)}"
            )
        try:
            cursor = c_void_p(encoded.value)
            key = lib.d2i_PUBKEY(None, ctypes.byref(cursor), size)
        finally:
            lib.CRYPTO_free(encoded.value, b"", 0)
        if not key:
            raise UnsupportedOpenSSLError(
                f"cannot copy the public key: {drain_errors(lib)}"
            )
        attached = (
            _attach_engine(lib, key, self.engine)
            if lib.is_libressl
            else lib.EVP_PKEY_set1_engine(key, self.engine)
        )
        if not attached:
            lib.EVP_PKEY_free(key)
            raise UnsupportedOpenSSLError(
                f"cannot attach the engine: {drain_errors(lib)}"
            )
        with self._lock:
            self._keys[key] = handle
        return key


# OpenSSL 1.0's struct evp_pkey_method_st: int pkey_id, int flags, then
# init, copy, cleanup, paramgen_init, paramgen, keygen_init, keygen,
# sign_init, sign; struct evp_pkey_st: int type, save_type, references,
# then ameth, engine.
_POINTER = ctypes.sizeof(c_void_p)
_SIGN_INIT_AT = 8 + 7 * _POINTER
_SIGN_AT = _SIGN_INIT_AT + _POINTER
_AMETH_AT = 16
_ENGINE_AT = _AMETH_AT + _POINTER


def _pointer_at(address: int, offset: int) -> int:
    return c_void_p.from_address(address + offset).value or 0


def _method_sign_init(lib: OpenSSL, source: int) -> int:
    """``source``'s ``sign_init``, read after proving where ``set_sign`` writes."""
    probe = lib.EVP_PKEY_meth_new(_EVP_PKEY_EC, 0)
    lib.EVP_PKEY_meth_set_sign(probe, 0x1111, 0x2222)
    found = (_pointer_at(probe, _SIGN_INIT_AT), _pointer_at(probe, _SIGN_AT))
    lib.EVP_PKEY_meth_free(probe)
    if found != (0x1111, 0x2222):
        raise UnsupportedOpenSSLError("unexpected EVP_PKEY_METHOD layout")
    return _pointer_at(source, _SIGN_INIT_AT)


def _attach_engine(lib: OpenSSL, key: int, engine: int) -> bool:
    """``EVP_PKEY_set1_engine`` for LibreSSL: one functional reference, which
    ``EVP_PKEY_free`` gives back."""
    if (
        ctypes.c_int.from_address(key).value != lib.EVP_PKEY_id(key)
        or _pointer_at(key, _AMETH_AT) != lib.EVP_PKEY_get0_asn1(key)
        or _pointer_at(key, _ENGINE_AT) != 0
    ):
        raise UnsupportedOpenSSLError("unexpected EVP_PKEY layout")
    if not lib.ENGINE_init(engine):
        return False
    c_void_p.from_address(key + _ENGINE_AT).value = engine
    return True


_engine: _Engine | None = None
_engine_lock = threading.Lock()


def make_key(lib: OpenSSL, handle: int, key_type: str) -> int:
    """An ``EVP_PKEY *`` (owned by the caller) whose signing goes to ``handle``."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = _Engine(lib)
    return _engine.key(handle)
