"""An OpenSSL 3 provider written in Python: RSA and EC keys signed by a :class:`Signer`.

The provider is registered as a built-in (``OSSL_PROVIDER_add_builtin``) in
the default library context, the one every stdlib ``SSLContext`` uses. It
offers only key management and signatures, under the property
``provider=sslcontext``; everything else stays with the providers already
active.

Lifetime rules, all forced by OpenSSL's ``atexit`` cleanup running after the
interpreter has finalised:

- there is no ``teardown`` function;
- a key's ``free`` is the C runtime's ``free``, so freeing a key never enters
  Python; the Python-side record is dropped when its ``SSLContext`` dies;
- every callback and every static array lives in module globals forever.
"""

from __future__ import annotations

import ctypes
import functools
import hashlib
import itertools
import logging
import sys
import threading
from ctypes import CFUNCTYPE, POINTER, c_char_p, c_int, c_size_t, c_uint64, c_void_p
from dataclasses import dataclass, field
from typing import Any, Callable

from .._identity import Padding
from ..exceptions import UnsupportedOpenSSLError
from . import _keys
from ._api import OpenSSL
from ._errors import drain_errors
from ._signing import (
    SALT_AUTO,
    SALT_AUTO_DIGEST_MAX,
    SALT_DIGEST,
    SALT_MAX,
    hash_name,
    salt_length,
)
from ._params import (
    OSSL_PARAM,
    PARAM_INTEGER,
    PARAM_UNSIGNED_INTEGER,
    PARAM_UTF8_STRING,
    descriptor_list,
    iter_params,
    read_int,
    read_text,
    write_int,
    write_text,
)

__all__ = ["make_key"]

_log = logging.getLogger("sslcontext")

PROVIDER_NAME = b"sslcontext"
_PROPERTIES = b"provider=sslcontext"
_HANDLE_PARAM = b"sslcontext-key-handle"

# core_dispatch.h
_OP_KEYMGMT, _OP_SIGNATURE = 10, 12
_QUERY_OPERATION = 1027
_KM_NEW, _KM_FREE, _KM_GET_PARAMS, _KM_GETTABLE_PARAMS = 1, 10, 11, 12
_KM_QUERY_OPERATION_NAME, _KM_HAS, _KM_MATCH = 20, 21, 23
_KM_IMPORT, _KM_IMPORT_TYPES, _KM_EXPORT, _KM_EXPORT_TYPES = 40, 41, 42, 43
_SIG_NEWCTX, _SIG_SIGN_INIT, _SIG_SIGN = 1, 2, 3
_SIG_DIGEST_SIGN_INIT, _SIG_DIGEST_SIGN_UPDATE, _SIG_DIGEST_SIGN_FINAL = 8, 9, 10
_SIG_FREECTX, _SIG_DUPCTX = 16, 17
_SIG_GET_CTX_PARAMS, _SIG_GETTABLE_CTX_PARAMS = 18, 19
_SIG_SET_CTX_PARAMS, _SIG_SETTABLE_CTX_PARAMS = 20, 21
# core.h / evp.h
_SELECT_PRIVATE_KEY, _SELECT_PUBLIC_KEY = 0x01, 0x02
_EVP_PKEY_KEYPAIR = 0x87
# rsa.h padding modes and PSS salt-length specials
_RSA_PKCS1_PADDING, _RSA_PKCS1_PSS_PADDING = 1, 6
_SALT_NAMES = {
    "digest": SALT_DIGEST,
    "auto": SALT_AUTO,
    "max": SALT_MAX,
    "auto-digestmax": SALT_AUTO_DIGEST_MAX,
}


class _DISPATCH(ctypes.Structure):
    _fields_ = [("function_id", c_int), ("function", c_void_p)]


class _ALGORITHM(ctypes.Structure):
    _fields_ = [
        ("names", c_char_p),
        ("properties", c_char_p),
        ("implementation", c_void_p),
        ("description", c_char_p),
    ]


def _guard(failure: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Never let an exception unwind into OpenSSL; return ``failure`` instead."""

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(function)
        def wrapper(*args: Any) -> Any:
            try:
                result = function(*args)
            except BaseException:  # noqa: BLE001 - must not cross the C boundary
                _log.warning(
                    "sslcontext provider: %s failed", function.__name__, exc_info=True
                )
                return failure
            if _log.isEnabledFor(logging.DEBUG):
                _log.debug(
                    "sslcontext provider: %s%r -> %r",
                    function.__name__,
                    args[1:],
                    result,
                )
            return result

        return wrapper

    return decorate


@dataclass
class _SignContext:
    handle: int = 0
    hash: str | None = None
    padding: int = _RSA_PKCS1_PADDING
    salt: int = SALT_AUTO_DIGEST_MAX
    hasher: Any = field(default=None, repr=False)

    def copy(self) -> _SignContext:
        clone = _SignContext(self.handle, self.hash, self.padding, self.salt)
        if self.hasher is not None:
            clone.hasher = self.hasher.copy()
        return clone


class _Provider:
    """Holds every ctypes object OpenSSL may call or read, for the process's life."""

    def __init__(self, lib: OpenSSL) -> None:
        self.lib = lib
        self._crt = _c_runtime()
        self._contexts: dict[int, _SignContext] = {}
        self._context_ids = itertools.count(1)
        self._lock = threading.Lock()
        self._strings: list[ctypes.Array[ctypes.c_char]] = []
        self._callbacks: list[Any] = []
        self._build_tables()

    # ------------------------------------------------------------ tables

    def _callback(self, prototype: Any, function: Callable[..., Any]) -> int:
        pointer = prototype(function)
        self._callbacks.append(pointer)
        return ctypes.cast(pointer, c_void_p).value or 0

    def _static_string(self, text: bytes) -> int:
        buffer = ctypes.create_string_buffer(text)
        self._strings.append(buffer)
        return ctypes.addressof(buffer)

    def _dispatch(self, entries: list[tuple[int, int]]) -> Any:
        table = (_DISPATCH * (len(entries) + 1))()
        for slot, (function_id, address) in zip(table, entries):
            slot.function_id, slot.function = function_id, address
        self._callbacks.append(table)
        return table

    def _algorithms(self, entries: list[tuple[bytes, Any]]) -> Any:
        table = (_ALGORITHM * (len(entries) + 1))()
        for slot, (names, dispatch) in zip(table, entries):
            slot.names = names
            slot.properties = _PROPERTIES
            slot.implementation = ctypes.addressof(dispatch)
            slot.description = b"keys signed through sslcontext"
        self._callbacks.append(table)
        return table

    def _build_tables(self) -> None:
        P = c_void_p
        self._handle_types = descriptor_list((_HANDLE_PARAM, PARAM_UNSIGNED_INTEGER))
        self._gettable = descriptor_list(
            (b"bits", PARAM_INTEGER),
            (b"security-bits", PARAM_INTEGER),
            (b"max-size", PARAM_INTEGER),
            (b"default-digest", PARAM_UTF8_STRING),
            (b"group", PARAM_UTF8_STRING),
        )
        self._settable_ctx = descriptor_list(
            (b"digest", PARAM_UTF8_STRING),
            (b"pad-mode", PARAM_UTF8_STRING),
            (b"saltlen", PARAM_UTF8_STRING),
            (b"mgf1-digest", PARAM_UTF8_STRING),
        )
        self._gettable_ctx = descriptor_list()
        self._ecdsa_name = self._static_string(b"ECDSA")
        free = ctypes.cast(self._crt.free, c_void_p).value

        def keymgmt(key_type: str) -> Any:
            def query_name(operation: int) -> int | None:
                if key_type == "ec" and operation == _OP_SIGNATURE:
                    return self._ecdsa_name
                return None

            return self._dispatch(
                [
                    (_KM_NEW, self._callback(CFUNCTYPE(P, P), self._km_new)),
                    (_KM_FREE, free),
                    (_KM_HAS, self._callback(CFUNCTYPE(c_int, P, c_int), self._km_has)),
                    (
                        _KM_MATCH,
                        self._callback(CFUNCTYPE(c_int, P, P, c_int), self._km_match),
                    ),
                    (
                        _KM_IMPORT,
                        self._callback(CFUNCTYPE(c_int, P, c_int, P), self._km_import),
                    ),
                    (
                        _KM_IMPORT_TYPES,
                        self._callback(CFUNCTYPE(P, c_int), self._km_import_types),
                    ),
                    (
                        _KM_EXPORT,
                        self._callback(
                            CFUNCTYPE(c_int, P, c_int, P, P), self._km_export
                        ),
                    ),
                    (
                        _KM_EXPORT_TYPES,
                        self._callback(CFUNCTYPE(P, c_int), self._km_export_types),
                    ),
                    (
                        _KM_GET_PARAMS,
                        self._callback(CFUNCTYPE(c_int, P, P), self._km_get_params),
                    ),
                    (
                        _KM_GETTABLE_PARAMS,
                        self._callback(CFUNCTYPE(P, P), self._km_gettable),
                    ),
                    (
                        _KM_QUERY_OPERATION_NAME,
                        self._callback(CFUNCTYPE(P, c_int), _guard(None)(query_name)),
                    ),
                ]
            )

        signature = self._dispatch(
            [
                (_SIG_NEWCTX, self._callback(CFUNCTYPE(P, P, P), self._sig_new)),
                (_SIG_FREECTX, self._callback(CFUNCTYPE(None, P), self._sig_free)),
                (_SIG_DUPCTX, self._callback(CFUNCTYPE(P, P), self._sig_dup)),
                (
                    _SIG_SIGN_INIT,
                    self._callback(CFUNCTYPE(c_int, P, P, P), self._sig_sign_init),
                ),
                (
                    _SIG_SIGN,
                    self._callback(
                        CFUNCTYPE(
                            c_int, P, P, POINTER(c_size_t), c_size_t, P, c_size_t
                        ),
                        self._sig_sign,
                    ),
                ),
                (
                    _SIG_DIGEST_SIGN_INIT,
                    self._callback(
                        CFUNCTYPE(c_int, P, c_char_p, P, P), self._sig_digest_init
                    ),
                ),
                (
                    _SIG_DIGEST_SIGN_UPDATE,
                    self._callback(
                        CFUNCTYPE(c_int, P, P, c_size_t), self._sig_digest_update
                    ),
                ),
                (
                    _SIG_DIGEST_SIGN_FINAL,
                    self._callback(
                        CFUNCTYPE(c_int, P, P, POINTER(c_size_t), c_size_t),
                        self._sig_digest_final,
                    ),
                ),
                (
                    _SIG_GET_CTX_PARAMS,
                    self._callback(CFUNCTYPE(c_int, P, P), self._sig_get_params),
                ),
                (
                    _SIG_GETTABLE_CTX_PARAMS,
                    self._callback(CFUNCTYPE(P, P, P), self._sig_gettable),
                ),
                (
                    _SIG_SET_CTX_PARAMS,
                    self._callback(CFUNCTYPE(c_int, P, P), self._sig_set_params),
                ),
                (
                    _SIG_SETTABLE_CTX_PARAMS,
                    self._callback(CFUNCTYPE(P, P, P), self._sig_settable),
                ),
            ]
        )
        self._keymgmt_table = self._algorithms(
            [
                (b"RSA:rsaEncryption:1.2.840.113549.1.1.1", keymgmt("rsa")),
                (b"EC:id-ecPublicKey:1.2.840.10045.2.1", keymgmt("ec")),
            ]
        )
        self._signature_table = self._algorithms(
            [
                (b"RSA:rsaEncryption:1.2.840.113549.1.1.1", signature),
                (b"ECDSA", signature),
            ]
        )
        provider = self._dispatch(
            [
                (
                    _QUERY_OPERATION,
                    self._callback(CFUNCTYPE(P, P, c_int, POINTER(c_int)), self._query),
                )
            ]
        )
        self._provider_table = provider

        @_guard(0)
        def init(handle: int, core: int, out: Any, provctx: Any) -> int:
            out[0] = ctypes.addressof(provider)
            provctx[0] = handle
            return 1

        self.init_address = self._callback(
            CFUNCTYPE(c_int, P, P, POINTER(c_void_p), POINTER(c_void_p)), init
        )

    # ---------------------------------------------------------- provider

    @_guard(None)
    def _query(self, provctx: int, operation: int, no_cache: Any) -> int | None:
        no_cache[0] = 0
        if operation == _OP_KEYMGMT:
            return ctypes.addressof(self._keymgmt_table)
        if operation == _OP_SIGNATURE:
            return ctypes.addressof(self._signature_table)
        return None

    # ----------------------------------------------------------- keymgmt

    def _handle(self, keydata: int | None) -> int:
        return c_uint64.from_address(keydata).value if keydata else 0

    @_guard(None)
    def _km_new(self, provctx: int) -> int | None:
        block = self._crt.malloc(8)
        if block:
            c_uint64.from_address(block).value = 0
        return block

    @_guard(0)
    def _km_has(self, keydata: int, selection: int) -> int:
        return int(_keys.lookup(self._handle(keydata)) is not None)

    @_guard(0)
    def _km_match(self, first: int, second: int, selection: int) -> int:
        a, b = _keys.lookup(self._handle(first)), _keys.lookup(self._handle(second))
        if a is None or b is None:
            return 0
        return int(self.lib.EVP_PKEY_eq(a.public, b.public) == 1)

    @_guard(0)
    def _km_import(self, keydata: int, selection: int, params: int) -> int:
        # Only keys made by make_key() carry a handle; refusing anything else
        # keeps OpenSSL from moving other providers' keys into this one.
        for param in iter_params(params):
            if param.key == _HANDLE_PARAM:
                handle = read_int(param)
                if _keys.lookup(handle) is None:
                    return 0
                c_uint64.from_address(keydata).value = handle
                return 1
        return 0

    @_guard(None)
    def _km_import_types(self, selection: int) -> int:
        return self._handle_types.address

    @_guard(0)
    def _km_export(
        self, keydata: int, selection: int, callback: int, argument: int
    ) -> int:
        record = _keys.lookup(self._handle(keydata))
        # Refusing any export that asks for the private half is what makes
        # OpenSSL sign with this provider: it first tries another provider's
        # signature and moves the key there, which must fail for a key that
        # has no exportable private part. Public-only exports (key matching,
        # certificate checks) are answered.
        if record is None or selection & _SELECT_PRIVATE_KEY:
            return 0
        exported = c_void_p()
        # The public half and the domain parameters, never a private key.
        if not self.lib.EVP_PKEY_todata(
            record.public, selection, ctypes.byref(exported)
        ):
            drain_errors(self.lib)
            return 0
        try:
            return CFUNCTYPE(c_int, c_void_p, c_void_p)(callback)(
                exported.value, argument
            )
        finally:
            self.lib.OSSL_PARAM_free(exported.value)

    @_guard(None)
    def _km_export_types(self, selection: int) -> int | None:
        return None

    @_guard(0)
    def _km_get_params(self, keydata: int, params: int) -> int:
        record = _keys.lookup(self._handle(keydata))
        if record is None:
            return 0
        # The public key knows its size, security bits and curve.
        return int(self.lib.EVP_PKEY_get_params(record.public, params) == 1)

    @_guard(None)
    def _km_gettable(self, provctx: int) -> int:
        return self._gettable.address

    # --------------------------------------------------------- signature

    def _context(self, pointer: int) -> _SignContext:
        with self._lock:
            return self._contexts[pointer]

    @_guard(None)
    def _sig_new(self, provctx: int, propq: int) -> int:
        with self._lock:
            pointer = next(self._context_ids)
            self._contexts[pointer] = _SignContext()
        return pointer

    @_guard(None)
    def _sig_free(self, pointer: int) -> None:
        with self._lock:
            self._contexts.pop(pointer, None)

    @_guard(None)
    def _sig_dup(self, pointer: int) -> int:
        clone = self._context(pointer).copy()
        with self._lock:
            new = next(self._context_ids)
            self._contexts[new] = clone
        return new

    def _bind(self, context: _SignContext, keydata: int | None) -> bool:
        if keydata:
            handle = self._handle(keydata)
            if _keys.lookup(handle) is None:
                return False
            context.handle = handle
        return context.handle != 0

    @_guard(0)
    def _sig_sign_init(self, pointer: int, keydata: int, params: int) -> int:
        context = self._context(pointer)
        if not self._bind(context, keydata):
            return 0
        return int(self._apply(context, params))

    @_guard(0)
    def _sig_digest_init(
        self, pointer: int, mdname: bytes | None, keydata: int, params: int
    ) -> int:
        context = self._context(pointer)
        if not self._bind(context, keydata):
            return 0
        if mdname:
            context.hash = hash_name(mdname.decode())
        if not self._apply(context, params):
            return 0
        context.hasher = hashlib.new(context.hash or "sha256")
        return 1

    @_guard(0)
    def _sig_digest_update(self, pointer: int, data: int, length: int) -> int:
        self._context(pointer).hasher.update(ctypes.string_at(data, length))
        return 1

    @_guard(0)
    def _sig_digest_final(
        self, pointer: int, signature: int, length: Any, capacity: int
    ) -> int:
        context = self._context(pointer)
        context.hash = context.hash or "sha256"
        if not signature:
            return self._report_size(context, length)
        return self._sign(context, context.hasher.digest(), signature, length, capacity)

    @_guard(0)
    def _sig_sign(
        self,
        pointer: int,
        signature: int,
        length: Any,
        capacity: int,
        data: int,
        size: int,
    ) -> int:
        context = self._context(pointer)
        if not signature:
            return self._report_size(context, length)
        digest = ctypes.string_at(data, size)
        if context.hash is None:
            context.hash = {
                20: "sha1",
                28: "sha224",
                32: "sha256",
                48: "sha384",
                64: "sha512",
            }[size]
        return self._sign(context, digest, signature, length, capacity)

    def _report_size(self, context: _SignContext, length: Any) -> int:
        record = _keys.lookup(context.handle)
        if record is None:
            return 0
        length[0] = record.max_size
        return 1

    def _sign(
        self,
        context: _SignContext,
        digest: bytes,
        signature: int,
        length: Any,
        capacity: int,
    ) -> int:
        record = _keys.lookup(context.handle)
        if record is None:
            return 0
        if record.key_type == "rsa":
            padding = (
                Padding.PSS
                if context.padding == _RSA_PKCS1_PSS_PADDING
                else Padding.PKCS1V15
            )
            salt = (
                salt_length(context.salt, len(digest), record.bits)
                if padding is Padding.PSS
                else None
            )
        else:
            padding, salt = None, None
        result = record.signer.sign(
            digest, hash=context.hash, padding=padding, salt_length=salt
        )
        if not isinstance(result, (bytes, bytearray)) or len(result) > capacity:
            raise ValueError(
                f"signer returned {len(result)} bytes, room for {capacity}"
            )
        ctypes.memmove(signature, bytes(result), len(result))
        length[0] = len(result)
        return 1

    def _apply(self, context: _SignContext, params: int) -> bool:
        for param in iter_params(params):
            key = param.key
            if key == b"digest":
                context.hash = hash_name(read_text(param))
            elif key == b"pad-mode":
                if param.data_type == PARAM_UTF8_STRING or param.data_type == 6:
                    mode = read_text(param)
                    context.padding = {
                        "pkcs1": _RSA_PKCS1_PADDING,
                        "pss": _RSA_PKCS1_PSS_PADDING,
                    }[mode]
                else:
                    context.padding = read_int(param)
                if context.padding not in (_RSA_PKCS1_PADDING, _RSA_PKCS1_PSS_PADDING):
                    return False
            elif key == b"saltlen":
                if param.data_type in (PARAM_INTEGER, PARAM_UNSIGNED_INTEGER):
                    context.salt = read_int(param)
                else:
                    text = read_text(param)
                    context.salt = (
                        _SALT_NAMES[text] if text in _SALT_NAMES else int(text)
                    )
            elif key == b"mgf1-digest":
                mgf1 = hash_name(read_text(param))
                if context.hash and mgf1 != context.hash:
                    return False
        return True

    @_guard(0)
    def _sig_set_params(self, pointer: int, params: int) -> int:
        return int(self._apply(self._context(pointer), params))

    @_guard(0)
    def _sig_get_params(self, pointer: int, params: int) -> int:
        context = self._context(pointer)
        for param in iter_params(params):
            if param.key == b"digest" and context.hash:
                write_text(param, context.hash.upper())
            elif param.key == b"pad-mode" and param.data_type == PARAM_INTEGER:
                write_int(param, context.padding)
        return 1

    @_guard(None)
    def _sig_settable(self, pointer: int, provctx: int) -> int:
        return self._settable_ctx.address

    @_guard(None)
    def _sig_gettable(self, pointer: int, provctx: int) -> int:
        return self._gettable_ctx.address


def _c_runtime() -> Any:
    """The C runtime whose ``malloc``/``free`` pair backs key handles."""
    if sys.platform == "win32":
        crt = ctypes.CDLL("ucrtbase")
    else:
        crt = ctypes.CDLL(None)
    crt.malloc.restype = c_void_p
    crt.malloc.argtypes = [c_size_t]
    crt.free.restype = None
    crt.free.argtypes = [c_void_p]
    return crt


_provider: _Provider | None = None
_provider_lock = threading.Lock()


def _ensure_provider(lib: OpenSSL) -> _Provider:
    global _provider
    with _provider_lock:
        if _provider is None:
            provider = _Provider(lib)
            # Activate whatever the default context would have used anyway
            # (normally `default`): explicitly loading a provider first would
            # switch that fallback off for the whole process.
            lib.OSSL_PROVIDER_available(None, b"default")
            if not lib.OSSL_PROVIDER_add_builtin(
                None, PROVIDER_NAME, provider.init_address
            ):
                raise UnsupportedOpenSSLError(
                    f"cannot register provider: {drain_errors(lib)}"
                )
            if not lib.OSSL_PROVIDER_load(None, PROVIDER_NAME):
                raise UnsupportedOpenSSLError(
                    f"cannot load provider: {drain_errors(lib)}"
                )
            _provider = provider
        return _provider


def make_key(lib: OpenSSL, handle: int, key_type: str) -> int:
    """An ``EVP_PKEY *`` (owned by the caller) whose signing goes to ``handle``."""
    _ensure_provider(lib)
    name = b"RSA" if key_type == "rsa" else b"EC"
    context = lib.EVP_PKEY_CTX_new_from_name(None, name, _PROPERTIES)
    if not context:
        raise UnsupportedOpenSSLError(
            f"cannot use the sslcontext provider: {drain_errors(lib)}"
        )
    try:
        value = c_uint64(handle)
        params = (OSSL_PARAM * 2)()
        params[0].key = _HANDLE_PARAM
        params[0].data_type = PARAM_UNSIGNED_INTEGER
        params[0].data = ctypes.addressof(value)
        params[0].data_size = ctypes.sizeof(value)
        key = c_void_p()
        if (
            lib.EVP_PKEY_fromdata_init(context) != 1
            or lib.EVP_PKEY_fromdata(
                context, ctypes.byref(key), _EVP_PKEY_KEYPAIR, ctypes.addressof(params)
            )
            != 1
        ):
            raise UnsupportedOpenSSLError(
                f"cannot create a provider key: {drain_errors(lib)}"
            )
        return key.value
    finally:
        lib.EVP_PKEY_CTX_free(context)
