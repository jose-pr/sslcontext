"""Answer a server's certificate request from Python, one connection at a time.

``SSL_CTX_set_cert_cb`` runs on a client when the server sends a
CertificateRequest (TLS 1.3 post-handshake requests included). One ctypes
callback serves every context; its argument names the handler registered for
that context.
"""

from __future__ import annotations

import ctypes
import itertools
import logging
import ssl
import threading
import weakref
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ..exceptions import CredentialError
from ._api import OpenSSL
from ._ctx import handshake_context, ssl_ctx_pointer
from ._errors import drain_errors

__all__ = ["install_handler", "read_request", "use_identity"]

_log = logging.getLogger("sslcontext")

# ssl.h: SSL_CTRL_CHAIN, SSL_CTRL_CHAIN_CERT, SSL_CTRL_SET_CLIENT_SIGALGS_LIST,
# TLSEXT_NAMETYPE_host_name; obj_mac.h NIDs of the signature algorithms.
_CTRL_CHAIN = 88
_CTRL_CHAIN_CERT = 89
_CTRL_SET_CLIENT_SIGALGS_LIST = 102
_NAMETYPE_HOST = 0
_NID_RSA, _NID_RSA_PSS, _NID_EC = 6, 912, 408
_VERSIONS = {0x0304: "TLSv1.3", 0x0303: "TLSv1.2", 0x0302: "TLSv1.1", 0x0301: "TLSv1"}

Handler = Callable[[int], int]
"""Given an ``SSL *`` mid-handshake, return 1 to go on or 0 to fail it."""

_CALLBACK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
_lock = threading.Lock()
_handlers: Dict[int, Handler] = {}
_by_context: Dict[int, int] = {}
_ids = itertools.count(1)


@_CALLBACK  # type: ignore[misc]
def _dispatch(ssl_pointer: Optional[int], argument: Optional[int]) -> int:
    with _lock:
        handler = _handlers.get(argument or 0)
    if handler is None or not ssl_pointer:
        return 1
    try:
        return handler(ssl_pointer)
    except BaseException:  # noqa: BLE001 - nothing may unwind into OpenSSL
        _log.warning("sslcontext: client certificate selection failed", exc_info=True)
        return 0


def _forget(pointer: int, handler_id: int) -> None:
    with _lock:
        _handlers.pop(handler_id, None)
        if _by_context.get(pointer) == handler_id:
            del _by_context[pointer]


def install_handler(lib: OpenSSL, context: ssl.SSLContext, handler: Handler) -> None:
    """Make ``handler`` answer every certificate request on ``context``,
    replacing a handler installed before; it lives as long as ``context``."""
    pointer = ssl_ctx_pointer(lib, context)
    with _lock:
        handler_id = next(_ids)
        previous = _by_context.pop(pointer, None)
        if previous is not None:
            _handlers.pop(previous, None)
        _handlers[handler_id] = handler
        _by_context[pointer] = handler_id
    lib.SSL_CTX_set_cert_cb(
        pointer, ctypes.cast(_dispatch, ctypes.c_void_p), ctypes.c_void_p(handler_id)
    )
    weakref.finalize(handshake_context(context), _forget, pointer, handler_id)


def _name_der(lib: OpenSSL, name: int) -> bytes:
    out = ctypes.c_void_p()
    length = lib.i2d_X509_NAME(name, ctypes.byref(out))
    if length <= 0:
        raise CredentialError(f"cannot encode a name: {drain_errors(lib)}")
    try:
        return ctypes.string_at(out.value, length)
    finally:
        lib.CRYPTO_free(out.value, b"", 0)


def read_request(
    lib: OpenSSL, ssl_pointer: int
) -> Tuple[Optional[str], List[Tuple[str, bytes]], frozenset, bool, str, bool]:
    """``(host, [(name, der)], key_types, rsa_pss_required, version, server)``
    for the request being answered on ``ssl_pointer``."""
    from ._objects import _name_text

    server = bool(lib.SSL_is_server(ssl_pointer))
    host = lib.SSL_get_servername(ssl_pointer, _NAMETYPE_HOST)
    version_number = lib.SSL_version(ssl_pointer)
    version = _VERSIONS.get(version_number, f"0x{version_number:04x}")
    authorities = []
    names = lib.SSL_get_client_CA_list(ssl_pointer)
    if names:
        for index in range(lib.OPENSSL_sk_num(names)):
            name = lib.OPENSSL_sk_value(names, index)
            authorities.append((_name_text(lib, name), _name_der(lib, name)))
    signs = set()
    count = lib.SSL_get_sigalgs(ssl_pointer, 0, None, None, None, None, None)
    for index in range(max(count, 0)):
        sign = ctypes.c_int()
        lib.SSL_get_sigalgs(
            ssl_pointer, index, ctypes.byref(sign), None, None, None, None
        )
        signs.add(sign.value)
    if not signs:  # no list: TLS 1.2 then allows RSA and ECDSA with SHA-1
        signs = {_NID_RSA, _NID_EC}
    key_types = set()
    if signs & {_NID_RSA, _NID_RSA_PSS}:
        key_types.add("rsa")
    if _NID_EC in signs:
        key_types.add("ec")
    pss_required = version == "TLSv1.3" or _NID_RSA not in signs
    return (
        host.decode("ascii", "replace") if host else None,
        authorities,
        frozenset(key_types),
        pss_required,
        version,
        server,
    )


def use_identity(
    lib: OpenSSL,
    ssl_pointer: int,
    certificate: int,
    chain: Sequence[int],
    key: int,
    sigalgs: Optional[bytes] = None,
) -> None:
    """Make ``certificate``, ``chain`` and ``key`` this connection's identity;
    the connection takes its own references. ``sigalgs`` limits the
    connection's own signature algorithms."""
    lib.ERR_clear_error()
    if not lib.SSL_use_certificate(ssl_pointer, certificate):
        raise CredentialError(f"certificate rejected: {drain_errors(lib)}")
    lib.SSL_ctrl(ssl_pointer, _CTRL_CHAIN, 0, None)
    for link in chain:
        if not lib.SSL_ctrl(ssl_pointer, _CTRL_CHAIN_CERT, 1, link):
            raise CredentialError(f"chain certificate rejected: {drain_errors(lib)}")
    if not lib.SSL_use_PrivateKey(ssl_pointer, key):
        raise CredentialError(f"private key rejected: {drain_errors(lib)}")
    if sigalgs is not None and not lib.SSL_ctrl(
        ssl_pointer, _CTRL_SET_CLIENT_SIGALGS_LIST, 0, sigalgs
    ):
        raise CredentialError(
            f"cannot restrict signature algorithms: {drain_errors(lib)}"
        )
