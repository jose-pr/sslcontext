"""Reach the ``SSL_CTX *`` behind a standard-library :class:`ssl.SSLContext`."""

from __future__ import annotations

import ctypes
import ssl

from ..exceptions import UnsupportedOpenSSLError
from ._api import OpenSSL

__all__ = ["ssl_ctx_pointer"]

# CPython's PySSLContext begins `PyObject_HEAD; SSL_CTX *ctx;` (Modules/_ssl.c),
# so the pointer sits right after the object header.
_HEADER = object.__basicsize__

_VERIFY_BITS = {ssl.CERT_NONE: 0, ssl.CERT_OPTIONAL: 1, ssl.CERT_REQUIRED: 3}


def handshake_context(context: ssl.SSLContext) -> ssl.SSLContext:
    """The context whose ``SSL_CTX`` performs ``context``'s handshakes.

    A ``truststore.SSLContext`` is an ``ssl.SSLContext`` that delegates every
    connection to an inner one in ``_ctx``; its own ``SSL_CTX`` is never used.
    """
    inner = getattr(context, "_ctx", None)
    if type(context).__module__.split(".")[0] == "truststore" and isinstance(
        inner, ssl.SSLContext
    ):
        return inner
    return context


def ssl_ctx_pointer(lib: OpenSSL, context: ssl.SSLContext) -> int:
    """Return the ``SSL_CTX *`` that performs the context's handshakes.

    The pointer is cross-checked against the context's options and verify
    mode before it is used, so an interpreter laid out differently raises
    :class:`UnsupportedOpenSSLError` instead of corrupting memory.
    """
    if not isinstance(context, ssl.SSLContext):
        raise TypeError(f"expected ssl.SSLContext, got {type(context).__name__}")
    context = handshake_context(context)
    pointer = ctypes.c_void_p.from_address(id(context) + _HEADER).value
    if not pointer:
        raise UnsupportedOpenSSLError("this interpreter's SSLContext holds no SSL_CTX")
    mask = (
        (1 << 64) - 1 if lib.is_v3 else (1 << (8 * ctypes.sizeof(ctypes.c_ulong))) - 1
    )
    # OpenSSL's verify bits: PEER=1, FAIL_IF_NO_PEER_CERT=2 (higher bits vary).
    expected_mode = _VERIFY_BITS[context.verify_mode]
    if (lib.SSL_CTX_get_options(pointer) & mask) != (int(context.options) & mask) or (
        lib.SSL_CTX_get_verify_mode(pointer) & 3 != expected_mode
    ):
        raise UnsupportedOpenSSLError(
            "cannot locate SSL_CTX inside ssl.SSLContext on this interpreter"
        )
    return pointer
