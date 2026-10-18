"""Turn OpenSSL's thread-local error queue into a message."""

from __future__ import annotations

import ctypes

from ._api import OpenSSL

__all__ = ["drain_errors"]


def drain_errors(lib: OpenSSL) -> str:
    """Empty the error queue; return its entries joined, newest last."""
    messages = []
    buffer = ctypes.create_string_buffer(256)
    while True:
        code = lib.ERR_get_error()
        if not code:
            break
        lib.ERR_error_string_n(code, buffer, len(buffer))
        messages.append(buffer.value.decode("ascii", "replace"))
    return "; ".join(messages) or "no OpenSSL error recorded"
