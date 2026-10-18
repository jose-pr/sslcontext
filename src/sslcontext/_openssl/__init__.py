"""Bindings to the interpreter's own OpenSSL. Private."""

from __future__ import annotations

from ._api import OpenSSL, openssl
from ._ctx import ssl_ctx_pointer

__all__ = ["OpenSSL", "openssl", "ssl_ctx_pointer"]
