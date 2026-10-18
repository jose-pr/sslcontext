"""Private keys whose signatures come from a :class:`Signer`, on any OpenSSL."""

from __future__ import annotations

from ..exceptions import UnsupportedOpenSSLError
from ._api import OpenSSL

__all__ = ["make_private_key"]


def make_private_key(lib: OpenSSL, handle: int, key_type: str) -> int:
    """An ``EVP_PKEY *`` for the record ``handle``: a provider key on OpenSSL 3."""
    if lib.is_v3:
        from ._provider import make_key

        return make_key(lib, handle, key_type)
    raise UnsupportedOpenSSLError(
        "keystore identities on OpenSSL 1.1 are not available in this build"
    )
