"""Private keys whose signatures come from a :class:`Signer`, on any OpenSSL."""

from __future__ import annotations

from ._api import OpenSSL

__all__ = ["hash_name", "make_private_key", "salt_length"]

# rsa.h PSS salt-length specials (OpenSSL 1.1.1 and 3.x)
SALT_DIGEST, SALT_AUTO, SALT_MAX, SALT_AUTO_DIGEST_MAX = -1, -2, -3, -4


def hash_name(name: str) -> str:
    """OpenSSL's digest names (``SHA2-256``, ``SHA256``, ``sha256``) as hashlib's."""
    normal = name.upper().replace("SHA2-", "SHA").replace("SHA-", "SHA")
    if not normal.startswith("SHA") or not normal[3:].isdigit():
        raise ValueError(f"unsupported digest {name!r}")
    return normal.lower()


def salt_length(spec: int, digest_size: int, bits: int) -> int:
    """The PSS salt length in bytes for OpenSSL's salt-length setting ``spec``."""
    maximum = (bits - 1 + 7) // 8 - digest_size - 2
    if spec in (SALT_AUTO, SALT_MAX):
        return maximum
    if spec in (SALT_DIGEST, SALT_AUTO_DIGEST_MAX):
        return min(digest_size, maximum)
    if spec < 0:
        raise ValueError(f"unsupported PSS salt length {spec}")
    return spec


def make_private_key(lib: OpenSSL, handle: int, key_type: str) -> int:
    """An ``EVP_PKEY *`` (owned by the caller) that signs through ``handle``.

    OpenSSL 3 gets a provider key; OpenSSL 1.1 and LibreSSL a key bound to an
    engine.
    """
    if lib.is_v3:
        from ._provider import make_key
    else:
        from ._engine import make_key
    return make_key(lib, handle, key_type)
