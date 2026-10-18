"""Keys whose private half is a Python :class:`Signer`.

OpenSSL sees an opaque key handle; the record behind it holds the signer and
the certificate's public key, which answers every question about the key
except how to sign.
"""

from __future__ import annotations

import itertools
import logging
import threading
from dataclasses import dataclass

from .._identity import Signer
from ._api import OpenSSL

__all__ = ["KeyRecord", "forget", "lookup", "remember"]

_log = logging.getLogger("sslcontext")

EVP_PKEY_RSA = 6
EVP_PKEY_EC = 408


@dataclass
class KeyRecord:
    signer: Signer
    public: int
    """``EVP_PKEY *`` of the certificate's public key, owned by the record."""
    key_type: str
    """``"rsa"`` or ``"ec"``."""
    bits: int
    max_size: int
    label: str


_lock = threading.Lock()
_records: dict[int, KeyRecord] = {}
_handles = itertools.count(1)


def remember(lib: OpenSSL, signer: Signer, public: int, label: str) -> int:
    """Register a signer for the public key ``public`` (ownership moves here)."""
    kind = lib.EVP_PKEY_id(public)
    if kind == EVP_PKEY_RSA:
        key_type = "rsa"
    elif kind == EVP_PKEY_EC:
        key_type = "ec"
    else:
        lib.EVP_PKEY_free(public)
        raise ValueError("only RSA and EC certificates can use a signer")
    record = KeyRecord(
        signer,
        public,
        key_type,
        lib.EVP_PKEY_bits(public),
        lib.EVP_PKEY_size(public),
        label,
    )
    with _lock:
        handle = next(_handles)
        _records[handle] = record
    return handle


def lookup(handle: int) -> KeyRecord | None:
    with _lock:
        return _records.get(handle)


def forget(lib: OpenSSL, handle: int) -> None:
    """Drop a record once no ``SSLContext`` can use its key any more."""
    with _lock:
        record = _records.pop(handle, None)
    if record is not None:
        lib.EVP_PKEY_free(record.public)
