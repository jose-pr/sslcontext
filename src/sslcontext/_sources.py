"""Certificates and keys from wherever the caller keeps them."""

from __future__ import annotations

import os
from typing import Any, Iterable, List, Union

__all__ = [
    "CertificateLike",
    "CertificatesLike",
    "KeyLike",
    "read_source",
    "read_sources",
]

_PEM = "-----BEGIN "

CertificateLike = Union[str, bytes, bytearray, memoryview, "os.PathLike[str]", Any]
"""One certificate source: PEM text (a ``str`` holding a PEM header), PEM or
DER bytes, a path (``str`` without a PEM header, or ``os.PathLike``), an
object with ``open()`` (``pathlib.Path`` and its kin, zip paths, package
resources), a readable file object, or a ``cryptography`` certificate."""

CertificatesLike = Union[CertificateLike, Iterable[CertificateLike]]
"""One source, or a list or tuple of them."""

KeyLike = Union[str, bytes, bytearray, memoryview, "os.PathLike[str]", Any]
"""A private key from the same sources, or a ``cryptography`` private key."""


def read_source(value: Any, what: str = "certificate") -> bytes:
    """The bytes ``value`` holds or names; ``what`` names it in errors."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        if _PEM in value:
            return value.encode("ascii")
        return _read_path(value)
    if isinstance(value, os.PathLike):
        return _read_path(os.fspath(value))
    if callable(getattr(value, "private_bytes", None)):  # cryptography private key
        from cryptography.hazmat.primitives import serialization

        return value.private_bytes(  # type: ignore[no-any-return]
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    if callable(getattr(value, "public_bytes", None)) and callable(
        getattr(value, "fingerprint", None)
    ):  # cryptography certificate
        from cryptography.hazmat.primitives import serialization

        return value.public_bytes(serialization.Encoding.DER)  # type: ignore[no-any-return]
    if callable(getattr(value, "read", None)):
        return _as_bytes(value.read(), what)
    if callable(getattr(value, "open", None)):
        with value.open("rb") as handle:
            return _as_bytes(handle.read(), what)
    raise TypeError(
        f"{what} must be PEM text, bytes, a path, something with open() or "
        f"read(), or a cryptography object, not {type(value).__name__}"
    )


def read_sources(value: Any, what: str = "certificate") -> List[bytes]:
    """``read_source`` of each item of a list or tuple, or of ``value`` alone."""
    if isinstance(value, (list, tuple)):
        if not value:
            raise ValueError(f"{what}: the list is empty")
        return [read_source(item, what) for item in value]
    return [read_source(value, what)]


def is_pem(data: bytes) -> bool:
    return _PEM.encode() in data


def _read_path(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _as_bytes(data: Any, what: str) -> bytes:
    if isinstance(data, str):
        return data.encode("ascii")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"reading the {what} gave {type(data).__name__}, not bytes")


def pem_and_der(blobs: Iterable[bytes]) -> tuple:
    """``(pem_text, der_bytes)``: PEM blobs joined as text, DER ones concatenated,
    as ``SSLContext.load_verify_locations(cadata=...)`` takes them."""
    pem, der = [], []
    for blob in blobs:
        (pem if is_pem(blob) else der).append(blob)
    text = "\n".join(b.decode("ascii").strip() for b in pem) + "\n" if pem else ""
    return text, b"".join(der)
