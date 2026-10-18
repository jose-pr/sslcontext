"""Load certificates and keys held in memory into an :class:`ssl.SSLContext`."""

from __future__ import annotations

import ssl
from typing import Sequence, Union

from ._openssl import OpenSSL, openssl, ssl_ctx_pointer
from ._openssl._errors import drain_errors
from ._openssl._objects import read_certificates, read_pkcs12, read_private_key
from .exceptions import CredentialError

__all__ = ["BytesOrText", "load_pem", "load_pkcs12"]

BytesOrText = Union[bytes, bytearray, memoryview, str]
"""PEM text as ``str``, or bytes holding PEM or DER."""

_SSL_CTRL_CHAIN = 88
_SSL_CTRL_CHAIN_CERT = 89


def _as_bytes(value: BytesOrText, name: str) -> bytes:
    if isinstance(value, str):
        return value.encode("ascii")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{name} must be bytes or str, not {type(value).__name__}")


def _password(value: str | bytes | None) -> bytes | None:
    if value is None or isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"password must be str or bytes, not {type(value).__name__}")


def install(
    lib: OpenSSL,
    context: ssl.SSLContext,
    certificate: int,
    chain: Sequence[int],
    key: int,
) -> None:
    """Make ``certificate``, ``chain`` and ``key`` the context's identity.

    The context takes its own references; the caller still frees its pointers.
    Identities of different key types (RSA, EC) coexist; one of the same type
    replaces the previous one.
    """
    pointer = ssl_ctx_pointer(lib, context)
    lib.ERR_clear_error()
    if not lib.SSL_CTX_use_certificate(pointer, certificate):
        raise CredentialError(f"certificate rejected: {drain_errors(lib)}")
    lib.SSL_CTX_ctrl(pointer, _SSL_CTRL_CHAIN, 0, None)
    for link in chain:
        if not lib.SSL_CTX_ctrl(pointer, _SSL_CTRL_CHAIN_CERT, 1, link):
            raise CredentialError(f"chain certificate rejected: {drain_errors(lib)}")
    if not lib.SSL_CTX_use_PrivateKey(pointer, key):
        errors = drain_errors(lib)
        if "key values mismatch" in errors:
            raise CredentialError(
                f"the private key does not match the certificate: {errors}"
            )
        raise CredentialError(f"private key rejected: {errors}")
    if not lib.SSL_CTX_check_private_key(pointer):
        raise CredentialError(
            f"the private key does not match the certificate: {drain_errors(lib)}"
        )


def load_pem(
    context: ssl.SSLContext,
    certificate: BytesOrText,
    key: BytesOrText | None = None,
    password: str | bytes | None = None,
) -> None:
    """Load a certificate, its chain and its private key from memory.

    ``certificate`` is PEM (the leaf first, then any chain certificates) or a
    single DER certificate. ``key`` is a PEM or DER private key; when omitted
    it is read from ``certificate``, which then holds both. ``password``
    decrypts an encrypted key. Nothing is written to disk.

    Raises :class:`CredentialError` for malformed data, a wrong password, or a
    key that does not match the certificate.
    """
    lib = openssl()
    certificate_data = _as_bytes(certificate, "certificate")
    key_data = certificate_data if key is None else _as_bytes(key, "key")
    certificates = read_certificates(lib, certificate_data)
    try:
        private_key = read_private_key(lib, key_data, _password(password))
        try:
            install(lib, context, certificates[0], certificates[1:], private_key)
        finally:
            lib.EVP_PKEY_free(private_key)
    finally:
        for pointer in certificates:
            lib.X509_free(pointer)


def load_pkcs12(
    context: ssl.SSLContext,
    data: bytes | bytearray | memoryview,
    password: str | bytes | None = None,
) -> None:
    """Load the key, certificate and chain of a PKCS#12 (``.p12``/``.pfx``) bundle.

    Raises :class:`CredentialError` for a malformed bundle or a wrong password.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes, not {type(data).__name__}")
    lib = openssl()
    key, certificate, chain = read_pkcs12(lib, bytes(data), _password(password))
    try:
        install(lib, context, certificate, chain, key)
    finally:
        lib.EVP_PKEY_free(key)
        lib.X509_free(certificate)
        for pointer in chain:
            lib.X509_free(pointer)
