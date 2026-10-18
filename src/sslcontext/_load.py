"""Load certificates and keys held in memory into an :class:`ssl.SSLContext`."""

from __future__ import annotations

import ssl
import weakref
from typing import Sequence, Union

from ._identity import Identity
from ._openssl import OpenSSL, openssl, ssl_ctx_pointer
from ._openssl import _keys
from ._openssl._errors import drain_errors
from ._openssl._objects import read_certificates, read_pkcs12, read_private_key
from ._openssl._signing import make_private_key
from ._pin import PasswordSource, resolve_password
from .exceptions import CredentialError

__all__ = ["BytesOrText", "load_identity", "load_pem", "load_pkcs12"]

BytesOrText = Union[bytes, bytearray, memoryview, str]
"""PEM text as ``str``, or bytes holding PEM or DER."""

_SSL_CTRL_CHAIN = 88
_SSL_CTRL_CHAIN_CERT = 89
_SSL_CTRL_EXTRA_CHAIN_CERT = 14
_SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS = 83
_SSL_CTRL_SET_CLIENT_SIGALGS_LIST = 102
# Client-authentication signatures a PKCS#1-only RSA key can still make.
_NO_PSS_SIGALGS = (
    b"RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512"
)


def _as_bytes(value: BytesOrText, name: str) -> bytes:
    if isinstance(value, str):
        return value.encode("ascii")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{name} must be bytes or str, not {type(value).__name__}")


def read_key_with(lib: OpenSSL, data: bytes, password: PasswordSource) -> int:
    """Read a private key, consulting ``password`` only if the key is encrypted.

    A callable is not called for an unencrypted key, so it never prompts
    needlessly; when it gives nothing, an encrypted key fails at once.
    """
    if not callable(password):
        return read_private_key(lib, data, resolve_password(password))
    try:
        return read_private_key(lib, data, None)
    except CredentialError:
        given = resolve_password(password)
        if given is None:
            raise
        return read_private_key(lib, data, given)


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
    if lib.is_libressl:
        # No per-certificate chains: the context's extra chain, which it owns.
        lib.SSL_CTX_ctrl(pointer, _SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS, 0, None)
        for link in chain:
            lib.X509_up_ref(link)
            if not lib.SSL_CTX_ctrl(pointer, _SSL_CTRL_EXTRA_CHAIN_CERT, 0, link):
                lib.X509_free(link)
                raise CredentialError(
                    f"chain certificate rejected: {drain_errors(lib)}"
                )
    else:
        lib.SSL_CTX_ctrl(pointer, _SSL_CTRL_CHAIN, 0, None)
        for link in chain:
            if not lib.SSL_CTX_ctrl(pointer, _SSL_CTRL_CHAIN_CERT, 1, link):
                raise CredentialError(
                    f"chain certificate rejected: {drain_errors(lib)}"
                )
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
    password: PasswordSource = None,
) -> None:
    """Load a certificate, its chain and its private key from memory.

    ``certificate`` is PEM (the leaf first, then any chain certificates) or a
    single DER certificate. ``key`` is a PEM or DER private key; when omitted
    it is read from ``certificate``, which then holds both. ``password``
    (a value, or a callable asked only if the key turns out encrypted)
    decrypts an encrypted key. Nothing is written to disk.

    Raises :class:`CredentialError` for malformed data, a wrong password, or a
    key that does not match the certificate.
    """
    lib = openssl()
    certificate_data = _as_bytes(certificate, "certificate")
    key_data = certificate_data if key is None else _as_bytes(key, "key")
    certificates = read_certificates(lib, certificate_data)
    try:
        private_key = read_key_with(lib, key_data, password)
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
    password: PasswordSource = None,
) -> None:
    """Load the key, certificate and chain of a PKCS#12 (``.p12``/``.pfx``) bundle.

    Raises :class:`CredentialError` for a malformed bundle or a wrong password.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes, not {type(data).__name__}")
    lib = openssl()
    if callable(password):
        try:
            key, certificate, chain = read_pkcs12(lib, bytes(data), None)
        except CredentialError:
            given = resolve_password(password)
            if given is None:
                raise
            key, certificate, chain = read_pkcs12(lib, bytes(data), given)
    else:
        key, certificate, chain = read_pkcs12(
            lib, bytes(data), resolve_password(password)
        )
    try:
        install(lib, context, certificate, chain, key)
    finally:
        lib.EVP_PKEY_free(key)
        lib.X509_free(certificate)
        for pointer in chain:
            lib.X509_free(pointer)


def load_identity(context: ssl.SSLContext, identity: Identity) -> None:
    """Make a keystore :class:`Identity` the context's certificate and key.

    The private key stays wherever ``identity.signer`` keeps it: OpenSSL asks
    the signer for each handshake signature. The signer is held until
    ``context`` is garbage-collected.

    Raises :class:`CredentialError` for a malformed certificate,
    :class:`UnsupportedOpenSSLError` when the interpreter's OpenSSL cannot
    host the signer, and ``TypeError`` for arguments of the wrong type.
    """
    if not isinstance(identity, Identity):
        raise TypeError(f"expected Identity, got {type(identity).__name__}")
    lib = openssl()
    ssl_ctx_pointer(lib, context)  # type check before anything is allocated
    certificates = read_certificates(lib, identity.certificate)
    try:
        for link in identity.chain:
            certificates.extend(read_certificates(lib, link))
        public = lib.X509_get_pubkey(certificates[0])
        if not public:
            raise CredentialError(f"certificate has no public key: {drain_errors(lib)}")
        handle = _keys.remember(lib, identity.signer, public, identity.label)
        try:
            record = _keys.lookup(handle)
            key = make_private_key(lib, handle, record.key_type)
            try:
                install(lib, context, certificates[0], certificates[1:], key)
            finally:
                lib.EVP_PKEY_free(key)
            # LibreSSL negotiates TLS 1.2 without RSA-PSS: nothing to restrict.
            if (
                record.key_type == "rsa"
                and not lib.is_libressl
                and not getattr(identity.signer, "supports_pss", True)
            ):
                _sign_without_pss(lib, context)
        except BaseException:
            _keys.forget(lib, handle)
            raise
        weakref.finalize(context, _keys.forget, lib, handle)
    finally:
        for pointer in certificates:
            lib.X509_free(pointer)


def _sign_without_pss(lib: OpenSSL, context: ssl.SSLContext) -> None:
    """Keep the context's own signatures to PKCS#1 v1.5 RSA and ECDSA.

    TLS 1.3 needs RSA-PSS, so an RSA identity restricted this way is limited
    to TLS 1.2 peers.
    """
    pointer = ssl_ctx_pointer(lib, context)
    if not lib.SSL_CTX_ctrl(
        pointer, _SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, _NO_PSS_SIGALGS
    ):
        raise CredentialError(
            f"cannot restrict signature algorithms: {drain_errors(lib)}"
        )
