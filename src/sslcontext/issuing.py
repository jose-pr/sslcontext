"""A small certificate authority: create or load one, issue server certificates.

Keys and certificates are made by the interpreter's own OpenSSL, the one the
``ssl`` module uses, so no third-party package is needed and the result works
on OpenSSL 1.1.1 and 3.x alike. The CA's private key is held in memory;
:meth:`CertificateAuthority.private_key_pem` exports it (optionally
encrypted) for the caller to store.

Meant for local use: test servers, and proxies that terminate TLS for
clients told to trust the CA. Restrict such a CA with ``permitted=`` (X.509
name constraints) so that, if its key leaks, it cannot vouch for other sites.
"""

from __future__ import annotations

import ctypes
import ipaddress
import secrets
import ssl
import threading
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Union

from ._context import create_context
from ._identity import CertificateInfo
from ._load import BytesOrText, _as_bytes, load_pem, read_key_with
from ._openssl import OpenSSL, openssl
from ._openssl._errors import drain_errors
from ._openssl._objects import certificate_der, certificate_fields, read_certificates
from ._pin import PasswordSource, resolve_password
from .exceptions import CredentialError, SSLContextError

__all__ = ["CertificateAuthority", "IssuedCertificate"]

_EVP_PKEY_RSA, _EVP_PKEY_EC = 6, 408
_NID_PRIME256V1 = 415
_OPENSSL_EC_NAMED_CURVE = 1
# evp.h / ec.h / rsa.h controls; PARAMGEN|KEYGEN is 6 in OpenSSL 1.1.1 and 3.x.
_OP_KEYGEN, _OP_PARAMGEN_KEYGEN = 4, 6
_CTRL_EC_PARAMGEN_CURVE_NID = 0x1001
_CTRL_RSA_KEYGEN_BITS = 0x1003
_MBSTRING_UTF8 = 0x1000
_BIO_CTRL_INFO = 3
# X509V3_CTX is a small struct the caller allocates; this is ample for 1.1 and 3.x.
_X509V3_CTX_SIZE = 512


@dataclass(frozen=True)
class IssuedCertificate:
    """A leaf certificate and its key, as PEM.

    ``chain`` holds the issuing CA's certificate. :meth:`load_into` installs
    all of it into a context.
    """

    certificate: bytes
    key: bytes = field(repr=False)
    chain: bytes = b""

    def load_into(self, context: ssl.SSLContext) -> None:
        load_pem(context, self.certificate + self.chain, self.key)

    @property
    def info(self) -> CertificateInfo:
        """The decoded leaf certificate."""
        lib = openssl()
        (x509,) = read_certificates(lib, self.certificate)
        try:
            return CertificateInfo(
                **certificate_fields(lib, certificate_der(lib, x509))
            )
        finally:
            lib.X509_free(x509)


def _bio_bytes(lib: OpenSSL, write: "ctypes._CFuncPtr", *args: object) -> bytes:
    bio = lib.BIO_new(lib.BIO_s_mem())
    try:
        if write(bio, *args) != 1:
            raise SSLContextError(f"cannot encode as PEM: {drain_errors(lib)}")
        data = ctypes.c_void_p()
        size = lib.BIO_ctrl(bio, _BIO_CTRL_INFO, 0, ctypes.byref(data))
        return ctypes.string_at(data.value, size)
    finally:
        lib.BIO_free(bio)


def _generate_key(lib: OpenSSL, key_type: str) -> int:
    if key_type not in ("ec", "rsa"):
        raise ValueError(f"key_type must be 'ec' or 'rsa', not {key_type!r}")
    if key_type == "ec" and lib.is_libressl:
        return _generate_ec_key_libressl(lib)
    kind = _EVP_PKEY_EC if key_type == "ec" else _EVP_PKEY_RSA
    context = lib.EVP_PKEY_CTX_new_id(kind, None)
    try:
        ok = context and lib.EVP_PKEY_keygen_init(context) == 1
        if key_type == "ec":
            ok = (
                ok
                and lib.EVP_PKEY_CTX_ctrl(
                    context,
                    kind,
                    _OP_PARAMGEN_KEYGEN,
                    _CTRL_EC_PARAMGEN_CURVE_NID,
                    _NID_PRIME256V1,
                    None,
                )
                > 0
            )
        else:
            ok = (
                ok
                and lib.EVP_PKEY_CTX_ctrl(
                    context, kind, _OP_KEYGEN, _CTRL_RSA_KEYGEN_BITS, 2048, None
                )
                > 0
            )
        key = ctypes.c_void_p()
        if not ok or lib.EVP_PKEY_keygen(context, ctypes.byref(key)) != 1:
            raise SSLContextError(f"key generation failed: {drain_errors(lib)}")
        return key.value
    finally:
        if context:
            lib.EVP_PKEY_CTX_free(context)


def _generate_ec_key_libressl(lib: OpenSSL) -> int:
    # OpenSSL 1.0's EC keygen needs parameters first; and a key not marked as
    # a named curve is written with explicit parameters, which verifiers refuse.
    inner = lib.EC_KEY_new_by_curve_name(_NID_PRIME256V1)
    key = lib.EVP_PKEY_new()
    try:
        lib.EC_KEY_set_asn1_flag(inner, _OPENSSL_EC_NAMED_CURVE)
        if (
            not inner
            or not key
            or lib.EC_KEY_generate_key(inner) != 1
            or lib.EVP_PKEY_set1_EC_KEY(key, inner) != 1
        ):
            lib.EVP_PKEY_free(key)
            raise SSLContextError(f"key generation failed: {drain_errors(lib)}")
        return key  # type: ignore[no-any-return]
    finally:
        lib.EC_KEY_free(inner)


def _san_and_constraints(names: Iterable[str]) -> List[str]:
    entries = []
    for name in names:
        try:
            entries.append(f"IP:{ipaddress.ip_address(name)}")
        except ValueError:
            entries.append(f"DNS:{name}")
    return entries


def _permitted_entries(permitted: Iterable[str]) -> List[str]:
    """RFC 5280 name-constraint subtrees: a DNS name covers its subdomains."""
    subtrees = []
    for item in permitted:
        text = item.strip().lower().rstrip(".")
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            domain = text[2:] if text.startswith("*.") else text.lstrip(".")
            if not domain or "*" in domain:
                raise ValueError(
                    f"cannot express {item!r} as a name constraint"
                ) from None
            subtrees.append(f"permitted;DNS:{domain}")
        else:
            subtrees.append(f"permitted;IP:{network.network_address}/{network.netmask}")
    return subtrees


class _Builder:
    """One certificate being assembled; frees what it allocates."""

    def __init__(self, lib: OpenSSL, public_key: int, days: float) -> None:
        self.lib = lib
        self.x509 = lib.X509_new()
        if not self.x509:
            raise MemoryError("X509_new failed")
        lib.X509_set_version(self.x509, 2)
        serial = secrets.token_bytes(16)
        serial = bytes([serial[0] & 0x7F]) + serial[1:]  # positive, nonzero length
        number = lib.BN_bin2bn(serial, len(serial), None)
        lib.BN_to_ASN1_INTEGER(number, lib.X509_get_serialNumber(self.x509))
        lib.BN_free(number)
        whole_days = int(days)
        seconds = int((days - whole_days) * 86400)
        lib.X509_time_adj_ex(lib.X509_getm_notBefore(self.x509), 0, -3600, None)
        lib.X509_time_adj_ex(
            lib.X509_getm_notAfter(self.x509), whole_days, seconds, None
        )
        lib.X509_set_pubkey(self.x509, public_key)

    def subject(self, common_name: str) -> None:
        name = self.lib.X509_get_subject_name(self.x509)
        if not self.lib.X509_NAME_add_entry_by_txt(
            name, b"CN", _MBSTRING_UTF8, common_name.encode("utf-8"), -1, -1, 0
        ):
            raise ValueError(f"invalid common name: {drain_errors(self.lib)}")

    def extensions(self, issuer: int, values: List[tuple]) -> None:
        lib = self.lib
        context = ctypes.create_string_buffer(_X509V3_CTX_SIZE)
        lib.X509V3_set_ctx(context, issuer or self.x509, self.x509, None, None, 0)
        for short_name, value in values:
            nid = lib.OBJ_sn2nid(short_name.encode("ascii"))
            extension = lib.X509V3_EXT_conf_nid(
                None, context, nid, value.encode("ascii")
            )
            if not extension:
                raise ValueError(
                    f"invalid {short_name} extension {value!r}: {drain_errors(lib)}"
                )
            try:
                lib.X509_add_ext(self.x509, extension, -1)
            finally:
                lib.X509_EXTENSION_free(extension)

    def sign(self, issuer_name_from: int, key: int) -> int:
        lib = self.lib
        lib.X509_set_issuer_name(self.x509, lib.X509_get_subject_name(issuer_name_from))
        if lib.X509_sign(self.x509, key, lib.EVP_sha256()) <= 0:
            raise SSLContextError(
                f"signing the certificate failed: {drain_errors(lib)}"
            )
        x509, self.x509 = self.x509, None
        return x509

    def close(self) -> None:
        if self.x509:
            self.lib.X509_free(self.x509)
            self.x509 = None


class CertificateAuthority:
    """A CA whose certificate and private key are held in memory.

    Construct from PEM (``certificate`` and ``key``; ``password`` decrypts an
    encrypted key) or with :meth:`create`. Raises ``CredentialError`` for
    malformed PEM or a key that is not the certificate's.
    """

    def __init__(
        self,
        certificate: BytesOrText,
        key: BytesOrText,
        password: PasswordSource = None,
    ) -> None:
        self._lib = lib = openssl()
        self._lock = threading.Lock()
        certificates = read_certificates(lib, _as_bytes(certificate, "certificate"))
        for extra in certificates[1:]:
            lib.X509_free(extra)
        self._x509 = certificates[0]
        self._key = 0
        self._key = read_key_with(lib, _as_bytes(key, "key"), password)
        public = lib.X509_get_pubkey(self._x509)
        try:
            matches = (
                lib.EVP_PKEY_eq(public, self._key) == 1
                if lib.is_v3
                else (lib.EVP_PKEY_cmp(public, self._key) == 1)
            )
        finally:
            lib.EVP_PKEY_free(public)
        if not matches:
            raise CredentialError("the key does not belong to the CA certificate")
        self.certificate: bytes = _bio_bytes(lib, lib.PEM_write_bio_X509, self._x509)
        """The CA certificate, PEM: what clients must trust."""

    def __del__(self) -> None:
        lib = getattr(self, "_lib", None)
        if lib is None:
            return
        if getattr(self, "_x509", None):
            lib.X509_free(self._x509)
            self._x509 = None
        if getattr(self, "_key", None):
            lib.EVP_PKEY_free(self._key)
            self._key = None

    def __repr__(self) -> str:
        return f"<CertificateAuthority {self.info.subject!r}>"

    @property
    def info(self) -> CertificateInfo:
        return CertificateInfo(**certificate_fields(self._lib, self.der))

    @property
    def der(self) -> bytes:
        return certificate_der(self._lib, self._x509)

    @classmethod
    def create(
        cls,
        common_name: str,
        *,
        permitted: Iterable[str] = (),
        days: float = 3650,
        key_type: str = "ec",
    ) -> "CertificateAuthority":
        """A new self-signed CA.

        ``permitted`` names what it may vouch for, as critical X.509 name
        constraints: DNS names (``corp.example`` covers its subdomains;
        ``*.corp.example`` and ``.corp.example`` mean the same) and IP
        networks (``10.0.0.0/8``). Empty means unconstrained. ``key_type``
        is ``"ec"`` (P-256) or ``"rsa"`` (2048-bit). ``ValueError`` for a
        name that cannot be a constraint.
        """
        subtrees = _permitted_entries(permitted)
        lib = openssl()
        key = _generate_key(lib, key_type)
        try:
            builder = _Builder(lib, key, days)
            try:
                builder.subject(common_name)
                extensions = [
                    ("basicConstraints", "critical,CA:TRUE,pathlen:0"),
                    ("keyUsage", "critical,keyCertSign,cRLSign,digitalSignature"),
                    ("subjectKeyIdentifier", "hash"),
                ]
                if subtrees:
                    extensions.append(
                        ("nameConstraints", "critical," + ",".join(subtrees))
                    )
                builder.extensions(0, extensions)
                x509 = builder.sign(builder.x509, key)
            finally:
                builder.close()
            try:
                certificate = _bio_bytes(lib, lib.PEM_write_bio_X509, x509)
            finally:
                lib.X509_free(x509)
            key_pem = _bio_bytes(
                lib, lib.PEM_write_bio_PKCS8PrivateKey, key, None, None, 0, None, None
            )
        finally:
            lib.EVP_PKEY_free(key)
        return cls(certificate, key_pem)

    def private_key_pem(self, password: Union[str, bytes, None] = None) -> bytes:
        """The CA key as PKCS#8 PEM, AES-256 encrypted when ``password`` is given."""
        lib = self._lib
        secret = resolve_password(password)
        cipher = lib.EVP_aes_256_cbc() if secret else None
        return _bio_bytes(
            lib,
            lib.PEM_write_bio_PKCS8PrivateKey,
            self._key,
            cipher,
            None,
            0,
            None,
            secret,
        )

    def issue(
        self,
        names: Iterable[str],
        *,
        days: float = 30,
        key_type: str = "ec",
        common_name: Optional[str] = None,
    ) -> IssuedCertificate:
        """A server certificate for ``names`` (DNS names and IP addresses).

        The leaf carries them as subject alternative names, serverAuth and
        clientAuth usage, and an authority key identifier, so strict X.509
        verification (the default from Python 3.13) accepts it. A fresh key
        each time. ``ValueError`` for an empty ``names``.
        """
        names = [str(n) for n in names]
        if not names:
            raise ValueError("issue() needs at least one name")
        lib = self._lib
        key = _generate_key(lib, key_type)
        try:
            builder = _Builder(lib, key, days)
            try:
                builder.subject(common_name or names[0])
                builder.extensions(
                    self._x509,
                    [
                        ("basicConstraints", "critical,CA:FALSE"),
                        ("keyUsage", "critical,digitalSignature,keyEncipherment"),
                        ("extendedKeyUsage", "serverAuth,clientAuth"),
                        ("subjectAltName", ",".join(_san_and_constraints(names))),
                        ("subjectKeyIdentifier", "hash"),
                        ("authorityKeyIdentifier", "keyid:always"),
                    ],
                )
                with self._lock:
                    x509 = builder.sign(self._x509, self._key)
            finally:
                builder.close()
            try:
                certificate = _bio_bytes(lib, lib.PEM_write_bio_X509, x509)
            finally:
                lib.X509_free(x509)
            key_pem = _bio_bytes(
                lib, lib.PEM_write_bio_PKCS8PrivateKey, key, None, None, 0, None, None
            )
        finally:
            lib.EVP_PKEY_free(key)
        return IssuedCertificate(certificate, key_pem, self.certificate)

    def server_context(self, names: Iterable[str], **options: object) -> ssl.SSLContext:
        """A server context presenting a fresh certificate for ``names``.

        ``options`` go to :func:`sslcontext.create_context` (purpose is
        ``"server"``).
        """
        context = create_context("server", **options)  # type: ignore[arg-type]
        self.issue(names).load_into(context)
        return context
