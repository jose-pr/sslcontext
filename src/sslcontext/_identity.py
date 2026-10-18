"""The contract between a keystore and the TLS stack: identities and signers."""

from __future__ import annotations

import datetime
import enum
import functools
from dataclasses import dataclass, field
from typing import Optional, Protocol, Tuple, runtime_checkable

__all__ = ["CertificateInfo", "HASHES", "Identity", "Padding", "Signer"]

HASHES = ("sha1", "sha224", "sha256", "sha384", "sha512")
"""Hash names a signer may be asked to sign for, as :mod:`hashlib` spells them."""


class Padding(enum.Enum):
    """RSA signature padding. ECDSA signatures have none."""

    PKCS1V15 = "pkcs1v15"
    PSS = "pss"


@runtime_checkable
class Signer(Protocol):
    """Signs a digest with a private key the caller cannot see.

    Implemented by every keystore backend, and by anything else that can sign:
    a remote HSM, a cloud KMS, a test key.

    A signer may also have a ``supports_pss`` attribute. When it is
    ``False`` for an RSA key, :func:`load_identity` keeps the context's own
    signatures to PKCS#1 v1.5, which limits that identity to TLS 1.2.
    """

    def sign(
        self,
        digest: bytes,
        *,
        hash: str,
        padding: Optional[Padding] = None,
        salt_length: Optional[int] = None,
    ) -> bytes:
        """Return the signature of ``digest``, already hashed with ``hash``.

        ``hash`` is one of :data:`HASHES`. For an RSA key ``padding`` is set;
        with :attr:`Padding.PSS`, ``salt_length`` is the salt length in bytes
        and MGF1 uses ``hash``. For an EC key ``padding`` is ``None`` and the
        result is a DER-encoded ECDSA signature. Raising any exception fails
        the handshake.

        Called from the thread performing the TLS handshake, with OpenSSL
        mid-operation: a signer must not use the same ``ssl.SSLContext``.
        """
        ...


@dataclass(frozen=True)
class CertificateInfo:
    """What a certificate says about itself, decoded by OpenSSL."""

    subject: str
    """RFC 4514 distinguished name, e.g. ``CN=alice,O=Example``."""
    issuer: str
    serial: str
    """Serial number in upper-case hexadecimal."""
    not_before: datetime.datetime
    not_after: datetime.datetime
    """Validity bounds, timezone-aware UTC."""
    sha1: str
    """SHA-1 thumbprint of the DER certificate, upper-case hex (Windows' "Thumbprint")."""
    sha256: str
    key_type: str
    """``"rsa"``, ``"ec"`` or ``"other"``."""
    key_bits: int

    def valid_at(self, when: Optional[datetime.datetime] = None) -> bool:
        """Whether ``when`` (default: now) lies inside the validity period."""
        when = when or datetime.datetime.now(datetime.timezone.utc)
        return self.not_before <= when <= self.not_after


@dataclass(frozen=True)
class Identity:
    """A certificate, its chain, and a signer for its private key.

    ``certificate`` and each entry of ``chain`` are DER bytes; ``chain`` runs
    from the issuer of ``certificate`` upward and may omit the root.
    """

    certificate: bytes = field(repr=False)
    signer: Signer = field(repr=False)
    chain: Tuple[bytes, ...] = field(default=(), repr=False)
    label: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.certificate, bytes):
            raise TypeError("certificate must be DER bytes")
        if not isinstance(self.chain, tuple) or not all(
            isinstance(link, bytes) for link in self.chain
        ):
            raise TypeError("chain must be a tuple of DER bytes")
        if not callable(getattr(self.signer, "sign", None)):
            raise TypeError("signer must have a sign() method")

    @functools.cached_property
    def info(self) -> CertificateInfo:
        """The decoded certificate. Raises ``CredentialError`` if it is malformed."""
        from ._openssl import openssl
        from ._openssl._objects import certificate_fields

        return CertificateInfo(**certificate_fields(openssl(), self.certificate))
