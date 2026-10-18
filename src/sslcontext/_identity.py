"""The contract between a keystore and the TLS stack: identities and signers."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional, Protocol, Tuple, runtime_checkable

__all__ = ["HASHES", "Identity", "Padding", "Signer"]

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
class Identity:
    """A certificate, its chain, and a signer for its private key.

    ``certificate`` and each entry of ``chain`` are DER bytes; ``chain`` runs
    from the issuer of ``certificate`` upward and may omit the root.
    """

    certificate: bytes
    signer: Signer = field(repr=False)
    chain: Tuple[bytes, ...] = ()
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
