"""Client identities from OS keystores in a standard :class:`ssl.SSLContext`."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._context import VerifyLike, create_context
from ._identity import HASHES, Identity, Padding, Signer
from ._load import BytesOrText, load_identity, load_pem, load_pkcs12
from .exceptions import (
    CredentialError,
    IdentityNotFoundError,
    KeystoreError,
    SigningError,
    SSLContextError,
    UnsupportedOpenSSLError,
)

try:
    __version__ = version("sslcontext")
except PackageNotFoundError:  # running from a checkout without an install
    __version__ = "0+unknown"

__all__ = [
    "BytesOrText",
    "CredentialError",
    "HASHES",
    "Identity",
    "IdentityNotFoundError",
    "KeystoreError",
    "Padding",
    "Signer",
    "SigningError",
    "SSLContextError",
    "UnsupportedOpenSSLError",
    "VerifyLike",
    "__version__",
    "create_context",
    "load_identity",
    "load_pem",
    "load_pkcs12",
]
