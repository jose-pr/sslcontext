"""Client identities from OS keystores in a standard :class:`ssl.SSLContext`."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._context import VerifyLike, create_context
from ._load import BytesOrText, load_pem, load_pkcs12
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
    "IdentityNotFoundError",
    "KeystoreError",
    "SigningError",
    "SSLContextError",
    "UnsupportedOpenSSLError",
    "VerifyLike",
    "__version__",
    "create_context",
    "load_pem",
    "load_pkcs12",
]
