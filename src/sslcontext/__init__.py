"""Client identities from OS keystores in a standard :class:`ssl.SSLContext`."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._context import VerifyLike, create_context
from ._identity import HASHES, CertificateInfo, Identity, Padding, Signer
from ._load import BytesOrText, load_identity, load_pem, load_pkcs12
from ._pin import (
    KEYSTORE_PROMPT,
    PasswordSource,
    PinCallback,
    PinRequest,
    PinSource,
    Prompt,
)
from ._policy import browser_policies, rules_from_policy
from ._select import (
    AutoSelectRule,
    CertificateRequest,
    Chooser,
    ClientCertificateSelector,
    IdentitySource,
)
from ._system import system_context, system_selector, system_sources
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
    "AutoSelectRule",
    "BytesOrText",
    "CertificateInfo",
    "CertificateRequest",
    "Chooser",
    "ClientCertificateSelector",
    "CredentialError",
    "HASHES",
    "Identity",
    "IdentityNotFoundError",
    "IdentitySource",
    "KEYSTORE_PROMPT",
    "KeystoreError",
    "Padding",
    "PasswordSource",
    "PinCallback",
    "PinRequest",
    "PinSource",
    "Prompt",
    "Signer",
    "SigningError",
    "SSLContextError",
    "UnsupportedOpenSSLError",
    "VerifyLike",
    "__version__",
    "browser_policies",
    "create_context",
    "load_identity",
    "load_pem",
    "load_pkcs12",
    "rules_from_policy",
    "system_context",
    "system_selector",
    "system_sources",
]
