"""Errors raised by :mod:`sslcontext`.

A caller's bad argument raises plain :class:`TypeError` or :class:`ValueError`;
everything here is a failure found at run time.
"""

from __future__ import annotations

__all__ = [
    "CredentialError",
    "IdentityNotFoundError",
    "KeystoreError",
    "SigningError",
    "SSLContextError",
    "UnsupportedOpenSSLError",
]


class SSLContextError(Exception):
    """Base class for every error this package raises."""


class UnsupportedOpenSSLError(SSLContextError):
    """The interpreter's OpenSSL cannot be driven by this package.

    LibreSSL, OpenSSL older than 1.1.1, and a statically linked ``_ssl`` that
    hides its symbols all raise this.
    """


class CredentialError(SSLContextError, ValueError):
    """A certificate or key is malformed, encrypted with another password, or
    does not match its certificate."""


class IdentityNotFoundError(SSLContextError, LookupError):
    """No keystore entry matched the query."""


class KeystoreError(SSLContextError, OSError):
    """The keystore refused or failed an operation; ``errno`` holds its code."""


class SigningError(SSLContextError):
    """The signer failed while OpenSSL was performing a handshake."""
