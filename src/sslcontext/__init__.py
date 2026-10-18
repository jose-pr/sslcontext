"""Client identities from OS keystores in a standard :class:`ssl.SSLContext`."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sslcontext")
except PackageNotFoundError:  # running from a checkout without an install
    __version__ = "0+unknown"

__all__ = ["__version__"]
