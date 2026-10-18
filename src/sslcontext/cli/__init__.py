"""The ``sslcontext`` command line, built on duho, installed by the ``cli`` extra.

    sslcontext list                      # the system's client certificates
    sslcontext show alice                # one, by thumbprint or subject
    sslcontext probe https://intranet/   # what the server asks, what answers

Importing this package needs no duho; :func:`main` reports the missing extra.
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence

__all__ = ["main"]

_NEEDS_EXTRA = (
    "sslcontext: error: the command line needs the 'cli' extra: "
    'pip install "sslcontext[cli]"'
)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the command line; return its exit status.

    ``0`` done, ``1`` the operation failed (or the ``cli`` extra is missing),
    ``2`` the invocation was wrong.
    """
    try:
        import duho  # noqa: F401
    except ImportError:
        print(_NEEDS_EXTRA, file=sys.stderr)
        return 1
    from ._root import execute

    return execute(argv)
