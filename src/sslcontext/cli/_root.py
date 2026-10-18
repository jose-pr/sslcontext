"""The root command and its error handling."""

from __future__ import annotations

from typing import Optional, Sequence

from duho import AUTO, Cli, LoggingArgs
from duho import main as run_main

from ..exceptions import SSLContextError
from ._keystore import List, Show
from ._probe import Probe

__all__ = ["SSLContextCli", "execute"]


class SSLContextCli(LoggingArgs, Cli):
    """Client certificates from the system's keystores: list them, and see which one a server gets."""

    _parsername_ = "sslcontext"
    _logger_name_ = "sslcontext"
    _version_ = AUTO
    _distribution_ = "sslcontext"
    _subcommands_ = [List, Show, Probe]
    _errors_ = {SSLContextError: 1, OSError: 1}


def execute(argv: Optional[Sequence[str]] = None) -> int:
    status = run_main(SSLContextCli, list(argv) if argv is not None else None)
    return int(status or 0)
