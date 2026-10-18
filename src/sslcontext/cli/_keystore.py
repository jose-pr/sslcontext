"""``sslcontext list`` and ``sslcontext show``: the identities a keystore holds."""

from __future__ import annotations

import json

from duho import CommandError

from .._select import ClientCertificateSelector
from ._common import SourceCommand, describe

__all__ = ["List", "Show"]


class List(SourceCommand):
    """List the client certificates whose private key can be used, newest expiry first."""

    _parsername_ = "list"

    all: bool = False
    "Include expired and not-yet-valid certificates"
    ("--all", "-a")

    json_output: bool = False
    "Print a JSON array instead of lines"
    ("--json",)

    def __call__(self) -> int:
        selector = ClientCertificateSelector(self.sources())
        rows = [describe(identity, selector) for identity in selector.identities()]
        if not self.all:
            rows = [row for row in rows if row["valid"]]
        rows.sort(key=lambda row: row["not_after"], reverse=True)
        if self.json_output:
            print(json.dumps(rows, indent=2))
            return 0
        for row in rows:
            usable = {True: "client", False: "no-client", None: "?"}[row["client_auth"]]
            print(
                f"{row['sha1']}  {row['not_after']}  {row['key']:<8} {usable:<9} "
                f"{row['subject']}  (issuer {row['issuer']})"
            )
        return 0


class Show(SourceCommand):
    """Show one identity in full: by SHA-1 or SHA-256 thumbprint, or a subject substring."""

    _parsername_ = "show"

    query: str
    "A thumbprint, or text found in the subject"
    ("query",)

    def __call__(self) -> int:
        selector = ClientCertificateSelector(self.sources())
        wanted = "".join(ch for ch in self.query if ch not in " :").upper()
        found = [
            identity
            for identity in selector.identities()
            if wanted in (identity.info.sha1, identity.info.sha256)
            or self.query.casefold() in identity.info.subject.casefold()
        ]
        if not found:
            raise CommandError(f"no identity matches {self.query!r}", 1)
        for identity in found:
            row = describe(identity, selector)
            info = identity.info
            row.update(
                sha256=info.sha256,
                serial=info.serial,
                not_before=info.not_before.strftime("%Y-%m-%d %H:%M:%S"),
                not_after=info.not_after.strftime("%Y-%m-%d %H:%M:%S"),
                chain=[_subject(der) for der in identity.chain],
                supports_pss=_pss(identity),
            )
            print(json.dumps(row, indent=2))
        return 0


def _subject(der: bytes) -> str:
    from .. import Identity

    try:
        return Identity(der, _NoSigner()).info.subject
    except Exception as error:  # noqa: BLE001 - shown, never fatal
        return f"<unreadable: {error}>"


def _pss(identity) -> object:
    try:
        return getattr(identity.signer, "supports_pss", True)
    except Exception as error:  # noqa: BLE001 - asking may open the key
        return f"unknown: {error}"


class _NoSigner:
    def sign(self, digest, **kwargs):  # pragma: no cover - never called
        raise NotImplementedError
