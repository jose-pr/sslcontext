"""What the commands share: where identities come from, and how they print."""

from __future__ import annotations

import getpass
import sys
from typing import Any, Dict, List, Literal, Optional

from duho import Cmd, CommandError

from .. import KEYSTORE_PROMPT, CertificateRequest, Identity, PinRequest
from .._select import ClientCertificateSelector
from ..backends import Backend, get
from .._system import system_sources

__all__ = ["SourceCommand", "describe", "terminal_chooser"]


class SourceCommand(Cmd):
    """Base of the commands that read keystores."""

    backend: str = "system"
    "Where identities come from: system (the system's keystores), or a backend name (cng, pkcs11, a registered one)"
    ("--backend", "-b")

    store: str = "MY"
    "cng: the certificate store name"
    ("--store",)

    location: Literal["current_user", "local_machine"] = "current_user"
    "cng: the store location"
    ("--location",)

    module: Optional[str] = None
    "pkcs11: the PKCS#11 module. Omitted: SSLCONTEXT_PKCS11_MODULE, else the system default"
    ("--module",)

    token: Optional[str] = None
    "pkcs11: only the token with this label or serial number"
    ("--token",)

    pin: Literal["none", "ask", "keystore"] = "none"
    "How a PIN is given when a key needs one: none (fail at once), ask (on this terminal), keystore (the keystore's own dialog or PIN pad)"
    ("--pin",)

    def pin_source(self) -> Any:
        if self.pin == "keystore":
            return KEYSTORE_PROMPT
        if self.pin == "ask":
            return _ask_pin
        return None

    def sources(self) -> List[Backend]:
        if self.backend == "system":
            return system_sources(pin=self.pin_source())
        try:
            backend_class = get(self.backend)
        except ValueError as error:
            raise CommandError(str(error), 2) from None
        if self.backend == "cng":
            return [backend_class(self.store, self.location, pin=self.pin_source())]
        if self.backend == "pkcs11":
            return [backend_class(self.module, token=self.token, pin=self.pin_source())]
        return [backend_class()]


def _ask_pin(request: PinRequest) -> Optional[str]:
    if request.purpose == "list" or not sys.stdin.isatty():
        return None
    return getpass.getpass(f"PIN for {request.token or request.certificate}: ")


def describe(identity: Identity, selector: ClientCertificateSelector) -> Dict[str, Any]:
    """The fields ``list``, ``show`` and ``probe`` print for an identity."""
    info = identity.info
    try:
        client_auth: Optional[bool] = selector._prepare(identity).client_auth
    except Exception:  # noqa: BLE001 - shown as unknown, never fatal
        client_auth = None
    return {
        "sha1": info.sha1,
        "subject": info.subject,
        "issuer": info.issuer,
        "not_after": info.not_after.strftime("%Y-%m-%d"),
        "key": f"{info.key_type}-{info.key_bits}",
        "client_auth": client_auth,
        "valid": info.valid_at(),
        "label": identity.label,
    }


def terminal_chooser(
    request: CertificateRequest, candidates: List[Identity]
) -> Optional[Identity]:
    """Ask on the terminal which certificate to send, as a browser's dialog
    does; with no terminal, send none."""
    if not sys.stdin.isatty():
        return None
    print(
        f"{request.host or 'The server'} asks for a client certificate:",
        file=sys.stderr,
    )
    for number, identity in enumerate(candidates, 1):
        info = identity.info
        print(
            f"  {number}. {info.subject}  (issuer {info.issuer}, until "
            f"{info.not_after:%Y-%m-%d})",
            file=sys.stderr,
        )
    answer = input("Send which (number, empty for none)? ").strip()
    if answer.isdigit() and 1 <= int(answer) <= len(candidates):
        return candidates[int(answer) - 1]
    return None
