"""``sslcontext probe``: connect as the system would, and say what happened."""

from __future__ import annotations

import json
import socket
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from duho import CommandError

from .. import CertificateRequest, Identity
from .._select import ClientCertificateSelector
from .._system import system_context
from ._common import SourceCommand, describe, terminal_chooser

__all__ = ["Probe"]


class _Recording(ClientCertificateSelector):
    """A selector that keeps what each certificate request asked and got."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.requests: List[Dict[str, Any]] = []

    def select(self, request: CertificateRequest) -> Optional[Identity]:
        candidates = self.candidates(request)
        chosen = super().select(request)
        self.requests.append(
            {
                "host": request.host,
                "tls_version": request.tls_version,
                "authorities": list(request.authorities),
                "key_types": sorted(request.key_types),
                "candidates": [describe(c, self) for c in candidates],
                "sent": describe(chosen, self) if chosen is not None else None,
            }
        )
        return chosen


class Probe(SourceCommand):
    """Connect to a server with the system's context: show its certificate, whether it asked for a client certificate, which ones fit and which was sent, and (https) the HTTP status."""

    _parsername_ = "probe"

    url: str
    "https://host[:port]/path, or host[:port] for TLS only"
    ("url",)

    cafile: Optional[str] = None
    "Trust this CA bundle instead of the system's"
    ("--cafile",)

    insecure: bool = False
    "Do not verify the server (still shows its certificate)"
    ("--insecure", "-k")

    ask: bool = False
    "When several certificates fit and nothing picks one, ask on the terminal (a browser's dialog)"
    ("--ask",)

    no_policy: bool = False
    "Ignore the browsers' AutoSelectCertificateForUrls policy"
    ("--no-policy",)

    timeout: float = 15.0
    "Seconds to wait for the connection and each reply"
    ("--timeout",)

    json_output: bool = False
    "Print one JSON object instead of lines"
    ("--json",)

    def target(self) -> tuple:
        text = self.url if "://" in self.url else f"tls://{self.url}"
        parts = urlsplit(text)
        if not parts.hostname:
            raise CommandError(f"no host in {self.url!r}", 2)
        if parts.scheme not in ("https", "tls"):
            raise CommandError("probe speaks https:// or a bare host[:port]", 2)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        return parts.scheme, parts.hostname, parts.port or 443, path

    def __call__(self) -> int:
        scheme, host, port, path = self.target()
        selector = _Recording(
            self.sources(),
            choose=terminal_chooser if self.ask else None,
            browser_policy=not self.no_policy,
        )
        context = system_context(
            selector=selector,
            verify=False if self.insecure else None,
            cafile=self.cafile,
        )
        result: Dict[str, Any] = {"host": host, "port": port}
        status = 0
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    result["tls_version"] = tls.version()
                    result["cipher"] = (tls.cipher() or ("",))[0]
                    result["server"] = _server(tls)
                    if scheme == "https":
                        result["http"] = _status(tls, host, port, path)
        except (OSError, ssl.SSLError) as error:
            result["error"] = f"{type(error).__name__}: {error}"
            status = 1
        result["certificate_requests"] = selector.requests
        if self.json_output:
            print(json.dumps(result, indent=2))
        else:
            _print(result)
        return status


def _server(tls: ssl.SSLSocket) -> Dict[str, Any]:
    from .._identity import Identity
    from ._keystore import _NoSigner

    der = tls.getpeercert(binary_form=True)
    if not der:
        return {}
    info = Identity(der, _NoSigner()).info
    return {"subject": info.subject, "issuer": info.issuer, "sha1": info.sha1}


def _status(tls: ssl.SSLSocket, host: str, port: int, path: str) -> str:
    authority = host if port == 443 else f"{host}:{port}"
    tls.sendall(
        f"HEAD {path} HTTP/1.1\r\nHost: {authority}\r\n"
        "User-Agent: sslcontext-probe\r\nConnection: close\r\n\r\n".encode()
    )
    reply = b""
    while b"\r\n" not in reply:
        chunk = tls.recv(4096)  # a TLS 1.3 post-handshake request is answered here
        if not chunk:
            break
        reply += chunk
    return reply.split(b"\r\n", 1)[0].decode("latin-1")


def _print(result: Dict[str, Any]) -> None:
    print(f"{result['host']}:{result['port']}")
    if "tls_version" in result:
        print(f"  {result['tls_version']} {result['cipher']}")
        server = result.get("server") or {}
        if server:
            print(f"  server: {server['subject']}  (issuer {server['issuer']})")
    requests = result["certificate_requests"]
    if not requests:
        print("  client certificate: not requested")
    for request in requests:
        names = ", ".join(request["authorities"]) or "any CA"
        print(f"  client certificate requested; accepted issuers: {names}")
        for candidate in request["candidates"]:
            print(f"    fits: {candidate['subject']}  ({candidate['sha1']})")
        sent = request["sent"]
        print(f"  sent: {sent['subject'] if sent else 'none'}")
    if "http" in result:
        print(f"  http: {result['http']}")
    if "error" in result:
        print(f"  error: {result['error']}")
