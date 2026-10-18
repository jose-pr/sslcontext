"""Choose a client certificate when the server asks, the way a browser does."""

from __future__ import annotations

import datetime
import logging
import ssl
import threading
import time
import weakref
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from ._identity import Identity
from .exceptions import KeystoreError

if TYPE_CHECKING:
    from .backends import Backend

__all__ = [
    "AutoSelectRule",
    "CertificateRequest",
    "Chooser",
    "ClientCertificateSelector",
    "IdentitySource",
]

_log = logging.getLogger("sslcontext")

# x509v3.h: XKU_SSL_CLIENT, XKU_ANYEKU, KU_DIGITAL_SIGNATURE; all ones = absent.
_XKU_SSL_CLIENT = 0x2
_XKU_ANYEKU = 0x100
_KU_DIGITAL_SIGNATURE = 0x80
_ABSENT = 0xFFFFFFFF
_NO_PSS_SIGALGS = (
    b"RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512"
)


@dataclass(frozen=True)
class CertificateRequest:
    """What a server asked for when it requested a client certificate."""

    host: Optional[str]
    """The server name the client sent (SNI); ``None`` when it sent none."""
    authorities: Tuple[str, ...]
    """RFC 4514 names of the CAs the server accepts; empty means any."""
    authorities_der: Tuple[bytes, ...] = field(repr=False)
    key_types: FrozenSet[str]
    """``"rsa"`` and/or ``"ec"``: key types the server's signature algorithms allow."""
    rsa_pss_required: bool
    """An RSA key must sign RSA-PSS (TLS 1.3, or a server offering no PKCS#1)."""
    tls_version: str
    """``"TLSv1.3"``, ``"TLSv1.2"``, ..."""


Chooser = Callable[[CertificateRequest, List[Identity]], Optional[Identity]]
"""Picks one of the candidates, or ``None`` to send no certificate."""

IdentitySource = Union["Backend", Identity, Callable[[], Iterable[Identity]]]
"""A keystore backend, one identity, or a callable returning identities."""


def _split_name(name: str) -> List[Tuple[str, str]]:
    """``[(attribute, value)]`` of an RFC 4514 name, escapes resolved."""
    parts: List[Tuple[str, str]] = []
    current, escaped = "", False
    for char in name + ",":
        if escaped:
            current += char
            escaped = False
        elif char == "\\":
            escaped = True
        elif char in ",+":
            attribute, _, value = current.partition("=")
            if attribute:
                parts.append((attribute.strip().upper(), value.strip()))
            current = ""
        else:
            current += char
    return parts


def _filter_matches(spec: Union[str, Mapping[str, str], None], name: str) -> bool:
    if spec is None:
        return True
    if isinstance(spec, str):
        return spec.casefold() in name.casefold()
    attributes = _split_name(name)
    for attribute, wanted in spec.items():
        values = [v for a, v in attributes if a == attribute.upper()]
        if wanted not in values:
            return False
    return True


@dataclass(frozen=True)
class AutoSelectRule:
    """Pick a certificate without asking, as Chrome's and Edge's
    ``AutoSelectCertificateForUrls`` policy does.

    ``pattern`` is a host pattern: ``example.com`` (that host),
    ``[*.]example.com`` (it and every subdomain), ``*.example.com`` (the
    subdomains), ``*`` (any host). A scheme, port or path in it is accepted
    and ignored: the request knows only the server name. ``issuer`` and
    ``subject`` filter the certificate: a mapping of RFC 4514 attributes to
    exact values (``{"CN": "Corp CA"}``, as the policy's ``ISSUER``/``SUBJECT``),
    or a string matched as a case-insensitive substring of the whole name.
    """

    pattern: str
    issuer: Union[str, Mapping[str, str], None] = None
    subject: Union[str, Mapping[str, str], None] = None

    def matches_host(self, host: Optional[str]) -> bool:
        pattern = self.pattern.strip()
        if "://" in pattern:
            pattern = pattern.split("://", 1)[1]
        pattern = pattern.split("/", 1)[0]
        any_subdomain = pattern.startswith("[*.]")
        if any_subdomain:
            pattern = pattern[4:]
        if pattern.startswith("["):  # an IPv6 literal, with or without a port
            pattern = pattern[1:].split("]", 1)[0]
        elif pattern.count(":") == 1:
            pattern = pattern.split(":", 1)[0]
        pattern = pattern.rstrip(".").casefold()
        if pattern == "*":
            return True
        if host is None:
            return False
        host = host.rstrip(".").casefold()
        if pattern.startswith("*."):
            return host.endswith(pattern[1:])
        return host == pattern or (any_subdomain and host.endswith("." + pattern))

    def matches(self, identity: Identity) -> bool:
        info = identity.info
        return _filter_matches(self.issuer, info.issuer) and _filter_matches(
            self.subject, info.subject
        )


@dataclass
class _Prepared:
    """An identity decoded once: what filtering needs and what OpenSSL uses."""

    identity: Identity
    client_auth: bool
    names: FrozenSet[bytes]
    certificates: List[int]
    key: int = 0
    handle: int = 0


class ClientCertificateSelector:
    """Answers a server's certificate request with an identity from ``sources``.

    Candidates are the identities a browser would offer: valid now, usable
    for client authentication (no extended key usage, ``clientAuth`` or
    ``anyExtendedKeyUsage``; ``digitalSignature`` when key usage is present),
    of a key type the server's signature algorithms allow (an RSA key that
    cannot sign PSS is left out where PSS is required), and, when the server
    names CAs, issued under one of them (the leaf's issuer or any certificate
    of its chain). Newest expiry first.

    The choice, in order: the identity remembered for the host, the first
    of ``rules`` matching the host with a matching candidate, the same for
    the browsers' policies when ``browser_policy`` is true (see
    :func:`browser_policies`), ``choose(request, candidates)``, and, with no
    ``choose``, the only candidate when there is exactly one. Otherwise no
    certificate is sent and the server decides.

    Sources are listed again after ``cache_ttl`` seconds. A source that fails
    is logged and skipped. An exception from ``choose`` (or a result that is
    not one of the candidates) fails that handshake.
    """

    def __init__(
        self,
        sources: Iterable[IdentitySource],
        *,
        choose: Optional[Chooser] = None,
        rules: Iterable[AutoSelectRule] = (),
        browser_policy: bool = False,
        remember: bool = True,
        cache_ttl: float = 60.0,
    ) -> None:
        self.sources = list(sources)
        self.choose = choose
        self.rules = tuple(rules)
        self.browser_policy = browser_policy
        self.remember = remember
        self.cache_ttl = cache_ttl
        self._lock = threading.RLock()
        self._listed: List[Identity] = []
        self._listed_at: Optional[float] = None
        self._policies: Tuple[AutoSelectRule, ...] = ()
        self._policies_at: Optional[float] = None
        self._prepared: Dict[str, _Prepared] = {}
        self._remembered: Dict[str, str] = {}
        self._finalizer = weakref.finalize(self, _release, self._prepared)

    def __repr__(self) -> str:
        return f"<ClientCertificateSelector sources={len(self.sources)}>"

    # ------------------------------------------------------------ listing

    def identities(self) -> List[Identity]:
        """Every identity the sources hold, listed at most every ``cache_ttl``."""
        with self._lock:
            now = time.monotonic()
            if self._listed_at is None or now - self._listed_at > self.cache_ttl:
                self._listed = list(self._list())
                self._listed_at = now
            return list(self._listed)

    def _list(self) -> Iterable[Identity]:
        for source in self.sources:
            try:
                if isinstance(source, Identity):
                    yield source
                elif callable(getattr(source, "identities", None)):
                    yield from source.identities()  # type: ignore[union-attr]
                elif callable(source):
                    yield from source()
                else:
                    raise TypeError(f"not an identity source: {source!r}")
            except (KeystoreError, OSError) as error:
                _log.warning("sslcontext: %r cannot be listed: %s", source, error)

    def policies(self) -> Tuple[AutoSelectRule, ...]:
        """The browsers' rules (empty unless ``browser_policy``), cached."""
        if not self.browser_policy:
            return ()
        from ._policy import browser_policies

        with self._lock:
            now = time.monotonic()
            if self._policies_at is None or now - self._policies_at > self.cache_ttl:
                self._policies = tuple(browser_policies())
                self._policies_at = now
            return self._policies

    def refresh(self) -> None:
        """List the sources and read the policies again on the next request."""
        with self._lock:
            self._listed_at = self._policies_at = None

    def forget(self, host: Optional[str] = None) -> None:
        """Forget the choice made for ``host``, or for every host."""
        with self._lock:
            if host is None:
                self._remembered.clear()
            else:
                self._remembered.pop(host.casefold(), None)

    # ---------------------------------------------------------- selection

    def _prepare(self, identity: Identity) -> _Prepared:
        from ._openssl import openssl
        from ._openssl._certcb import _name_der
        from ._openssl._objects import read_certificates

        key = identity.info.sha256
        with self._lock:
            prepared = self._prepared.get(key)
            if prepared is not None:
                return prepared
            lib = openssl()
            certificates = read_certificates(lib, identity.certificate)
            for link in identity.chain:
                certificates.extend(read_certificates(lib, link))
            leaf = certificates[0]
            usage = lib.X509_get_extended_key_usage(leaf)
            key_usage = lib.X509_get_key_usage(leaf)
            client_auth = (
                usage == _ABSENT or bool(usage & (_XKU_SSL_CLIENT | _XKU_ANYEKU))
            ) and (key_usage == _ABSENT or bool(key_usage & _KU_DIGITAL_SIGNATURE))
            names = {_name_der(lib, lib.X509_get_issuer_name(leaf))}
            for pointer in certificates[1:]:
                names.add(_name_der(lib, lib.X509_get_subject_name(pointer)))
                names.add(_name_der(lib, lib.X509_get_issuer_name(pointer)))
            prepared = _Prepared(identity, client_auth, frozenset(names), certificates)
            self._prepared[key] = prepared
            return prepared

    def candidates(self, request: CertificateRequest) -> List[Identity]:
        """The identities a browser would offer for ``request``, newest expiry first."""
        now = datetime.datetime.now(datetime.timezone.utc)
        wanted = set(request.authorities_der)
        found = []
        for identity in self.identities():
            try:
                if self._offered(identity, request, now, wanted):
                    found.append(identity)
            except Exception as error:  # noqa: BLE001 - one bad entry is skipped
                _log.debug("sslcontext: skipping %r: %s", identity, error)
        found.sort(key=lambda identity: identity.info.not_after, reverse=True)
        return found

    def _offered(
        self,
        identity: Identity,
        request: CertificateRequest,
        now: datetime.datetime,
        wanted: set,
    ) -> bool:
        info = identity.info
        if not info.valid_at(now) or info.key_type not in request.key_types:
            return False
        prepared = self._prepare(identity)
        if not prepared.client_auth or (wanted and not wanted & prepared.names):
            return False
        # Last: asking a keystore about its key may open it.
        return not (
            info.key_type == "rsa"
            and request.rsa_pss_required
            and not getattr(identity.signer, "supports_pss", True)
        )

    def select(self, request: CertificateRequest) -> Optional[Identity]:
        """The identity to answer ``request`` with, or ``None`` for none."""
        candidates = self.candidates(request)
        if not candidates:
            return None
        host = request.host.casefold() if request.host else None
        with self._lock:
            remembered = self._remembered.get(host) if host else None
        if remembered:
            for identity in candidates:
                if identity.info.sha256 == remembered:
                    return identity
        chosen = self._by_rules(request, candidates)
        if chosen is None:
            if self.choose is not None:
                chosen = self.choose(request, list(candidates))
                if chosen is not None and not any(chosen is c for c in candidates):
                    raise ValueError(
                        "choose() must return one of the candidates or None"
                    )
            elif len(candidates) == 1:
                chosen = candidates[0]
            else:
                _log.info(
                    "sslcontext: %d certificates fit %s and nothing picks one; "
                    "sending none (add a rule or a choose callback)",
                    len(candidates),
                    request.host,
                )
        if chosen is not None and host and self.remember:
            with self._lock:
                self._remembered[host] = chosen.info.sha256
        return chosen

    def _by_rules(
        self, request: CertificateRequest, candidates: Sequence[Identity]
    ) -> Optional[Identity]:
        for rule in self.rules + self.policies():
            if rule.matches_host(request.host):
                for identity in candidates:
                    if rule.matches(identity):
                        return identity
        return None

    # ------------------------------------------------------------ OpenSSL

    def install(self, context: ssl.SSLContext) -> None:
        """Answer every certificate request on ``context`` from now on.

        A client context only; it replaces a selector installed before. An
        identity loaded with :func:`~sslcontext.load_identity` is still sent
        when this selector picks none. ``context`` keeps the selector alive.
        """
        from ._openssl import openssl
        from ._openssl._certcb import install_handler

        install_handler(openssl(), context, self._answer)

    def _answer(self, ssl_pointer: int) -> int:
        from ._openssl import openssl
        from ._openssl._certcb import read_request, use_identity
        from ._openssl._keys import lookup, remember
        from ._openssl._signing import make_private_key

        lib = openssl()
        host, authorities, key_types, pss, version, server = read_request(
            lib, ssl_pointer
        )
        if server:
            return 1
        request = CertificateRequest(
            host,
            tuple(text for text, _ in authorities),
            tuple(der for _, der in authorities),
            key_types,
            pss,
            version,
        )
        identity = self.select(request)
        if identity is None:
            return 1
        prepared = self._prepare(identity)
        with self._lock:
            if not prepared.key:
                public = lib.X509_get_pubkey(prepared.certificates[0])
                prepared.handle = remember(lib, identity.signer, public, identity.label)
                record = lookup(prepared.handle)
                assert record is not None
                prepared.key = make_private_key(lib, prepared.handle, record.key_type)
        no_pss = identity.info.key_type == "rsa" and not getattr(
            identity.signer, "supports_pss", True
        )
        use_identity(
            lib,
            ssl_pointer,
            prepared.certificates[0],
            prepared.certificates[1:],
            prepared.key,
            _NO_PSS_SIGALGS if no_pss else None,
        )
        _log.debug("sslcontext: answering %s with %s", host, identity.info.subject)
        return 1


def _release(prepared: Dict[str, _Prepared]) -> None:
    from ._openssl import openssl
    from ._openssl._keys import forget

    lib = openssl()
    for entry in prepared.values():
        for pointer in entry.certificates:
            lib.X509_free(pointer)
        if entry.key:
            lib.EVP_PKEY_free(entry.key)
        if entry.handle:
            forget(lib, entry.handle)
    prepared.clear()
