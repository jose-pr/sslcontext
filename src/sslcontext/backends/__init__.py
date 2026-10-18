"""Keystores that hold identities: the contract, the registry, the built-ins.

A backend lists the identities (certificate + usable private key) in one
keystore and finds one by a query. Built-in backends:

========== ================================ =====================================
name       class                            keystore
========== ================================ =====================================
``cng``    :class:`CNGBackend`              Windows certificate stores (CNG/CAPI)
``pkcs11`` :class:`PKCS11Backend`           PKCS#11 tokens: smart cards, HSMs, TPMs
========== ================================ =====================================

Third-party backends register under the entry-point group
``sslcontext.backends`` (``name = "package.module:Class"``).
"""

from __future__ import annotations

import datetime
import importlib
import threading
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Type, Union

from .._identity import Identity
from ..exceptions import IdentityNotFoundError

__all__ = ["Backend", "CNGBackend", "PKCS11Backend", "get", "names", "register_backend"]

_BUILTINS: Dict[str, str] = {
    "cng": "sslcontext.backends._cng:CNGBackend",
    "pkcs11": "sslcontext.backends._pkcs11:PKCS11Backend",
}
_registry: Dict[str, Union[str, Type["Backend"]]] = {}
_lock = threading.Lock()
_entry_points_loaded = False


class Backend(ABC):
    """One keystore. Constructing it does no I/O; :meth:`close` releases it.

    Subclasses implement :meth:`identities`; querying is shared. A backend is
    a context manager, and identities it returned stay usable after it is
    closed.
    """

    name: ClassVar[str] = ""

    def __enter__(self) -> "Backend":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Release what the backend holds open. Harmless to call twice."""

    @abstractmethod
    def identities(self) -> Iterator[Identity]:
        """Every identity in the keystore whose private key can be used.

        Raises :class:`~sslcontext.exceptions.KeystoreError` when the
        keystore cannot be read.
        """

    def find_identities(
        self,
        *,
        thumbprint: Optional[str] = None,
        subject: Optional[str] = None,
        issuer: Optional[str] = None,
        label: Optional[str] = None,
        valid: bool = True,
    ) -> List[Identity]:
        """The identities matching every criterion given, newest expiry first.

        ``thumbprint`` is the certificate's SHA-1 or SHA-256 in hex (case,
        spaces and colons ignored). ``subject`` and ``issuer`` match a
        case-insensitive substring of the RFC 4514 name. ``label`` matches
        the keystore's own name for the entry exactly, ignoring case.
        ``valid`` keeps only certificates valid now.
        """
        wanted = _normalize_thumbprint(thumbprint) if thumbprint else None
        now = datetime.datetime.now(datetime.timezone.utc)
        found = []
        for identity in self.identities():
            info = identity.info
            if wanted and wanted not in (info.sha1, info.sha256):
                continue
            if subject and subject.casefold() not in info.subject.casefold():
                continue
            if issuer and issuer.casefold() not in info.issuer.casefold():
                continue
            if label is not None and label.casefold() != identity.label.casefold():
                continue
            if valid and not info.valid_at(now):
                continue
            found.append(identity)
        found.sort(key=lambda identity: identity.info.not_after, reverse=True)
        return found

    def find_identity(self, **query: Any) -> Identity:
        """The best match for :meth:`find_identities` ``(**query)``.

        Several matches resolve to the one that expires last, so a renewed
        certificate wins over the one it replaces. Raises
        :class:`~sslcontext.exceptions.IdentityNotFoundError` when nothing
        matches.
        """
        found = self.find_identities(**query)
        if not found:
            criteria = ", ".join(f"{k}={v!r}" for k, v in query.items()) or "any"
            raise IdentityNotFoundError(f"no identity in {self!r} matches {criteria}")
        return found[0]


def _normalize_thumbprint(text: str) -> str:
    return "".join(ch for ch in text if ch not in " :‎").upper()


def register_backend(name: str, backend: Union[str, Type[Backend]]) -> None:
    """Register ``backend`` (a class, or ``"module:Class"``) under ``name``.

    Names are lower case; registering a taken name raises ``ValueError``.
    """
    if not name or name != name.lower():
        raise ValueError(f"backend names are lower case and non-empty: {name!r}")
    with _lock:
        if name in _registry or name in _BUILTINS:
            raise ValueError(f"a backend named {name!r} is already registered")
        _registry[name] = backend


def _load_entry_points() -> None:
    global _entry_points_loaded
    if _entry_points_loaded:
        return
    _entry_points_loaded = True
    from importlib.metadata import entry_points

    found = entry_points()
    group = (
        found.select(group="sslcontext.backends")
        if hasattr(found, "select")
        else found.get("sslcontext.backends", [])
    )
    for entry in group:
        if entry.name not in _registry and entry.name not in _BUILTINS:
            _registry[entry.name] = entry.value


def names() -> List[str]:
    """Every registered backend name, built-in and third-party."""
    _load_entry_points()
    return sorted(set(_BUILTINS) | set(_registry))


def get(name: str) -> Type[Backend]:
    """The backend class registered as ``name``.

    An unknown name raises ``ValueError`` naming the registered ones.
    """
    _load_entry_points()
    target = _registry.get(name) or _BUILTINS.get(name)
    if target is None:
        raise ValueError(f"unknown backend {name!r}; registered: {', '.join(names())}")
    if isinstance(target, str):
        module, _, attribute = target.partition(":")
        target = getattr(importlib.import_module(module), attribute)
    return target


def __getattr__(attribute: str) -> Any:
    # Backend classes load on first use, so importing sslcontext.backends
    # touches no platform library.
    for name, path in _BUILTINS.items():
        if path.endswith(":" + attribute):
            return get(name)
    raise AttributeError(f"module {__name__!r} has no attribute {attribute!r}")
