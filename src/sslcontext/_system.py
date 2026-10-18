"""A client context that trusts and authenticates the way the system's browser does."""

from __future__ import annotations

import os
import ssl
import sys
import warnings
from typing import TYPE_CHECKING, Any, Iterable, List, Optional, Union

from ._context import VerifyLike, create_context
from ._pin import PinSource
from ._select import AutoSelectRule, Chooser, ClientCertificateSelector
from ._sources import CertificatesLike, KeyLike

if TYPE_CHECKING:
    from .backends import Backend

__all__ = ["system_context", "system_selector", "system_sources"]


def system_sources(*, pin: PinSource = None) -> List["Backend"]:
    """The keystores a browser on this system offers client certificates from.

    Windows: the user's Personal store (``CNGBackend("MY")``), which also
    holds the certificates of inserted smart cards. Elsewhere: the PKCS#11
    module :class:`~sslcontext.backends.PKCS11Backend` would load by default
    (p11-kit's proxy on Linux, every token the system configured), when one
    is installed. ``pin`` is given to each backend. Nothing is opened here.
    """
    if sys.platform == "win32":
        from .backends import CNGBackend

        return [CNGBackend("MY", "current_user", pin=pin)]
    from .backends import PKCS11Backend
    from .backends._pkcs11 import default_module

    if default_module() is None:
        return []
    return [PKCS11Backend(pin=pin)]


def system_selector(
    *,
    pin: PinSource = None,
    choose: Optional[Chooser] = None,
    rules: Iterable[AutoSelectRule] = (),
    browser_policy: bool = True,
    remember: bool = True,
    cache_ttl: float = 60.0,
) -> ClientCertificateSelector:
    """A :class:`ClientCertificateSelector` over :func:`system_sources`,
    following the browsers' ``AutoSelectCertificateForUrls`` policy."""
    return ClientCertificateSelector(
        system_sources(pin=pin),
        choose=choose,
        rules=rules,
        browser_policy=browser_policy,
        remember=remember,
        cache_ttl=cache_ttl,
    )


def _truststore() -> Optional[type]:
    # truststore's import wraps a probe SSLObject without a host name, which
    # Python 3.10's later patch releases report as a DeprecationWarning.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", "check_hostname requires server_hostname", DeprecationWarning
        )
        try:
            import truststore
        except ImportError:
            return None
    return truststore.SSLContext  # type: ignore[no-any-return]


def system_context(
    *,
    selector: Union[ClientCertificateSelector, bool, None] = None,
    pin: PinSource = None,
    verify: VerifyLike = None,
    ca: Optional[CertificatesLike] = None,
    cafile: Union[str, "os.PathLike[str]", None] = None,
    capath: Union[str, "os.PathLike[str]", None] = None,
    cadata: Union[str, bytes, None] = None,
    certificate: Optional[CertificatesLike] = None,
    key: Optional[KeyLike] = None,
    password: Any = None,
    identity: Any = None,
    minimum_version: Optional[ssl.TLSVersion] = None,
    maximum_version: Optional[ssl.TLSVersion] = None,
    alpn: Optional[Iterable[str]] = None,
) -> ssl.SSLContext:
    """A client context that behaves as the system's own clients do.

    Servers are verified by the operating system (``truststore``: CryptoAPI
    on Windows, the Security framework on macOS, the system store elsewhere)
    on Python 3.10 and later, and by OpenSSL over the default store on 3.9.
    A ``verify``, ``ca``, ``cafile``, ``capath`` or ``cadata`` means what it
    means to :func:`create_context` and replaces the system's trust.

    A server's certificate request is answered by ``selector``: by default
    :func:`system_selector` ``(pin=pin)``; ``False`` sends no certificate.
    A ``certificate`` (with ``key`` and ``password``) or an ``identity`` is
    loaded as by :func:`create_context` and is then the one sent: the
    default selector is not installed unless ``selector`` asks for it. TLS
    1.3 post-handshake requests are accepted. One context serves every
    server and may be shared between threads.
    """
    custom_trust = any(
        value is not None for value in (verify, ca, cafile, capath, cadata)
    )
    truststore_class = None if custom_trust else _truststore()
    if truststore_class is not None:
        context = truststore_class(ssl.PROTOCOL_TLS_CLIENT)
        if minimum_version is not None:
            context.minimum_version = minimum_version
        if maximum_version is not None:
            context.maximum_version = maximum_version
        if alpn is not None:
            context.set_alpn_protocols(list(alpn))
        if certificate is not None:
            from ._load import load_pem

            load_pem(context, certificate, key, password)
        elif key is not None:
            raise ValueError("key needs its certificate")
        if identity is not None:
            from ._load import load_identity

            load_identity(context, identity)
    else:
        context = create_context(
            "client",
            verify=verify,
            ca=ca,
            cafile=cafile,
            capath=capath,
            cadata=cadata,
            certificate=certificate,
            key=key,
            password=password,
            identity=identity,
            minimum_version=minimum_version,
            maximum_version=maximum_version,
            alpn=alpn,
        )
    if ssl.HAS_TLSv1_3:  # read-only on a TLS library without it (LibreSSL 2.x)
        context.post_handshake_auth = True
    if selector is None:
        selector = certificate is None and identity is None
    if selector is True:
        selector = system_selector(pin=pin)
    if selector is not False:
        if not isinstance(selector, ClientCertificateSelector):
            raise TypeError(
                "selector must be a ClientCertificateSelector, True, False or None"
            )
        selector.install(context)
    return context
