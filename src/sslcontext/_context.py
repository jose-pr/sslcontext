"""Build a verifying :class:`ssl.SSLContext` from the usual knobs."""

from __future__ import annotations

import os
import ssl
from typing import Any, Iterable, Optional, Union

from ._sources import CertificatesLike, KeyLike, pem_and_der, read_sources

__all__ = ["create_context", "VerifyLike"]

VerifyLike = Union[bool, str, "os.PathLike[str]", None]
"""``True``/``False``, or a CA bundle file or hashed CA directory to trust."""

_PURPOSES = {"client": ssl.Purpose.SERVER_AUTH, "server": ssl.Purpose.CLIENT_AUTH}


def create_context(
    purpose: str = "client",
    *,
    verify: VerifyLike = None,
    cafile: str | os.PathLike[str] | None = None,
    capath: str | os.PathLike[str] | None = None,
    cadata: str | bytes | None = None,
    ca: Optional[CertificatesLike] = None,
    certificate: Optional[CertificatesLike] = None,
    key: Optional[KeyLike] = None,
    password: Any = None,
    identity: Any = None,
    minimum_version: ssl.TLSVersion | None = None,
    maximum_version: ssl.TLSVersion | None = None,
    alpn: Iterable[str] | None = None,
) -> ssl.SSLContext:
    """A context for ``purpose`` ``"client"`` or ``"server"``.

    ``verify`` decides whether the peer's certificate is checked. ``None``
    means the purpose's default: a client verifies the server, a server does
    not ask for a client certificate. ``True`` turns checking on (a server
    then requires a client certificate), ``False`` turns it off (a client
    also stops checking the host name). A path is shorthand for trusting that
    CA bundle file or hashed directory, as in ``requests``.

    Trust comes from ``ca``/``cafile``/``capath``/``cadata`` when any is
    given, and from the platform's default store otherwise. ``ca`` takes the
    CA certificates themselves or where they are, in any form
    :data:`CertificatesLike` names, one or a list.

    ``certificate`` (leaf first, then its chain; one source or a list),
    ``key`` and ``password`` load the context's own certificate as
    :func:`load_pem` does; ``identity`` (an :class:`Identity`) as
    :func:`load_identity` does. ``SSLKEYLOGFILE`` is honoured as by
    :func:`ssl.create_default_context`.
    """
    try:
        ssl_purpose = _PURPOSES[purpose]
    except KeyError:
        raise ValueError(
            f"purpose must be 'client' or 'server', not {purpose!r}"
        ) from None
    if verify is not None and not isinstance(verify, (bool, str, os.PathLike)):
        raise TypeError(f"verify must be a bool or a path, not {type(verify).__name__}")
    if isinstance(verify, (str, os.PathLike)):
        if cafile is not None or capath is not None:
            raise ValueError("pass a CA path as verify or as cafile/capath, not both")
        if os.path.isdir(verify):
            capath = verify
        else:
            cafile = verify
        verify = True

    der = b""
    if ca is not None:
        if cadata is not None:
            raise ValueError("pass CA certificates as ca or as cadata, not both")
        pem, der = pem_and_der(read_sources(ca, "ca"))
        # cadata takes PEM text or DER bytes, not both in one call.
        cadata, der = (pem, der) if pem else (der, b"")
    context = ssl.create_default_context(
        ssl_purpose, cafile=cafile, capath=capath, cadata=cadata
    )
    if der:
        context.load_verify_locations(cadata=der)
    if purpose == "client":
        if verify is False:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    elif verify:
        context.verify_mode = ssl.CERT_REQUIRED
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
    return context
