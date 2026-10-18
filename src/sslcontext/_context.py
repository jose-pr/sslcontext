"""Build a verifying :class:`ssl.SSLContext` from the usual knobs."""

from __future__ import annotations

import os
import ssl
from typing import Iterable, Union

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

    Trust comes from ``cafile``/``capath``/``cadata`` when any is given, and
    from the platform's default store otherwise. ``SSLKEYLOGFILE`` is honoured
    as by :func:`ssl.create_default_context`.
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

    context = ssl.create_default_context(
        ssl_purpose, cafile=cafile, capath=capath, cadata=cadata
    )
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
    return context
