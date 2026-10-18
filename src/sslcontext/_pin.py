"""How a caller supplies PINs and passwords: a value, a callback, or nothing.

Nothing ever waits on a user unless the caller asked for it. With no PIN, an
operation that needs one fails at once; a keystore's own prompt (a Windows
dialog, a PIN pad) is used only when the caller returns or passes
:data:`KEYSTORE_PROMPT`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Callable, Optional, Union

__all__ = [
    "KEYSTORE_PROMPT",
    "PasswordSource",
    "PinCallback",
    "PinRequest",
    "PinSource",
    "Prompt",
    "resolve_password",
    "resolve_pin",
]


class Prompt(enum.Enum):
    """Sentinels a PIN source may give instead of a PIN."""

    KEYSTORE = "keystore"
    """Let the keystore ask the user itself: Windows' PIN dialog, a reader's
    PIN pad. Waits for the user, so it is never the default."""


KEYSTORE_PROMPT = Prompt.KEYSTORE


@dataclass(frozen=True)
class PinRequest:
    """What a PIN callback is told. It never contains a PIN."""

    backend: str
    """The backend asking: ``"cng"`` or ``"pkcs11"``."""
    token: str
    """The token's label (PKCS#11), or the key's container name (CNG)."""
    certificate: str
    """Subject of the certificate whose key needs the PIN; ``""`` when the
    request is not about one key (logging in to list a token)."""
    purpose: str
    """``"list"``: logging in to see private keys; declining only hides
    them. ``"sign"``: logging in before a signature; declining fails it.
    ``"per-signature"``: the key demands the PIN for every signature
    (``CKA_ALWAYS_AUTHENTICATE``, a PIV card's signature key)."""
    keystore_prompt: bool
    """Whether returning :data:`KEYSTORE_PROMPT` can work here (the token has
    a PIN pad, or Windows can show its dialog)."""


PinCallback = Callable[[PinRequest], Union[str, Prompt, None]]
"""Returns the PIN, :data:`KEYSTORE_PROMPT`, or ``None`` to decline."""

PinSource = Union[str, Prompt, PinCallback, None]
"""A PIN, :data:`KEYSTORE_PROMPT`, a :data:`PinCallback`, or ``None`` (no PIN:
fail instead of asking anyone)."""

PasswordSource = Union[str, bytes, Callable[[], Union[str, bytes, None]], None]
"""A password, a callable returning one (or ``None`` to decline), or ``None``."""


def resolve_pin(source: PinSource, request: PinRequest) -> Union[str, Prompt, None]:
    """The PIN ``source`` gives for ``request``; ``None`` means none.

    A callback is called every time; it decides whether to prompt, cache or
    decline. Exceptions it raises propagate.
    """
    if source is None or isinstance(source, (str, Prompt)):
        return source
    if not callable(source):
        # The type only: the value may be a secret in the wrong form.
        raise TypeError(
            "pin must be a str, KEYSTORE_PROMPT or a callable, "
            f"not {type(source).__name__}"
        )
    answer = source(request)
    if answer is not None and not isinstance(answer, (str, Prompt)):
        raise TypeError(
            f"the PIN callback returned {type(answer).__name__}; "
            "expected str, KEYSTORE_PROMPT or None"
        )
    return answer


def resolve_password(source: PasswordSource) -> Optional[bytes]:
    """The password ``source`` gives, as bytes; ``None`` means none."""
    if callable(source):
        source = source()
    if source is None or isinstance(source, bytes):
        return source
    if isinstance(source, str):
        return source.encode("utf-8")
    raise TypeError(f"a password must be str or bytes, not {type(source).__name__}")
