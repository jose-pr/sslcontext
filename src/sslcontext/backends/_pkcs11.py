"""PKCS#11 tokens: smart cards (real or virtual), HSMs, TPMs, software tokens.

Signing uses the token's own mechanisms: ``CKM_RSA_PKCS`` over a DigestInfo,
``CKM_RSA_PKCS_PSS`` and ``CKM_ECDSA``. A key flagged
``CKA_ALWAYS_AUTHENTICATE`` (a PIV card's signature key) gets the PIN again,
as ``CKU_CONTEXT_SPECIFIC``, before every signature.
"""

from __future__ import annotations

import errno
import os
import sys
import threading
from ctypes import addressof, byref, c_ulong, create_string_buffer, sizeof
from typing import Callable, Dict, Iterator, List, Optional, Union

from .._asn1 import DIGEST_INFO_PREFIX, ecdsa_der
from .._identity import Identity, Padding
from ..exceptions import KeystoreError, SigningError
from . import Backend
from ._cryptoki import (
    CK_MECHANISM,
    CK_RSA_PKCS_PSS_PARAMS,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_CERTIFICATE_TYPE,
    CKA_CLASS,
    CKA_ID,
    CKA_LABEL,
    CKA_VALUE,
    CKC_X_509,
    CKF_LOGIN_REQUIRED,
    CKF_PROTECTED_AUTHENTICATION_PATH,
    CKF_TOKEN_INITIALIZED,
    CKG_MGF1,
    CKM_ECDSA,
    CKM_HASH,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS,
    CKO_CERTIFICATE,
    CKO_PRIVATE_KEY,
    CKU_CONTEXT_SPECIFIC,
    CKU_USER,
    SESSION_LOST,
    CryptokiError,
    Module,
    load_module,
    text,
    ulong,
)

__all__ = ["PKCS11Backend", "PinSource"]

PinSource = Union[str, Callable[[str], str], None]
"""A PIN, a callable given the token label that returns one, or ``None``."""

_MODULE_ENV = "SSLCONTEXT_PKCS11_MODULE"

_CANDIDATES = {
    "win32": [
        r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
        os.path.expandvars(r"%SystemRoot%\System32\opensc-pkcs11.dll"),
    ],
    "darwin": [
        "/Library/OpenSC/lib/opensc-pkcs11.so",
        "/opt/homebrew/lib/opensc-pkcs11.so",
        "/usr/local/lib/opensc-pkcs11.so",
    ],
    "linux": [
        "/usr/lib64/p11-kit-proxy.so",
        "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so",
        "/usr/lib/aarch64-linux-gnu/p11-kit-proxy.so",
        "/usr/lib/p11-kit-proxy.so",
        "/usr/lib64/opensc-pkcs11.so",
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
    ],
}


def default_module() -> Optional[str]:
    """``SSLCONTEXT_PKCS11_MODULE``, else the first platform default present.

    The defaults are p11-kit's proxy (every module the system has configured)
    on Linux, and OpenSC elsewhere.
    """
    configured = os.environ.get(_MODULE_ENV)
    if configured:
        return configured
    platform = "linux" if sys.platform.startswith("linux") else sys.platform
    for candidate in _CANDIDATES.get(platform, []):
        if os.path.exists(candidate):
            return candidate
    return None


class _Token:
    """One token in one slot, shared by the signers made from it."""

    def __init__(self, module: Module, slot: int, pin: PinSource) -> None:
        info = module.token_info(slot)
        self.module = module
        self.slot = slot
        self.label = text(info.label)
        self.serial = text(info.serialNumber)
        self.flags = info.flags
        self._pin = pin
        self._mechanisms: Optional[List[int]] = None

    @property
    def needs_login(self) -> bool:
        return bool(self.flags & CKF_LOGIN_REQUIRED)

    @property
    def can_login(self) -> bool:
        return self._pin is not None or bool(
            self.flags & CKF_PROTECTED_AUTHENTICATION_PATH
        )

    def pin(self) -> Optional[str]:
        """The PIN, ``None`` for a PIN pad; asks a callable every time."""
        if callable(self._pin):
            return self._pin(self.label)
        if self._pin is None and not self.flags & CKF_PROTECTED_AUTHENTICATION_PATH:
            raise KeystoreError(
                errno.EACCES,
                f"token {self.label!r} needs a PIN; pass pin= to PKCS11Backend",
            )
        return self._pin

    def login(self, session: int, user: int = CKU_USER) -> None:
        self.module.login(session, user, self.pin())

    def mechanisms(self) -> List[int]:
        if self._mechanisms is None:
            self._mechanisms = self.module.mechanisms(self.slot)
        return self._mechanisms

    def relocate(self) -> None:
        """Find this token again after its card was removed and reinserted.

        Re-reading the slot list is what makes a module notice card events,
        and the token may come back in another slot (another reader).
        """
        for slot in self.module.slots():
            info = self.module.token_info(slot)
            if (
                text(info.serialNumber) == self.serial
                and text(info.label) == self.label
            ):
                self.slot, self.flags = slot, info.flags
                return
        raise KeystoreError(errno.ENODEV, f"token {self.label!r} is not present")


class _PKCS11Signer:
    """Signs with the private key whose ``CKA_ID`` is ``key_id`` on ``token``."""

    def __init__(self, token: _Token, key_id: bytes) -> None:
        self._token = token
        self._key_id = key_id
        self._lock = threading.Lock()
        self._session = 0
        self._key = 0
        self._always_authenticate = False

    def __repr__(self) -> str:
        return f"<PKCS11Signer token={self._token.label!r} id={self._key_id.hex()}>"

    @property
    def supports_pss(self) -> bool:
        """Whether the token offers ``CKM_RSA_PKCS_PSS``."""
        with self._lock:
            return CKM_RSA_PKCS_PSS in self._token.mechanisms()

    def _open(self) -> None:
        token, module = self._token, self._token.module
        self._session = module.open_session(token.slot)
        if token.needs_login:
            token.login(self._session)
        keys = list(
            module.find(
                self._session, {CKA_CLASS: CKO_PRIVATE_KEY, CKA_ID: self._key_id}
            )
        )
        if not keys:
            raise KeystoreError(
                errno.ENOENT,
                f"no private key with id {self._key_id.hex()} on {token.label!r}",
            )
        self._key = keys[0]
        flag = ulong(
            module.attribute(self._session, self._key, CKA_ALWAYS_AUTHENTICATE)
        )
        self._always_authenticate = bool(flag)

    def _drop(self) -> None:
        if self._session:
            self._token.module.close_session(self._session)
        self._session = self._key = 0

    def sign(
        self,
        digest: bytes,
        *,
        hash: str,
        padding: Optional[Padding] = None,
        salt_length: Optional[int] = None,
    ) -> bytes:
        if hash not in CKM_HASH:
            raise SigningError(f"PKCS#11 signing does not cover {hash}")
        with self._lock:
            for attempt in (1, 2):
                try:
                    if not self._session:
                        self._open()
                    return self._sign(digest, hash, padding, salt_length)
                except CryptokiError as error:
                    # A reinserted card invalidates sessions and handles; find
                    # the token again and reopen once.
                    self._drop()
                    if attempt == 2 or error.rv not in SESSION_LOST:
                        raise
                    self._token.relocate()
        raise AssertionError("unreachable")

    def _sign(
        self, digest: bytes, hash: str, padding: Optional[Padding], salt: Optional[int]
    ) -> bytes:
        module = self._token.module
        parameters: object = None
        if padding is Padding.PSS:
            parameters = CK_RSA_PKCS_PSS_PARAMS(
                CKM_HASH[hash], CKG_MGF1[hash], salt or 0
            )
            mechanism = CK_MECHANISM(
                CKM_RSA_PKCS_PSS, addressof(parameters), sizeof(parameters)
            )
            data = digest
        elif padding is Padding.PKCS1V15:
            mechanism, data = (
                CK_MECHANISM(CKM_RSA_PKCS, None, 0),
                DIGEST_INFO_PREFIX[hash] + digest,
            )
        else:
            mechanism, data = CK_MECHANISM(CKM_ECDSA, None, 0), digest
        module.call("C_SignInit", self._session, byref(mechanism), self._key)
        if self._always_authenticate:
            self._token.login(self._session, CKU_CONTEXT_SPECIFIC)
        size = c_ulong()
        module.call("C_Sign", self._session, data, len(data), None, byref(size))
        signature = create_string_buffer(size.value)
        module.call("C_Sign", self._session, data, len(data), signature, byref(size))
        raw = signature.raw[: size.value]
        return raw if padding is not None else ecdsa_der(raw)

    def close(self) -> None:
        with self._lock:
            self._drop()


class PKCS11Backend(Backend):
    """Identities on the tokens of a PKCS#11 module.

    ``module`` is the module's path; by default ``SSLCONTEXT_PKCS11_MODULE``,
    else p11-kit's proxy on Linux or OpenSC elsewhere. ``token`` limits the
    search to a token label or serial number, ``slot`` to a slot id. ``pin``
    is the user PIN, or a callable given the token label that returns it
    (asked at each login, so it can prompt); ``None`` uses a PIN pad when
    the token has one and otherwise lists only what is visible without
    logging in.
    """

    name = "pkcs11"

    def __init__(
        self,
        module: Union[str, "os.PathLike[str]", None] = None,
        *,
        token: Optional[str] = None,
        slot: Optional[int] = None,
        pin: PinSource = None,
    ) -> None:
        self.module = os.fspath(module) if module is not None else None
        self.token = token
        self.slot = slot
        self._pin = pin

    def __repr__(self) -> str:
        return f"PKCS11Backend(module={self.module!r}, token={self.token!r}, slot={self.slot!r})"

    def _module(self) -> Module:
        path = self.module or default_module()
        if path is None:
            raise KeystoreError(
                errno.ENOENT,
                f"no PKCS#11 module found; pass module= or set {_MODULE_ENV}",
            )
        return load_module(path)

    def tokens(self) -> List[str]:
        """Labels of the tokens present, after the ``token``/``slot`` filters."""
        return [token.label for token in self._tokens()]

    def _tokens(self) -> Iterator[_Token]:
        module = self._module()
        for slot in module.slots():
            if self.slot is not None and slot != self.slot:
                continue
            token = _Token(module, slot, self._pin)
            if not token.flags & CKF_TOKEN_INITIALIZED:
                continue
            if self.token is not None and self.token not in (token.label, token.serial):
                continue
            yield token

    def identities(self) -> Iterator[Identity]:
        for token in self._tokens():
            yield from self._token_identities(token)

    def _token_identities(self, token: _Token) -> List[Identity]:
        module = token.module
        session = module.open_session(token.slot)
        try:
            logged_in = False
            if token.needs_login and token.can_login:
                token.login(session)
                logged_in = True
            certificates = []
            for handle in module.find(
                session, {CKA_CLASS: CKO_CERTIFICATE, CKA_CERTIFICATE_TYPE: CKC_X_509}
            ):
                value = module.attribute(session, handle, CKA_VALUE)
                if value:
                    certificates.append(
                        (
                            value,
                            module.attribute(session, handle, CKA_ID) or b"",
                            (
                                module.attribute(session, handle, CKA_LABEL) or b""
                            ).decode("utf-8", "replace"),
                        )
                    )
            key_ids = {
                module.attribute(session, handle, CKA_ID) or b""
                for handle in module.find(session, {CKA_CLASS: CKO_PRIVATE_KEY})
            }
        finally:
            module.close_session(session)
        # Without a login, private keys may be hidden; a certificate with an id
        # is then assumed to have its key, which the first signature checks.
        unseen_keys_possible = token.needs_login and not logged_in
        identities = []
        for value, key_id, label in certificates:
            if not key_id or (key_id not in key_ids and not unseen_keys_possible):
                continue
            identities.append(
                Identity(
                    value,
                    _PKCS11Signer(token, key_id),
                    tuple(_chain(value, [c[0] for c in certificates])),
                    label,
                )
            )
        return identities


def _chain(leaf: bytes, pool: List[bytes]) -> List[bytes]:
    """Issuers of ``leaf`` found among the token's certificates, root excluded."""
    from .._openssl import openssl
    from .._openssl._objects import certificate_fields

    lib = openssl()
    fields: Dict[bytes, dict] = {der: certificate_fields(lib, der) for der in pool}
    chain: List[bytes] = []
    current = fields.get(leaf) or certificate_fields(lib, leaf)
    while current["issuer"] != current["subject"] and len(chain) < 8:
        issuer = next(
            (
                der
                for der, f in fields.items()
                if f["subject"] == current["issuer"] and der != leaf
            ),
            None,
        )
        if (
            issuer is None
            or issuer in chain
            or fields[issuer]["issuer"] == fields[issuer]["subject"]
        ):
            break
        chain.append(issuer)
        current = fields[issuer]
    return chain
