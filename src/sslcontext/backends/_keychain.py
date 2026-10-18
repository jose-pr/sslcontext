"""The ``keychain`` backend: identities in the macOS Keychain, smart cards included."""

from __future__ import annotations

import errno
import logging
import os
import sys
import threading
from ctypes import byref, c_bool, c_void_p
from typing import Iterator, List, Optional, Tuple, Union

from .._identity import Identity, Padding
from .._pin import KEYSTORE_PROMPT, PinRequest, PinSource, resolve_pin
from ..exceptions import KeystoreError, SigningError
from . import Backend
from ._macos import CF, cf_data, data_bytes, frameworks, string_text

__all__ = ["KeychainBackend"]

_log = logging.getLogger("sslcontext")

_ERR_SEC_ITEM_NOT_FOUND = -25300
_ERR_SEC_INTERACTION_NOT_ALLOWED = -25308
_ERR_SEC_AUTH_FAILED = -25293
_ERR_SEC_USER_CANCELED = -128
_SIGN = 0  # kSecKeyOperationTypeSign
# Security.framework's digest algorithm names; PSS salts are as long as the digest.
_RSA_PKCS1 = "kSecKeyAlgorithmRSASignatureDigestPKCS1v15{}"
_RSA_PSS = "kSecKeyAlgorithmRSASignatureDigestPSS{}"
_ECDSA = "kSecKeyAlgorithmECDSASignatureDigestX962{}"
_HASHES = {
    "sha1": "SHA1",
    "sha224": "SHA224",
    "sha256": "SHA256",
    "sha384": "SHA384",
    "sha512": "SHA512",
}
_DIGEST_SIZE = {"sha1": 20, "sha224": 28, "sha256": 32, "sha384": 48, "sha512": 64}
# Keychain user interaction is process-wide: one signer changes it at a time.
_interaction_lock = threading.Lock()


class _KeychainSigner:
    """Signs with a Keychain identity's key, silently unless allowed to ask."""

    def __init__(self, cf: CF, identity: int, label: str, pin: PinSource) -> None:
        self._cf = cf
        self._identity = cf.CFRetain(identity)
        self._label = label
        self._pin = pin
        self._key: Optional[int] = None
        self._lock = threading.Lock()

    def __del__(self) -> None:
        try:
            if self._key:
                self._cf.CFRelease(self._key)
            self._cf.CFRelease(self._identity)
        except Exception:  # noqa: BLE001 - interpreter shutdown
            pass

    def __repr__(self) -> str:
        return f"<keychain signer {self._label!r}>"

    def _private_key(self) -> int:
        if self._key is None:
            key = c_void_p()
            status = self._cf.SecIdentityCopyPrivateKey(self._identity, byref(key))
            if status != 0:
                raise KeystoreError(
                    errno.EIO,
                    f"no private key for {self._label}: {self._cf.message(status)}",
                )
            self._key = key.value
        return self._key  # type: ignore[return-value]

    def _algorithm(self, name: str) -> int:
        return self._cf.constant(name)

    @property
    def supports_pss(self) -> bool:
        with self._lock:
            return bool(
                self._cf.SecKeyIsAlgorithmSupported(
                    self._private_key(),
                    _SIGN,
                    self._algorithm(_RSA_PSS.format("SHA256")),
                )
            )

    def sign(
        self,
        digest: bytes,
        *,
        hash: str,
        padding: Optional[Padding] = None,
        salt_length: Optional[int] = None,
    ) -> bytes:
        suffix = _HASHES[hash]
        if padding is Padding.PSS:
            if salt_length != _DIGEST_SIZE[hash]:
                raise SigningError(
                    f"the Keychain signs PSS with a {_DIGEST_SIZE[hash]}-byte salt, "
                    f"not {salt_length}"
                )
            name = _RSA_PSS.format(suffix)
        elif padding is Padding.PKCS1V15:
            name = _RSA_PKCS1.format(suffix)
        else:
            name = _ECDSA.format(suffix)
        with self._lock:
            key = self._private_key()
            code, message, signature = self._attempt(
                key, name, digest, interactive=False
            )
            if signature is not None:
                return signature
            if code != _ERR_SEC_INTERACTION_NOT_ALLOWED:
                raise SigningError(
                    f"the Keychain refused to sign with {self._label}: {message}"
                )
            answer = resolve_pin(
                self._pin,
                PinRequest("keychain", self._label, self._label, "sign", True),
            )
            if answer is not KEYSTORE_PROMPT:
                raise KeystoreError(
                    errno.EACCES,
                    f"{self._label} needs the user to allow it (a password, a PIN or "
                    "Touch ID) and no KEYSTORE_PROMPT was given",
                )
            code, message, signature = self._attempt(
                key, name, digest, interactive=True
            )
            if signature is None:
                raise SigningError(
                    f"the Keychain refused to sign with {self._label}: {message}"
                )
            return signature

    def _attempt(
        self, key: int, algorithm_name: str, digest: bytes, *, interactive: bool
    ) -> Tuple[int, str, Optional[bytes]]:
        cf = self._cf
        data = cf_data(cf, digest)
        error = c_void_p()
        with _interaction_lock:
            before = c_bool()
            cf.SecKeychainGetUserInteractionAllowed(byref(before))
            cf.SecKeychainSetUserInteractionAllowed(interactive)
            try:
                result = cf.SecKeyCreateSignature(
                    key, self._algorithm(algorithm_name), data, byref(error)
                )
            finally:
                cf.SecKeychainSetUserInteractionAllowed(before.value)
                cf.CFRelease(data)
        if result:
            try:
                return 0, "", data_bytes(cf, result)
            finally:
                cf.CFRelease(result)
        code, message = cf.error_text(error.value) if error.value else (-1, "no error")
        return code, message, None


class KeychainBackend(Backend):
    """Identities in the macOS Keychain: the user's search list (login and
    System keychains) and smart cards (CryptoTokenKit), or one keychain file.

    ``keychain`` is the path of a keychain file to search instead (it must be
    unlocked). Keys are used silently; when macOS reports that one needs the
    user (``errSecInteractionNotAllowed``: a keychain access prompt, a smart
    card PIN, Touch ID), ``pin`` is consulted (``purpose="sign"``):
    ``KEYSTORE_PROMPT`` lets macOS ask with its own dialog, anything else
    fails at once with ``KeystoreError`` (``errno.EACCES``); a PIN value cannot
    be handed to the Keychain.
    """

    name = "keychain"

    def __init__(
        self,
        keychain: Union[str, "os.PathLike[str]", None] = None,
        *,
        pin: PinSource = None,
    ) -> None:
        self.keychain = os.fspath(keychain) if keychain is not None else None
        self._pin = pin

    def __repr__(self) -> str:
        return f"KeychainBackend(keychain={self.keychain!r})"

    def identities(self) -> Iterator[Identity]:
        if sys.platform != "darwin":
            raise KeystoreError(errno.ENOSYS, "the Keychain exists only on macOS")
        cf = frameworks()
        for reference in self._identity_refs(cf):
            try:
                yield self._identity(cf, reference)
            except KeystoreError as error:
                _log.debug("sslcontext: skipping a Keychain identity: %s", error)
            finally:
                cf.CFRelease(reference)

    def _identity_refs(self, cf: CF) -> List[int]:
        queries = [[]]
        search: Optional[int] = None
        if self.keychain is not None:
            # SecKeychainOpen accepts a path that does not exist.
            if not os.path.exists(self.keychain):
                raise KeystoreError(errno.ENOENT, f"no keychain at {self.keychain}")
            keychain = c_void_p()
            status = cf.SecKeychainOpen(self.keychain.encode(), byref(keychain))
            if status != 0:
                raise KeystoreError(
                    errno.ENOENT, f"{self.keychain}: {cf.message(status)}"
                )
            search = cf.array([keychain.value])
            cf.CFRelease(keychain.value)
            queries = [[(cf.constant("kSecMatchSearchList"), search)]]
        else:  # the search list, then the tokens a smart card exposes
            queries.append(
                [
                    (
                        cf.constant("kSecAttrAccessGroup"),
                        cf.constant("kSecAttrAccessGroupToken"),
                    )
                ]
            )
        found: List[int] = []
        seen = set()
        try:
            for extra in queries:
                query = cf.dictionary(
                    [
                        (cf.constant("kSecClass"), cf.constant("kSecClassIdentity")),
                        (cf.constant("kSecReturnRef"), cf.boolean_true),
                        (
                            cf.constant("kSecMatchLimit"),
                            cf.constant("kSecMatchLimitAll"),
                        ),
                    ]
                    + extra
                )
                result = c_void_p()
                status = cf.SecItemCopyMatching(query, byref(result))
                cf.CFRelease(query)
                if status == _ERR_SEC_ITEM_NOT_FOUND or (
                    status != 0 and extra and search is None
                ):
                    continue  # nothing there, or no token access for this process
                if status != 0:
                    raise KeystoreError(
                        errno.EIO, f"Keychain search failed: {cf.message(status)}"
                    )
                try:
                    for reference in cf.items(result.value):
                        der = _certificate_der(cf, reference)
                        if der is not None and der not in seen:
                            seen.add(der)
                            found.append(cf.CFRetain(reference))
                finally:
                    cf.CFRelease(result.value)
        finally:
            if search:
                cf.CFRelease(search)
        return found

    def _identity(self, cf: CF, reference: int) -> Identity:
        certificate = c_void_p()
        status = cf.SecIdentityCopyCertificate(reference, byref(certificate))
        if status != 0:
            raise KeystoreError(errno.EIO, cf.message(status))
        try:
            der = data_bytes_of(cf, certificate.value)
            summary = cf.SecCertificateCopySubjectSummary(certificate.value)
            label = string_text(cf, summary) if summary else ""
            if summary:
                cf.CFRelease(summary)
            chain = _chain(cf, certificate.value)
        finally:
            cf.CFRelease(certificate.value)
        return Identity(
            der, _KeychainSigner(cf, reference, label, self._pin), chain, label
        )


def data_bytes_of(cf: CF, certificate: int) -> bytes:
    data = cf.SecCertificateCopyData(certificate)
    try:
        return data_bytes(cf, data)
    finally:
        cf.CFRelease(data)


def _certificate_der(cf: CF, identity: int) -> Optional[bytes]:
    certificate = c_void_p()
    if cf.SecIdentityCopyCertificate(identity, byref(certificate)) != 0:
        return None
    try:
        return data_bytes_of(cf, certificate.value)
    finally:
        cf.CFRelease(certificate.value)


def _chain(cf: CF, certificate: int) -> Tuple[bytes, ...]:
    """The issuers macOS finds without the network, root excluded."""
    policy = cf.SecPolicyCreateBasicX509()
    certificates = cf.array([certificate])
    trust = c_void_p()
    try:
        if cf.SecTrustCreateWithCertificates(certificates, policy, byref(trust)) != 0:
            return ()
        try:
            cf.SecTrustSetNetworkFetchAllowed(trust.value, False)
            error = c_void_p()
            cf.SecTrustEvaluateWithError(trust.value, byref(error))  # builds the chain
            if error.value:
                cf.CFRelease(error.value)
            links = [
                data_bytes_of(cf, cf.SecTrustGetCertificateAtIndex(trust.value, index))
                for index in range(1, cf.SecTrustGetCertificateCount(trust.value))
            ]
        finally:
            cf.CFRelease(trust.value)
    finally:
        cf.CFRelease(certificates)
        cf.CFRelease(policy)
    if links and _self_signed(links[-1]):
        links.pop()
    return tuple(links)


def _self_signed(der: bytes) -> bool:
    from .._openssl import openssl
    from .._openssl._objects import certificate_fields

    fields = certificate_fields(openssl(), der)
    return fields["subject"] == fields["issuer"]
