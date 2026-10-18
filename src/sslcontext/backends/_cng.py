"""Windows certificate stores: keys in CNG key storage providers or legacy CSPs.

Covers software keys (exportable or not), TPM-backed keys, smart cards and
virtual smart cards through their minidrivers. Signing goes through
``NCryptSignHash``; a key held by a legacy CryptoAPI CSP signs through
``CryptSignHash``, which offers PKCS#1 v1.5 only (enough for TLS 1.2).
"""

from __future__ import annotations

import ctypes
import errno
import sys
import threading
from ctypes import POINTER, byref, c_size_t, c_void_p, c_wchar_p
from typing import Iterator, List, Optional

from .._identity import Identity, Padding
from ..exceptions import KeystoreError, SigningError
from . import Backend

__all__ = ["CNGBackend"]

_LOCATIONS = {"current_user": 1 << 16, "local_machine": 2 << 16}
_CERT_STORE_PROV_SYSTEM_W = 10
_CERT_STORE_OPEN_EXISTING_FLAG = 0x4000
_CERT_STORE_READONLY_FLAG = 0x8000
_CERT_KEY_PROV_INFO_PROP_ID = 2
_CERT_FRIENDLY_NAME_PROP_ID = 11
_CRYPT_ACQUIRE_CACHE_FLAG = 0x1
_CRYPT_ACQUIRE_SILENT_FLAG = 0x40
_CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x20000
_CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF
_CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL = 0x80000000
_CERT_TRUST_IS_SELF_SIGNED = 0x8
_BCRYPT_PAD_PKCS1, _BCRYPT_PAD_PSS = 0x2, 0x8
_NCRYPT_SILENT_FLAG = 0x40
_NCRYPT_PIN_PROPERTY = "SmartCardPin"
_HP_HASHVAL = 2
_PP_SIGNATURE_PIN = 33
_CALG = {"sha1": 0x8004, "sha256": 0x800C, "sha384": 0x800D, "sha512": 0x800E}
_CNG_HASH = {"sha1": "SHA1", "sha256": "SHA256", "sha384": "SHA384", "sha512": "SHA512"}


class _CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", ctypes.c_uint32),
        ("pbCertEncoded", c_void_p),
        ("cbCertEncoded", ctypes.c_uint32),
        ("pCertInfo", c_void_p),
        ("hCertStore", c_void_p),
    ]


class _TRUST_STATUS(ctypes.Structure):
    _fields_ = [("dwErrorStatus", ctypes.c_uint32), ("dwInfoStatus", ctypes.c_uint32)]


class _CHAIN_ELEMENT(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("pCertContext", POINTER(_CERT_CONTEXT)),
        ("TrustStatus", _TRUST_STATUS),
    ]


class _SIMPLE_CHAIN(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("TrustStatus", _TRUST_STATUS),
        ("cElement", ctypes.c_uint32),
        ("rgpElement", POINTER(POINTER(_CHAIN_ELEMENT))),
    ]


class _CHAIN_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("TrustStatus", _TRUST_STATUS),
        ("cChain", ctypes.c_uint32),
        ("rgpChain", POINTER(POINTER(_SIMPLE_CHAIN))),
    ]


class _CHAIN_PARA(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("dwType", ctypes.c_uint32),
        ("cUsageIdentifier", ctypes.c_uint32),
        ("rgpszUsageIdentifier", c_void_p),
    ]


class _PKCS1_PADDING_INFO(ctypes.Structure):
    _fields_ = [("pszAlgId", c_wchar_p)]


class _PSS_PADDING_INFO(ctypes.Structure):
    _fields_ = [("pszAlgId", c_wchar_p), ("cbSalt", ctypes.c_ulong)]


class _API:
    """crypt32, ncrypt and advapi32 with their signatures declared."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise KeystoreError(errno.ENOSYS, "the cng backend needs Windows")
        W = ctypes.WinDLL
        self.crypt32 = c = W("crypt32", use_last_error=True)
        self.ncrypt = n = W("ncrypt")
        self.advapi32 = a = W("advapi32", use_last_error=True)
        PCTX = POINTER(_CERT_CONTEXT)
        BOOL, DWORD = ctypes.c_int, ctypes.c_uint32
        self._declare(
            c.CertOpenStore, c_void_p, [c_void_p, DWORD, c_size_t, DWORD, c_wchar_p]
        )
        self._declare(c.CertCloseStore, BOOL, [c_void_p, DWORD])
        self._declare(c.CertEnumCertificatesInStore, PCTX, [c_void_p, PCTX])
        self._declare(c.CertDuplicateCertificateContext, PCTX, [PCTX])
        self._declare(c.CertFreeCertificateContext, BOOL, [PCTX])
        self._declare(
            c.CertGetCertificateContextProperty,
            BOOL,
            [PCTX, DWORD, c_void_p, POINTER(DWORD)],
        )
        self._declare(
            c.CryptAcquireCertificatePrivateKey,
            BOOL,
            [PCTX, DWORD, c_void_p, POINTER(c_size_t), POINTER(DWORD), POINTER(BOOL)],
        )
        self._declare(
            c.CertGetCertificateChain,
            BOOL,
            [
                c_void_p,
                PCTX,
                c_void_p,
                c_void_p,
                POINTER(_CHAIN_PARA),
                DWORD,
                c_void_p,
                POINTER(POINTER(_CHAIN_CONTEXT)),
            ],
        )
        self._declare(c.CertFreeCertificateChain, None, [POINTER(_CHAIN_CONTEXT)])
        self._declare(
            n.NCryptSignHash,
            ctypes.c_long,
            [
                c_size_t,
                c_void_p,
                ctypes.c_char_p,
                DWORD,
                c_void_p,
                DWORD,
                POINTER(DWORD),
                DWORD,
            ],
        )
        self._declare(
            n.NCryptSetProperty,
            ctypes.c_long,
            [c_size_t, c_wchar_p, c_void_p, DWORD, DWORD],
        )
        self._declare(n.NCryptFreeObject, ctypes.c_long, [c_size_t])
        self._declare(
            a.CryptCreateHash,
            BOOL,
            [c_size_t, DWORD, c_size_t, DWORD, POINTER(c_size_t)],
        )
        self._declare(
            a.CryptSetHashParam, BOOL, [c_size_t, DWORD, ctypes.c_char_p, DWORD]
        )
        self._declare(
            a.CryptSignHashW,
            BOOL,
            [c_size_t, DWORD, c_wchar_p, DWORD, c_void_p, POINTER(DWORD)],
        )
        self._declare(a.CryptDestroyHash, BOOL, [c_size_t])
        self._declare(
            a.CryptSetProvParam, BOOL, [c_size_t, DWORD, ctypes.c_char_p, DWORD]
        )
        self._declare(a.CryptReleaseContext, BOOL, [c_size_t, DWORD])

    @staticmethod
    def _declare(function, restype, argtypes) -> None:  # type: ignore[no-untyped-def]
        function.restype = restype
        function.argtypes = argtypes


_api: Optional[_API] = None
_api_lock = threading.Lock()


def _windows() -> _API:
    global _api
    with _api_lock:
        if _api is None:
            _api = _API()
        return _api


def _last_error(action: str) -> KeystoreError:
    code = ctypes.get_last_error() & 0xFFFFFFFF
    return KeystoreError(
        code, f"{action} failed: 0x{code:08X} {ctypes.FormatError(code).strip()}"
    )


def _status_error(action: str, status: int) -> KeystoreError:
    code = status & 0xFFFFFFFF
    return KeystoreError(
        code, f"{action} failed: 0x{code:08X} {ctypes.FormatError(code).strip()}"
    )


def _context_der(context: "ctypes._Pointer[_CERT_CONTEXT]") -> bytes:
    return ctypes.string_at(
        context.contents.pbCertEncoded, context.contents.cbCertEncoded
    )


def _der_integer(value: bytes) -> bytes:
    value = value.lstrip(b"\0") or b"\0"
    if value[0] & 0x80:
        value = b"\0" + value
    return b"\x02" + _der_length(len(value)) + value


def _der_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def ecdsa_der(raw: bytes) -> bytes:
    """CNG's ``r || s`` ECDSA signature as the DER ``SEQUENCE`` TLS expects."""
    half = len(raw) // 2
    body = _der_integer(raw[:half]) + _der_integer(raw[half:])
    return b"\x30" + _der_length(len(body)) + body


class _CNGSigner:
    """Signs with the private key of one certificate in a Windows store."""

    def __init__(
        self,
        context: "ctypes._Pointer[_CERT_CONTEXT]",
        pin: Optional[str],
        silent: bool,
    ) -> None:
        self._win = _windows()
        self._context = self._win.crypt32.CertDuplicateCertificateContext(context)
        self._pin = pin
        self._silent = silent
        self._lock = threading.Lock()
        self._key = 0
        self._key_spec = 0
        self._free_key = False

    def __repr__(self) -> str:
        return "<CNGSigner>"

    def _acquire(self) -> None:
        if self._key:
            return
        win = self._win
        key, spec, free = c_size_t(), ctypes.c_uint32(), ctypes.c_int()
        flags = _CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | _CRYPT_ACQUIRE_CACHE_FLAG
        if self._silent:
            flags |= _CRYPT_ACQUIRE_SILENT_FLAG
        if not win.crypt32.CryptAcquireCertificatePrivateKey(
            self._context, flags, None, byref(key), byref(spec), byref(free)
        ):
            raise _last_error("CryptAcquireCertificatePrivateKey")
        self._key, self._key_spec, self._free_key = (
            key.value,
            spec.value,
            bool(free.value),
        )
        if self._pin is None:
            return
        if self._key_spec == _CERT_NCRYPT_KEY_SPEC:
            pin = ctypes.create_unicode_buffer(self._pin)
            status = win.ncrypt.NCryptSetProperty(
                self._key, _NCRYPT_PIN_PROPERTY, pin, ctypes.sizeof(pin), 0
            )
            if status:
                raise _status_error("setting the smart card PIN", status)
        elif not win.advapi32.CryptSetProvParam(
            self._key, _PP_SIGNATURE_PIN, self._pin.encode() + b"\0", 0
        ):
            raise _last_error("setting the smart card PIN")

    @property
    def supports_pss(self) -> bool:
        """``False`` for a key only a legacy CryptoAPI provider can use."""
        with self._lock:
            self._acquire()
            return self._key_spec == _CERT_NCRYPT_KEY_SPEC

    def sign(
        self,
        digest: bytes,
        *,
        hash: str,
        padding: Optional[Padding] = None,
        salt_length: Optional[int] = None,
    ) -> bytes:
        with self._lock:
            self._acquire()
            if self._key_spec == _CERT_NCRYPT_KEY_SPEC:
                return self._sign_cng(digest, hash, padding, salt_length)
            return self._sign_legacy(digest, hash, padding)

    def _sign_cng(
        self, digest: bytes, hash: str, padding: Optional[Padding], salt: Optional[int]
    ) -> bytes:
        ncrypt = self._win.ncrypt
        if padding is not None and hash not in _CNG_HASH:
            raise SigningError(f"CNG cannot sign {hash} digests")
        if padding is Padding.PSS:
            info: object = _PSS_PADDING_INFO(_CNG_HASH[hash], salt or 0)
            flags = _BCRYPT_PAD_PSS
        elif padding is Padding.PKCS1V15:
            info, flags = _PKCS1_PADDING_INFO(_CNG_HASH[hash]), _BCRYPT_PAD_PKCS1
        else:
            info, flags = None, 0
        if self._silent:
            flags |= _NCRYPT_SILENT_FLAG
        info_pointer = ctypes.addressof(info) if info is not None else None
        size = ctypes.c_uint32()
        status = ncrypt.NCryptSignHash(
            self._key, info_pointer, digest, len(digest), None, 0, byref(size), flags
        )
        if status:
            raise _status_error("NCryptSignHash", status)
        signature = ctypes.create_string_buffer(size.value)
        status = ncrypt.NCryptSignHash(
            self._key,
            info_pointer,
            digest,
            len(digest),
            signature,
            size,
            byref(size),
            flags,
        )
        if status:
            raise _status_error("NCryptSignHash", status)
        raw = signature.raw[: size.value]
        return raw if padding is not None else ecdsa_der(raw)

    def _sign_legacy(
        self, digest: bytes, hash: str, padding: Optional[Padding]
    ) -> bytes:
        if padding is not Padding.PKCS1V15:
            raise SigningError(
                "this key is held by a legacy CryptoAPI provider, which signs only "
                "RSA PKCS#1 v1.5; limit the connection to TLS 1.2"
            )
        advapi = self._win.advapi32
        handle = c_size_t()
        if not advapi.CryptCreateHash(self._key, _CALG[hash], 0, 0, byref(handle)):
            raise _last_error(f"CryptCreateHash({hash})")
        try:
            if not advapi.CryptSetHashParam(handle, _HP_HASHVAL, digest, 0):
                raise _last_error("CryptSetHashParam")
            size = ctypes.c_uint32()
            if not advapi.CryptSignHashW(
                handle, self._key_spec, None, 0, None, byref(size)
            ):
                raise _last_error("CryptSignHash")
            signature = ctypes.create_string_buffer(size.value)
            if not advapi.CryptSignHashW(
                handle, self._key_spec, None, 0, signature, byref(size)
            ):
                raise _last_error("CryptSignHash")
        finally:
            advapi.CryptDestroyHash(handle)
        # CryptoAPI returns the signature little-endian.
        return signature.raw[: size.value][::-1]

    def close(self) -> None:
        with self._lock:
            if self._key and self._free_key:
                if self._key_spec == _CERT_NCRYPT_KEY_SPEC:
                    self._win.ncrypt.NCryptFreeObject(self._key)
                else:
                    self._win.advapi32.CryptReleaseContext(self._key, 0)
            self._key = 0
            if self._context:
                self._win.crypt32.CertFreeCertificateContext(self._context)
                self._context = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001 - interpreter shutdown
            pass


class CNGBackend(Backend):
    """A Windows system certificate store, e.g. ``CurrentUser\\MY``.

    ``store`` is the store name (``"MY"`` holds personal certificates);
    ``location`` is ``"current_user"`` or ``"local_machine"``. ``pin`` is
    given to smart-card keys instead of a PIN dialog; ``silent=True`` makes
    any key that would need a dialog fail instead.
    """

    name = "cng"

    def __init__(
        self,
        store: str = "MY",
        location: str = "current_user",
        *,
        pin: Optional[str] = None,
        silent: bool = False,
    ) -> None:
        if location not in _LOCATIONS:
            raise ValueError(
                f"location must be one of {sorted(_LOCATIONS)}, not {location!r}"
            )
        if not store:
            raise ValueError("store must be a store name such as 'MY'")
        self.store = store
        self.location = location
        self._pin = pin
        self.silent = silent

    def __repr__(self) -> str:
        return f"CNGBackend(store={self.store!r}, location={self.location!r})"

    def identities(self) -> Iterator[Identity]:
        win = _windows()
        handle = win.crypt32.CertOpenStore(
            _CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            _LOCATIONS[self.location]
            | _CERT_STORE_OPEN_EXISTING_FLAG
            | _CERT_STORE_READONLY_FLAG,
            self.store,
        )
        if not handle:
            raise _last_error(f"opening store {self.location}\\{self.store}")
        try:
            context = None
            while True:
                context = win.crypt32.CertEnumCertificatesInStore(handle, context)
                if not context:
                    break
                if not _has_private_key(win, context):
                    continue
                yield Identity(
                    _context_der(context),
                    _CNGSigner(context, self._pin, self.silent),
                    tuple(_chain(win, context)),
                    _friendly_name(win, context),
                )
        finally:
            win.crypt32.CertCloseStore(handle, 0)


def _has_private_key(win: _API, context: "ctypes._Pointer[_CERT_CONTEXT]") -> bool:
    size = ctypes.c_uint32()
    return bool(
        win.crypt32.CertGetCertificateContextProperty(
            context, _CERT_KEY_PROV_INFO_PROP_ID, None, byref(size)
        )
    )


def _friendly_name(win: _API, context: "ctypes._Pointer[_CERT_CONTEXT]") -> str:
    size = ctypes.c_uint32()
    if not win.crypt32.CertGetCertificateContextProperty(
        context, _CERT_FRIENDLY_NAME_PROP_ID, None, byref(size)
    ):
        return ""
    buffer = ctypes.create_string_buffer(size.value)
    if not win.crypt32.CertGetCertificateContextProperty(
        context, _CERT_FRIENDLY_NAME_PROP_ID, buffer, byref(size)
    ):
        return ""
    return buffer.raw[: size.value].decode("utf-16-le").rstrip("\0")


def _chain(win: _API, context: "ctypes._Pointer[_CERT_CONTEXT]") -> List[bytes]:
    """The issuers Windows can find for ``context`` without the network, root excluded."""
    para = _CHAIN_PARA(ctypes.sizeof(_CHAIN_PARA), 0, 0, None)
    chain = POINTER(_CHAIN_CONTEXT)()
    if not win.crypt32.CertGetCertificateChain(
        None,
        context,
        None,
        None,
        byref(para),
        _CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
        None,
        byref(chain),
    ):
        return []
    try:
        if not chain.contents.cChain:
            return []
        simple = chain.contents.rgpChain[0].contents
        issuers = []
        for index in range(1, simple.cElement):
            element = simple.rgpElement[index].contents
            if element.TrustStatus.dwInfoStatus & _CERT_TRUST_IS_SELF_SIGNED:
                break
            issuers.append(_context_der(element.pCertContext))
        return issuers
    finally:
        win.crypt32.CertFreeCertificateChain(chain)
