"""Security.framework and CoreFoundation through ctypes, for the Keychain
backend and the macOS trust anchors. Loaded on first use, macOS only."""

from __future__ import annotations

import ctypes
import errno
import threading
from ctypes import POINTER, byref, c_bool, c_char_p, c_int32, c_long, c_void_p
from typing import Iterator, List, Optional, Sequence

from ..exceptions import KeystoreError

__all__ = ["CF", "cf_data", "cf_string", "data_bytes", "frameworks", "string_text"]

_SECURITY = "/System/Library/Frameworks/Security.framework/Security"
_CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_UTF8 = 0x08000100  # kCFStringEncodingUTF8


class CF:
    """The two frameworks with the signatures used here."""

    def __init__(self) -> None:
        try:
            self.security = ctypes.CDLL(_SECURITY)
            self.core = ctypes.CDLL(_CORE_FOUNDATION)
        except OSError as error:
            raise KeystoreError(
                errno.ENOSYS, f"the macOS Keychain needs Security.framework: {error}"
            ) from None
        P = c_void_p
        for name, restype, argtypes, lib in (
            ("CFRelease", None, [P], self.core),
            ("CFRetain", P, [P], self.core),
            ("CFGetTypeID", c_long, [P], self.core),
            ("CFArrayGetTypeID", c_long, [], self.core),
            ("CFDictionaryGetTypeID", c_long, [], self.core),
            ("CFNumberGetTypeID", c_long, [], self.core),
            ("CFArrayGetCount", c_long, [P], self.core),
            ("CFArrayGetValueAtIndex", P, [P, c_long], self.core),
            ("CFArrayCreate", P, [P, POINTER(P), c_long, P], self.core),
            (
                "CFDictionaryCreate",
                P,
                [P, POINTER(P), POINTER(P), c_long, P, P],
                self.core,
            ),
            ("CFDictionaryGetValue", P, [P, P], self.core),
            ("CFDataCreate", P, [P, c_char_p, c_long], self.core),
            ("CFDataGetLength", c_long, [P], self.core),
            ("CFDataGetBytePtr", P, [P], self.core),
            ("CFStringCreateWithCString", P, [P, c_char_p, ctypes.c_uint32], self.core),
            ("CFStringGetLength", c_long, [P], self.core),
            (
                "CFStringGetMaximumSizeForEncoding",
                c_long,
                [c_long, ctypes.c_uint32],
                self.core,
            ),
            (
                "CFStringGetCString",
                c_bool,
                [P, c_char_p, c_long, ctypes.c_uint32],
                self.core,
            ),
            ("CFNumberGetValue", c_bool, [P, c_long, P], self.core),
            ("CFErrorGetCode", c_long, [P], self.core),
            ("CFErrorCopyDescription", P, [P], self.core),
            ("SecItemCopyMatching", c_int32, [P, POINTER(P)], self.security),
            ("SecIdentityCopyCertificate", c_int32, [P, POINTER(P)], self.security),
            ("SecIdentityCopyPrivateKey", c_int32, [P, POINTER(P)], self.security),
            ("SecCertificateCopyData", P, [P], self.security),
            ("SecCertificateCreateWithData", P, [P, P], self.security),
            ("SecCertificateCopySubjectSummary", P, [P], self.security),
            ("SecKeyCreateSignature", P, [P, P, P, POINTER(P)], self.security),
            ("SecKeyIsAlgorithmSupported", c_bool, [P, c_long, P], self.security),
            ("SecKeychainOpen", c_int32, [c_char_p, POINTER(P)], self.security),
            ("SecKeychainSetUserInteractionAllowed", c_int32, [c_bool], self.security),
            (
                "SecKeychainGetUserInteractionAllowed",
                c_int32,
                [POINTER(c_bool)],
                self.security,
            ),
            ("SecPolicyCreateBasicX509", P, [], self.security),
            (
                "SecTrustCreateWithCertificates",
                c_int32,
                [P, P, POINTER(P)],
                self.security,
            ),
            ("SecTrustSetNetworkFetchAllowed", c_int32, [P, c_bool], self.security),
            ("SecTrustEvaluateWithError", c_bool, [P, POINTER(P)], self.security),
            ("SecTrustGetCertificateCount", c_long, [P], self.security),
            ("SecTrustGetCertificateAtIndex", P, [P, c_long], self.security),
            ("SecTrustCopyAnchorCertificates", c_int32, [POINTER(P)], self.security),
            (
                "SecTrustSettingsCopyCertificates",
                c_int32,
                [ctypes.c_uint32, POINTER(P)],
                self.security,
            ),
            (
                "SecTrustSettingsCopyTrustSettings",
                c_int32,
                [P, ctypes.c_uint32, POINTER(P)],
                self.security,
            ),
            ("SecCopyErrorMessageString", P, [c_int32, P], self.security),
        ):
            function = getattr(lib, name)
            function.restype = restype
            function.argtypes = argtypes
            setattr(self, name, function)
        self.boolean_true = c_void_p.in_dll(self.core, "kCFBooleanTrue").value
        self.key_callbacks = ctypes.addressof(
            c_void_p.in_dll(self.core, "kCFTypeDictionaryKeyCallBacks")
        )
        self.value_callbacks = ctypes.addressof(
            c_void_p.in_dll(self.core, "kCFTypeDictionaryValueCallBacks")
        )
        self.array_callbacks = ctypes.addressof(
            c_void_p.in_dll(self.core, "kCFTypeArrayCallBacks")
        )

    def constant(self, name: str) -> int:
        """A ``CFStringRef`` constant exported by Security.framework."""
        return c_void_p.in_dll(self.security, name).value  # type: ignore[return-value]

    def dictionary(self, pairs: Sequence[tuple]) -> int:
        keys = (c_void_p * len(pairs))(*(k for k, _ in pairs))
        values = (c_void_p * len(pairs))(*(v for _, v in pairs))
        return self.CFDictionaryCreate(  # type: ignore[no-any-return]
            None, keys, values, len(pairs), self.key_callbacks, self.value_callbacks
        )

    def array(self, items: Sequence[int]) -> int:
        values = (c_void_p * len(items))(*items)
        return self.CFArrayCreate(None, values, len(items), self.array_callbacks)  # type: ignore[no-any-return]

    def items(self, array: int) -> Iterator[int]:
        for index in range(self.CFArrayGetCount(array)):
            yield self.CFArrayGetValueAtIndex(array, index)

    def message(self, status: int) -> str:
        text = self.SecCopyErrorMessageString(status, None)
        try:
            return string_text(self, text) if text else f"OSStatus {status}"
        finally:
            if text:
                self.CFRelease(text)

    def error_text(self, error: int) -> tuple:
        """``(code, description)`` of a ``CFErrorRef``, which is released."""
        try:
            code = self.CFErrorGetCode(error)
            description = self.CFErrorCopyDescription(error)
            try:
                return code, string_text(self, description) if description else ""
            finally:
                if description:
                    self.CFRelease(description)
        finally:
            self.CFRelease(error)


def cf_data(cf: CF, data: bytes) -> int:
    return cf.CFDataCreate(None, data, len(data))  # type: ignore[no-any-return]


def cf_string(cf: CF, text: str) -> int:
    return cf.CFStringCreateWithCString(None, text.encode("utf-8"), _UTF8)  # type: ignore[no-any-return]


def data_bytes(cf: CF, data: int) -> bytes:
    return ctypes.string_at(cf.CFDataGetBytePtr(data), cf.CFDataGetLength(data))


def string_text(cf: CF, string: int) -> str:
    size = cf.CFStringGetMaximumSizeForEncoding(cf.CFStringGetLength(string), _UTF8) + 1
    buffer = ctypes.create_string_buffer(size)
    if not cf.CFStringGetCString(string, buffer, size, _UTF8):
        return ""
    return buffer.value.decode("utf-8", "replace")


_cf: Optional[CF] = None
_lock = threading.Lock()


def frameworks() -> CF:
    global _cf
    with _lock:
        if _cf is None:
            _cf = CF()
        return _cf


def anchor_certificates() -> List[bytes]:
    """DER of the certificates macOS trusts as roots: the system's anchors,
    and those an administrator or the user marked trusted (any with a "deny"
    setting is left out)."""
    cf = frameworks()
    found: List[bytes] = []
    out = c_void_p()
    if cf.SecTrustCopyAnchorCertificates(byref(out)) == 0 and out.value:
        try:
            found += [_certificate_der(cf, c) for c in cf.items(out.value)]
        finally:
            cf.CFRelease(out.value)
    for domain in (1, 0):  # kSecTrustSettingsDomainAdmin, kSecTrustSettingsDomainUser
        out = c_void_p()
        if (
            cf.SecTrustSettingsCopyCertificates(domain, byref(out)) != 0
            or not out.value
        ):
            continue
        try:
            for certificate in cf.items(out.value):
                if not _denied(cf, certificate, domain):
                    found.append(_certificate_der(cf, certificate))
        finally:
            cf.CFRelease(out.value)
    return list(dict.fromkeys(found))


def _certificate_der(cf: CF, certificate: int) -> bytes:
    data = cf.SecCertificateCopyData(certificate)
    try:
        return data_bytes(cf, data)
    finally:
        cf.CFRelease(data)


def _denied(cf: CF, certificate: int, domain: int) -> bool:
    settings = c_void_p()
    if cf.SecTrustSettingsCopyTrustSettings(certificate, domain, byref(settings)) != 0:
        return True  # unreadable settings are not trust
    if not settings.value:
        return False
    try:
        result_key = cf_string(cf, "kSecTrustSettingsResult")
        try:
            for entry in cf.items(settings.value):
                value = cf.CFDictionaryGetValue(entry, result_key)
                number = ctypes.c_int32()
                if value and cf.CFNumberGetValue(
                    value, 3, byref(number)
                ):  # kCFNumberSInt32Type
                    if number.value == 3:  # kSecTrustSettingsResultDeny
                        return True
        finally:
            cf.CFRelease(result_key)
    finally:
        cf.CFRelease(settings.value)
    return False
