"""A minimal ctypes binding of PKCS#11 (Cryptoki) v2.40: enough to find and sign.

Layout rules from the specification's platform notes: ``CK_ULONG`` is the C
``unsigned long`` (32 bits on Windows, the word size elsewhere), and on
Windows every Cryptoki structure is packed to 1 byte.
"""

from __future__ import annotations

import ctypes
import sys
import threading
from ctypes import POINTER, byref, c_char_p, c_ubyte, c_ulong, c_void_p
from typing import Dict, Iterator, List, Optional, Tuple

from ..exceptions import KeystoreError

__all__ = ["Module", "load_module"]

CK_ULONG = c_ulong
_PACK = 1 if sys.platform == "win32" else 0
_UNAVAILABLE = CK_ULONG(-1).value

# object classes, attributes, key types, mechanisms
CKO_CERTIFICATE, CKO_PRIVATE_KEY = 1, 3
CKA_CLASS, CKA_TOKEN, CKA_LABEL, CKA_VALUE = 0x0, 0x1, 0x3, 0x11
CKA_CERTIFICATE_TYPE, CKA_KEY_TYPE, CKA_ID = 0x80, 0x100, 0x102
CKA_ALWAYS_AUTHENTICATE = 0x202
CKC_X_509 = 0
CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_ECDSA = 0x1, 0xD, 0x1041
CKM_HASH = {
    "sha1": 0x220,
    "sha224": 0x255,
    "sha256": 0x250,
    "sha384": 0x260,
    "sha512": 0x270,
}
CKG_MGF1 = {"sha1": 1, "sha224": 5, "sha256": 2, "sha384": 3, "sha512": 4}
# users, flags
CKU_USER, CKU_CONTEXT_SPECIFIC = 1, 2
CKF_OS_LOCKING_OK = 0x2
CKF_SERIAL_SESSION = 0x4
CKF_LOGIN_REQUIRED = 0x4
CKF_PROTECTED_AUTHENTICATION_PATH = 0x100
CKF_TOKEN_INITIALIZED = 0x400
# return values
CKR_OK = 0x0
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191
CKR_USER_ALREADY_LOGGED_IN = 0x100
CKR_NAMES = {
    0x5: "CKR_GENERAL_ERROR",
    0x6: "CKR_FUNCTION_FAILED",
    0x7: "CKR_ARGUMENTS_BAD",
    0x30: "CKR_DEVICE_ERROR",
    0x31: "CKR_DEVICE_MEMORY",
    0x32: "CKR_DEVICE_REMOVED",
    0x60: "CKR_KEY_HANDLE_INVALID",
    0x68: "CKR_KEY_TYPE_INCONSISTENT",
    0x70: "CKR_MECHANISM_INVALID",
    0x71: "CKR_MECHANISM_PARAM_INVALID",
    0x82: "CKR_OBJECT_HANDLE_INVALID",
    0x91: "CKR_OPERATION_NOT_INITIALIZED",
    0xA0: "CKR_PIN_INCORRECT",
    0xA1: "CKR_PIN_INVALID",
    0xA2: "CKR_PIN_LEN_RANGE",
    0xA4: "CKR_PIN_LOCKED",
    0xB0: "CKR_SESSION_CLOSED",
    0xB3: "CKR_SESSION_HANDLE_INVALID",
    0xE0: "CKR_TOKEN_NOT_PRESENT",
    0xE1: "CKR_TOKEN_NOT_RECOGNIZED",
    0x100: "CKR_USER_ALREADY_LOGGED_IN",
    0x101: "CKR_USER_NOT_LOGGED_IN",
    0x102: "CKR_USER_PIN_NOT_INITIALIZED",
    0x103: "CKR_USER_TYPE_INVALID",
    0x150: "CKR_BUFFER_TOO_SMALL",
    0x190: "CKR_CRYPTOKI_NOT_INITIALIZED",
}
# A session or handle that a removed and reinserted token invalidated.
SESSION_LOST = {0x60, 0x82, 0xB0, 0xB3, 0x101, 0x32, 0xE0}


class CK_VERSION(ctypes.Structure):
    if _PACK:
        _pack_ = _PACK
    _fields_ = [("major", c_ubyte), ("minor", c_ubyte)]


class CK_TOKEN_INFO(ctypes.Structure):
    if _PACK:
        _pack_ = _PACK
    _fields_ = [
        ("label", c_ubyte * 32),
        ("manufacturerID", c_ubyte * 32),
        ("model", c_ubyte * 16),
        ("serialNumber", c_ubyte * 16),
        ("flags", CK_ULONG),
        ("ulMaxSessionCount", CK_ULONG),
        ("ulSessionCount", CK_ULONG),
        ("ulMaxRwSessionCount", CK_ULONG),
        ("ulRwSessionCount", CK_ULONG),
        ("ulMaxPinLen", CK_ULONG),
        ("ulMinPinLen", CK_ULONG),
        ("ulTotalPublicMemory", CK_ULONG),
        ("ulFreePublicMemory", CK_ULONG),
        ("ulTotalPrivateMemory", CK_ULONG),
        ("ulFreePrivateMemory", CK_ULONG),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
        ("utcTime", c_ubyte * 16),
    ]


class CK_ATTRIBUTE(ctypes.Structure):
    if _PACK:
        _pack_ = _PACK
    _fields_ = [("type", CK_ULONG), ("pValue", c_void_p), ("ulValueLen", CK_ULONG)]


class CK_MECHANISM(ctypes.Structure):
    if _PACK:
        _pack_ = _PACK
    _fields_ = [
        ("mechanism", CK_ULONG),
        ("pParameter", c_void_p),
        ("ulParameterLen", CK_ULONG),
    ]


class CK_RSA_PKCS_PSS_PARAMS(ctypes.Structure):
    if _PACK:
        _pack_ = _PACK
    _fields_ = [("hashAlg", CK_ULONG), ("mgf", CK_ULONG), ("sLen", CK_ULONG)]


class CK_C_INITIALIZE_ARGS(ctypes.Structure):
    if _PACK:
        _pack_ = _PACK
    _fields_ = [
        ("CreateMutex", c_void_p),
        ("DestroyMutex", c_void_p),
        ("LockMutex", c_void_p),
        ("UnlockMutex", c_void_p),
        ("flags", CK_ULONG),
        ("pReserved", c_void_p),
    ]


class CK_SESSION_INFO(ctypes.Structure):
    if _PACK:
        _pack_ = _PACK
    _fields_ = [
        ("slotID", CK_ULONG),
        ("state", CK_ULONG),
        ("flags", CK_ULONG),
        ("ulDeviceError", CK_ULONG),
    ]


# CKS_RO_USER_FUNCTIONS, CKS_RW_USER_FUNCTIONS, CKS_RW_SO_FUNCTIONS
_LOGGED_IN_STATES = {1, 3, 4}

_P, _UL, _PUL = c_void_p, CK_ULONG, POINTER(CK_ULONG)
# Position in CK_FUNCTION_LIST (after the version) and argument types.
_FUNCTIONS = {
    "C_Initialize": (0, [_P]),
    "C_GetSlotList": (4, [c_ubyte, _PUL, _PUL]),
    "C_GetTokenInfo": (6, [_UL, POINTER(CK_TOKEN_INFO)]),
    "C_GetMechanismList": (7, [_UL, _PUL, _PUL]),
    "C_OpenSession": (12, [_UL, _UL, _P, _P, _PUL]),
    "C_CloseSession": (13, [_UL]),
    "C_GetSessionInfo": (15, [_UL, POINTER(CK_SESSION_INFO)]),
    "C_Login": (18, [_UL, _UL, c_char_p, _UL]),
    "C_GetAttributeValue": (24, [_UL, _UL, POINTER(CK_ATTRIBUTE), _UL]),
    "C_FindObjectsInit": (26, [_UL, POINTER(CK_ATTRIBUTE), _UL]),
    "C_FindObjects": (27, [_UL, _PUL, _UL, _PUL]),
    "C_FindObjectsFinal": (28, [_UL]),
    "C_SignInit": (42, [_UL, POINTER(CK_MECHANISM), _UL]),
    "C_Sign": (43, [_UL, c_char_p, _UL, _P, _PUL]),
}


def rv_name(rv: int) -> str:
    return CKR_NAMES.get(rv, f"CKR_0x{rv:X}")


class CryptokiError(KeystoreError):
    """A PKCS#11 call returned an error; ``errno`` is the ``CKR_*`` value."""

    def __init__(self, function: str, rv: int) -> None:
        super().__init__(rv, f"{function} failed: {rv_name(rv)} (0x{rv:X})")
        self.rv = rv


class Module:
    """One loaded, initialised PKCS#11 module. Never finalised: signers made
    from it may be used until the process exits."""

    def __init__(self, path: str) -> None:
        self.path = path
        try:
            self._library = ctypes.CDLL(path)
        except OSError as error:
            raise KeystoreError(
                error.errno or 0, f"cannot load PKCS#11 module {path!r}: {error}"
            )
        get_list = self._library.C_GetFunctionList
        get_list.restype = CK_ULONG
        get_list.argtypes = [POINTER(c_void_p)]
        table = c_void_p()
        rv = get_list(byref(table))
        if rv != CKR_OK:
            raise CryptokiError("C_GetFunctionList", rv)
        first = 2 if _PACK == 1 else ctypes.sizeof(c_void_p)
        self._functions = {}
        for name, (index, argtypes) in _FUNCTIONS.items():
            address = c_void_p.from_address(
                table.value + first + index * ctypes.sizeof(c_void_p)
            ).value
            self._functions[name] = ctypes.CFUNCTYPE(CK_ULONG, *argtypes)(address)
        arguments = CK_C_INITIALIZE_ARGS(flags=CKF_OS_LOCKING_OK)
        rv = self._functions["C_Initialize"](byref(arguments))
        if rv not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
            raise CryptokiError("C_Initialize", rv)

    def call(
        self, name: str, *arguments: object, ok: Tuple[int, ...] = (CKR_OK,)
    ) -> int:
        rv = self._functions[name](*arguments)
        if rv not in ok:
            raise CryptokiError(name, rv)
        return rv

    # ------------------------------------------------------------ helpers

    def slots(self) -> List[int]:
        count = CK_ULONG()
        self.call("C_GetSlotList", 1, None, byref(count))
        slots = (CK_ULONG * max(count.value, 1))()
        self.call("C_GetSlotList", 1, slots, byref(count))
        return list(slots[: count.value])

    def token_info(self, slot: int) -> CK_TOKEN_INFO:
        info = CK_TOKEN_INFO()
        self.call("C_GetTokenInfo", slot, byref(info))
        return info

    def mechanisms(self, slot: int) -> List[int]:
        count = CK_ULONG()
        self.call("C_GetMechanismList", slot, None, byref(count))
        found = (CK_ULONG * max(count.value, 1))()
        self.call("C_GetMechanismList", slot, found, byref(count))
        return list(found[: count.value])

    def open_session(self, slot: int) -> int:
        session = CK_ULONG()
        self.call("C_OpenSession", slot, CKF_SERIAL_SESSION, None, None, byref(session))
        return session.value

    def logged_in(self, session: int) -> bool:
        """Whether the token is already logged in for this application."""
        info = CK_SESSION_INFO()
        self.call("C_GetSessionInfo", session, byref(info))
        return info.state in _LOGGED_IN_STATES

    def close_session(self, session: int) -> None:
        self._functions["C_CloseSession"](session)

    def login(self, session: int, user: int, pin: Optional[str]) -> None:
        """Log in; ``pin=None`` uses the token's own PIN pad."""
        encoded = pin.encode("utf-8") if pin is not None else None
        self.call(
            "C_Login",
            session,
            user,
            encoded,
            len(encoded) if encoded is not None else 0,
            ok=(CKR_OK, CKR_USER_ALREADY_LOGGED_IN),
        )

    def find(self, session: int, template: Dict[int, object]) -> Iterator[int]:
        attributes, _keep = _template(template)
        self.call("C_FindObjectsInit", session, attributes, len(template))
        try:
            batch = (CK_ULONG * 32)()
            count = CK_ULONG()
            while True:
                self.call("C_FindObjects", session, batch, len(batch), byref(count))
                if not count.value:
                    return
                yield from list(batch[: count.value])
        finally:
            self._functions["C_FindObjectsFinal"](session)

    def attribute(self, session: int, handle: int, kind: int) -> Optional[bytes]:
        """One attribute's raw bytes, or ``None`` when the token will not say."""
        attribute = CK_ATTRIBUTE(kind, None, 0)
        rv = self._functions["C_GetAttributeValue"](
            session, handle, byref(attribute), 1
        )
        if rv != CKR_OK or attribute.ulValueLen == _UNAVAILABLE:
            return None
        buffer = ctypes.create_string_buffer(attribute.ulValueLen)
        attribute.pValue = ctypes.cast(buffer, c_void_p)
        self.call("C_GetAttributeValue", session, handle, byref(attribute), 1)
        return buffer.raw[: attribute.ulValueLen]


def _template(values: Dict[int, object]) -> Tuple[object, List[object]]:
    """A CK_ATTRIBUTE array for ``values`` (ints become CK_ULONG, bytes stay)."""
    attributes = (CK_ATTRIBUTE * len(values))()
    keep: List[object] = []
    for slot, (kind, value) in zip(attributes, values.items()):
        if isinstance(value, bool):
            data: object = ctypes.c_ubyte(int(value))
        elif isinstance(value, int):
            data = CK_ULONG(value)
        else:
            data = ctypes.create_string_buffer(bytes(value), len(value))  # type: ignore[arg-type]
        keep.append(data)
        slot.type = kind
        slot.pValue = ctypes.cast(ctypes.pointer(data), c_void_p)  # type: ignore[arg-type]
        slot.ulValueLen = ctypes.sizeof(data)  # type: ignore[arg-type]
    return attributes, keep


def ulong(data: Optional[bytes]) -> Optional[int]:
    """A CK_ULONG or CK_BBOOL attribute value."""
    if data is None:
        return None
    return int.from_bytes(data, sys.byteorder)


def text(field: "ctypes.Array[c_ubyte]") -> str:
    """A blank-padded Cryptoki string field."""
    return bytes(field).decode("utf-8", "replace").rstrip(" \0")


_modules: Dict[str, Module] = {}
_modules_lock = threading.Lock()


def load_module(path: str) -> Module:
    """The process-wide :class:`Module` for ``path``, loaded on first use."""
    with _modules_lock:
        module = _modules.get(path)
        if module is None:
            module = _modules[path] = Module(path)
        return module
