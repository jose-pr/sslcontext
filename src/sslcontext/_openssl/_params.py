"""``OSSL_PARAM`` arrays: the structure, readers, and static descriptor lists."""

from __future__ import annotations

import ctypes
from ctypes import c_char_p, c_size_t, c_uint, c_void_p
from typing import Iterable

__all__ = [
    "OSSL_PARAM",
    "PARAM_INTEGER",
    "PARAM_OCTET_STRING",
    "PARAM_UNSIGNED_INTEGER",
    "PARAM_UTF8_STRING",
    "descriptor_list",
    "iter_params",
    "read_int",
    "read_text",
    "read_uint",
    "write_int",
    "write_text",
]

# core.h
PARAM_INTEGER = 1
PARAM_UNSIGNED_INTEGER = 2
PARAM_UTF8_STRING = 4
PARAM_OCTET_STRING = 5
PARAM_UTF8_PTR = 6
PARAM_OCTET_PTR = 7
_UNMODIFIED = ctypes.c_size_t(-1).value


class OSSL_PARAM(ctypes.Structure):
    _fields_ = [
        ("key", c_char_p),
        ("data_type", c_uint),
        ("data", c_void_p),
        ("data_size", c_size_t),
        ("return_size", c_size_t),
    ]


def iter_params(address: int | None) -> Iterable[OSSL_PARAM]:
    """Walk a NULL-key-terminated ``OSSL_PARAM`` array in place."""
    if not address:
        return
    size = ctypes.sizeof(OSSL_PARAM)
    while True:
        param = OSSL_PARAM.from_address(address)
        if param.key is None:
            return
        yield param
        address += size


def read_int(param: OSSL_PARAM) -> int:
    """A native-endian (un)signed integer parameter."""
    if param.data_type not in (PARAM_INTEGER, PARAM_UNSIGNED_INTEGER):
        raise TypeError(f"{param.key!r} is not an integer")
    raw = ctypes.string_at(param.data, param.data_size)
    return int.from_bytes(raw, _byteorder(), signed=param.data_type == PARAM_INTEGER)


read_uint = read_int


def read_text(param: OSSL_PARAM) -> str:
    """A UTF-8 string parameter, by value or by pointer."""
    if param.data_type == PARAM_UTF8_STRING:
        return ctypes.string_at(param.data, param.data_size).split(b"\0", 1)[0].decode()
    if param.data_type == PARAM_UTF8_PTR:
        return ctypes.cast(
            ctypes.c_void_p.from_address(param.data).value, c_char_p
        ).value.decode()
    raise TypeError(f"{param.key!r} is not a string")


def write_int(param: OSSL_PARAM, value: int) -> bool:
    """Store ``value`` into an integer parameter the caller sized."""
    if param.data_type not in (PARAM_INTEGER, PARAM_UNSIGNED_INTEGER):
        return False
    size = param.data_size
    if param.data:
        ctypes.memmove(
            param.data,
            value.to_bytes(size, _byteorder(), signed=param.data_type == PARAM_INTEGER),
            size,
        )
    param.return_size = size
    return True


def write_text(param: OSSL_PARAM, value: str) -> bool:
    """Store ``value`` into a UTF-8 string parameter (NUL-terminated if room)."""
    if param.data_type != PARAM_UTF8_STRING:
        return False
    encoded = value.encode()
    param.return_size = len(encoded)
    if param.data:
        if param.data_size < len(encoded):
            return False
        ctypes.memmove(param.data, encoded, len(encoded))
        if param.data_size > len(encoded):
            ctypes.memset(param.data + len(encoded), 0, 1)
    return True


def _byteorder() -> str:
    import sys

    return sys.byteorder


class _DescriptorList:
    """A static ``OSSL_PARAM`` array naming parameters and their types.

    The instance keeps the key strings alive for as long as OpenSSL may read
    them, which is the life of the process.
    """

    def __init__(self, entries: Iterable[tuple[bytes, int]]) -> None:
        entries = list(entries)
        self._keys = [key for key, _ in entries]
        self.array = (OSSL_PARAM * (len(entries) + 1))()
        for slot, (key, kind) in zip(self.array, entries):
            slot.key = key
            slot.data_type = kind
            slot.return_size = _UNMODIFIED
        self.address = ctypes.addressof(self.array)


def descriptor_list(*entries: tuple[bytes, int]) -> _DescriptorList:
    return _DescriptorList(entries)
