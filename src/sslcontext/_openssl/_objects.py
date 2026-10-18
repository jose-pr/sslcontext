"""Decode certificates and keys from bytes into OpenSSL objects, and back.

Every pointer returned here is owned by the caller and must be released with
``X509_free`` or ``EVP_PKEY_free``.
"""

from __future__ import annotations

import ctypes
from typing import Iterator

from ..exceptions import CredentialError
from ._api import OpenSSL
from ._errors import drain_errors

__all__ = [
    "certificate_der",
    "certificate_fields",
    "read_certificates",
    "read_pkcs12",
    "read_private_key",
]

_PEM_CERTIFICATE = b"-----BEGIN CERTIFICATE-----"
_PEM_ANY = b"-----BEGIN "


class _MemoryBIO:
    """A read-only BIO over ``data``; keeps the bytes alive while in use."""

    def __init__(self, lib: OpenSSL, data: bytes) -> None:
        self._lib = lib
        self._data = data
        self.pointer = lib.BIO_new_mem_buf(data, len(data))
        if not self.pointer:
            raise MemoryError("BIO_new_mem_buf failed")

    def __enter__(self) -> int:
        return self.pointer

    def __exit__(self, *exc: object) -> None:
        self._lib.BIO_free(self.pointer)


def read_certificates(lib: OpenSSL, data: bytes) -> list[int]:
    """Every certificate in PEM ``data`` (in order), or the one DER certificate."""
    lib.ERR_clear_error()
    certificates: list[int] = []
    if _PEM_ANY not in data:
        with _MemoryBIO(lib, data) as bio:
            certificate = lib.d2i_X509_bio(bio, None)
        if not certificate:
            raise CredentialError(f"not a DER certificate: {drain_errors(lib)}")
        return [certificate]
    if _PEM_CERTIFICATE not in data:
        raise CredentialError("no PEM certificate found")
    with _MemoryBIO(lib, data) as bio:
        while True:
            certificate = lib.PEM_read_bio_X509(bio, None, None, None)
            if not certificate:
                break
            certificates.append(certificate)
    # Reading stops with a "no start line" error at the end of the data.
    lib.ERR_clear_error()
    return certificates


def read_private_key(lib: OpenSSL, data: bytes, password: bytes | None) -> int:
    """The private key in PEM or DER ``data``, decrypting with ``password``."""
    lib.ERR_clear_error()
    with _MemoryBIO(lib, data) as bio:
        if _PEM_ANY in data:
            # With no callback, OpenSSL takes the last argument as the passphrase;
            # an empty one fails cleanly on an encrypted key instead of prompting.
            key = lib.PEM_read_bio_PrivateKey(bio, None, None, password or b"")
        else:
            key = lib.d2i_PrivateKey_bio(bio, None)
    if not key:
        raise CredentialError(f"cannot read the private key: {drain_errors(lib)}")
    return key


def read_pkcs12(
    lib: OpenSSL, data: bytes, password: bytes | None
) -> tuple[int, int, list[int]]:
    """``(key, certificate, chain)`` from a PKCS#12 bundle."""
    lib.ERR_clear_error()
    with _MemoryBIO(lib, data) as bio:
        bundle = lib.d2i_PKCS12_bio(bio, None)
    if not bundle:
        raise CredentialError(f"not a PKCS#12 bundle: {drain_errors(lib)}")
    key, certificate, stack = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    try:
        ok = lib.PKCS12_parse(
            bundle,
            password if password is not None else None,
            ctypes.byref(key),
            ctypes.byref(certificate),
            ctypes.byref(stack),
        )
    finally:
        lib.PKCS12_free(bundle)
    if not ok:
        raise CredentialError(
            f"cannot open the PKCS#12 bundle (wrong password?): {drain_errors(lib)}"
        )
    chain = list(_drain_stack(lib, stack.value))
    if not key.value or not certificate.value:
        for pointer in (key.value, certificate.value):
            if pointer:
                (lib.EVP_PKEY_free if pointer == key.value else lib.X509_free)(pointer)
        for pointer in chain:
            lib.X509_free(pointer)
        raise CredentialError("the PKCS#12 bundle holds no key and certificate pair")
    return key.value, certificate.value, chain


def _drain_stack(lib: OpenSSL, stack: int | None) -> Iterator[int]:
    if not stack:
        return
    try:
        for index in range(lib.OPENSSL_sk_num(stack)):
            yield lib.OPENSSL_sk_value(stack, index)
    finally:
        # Frees the stack only; the certificates now belong to the caller.
        lib.OPENSSL_sk_free(stack)


def certificate_der(lib: OpenSSL, certificate: int) -> bytes:
    """DER encoding of an ``X509 *``."""
    out = ctypes.c_void_p()
    length = lib.i2d_X509(certificate, ctypes.byref(out))
    if length <= 0:
        raise CredentialError(f"cannot encode the certificate: {drain_errors(lib)}")
    try:
        return ctypes.string_at(out.value, length)
    finally:
        lib.CRYPTO_free(out.value, b"", 0)


# x509.h: XN_FLAG_RFC2253, identical in OpenSSL 1.1.1 and 3.x.
_XN_FLAG_RFC2253 = 0x1110317
_BIO_CTRL_INFO = 3


def _name_text(lib: OpenSSL, name: int) -> str:
    bio = lib.BIO_new(lib.BIO_s_mem())
    try:
        lib.X509_NAME_print_ex(bio, name, 0, _XN_FLAG_RFC2253)
        data = ctypes.c_void_p()
        size = lib.BIO_ctrl(bio, _BIO_CTRL_INFO, 0, ctypes.byref(data))
        return ctypes.string_at(data.value, size).decode("utf-8", "replace")
    finally:
        lib.BIO_free(bio)


def _time(lib: OpenSSL, asn1_time: int) -> "datetime.datetime":
    import datetime

    if lib.is_libressl:  # no ASN1_TIME_to_tm: "Mon DD HH:MM:SS YYYY GMT"
        bio = lib.BIO_new(lib.BIO_s_mem())
        try:
            if not lib.ASN1_TIME_print(bio, asn1_time):
                raise CredentialError(
                    f"unreadable certificate date: {drain_errors(lib)}"
                )
            data = ctypes.c_void_p()
            size = lib.BIO_ctrl(bio, _BIO_CTRL_INFO, 0, ctypes.byref(data))
            text = ctypes.string_at(data.value, size).decode("ascii")
        finally:
            lib.BIO_free(bio)
        return datetime.datetime.strptime(
            " ".join(text.split()), "%b %d %H:%M:%S %Y GMT"
        ).replace(tzinfo=datetime.timezone.utc)
    tm = (ctypes.c_int * 16)()  # struct tm, with room for platform extras
    if not lib.ASN1_TIME_to_tm(asn1_time, tm):
        raise CredentialError(f"unreadable certificate date: {drain_errors(lib)}")
    return datetime.datetime(
        tm[5] + 1900,
        tm[4] + 1,
        tm[3],
        tm[2],
        tm[1],
        tm[0],
        tzinfo=datetime.timezone.utc,
    )


def certificate_fields(lib: OpenSSL, der: bytes) -> dict:
    """Subject, issuer, serial, validity and key of a DER certificate."""
    import hashlib

    (certificate,) = read_certificates(lib, der)
    try:
        serial = lib.ASN1_INTEGER_to_BN(lib.X509_get_serialNumber(certificate), None)
        text = lib.BN_bn2hex(serial)
        try:
            serial_hex = ctypes.string_at(text).decode()
        finally:
            lib.CRYPTO_free(text, b"", 0)
            lib.BN_free(serial)
        public = lib.X509_get_pubkey(certificate)
        try:
            kind = {6: "rsa", 408: "ec"}.get(lib.EVP_PKEY_id(public), "other")
            bits = lib.EVP_PKEY_bits(public)
        finally:
            lib.EVP_PKEY_free(public)
        return {
            "subject": _name_text(lib, lib.X509_get_subject_name(certificate)),
            "issuer": _name_text(lib, lib.X509_get_issuer_name(certificate)),
            "serial": serial_hex,
            "not_before": _time(lib, lib.X509_get0_notBefore(certificate)),
            "not_after": _time(lib, lib.X509_get0_notAfter(certificate)),
            "sha1": hashlib.sha1(der).hexdigest().upper(),
            "sha256": hashlib.sha256(der).hexdigest().upper(),
            "key_type": kind,
            "key_bits": bits,
        }
    finally:
        lib.X509_free(certificate)
