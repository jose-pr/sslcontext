"""Typed access to the interpreter's libssl and libcrypto.

Every function this package calls is declared once in ``_SIGNATURES``; an
attribute lookup on :class:`OpenSSL` binds it with that signature. A name
missing from the table is a programming error, not a fallback to ctypes'
guess of ``int`` arguments.
"""

from __future__ import annotations

import ctypes
import ssl
import threading
from ctypes import (
    POINTER,
    c_char_p,
    c_int,
    c_long,
    c_size_t,
    c_uint64,
    c_ulong,
    c_void_p,
)
from typing import Any

from ._loader import find_libraries

__all__ = ["OpenSSL", "openssl"]

_P = c_void_p
_PP = POINTER(c_void_p)

# name: (library, restype, argtypes)
_SIGNATURES: dict[str, tuple[str, Any, tuple[Any, ...]]] = {
    # errors
    "ERR_get_error": ("crypto", c_ulong, ()),
    "ERR_error_string_n": ("crypto", None, (c_ulong, c_char_p, c_size_t)),
    "ERR_clear_error": ("crypto", None, ()),
    # memory BIOs and decoding
    "BIO_new_mem_buf": ("crypto", _P, (c_char_p, c_int)),
    "BIO_free": ("crypto", c_int, (_P,)),
    "PEM_read_bio_X509": ("crypto", _P, (_P, _P, _P, _P)),
    "PEM_read_bio_PrivateKey": ("crypto", _P, (_P, _P, _P, c_char_p)),
    "d2i_X509_bio": ("crypto", _P, (_P, _P)),
    "d2i_PrivateKey_bio": ("crypto", _P, (_P, _P)),
    "d2i_PKCS12_bio": ("crypto", _P, (_P, _P)),
    "i2d_X509": ("crypto", c_int, (_P, _PP)),
    "CRYPTO_free": ("crypto", None, (_P, c_char_p, c_int)),
    "PKCS12_parse": ("crypto", c_int, (_P, c_char_p, _PP, _PP, _PP)),
    "PKCS12_free": ("crypto", None, (_P,)),
    "OPENSSL_sk_num": ("crypto", c_int, (_P,)),
    "OPENSSL_sk_value": ("crypto", _P, (_P, c_int)),
    "OPENSSL_sk_free": ("crypto", None, (_P,)),
    # certificate fields
    "BIO_new": ("crypto", _P, (_P,)),
    "BIO_s_mem": ("crypto", _P, ()),
    "BIO_ctrl": ("crypto", c_long, (_P, c_int, c_long, _P)),
    "X509_NAME_print_ex": ("crypto", c_int, (_P, _P, c_int, c_ulong)),
    "X509_get_subject_name": ("crypto", _P, (_P,)),
    "X509_get_issuer_name": ("crypto", _P, (_P,)),
    "X509_get_serialNumber": ("crypto", _P, (_P,)),
    "X509_get0_notBefore": ("crypto", _P, (_P,)),
    "X509_get0_notAfter": ("crypto", _P, (_P,)),
    "ASN1_TIME_to_tm": ("crypto", c_int, (_P, _P)),
    "ASN1_INTEGER_to_BN": ("crypto", _P, (_P, _P)),
    "BN_bn2hex": ("crypto", _P, (_P,)),
    "BN_free": ("crypto", None, (_P,)),
    # objects
    "X509_free": ("crypto", None, (_P,)),
    "X509_get_pubkey": ("crypto", _P, (_P,)),
    "EVP_PKEY_free": ("crypto", None, (_P,)),
    "EVP_PKEY_id": ("crypto", c_int, (_P,)),
    "EVP_PKEY_bits": ("crypto", c_int, (_P,)),
    "EVP_PKEY_size": ("crypto", c_int, (_P,)),
    "EVP_PKEY_eq": ("crypto", c_int, (_P, _P)),
    "EVP_PKEY_get_params": ("crypto", c_int, (_P, _P)),
    "EVP_PKEY_todata": ("crypto", c_int, (_P, c_int, _PP)),
    "OSSL_PARAM_free": ("crypto", None, (_P,)),
    # signing with an ordinary key (sslcontext.testing)
    "EVP_get_digestbyname": ("crypto", _P, (c_char_p,)),
    "EVP_PKEY_CTX_new": ("crypto", _P, (_P, _P)),
    "EVP_PKEY_CTX_free": ("crypto", None, (_P,)),
    "EVP_PKEY_CTX_ctrl": ("crypto", c_int, (_P, c_int, c_int, c_int, c_int, _P)),
    "EVP_PKEY_sign_init": ("crypto", c_int, (_P,)),
    "EVP_PKEY_sign": (
        "crypto",
        c_int,
        (_P, c_char_p, POINTER(c_size_t), c_char_p, c_size_t),
    ),
    # engines (OpenSSL 1.1)
    "ENGINE_new": ("crypto", _P, ()),
    "ENGINE_set_id": ("crypto", c_int, (_P, c_char_p)),
    "ENGINE_set_name": ("crypto", c_int, (_P, c_char_p)),
    "ENGINE_set_pkey_meths": ("crypto", c_int, (_P, _P)),
    "EVP_PKEY_meth_find": ("crypto", _P, (c_int,)),
    "EVP_PKEY_meth_new": ("crypto", _P, (c_int, c_int)),
    "EVP_PKEY_meth_copy": ("crypto", None, (_P, _P)),
    "EVP_PKEY_meth_get_sign": ("crypto", None, (_P, _PP, _PP)),
    "EVP_PKEY_meth_set_sign": ("crypto", None, (_P, _P, _P)),
    "EVP_PKEY_set1_engine": ("crypto", c_int, (_P, _P)),
    "EVP_PKEY_CTX_get0_pkey": ("crypto", _P, (_P,)),
    "EVP_MD_type": ("crypto", c_int, (_P,)),
    "OBJ_nid2sn": ("crypto", c_char_p, (c_int,)),
    "i2d_PUBKEY": ("crypto", c_int, (_P, _PP)),
    "d2i_PUBKEY": ("crypto", _P, (_P, _PP, c_long)),
    # providers (OpenSSL 3)
    "OSSL_PROVIDER_available": ("crypto", c_int, (_P, c_char_p)),
    "OSSL_PROVIDER_add_builtin": ("crypto", c_int, (_P, c_char_p, _P)),
    "OSSL_PROVIDER_load": ("crypto", _P, (_P, c_char_p)),
    "EVP_PKEY_CTX_new_from_name": ("crypto", _P, (_P, c_char_p, c_char_p)),
    "EVP_PKEY_fromdata_init": ("crypto", c_int, (_P,)),
    "EVP_PKEY_fromdata": ("crypto", c_int, (_P, _PP, c_int, _P)),
    # contexts
    "SSL_CTX_get_verify_mode": ("ssl", c_int, (_P,)),
    "SSL_CTX_use_certificate": ("ssl", c_int, (_P, _P)),
    "SSL_CTX_use_PrivateKey": ("ssl", c_int, (_P, _P)),
    "SSL_CTX_check_private_key": ("ssl", c_int, (_P,)),
    "SSL_CTX_ctrl": ("ssl", c_long, (_P, c_int, c_long, _P)),
}


# OpenSSL 3 exports these under new names; the old ones are macros there.
_V3_SYMBOLS = {
    "EVP_PKEY_id": "EVP_PKEY_get_id",
    "EVP_PKEY_bits": "EVP_PKEY_get_bits",
    "EVP_PKEY_size": "EVP_PKEY_get_size",
}


class OpenSSL:
    """The bound libraries plus what the glue needs to know about them."""

    def __init__(self) -> None:
        self.libssl, self.libcrypto = find_libraries()
        self.version = ssl.OPENSSL_VERSION_INFO
        self.is_v3 = self.version >= (3, 0)
        # SSL_CTX_get_options returns uint64_t from 3.0, unsigned long before.
        options = self.libssl.SSL_CTX_get_options
        options.restype = c_uint64 if self.is_v3 else c_ulong
        options.argtypes = [_P]
        self.SSL_CTX_get_options = options

    def __getattr__(self, name: str) -> Any:
        try:
            library, restype, argtypes = _SIGNATURES[name]
        except KeyError:
            raise AttributeError(f"{name} is not declared in _SIGNATURES") from None
        symbol = _V3_SYMBOLS.get(name, name) if self.is_v3 else name
        function = getattr(self.libssl if library == "ssl" else self.libcrypto, symbol)
        function.restype = restype
        function.argtypes = list(argtypes)
        setattr(self, name, function)
        return function

    def address(self, name: str) -> int:
        """The raw address of an exported function, for OpenSSL to call."""
        library, _, _ = _SIGNATURES[name]
        lib = self.libssl if library == "ssl" else self.libcrypto
        return ctypes.cast(getattr(lib, name), c_void_p).value or 0


_lock = threading.Lock()
_instance: OpenSSL | None = None


def openssl() -> OpenSSL:
    """The process-wide binding, created on first use."""
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = OpenSSL()
    return _instance
