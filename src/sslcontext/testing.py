"""Test helpers: a :class:`Signer` over an in-memory key.

:class:`SoftwareSigner` holds an ordinary private key and signs with
OpenSSL, through the same :class:`Signer` contract a keystore backend
implements. It exercises the whole keystore path without a keystore, and it
is the reference for what a backend's ``sign`` must return.
"""

from __future__ import annotations

import ctypes
import threading
from typing import List, Optional, Tuple

from ._identity import Identity, Padding
from ._load import BytesOrText, _as_bytes, read_key_with
from ._pin import PasswordSource
from ._openssl import openssl
from ._openssl._errors import drain_errors
from ._openssl._objects import certificate_der, read_certificates
from .exceptions import SigningError

__all__ = ["SoftwareSigner", "software_identity"]

# evp.h / rsa.h control commands, valid on OpenSSL 1.1.1 and 3.x alike.
_EVP_PKEY_RSA = 6
_EVP_PKEY_CTRL_MD = 1
_EVP_PKEY_CTRL_RSA_PADDING = 0x1001
_EVP_PKEY_CTRL_RSA_PSS_SALTLEN = 0x1002
_EVP_PKEY_CTRL_RSA_MGF1_MD = 0x1005
_PADDING_CODES = {Padding.PKCS1V15: 1, Padding.PSS: 6}


class SoftwareSigner:
    """Signs with a PEM or DER private key held in memory.

    ``calls`` records ``(hash, padding, salt_length)`` for every signature, so
    a test can see what the TLS stack asked for.
    """

    def __init__(self, key: BytesOrText, password: PasswordSource = None) -> None:
        self._lib = openssl()
        self._key = read_key_with(self._lib, _as_bytes(key, "key"), password)
        self._lock = threading.Lock()
        self.calls: List[Tuple[str, Optional[Padding], Optional[int]]] = []

    def __del__(self) -> None:
        key, self._key = getattr(self, "_key", None), None
        if key:
            self._lib.EVP_PKEY_free(key)

    def __repr__(self) -> str:
        return f"<SoftwareSigner {self._lib.EVP_PKEY_bits(self._key)}-bit>"

    def sign(
        self,
        digest: bytes,
        *,
        hash: str,
        padding: Optional[Padding] = None,
        salt_length: Optional[int] = None,
    ) -> bytes:
        lib = self._lib
        with self._lock:
            self.calls.append((hash, padding, salt_length))
            context = lib.EVP_PKEY_CTX_new(self._key, None)
            if not context:
                raise SigningError(drain_errors(lib))
            try:
                md = lib.EVP_get_digestbyname(hash.encode())
                if not md:
                    raise SigningError(f"unknown digest {hash!r}")
                ok = lib.EVP_PKEY_sign_init(context) == 1
                ok = (
                    ok
                    and lib.EVP_PKEY_CTX_ctrl(context, -1, -1, _EVP_PKEY_CTRL_MD, 0, md)
                    > 0
                )
                if padding is not None:
                    ok = (
                        ok
                        and lib.EVP_PKEY_CTX_ctrl(
                            context,
                            _EVP_PKEY_RSA,
                            -1,
                            _EVP_PKEY_CTRL_RSA_PADDING,
                            _PADDING_CODES[padding],
                            None,
                        )
                        > 0
                    )
                if padding is Padding.PSS:
                    ok = (
                        ok
                        and lib.EVP_PKEY_CTX_ctrl(
                            context,
                            _EVP_PKEY_RSA,
                            -1,
                            _EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
                            salt_length,
                            None,
                        )
                        > 0
                    )
                    ok = (
                        ok
                        and lib.EVP_PKEY_CTX_ctrl(
                            context,
                            _EVP_PKEY_RSA,
                            -1,
                            _EVP_PKEY_CTRL_RSA_MGF1_MD,
                            0,
                            md,
                        )
                        > 0
                    )
                size = ctypes.c_size_t(0)
                ok = (
                    ok
                    and lib.EVP_PKEY_sign(
                        context, None, ctypes.byref(size), digest, len(digest)
                    )
                    == 1
                )
                buffer = ctypes.create_string_buffer(size.value)
                ok = (
                    ok
                    and lib.EVP_PKEY_sign(
                        context, buffer, ctypes.byref(size), digest, len(digest)
                    )
                    == 1
                )
                if not ok:
                    raise SigningError(f"signing failed: {drain_errors(lib)}")
                return buffer.raw[: size.value]
            finally:
                lib.EVP_PKEY_CTX_free(context)


def software_identity(
    certificate: BytesOrText,
    key: BytesOrText,
    password: PasswordSource = None,
) -> Identity:
    """An :class:`Identity` for a PEM certificate (+ chain) and an in-memory key."""
    lib = openssl()
    pointers = read_certificates(lib, _as_bytes(certificate, "certificate"))
    try:
        ders = [certificate_der(lib, pointer) for pointer in pointers]
    finally:
        for pointer in pointers:
            lib.X509_free(pointer)
    return Identity(ders[0], SoftwareSigner(key, password), tuple(ders[1:]), "software")
