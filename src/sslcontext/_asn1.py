"""The few DER encodings keystores need: ECDSA signatures and RSA DigestInfo."""

from __future__ import annotations

__all__ = ["DIGEST_INFO_PREFIX", "ecdsa_der"]

# RFC 8017 section 9.2, note 1: DER of DigestInfo up to the digest bytes.
DIGEST_INFO_PREFIX = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha224": bytes.fromhex("302d300d06096086480165030402040500041c"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def _length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _integer(value: bytes) -> bytes:
    value = value.lstrip(b"\0") or b"\0"
    if value[0] & 0x80:
        value = b"\0" + value
    return b"\x02" + _length(len(value)) + value


def ecdsa_der(raw: bytes) -> bytes:
    """A raw ``r || s`` ECDSA signature (CNG, PKCS#11) as DER ``SEQUENCE {r, s}``."""
    if not raw or len(raw) % 2:
        raise ValueError(f"raw ECDSA signature has odd length {len(raw)}")
    half = len(raw) // 2
    body = _integer(raw[:half]) + _integer(raw[half:])
    return b"\x30" + _length(len(body)) + body
