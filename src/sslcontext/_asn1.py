"""The few DER encodings sslcontext needs: ECDSA signatures, RSA DigestInfo,
and a certificate's key usages."""

from __future__ import annotations

__all__ = [
    "ANY_EXTENDED_KEY_USAGE",
    "CLIENT_AUTH",
    "DIGEST_INFO_PREFIX",
    "certificate_usages",
    "ecdsa_der",
]

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


_EXTENDED_KEY_USAGE = bytes.fromhex("551d25")  # 2.5.29.37
_KEY_USAGE = bytes.fromhex("551d0f")  # 2.5.29.15
CLIENT_AUTH = bytes.fromhex("2b06010505070302")  # 1.3.6.1.5.5.7.3.2
ANY_EXTENDED_KEY_USAGE = bytes.fromhex("551d2500")  # 2.5.29.37.0


def _element(data: bytes, offset: int) -> tuple:
    """``(tag, content start, content end)`` of the DER element at ``offset``."""
    tag = data[offset]
    size = data[offset + 1]
    start = offset + 2
    if size & 0x80:
        count = size & 0x7F
        size = int.from_bytes(data[start : start + count], "big")
        start += count
    end = start + size
    if end > len(data):
        raise ValueError("truncated DER")
    return tag, start, end


def _children(data: bytes, start: int, end: int) -> list:
    out = []
    while start < end:
        element = _element(data, start)
        out.append(element)
        start = element[2]
    return out


def certificate_usages(der: bytes) -> tuple:
    """``(extended_key_usages, key_usage)`` of a DER certificate.

    ``extended_key_usages`` is a frozenset of DER OID bodies, ``None`` when the
    extension is absent; ``key_usage`` is the bits as OpenSSL numbers them
    (``0x80`` digitalSignature in the first octet), ``None`` when absent.
    """
    _, start, end = _element(der, 0)
    _, start, end = _children(der, start, end)[0]  # tbsCertificate
    extended, usage = None, None
    for tag, inner_start, inner_end in _children(der, start, end):
        if tag != 0xA3:  # [3] extensions
            continue
        _, list_start, list_end = _element(der, inner_start)
        for _, ext_start, ext_end in _children(der, list_start, list_end):
            parts = _children(der, ext_start, ext_end)
            oid = der[parts[0][1] : parts[0][2]]
            _, value_start, value_end = parts[-1]  # OCTET STRING
            if oid == _EXTENDED_KEY_USAGE:
                _, seq_start, seq_end = _element(der, value_start)
                extended = frozenset(
                    der[s:e] for _, s, e in _children(der, seq_start, seq_end)
                )
            elif oid == _KEY_USAGE:
                _, bits_start, bits_end = _element(der, value_start)
                octets = der[bits_start + 1 : bits_end]  # after the unused-bits count
                usage = sum(octet << (8 * i) for i, octet in enumerate(octets[:2]))
    return extended, usage
