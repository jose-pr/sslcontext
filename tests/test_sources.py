from __future__ import annotations

import io
import ssl
from pathlib import Path

import pytest

import sslcontext
from conftest import DATA, data

CA = DATA / "ca.pem"


def der(name: str) -> bytes:
    return ssl.PEM_cert_to_DER_cert(data(name).decode())


class _Opener:
    """Something with open(), as pathlib-like and resource objects are."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def open(self, mode: str = "r"):
        return open(self.path, mode)


@pytest.mark.parametrize(
    "ca",
    [
        str(CA),
        CA,
        data("ca.pem"),
        data("ca.pem").decode(),
        der("ca.pem"),
        [der("ca.pem")],
        [str(CA), der("ca.pem")],
        _Opener(CA),
        io.BytesIO(data("ca.pem")),
    ],
    ids=[
        "str-path",
        "pathlike",
        "pem-bytes",
        "pem-text",
        "der",
        "der-list",
        "mixed-list",
        "opener",
        "file-object",
    ],
)
def test_every_ca_form_trusts_the_server(tls_server, ca):
    context = sslcontext.create_context(
        ca=ca, certificate=DATA / "client-ec.pem", key=DATA / "client-ec.key"
    )
    assert tls_server.handshake(context).client_cn == "client-ec"


@pytest.mark.parametrize(
    "certificate, key",
    [
        (str(DATA / "client-rsa.pem"), str(DATA / "client-rsa.key")),
        (data("client-rsa.pem").decode(), data("client-rsa.key").decode()),
        (der("client-rsa.pem"), data("client-rsa.key")),
        ([_Opener(DATA / "client-rsa.pem")], _Opener(DATA / "client-rsa.key")),
        (data("client-rsa.pem") + data("client-rsa.key"), None),
    ],
    ids=["paths", "text", "der", "openers", "combined"],
)
def test_every_certificate_and_key_form_authenticates(tls_server, certificate, key):
    context = sslcontext.create_context(ca=CA, certificate=certificate, key=key)
    assert tls_server.handshake(context).client_cn == "client-rsa"


def test_a_certificate_list_is_leaf_then_chain(tls_server):
    # The chain entry is the CA itself: the server accepts a chain it can build.
    context = sslcontext.create_context(
        ca=CA,
        certificate=[DATA / "client-ec.pem", DATA / "ca.pem"],
        key=DATA / "client-ec.key",
    )
    assert tls_server.handshake(context).client_cn == "client-ec"


def test_cryptography_objects_are_accepted(tls_server):
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    certificate = x509.load_pem_x509_certificate(data("client-ec.pem"))
    key = load_pem_private_key(data("client-ec.key"), None)
    ca = x509.load_pem_x509_certificate(data("ca.pem"))
    context = sslcontext.create_context(ca=[ca], certificate=certificate, key=key)
    assert tls_server.handshake(context).client_cn == "client-ec"


def test_pkcs12_from_a_path_and_an_opener(tls_server):
    for source in (DATA / "client-rsa.p12", str(DATA / "client-rsa.p12")):
        context = sslcontext.create_context(ca=CA)
        sslcontext.load_pkcs12(context, source, password="test")
        assert tls_server.handshake(context).client_cn == "client-rsa"


def test_the_system_context_sends_a_given_certificate(tls_server):
    context = sslcontext.system_context(
        ca=CA, certificate=DATA / "client-ec.pem", key=DATA / "client-ec.key"
    )
    assert tls_server.handshake(context).client_cn == "client-ec"


def test_a_missing_file_names_itself():
    with pytest.raises(FileNotFoundError):
        sslcontext.create_context(ca="no-such-ca.pem")


def test_wrong_uses_are_refused():
    with pytest.raises(ValueError, match="key needs its certificate"):
        sslcontext.create_context(key=DATA / "client-ec.key")
    with pytest.raises(ValueError, match="not both"):
        sslcontext.create_context(ca=CA, cadata=data("ca.pem").decode())
    with pytest.raises(ValueError, match="empty"):
        sslcontext.create_context(ca=[])
    with pytest.raises(TypeError, match="not int"):
        sslcontext.create_context(ca=42)


@pytest.mark.parametrize(
    "bundle",
    [DATA / "client-rsa.p12", str(DATA / "client-rsa.p12"), data("client-rsa.p12")],
    ids=["pathlike", "str-path", "bytes"],
)
def test_a_pkcs12_bundle_is_a_certificate(tls_server, bundle):
    context = sslcontext.create_context(ca=CA, certificate=bundle, password="test")
    assert tls_server.handshake(context).client_cn == "client-rsa"


def test_a_pkcs12_password_callback_and_the_system_context(tls_server):
    asked = []

    def password():
        asked.append(1)
        return "test"

    context = sslcontext.system_context(
        ca=CA, certificate=DATA / "client-rsa.p12", password=password
    )
    assert tls_server.handshake(context).client_cn == "client-rsa"
    assert asked == [1]


def test_pkcs12_misuse_is_refused():
    with pytest.raises(sslcontext.CredentialError, match="wrong password"):
        sslcontext.create_context(certificate=DATA / "client-rsa.p12", password="no")
    with pytest.raises(ValueError, match="PKCS#12"):
        sslcontext.create_context(
            certificate=DATA / "client-rsa.p12", key=DATA / "client-rsa.key"
        )
    with pytest.raises(ValueError, match="PKCS#12"):
        sslcontext.create_context(
            certificate=[DATA / "client-rsa.p12", DATA / "ca.pem"], password="test"
        )


def test_an_encrypted_der_key_takes_the_password(tls_server):
    context = sslcontext.create_context(
        ca=CA,
        certificate=DATA / "client-ec.pem",
        key=DATA / "client-ec.enc.der",
        password="test",
    )
    assert tls_server.handshake(context).client_cn == "client-ec"
    for wrong in (None, "no"):
        with pytest.raises(sslcontext.CredentialError):
            sslcontext.create_context(
                certificate=DATA / "client-ec.pem",
                key=DATA / "client-ec.enc.der",
                password=wrong,
            )


def test_a_plain_der_key_never_asks_for_a_password(tls_server):
    context = sslcontext.create_context(
        ca=CA,
        certificate=DATA / "client-ec.pem",
        key=DATA / "client-ec.der",
        password=lambda: pytest.fail("asked for a password"),
    )
    assert tls_server.handshake(context).client_cn == "client-ec"


class _Reader:
    def __init__(self, data):
        self.data = data
        self.reads = 0

    def read(self):
        self.reads += 1
        return self.data


@pytest.mark.parametrize(
    "make",
    [
        lambda tmp: tmp / "pw.txt",
        lambda tmp: str(tmp / "pw.txt"),
        lambda tmp: _Opener(tmp / "pw.txt"),
        lambda tmp: _Reader(b"test\r\nsecond line ignored\n"),
        lambda tmp: b"test",
        lambda tmp: bytearray(b"test"),
    ],
    ids=["pathlike", "str-is-the-password", "opener", "reader", "bytes", "bytearray"],
)
def test_passwords_from_values_and_files(tls_server, tmp_path, make):
    (tmp_path / "pw.txt").write_bytes(b"test\n")
    source = make(tmp_path)
    if isinstance(source, str):  # a str is always the password itself
        with pytest.raises(sslcontext.CredentialError):
            sslcontext.create_context(
                certificate=DATA / "client-rsa.p12", password=source
            )
        return
    for certificate, key in (
        (DATA / "client-rsa.p12", None),
        (DATA / "client-ec.pem", DATA / "client-ec.enc.der"),
        (DATA / "client-ec.pem", DATA / "client-ec.enc.key"),
    ):
        context = sslcontext.create_context(
            ca=CA, certificate=certificate, key=key, password=source
        )
        assert tls_server.handshake(context).client_cn in ("client-rsa", "client-ec")


def test_a_password_file_is_read_only_when_needed():
    reader = _Reader(b"test")
    sslcontext.create_context(
        certificate=DATA / "client-ec.pem", key=DATA / "client-ec.key", password=reader
    )
    assert reader.reads == 0
    sslcontext.create_context(
        certificate=DATA / "client-ec.pem",
        key=DATA / "client-ec.enc.key",
        password=reader,
    )
    assert reader.reads == 1
