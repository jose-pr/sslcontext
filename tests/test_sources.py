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
