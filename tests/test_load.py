from __future__ import annotations

import ssl

import pytest

import sslcontext
from conftest import data, needs_tls13


@pytest.mark.parametrize(
    "version",
    [ssl.TLSVersion.TLSv1_2, pytest.param(ssl.TLSVersion.TLSv1_3, marks=needs_tls13)],
)
@pytest.mark.parametrize("name", ["client-rsa", "client-ec"])
def test_load_pem_authenticates_the_client(tls_server, client_context, name, version):
    client_context.maximum_version = version
    sslcontext.load_pem(client_context, data(f"{name}.pem"), data(f"{name}.key"))
    seen = tls_server.handshake(client_context)
    assert seen.client_cn == name
    assert seen.version == {"TLSv1_2": "TLSv1.2", "TLSv1_3": "TLSv1.3"}[version.name]


def test_load_pem_accepts_text_and_a_combined_bundle(tls_server, client_context):
    bundle = (data("client-rsa.pem") + data("client-rsa.key")).decode()
    sslcontext.load_pem(client_context, bundle)
    assert tls_server.handshake(client_context).client_cn == "client-rsa"


def test_load_pem_decrypts_an_encrypted_key(tls_server, client_context):
    sslcontext.load_pem(
        client_context,
        data("client-ec.pem"),
        data("client-ec.enc.key"),
        password="test",
    )
    assert tls_server.handshake(client_context).client_cn == "client-ec"


def test_load_pem_rejects_a_wrong_password(client_context):
    with pytest.raises(sslcontext.CredentialError):
        sslcontext.load_pem(
            client_context,
            data("client-ec.pem"),
            data("client-ec.enc.key"),
            password="no",
        )


def test_load_pem_rejects_an_encrypted_key_without_password(client_context):
    with pytest.raises(sslcontext.CredentialError):
        sslcontext.load_pem(
            client_context, data("client-ec.pem"), data("client-ec.enc.key")
        )


def test_load_pem_rejects_a_key_for_another_certificate(client_context):
    with pytest.raises(sslcontext.CredentialError, match="does not match"):
        sslcontext.load_pem(client_context, data("client-rsa.pem"), data("server.key"))


def test_load_pem_rejects_garbage(client_context):
    with pytest.raises(sslcontext.CredentialError):
        sslcontext.load_pem(
            client_context, b"not a certificate", data("client-rsa.key")
        )


def test_load_pkcs12_authenticates_the_client(tls_server, client_context):
    sslcontext.load_pkcs12(client_context, data("client-rsa.p12"), password="test")
    assert tls_server.handshake(client_context).client_cn == "client-rsa"


def test_load_pkcs12_rejects_a_wrong_password(client_context):
    with pytest.raises(sslcontext.CredentialError, match="wrong password"):
        sslcontext.load_pkcs12(client_context, data("client-rsa.p12"), password="no")


def test_without_an_identity_the_server_refuses(tls_server, client_context):
    with pytest.raises((ssl.SSLError, ConnectionError)):
        tls_server.handshake(client_context)


def test_a_non_context_argument_is_a_type_error():
    with pytest.raises(TypeError):
        sslcontext.load_pem(object(), data("client-rsa.pem"), data("client-rsa.key"))
