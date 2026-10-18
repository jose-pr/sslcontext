from __future__ import annotations

import socket
import ssl
import threading

import pytest

import sslcontext
from sslcontext.issuing import CertificateAuthority


@pytest.fixture(scope="module")
def ca() -> CertificateAuthority:
    return CertificateAuthority.create("sslcontext test issuing CA")


def handshake(server_context: ssl.SSLContext, client_context: ssl.SSLContext, name):
    """Complete a loopback handshake; return the client's TLS version."""
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    errors = []

    def serve():
        raw, _ = listener.accept()
        try:
            with server_context.wrap_socket(raw, server_side=True) as tls:
                tls.recv(1)
        except (OSError, ssl.SSLError) as error:
            errors.append(error)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with client_context.wrap_socket(raw, server_hostname=name) as tls:
                version = tls.version()
                tls.sendall(b"x")
        return version
    finally:
        thread.join(5)
        listener.close()


def trusting(ca: CertificateAuthority) -> ssl.SSLContext:
    return sslcontext.create_context(cadata=ca.certificate.decode())


@pytest.mark.parametrize("key_type", ["ec", "rsa"])
def test_issued_certificates_verify_strictly(ca, key_type):
    server = ca.server_context(["localhost", "127.0.0.1"])
    if key_type == "rsa":
        server = sslcontext.create_context("server")
        ca.issue(["localhost"], key_type="rsa").load_into(server)
    assert handshake(server, trusting(ca), "localhost") == "TLSv1.3"


def test_ip_names_are_subject_alternative_names(ca):
    server = ca.server_context(["127.0.0.1"])
    assert handshake(server, trusting(ca), "127.0.0.1") == "TLSv1.3"


def test_issued_certificate_reports_its_names_and_issuer(ca):
    issued = ca.issue(["svc.example"], days=2)
    info = issued.info
    assert info.subject == "CN=svc.example"
    assert info.issuer == ca.info.subject
    assert (info.not_after - info.not_before).days in (2, 3)


def test_name_constraints_refuse_hosts_outside_them():
    constrained = CertificateAuthority.create(
        "constrained", permitted=["*.corp.example", "10.0.0.0/8"]
    )
    inside = constrained.server_context(["api.corp.example"])
    assert handshake(inside, trusting(constrained), "api.corp.example")
    outside = constrained.server_context(["bank.example"])
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(outside, trusting(constrained), "bank.example")


def test_a_ca_round_trips_through_encrypted_pem(ca):
    pem = ca.private_key_pem(password="hunter2")
    assert b"ENCRYPTED PRIVATE KEY" in pem
    loaded = CertificateAuthority(ca.certificate, pem, password=lambda: "hunter2")
    assert loaded.info.sha256 == ca.info.sha256
    server = loaded.server_context(["localhost"])
    assert handshake(server, trusting(ca), "localhost")


def test_loading_a_key_for_another_certificate_fails(ca):
    other = CertificateAuthority.create("other")
    with pytest.raises(sslcontext.CredentialError):
        CertificateAuthority(ca.certificate, other.private_key_pem())


def test_bad_arguments():
    with pytest.raises(ValueError):
        CertificateAuthority.create("x", permitted=["re:.*"])
    with pytest.raises(ValueError):
        CertificateAuthority.create("x", key_type="dsa")
