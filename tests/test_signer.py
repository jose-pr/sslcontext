"""Identities whose private key is reached only through a Signer."""

from __future__ import annotations

import gc
import logging
import ssl
import subprocess
import sys
import textwrap
import weakref

import pytest

import sslcontext
from conftest import DATA, TLSServer, data, needs_client_sigalgs, needs_tls13
from sslcontext.testing import SoftwareSigner, software_identity

TLS12, TLS13 = ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3


def identity(name: str) -> sslcontext.Identity:
    return software_identity(data(f"{name}.pem"), data(f"{name}.key"))


@needs_tls13
def test_rsa_over_tls13_signs_with_pss(tls_server, client_context):
    client_context.minimum_version = TLS13
    ident = identity("client-rsa")
    sslcontext.load_identity(client_context, ident)
    seen = tls_server.handshake(client_context)
    assert seen == ("client-rsa", "TLSv1.3")
    hash_name, padding, salt = ident.signer.calls[-1]
    assert padding is sslcontext.Padding.PSS
    assert salt == {"sha256": 32, "sha384": 48, "sha512": 64}[hash_name]


@needs_client_sigalgs
def test_rsa_over_tls12_signs_with_pkcs1_when_the_server_asks(client_context):
    client_context.maximum_version = TLS12
    ident = identity("client-rsa")
    sslcontext.load_identity(client_context, ident)
    with TLSServer(client_sigalgs="RSA+SHA256") as server:
        assert server.handshake(client_context) == ("client-rsa", "TLSv1.2")
    assert ident.signer.calls[-1] == ("sha256", sslcontext.Padding.PKCS1V15, None)


@pytest.mark.parametrize("version", [TLS12, pytest.param(TLS13, marks=needs_tls13)])
def test_ec_signs_ecdsa(tls_server, client_context, version):
    client_context.minimum_version = client_context.maximum_version = version
    ident = identity("client-ec")
    sslcontext.load_identity(client_context, ident)
    assert tls_server.handshake(client_context).client_cn == "client-ec"
    hash_name, padding, salt = ident.signer.calls[-1]
    assert (padding, salt) == (None, None)
    # TLS 1.3 fixes P-256 to SHA-256; over 1.2 the client picks among the server's.
    assert hash_name in (
        ("sha256",) if version is TLS13 else ("sha256", "sha384", "sha512")
    )


def test_rsa_and_ec_identities_coexist(tls_server, client_context):
    sslcontext.load_identity(client_context, identity("client-rsa"))
    sslcontext.load_identity(client_context, identity("client-ec"))
    assert tls_server.handshake(client_context).client_cn in ("client-rsa", "client-ec")


def test_ordinary_keys_keep_working_beside_signer_keys(tls_server, client_context):
    sslcontext.load_identity(client_context, identity("client-ec"))
    other = ssl.create_default_context(cafile=str(DATA / "ca.pem"))
    sslcontext.load_pem(other, data("client-rsa.pem"), data("client-rsa.key"))
    assert tls_server.handshake(other).client_cn == "client-rsa"
    assert tls_server.handshake(client_context).client_cn == "client-ec"


class _FailingSigner:
    def sign(self, digest, *, hash, padding=None, salt_length=None):
        raise RuntimeError("card removed")


def test_a_failing_signer_fails_the_handshake_and_is_logged(
    tls_server, client_context, caplog
):
    sslcontext.load_identity(
        client_context,
        sslcontext.Identity(data_der("client-ec.pem"), _FailingSigner()),
    )
    with caplog.at_level(logging.WARNING, logger="sslcontext"):
        with pytest.raises((ssl.SSLError, ConnectionError)):
            tls_server.handshake(client_context)
    assert "card removed" in caplog.text


def test_a_signer_for_another_key_is_rejected_by_the_server(tls_server, client_context):
    wrong = SoftwareSigner(data("server.key"))
    sslcontext.load_identity(
        client_context, sslcontext.Identity(data_der("client-rsa.pem"), wrong)
    )
    with pytest.raises((ssl.SSLError, ConnectionError)):
        tls_server.handshake(client_context)


def test_the_signer_is_released_with_its_context():
    context = ssl.create_default_context()
    ident = identity("client-ec")
    signer = weakref.ref(ident.signer)
    sslcontext.load_identity(context, ident)
    del ident
    gc.collect()
    assert signer() is not None
    del context
    gc.collect()
    assert signer() is None


def test_identity_rejects_wrong_types():
    with pytest.raises(TypeError):
        sslcontext.Identity("not bytes", SoftwareSigner(data("client-ec.key")))
    with pytest.raises(TypeError):
        sslcontext.Identity(b"der", object())
    with pytest.raises(TypeError):
        sslcontext.load_identity(ssl.create_default_context(), "identity")


def test_the_interpreter_exits_cleanly_after_signing():
    """OpenSSL's exit-time cleanup must never call back into Python."""
    source = f"""
        import ssl, sys
        sys.path.insert(0, {str(DATA.parent)!r})
        import sslcontext
        from sslcontext.testing import software_identity
        d = {str(DATA)!r}
        server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=d + "/ca.pem")
        server.verify_mode = ssl.CERT_REQUIRED
        server.load_cert_chain(d + "/server.pem", d + "/server.key")
        client = ssl.create_default_context(cafile=d + "/ca.pem")
        ident = software_identity(open(d + "/client-rsa.pem", "rb").read(),
                                  open(d + "/client-rsa.key", "rb").read())
        sslcontext.load_identity(client, ident)
        bios = [ssl.MemoryBIO() for _ in range(4)]
        c = client.wrap_bio(bios[0], bios[1], server_hostname="localhost")
        s = server.wrap_bio(bios[2], bios[3], server_side=True)
        for _ in range(20):
            for end in (c, s):
                try:
                    end.do_handshake()
                except ssl.SSLWantReadError:
                    pass
            bios[2].write(bios[1].read())
            bios[0].write(bios[3].read())
        assert s.getpeercert()["subject"][0][0][1] == "client-rsa"
        print("ok")
        """
    script = textwrap.dedent(source)
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def data_der(name: str) -> bytes:
    return software_identity(data(name), data("client-ec.key")).certificate
