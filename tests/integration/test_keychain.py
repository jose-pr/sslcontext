"""The keychain backend against a real, temporary macOS keychain.

Each test module run creates a keychain file under pytest's temporary
directory, imports the test identities into it (any application may use
their keys, so nothing prompts), and deletes it afterwards. The user's own
keychains and search list are never touched.
"""

from __future__ import annotations

import shutil
import ssl
import subprocess
import sys
from typing import Iterator

import pytest

import sslcontext
from conftest import DATA, TOP_VERSION, TLSServer
from sslcontext.backends import KeychainBackend

pytestmark = pytest.mark.integration

if sys.platform != "darwin" or not shutil.which("security"):
    pytest.skip("needs macOS and its security tool", allow_module_level=True)

PASSWORD = "sslcontext-test"


def security(*arguments: str) -> None:
    subprocess.run(
        ["security", *arguments], check=True, capture_output=True, timeout=60
    )


@pytest.fixture(scope="module")
def keychain(tmp_path_factory) -> Iterator[str]:
    path = str(tmp_path_factory.mktemp("keychain") / "test.keychain-db")
    security("create-keychain", "-p", PASSWORD, path)
    try:
        security("unlock-keychain", "-p", PASSWORD, path)
        security("set-keychain-settings", path)  # no auto-lock during the run
        # macOS imports PKCS#12 with legacy encryption only; the system's own
        # openssl (LibreSSL) still writes that by default.
        for name in ("client-rsa", "client-ec"):
            bundle = str(tmp_path_factory.mktemp(name) / f"{name}.p12")
            subprocess.run(
                [
                    "/usr/bin/openssl", "pkcs12", "-export",
                    "-in", str(DATA / f"{name}.pem"),
                    "-inkey", str(DATA / f"{name}.key"),
                    "-out", bundle, "-passout", "pass:" + PASSWORD,
                ],
                check=True, capture_output=True, timeout=60,
            )  # fmt: skip
            security("import", bundle, "-k", path, "-P", PASSWORD, "-A")
        # Unsigned interpreters (Homebrew's) are not apple-tool:; allow them too.
        security(
            "set-key-partition-list",
            "-S",
            "apple-tool:,apple:,unsigned:",
            "-s",
            "-k",
            PASSWORD,
            path,
        )
        yield path
    finally:
        subprocess.run(["security", "delete-keychain", path], capture_output=True)


def client_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(DATA / "ca.pem"))


@pytest.mark.parametrize("name", ["client-rsa", "client-ec"])
def test_keychain_identities_authenticate(keychain, tls_server, name):
    identity = KeychainBackend(keychain).find_identity(subject=name)
    assert identity.label == name
    context = client_context()
    sslcontext.load_identity(context, identity)
    assert tls_server.handshake(context) == (name, TOP_VERSION)


def test_keys_usable_silently_never_consult_the_pin(keychain, tls_server):
    def never(request):
        raise AssertionError(f"asked for a PIN: {request}")

    identity = KeychainBackend(keychain, pin=never).find_identity(subject="client-rsa")
    assert identity.signer.supports_pss
    context = client_context()
    sslcontext.load_identity(context, identity)
    assert tls_server.handshake(context).client_cn == "client-rsa"


def test_the_selector_answers_from_the_keychain(keychain, tls_server):
    selector = sslcontext.ClientCertificateSelector(
        [KeychainBackend(keychain)],
        rules=[sslcontext.AutoSelectRule("localhost", subject={"CN": "client-ec"})],
    )
    context = client_context()
    selector.install(context)
    assert tls_server.handshake(context).client_cn == "client-ec"


def test_a_missing_keychain_is_a_keystore_error(tmp_path):
    with pytest.raises(sslcontext.KeystoreError):
        list(KeychainBackend(tmp_path / "absent.keychain-db").identities())


def test_the_trust_anchors_hold_the_system_roots():
    from sslcontext.backends._macos import anchor_certificates

    anchors = anchor_certificates()
    assert len(anchors) > 50  # macOS ships well over a hundred roots
    assert all(isinstance(der, bytes) and der[:1] == b"\x30" for der in anchors)


def test_without_truststore_the_system_context_loads_them(monkeypatch):
    from sslcontext import _system

    monkeypatch.setattr(_system, "_truststore", lambda: None)
    context = sslcontext.system_context(selector=False)
    assert type(context).__module__ == "ssl"
    assert context.cert_store_stats()["x509_ca"] > 50
