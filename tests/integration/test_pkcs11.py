"""The pkcs11 backend against SoftHSM2 and a virtual smart card.

SoftHSM2 tests build their own token. The virtual smart card tests need a
running ``pcscd`` with vsmartcard's ``vpcd`` driver, a ``virt_cacard``
inserted into it and OpenSC; they skip when that card is absent. The
contributor guide in AGENTS.md says how to start it.
"""

from __future__ import annotations

import logging
import os
import shutil
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator, Optional

import pytest

import sslcontext
from conftest import DATA, TLSServer
from sslcontext.backends import PKCS11Backend

pytestmark = pytest.mark.integration

PIN, SO_PIN, LABEL, ALWAYS = "1234", "5678", "sslcontext", "always-auth"


def _first(*paths: str) -> Optional[str]:
    return next((p for p in paths if p and os.path.exists(p)), None)


SOFTHSM = _first(
    os.environ.get("SSLCONTEXT_TEST_SOFTHSM", ""),
    "/usr/lib64/pkcs11/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
)
OPENSC = _first(
    os.environ.get("SSLCONTEXT_TEST_OPENSC", ""),
    "/usr/lib64/pkcs11/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
    r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
)
TOOLS = all(shutil.which(t) for t in ("softhsm2-util", "pkcs11-tool", "openssl"))


def run(*command: str) -> None:
    subprocess.run(command, check=True, capture_output=True, timeout=60)


@pytest.fixture(scope="session")
def softhsm(tmp_path_factory) -> Iterator[str]:
    """A SoftHSM2 token holding the RSA and EC test clients (ids 01, 02)."""
    if not (SOFTHSM and TOOLS):
        pytest.skip("needs SoftHSM2, OpenSC's pkcs11-tool and openssl")
    root = tmp_path_factory.mktemp("softhsm")
    (root / "tokens").mkdir()
    config = root / "softhsm2.conf"
    config.write_text(f"directories.tokendir = {root / 'tokens'}\n")
    # SoftHSM reads its configuration once, at C_Initialize.
    previous = os.environ.get("SOFTHSM2_CONF")
    os.environ["SOFTHSM2_CONF"] = str(config)
    try:
        run(
            "softhsm2-util",
            "--init-token",
            "--free",
            "--label",
            LABEL,
            "--pin",
            PIN,
            "--so-pin",
            SO_PIN,
        )
        for key_id, name in (("01", "client-rsa"), ("02", "client-ec")):
            key, cert = root / f"{name}.key.der", root / f"{name}.der"
            run(
                "openssl",
                "pkey",
                "-in",
                str(DATA / f"{name}.key"),
                "-outform",
                "DER",
                "-out",
                str(key),
            )
            run(
                "openssl",
                "x509",
                "-in",
                str(DATA / f"{name}.pem"),
                "-outform",
                "DER",
                "-out",
                str(cert),
            )
            for path, kind in ((key, "privkey"), (cert, "cert")):
                run(
                    "pkcs11-tool",
                    "--module",
                    SOFTHSM,
                    "--token-label",
                    LABEL,
                    "--login",
                    "--pin",
                    PIN,
                    "--write-object",
                    str(path),
                    "--type",
                    kind,
                    "--id",
                    key_id,
                    "--label",
                    name,
                )
        # A second token whose key needs the PIN for every signature, like a
        # PIV card's signature key (slot 9C).
        run(
            "softhsm2-util",
            "--init-token",
            "--free",
            "--label",
            ALWAYS,
            "--pin",
            PIN,
            "--so-pin",
            SO_PIN,
        )
        run(
            "pkcs11-tool",
            "--module",
            SOFTHSM,
            "--token-label",
            ALWAYS,
            "--login",
            "--pin",
            PIN,
            "--write-object",
            str(root / "client-rsa.key.der"),
            "--type",
            "privkey",
            "--id",
            "01",
            "--label",
            "client-rsa",
            "--always-auth",
        )
        run(
            "pkcs11-tool",
            "--module",
            SOFTHSM,
            "--token-label",
            ALWAYS,
            "--login",
            "--pin",
            PIN,
            "--write-object",
            str(root / "client-rsa.der"),
            "--type",
            "cert",
            "--id",
            "01",
            "--label",
            "client-rsa",
        )
        yield SOFTHSM
    finally:
        if previous is None:
            os.environ.pop("SOFTHSM2_CONF", None)
        else:
            os.environ["SOFTHSM2_CONF"] = previous


def trusting_client() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(DATA / "ca.pem"))


# ------------------------------------------------------------------ SoftHSM2


def test_identities_pair_each_certificate_with_its_key(softhsm):
    backend = PKCS11Backend(softhsm, token=LABEL, pin=PIN)
    labels = sorted(i.label for i in backend.identities())
    assert labels == ["client-ec", "client-rsa"]


@pytest.mark.parametrize("name", ["client-rsa", "client-ec"])
def test_token_keys_authenticate_over_tls13(softhsm, tls_server, name):
    identity = PKCS11Backend(softhsm, token=LABEL, pin=PIN).find_identity(label=name)
    assert identity.signer.supports_pss
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    assert tls_server.handshake(context) == (name, "TLSv1.3")


def test_token_rsa_key_signs_pkcs1_for_tls12(softhsm):
    identity = PKCS11Backend(softhsm, token=LABEL, pin=PIN).find_identity(
        label="client-rsa"
    )
    context = trusting_client()
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    sslcontext.load_identity(context, identity)
    with TLSServer(client_sigalgs="RSA+SHA256") as server:
        assert server.handshake(context) == ("client-rsa", "TLSv1.2")


def test_pin_callable_receives_the_token_label(softhsm, tls_server):
    asked = []

    def pin(label: str) -> str:
        asked.append(label)
        return PIN

    identity = PKCS11Backend(softhsm, token=LABEL, pin=pin).find_identity(
        label="client-ec"
    )
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    tls_server.handshake(context)
    assert asked and set(asked) == {LABEL}


def test_always_authenticate_keys_get_the_pin_before_every_signature(
    softhsm, tls_server
):
    asked = []

    def pin(label: str) -> str:
        asked.append(label)
        return PIN

    backend = PKCS11Backend(softhsm, token=ALWAYS, pin=pin)
    identity = backend.find_identity(label="client-rsa")
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    assert tls_server.handshake(context).client_cn == "client-rsa"
    before = len(asked)
    assert tls_server.handshake(context).client_cn == "client-rsa"
    # The session stays logged in; only the per-signature login repeats.
    assert len(asked) == before + 1


def test_wrong_pin_is_a_keystore_error_naming_the_code(softhsm):
    # Login state is per process and token, and earlier tests logged in, so
    # a wrong PIN is only checked in a fresh process.
    script = "\n".join(
        [
            "import sslcontext",
            "from sslcontext.backends import PKCS11Backend",
            "try:",
            f"    list(PKCS11Backend({softhsm!r}, pin='0000').identities())",
            "except sslcontext.KeystoreError as error:",
            "    print(error)",
        ]
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
    )
    assert "CKR_PIN_INCORRECT" in result.stdout, result.stderr


def test_without_a_pin_signing_fails_and_says_why(softhsm, tls_server, caplog):
    identity = PKCS11Backend(softhsm, token=LABEL).find_identity(label="client-rsa")
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    with caplog.at_level(logging.WARNING, logger="sslcontext"):
        with pytest.raises((ssl.SSLError, ConnectionError)):
            tls_server.handshake(context)
    assert "needs a PIN" in caplog.text


def test_token_filter_selects_by_label(softhsm):
    assert PKCS11Backend(softhsm, token=LABEL, pin=PIN).tokens() == [LABEL]
    with pytest.raises(sslcontext.IdentityNotFoundError):
        PKCS11Backend(softhsm, token="other", pin=PIN).find_identity()


def test_missing_module_is_a_keystore_error(tmp_path):
    with pytest.raises(sslcontext.KeystoreError):
        list(PKCS11Backend(tmp_path / "missing.so").identities())


# ------------------------------------------------------- virtual smart card

VCARD_PIN = os.environ.get("SSLCONTEXT_TEST_VCARD_PIN", "12345678")
VIRT_CACARD = os.environ.get(
    "SSLCONTEXT_TEST_VIRT_CACARD", str(Path.home() / "build/virt_cacard/virt_cacard")
)


@pytest.fixture
def virtual_card() -> PKCS11Backend:
    if not OPENSC:
        pytest.skip("needs OpenSC")
    backend = PKCS11Backend(OPENSC, token="CAC II", pin=VCARD_PIN)
    try:
        present = backend.tokens()
    except sslcontext.KeystoreError:
        present = []
    if not present:
        pytest.skip("no virtual CAC card inserted (start pcscd and virt_cacard)")
    return backend


def card_identity(backend: PKCS11Backend) -> sslcontext.Identity:
    return backend.find_identity(label="CAC ID Certificate", valid=False)


def handshake(identity: sslcontext.Identity):
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    with TLSServer(trust=identity.certificate) as server:
        return server.handshake(context)


def test_virtual_smart_card_authenticates(virtual_card):
    identity = card_identity(virtual_card)
    assert handshake(identity).client_cn == identity.info.subject


def test_virtual_smart_card_survives_removal_and_reinsertion(virtual_card):
    if not os.path.exists(VIRT_CACARD):
        pytest.skip("needs the virt_cacard binary to remove and insert the card")
    identity = card_identity(virtual_card)
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    with TLSServer(trust=identity.certificate) as server:
        server.handshake(context)
        run(VIRT_CACARD, "-r")
        time.sleep(2)
        run(VIRT_CACARD, "-i")
        time.sleep(3)
        assert server.handshake(context).client_cn == identity.info.subject
