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
import time
from pathlib import Path
from typing import Iterable, Iterator, Optional

import pytest

import sslcontext
from conftest import DATA, TLSServer
from sslcontext.backends import PKCS11Backend

pytestmark = pytest.mark.integration

PIN, SO_PIN = "1234", "5678"
LABEL, ALWAYS, NOPIN, ASKED = "sslcontext", "always-auth", "no-pin", "asked"


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


def add_token(root: Path, label: str, names: Iterable[str], *extra: str) -> None:
    """Initialise a SoftHSM token and import each named test client into it."""
    run(
        "softhsm2-util",
        "--init-token",
        "--free",
        "--label",
        label,
        "--pin",
        PIN,
        "--so-pin",
        SO_PIN,
    )
    for number, name in enumerate(names, 1):
        key, cert = root / f"{name}.key.der", root / f"{name}.der"
        if not key.exists():
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
        for path, kind, flags in ((key, "privkey", extra), (cert, "cert", ())):
            run(
                "pkcs11-tool",
                "--module",
                SOFTHSM,
                "--token-label",
                label,
                "--login",
                "--pin",
                PIN,
                "--write-object",
                str(path),
                "--type",
                kind,
                "--id",
                f"{number:02d}",
                "--label",
                name,
                *flags,
            )


@pytest.fixture(scope="session")
def softhsm(tmp_path_factory) -> Iterator[str]:
    """SoftHSM tokens: LABEL (RSA + EC clients), ALWAYS (a key that needs the
    PIN for every signature, like a PIV card's slot 9C) and NOPIN (never
    logged in by any test, so login-state checks start from scratch) and
    ASKED (logged in only by the PIN-callback test)."""
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
        add_token(root, LABEL, ["client-rsa", "client-ec"])
        add_token(root, ALWAYS, ["client-rsa"], "--always-auth")
        add_token(root, NOPIN, ["client-ec"])
        add_token(root, ASKED, ["client-ec"])
        yield SOFTHSM
    finally:
        if previous is None:
            os.environ.pop("SOFTHSM2_CONF", None)
        else:
            os.environ["SOFTHSM2_CONF"] = previous


def trusting_client() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(DATA / "ca.pem"))


def recording(answer: object) -> tuple:
    """A PIN callback answering ``answer`` and the list of requests it saw."""
    requests: list = []

    def callback(request: sslcontext.PinRequest) -> object:
        requests.append(request)
        return answer

    return callback, requests


def fails_quickly(server, context, caplog, expected: str) -> None:
    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="sslcontext"):
        with pytest.raises((ssl.SSLError, ConnectionError)):
            server.handshake(context)
    assert time.monotonic() - started < 5, "a missing PIN must fail, not wait"
    assert expected in caplog.text


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
    backend = PKCS11Backend(softhsm, token=LABEL, pin=PIN)
    identity = backend.find_identity(label="client-rsa")
    context = trusting_client()
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    sslcontext.load_identity(context, identity)
    with TLSServer(client_sigalgs="RSA+SHA256") as server:
        assert server.handshake(context) == ("client-rsa", "TLSv1.2")


def test_pin_callback_is_told_who_asks_and_why(softhsm, tls_server):
    callback, requests = recording(PIN)
    identity = PKCS11Backend(softhsm, token=ASKED, pin=callback).find_identity(
        label="client-ec"
    )
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    tls_server.handshake(context)
    assert requests, "a token needing a login must consult the callback"
    assert {(r.backend, r.token) for r in requests} == {("pkcs11", ASKED)}
    assert requests[0].purpose == "list" and requests[0].certificate == ""
    for request in requests[1:]:
        assert (request.purpose, request.certificate) == ("sign", "CN=client-ec")
    assert not any(r.keystore_prompt for r in requests)  # SoftHSM has no PIN pad


def test_always_authenticate_keys_get_the_pin_before_every_signature(
    softhsm, tls_server
):
    callback, requests = recording(PIN)
    backend = PKCS11Backend(softhsm, token=ALWAYS, pin=callback)
    identity = backend.find_identity(label="client-rsa")
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    assert tls_server.handshake(context).client_cn == "client-rsa"
    before = len(requests)
    assert tls_server.handshake(context).client_cn == "client-rsa"
    # The session stays logged in; only the per-signature login repeats.
    assert [r.purpose for r in requests[before:]] == ["per-signature"]


def test_wrong_pin_is_a_keystore_error_naming_the_code(softhsm):
    with pytest.raises(sslcontext.KeystoreError, match="CKR_PIN_INCORRECT"):
        list(PKCS11Backend(softhsm, token=NOPIN, pin="0000").identities())


def test_without_a_pin_listing_works_and_signing_fails_at_once(
    softhsm, tls_server, caplog
):
    identity = PKCS11Backend(softhsm, token=NOPIN).find_identity(label="client-ec")
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    fails_quickly(tls_server, context, caplog, "none was given")


def test_a_declining_callback_fails_at_once(softhsm, tls_server, caplog):
    callback, requests = recording(None)
    backend = PKCS11Backend(softhsm, token=NOPIN, pin=callback)
    identity = backend.find_identity(label="client-ec")  # declining "list" is fine
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    fails_quickly(tls_server, context, caplog, "none was given")
    assert [r.purpose for r in requests] == ["list", "sign"]


def test_keystore_prompt_without_a_pin_pad_fails_instead_of_waiting(
    softhsm, tls_server, caplog
):
    identity = PKCS11Backend(
        softhsm, token=NOPIN, pin=sslcontext.KEYSTORE_PROMPT
    ).find_identity(label="client-ec")
    context = trusting_client()
    sslcontext.load_identity(context, identity)
    fails_quickly(tls_server, context, caplog, "has no PIN pad")


def test_a_raising_callback_propagates(softhsm):
    def callback(request):
        raise RuntimeError("user closed the PIN dialog")

    with pytest.raises(RuntimeError, match="user closed"):
        PKCS11Backend(softhsm, token=NOPIN, pin=callback).find_identity()


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


def test_a_selector_answers_from_the_token(softhsm, tls_server):
    backend = PKCS11Backend(softhsm, token=LABEL, pin=PIN)
    selector = sslcontext.ClientCertificateSelector(
        [backend],
        rules=[sslcontext.AutoSelectRule("localhost", subject={"CN": "client-ec"})],
    )
    context = trusting_client()
    selector.install(context)
    assert tls_server.handshake(context) == ("client-ec", "TLSv1.3")


def test_system_sources_use_the_configured_module(softhsm, monkeypatch):
    monkeypatch.setenv("SSLCONTEXT_PKCS11_MODULE", softhsm)
    from sslcontext.backends._pkcs11 import default_module

    (source,) = sslcontext.system_sources(pin=PIN)
    assert isinstance(source, PKCS11Backend) and source.module is None
    assert default_module() == softhsm
