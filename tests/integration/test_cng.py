"""The cng backend against real Windows certificate stores.

Each test creates a short-lived, non-exportable certificate in
``CurrentUser\\MY`` with PowerShell's ``New-SelfSignedCertificate`` and
deletes it, key included, afterwards.
"""

from __future__ import annotations

import base64
import contextlib
import os
import shutil
import ssl
import subprocess
import uuid
from typing import Iterator, NamedTuple

import pytest

import sslcontext
from conftest import DATA, TLSServer
from sslcontext.backends import CNGBackend

pytestmark = pytest.mark.integration


def _powershell() -> str | None:
    try:
        import ctypes

        ctypes.WinDLL("ncrypt")
    except (ImportError, OSError, AttributeError):
        return None
    return shutil.which("powershell")


POWERSHELL = _powershell()
if POWERSHELL is None:
    pytest.skip("needs Windows CNG and PowerShell", allow_module_level=True)

KINDS = {
    "rsa": "-KeyAlgorithm RSA -KeyLength 2048 -Provider 'Microsoft Software Key Storage Provider'",
    "ec": "-KeyAlgorithm ECDSA_nistP256 -Provider 'Microsoft Software Key Storage Provider'",
    "legacy-rsa": "-KeyAlgorithm RSA -KeyLength 2048 -KeySpec Signature "
    "-Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'",
}


class StoreCertificate(NamedTuple):
    subject: str
    thumbprint: str
    der: bytes
    friendly_name: str


def run_powershell(command: str) -> str:
    # A PSModulePath inherited from PowerShell 7 hides Windows PowerShell's
    # own modules, the Cert: drive among them.
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@contextlib.contextmanager
def created(kind: str) -> Iterator[StoreCertificate]:
    tag = uuid.uuid4().hex[:8]
    subject = f"sslcontext-test-{kind}-{tag}"
    friendly = f"sslcontext test {tag}"
    out = run_powershell(
        f"$c = New-SelfSignedCertificate -Subject 'CN={subject}' "
        f"-FriendlyName '{friendly}' -CertStoreLocation Cert:/CurrentUser/My "
        f"-KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(1) {KINDS[kind]}; "
        "$c.Thumbprint + ' ' + [Convert]::ToBase64String($c.RawData)"
    )
    thumbprint, encoded = out.split()
    try:
        yield StoreCertificate(subject, thumbprint, base64.b64decode(encoded), friendly)
    finally:
        run_powershell(f"Remove-Item Cert:/CurrentUser/My/{thumbprint} -DeleteKey")


@pytest.fixture(params=sorted(KINDS))
def store_certificate(request) -> Iterator[StoreCertificate]:
    with created(request.param) as certificate:
        yield certificate


@pytest.fixture
def legacy_certificate(monkeypatch) -> Iterator[StoreCertificate]:
    """A legacy-CSP key acquired as a CryptoAPI handle, as for a CSP with no
    CNG equivalent (the default flags would open it through CNG)."""
    from sslcontext.backends import _cng

    monkeypatch.setattr(_cng, "_CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG", 0x10000)
    with created("legacy-rsa") as certificate:
        yield certificate


def client_context(maximum: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(DATA / "ca.pem"))
    if maximum:
        context.maximum_version = maximum
    return context


def test_identity_is_found_by_thumbprint_and_authenticates(store_certificate):
    identity = CNGBackend().find_identity(thumbprint=store_certificate.thumbprint)
    assert identity.certificate == store_certificate.der
    assert identity.label == store_certificate.friendly_name
    # Legacy CSP software keys open through CNG too, so TLS 1.3 (PSS) works.
    context = client_context()
    sslcontext.load_identity(context, identity)
    with TLSServer(trust=store_certificate.der) as server:
        assert server.handshake(context) == (store_certificate.subject, "TLSv1.3")


def test_identity_is_found_by_subject_and_label(store_certificate):
    backend = CNGBackend()
    by_subject = backend.find_identity(subject=store_certificate.subject.upper())
    by_label = backend.find_identity(label=store_certificate.friendly_name)
    assert by_subject.certificate == by_label.certificate == store_certificate.der


def test_identities_lists_the_certificate(store_certificate):
    listed = [i.info.sha1 for i in CNGBackend().identities()]
    assert store_certificate.thumbprint in listed


def test_cryptoapi_keys_sign_pkcs1_for_tls12(legacy_certificate):
    identity = CNGBackend().find_identity(thumbprint=legacy_certificate.thumbprint)
    assert identity.signer.supports_pss is False
    context = client_context(ssl.TLSVersion.TLSv1_2)
    sslcontext.load_identity(context, identity)
    with TLSServer(trust=legacy_certificate.der) as server:
        assert server.handshake(context) == (legacy_certificate.subject, "TLSv1.2")


def test_cryptoapi_keys_cannot_complete_tls13(legacy_certificate):
    identity = CNGBackend().find_identity(thumbprint=legacy_certificate.thumbprint)
    context = client_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    sslcontext.load_identity(context, identity)
    with TLSServer(trust=legacy_certificate.der) as server:
        with pytest.raises((ssl.SSLError, ConnectionError)):
            server.handshake(context)


def test_unknown_thumbprint_is_not_found():
    with pytest.raises(sslcontext.IdentityNotFoundError):
        CNGBackend().find_identity(thumbprint="00" * 20)


def test_bad_location_is_a_value_error():
    with pytest.raises(ValueError):
        CNGBackend(location="everywhere")
