from __future__ import annotations

import pytest

import sslcontext
from conftest import data
from sslcontext import backends
from sslcontext.testing import software_identity


class MemoryBackend(backends.Backend):
    name = "memory"

    def __init__(self, *identities: sslcontext.Identity) -> None:
        self._identities = identities

    def identities(self):
        return iter(self._identities)


@pytest.fixture
def store() -> MemoryBackend:
    rsa = software_identity(data("client-rsa.pem"), data("client-rsa.key"))
    ec = software_identity(data("client-ec.pem"), data("client-ec.key"))
    return MemoryBackend(rsa, ec)


def test_thumbprint_matches_sha1_or_sha256_in_any_spelling(store):
    rsa_info = software_identity(data("client-rsa.pem"), data("client-rsa.key")).info
    colons = ":".join(rsa_info.sha1[i : i + 2] for i in range(0, 40, 2)).lower()
    assert store.find_identity(thumbprint=colons).info.subject == "CN=client-rsa"
    assert (
        store.find_identity(thumbprint=rsa_info.sha256).info.subject == "CN=client-rsa"
    )


def test_subject_and_issuer_match_substrings_ignoring_case(store):
    assert store.find_identity(subject="client-EC").info.key_type == "ec"
    assert len(store.find_identities(issuer="SSLCONTEXT TEST CA")) == 2


def test_no_match_raises_identity_not_found(store):
    with pytest.raises(sslcontext.IdentityNotFoundError, match="subject='nobody'"):
        store.find_identity(subject="nobody")


def test_label_matches_exactly(store):
    assert len(store.find_identities(label="SOFTWARE")) == 2
    assert store.find_identities(label="soft") == []


def test_cng_is_registered_without_importing_it():
    assert "cng" in backends.names()
    assert backends.get("cng").name == "cng"


def test_unknown_backend_names_the_registered_ones():
    with pytest.raises(ValueError, match="cng"):
        backends.get("nope")


def test_registering_a_taken_name_is_refused():
    with pytest.raises(ValueError):
        backends.register_backend("cng", MemoryBackend)
    with pytest.raises(ValueError):
        backends.register_backend("Upper", MemoryBackend)


def test_backends_are_context_managers(store):
    with store as opened:
        assert opened is store
