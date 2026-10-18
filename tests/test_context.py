from __future__ import annotations

import ssl

import pytest

import sslcontext
from conftest import DATA, data


def test_client_default_verifies_the_server_and_its_name():
    context = sslcontext.create_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_client_verify_false_checks_nothing():
    context = sslcontext.create_context(verify=False)
    assert context.verify_mode == ssl.CERT_NONE
    assert not context.check_hostname


def test_verify_path_trusts_that_bundle(tls_server):
    context = sslcontext.create_context(verify=str(DATA / "ca.pem"))
    sslcontext.load_pem(context, data("client-ec.pem"), data("client-ec.key"))
    assert tls_server.handshake(context).client_cn == "client-ec"


def test_verify_directory_is_used_as_capath(tmp_path):
    context = sslcontext.create_context(verify=tmp_path)
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_a_server_name_outside_the_bundle_fails(tls_server):
    context = sslcontext.create_context()  # system trust, not the test CA
    sslcontext.load_pem(context, data("client-ec.pem"), data("client-ec.key"))
    with pytest.raises(ssl.SSLCertVerificationError):
        tls_server.handshake(context)


def test_server_verify_true_requires_a_client_certificate():
    context = sslcontext.create_context("server", verify=True, cafile=DATA / "ca.pem")
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_server_default_does_not_ask_for_a_client_certificate():
    assert sslcontext.create_context("server").verify_mode == ssl.CERT_NONE


def test_versions_and_alpn_are_applied():
    context = sslcontext.create_context(
        minimum_version=ssl.TLSVersion.TLSv1_2,
        maximum_version=ssl.TLSVersion.TLSv1_3,
        alpn=["h2", "http/1.1"],
    )
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == ssl.TLSVersion.TLSv1_3


def test_unknown_purpose_is_a_value_error():
    with pytest.raises(ValueError):
        sslcontext.create_context("peer")


def test_verify_path_and_cafile_together_is_a_value_error():
    with pytest.raises(ValueError):
        sslcontext.create_context(verify=str(DATA / "ca.pem"), cafile=DATA / "ca.pem")
