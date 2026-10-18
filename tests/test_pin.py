from __future__ import annotations

import pytest

import sslcontext
from conftest import data
from sslcontext._pin import resolve_password, resolve_pin

REQUEST = sslcontext.PinRequest("pkcs11", "card", "CN=alice", "sign", False)


def test_a_plain_pin_is_returned_as_is():
    assert resolve_pin("1234", REQUEST) == "1234"


def test_no_pin_means_none_and_nobody_is_asked():
    assert resolve_pin(None, REQUEST) is None


def test_keystore_prompt_passes_through():
    assert (
        resolve_pin(sslcontext.KEYSTORE_PROMPT, REQUEST) is sslcontext.KEYSTORE_PROMPT
    )


def test_a_callback_gets_the_request_and_decides():
    seen = []
    assert resolve_pin(lambda r: seen.append(r) or "9999", REQUEST) == "9999"
    assert seen == [REQUEST]
    assert resolve_pin(lambda r: None, REQUEST) is None
    assert resolve_pin(lambda r: sslcontext.KEYSTORE_PROMPT, REQUEST) is (
        sslcontext.KEYSTORE_PROMPT
    )


def test_a_callback_returning_the_wrong_type_never_echoes_the_value():
    with pytest.raises(TypeError) as caught:
        resolve_pin(lambda r: b"secret-pin", REQUEST)
    assert "secret-pin" not in str(caught.value)
    with pytest.raises(TypeError) as caught:
        resolve_pin(b"secret-pin", REQUEST)  # type: ignore[arg-type]
    assert "secret-pin" not in str(caught.value)


def test_pin_request_repr_holds_no_secret():
    assert "1234" not in repr(REQUEST)


def test_passwords_come_from_values_or_callables():
    assert resolve_password("pw") == b"pw"
    assert resolve_password(b"pw") == b"pw"
    assert resolve_password(lambda: "pw") == b"pw"
    assert resolve_password(lambda: None) is None
    assert resolve_password(None) is None


def test_password_callable_is_not_called_for_an_unencrypted_key(client_context):
    def never():
        raise AssertionError("asked for a password the key does not need")

    sslcontext.load_pem(
        client_context, data("client-ec.pem"), data("client-ec.key"), password=never
    )


def test_password_callable_is_called_for_an_encrypted_key(tls_server, client_context):
    asked = []
    sslcontext.load_pem(
        client_context,
        data("client-ec.pem"),
        data("client-ec.enc.key"),
        password=lambda: asked.append(1) or "test",
    )
    assert asked == [1]
    assert tls_server.handshake(client_context).client_cn == "client-ec"


def test_a_declined_password_fails_at_once(client_context):
    with pytest.raises(sslcontext.CredentialError):
        sslcontext.load_pem(
            client_context,
            data("client-ec.pem"),
            data("client-ec.enc.key"),
            password=lambda: None,
        )


def test_pkcs12_password_callable(tls_server, client_context):
    sslcontext.load_pkcs12(client_context, data("client-rsa.p12"), lambda: "test")
    assert tls_server.handshake(client_context).client_cn == "client-rsa"
