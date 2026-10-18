from __future__ import annotations

import ssl
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

import sslcontext
from conftest import DATA, TLSServer, data
from sslcontext import AutoSelectRule, CertificateRequest, ClientCertificateSelector
from sslcontext.exceptions import KeystoreError
from sslcontext.issuing import CertificateAuthority
from sslcontext.testing import SoftwareSigner, software_identity

CA_A = data("ca.pem")


@pytest.fixture(scope="module")
def ca_b() -> CertificateAuthority:
    return CertificateAuthority.create("Test CA B", key_type="rsa")


@pytest.fixture(scope="module")
def identity_a():
    return software_identity(data("client-rsa.pem"), data("client-rsa.key"))


@pytest.fixture(scope="module")
def identity_b(ca_b):
    issued = ca_b.issue(["client-b"], common_name="client-b")
    return software_identity(issued.certificate + issued.chain, issued.key)


def announce(server: TLSServer, *pems: bytes, tmp_path) -> None:
    """Make ``server`` name these CAs in its certificate request."""
    from sslcontext._openssl import openssl, ssl_ctx_pointer

    lib = openssl()
    path = tmp_path / f"announce-{id(server)}.pem"
    path.write_bytes(b"".join(pems))
    names = lib.SSL_load_client_CA_file(str(path).encode())
    assert names
    lib.SSL_CTX_set_client_CA_list(ssl_ctx_pointer(lib, server.context), names)


def server(ca_b, *announced, tmp_path, mode=ssl.CERT_REQUIRED, maximum=None):
    result = TLSServer(trust=ca_b.certificate.decode())
    result.context.verify_mode = mode
    if maximum is not None:
        result.context.maximum_version = maximum
    if announced:
        announce(result, *announced, tmp_path=tmp_path)
    return result


def client(selector: ClientCertificateSelector) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(DATA / "ca.pem"))
    selector.install(context)
    return context


def request(**overrides) -> CertificateRequest:
    values = dict(
        host="example.com",
        authorities=(),
        authorities_der=(),
        key_types=frozenset({"rsa", "ec"}),
        rsa_pss_required=False,
        tls_version="TLSv1.3",
    )
    values.update(overrides)
    return CertificateRequest(**values)


# ------------------------------------------------------------ handshakes


def test_each_server_gets_the_identity_its_ca_list_names(
    ca_b, identity_a, identity_b, tmp_path
):
    context = client(ClientCertificateSelector([identity_a, identity_b]))
    with server(ca_b, CA_A, tmp_path=tmp_path) as first:
        assert first.handshake(context).client_cn == "client-rsa"
    with server(ca_b, ca_b.certificate, tmp_path=tmp_path) as second:
        assert second.handshake(context).client_cn == "client-b"


def test_two_candidates_and_nothing_to_pick_sends_none(
    ca_b, identity_a, identity_b, tmp_path
):
    context = client(ClientCertificateSelector([identity_a, identity_b]))
    with server(ca_b, tmp_path=tmp_path, mode=ssl.CERT_OPTIONAL) as optional:
        assert optional.handshake(context).client_cn == "-"


def test_the_only_candidate_is_sent(ca_b, identity_a, identity_b, tmp_path):
    context = client(ClientCertificateSelector([identity_a, identity_b]))
    with server(ca_b, ca_b.certificate, tmp_path=tmp_path) as only_b:
        assert only_b.handshake(context).client_cn == "client-b"


def test_choose_sees_the_request_and_picks(ca_b, identity_a, identity_b, tmp_path):
    seen = []

    def choose(req, candidates):
        seen.append((req, [c.info.subject for c in candidates]))
        return candidates[-1]

    context = client(ClientCertificateSelector([identity_a, identity_b], choose=choose))
    with server(ca_b, tmp_path=tmp_path) as anyone:
        cn = anyone.handshake(context).client_cn
    ((req, subjects),) = seen
    assert req.host == "localhost" and req.authorities == ()
    assert req.tls_version == "TLSv1.3" and req.rsa_pss_required
    assert "rsa" in req.key_types and "ec" in req.key_types
    assert cn == subjects[-1].split(",")[0].split("=")[1]


def test_the_choice_is_remembered_per_host(ca_b, identity_a, identity_b, tmp_path):
    calls = []

    def choose(req, candidates):
        calls.append(req.host)
        return candidates[0]

    selector = ClientCertificateSelector([identity_a, identity_b], choose=choose)
    context = client(selector)
    with server(ca_b, tmp_path=tmp_path) as anyone:
        first = anyone.handshake(context).client_cn
        assert anyone.handshake(context).client_cn == first
        selector.forget("localhost")
        anyone.handshake(context)
    assert calls == ["localhost", "localhost"]


def test_a_rule_picks_without_asking(ca_b, identity_a, identity_b, tmp_path):
    rule = AutoSelectRule("https://[*.]localhost:443/", issuer={"CN": "Test CA B"})
    selector = ClientCertificateSelector(
        [identity_a, identity_b], rules=[rule], choose=lambda *_: pytest.fail()
    )
    with server(ca_b, tmp_path=tmp_path) as anyone:
        assert anyone.handshake(client(selector)).client_cn == "client-b"


def test_a_server_that_asks_nothing_is_never_answered(identity_a, ca_b, tmp_path):
    selector = ClientCertificateSelector(
        [identity_a], choose=lambda *_: pytest.fail("asked")
    )
    with server(ca_b, tmp_path=tmp_path, mode=ssl.CERT_NONE) as silent:
        assert silent.handshake(client(selector)).client_cn == "-"


def test_choose_raising_fails_the_handshake(ca_b, identity_a, identity_b, tmp_path):
    def choose(req, candidates):
        raise RuntimeError("user cancelled")

    context = client(ClientCertificateSelector([identity_a, identity_b], choose=choose))
    with server(ca_b, tmp_path=tmp_path) as anyone:
        with pytest.raises((ssl.SSLError, OSError)):
            anyone.handshake(context)


def test_choose_returning_a_stranger_fails_the_handshake(
    ca_b, identity_a, identity_b, tmp_path
):
    stranger = software_identity(data("client-ec.pem"), data("client-ec.key"))
    context = client(
        ClientCertificateSelector([identity_a, identity_b], choose=lambda *_: stranger)
    )
    with server(ca_b, tmp_path=tmp_path) as anyone:
        with pytest.raises((ssl.SSLError, OSError)):
            anyone.handshake(context)


class _NoPSS:
    supports_pss = False

    def __init__(self, inner):
        self.inner = inner

    def sign(self, digest, **kwargs):
        return self.inner.sign(digest, **kwargs)


def test_a_pkcs1_only_key_answers_tls12_and_sits_out_tls13(ca_b, tmp_path):
    signer = _NoPSS(SoftwareSigner(data("client-rsa.key")))
    identity = sslcontext.Identity(
        software_identity(data("client-rsa.pem"), data("client-rsa.key")).certificate,
        signer,
    )
    context = client(ClientCertificateSelector([identity]))
    with server(ca_b, CA_A, tmp_path=tmp_path, maximum=ssl.TLSVersion.TLSv1_2) as tls12:
        assert tls12.handshake(context) == ("client-rsa", "TLSv1.2")
    with server(ca_b, CA_A, tmp_path=tmp_path, mode=ssl.CERT_OPTIONAL) as tls13:
        assert tls13.handshake(context) == ("-", "TLSv1.3")


def test_a_failing_source_is_skipped(ca_b, identity_b, tmp_path):
    def broken():
        raise KeystoreError("card reader unplugged")

    context = client(ClientCertificateSelector([broken, identity_b]))
    with server(ca_b, ca_b.certificate, tmp_path=tmp_path) as only_b:
        assert only_b.handshake(context).client_cn == "client-b"


def test_concurrent_handshakes_each_get_their_answer(
    ca_b, identity_a, identity_b, tmp_path
):
    context = client(ClientCertificateSelector([identity_a, identity_b]))
    with (
        server(ca_b, CA_A, tmp_path=tmp_path) as first,
        server(ca_b, ca_b.certificate, tmp_path=tmp_path) as second,
    ):
        jobs = [first, second] * 8
        with ThreadPoolExecutor(8) as pool:
            names = list(pool.map(lambda s: s.handshake(context).client_cn, jobs))
    assert names == ["client-rsa", "client-b"] * 8


def test_a_truststore_context_answers_too(ca_b, identity_b, tmp_path):
    truststore = pytest.importorskip("truststore")
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(DATA / "ca.pem"))
    ClientCertificateSelector([identity_b]).install(context)
    with server(ca_b, ca_b.certificate, tmp_path=tmp_path) as only_b:
        assert only_b.handshake(context).client_cn == "client-b"


def test_installing_again_replaces_the_selector(ca_b, identity_a, identity_b, tmp_path):
    context = client(ClientCertificateSelector([identity_a]))
    ClientCertificateSelector([identity_b]).install(context)
    with server(ca_b, tmp_path=tmp_path) as anyone:
        assert anyone.handshake(context).client_cn == "client-b"


# ------------------------------------------------------------ filtering


def test_a_server_only_certificate_is_no_candidate(identity_a):
    server_only = software_identity(data("server.pem"), data("server.key"))
    selector = ClientCertificateSelector([server_only, identity_a])
    assert selector.candidates(request()) == [identity_a]


def test_key_types_and_pss_filter(identity_a):
    ec = software_identity(data("client-ec.pem"), data("client-ec.key"))
    no_pss = sslcontext.Identity(identity_a.certificate, _NoPSS(identity_a.signer))
    selector = ClientCertificateSelector([identity_a, ec, no_pss])
    assert selector.candidates(request(key_types=frozenset({"ec"}))) == [ec]
    rsa_pss = selector.candidates(
        request(key_types=frozenset({"rsa"}), rsa_pss_required=True)
    )
    assert rsa_pss == [identity_a]
    assert len(selector.candidates(request(key_types=frozenset({"rsa"})))) == 2


def test_sources_are_listed_once_per_ttl(identity_a):
    calls = []

    def source():
        calls.append(1)
        return [identity_a]

    selector = ClientCertificateSelector([source], cache_ttl=3600)
    selector.candidates(request())
    selector.candidates(request())
    assert len(calls) == 1
    selector.refresh()
    selector.candidates(request())
    assert len(calls) == 2


@pytest.mark.parametrize(
    "pattern, host, expected",
    [
        ("example.com", "example.com", True),
        ("example.com", "www.example.com", False),
        ("[*.]example.com", "example.com", True),
        ("[*.]example.com", "a.b.example.com", True),
        ("[*.]example.com", "badexample.com", False),
        ("*.example.com", "example.com", False),
        ("*.example.com", "www.example.com", True),
        ("https://example.com:8443/path", "EXAMPLE.com.", True),
        ("*", "anything", True),
        ("*", None, True),
        ("example.com", None, False),
        ("[::1]:443", "::1", True),
    ],
)
def test_rule_patterns(pattern, host, expected):
    assert AutoSelectRule(pattern).matches_host(host) is expected


def test_rule_filters(identity_a, identity_b):
    issuer_a = identity_a.info.issuer
    assert AutoSelectRule("*", issuer=issuer_a.split(",")[0].lower()).matches(
        identity_a
    )
    assert AutoSelectRule("*", subject={"CN": "client-b"}).matches(identity_b)
    assert not AutoSelectRule("*", subject={"CN": "client"}).matches(identity_b)
    assert not AutoSelectRule("*", issuer={"O": "nobody"}).matches(identity_b)


# ------------------------------------------------------------ policies


def test_policy_entries_become_rules():
    rules = sslcontext.rules_from_policy(
        [
            '{"pattern": "https://[*.]corp.example", "filter": {"ISSUER": {"CN": "Corp CA"}}}',
            {"pattern": "*", "filter": {"SUBJECT": {"OU": ["Staff"]}}},
            "not json",
            '{"filter": {}}',
            '{"pattern": "x", "filter": {"ISSUER": {"CN": ["a", "b"]}}}',
        ]
    )
    assert rules == [
        AutoSelectRule("https://[*.]corp.example", issuer={"CN": "Corp CA"}),
        AutoSelectRule("*", subject={"OU": "Staff"}),
    ]


def test_linux_and_macos_policy_files_are_read(tmp_path, monkeypatch):
    import plistlib

    from sslcontext import _policy

    managed = tmp_path / "chrome"
    managed.mkdir()
    (managed / "certs.json").write_text(
        '{"AutoSelectCertificateForUrls": ["{\\"pattern\\": \\"a.example\\"}"]}'
    )
    (managed / "broken.json").write_text("{")
    monkeypatch.setattr(_policy, "_POLICY_DIRS", (str(managed),))
    assert _policy.rules_from_policy(_policy._json_entries()) == [
        AutoSelectRule("a.example")
    ]
    plist = tmp_path / "com.google.Chrome.plist"
    plist.write_bytes(
        plistlib.dumps(
            {"AutoSelectCertificateForUrls": ['{"pattern": "b.example"}']},
            fmt=plistlib.FMT_BINARY,
        )
    )
    monkeypatch.setattr(_policy, "_PLIST_GLOBS", (str(tmp_path / "*.plist"),))
    assert _policy.rules_from_policy(_policy._plist_entries()) == [
        AutoSelectRule("b.example")
    ]


@pytest.mark.skipif(
    not hasattr(ssl, "enum_certificates"), reason="the registry is Windows only"
)
def test_windows_registry_policies_are_read_in_order(monkeypatch):
    import winreg

    from sslcontext import _policy

    base = r"Software\sslcontext-tests\Policies\Edge"
    with winreg.CreateKey(
        winreg.HKEY_CURRENT_USER, base + r"\AutoSelectCertificateForUrls"
    ) as key:
        winreg.SetValueEx(key, "2", 0, winreg.REG_SZ, '{"pattern": "second"}')
        winreg.SetValueEx(key, "10", 0, winreg.REG_SZ, '{"pattern": "third"}')
        winreg.SetValueEx(key, "1", 0, winreg.REG_SZ, '{"pattern": "first"}')
    try:
        monkeypatch.setattr(_policy, "_REGISTRY_KEYS", (base,))
        patterns = [rule.pattern for rule in _policy.browser_policies()]
        assert patterns == ["first", "second", "third"]
    finally:
        winreg.DeleteKey(
            winreg.HKEY_CURRENT_USER, base + r"\AutoSelectCertificateForUrls"
        )
        for part in (base, r"Software\sslcontext-tests\Policies"):
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, part)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\sslcontext-tests")


def test_browser_policy_rules_pick(ca_b, identity_a, identity_b, tmp_path, monkeypatch):
    from sslcontext import _policy

    monkeypatch.setattr(
        _policy,
        "browser_policies",
        lambda: [AutoSelectRule("localhost", subject={"CN": "client-rsa"})],
    )
    selector = ClientCertificateSelector([identity_a, identity_b], browser_policy=True)
    with server(ca_b, tmp_path=tmp_path) as anyone:
        assert anyone.handshake(client(selector)).client_cn == "client-rsa"
