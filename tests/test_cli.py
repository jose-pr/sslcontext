from __future__ import annotations

import json
import socket
import ssl
import sys

import pytest

from conftest import DATA, data
from sslcontext.backends import Backend, register_backend
from sslcontext.testing import software_identity

pytest.importorskip("duho")

from sslcontext.cli import main  # noqa: E402


class _TestBackend(Backend):
    name = "clitest"

    def identities(self):
        yield software_identity(data("client-rsa.pem"), data("client-rsa.key"))
        yield software_identity(data("client-ec.pem"), data("client-ec.key"))
        yield software_identity(data("server.pem"), data("server.key"))


register_backend("clitest", _TestBackend)


def run(capsys, *argv):
    status = main(list(argv))
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def test_list_prints_every_identity_with_its_usage(capsys):
    status, out, _ = run(capsys, "list", "--backend", "clitest")
    lines = out.splitlines()
    assert status == 0 and len(lines) == 3
    assert any("no-client" in line and "CN=server" in line for line in lines)
    assert sum(" client " in line for line in lines) == 2


def test_list_json(capsys):
    status, out, _ = run(capsys, "list", "-b", "clitest", "--json")
    rows = json.loads(out)
    assert status == 0
    assert {row["key"].split("-")[0] for row in rows} == {"rsa", "ec"}
    assert {"sha1", "subject", "issuer", "not_after", "client_auth", "label"} <= set(
        rows[0]
    )


def test_show_finds_by_subject_and_thumbprint(capsys):
    status, out, _ = run(capsys, "show", "-b", "clitest", "client-ec")
    shown = json.loads(out)
    assert status == 0 and shown["subject"].startswith("CN=client-ec")
    thumbprint = ":".join(
        shown["sha1"][i : i + 2] for i in range(0, len(shown["sha1"]), 2)
    )
    status, out, _ = run(capsys, "show", "-b", "clitest", thumbprint.lower())
    assert json.loads(out)["sha256"] == shown["sha256"]


def test_show_without_a_match_fails(capsys):
    status, _, err = run(capsys, "show", "-b", "clitest", "nobody")
    assert status == 1 and "nobody" in err


def test_an_unknown_backend_is_a_usage_error(capsys):
    status, _, err = run(capsys, "list", "-b", "nosuch")
    assert status == 2 and "nosuch" in err


def test_probe_reports_the_request_and_the_answer(capsys, tls_server, tmp_path):
    from test_select import announce

    announce(tls_server, data("ca.pem"), tmp_path=tmp_path)
    status, out, _ = run(
        capsys,
        "probe",
        f"localhost:{tls_server.port}",
        "-b",
        "clitest",
        "--cafile",
        str(DATA / "ca.pem"),
        "--no-policy",
        "--json",
    )
    result = json.loads(out)
    # TLS 1.3 finishes the handshake before the server refuses; 1.2 refuses in it.
    assert status == (0 if ssl.HAS_TLSv1_3 else 1), result
    (request,) = result["certificate_requests"]
    assert request["authorities"] and request["host"] == "localhost"
    # The server-only certificate does not fit; two client ones do, so with
    # nothing to pick between them none is sent and the server refuses.
    assert len(request["candidates"]) == 2 and request["sent"] is None
    if ssl.HAS_TLSv1_3:  # 1.2 fails before the server's certificate is reported
        assert result["server"]["subject"].startswith("CN=")


def test_probe_lines_and_a_failed_connection(capsys):
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    status, out, _ = run(capsys, "probe", f"127.0.0.1:{port}", "-b", "clitest")
    assert status == 1
    assert "client certificate: not requested" in out and "error:" in out


def test_probe_refuses_other_schemes(capsys):
    status, _, err = run(capsys, "probe", "http://example.com", "-b", "clitest")
    assert status == 2 and "https" in err


def test_without_the_extra_main_names_it(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "duho", None)
    assert main(["list"]) == 1
    assert "sslcontext[cli]" in capsys.readouterr().err
