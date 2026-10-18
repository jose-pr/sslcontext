# sslcontext

[![Version](https://img.shields.io/pypi/v/sslcontext.svg)](https://pypi.org/project/sslcontext/)
[![Python versions](https://img.shields.io/pypi/pyversions/sslcontext.svg)](https://pypi.org/project/sslcontext/)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/sslcontext/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/sslcontext/test.yml)](https://github.com/jose-pr/sslcontext/actions/workflows/test.yml)

**Client certificates whose private keys never leave the OS keystore, in a
plain `ssl.SSLContext`.** `sslcontext` signs TLS handshakes through Windows
CNG, a PKCS#11 token or the macOS Keychain, so every library that accepts an
`ssl_context` gets mutual TLS with no patching, no temporary key files and no
compiled extension. Documentation: <https://jose-pr.github.io/sslcontext/>.

## Features

- **Keystore identities in stdlib `ssl`** — non-exportable and smart-card
  keys work, because the key is used through the keystore, never copied.
- **Pure Python** — ctypes over the OpenSSL that Python itself loaded: an
  OpenSSL 3 provider on modern builds, an OpenSSL 1.1 engine on older ones.
- **In-memory credentials** — load PEM or PKCS#12 bytes into a context
  without writing a key to disk.
- **Never blocks on a PIN** — PINs and passwords come from a value or a
  callback you write; with none, operations fail at once. Keystore dialogs
  and PIN pads are opt-in.
- **One context builder** — `create_context()` for the verify/cafile/capath
  combinations every HTTP client reimplements.

### Keystores

| Backend | Platform | Keys | Extra |
| --- | --- | --- | --- |
| `cng` | Windows | certificate stores: software (incl. non-exportable), TPM, smart cards and virtual smart cards, legacy CryptoAPI CSPs | none |
| `pkcs11` | any | PKCS#11 tokens: smart cards (real or virtual) via OpenSC, HSMs, TPMs, SoftHSM | none |

## Installation

```bash
pip install sslcontext
```

## Quick start

Load a certificate and key held in memory:

```python
import sslcontext

ctx = sslcontext.create_context(cafile="ca.pem")
sslcontext.load_pem(ctx, certificate=cert_pem, key=key_pem)
```

Use a certificate from the Windows store whose key cannot be exported:

```python
import urllib.request
import sslcontext
from sslcontext.backends import CNGBackend

ctx = sslcontext.create_context()
sslcontext.load_identity(ctx, CNGBackend().find_identity(subject="alice"))
urllib.request.urlopen("https://mtls.example.com/", context=ctx)
```

Use a smart card through its PKCS#11 module. The PIN callback decides how
the PIN is obtained; with no PIN, signing fails instead of waiting:

```python
from getpass import getpass
from sslcontext.backends import PKCS11Backend

def pin(request: sslcontext.PinRequest):
    if request.purpose == "list":
        return None  # list without logging in
    return getpass(f"PIN for {request.token}: ")

card = PKCS11Backend(pin=pin)
sslcontext.load_identity(ctx, card.find_identity(subject="alice"))
```

## API overview

| Module | Purpose |
| --- | --- |
| `sslcontext` | context builder, identity loading, the `Signer` contract |
| `sslcontext.backends` | keystore backends and their registry |
| `sslcontext.testing` | `SoftwareSigner`, an in-memory signer for tests |
| `sslcontext.exceptions` | the package's errors |

## Development

```bash
dotagents pyvenv && dotagents pyvenv 3.9
.pyvenv/<tag>/Scripts/python -m pip install -e ".[dev]"
.pyvenv/<tag>/Scripts/python -m pytest -q -rs
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/jose-pr/sslcontext/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow: test gate → build
(checking the tag names the version built) → a strict docs build as a gate →
GitHub release → publish. The release workflow never deploys the docs site
itself: for a final release its last job dispatches the docs workflow at the
tag, which owns every Pages deploy.
