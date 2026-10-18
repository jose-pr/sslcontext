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
- **One context builder** — `create_context()` for the verify/cafile/capath
  combinations every HTTP client reimplements.

## Installation

```bash
pip install sslcontext
```

## Quick start

```python
import sslcontext

ctx = sslcontext.create_context(cafile="ca.pem")
sslcontext.load_pem(ctx, certificate=cert_pem, key=key_pem)
```

## API overview

| Module | Purpose |
| --- | --- |
| `sslcontext` | context builder, identity loading, the `Signer` contract |
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
