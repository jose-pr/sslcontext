# sslcontext

**Client certificates whose private keys never leave the OS keystore, in a
plain `ssl.SSLContext`.** `sslcontext` signs TLS handshakes through Windows
CNG or a PKCS#11 token (smart cards included), so every library that takes an
`ssl_context` gets mutual TLS with no patching, no temporary key files and no
compiled extension. It drives the OpenSSL your Python already loaded, through
ctypes, on OpenSSL 1.1.1 and 3.x. Nothing ever waits for a PIN unless you say
how one is given.

## Installation

```bash
pip install sslcontext
```

Requires Python 3.9 or newer.

| Extra | Adds | Needed for |
| --- | --- | --- |
| `cli` | `duho` | the `sslcontext` command |

## 30-second tour

Behave like the system's browser: the OS verifies the server and, when a
server asks for a client certificate, the matching one is chosen from the
system's keystores. Build it once and share it:

```python
import urllib.request
import sslcontext

ctx = sslcontext.system_context()
urllib.request.urlopen("https://intranet.example.com/", context=ctx)
```

Or name the certificate yourself:

```python
from sslcontext.backends import CNGBackend, PKCS11Backend

ctx = sslcontext.create_context()
sslcontext.load_identity(ctx, CNGBackend().find_identity(subject="alice"))
# or a smart card: PKCS11Backend(pin=...).find_identity(label="...")
```

See which certificate a server would get:

```bash
sslcontext list
sslcontext probe https://intranet.example.com/
```

## Learn more

- [The API header](header.md): every public name, its contract and gotchas.
- [API reference](api/reference.md), generated from the docstrings.
- [Changelog](changelog.md)
