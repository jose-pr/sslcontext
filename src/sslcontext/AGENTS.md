# `sslcontext` — public API header

Header-file-style reference for the `sslcontext` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is
self-contained. Development documentation lives with the source at
<https://github.com/jose-pr/sslcontext>.

Import everything from the root `sslcontext`, except the errors, which live in
`sslcontext.exceptions` and are re-exported from the root. Modules whose
names start with `_` are private.

`pip install sslcontext`. No runtime dependencies.

`sslcontext.__version__` is the installed distribution's version.

## Building a context (`sslcontext`)

```python
def create_context(
    purpose: str = "client",
    *,
    verify: bool | str | os.PathLike | None = None,
    cafile: str | os.PathLike | None = None,
    capath: str | os.PathLike | None = None,
    cadata: str | bytes | None = None,
    minimum_version: ssl.TLSVersion | None = None,
    maximum_version: ssl.TLSVersion | None = None,
    alpn: Iterable[str] | None = None,
) -> ssl.SSLContext
```

Returns a plain `ssl.SSLContext` built on `ssl.create_default_context`.
`purpose` is `"client"` or `"server"` (anything else: `ValueError`).
`verify=None` keeps the purpose's default: a client verifies the server and
its host name; a server does not ask for a client certificate. `True` turns
verification on (a server then requires a client certificate); `False` turns
it off (a client stops checking the host name too). A path in `verify` means
"trust this CA bundle file, or this hashed CA directory", as in `requests`;
combining it with `cafile`/`capath` is a `ValueError`. Trust comes from
`cafile`/`capath`/`cadata` when given, else the platform's default store.

`VerifyLike` is the exported alias for the `verify` type.

## Loading credentials from memory (`sslcontext`)

```python
def load_pem(
    context: ssl.SSLContext,
    certificate: bytes | str,
    key: bytes | str | None = None,
    password: str | bytes | None = None,
) -> None
```

Makes `certificate` (+ chain) and `key` the context's identity without
touching the disk. `certificate` is PEM text (leaf first, then chain) or one
DER certificate. `key` is a PEM or DER private key; omitted, it is read from
`certificate` (a combined PEM). `password` decrypts an encrypted key.

```python
def load_pkcs12(
    context: ssl.SSLContext,
    data: bytes,
    password: str | bytes | None = None,
) -> None
```

Loads the key, certificate and chain of a PKCS#12 (`.p12`/`.pfx`) bundle.

Both raise `CredentialError` for malformed data, a wrong or missing password,
or a key that does not match the certificate, and `TypeError` when `context`
is not an `ssl.SSLContext`. An identity of one key type (RSA, EC) replaces a
previously loaded identity of the same type; identities of different types
coexist and OpenSSL picks per handshake. `BytesOrText` is the exported alias
for the credential argument types.

## Keystore identities (`sslcontext`)

```python
class Signer(Protocol):
    def sign(
        self, digest: bytes, *, hash: str,
        padding: Padding | None = None, salt_length: int | None = None,
    ) -> bytes
```

The private-key contract. `digest` is already hashed with `hash`, one of
`HASHES` (`"sha1"`, `"sha224"`, `"sha256"`, `"sha384"`, `"sha512"`). For an
RSA key `padding` is `Padding.PKCS1V15` or `Padding.PSS`; with PSS,
`salt_length` is in bytes and MGF1 uses `hash`. For an EC key `padding` and
`salt_length` are `None` and the result must be a DER-encoded ECDSA
signature. Any exception fails the handshake; it is logged at WARNING on the
`sslcontext` logger. `sign` runs on the thread doing the handshake while
OpenSSL is mid-operation, so it must not use the same `ssl.SSLContext`.
TLS 1.3 always asks RSA keys for PSS.

```python
class Padding(enum.Enum):
    PKCS1V15 = "pkcs1v15"
    PSS = "pss"

@dataclass(frozen=True)
class Identity:
    certificate: bytes          # DER
    signer: Signer
    chain: tuple[bytes, ...] = ()   # DER, issuer of certificate first
    label: str = ""
```

`Identity` raises `TypeError` when `certificate`/`chain` are not DER bytes
or `signer` has no `sign` method.

```python
def load_identity(context: ssl.SSLContext, identity: Identity) -> None
```

Makes the identity the context's certificate and key; each handshake
signature is delegated to `identity.signer`. RSA and EC certificates only.
The signer is kept alive until `context` is garbage-collected. Raises
`CredentialError` (malformed certificate), `UnsupportedOpenSSLError`
(interpreter's OpenSSL cannot host the signer), `TypeError`. Works on
OpenSSL 1.1.1 and 3.x.

## Test helpers (`sslcontext.testing`)

```python
class SoftwareSigner:
    def __init__(self, key: bytes | str, password: str | bytes | None = None)
    calls: list[tuple[str, Padding | None, int | None]]
    def sign(self, digest, *, hash, padding=None, salt_length=None) -> bytes

def software_identity(certificate, key, password=None) -> Identity
```

`SoftwareSigner` is a `Signer` over an in-memory PEM/DER key, signing with
OpenSSL; `calls` records every `(hash, padding, salt_length)` it was asked
for. `software_identity` wraps a PEM certificate (+ chain) and key into an
`Identity`. Meant for tests and as the reference a keystore signer must
match.

## Exceptions

All in `sslcontext.exceptions`, re-exported from the root.

| Class | Bases | Raised when |
| --- | --- | --- |
| `SSLContextError` | `Exception` | base of everything below |
| `UnsupportedOpenSSLError` | `SSLContextError` | the interpreter's OpenSSL cannot be driven: LibreSSL, OpenSSL < 1.1.1, a static `_ssl` that hides its symbols, or an unrecognised `SSLContext` layout |
| `CredentialError` | `SSLContextError`, `ValueError` | malformed certificate/key, wrong password, key/certificate mismatch |
| `IdentityNotFoundError` | `SSLContextError`, `LookupError` | no keystore entry matched a query |
| `KeystoreError` | `SSLContextError`, `OSError` | the keystore refused or failed an operation |
| `SigningError` | `SSLContextError` | a signer failed during a handshake |

## Gotchas

- `sslcontext` drives the OpenSSL that the running interpreter's `ssl` module
  loaded, through ctypes. It does not work with LibreSSL (Apple's
  `/usr/bin/python3`) and needs OpenSSL 1.1.1 or later.
- `SSL_CTX_check_private_key` compares public keys only, so an `Identity`
  whose signer holds a different private key than the certificate loads
  fine and fails at the peer, which rejects the signature.
- On first `load_identity`, `sslcontext` registers an OpenSSL provider named
  `sslcontext` in the default library context (OpenSSL 3), or creates an
  engine with id `sslcontext` (OpenSSL 1.1). Either serves only the keys
  `load_identity` creates; every other key keeps using OpenSSL's own code.
- PKCS#12 bundles encrypted with legacy algorithms (RC2, 3DES; common in old
  `.pfx` exports) need OpenSSL's `legacy` provider, which many Python builds
  do not ship; such a bundle fails with `CredentialError`. Re-export it with
  AES, or convert it to PEM.
