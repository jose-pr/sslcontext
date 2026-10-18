# `sslcontext` — public API header

Header-file-style reference for the `sslcontext` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is
self-contained. Development documentation lives with the source at
<https://github.com/jose-pr/sslcontext>.

Import everything from the root `sslcontext`, except the errors, which live in
`sslcontext.exceptions` and are re-exported from the root, the keystore
backends (`sslcontext.backends`) and the test helpers (`sslcontext.testing`).
Modules whose names start with `_` are private.

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
or `signer` has no `sign` method. `identity.info` (cached) decodes the
certificate into a `CertificateInfo`:

```python
@dataclass(frozen=True)
class CertificateInfo:
    subject: str        # RFC 4514, e.g. "CN=alice,O=Example"
    issuer: str
    serial: str         # upper-case hex
    not_before: datetime.datetime   # UTC, timezone-aware
    not_after: datetime.datetime
    sha1: str           # upper-case hex; Windows' "Thumbprint"
    sha256: str
    key_type: str       # "rsa", "ec" or "other"
    key_bits: int
    def valid_at(self, when: datetime.datetime | None = None) -> bool
```

A signer may carry `supports_pss: bool`. When it is `False` on an RSA
identity, `load_identity` restricts the context's own signatures to PKCS#1
v1.5 RSA and ECDSA (`SSL_CTX_set1_client_sigalgs_list`), so that identity
can only complete TLS 1.2.

```python
def load_identity(context: ssl.SSLContext, identity: Identity) -> None
```

Makes the identity the context's certificate and key; each handshake
signature is delegated to `identity.signer`. RSA and EC certificates only.
The signer is kept alive until `context` is garbage-collected. Raises
`CredentialError` (malformed certificate), `UnsupportedOpenSSLError`
(interpreter's OpenSSL cannot host the signer), `TypeError`. Works on
OpenSSL 1.1.1 and 3.x.

## Keystores (`sslcontext.backends`)

```python
class Backend(ABC):
    name: ClassVar[str]
    def identities(self) -> Iterator[Identity]          # abstract
    def find_identities(self, *, thumbprint=None, subject=None, issuer=None,
                        label=None, valid=True) -> list[Identity]
    def find_identity(self, **query) -> Identity
    def close(self) -> None
    # context manager: `with backend: ...`
```

A backend's constructor does no I/O. `identities()` yields every entry whose
private key is usable; it raises `KeystoreError` when the keystore cannot be
read. `find_identities` keeps entries matching every criterion given, newest
expiry first: `thumbprint` is SHA-1 or SHA-256 hex (case, spaces, colons
ignored); `subject`/`issuer` match a case-insensitive substring of the RFC
4514 name; `label` equals the keystore's own entry name (case-insensitive);
`valid=True` keeps only certificates valid now. `find_identity` returns the
first of those (the renewed certificate wins) or raises
`IdentityNotFoundError`. Identities stay usable after the backend is closed.

```python
def names() -> list[str]
def get(name: str) -> type[Backend]          # ValueError naming registered ones
def register_backend(name: str, backend: type[Backend] | str) -> None
```

Third-party backends register under the entry-point group
`sslcontext.backends` (`name = "module:Class"`). Names are lower case; a
taken name raises `ValueError`.

| Name | Class | Keystore |
| --- | --- | --- |
| `cng` | `CNGBackend` | Windows certificate stores; keys in CNG providers (software, TPM, smart cards and virtual smart cards via minidrivers) or legacy CryptoAPI CSPs |

```python
class CNGBackend(Backend):
    def __init__(self, store: str = "MY", location: str = "current_user", *,
                 pin: str | None = None, silent: bool = False)
```

`store` is a system store name (`"MY"` = Personal). `location` is
`"current_user"` or `"local_machine"` (else `ValueError`). `pin` is set on
smart-card keys instead of showing Windows' PIN dialog; `silent=True` makes a
key that needs a dialog fail instead. `label` is the certificate's Windows
friendly name. The chain is what Windows can build from its stores without
network access, root excluded. A key that only a legacy CryptoAPI CSP can use
has `signer.supports_pss == False` (TLS 1.2 only); legacy *software* CSP keys
open through CNG and support TLS 1.3. On a non-Windows system, `identities()`
raises `KeystoreError` (`errno.ENOSYS`).

```python
import sslcontext
from sslcontext.backends import CNGBackend

ctx = sslcontext.create_context()
sslcontext.load_identity(ctx, CNGBackend().find_identity(subject="alice"))
```

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
- Smart-card PIN dialogs and other keystore prompts happen inside the TLS
  handshake, on the thread doing it; in asyncio that blocks the event loop.
  Pass `pin=` or do the first handshake off the loop.
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
