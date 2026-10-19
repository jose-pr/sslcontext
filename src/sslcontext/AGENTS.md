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

`pip install sslcontext`. One dependency, `truststore` (Python 3.10+ only),
for `system_context()`'s OS verification; the extra `cli` adds the
`sslcontext` command (duho).

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
    ca: CertificatesLike | None = None,
    certificate: CertificatesLike | None = None,
    key: KeyLike | None = None,
    password: PasswordSource = None,
    identity: Identity | None = None,
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
`ca`/`cafile`/`capath`/`cadata` when given, else the platform's default
store; `ca` with `cadata` is a `ValueError`. `certificate`, `key` and
`password` load the context's own certificate as `load_pem` does (a `key`
alone is a `ValueError`); `identity` as `load_identity` does. A client
context with a certificate is an mTLS context in one call:

```python
ctx = sslcontext.create_context(ca="ca.pem", certificate="client.pem", key="client.key")
```

`VerifyLike` is the exported alias for the `verify` type.

### Certificate and key sources

```python
CertificateLike = str | bytes | os.PathLike | <has open()> | <has read()> | cryptography.x509.Certificate
CertificatesLike = CertificateLike | list[CertificateLike] | tuple[CertificateLike, ...]
KeyLike = str | bytes | os.PathLike | <has open()> | <has read()> | <cryptography private key>
```

Every certificate, key, CA and bundle argument takes any of these. A `str`
holding a PEM header (`-----BEGIN `) is PEM text; any other `str` is a path.
Bytes are PEM or DER. `os.PathLike` is a path; an object with `open()`
(`pathlib.Path`, pathlib-next paths, `zipfile.Path`,
`importlib.resources` files) is opened `"rb"`; an object with `read()` is
read (text is encoded as ASCII). A `cryptography` certificate (it has
`public_bytes` and `fingerprint`) or private key (it has `private_bytes`;
written unencrypted, in memory only) is converted; `cryptography` is never
imported otherwise. A list holds several sources in order: a CA bundle, or
a leaf followed by its chain; an empty list is a `ValueError`. Anything else
is a `TypeError`; a file that cannot be read raises its `OSError` (a
mistyped path in a `str` is `FileNotFoundError`, never "not PEM").

## The system's context: OS trust and browser-like client certificates (`sslcontext`)

```python
def system_context(*, selector: ClientCertificateSelector | bool | None = None,
                   pin: PinSource = None, verify=None, ca=None, cafile=None,
                   capath=None, cadata=None, certificate=None, key=None,
                   password=None, identity=None, minimum_version=None,
                   maximum_version=None, alpn=None) -> ssl.SSLContext
def system_selector(*, pin: PinSource = None, choose: Chooser | None = None,
                    rules: Iterable[AutoSelectRule] = (), browser_policy: bool = True,
                    remember: bool = True, cache_ttl: float = 60.0
                    ) -> ClientCertificateSelector
def system_sources(*, pin: PinSource = None) -> list[Backend]
```

`system_context()` is a client context that behaves like the system's
browser. Servers are verified by the operating system (a
`truststore.SSLContext`: CryptoAPI on Windows, the Security framework on
macOS) on Python 3.10+, and by OpenSSL over the default store on 3.9
(on macOS with the Keychain's trust anchors added: the system roots and
those an administrator or the user trusted, none marked "deny")
(truststore needs 3.10); `verify`/`ca`/`cafile`/`capath`/`cadata` replace
that trust exactly as for `create_context`. When a server asks for a client
certificate, `selector` answers (default `system_selector(pin=pin)`;
`False`: never send one). A `certificate` (+ `key`, `password`) or
`identity` is loaded as by `create_context` and is then the certificate
sent: the default selector is not installed then (pass `selector=True` or
one of your own to have both).
`post_handshake_auth` is on. Nothing is opened until a server asks; one
context serves every server and every thread, so share it (urllib3 keys its
pools by context). `system_sources()`: Windows `CNGBackend("MY")` (smart-card
certificates appear there while the card is inserted); macOS
`KeychainBackend()` (the user's keychains and smart cards); elsewhere
`PKCS11Backend()` when its default module exists (p11-kit's proxy on Linux),
else `[]`.

```python
class ClientCertificateSelector:
    def __init__(self, sources: Iterable[IdentitySource], *, choose: Chooser | None = None,
                 rules: Iterable[AutoSelectRule] = (), browser_policy: bool = False,
                 remember: bool = True, cache_ttl: float = 60.0)
    def install(self, context: ssl.SSLContext) -> None   # client contexts; replaces a previous one
    def candidates(self, request: CertificateRequest) -> list[Identity]
    def select(self, request: CertificateRequest) -> Identity | None
    def identities(self) -> list[Identity]               # every source, cached cache_ttl s
    def policies(self) -> tuple[AutoSelectRule, ...]     # browser rules, cached; () unless browser_policy
    def refresh(self) -> None                            # list sources and policies again
    def forget(self, host: str | None = None) -> None    # drop remembered choices

IdentitySource = Backend | Identity | Callable[[], Iterable[Identity]]
Chooser = Callable[[CertificateRequest, list[Identity]], Identity | None]

@dataclass(frozen=True)
class CertificateRequest:
    host: str | None                  # the SNI the client sent
    authorities: tuple[str, ...]      # RFC 4514 names of acceptable CAs; () = any
    authorities_der: tuple[bytes, ...]
    key_types: frozenset[str]         # "rsa" / "ec" the server's signature algorithms allow
    rsa_pss_required: bool            # TLS 1.3, or no PKCS#1 offered
    tls_version: str                  # "TLSv1.3", "TLSv1.2", ...
```

The selector answers each certificate request during the handshake, on that
connection only. Candidates are what a browser offers: valid now; no
extended key usage, `clientAuth` or `anyExtendedKeyUsage`, and
`digitalSignature` when key usage is present; a key type in `key_types` (an
RSA key whose signer has `supports_pss == False` is left out when PSS is
required); issued under a named authority (the leaf's issuer, or any subject
or issuer in its chain) when the server names any. Newest expiry first. The
choice, in order: the identity remembered for the host (when still a
candidate), the first `rules` entry matching the host with a matching
candidate, the same over `browser_policies()` when `browser_policy`, then
`choose(request, candidates)`; with no `choose`, the only candidate when
there is exactly one. Otherwise no certificate is sent (logged at INFO) and
an identity loaded with `load_identity` (if any) is sent instead, else none;
the server decides. A source that raises `KeystoreError`/`OSError` while
listing is logged at WARNING and skipped; an identity whose certificate or
key cannot be examined is skipped. An exception from `choose`, or a result
that is not one of the candidates, fails that handshake (`ssl.SSLError`,
logged at WARNING). `install` keeps the selector alive as long as the
context. Sources are listed at most every `cache_ttl` seconds.

```python
@dataclass(frozen=True)
class AutoSelectRule:
    pattern: str
    issuer: str | Mapping[str, str] | None = None
    subject: str | Mapping[str, str] | None = None
    def matches_host(self, host: str | None) -> bool
    def matches(self, identity: Identity) -> bool

def browser_policies() -> list[AutoSelectRule]
def rules_from_policy(entries: Iterable[str | Mapping]) -> list[AutoSelectRule]
```

`AutoSelectRule` is Chrome's and Edge's `AutoSelectCertificateForUrls` entry:
`pattern` `example.com` (that host), `[*.]example.com` (it and subdomains),
`*.example.com` (subdomains), `*` (any); a scheme, port or path in it is
ignored (the request knows only the host). `issuer`/`subject`: a mapping of
RFC 4514 attributes to exact values (`{"CN": "Corp CA", "OU": "Staff"}`), or
a string matched case-insensitively inside the whole name.
`browser_policies()` reads the policy set for Edge, Chrome and Chromium:
Windows registry (`HKLM` then `HKCU`, `SOFTWARE\Policies\{Microsoft\Edge,
Google\Chrome,Chromium}\AutoSelectCertificateForUrls`, values in numeric
order), Linux `/etc/opt/{edge,chrome}/policies/managed/*.json` and
`/etc/chromium/policies/managed/*.json`, macOS `/Library/Managed
Preferences/[<user>/]{com.microsoft.Edge,com.google.Chrome,
org.chromium.Chromium}.plist`. `rules_from_policy` parses entries
(`{"pattern": ..., "filter": {"ISSUER": {...}, "SUBJECT": {...}}}`, as JSON
text or objects); a malformed entry is skipped, as the browsers skip it.

```python
import sslcontext, urllib.request

ctx = sslcontext.system_context()      # share it
urllib.request.urlopen("https://intranet.example", context=ctx)

selector = sslcontext.system_selector(
    rules=[sslcontext.AutoSelectRule("[*.]corp.example", issuer={"CN": "Corp CA"})],
    choose=lambda request, candidates: candidates[0],   # instead of a dialog
)
ctx = sslcontext.system_context(selector=selector)
```

## Loading credentials from memory (`sslcontext`)

```python
def load_pem(
    context: ssl.SSLContext,
    certificate: CertificatesLike,
    key: KeyLike | None = None,
    password: PasswordSource = None,
) -> None
```

Makes `certificate` (+ chain) and `key` the context's identity; nothing is
written to disk. `certificate` is the leaf then its chain: PEM holding them
in order, one DER certificate, or a list of sources in that order; or one
PKCS#12 bundle (`.p12`/`.pfx`, recognised by its DER shape, whatever the file
is called), loaded as `load_pkcs12` loads it, with `password` and without
`key` (a `key`, or a bundle in a list, is a `ValueError`). `key` is a PEM or
DER private key (DER: PKCS#8, encrypted or not, or the traditional RSA/EC
form) or a `cryptography` key; omitted, it is read from the first
certificate source (a combined PEM). `password` decrypts an encrypted key or
bundle; see [PINs and passwords](#pins-and-passwords-sslcontext).
`create_context(certificate=..., password=...)` and `system_context` take the
same, so `create_context(certificate="client.p12", password="...")` is an
mTLS context.

```python
def load_pkcs12(
    context: ssl.SSLContext,
    data: bytes | str | os.PathLike | <has open()> | <has read()>,
    password: PasswordSource = None,
) -> None
```

Loads the key, certificate and chain of a PKCS#12 (`.p12`/`.pfx`) bundle,
given as its bytes or where it is (a `str` is a path here).

Both raise `CredentialError` for malformed data, a wrong or missing password,
or a key that does not match the certificate, and `TypeError` when `context`
is not an `ssl.SSLContext`. An identity of one key type (RSA, EC) replaces a
previously loaded identity of the same type; identities of different types
coexist and OpenSSL picks per handshake. `BytesOrText` (bytes or text) is
kept as an exported alias. Every loader (and `install`) configures
a `truststore.SSLContext` through the inner context its connections use.

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

## PINs and passwords (`sslcontext`)

Nothing waits on a user unless the caller chose it. Without a PIN, an
operation that needs one fails at once with `KeystoreError`; a keystore's own
prompt (Windows' PIN or consent dialog, a reader's PIN pad) is used only when
the caller passes or returns `KEYSTORE_PROMPT`.

```python
class Prompt(enum.Enum):
    KEYSTORE = "keystore"
KEYSTORE_PROMPT = Prompt.KEYSTORE

@dataclass(frozen=True)
class PinRequest:
    backend: str          # "cng" or "pkcs11"
    token: str            # PKCS#11 token label; CNG: the certificate's friendly name
    certificate: str      # subject of the certificate whose key needs it; "" when listing
    purpose: str          # "list", "sign" or "per-signature"
    keystore_prompt: bool # whether KEYSTORE_PROMPT can work (PIN pad / Windows dialog)

PinCallback = Callable[[PinRequest], str | Prompt | None]
PinSource = str | Prompt | PinCallback | None
PasswordSource = str | bytes | os.PathLike | <has open()> | <has read()> | Callable[[], str | bytes | None] | None
```

A backend's `pin=` takes a `PinSource`: the PIN; `KEYSTORE_PROMPT`; a
callback, which decides per request how to get the PIN (prompt, read a vault,
cache, decline) and returns it, `KEYSTORE_PROMPT`, or `None` to decline; or
`None`, meaning no PIN. The callback is consulted only when the keystore
actually needs the user, and every time it does: `purpose="list"` (logging
in to see a token's private keys; declining just lists what is visible),
`"sign"` (before signing; declining fails the signature), `"per-signature"`
(the key demands the PIN for every signature, `CKA_ALWAYS_AUTHENTICATE`). It
runs on the thread doing the TLS handshake; an exception it raises fails that
handshake (or the listing) and propagates from `identities()`. A callback
returning anything else raises `TypeError` (the message never includes the
value). `PinRequest` never holds a PIN.

Loaders take a `PasswordSource` for encrypted keys and PKCS#12 bundles: the
password as `str` (UTF-8) or `bytes` (a `str` is always the password itself,
never a path); a file holding it (`os.PathLike`, or an object with `open()`
or `read()`: its first line, without the line ending, as OpenSSL's `-passin
file:` reads it); or a callable. A file or callable is consulted only if the
key turns out to be encrypted (a callable returning `None` fails with
`CredentialError`). OpenSSL's terminal passphrase prompt is never used.

```python
def ask(request: sslcontext.PinRequest):
    if request.purpose == "list":
        return None                       # list without logging in
    return getpass(f"PIN for {request.token} ({request.certificate}): ")

backend = PKCS11Backend(pin=ask)
```

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
| `pkcs11` | `PKCS11Backend` | PKCS#11 tokens: smart cards (real or virtual) through OpenSC, HSMs, TPMs (tpm2-pkcs11), SoftHSM; any OS |
| `keychain` | `KeychainBackend` | the macOS Keychain: the user's keychains, and smart cards through CryptoTokenKit |

```python
class CNGBackend(Backend):
    def __init__(self, store: str = "MY", location: str = "current_user", *,
                 pin: PinSource = None)
```

`store` is a system store name (`"MY"` = Personal). `location` is
`"current_user"` or `"local_machine"` (else `ValueError`). Keys are opened
and used silently; only when Windows reports that a key needs the user
(`NTE_SILENT_CONTEXT`, a smart card without its PIN) is `pin` consulted
(`purpose="sign"`): a PIN is set on the key (`SmartCardPin`) and the
signature retried silently; `KEYSTORE_PROMPT` reopens the key with Windows'
dialogs allowed; no PIN fails with `KeystoreError` (`errno.EACCES`). A wrong
PIN is never retried. `label` is the certificate's Windows friendly name. The chain is what Windows can build from its stores without
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

```python
class PKCS11Backend(Backend):
    def __init__(self, module: str | os.PathLike | None = None, *,
                 token: str | None = None, slot: int | None = None,
                 pin: PinSource = None)
    def tokens(self) -> list[str]
```

`module` is the PKCS#11 library; default: `SSLCONTEXT_PKCS11_MODULE`, else
p11-kit's proxy (`p11-kit-proxy.so`, every module the system configured) on
Linux, else OpenSC (`opensc-pkcs11.dll`/`.so`). Missing → `KeystoreError`
(`errno.ENOENT`). `token` keeps only the token with that label or serial
number, `slot` only that slot id; uninitialised tokens are skipped.
`tokens()` lists the matching token labels.

`pin` is a `PinSource`. It is consulted only when the token is not
already logged in for this process (and for every signature by an
always-authenticate key). `KEYSTORE_PROMPT` logs in through the reader's PIN
pad (`CKF_PROTECTED_AUTHENTICATION_PATH`); on a token without one it fails
at once ("has no PIN pad"). With no PIN, a login-required token lists the
certificates that carry a `CKA_ID` (keys may be hidden until login) and its
signers fail at once with `KeystoreError` ("none was given"). A wrong PIN
raises `KeystoreError` naming `CKR_PIN_INCORRECT` and is not retried; `errno`
holds the `CKR_*` value.

An identity is a `CKO_CERTIFICATE` (X.509) and the `CKO_PRIVATE_KEY` with the
same `CKA_ID`; `label` is the certificate's `CKA_LABEL`; the chain is the
issuers found among the token's own certificates, root excluded. Signing uses
`CKM_RSA_PKCS` (over a DigestInfo), `CKM_RSA_PKCS_PSS` and `CKM_ECDSA`;
`signer.supports_pss` reports whether the token offers PSS. A key with
`CKA_ALWAYS_AUTHENTICATE` (a PIV card's signature key, slot 9C) gets
`C_Login(CKU_CONTEXT_SPECIFIC)` before every signature. Each signer keeps
one session, serialised by a lock. When the card is removed and reinserted,
the next signature finds the token again by label and serial number, opens
a new session and logs in again; it fails with `KeystoreError` if the token
is still absent.

Modules are loaded once per path, initialised with `CKF_OS_LOCKING_OK`, and
never finalised.

```python
from sslcontext.backends import PKCS11Backend

backend = PKCS11Backend("/usr/lib64/pkcs11/opensc-pkcs11.so",
                        pin=lambda request: getpass(f"PIN for {request.token}: "))
sslcontext.load_identity(ctx, backend.find_identity(label="Certificate for PIV Authentication"))
```

```python
class KeychainBackend(Backend):
    def __init__(self, keychain: str | os.PathLike | None = None, *,
                 pin: PinSource = None)
```

Searches the user's keychain search list (login, System) and the
identities smart cards expose (CryptoTokenKit), or only the keychain file
`keychain` (it must exist and be unlocked; missing: `KeystoreError`,
`errno.ENOENT`). `label` is the certificate's subject summary (usually its
common name); the chain is what macOS builds without network access, root
excluded. Signing goes through `SecKeyCreateSignature` (RSA PKCS#1 v1.5 and
PSS, the salt as long as the digest; ECDSA), silently first: only when macOS
reports that the key needs the user (`errSecInteractionNotAllowed`: an
access prompt, a smart-card PIN, Touch ID) is `pin` consulted
(`purpose="sign"`): `KEYSTORE_PROMPT` retries with macOS's own dialog
allowed; anything else fails at once with `KeystoreError` (`errno.EACCES`),
since a PIN value cannot be handed to the Keychain. On another system,
`identities()` raises `KeystoreError` (`errno.ENOSYS`).

```python
from sslcontext.backends import KeychainBackend

sslcontext.load_identity(ctx, KeychainBackend().find_identity(subject="alice"))
```

## Issuing certificates (`sslcontext.issuing`)

```python
class CertificateAuthority:
    def __init__(self, certificate: bytes | str, key: bytes | str, password: PasswordSource = None)
    @classmethod
    def create(cls, common_name: str, *, permitted: Iterable[str] = (), days: float = 3650,
               key_type: str = "ec") -> CertificateAuthority
    certificate: bytes                 # CA certificate, PEM: what clients trust
    der: bytes
    info: CertificateInfo
    def private_key_pem(self, password: str | bytes | None = None) -> bytes
    def issue(self, names: Iterable[str], *, days: float = 30, key_type: str = "ec",
              common_name: str | None = None) -> IssuedCertificate
    def server_context(self, names: Iterable[str], **create_context_options) -> ssl.SSLContext

@dataclass(frozen=True)
class IssuedCertificate:
    certificate: bytes    # leaf, PEM
    key: bytes            # PKCS#8 PEM, unencrypted (not in repr)
    chain: bytes          # the CA certificate, PEM
    info: CertificateInfo # property
    def load_into(self, context: ssl.SSLContext) -> None
```

Keys and certificates come from the interpreter's own OpenSSL (1.1.1 and
3.x); no third-party package. `create` makes a self-signed CA (critical
`basicConstraints CA:TRUE, pathlen:0`, `keyUsage keyCertSign,cRLSign`, SKI).
`permitted` adds critical RFC 5280 name constraints: DNS names, where
`corp.example`, `.corp.example` and `*.corp.example` all mean the domain and
its subdomains, and IP networks (`10.0.0.0/8`); a name that cannot be a
constraint (`re:...`, a wildcard inside a label) raises `ValueError`.
`key_type` is `"ec"` (P-256) or `"rsa"` (2048), else `ValueError`. Loading
from PEM raises `CredentialError` for malformed input or a key that is not
the certificate's. `issue` makes a leaf with a fresh key for DNS names and
IP addresses (SAN), `serverAuth`+`clientAuth`, SKI and AKI, valid from an
hour ago, so strict verification (the default from Python 3.13) accepts it;
`ValueError` for no names. `private_key_pem(password)` exports the CA key,
AES-256 encrypted when a password is given; store it as a secret. The CA
key lives in memory; keystore-held CA keys are not supported.

## Command line (`sslcontext`, extra `cli`)

```
sslcontext list  [SOURCE] [--all] [--json]
sslcontext show  [SOURCE] QUERY
sslcontext probe [SOURCE] URL [--cafile F] [-k] [--ask] [--no-policy] [--timeout S] [--json]
SOURCE: [-b system|cng|pkcs11|<registered>] [--store MY] [--location current_user|local_machine]
        [--module PATH] [--token LABEL] [--pin none|ask|keystore]
```

`list` prints the identities whose key is usable (valid ones unless
`--all`): SHA-1, expiry, key, `client`/`no-client` (whether a browser would
offer it for client authentication), subject, issuer. `show` prints one in
full as JSON, by SHA-1/SHA-256 (case, spaces, colons ignored) or a subject
substring; none matching exits 1. `probe` connects with `system_context()`
over the chosen sources (`https://host[:port]/path` also sends `HEAD` and
prints the status line; `host[:port]` is TLS only) and reports the server's
certificate, each certificate request (accepted issuers, the candidates,
what was sent); a failed connection is reported and exits 1. `--ask` picks
on the terminal when several fit; `--pin ask` reads a PIN with `getpass`
(never for listing), `--pin keystore` uses `KEYSTORE_PROMPT`; the default
never waits. `-b system` is `system_sources()`. Exit codes: 0 done, 1 failed
(or the extra is missing), 2 wrong invocation (an unknown backend, a scheme
other than `https`). `sslcontext.cli.main(argv=None) -> int` runs it in
process; importing `sslcontext.cli` needs no duho.

## Test helpers (`sslcontext.testing`)

```python
class SoftwareSigner:
    def __init__(self, key: bytes | str, password: PasswordSource = None)
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
| `UnsupportedOpenSSLError` | `SSLContextError` | the interpreter's TLS library cannot be driven: OpenSSL < 1.1.1, a static `_ssl` that hides its symbols, or an unrecognised `SSLContext` or LibreSSL structure layout |
| `CredentialError` | `SSLContextError`, `ValueError` | malformed certificate/key, wrong password, key/certificate mismatch |
| `IdentityNotFoundError` | `SSLContextError`, `LookupError` | no keystore entry matched a query |
| `KeystoreError` | `SSLContextError`, `OSError` | the keystore refused or failed an operation |
| `SigningError` | `SSLContextError` | a signer failed during a handshake |

## Environment variables

| Variable | Sets | Default |
| --- | --- | --- |
| `SSLCONTEXT_PKCS11_MODULE` | the PKCS#11 module `PKCS11Backend()` loads when `module` is not given | p11-kit proxy on Linux, OpenSC elsewhere |

## Gotchas

- `sslcontext` drives the TLS library that the running interpreter's `ssl`
  module loaded, through ctypes: OpenSSL 1.1.1 or later, or LibreSSL 2.8
  (Apple's `/usr/bin/python3`). On LibreSSL there is no TLS 1.3 (so no
  RSA-PSS), and a `ClientCertificateSelector` sees the server's CA names but
  not its signature algorithms, sends the leaf without its chain, and is
  not asked when the context already holds a loaded identity.
- A selector, like a `choose` callback, runs inside the handshake on the
  thread doing it (in asyncio, the event loop's); the first request lists
  the sources, which can open a keystore. Listing is cached for
  `cache_ttl`; call `identities()` beforehand to warm it.
- PIN callbacks, and with `KEYSTORE_PROMPT` the keystore's own dialogs, run
  inside the TLS handshake on the thread doing it; in asyncio a callback that
  waits for a person blocks the event loop. Without either, nothing waits.
- PKCS#11 login state belongs to the process and the token: once any
  session logged in, later logins succeed without checking the PIN, until
  every session on that token is closed.
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
