# sslcontext — contributor orientation

| Shipped header | Covers |
| --- | --- |
| [`src/sslcontext/AGENTS.md`](src/sslcontext/AGENTS.md) | the whole public API |

## Layout

- `src/sslcontext/` — the package. `_openssl/` binds the libssl/libcrypto that
  the running Python's `_ssl` module loaded; nothing else touches OpenSSL.
- `tests/` — unit tests and an in-process TLS server; `tests/data/` holds
  committed test certificates (never real credentials).
- `tests/integration/` — tests that create and remove real keystore entries.

## Environment

One venv per interpreter in `.pyvenv/<version>-<os>-<arch>/`, made with
`dotagents pyvenv` (latest) and `dotagents pyvenv 3.9` (the floor). On
Windows the 3.9 build links OpenSSL 1.1.1 and the latest links OpenSSL 3, so
the two venvs exercise the two OpenSSL glue paths.

```bash
.pyvenv/<tag>/Scripts/python -m pip install -e ".[dev]"
```

## Checks

Keystore tests in `tests/integration/` create what they need and skip,
naming it, when a tool is missing: the CNG tests need Windows PowerShell; the
PKCS#11 tests need SoftHSM2, OpenSC's `pkcs11-tool` and `openssl`, and the
virtual smart card tests also a card inserted by
`tests/integration/start_virtual_card.sh` (pcscd with vsmartcard's `vpcd`,
plus a built `virt_cacard`). On aarch64, `virt_cacard` spins at 100% CPU and
never connects unless `char c;` in `main()` is changed to `int c;` (its
`getopt()` result never equals -1 when `char` is unsigned).

```bash
.pyvenv/<tag>/Scripts/python -m pytest -q -rs
.pyvenv/<tag>/Scripts/black --check src tests
```

## Conventions

- Every function OpenSSL may call after interpreter shutdown is a native C
  function, never a ctypes callback: OpenSSL's own `atexit` cleanup runs after
  Python has finalised.
- The package binds only the OpenSSL that `_ssl` loaded. Loading a second
  libcrypto would mix objects from two heaps.

## Releasing

Tag `vX.Y.Z` after the changelog entry and the version bump land together;
the release workflow does the rest.
