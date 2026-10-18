# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The `sslcontext` command (extra `cli`): `list` and `show` keystore
  identities, `probe URL` to see a server's certificate request, the
  candidates and the certificate sent.
- Apple's `/usr/bin/python3` (LibreSSL 2.8) is supported: keystore
  identities sign through it over TLS 1.2, and client certificates are
  chosen when the server asks.
- `system_context()`: a client context that behaves like the system's
  browser: OS verification through truststore (a dependency on Python 3.10+) and
  client certificates chosen when the server asks by a
  `ClientCertificateSelector` over `system_sources()` (the Windows
  Personal store, the default PKCS#11 module elsewhere), filtered as a
  browser filters (validity, client-authentication usage, key type, the
  CAs the server names) and picked by remembered choice, `AutoSelectRule`
  rules, the Edge/Chrome/Chromium `AutoSelectCertificateForUrls` policy
  (`browser_policies()`), a `choose` callback or the only candidate.
- `create_context()` builds a verifying `ssl.SSLContext` from
  `verify`/`cafile`/`capath`/`cadata`, TLS version bounds and ALPN.
- `load_pem()` and `load_pkcs12()` load a certificate, chain and key from
  memory, with no temporary files.
- `Identity`, the `Signer` protocol and `load_identity()`: a certificate whose
  private key is used only through a signer, for every handshake signature
  (RSA PKCS#1 v1.5 and PSS, ECDSA; TLS 1.2 and 1.3). OpenSSL 1.1.1 and 3.x.
- `sslcontext.testing.SoftwareSigner` and `software_identity()`.
- `sslcontext.issuing`: `CertificateAuthority` (create, or load from PEM;
  optional X.509 name constraints; encrypted key export) issuing server
  certificates (`IssuedCertificate`) that pass strict verification, made with
  the interpreter's own OpenSSL.
- `Identity.info` (`CertificateInfo`: subject, issuer, serial, validity,
  SHA-1/SHA-256 thumbprints, key type and size).
- `sslcontext.backends`: the `Backend` contract with thumbprint, subject,
  issuer, label and validity queries, a registry (`names()`, `get()`,
  `register_backend()`, entry-point group `sslcontext.backends`), and
  `CNGBackend` for Windows certificate stores: non-exportable, TPM and
  smart-card keys through CNG, and legacy CryptoAPI CSP keys (PKCS#1 v1.5,
  TLS 1.2).
- PIN and password sources: `pin=` on every backend takes a PIN,
  `KEYSTORE_PROMPT`, or a callback receiving a `PinRequest` (backend, token,
  certificate, purpose); with no PIN, an operation needing one fails at once
  instead of showing a dialog or waiting on a PIN pad. `load_pem()`,
  `load_pkcs12()` and `SoftwareSigner` accept a password callable, called
  only for an encrypted key.
- `PKCS11Backend` for PKCS#11 tokens: smart cards (real and virtual, through
  OpenSC), HSMs, TPMs and software tokens. RSA PKCS#1 v1.5 and PSS and
  ECDSA, PINs from the PIN source (see below),
  per-signature login for `CKA_ALWAYS_AUTHENTICATE` keys, and recovery after
  the card is removed and reinserted. `SSLCONTEXT_PKCS11_MODULE` selects the
  default module.

### Changed

- Rewritten from scratch. `sslcontext` now loads certificates and keystore-held
  private keys into the standard library's `ssl.SSLContext`; nothing of the
  1.x API (`SSLContext`/`SSLSocket` interfaces, `PyOpenSSLContext`,
  `SSLContextProvider`) remains. The 1.x companions `sslcontext-factory`,
  `openssl-engine` and `openssl-engine-capi` are superseded: OpenSSL 4 removed
  the ENGINE API they were built on.

[Unreleased]: https://github.com/jose-pr/sslcontext/commits/main
