# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `create_context()` builds a verifying `ssl.SSLContext` from
  `verify`/`cafile`/`capath`/`cadata`, TLS version bounds and ALPN.
- `load_pem()` and `load_pkcs12()` load a certificate, chain and key from
  memory, with no temporary files.
- `Identity`, the `Signer` protocol and `load_identity()`: a certificate whose
  private key is used only through a signer, for every handshake signature
  (RSA PKCS#1 v1.5 and PSS, ECDSA; TLS 1.2 and 1.3). OpenSSL 1.1.1 and 3.x.
- `sslcontext.testing.SoftwareSigner` and `software_identity()`.
- `Identity.info` (`CertificateInfo`: subject, issuer, serial, validity,
  SHA-1/SHA-256 thumbprints, key type and size).
- `sslcontext.backends`: the `Backend` contract with thumbprint, subject,
  issuer, label and validity queries, a registry (`names()`, `get()`,
  `register_backend()`, entry-point group `sslcontext.backends`), and
  `CNGBackend` for Windows certificate stores: non-exportable, TPM and
  smart-card keys through CNG, and legacy CryptoAPI CSP keys (PKCS#1 v1.5,
  TLS 1.2).
- `PKCS11Backend` for PKCS#11 tokens: smart cards (real and virtual, through
  OpenSC), HSMs, TPMs and software tokens. RSA PKCS#1 v1.5 and PSS and
  ECDSA, PINs given directly, by a callable or through a PIN pad,
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
