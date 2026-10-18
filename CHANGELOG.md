# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Rewritten from scratch. `sslcontext` now loads certificates and keystore-held
  private keys into the standard library's `ssl.SSLContext`; nothing of the
  1.x API (`SSLContext`/`SSLSocket` interfaces, `PyOpenSSLContext`,
  `SSLContextProvider`) remains. The 1.x companions `sslcontext-factory`,
  `openssl-engine` and `openssl-engine-capi` are superseded: OpenSSL 4 removed
  the ENGINE API they were built on.

[Unreleased]: https://github.com/jose-pr/sslcontext/commits/main
