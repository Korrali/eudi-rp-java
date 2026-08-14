# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/) starting at 1.0.0 — everything before that is
`0.x.y`-SNAPSHOT and may break between minor versions without notice, per semver's own pre-1.0 rule.

## [Unreleased]

### Added
- `LICENSE` file at repo root (full Apache License 2.0 text) — previously only referenced from the
  README, not actually present.
- `pom.xml`: top-level `<organization>` element (was only present under `<developers>`).

## [0.1.0] - 2026-08-13

### Added
- `eudi-rp-core`: RP access certificate loading (PKCS#12/JKS), PKIX chain validation, CRL + OCSP
  revocation checking, local file-based trust list, hot reload on validation failure, tolerant
  (BouncyCastle) X.509 parsing fallback with a real, empirically-verified malformed-certificate
  fixture, typed exceptions (expired/revoked/untrusted/malformed).
- `eudi-rp-core`: OpenID4VP presentation flow — DCQL request construction, JAR (RFC 9101) request
  signing with `x509_hash` client ID, declared-attribute-set scope enforcement, SD-JWT VC response
  parsing and verification.
- `eudi-rp-spring-boot-starter`: auto-configuration for the above from `eudirp.*` properties, plus
  an actuator health indicator for certificate validity and trust list freshness.
- `eudi-rp-mock-wallet`: a mock wallet producing real, spec-shaped OpenID4VP responses for testing
  without a live wallet.
- `eudi-rp-demo`: a presentation-flow demo plus the certificate failure simulator (expired, revoked,
  malformed, rotated-mid-session).
- `DESIGN.md`: Phase 0 research output, with citations to ARF, Topic X, CIR 2025/848, and OpenID4VP.

### Known gaps (see README "Honest limitations")
- mdoc/ISO 18013-5 not supported.
- Not tested against a real EUDI wallet or the EU reference verifier — see
  `eudi-rp-mock-wallet/COMPATIBILITY.md`.
