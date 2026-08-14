# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/) starting at 1.0.0 — everything before that is
`0.x.y`-SNAPSHOT and may break between minor versions without notice, per semver's own pre-1.0 rule.

## [Unreleased]

## [0.1.1] - 2026-08-14

### Added
- `LICENSE` file at repo root (full Apache License 2.0 text) — previously only referenced from the
  README, not actually present.
- `pom.xml`: top-level `<organization>` element (was only present under `<developers>`).
- `eudi-rp-demo`: `robots.txt`, `sitemap.xml`, and a meta description for the live demo.
- Brainpool curve support (BrainpoolP256r1, BrainpoolP384r1) for RP access certificates — see
  `eudi-rp-mock-wallet/COMPATIBILITY.md` for what's verified and what's still open.

### Fixed
- `PresentationRequestBuilder.signingAlgorithm()` declared `ES256` for **any** EC signing key
  regardless of curve — a P-384 or P-521 RP certificate (not just Brainpool) would sign correctly
  but mislabel the JWS `alg` header, which a strict wallet should reject. Now selects `ES256`/
  `ES384`/`ES512` by the key's actual field size; BrainpoolP512r1 is explicitly rejected rather than
  guessed, since it doesn't fit any registered JOSE `alg`.
- `DefaultCertificateValidator`'s own chain-of-trust validation silently couldn't handle
  non-NIST-curve certificates at all (the JDK's default PKIX path validator, and even BouncyCastle's
  PKIX SPI when it delegates back to `X509CertImpl.verify()`, resolve ECDSA via the ambient global
  JCA provider order, which doesn't recognize Brainpool). Fixed by re-encoding certificates through
  BouncyCastle's own `CertificateFactory` before validation — no global JVM provider state changed.

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
