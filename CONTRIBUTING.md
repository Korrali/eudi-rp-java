# Contributing

This is a single-maintainer, unpaid, best-effort project (see the README's "Maintenance scope"
section). That shapes what kind of contribution is welcome.

## Welcome

- Bug reports, especially with a reproducible certificate/spec-compliance failure.
- Pull requests that fix a real bug, improve test coverage (particularly real fixtures, not
  mocks — see `eudi-rp-core`'s malformed-certificate fixtures for the standard this project holds
  itself to), or correct a factual error against a cited spec section.
- Corrections to DESIGN.md's citations, especially the open ARF version discrepancy noted in §0.

## Likely declined

- Feature requests that expand scope beyond certificate lifecycle + SD-JWT VC presentation flow.
  Certificate lifecycle done excellently beats every feature done partially — that's not a slogan,
  it's the actual design constraint (see DESIGN.md).
- mdoc/ISO 18013-5 support. Explicitly out of scope, not deferred (DESIGN.md §3/§6).
- New provider implementations beyond the local-file defaults (hosted/networked
  `TrustListProvider`, `RevocationChecker`, `RegistrationMetadataProvider` implementations). The
  interfaces are the extension point — write your own implementation against them rather than
  asking this project to ship one, per DESIGN.md §4's bounded-maintenance rule.
- Anything that adds a new runtime dependency without a strong reason. Every dependency is a future
  support question.

## Before opening a PR

1. `mvn -pl eudi-rp-core,eudi-rp-spring-boot-starter,eudi-rp-mock-wallet,eudi-rp-demo -am test`
   passes.
2. `grep -r org.springframework eudi-rp-core/src` returns nothing — `eudi-rp-core` stays hexagonal,
   zero Spring imports, verifiably.
3. If you touched certificate parsing/validation, add a real fixture-backed test, not a mock. See
   `MalformedCertificateFixtureGenerator`'s javadoc for how the existing malformed-certificate
   fixture was empirically chosen (several candidates were tried and rejected before landing on one
   that actually reproduces the strict-vs-tolerant split).
4. Cite the spec section or source file for any protocol-shape claim. "It should probably work like
   X" is not a citation.

## Code style

Standard Java conventions, no framework-specific formatter mandated. Match what's already there.
