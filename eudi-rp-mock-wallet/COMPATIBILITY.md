# Compatibility notes

## What was tested

`MockWalletEndToEndTest` runs the full round trip using only this project's own code: a real
`PresentationRequestBuilder`-signed OpenID4VP request object (JAR, `typ=oauth-authz-req+jwt`, real
`x5c` chain) is handed to `MockWallet`, which parses it, builds a real SD-JWT VC presentation
(actual RSA-signed JWT + selective-disclosure digests/disclosures, not a stub), and the response is
verified end-to-end by `PresentationResponseVerifier` — declared-scope enforcement, DCQL shape,
`state` matching, disclosed-claim resolution all exercised for real. This passes.

## What was NOT attempted, and why

Per the brief for this phase: attempt an end-to-end test against the EU reference verifier
(`eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt`) or a reference wallet, and
document what worked and what didn't.

**This was not attempted in this session.** Being honest about why, rather than skipping the
question: the EU reference verifier is a separate Kotlin/Spring Boot service with its own database
and Docker Compose setup (HAProxy/TLS termination per its own docs), and a reference wallet is a
mobile app requiring either a physical device or an emulator with the app installed and configured
against a specific environment. Neither is something this coding session had the infrastructure to
stand up and drive interactively — doing this properly needs:

1. Cloning and running `eudi-srv-web-verifier-endpoint-23220-4-kt` locally (Docker Compose, per its
   own README) and pointing this library's request construction at its `/ui/presentations` and
   `/wallet/request.jwt/{id}` endpoints to check the request shape this library produces is
   something that verifier's own wallet-side counterpart would accept — or, symmetrically, pointing
   a request built by *that* service's wallet-facing endpoints at this library's response
   verification, to check compatibility in the other direction.
2. A reference wallet app (the EUDI reference wallet, or any wallet implementing HAIP-profiled
   OpenID4VP with `x509_hash`) on a device or emulator, scanning a QR this library generates, to
   check whether a real wallet accepts the request object this library signs — in particular
   whether the RP access certificate trust chain, the `x509_hash` client ID, and the DCQL query
   shape all pass a real wallet's validation, not just this library's own tests of itself.

Neither happened here. **What this means concretely**: everything verified so far proves internal
consistency — this library's request-builder output is exactly what this library's own
verifier/mock-wallet expect. It does not yet prove interoperability with an independent
implementation, which is the real test of spec compliance. Treat the "works" claim as scoped to
"works against itself, per the spec sections cited in DESIGN.md" until someone runs it against the
reference verifier or a real wallet.

## Recommended next step

Before shipping this as a compatibility claim anywhere public-facing, run the demo app (Phase 5)
against the EU reference verifier's wallet-facing endpoints, or against a real EUDI reference
wallet, and update this file with the actual result — pass, fail, or partial, with specifics.
