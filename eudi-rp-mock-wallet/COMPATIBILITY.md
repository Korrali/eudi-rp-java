# Compatibility notes

## Verified against an independent implementation: the OIDF OpenID4VP conformance suite

The demo app (`eudi-rp-demo`, live at `eudirp.korrali.com`) was run against the OpenID
Foundation's official conformance suite (`certification.openid.net`), test plan
`oid4vp-1final-verifier-happy-flow`, variant `credential_format=sd_jwt_vc,
client_id_prefix=x509_hash, request_method=request_uri_signed, vp_profile=haip,
response_mode=direct_post.jwt`. This is a genuinely independent test: the suite acts as a real,
spec-driven simulated wallet, unrelated to this project's own `MockWallet`.

**Result: full pass.** Every protocol-level check reports `SUCCESS` — request object fetch and
parsing, `typ` header, x5c chain validation against the registered trust anchor, `x509_hash`
client ID matching, `aud`, nonce (URL-safety, length, entropy), `response_mode`, DCQL query shape,
`client_metadata.vp_formats_supported` and encryption parameters (HAIP `A128GCM`+`A256GCM`), the
encrypted response round trip, and `redirect_uri` in the direct_post response per HAIP §5.1. The
returned credential (issuer `https://www.certification.openid.net/test/a/eudi-rp-java`, `vct:
urn:eudi:pid:1`) was decrypted and its claims correctly resolved.

**First run found 5 real bugs, all fixed and re-verified**, not chased for the test's sake — each
is a genuine spec-compliance gap this library shipped with:

1. `x5c` was including the trust anchor (self-signed root) alongside the leaf — spec requires leaf
   (and any intermediates) only; the wallet already holds the anchor separately.
2. Nonce was plain Base64 (`+`, `/`, `=` — not URL-safe), not Base64URL.
3. `client_metadata.vp_formats_supported` was never populated — required unconditionally, not just
   under encrypted response mode.
4. `encrypted_response_enc_values_supported` only listed `A128GCM`; HAIP §5 requires both that and
   `A256GCM`.
5. The Request Object had no `aud` claim; added the static-discovery fixed value
   `https://self-issued.me/v2` per spec.

Plus one demo-layer fix: the `direct_post` response body was empty, which HAIP §5.1 disallows —
`redirect_uri` (a fresh 128-bit random value, per spec) is now always included.

All fixes verified against the actual OpenID4VP spec source before implementing (not recalled from
training data), with regression tests added to `eudi-rp-core`'s suite. See the git history for the
exact commits and spec citations.

**What this does and doesn't prove**: this confirms request/response protocol-level spec compliance
against an independent, spec-authoritative implementation — a materially stronger claim than "works
against our own mock wallet." It does **not** prove interoperability with a real EUDI wallet app's
actual UX/behavior (see below) — the conformance suite is a protocol simulator, not the EUDI
reference wallet or a production wallet implementation.

## Still not attempted: a real EUDI wallet app, or the EU reference verifier

Per the original brief for this phase: attempt an end-to-end test against the EU reference verifier
(`eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt`) or a reference wallet.

**Neither has been attempted.** Being honest about why: the EU reference verifier is a separate
Kotlin/Spring Boot service with its own database and Docker Compose setup, and a reference wallet is
a mobile app requiring either a physical device or an emulator with the app installed and
provisioned with a real test credential. Doing this properly needs:

1. Cloning and running `eudi-srv-web-verifier-endpoint-23220-4-kt` locally, or pointing this
   library's request construction at its wallet-facing endpoints, to check compatibility with that
   specific reference implementation.
2. A reference wallet app (the EUDI reference wallet, or any conformant HAIP/`x509_hash`
   implementation) on a device or emulator, scanning a real QR this library generates, to check
   whether an actual wallet's UX and validation — not just a protocol simulator — accepts what this
   library produces.

Both remain open. The OIDF conformance pass above is real, independent evidence of spec compliance,
but it is not the same claim as "works with a real wallet app in someone's hand."

## Recommended next step

Before making a broader interoperability claim publicly, run the demo against a real EUDI wallet
(device/emulator) or the EU reference verifier's wallet-facing endpoints, and update this file with
the actual result — pass, fail, or partial, with specifics.
