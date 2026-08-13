# DESIGN.md — eudi-rp-java

A Java/Spring Boot library for acting as an EUDI Wallet Relying Party (RP): requesting and verifying
credential presentations from EU Digital Identity Wallets, with certificate lifecycle management
(rotation, revocation, trust lists, tolerant parsing of malformed sovereign certificates) as the
core differentiator.

This document is Phase 0 output — research only, no code written. Every non-obvious claim is cited
to a spec section, article, or source file. Anything not confirmed by direct reading is marked
`UNVERIFIED`. Where two sources disagree, both are reported rather than silently resolved.

---

## 0. Sources actually read, and one open discrepancy

| # | Source | Version/tag read | Notes |
|---|---|---|---|
| 1 | `eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework` | tag **`v3.0.0`**, released 2024-07-23 | Chapters `05-data-model-and-data-exchange-protocols.md`, `06-trust-model.md`, `annex-2.01`, `annex-2.03` |
| 2 | Topic X — Relying Party Registration | `x-rr-relying-party-registration.md` **v1.0, 8 May 2026 ("2026 revision round")** | References "ARF v2.8.0" as its baseline |
| 3 | Commission Implementing Regulation (EU) 2025/848 | of 6 May 2025 | Full text corroborated via quotations embedded in the Topic X paper; direct EUR-Lex fetch was JS-gated and did not render |
| 4 | OpenID for Verifiable Presentations 1.0 | Editor's draft `openid-4-verifiable-presentations-1_0-31`, superseding OIDF Final Spec approved 2025-07-09 | `github.com/openid/OpenID4VP` |
| 5 | `eu-digital-identity-wallet/eudi-web-verifier` | current `main` | Angular UI shell only — no protocol logic |
| 6 | `eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt` | current `main` | The actual reference RP backend (Kotlin/Spring) — fetched instead of (5) since it holds the real logic |
| 7 | `eu-digital-identity-wallet/eudi-srv-web-relyingparty-registration-py` | current `main` | RP registration service (Python/Flask + EJBCA) |
| 8 | `eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt` (+ `eudi-lib-jvm-siop-openid4vp-kt` on Maven Central, v0.9.1) | current `main` | Closest JVM prior art — verifier-side, not issuance |

**Open discrepancy — UNVERIFIED, needs resolution before Phase 1 cites section numbers as final:**
Source #1 was fetched via a tagged release (`v3.0.0`, 2024-07-23), which the research pass judged
more reliable than two earlier `WebFetch` calls against the GitHub releases/tags list that returned
garbled 2025/2026 dates. But source #2 — a primary document dated 8 May 2026 — explicitly cites
**"ARF v2.8.0"** as its current baseline, and an (unverified, possibly AI-summarized) web search
separately surfaced "ARF v2.9.0, 21 May 2026." A repository that has shipped a `v3.0.0` tag in 2024
and is still being referenced as `v2.8.0`/`v2.9.0` in 2026 is internally inconsistent on its face —
either the ARF's versioning is not strictly monotonic across some branch/renumbering event
(possible — some EU doc repos reset major versions after a structural rewrite), or one of the two
fetches picked up stale/incorrect data. **Action before Phase 1**: re-fetch the actual current tag
list at `github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/tags`
directly and confirm which version is truly latest, then re-verify the section numbers below against
it. The trust-model and presentation-interface *concepts* below are very unlikely to have changed
structurally, but exact section numbers (§5.7.x, §6.4.2, §6.6.3.x) should be treated as
**high-confidence but not final** until that re-check happens.

This is a separate question from Topic X's own status, which is settled regardless of that
discrepancy: the primary source is `x-rr-relying-party-registration.md`, **v1.0, dated 8 May 2026**,
explicitly labeled a "2026 revision round" **discussion draft** — not Final. An earlier pass at this
research relied on a secondary blog summary claiming the ARF hit v2.9.0 on 21 May 2026 with Topic X
moving to Final; that claim does not hold up against the document actually read and is rejected.
Primary source wins. Cite Topic X status as: *unresolved / mid-revision as of 8 May 2026*, checkable
against that exact file and date if the situation changes.

**Gap check verdict: GAP CONFIRMED.** No actively-maintained, Java-native, Spring-idiomatic
OpenID4VP relying-party library exists on Maven Central or GitHub as of 2026-08. The EU reference
verifier (`eudi-srv-web-verifier-endpoint-23220-4-kt`) and every JVM verifier-side library in the
`eu-digital-identity-wallet` org are Kotlin. Maven Central's only `openid4vp`-named artifacts are
Kotlin (`eu.europa.ec.eudi:eudi-lib-jvm-siop-openid4vp-kt`) or wallet-side
(`io.mosip:inji-openid4vp`). Sphereon's OID4VC stack is TypeScript/Node, not JVM at all. walt.id is
Kotlin Multiplatform, not Java-idiomatic. Two single-maintainer Java repos exist
(`wistefan/oid4vp-client-lib`, `wistefan/dcql-java`) but the former is wallet-side and the latter
implements only the query language, not a verifier. Authlete's `com.authlete:sd-jwt` is a genuine,
maintained Java library, but it's an SD-JWT primitive, not an OpenID4VP protocol implementation —
useful as a dependency, not competition. **Honest caveat**: Kotlin JARs are fully JVM-interoperable,
so a determined Spring team could consume the EU reference libraries directly today. The gap is
specifically in an idiomatic, Spring-Boot-native, redistributable dependency — which does not exist.

---

## 1. End-to-end presentation flow

Scope: **remote presentation** (cross-device QR and same-device redirect), the case that matters for
a backend RP. Proximity/mDL-over-BLE (ISO/IEC 18013-5 device retrieval, ARF §5.7.2) is a distinct
transport and is out of scope (see §6).

ARF §5.7.3/§5.7.4 names OpenID4VP as the base protocol for remote presentation and mandates the
**HAIP** profile ("OpenID4VP for IETF SD-JWT VC" profile — *source #1*) for interoperability. Two
HAIP transmission mechanisms exist: a redirect-based flow with a custom URI scheme, and the W3C
Digital Credentials API (*source #1, §5.7.3–5.7.4*); this design targets the redirect-based flow —
the DC API is a browser-native transport with different integration mechanics and is called out
separately in §6.

### Step-by-step (cross-device / QR — the flow the demo app in Phase 5 implements)

1. **RP constructs and signs the Authorization Request.** Per OpenID4VP *(source #4)*:
   - `response_type=vp_token` (REQUIRED).
   - `dcql_query` — a DCQL query object (REQUIRED; DCQL is the **sole** query mechanism in Final
     1.0 — `presentation_definition`/`presentation_submission` from Presentation Exchange were
     removed; a full-text search of the spec confirms zero occurrences of `presentation_submission`).
   - `client_id` — see §2 below for the `x509_hash` prefix mandated by ARF.
   - `nonce` — fresh, ≥128 bits of entropy (REQUIRED).
   - `response_mode=direct_post` for cross-device (REQUIRED) — the wallet POSTs the response back
     to the RP's `response_uri` rather than redirecting the user-agent.
   - `response_uri` — REQUIRED when `response_mode=direct_post`, mutually exclusive with
     `redirect_uri`.
   - `state` — REQUIRED for credentials without holder binding, RECOMMENDED otherwise.
   - `client_metadata` — OPTIONAL; carries `vp_formats_supported`, `jwks`, encryption params.
   - The request is signed as a **Request Object (JAR, RFC 9101)**: `typ` header MUST be
     `oauth-authz-req+jwt`; wallets MUST reject requests missing that header value. If an `iss`
     claim is present, wallets MUST ignore it — `client_id` governs identity, not `iss`.
   - Request delivery: **by reference** via `request_uri` (+ `request_uri_method=get|post`), which
     is what the reference verifier endpoint does — see step-by-step API shape below.

2. **RP renders a QR code / deep link encoding the request (or a `request_uri` pointing to it).**
   The reference implementation's real API shape (*source #6*,
   `VerifierApi.kt`/`WalletApi.kt`/`openapi.json`):
   - `POST /ui/presentations` — RP-facing: initializes a transaction, returns `transaction_id`,
     `client_id`, `request_uri`.
   - `GET|POST /wallet/request.jwt/{requestId}` — wallet-facing: wallet fetches the signed Request
     Object JWT by reference.

3. **Wallet resolves the request, authenticates the RP, and evaluates scope** (ARF §6.6.3.1's
   ten-step trust chain, *source #1*): (1) authenticate the RP Instance via its access certificate,
   (2) check requested attributes don't exceed what's registered, (3) evaluate disclosure policy,
   (4) obtain user consent for selective disclosure, then later (5) RP verifies attestation
   signature, (6) RP checks revocation, (7) device binding check, (8) optional user binding, (9)
   same-user check across combined presentations, (10) post-interaction reporting/deletion. See §2
   for the certificate mechanics behind steps 1–2.

4. **Wallet builds and posts the Authorization Response.** Per OpenID4VP *(source #4)*:
   - `vp_token` — REQUIRED. A JSON object keyed by the `id` values from the DCQL query, each value
     an array of one or more presentations, e.g. `{"my_credential": ["eyJhbGci...QMA"]}`. There is
     no separate `presentation_submission` — DCQL being the only query language means the response
     shape doesn't vary by query mechanism.
   - `state` — echoed if present in the request.
   - Transport: cross-device uses `direct_post` (HTTP POST, `application/x-www-form-urlencoded`,
     to `response_uri`) or `direct_post.jwt` (same, but body is an encrypted JWT `response`
     parameter wrapping `{"vp_token": {...}}`). Same-device default is `fragment` (redirect with
     `vp_token` in the URL fragment) — not the primary case for a backend RP driving a QR flow.
   - Reference implementation endpoint: `POST /wallet/direct_post` (*source #6*).

5. **RP polls for / receives the response, verifies it, and extracts attributes.** Reference
   implementation: `GET /ui/presentations/{transactionId}?response_code={code}` for same-device
   polling, or without `response_code` for cross-device polling (*source #6*). Verification means:
   validate the credential's own signature (SD-JWT VC key binding / mdoc device signature),
   validate it against the DCQL query that was sent (right `vct`/`doctype`, right claims disclosed),
   and enforce that only declared attributes were requested in the first place (§2, ARF §6.6.3.3).

### DCQL query shapes actually used (verbatim from spec examples, `1.0/examples/query_lang/`)

SD-JWT VC:
```json
{"credentials":[{"id":"my_credential","format":"dc+sd-jwt",
  "meta":{"vct_values":["https://credentials.example.com/identity_credential"]},
  "claims":[{"path":["family_name"]},{"path":["given_name"]},{"path":["address","street_address"]}]}]}
```
mdoc:
```json
{"credentials":[{"id":"my_credential","format":"mso_mdoc",
  "meta":{"doctype_value":"org.iso.7367.1.mVRC"},
  "claims":[{"path":["org.iso.7367.1","vehicle_holder"]},{"path":["org.iso.18013.5.1","given_name"]}]}]}
```

---

## 2. Where RP access certificates enter the flow

Two distinct certificate types exist — conflating them is a real design risk, so this library
should model them as separate types, not one "the RP cert" concept.

### 2.1 The Access Certificate — authenticates the RP to the wallet at request time

- ARF §6.4.2 (*source #1*): a **Relying Party Instance** ("a combination of hardware and software
  used by a Relying Party to interact with a Wallet Unit") is issued an **access certificate** by an
  **Access Certificate Authority**. "A Relying Party Instance needs such a certificate to
  authenticate itself towards Wallet Units."
- CIR 2025/848 Art. 7(2) (*source #2/#3, quoted in the Topic X paper*): the **Wallet-Relying Party
  Access Certificate (RPAC)** is issued "exclusively to registered wallet-relying parties," by an
  authorized Access Certificate Authority. Annex IV requires it be **NCP-compliant per ETSI EN
  319411-1 v1.4.1**, with a build-up path to a trust anchor.
- **Concrete authentication mechanism — ARF Annex 2.03, requirement category `AS-WP-06`**
  (*source #1*), which is a materially important, specific finding:
  - `AS-WP-06-003`: the Wallet Unit SHALL "support access certificates as specified in **[ETSI TS
    119 475]** and **[ETSI TS 119 411-8]**," tied to OpenID4VP under the HAIP profile using the
    **`x509_hash` Client Identifier Prefix** — **not** `x509_san_dns`.
  - `AS-WP-06-005`: the Wallet Unit SHALL accept only trust anchors from the **Lists of Trusted
    Entities (LoTE)** of Access Certificate Authorities notified by Member States.
  - `AS-WP-06-002`: RP authentication SHALL NOT be delegated to a third party — the wallet retains
    full authority over the check.
- OpenID4VP's `x509_hash` scheme mechanics (*source #4*): `client_id` takes the form
  `x509_hash:<base64url SHA-256 of the DER-encoded leaf cert>`. The request MUST be signed with the
  private key corresponding to that leaf certificate, whose full chain is carried in the `x5c` JOSE
  header (RFC 7515). The wallet MUST validate both the signature and the trust chain up to the LoTE
  anchor.
- Reference implementation config surface (*source #6*): RP access certificate loaded from a
  keystore via `VERIFIER_ACCESS_CERTIFICATE_KEYSTORE` (+ `_KEYSTORE_TYPE` jks/pkcs12,
  `_KEYSTORE_PASSWORD`, `_ALIAS`, `_PASSWORD`, `_SIGNING_ALGORITHM`), with client-ID-scheme selection
  via `VERIFIER_CLIENTIDPREFIX` (supporting `pre-registered`, `x509_san_dns`, `x509_hash`) — the
  reference implementation explicitly documents the access certificate **"cannot be self-signed."**
  `eudi-lib-jvm-openid4vp-kt`'s `Config.kt` exposes a `RegistrationCertificatePolicy` interface for
  injecting custom X.509 trust-chain validation logic — direct prior art for this library's
  certificate-validation extension point.

### 2.2 The Registration Certificate — scopes what the RP is allowed to ask for

- ARF §6.4.2 / §6.6.3.3 (*source #1*): a separate **Provider of registration certificates** (itself
  CIR-2025/848-compliant) issues one or more **registration certificates** to the RP, one per
  registered "intended use," each scoping a specific declared attribute set. "Registration of a
  specific set of attributes for a specific intended use…does not imply authorization."
- CIR 2025/848 Art. 8 (*source #2, quoted*): the **Wallet-Relying Party Registration Certificate
  (RPRC)** is optional per Member State policy; when issued, it "indicates the attributes the
  relying party has registered to intend to request from users" and, per Art. 8(2)(c), must include
  a general access policy informing users the RP is only allowed to request the declared data.
  Annex V requires it be a **signed JWT (RFC 7519) or CWT (RFC 8392)**.
- Declared-scope enforcement is **wallet-side and user-facing**, not purely a certificate check: the
  wallet's ten-step trust chain (§6.6.3.1, step 2) checks the request against the registered scope
  before presenting it to the user, and CIR Art. 9(2)(c) makes "requesting more attributes than
  registered" explicit grounds for registration suspension/cancellation. eIDAS2 Art. 5b(3): "Relying
  parties shall not request users to provide any data other than that indicated" in their
  registration.
- Registration data shape, from the actual RP registration service (*source #7*,
  `app/relying_party_reg.sql`): country of establishment, official name, common name, official
  registration number/ID data, contact details, and a free-text "intended use" description (max 500
  chars) that declares the data to be requested. The service issues back an RPAC (via EJBCA) as a
  PKCS#12 keypair. API shape: `POST /wallet_rp/create`, `POST /wallet_rp/certificate`, public lookup
  via `GET /wrp/<identifier>`.

### 2.3 Revocation checking

CIR Annex II (*source #2, quoted*) requires the national RP register's API to be REST+JSON with
JWS-signed (RFC 7515) responses, documented via OpenAPI v3, and open to unauthenticated read/search —
this is the channel through which a wallet (or, symmetrically, this library acting as an RP checking
its own or a counterparty's status) can look up current registration state. Neither source #1 nor
source #2 specifies CRL/OCSP mechanics for the *access certificate* itself in the text actually
read — ARF Annex IV/V reference ETSI EN 319 411-1 (a general PKI/QTSP baseline that itself mandates
standard revocation mechanisms for qualified/NCP certificates) rather than spelling out CRL vs OCSP
choice explicitly in the ARF chapters fetched. **UNVERIFIED**: exact revocation-check requirements
(CRL vs OCSP vs both, checking frequency, grace periods) — this needs a direct read of ETSI EN 319
411-1 v1.4.1 and ETSI TS 119 475 before Phase 1 locks in the revocation-checking implementation,
since the ARF/CIR text read here establishes *that* revocation must be supportable (via the
standard PKI baseline it incorporates by reference) but not the exact mechanics. This library will
support both CRL and OCSP per your original scope (industry-standard for this cert-baseline class)
and treat the exact ETSI requirement as a Phase 1 pre-read, not an assumption baked into this design
doc.

### 2.4 Application date

CIR 2025/848 applies from **24 December 2026** (*source #2, via Better Regulation portal listing*).
That is before the December 2027 wallet-acceptance mandate you're building against, which matters
for the demo/positioning: the registration/certificate regime this library targets is not a future
hypothetical, it's live before the acceptance deadline hits.

---

## 3. Credential format: SD-JWT VC, mdoc, or both

**Decision: SD-JWT VC only. mdoc is out of scope, full stop — not a future step, not on a roadmap.**
This is a single-person, unpaid, Apache-2.0 project; it makes no forward commitments. mdoc support is
not "v0.2" because there is no v0.2.

Tradeoffs, based on what was actually found:

- **Both formats are real requirements, not a hypothetical choice.** ARF's remote-presentation path
  (§5.7.3–5.7.4) targets HAIP/SD-JWT VC explicitly by name ("OpenID4VP for IETF SD-JWT VC" profile),
  while proximity presentation (§5.7.2) uses ISO/IEC 18013-5 mdoc. OpenID4VP's DCQL supports both
  formats natively (`dc+sd-jwt` vs `mso_mdoc`, shown in §1 above) — this is not a case where you can
  claim spec compliance while only picking one.
- **SD-JWT VC has a materially shorter path to a solid Java implementation.** It's JOSE-based (JWT +
  selective disclosure), and Nimbus JOSE+JWT — already your planned dependency for JAR request
  signing — covers most of the primitive. Authlete's `com.authlete:sd-jwt` (*gap-check finding*) is
  a real, maintained Java library for the SD-JWT format itself, usable as a building block or a
  point of comparison. This is the format the EU's own HAIP profile treats as canonical for the
  redirect-based remote flow you're targeting first.
- **mdoc requires a materially larger, different stack**: CBOR/COSE encoding (not JOSE), device-key
  signature verification per ISO/IEC 18013-5, and namespace-based claim paths
  (`["org.iso.18013.5.1", "given_name"]` vs SD-JWT VC's JSON-pointer-style paths). The closest JVM
  prior art (`eudi-lib-jvm-openid4vp-kt`, *source #8*) depends on Authlete's CBOR library for this,
  confirming it's treated as a distinct dependency, not a JOSE extension.
  is a genuinely separate engineering effort, and doing it half-well (the exact failure mode this
  project's whole thesis argues against for certificates) is worse than deferring it explicitly.
- **Certificate lifecycle work is format-agnostic** — the access certificate / trust-chain /
  revocation machinery (§2) sits below both credential formats and is identical regardless of which
  credential format rides on top. This means deferring mdoc doesn't dilute the core differentiator;
  it just narrows which presentations can be *parsed* in v0.1, not how well certificates are handled.

**The DCQL query builder and credential-format enum should still recognize `mso_mdoc` as a value** —
not as a stepping stone toward future support, but because rejecting an unsupported format with a
clear, typed "not supported" error is better engineering than mishandling an unrecognized string
silently. That's a fail-closed design choice any library should make regardless of roadmap; it does
not imply mdoc will be revisited.

---

## 4. Provider boundaries

Three narrow interfaces gate all external data the library consumes. Each ships as a stable,
documented extension point with exactly one implementation in v0.1: a local, file-based default.
Building alternative implementations (hosted, networked, multi-tenant) is explicitly not part of
this project — the boundary exists for testability and for whoever plugs in their own
infrastructure, not as a hook for this project to later build a paid layer on top of.

- **`TrustListProvider`** — supplies trusted CAs / trust list data for chain validation, sourced
  conceptually from the LoTE requirement in §2.1 (ARF `AS-WP-06-005`). Default implementation reads
  from local files (a configured PEM/DER bundle or directory) — no network fetch, no scheduled
  refresh service, no remote LoTE polling.
- **`RevocationChecker`** — CRL and OCSP checks (§2.3). Default implementation performs direct
  lookups against the CRL Distribution Point / Authority Information Access endpoints named in the
  certificate itself — no caching layer, no revocation-status database, no background refresh job.
- **`RegistrationMetadataProvider`** — the RP's own declared attribute set (§2.2; ARF §6.6.3.3 /
  CIR Art. 8's declared-attributes concept). Default implementation reads from local static config
  (e.g. YAML/properties) — not a live call to a national registrar API.

**Design consequence of the Topic X correction (§0):** CIR 2025/848's registration mechanics and the
ARF's registration chapter are still mid-revision as of the primary source actually read.
`RegistrationMetadataProvider` therefore stays deliberately thin — it models only what's stable
enough to build against: a flat declared-attribute list and validation of outgoing requests against
it. It does **not** model registrar API shapes, RPRC JWT/CWT structure (Annex V), or
registration-certificate parsing — those are still moving in the spec. Anywhere this interface's
javadoc would otherwise need to guess at an unsettled detail, it states the uncertainty explicitly
(citing this DESIGN.md's §0/§2.2) rather than encoding a guess as if it were fixed.

---

## 5. Public API surface for v0.1 (interfaces/signatures only — proposed, not spec-sourced)

Everything below is this library's own design, informed by §1–3, `eudi-lib-jvm-openid4vp-kt`'s shape
(*source #8*) as prior art for how a JVM library in this ecosystem organizes itself, and the
reference verifier's config surface (*source #6*) for what a real deployment needs. Package root:
`com.korrali.eudirp`.

```java
// com.korrali.eudirp.cert — certificate lifecycle (the differentiator)

public interface RpCertificateStore {
    RpCertificate current();                     // hot-reload aware: always the latest valid cert
    RpCertificate reload();                       // force refresh from source (PKCS#12/JKS file, HSM, etc.)
}

public interface CertificateValidator {
    ValidationResult validate(X509Certificate leaf, List<X509Certificate> chain) throws CertificateValidationException;
}

public sealed interface ValidationResult permits ValidationResult.Valid, ValidationResult.Invalid { }

public interface TrustListProvider {
    List<X509Certificate> trustAnchors();          // sourced from LoTE per ARF AS-WP-06-005
    Instant lastRefreshed();
}

public interface RevocationChecker {
    RevocationStatus check(X509Certificate cert, List<X509Certificate> chain) throws RevocationCheckException;
}

// See §4 — thin by design; models only the stable part of an unsettled spec area.
public interface RegistrationMetadataProvider {
    DeclaredAttributeSet declaredAttributes();
}

// Typed exceptions — distinguishing failure classes per your explicit requirement
public sealed class CertificateValidationException extends Exception
    permits ExpiredCertificateException, RevokedCertificateException,
            UntrustedCertificateException, MalformedCertificateException { }

public final class ExpiredCertificateException extends CertificateValidationException {
    public Instant expiredAt();
}
public final class RevokedCertificateException extends CertificateValidationException {
    public Instant revokedAt();
    public RevocationReason reason();
    public RevocationSource source();              // CRL or OCSP — which one caught it
}
public final class UntrustedCertificateException extends CertificateValidationException { }
public final class MalformedCertificateException extends CertificateValidationException {
    public boolean tolerantParsePathEngaged();      // did the BouncyCastle fallback kick in
}
```

```java
// com.korrali.eudirp.presentation — Phase 2 surface, shown here for API continuity

public interface PresentationRequestBuilder {
    PresentationRequestBuilder credential(DcqlCredentialQuery query);
    PresentationRequestBuilder responseMode(ResponseMode mode);   // direct_post | direct_post.jwt
    SignedPresentationRequest build() throws DeclaredScopeViolationException;
}

// Declared-scope enforcement is a compile-time-adjacent constraint, not just a runtime check:
// a DcqlCredentialQuery can only be constructed against a DeclaredAttributeSet, so requesting
// undeclared attributes requires deliberately bypassing the type, not a one-line oversight.
public final class DeclaredAttributeSet {
    public static DeclaredAttributeSet from(RegistrationMetadataProvider provider);
    public DcqlClaimQuery claim(String path) throws UndeclaredAttributeException;
}

public interface PresentationResponseVerifier {
    VerifiedPresentation verify(AuthorizationResponse response, SignedPresentationRequest originalRequest)
        throws PresentationVerificationException;
}

public interface VerifiedPresentation {
    CredentialFormat format();                      // SD_JWT_VC supported; MSO_MDOC recognized only, always rejected — §3
    Map<String, Object> disclosedClaims();
    CertificateValidationOutcome rpCertOutcome();    // surfaced for the demo's result panel
}
```

```java
// com.korrali.eudirp.spring — Phase 3 surface, shown here for shape continuity only

@ConfigurationProperties("eudirp")
public class EudiRpProperties {
    public CertificateProperties certificate();       // keystore path/type/alias/password
    public TrustListProperties trustList();           // LoTE source URL(s), refresh interval
    public RevocationProperties revocation();          // CRL/OCSP toggle, timeout
}
```

These are illustrative of scope and shape, not final — Phase 1/2 will refine exact method
signatures against real usage once the ARF version discrepancy (§0) is resolved and ETSI TS 119
475 / TS 119 411-8 / EN 319 411-1 (§2.3) are read directly.

---

## 6. Explicitly out of scope

Not "deferred," not "v0.1 only implying more later" — out of scope, full stop, for a project that
makes no forward commitments. The README's limitations section should state these the same way: what
isn't supported, without implying it's coming.

- **mdoc/ISO 18013-5 credential parsing** — not supported (§3). The format is recognized only to be
  rejected cleanly.
- **Proximity presentation** (BLE device retrieval, ISO/IEC 18013-5 device-engagement) — ARF §5.7.2
  is a different transport entirely from the OpenID4VP remote flow this library targets. Not
  supported.
- **W3C Digital Credentials API transport** — ARF §5.7.3–5.7.4 names this as an alternative to the
  redirect-based flow; different integration surface (browser-native). Not supported.
- **RP registration/onboarding itself** (i.e., this library does not implement the
  `eudi-srv-web-relyingparty-registration-py`-style registrar service, §2.2) — it consumes an
  already-issued access certificate and registration certificate; it does not issue them.
- **Presentation Exchange / `presentation_definition`** — confirmed removed from OpenID4VP Final
  1.0 (§1); not implemented since it isn't spec-current.
- **Verifier attestation / `verifier_attestation` and `openid_federation` client-ID schemes** —
  ARF's concrete requirement (AS-WP-06-003) names `x509_hash` specifically; other schemes exist in
  the base OpenID4VP spec but aren't the ARF-mandated path. Not supported.
- **Non-Java credential holder/wallet-side functionality** — this is an RP library, not a wallet
  SDK (the mock wallet in Phase 4 is test support, not a product surface).
- **HSM-backed key storage** for the RP's own signing key — PKCS#12/JKS file-based loading only.
  This is a scope decision, not a placeholder for HSM support later.
- **Hosted or networked implementations of the §4 provider interfaces** — only local, file-based
  defaults ship. Alternative implementations are something a user of the library could write against
  the stable interface; they are not something this project builds or maintains.

---

## 7. Items needing resolution before Phase 1 begins

1. **ARF version discrepancy (§0)** — confirm the actual current tag and re-verify §5.7.x/§6.4.2/
   §6.6.3.x section numbers against it before citing them in code comments or tests.
2. **ETSI TS 119 475, ETSI TS 119 411-8, ETSI EN 319 411-1 v1.4.1** — not yet read directly; needed
   to lock in exact revocation-checking mechanics (§2.3) and access-certificate profile requirements
   beyond what the ARF/CIR text quotes secondhand.
3. **`ts5`/`ts6` technical specification stubs** (*source #1*) point to a separate repo,
   `eudi-doc-standards-and-technical-specifications`, not yet fetched — likely contains the
   field-level data model for registration/access certificates referenced only abstractly here.
4. **Confirm whether `eudi-lib-jvm-openid4vp-kt` and `eudi-lib-jvm-siop-openid4vp-kt`** (*source #8*)
   are the same lineage under two names or genuinely distinct libraries, before citing either as
   "the" JVM prior art in the README's positioning language (Phase 6).
