# eudi-rp-java

A Java/Spring Boot library that lets a backend act as an EUDI Wallet Relying Party — request and
verify credential presentations from EU Digital Identity Wallets, with certificate lifecycle
handling (rotation, revocation, malformed sovereign certificates) as the actual point of the
project, not presentation flows.

## Quick start

```xml
<dependency>
  <groupId>com.korrali</groupId>
  <artifactId>eudi-rp-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

```yaml
eudirp:
  certificate:
    keystore-path: /etc/eudirp/rp.p12
    store-password: ${RP_KEYSTORE_PASSWORD}
    alias: rp
  trust-list:
    path: /etc/eudirp/trust.pem
  registration:
    declared-attributes-file: /etc/eudirp/declared-attributes.txt
```

```java
@Autowired HotReloadingCertificateResolver certificateResolver;
@Autowired RegistrationMetadataProvider registrationMetadataProvider;

RpKeyMaterial rpKey = certificateResolver.resolveValid();
DeclaredAttributeSet declared = registrationMetadataProvider.declaredAttributes();

SignedPresentationRequest request = new PresentationRequestBuilder(rpKey, declared)
    .credential(new DcqlCredentialQuery("identity_credential", CredentialFormat.SD_JWT_VC,
        List.of("https://credentials.example.com/identity_credential"),
        List.of(declared.claim("given_name"), declared.claim("family_name"))))
    .responseUri("https://your-rp.example.org/wallet/direct_post")
    .state(UUID.randomUUID().toString())
    .build();
```

That's the whole integration surface for the happy path. `HotReloadingCertificateResolver` is doing
the actual work: chain validation, revocation checking, and transparent reload if the certificate on
disk has rotated since the last read — see below.

## The gap

Every European bank, insurer, and telco faces a **December 2027 mandatory-acceptance deadline** for
EU Digital Identity Wallets. The EU's own reference implementation is Kotlin. The Italian eIDAS
profile toolchain is Python. As of this writing, there is no actively-maintained, Java-native,
Spring-idiomatic library for the relying-party (verifier) side of OpenID4VP — the closest options
are Kotlin JARs usable via JVM interop, or unrelated single-format building blocks. Most European
regulated-industry backends run Java and Spring. That's the gap.

## Certificate lifecycle: what actually breaks in production

Presentation flows are table stakes — several will exist by next year. Certificate lifecycle is
where real deployments against sovereign PKI break, and it's the part this project was actually
built to get right:

- **Rotation.** An operator rotates the RP access certificate on disk. The in-memory cache is now
  stale. `HotReloadingCertificateResolver` detects the validation failure, reloads from source, and
  retries — the caller sees a successful request, not a transient outage.
- **Revocation.** OCSP is tried first; if the responder is unreachable or the certificate has no
  OCSP endpoint, it falls back to CRL. Either check finding the certificate revoked is authoritative,
  and the caller learns *which* mechanism caught it, not just "invalid."
- **Curve support beyond NIST.** Germany's BSI recommends Brainpool curves (RFC 5639) for sovereign
  PKI deployments; other Member States default to NIST curves. This library signs correctly with
  BrainpoolP256r1 and BrainpoolP384r1 RP certificates — not just P-256 — verified with real
  cryptographic sign/verify round trips and a full end-to-end run of the demo against a genuine
  Brainpool-keyed certificate, not just accepted without erroring. ENISA's ECCG "Agreed
  Cryptographic Mechanisms v2.0" (Apr 2025) — the document EUDI ARF Annex 2.03 defers to for
  algorithm approval — lists these curves "Recommended", the same tier as NIST's. See
  `eudi-rp-mock-wallet/COMPATIBILITY.md` for exactly what's verified and what's still open (whether
  a real wallet accepts the JOSE `alg` convention chosen, since RFC 7518 has no registered `alg` for
  Brainpool).
- **Malformed certificates from sovereign issuers.** Some CA software emits certificates that are
  valid BER but not strict DER — the JDK's default X.509 parser rejects some of these outright. The
  strict path is tried first; a BouncyCastle-based tolerant path is the fallback, engaging (and
  logging) only when needed rather than failing the request. The specific malformation this library
  ships a real, empirically-verified fixture for is a certificate with an empty issuer DN — chosen
  because it's the one that actually reproduces the split on a modern JDK, not the one folklore
  would have predicted (see `eudi-rp-core`'s `MalformedCertificateFixtureGenerator` for the other
  candidates that were tried and didn't).

The demo's **failure simulator** runs all four of these live against the real code, not canned
output — see below.

## Demo

The demo app (`eudi-rp-demo`, not published to Maven Central) is a proof, not a product: one
presentation flow plus four buttons that run the real certificate failure paths. Run it locally:

```
mvn -pl eudi-rp-core,eudi-rp-spring-boot-starter,eudi-rp-mock-wallet,eudi-rp-demo -am package -DskipTests
java -jar eudi-rp-demo/target/eudi-rp-demo.jar
```

Then open `http://localhost:8080`. See `eudi-rp-demo/README.md` for details. **A live-hosted demo
at a public URL does not exist yet** — deploying one is a remaining step, not something this build
could complete without real infrastructure access.

## Honest limitations

- **mdoc / ISO 18013-5 is not supported**, full stop — not deferred to a future release. This
  project makes no forward commitments (see DESIGN.md §3). SD-JWT VC is the only credential format
  implemented.
- **Verified against the OpenID Foundation's official OpenID4VP conformance suite — full pass**
  (`oid4vp-1final-verifier-happy-flow`, HAIP/SD-JWT VC/`x509_hash`/`direct_post.jwt` variant): every
  protocol-level check succeeds against an independent, spec-authoritative simulated wallet, not
  just this library's own mock. The first run found 5 real spec-compliance bugs (x5c trust-anchor
  inclusion, non-URL-safe nonce, missing `vp_formats_supported`, incomplete HAIP encryption
  algorithm list, missing `aud`) plus a missing `redirect_uri` in the demo's response — all fixed
  and re-verified, see `eudi-rp-mock-wallet/COMPATIBILITY.md` and the git history for specifics.
  **Still not tested**: a real EUDI wallet app (device/emulator) or the EU reference verifier
  service — the conformance suite is a protocol simulator, not either of those. See
  `eudi-rp-mock-wallet/COMPATIBILITY.md` for exactly what remains open and why.
- **Credential-issuer trust is out of scope.** Verifying who signed a presented credential (as
  opposed to the RP's own access certificate, which is this library's actual focus) is left to a
  caller-supplied `IssuerSignatureVerifierResolver` — this wasn't part of what the Phase 0 research
  covered (ARF's Relying Party trust chapter, not credential issuance trust).
- **Nested SD-JWT selective disclosure is not implemented** — only top-level object-property
  disclosures resolve. See `SdJwtVc`'s javadoc.
- **An open versioning discrepancy in DESIGN.md §0** (an ARF tag dated 2024 vs. a 2026 primary
  source citing an earlier-numbered version) was flagged, not resolved, before this code was
  written. Section numbers cited in code comments should be treated as high-confidence, not final.
- **Not published to Maven Central yet.** The POM has a `release` profile wired up (sources jar,
  javadoc jar, GPG signing, Central Portal publishing), but actually running it needs a real GPG
  key, a Central Portal account, and DNS TXT verification of the `com.korrali` namespace on
  korrali.com — none of which happened as part of this build.

## Maintenance scope

Support is best-effort, single maintainer, no SLA. Bug reports and PRs welcome; feature requests
will likely be declined — see the project brief's own scope-discipline rule: certificate lifecycle
done excellently beats every feature done partially, and a one-person unpaid project makes no
forward commitments. Stated once here so it doesn't need relitigating in every issue.

## Who built this

17 years in Java, most recently production SAML 2.0 SP work against a government identity provider
— including a BouncyCastle-based manual metadata parser to work around the JDK's strict X.509
parsing, and hot-reloadable signing certificates with automatic on-failure refresh. This library is
the same failure class, generalized to OpenID4VP relying-party certificates ahead of the EUDI
wallet mandate. [korrali.com](https://www.korrali.com)

**Need this integrated before the December 2027 deadline?** The library is free; getting it wired
into your actual stack — real access certificates from your notified Access Certificate Authority,
your specific attribute set, your registration declaration — is exactly the kind of production PKI
integration work described above. Reach out: bhagat.ashish.a@gmail.com.

## License

Apache License 2.0.
