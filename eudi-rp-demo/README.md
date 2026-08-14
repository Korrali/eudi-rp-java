# eudi-rp-demo

A proof, not a product. Single page: one presentation flow, and the certificate failure simulator
(the actual point of this demo — see the project root README).

## Run it

```
mvn -pl eudi-rp-core,eudi-rp-spring-boot-starter,eudi-rp-mock-wallet,eudi-rp-demo -am package -DskipTests
java -jar eudi-rp-demo/target/eudi-rp-demo.jar
```

Open `http://localhost:8080`. On first run it generates a throwaway demo CA and RP access
certificate under `./demo-data/` — this is a demo convenience, not how a real deployment
provisions certificates (see DESIGN.md §2.2: real access certificates come from a Member
State-notified Access Certificate Authority via the registration process).

By default that throwaway certificate is RSA. Set `EUDIRP_DEMO_KEY_ALGORITHM=brainpoolP256r1` (or
`brainpoolP384r1`, `secp256r1`, `secp384r1`, `secp521r1`) before first run to generate it on that
curve instead — only takes effect on a fresh `demo-data/` directory, it won't migrate an existing
one. See `eudi-rp-mock-wallet/COMPATIBILITY.md` for what Brainpool-curve support is and isn't
verified against.

Click "Request identity verification". With no live wallet configured (the default), click
"Simulate wallet scan" — the mock wallet (`eudi-rp-mock-wallet`) builds a real, signed SD-JWT VC
presentation and the flow completes for real: request signing, DCQL query, response verification,
selective-disclosure resolution.

## Certificate failure simulator

Four buttons, each running real code against real BouncyCastle/JDK certificate machinery — not
canned responses:

- **Expired certificate** — `DefaultCertificateValidator` rejects it with the exact expiry timestamp.
- **Revoked certificate** — OCSP is attempted first (no responder configured for the throwaway
  simulator cert, so it fails), falls back to CRL, which has a real answer.
- **Malformed certificate** — an empty-issuer-DN certificate, which the JDK's strict parser rejects
  and BouncyCastle's tolerant parser accepts (see `eudi-rp-core`'s `MalformedCertificateFixtureGenerator`
  for how this specific malformation was found — it wasn't the first one tried).
- **Certificate rotated mid-session** — the first `resolveValid()` call fails against a cached
  expired certificate; the keystore file is then overwritten with a fresh one; the retry succeeds
  via hot reload.

## Real wallet mode

Set `EUDIRP_DEMO_WALLET_MODE=real` and `EUDIRP_DEMO_BASE_URL` to a publicly-reachable URL before
starting (the live deployment already does this — `eudirp.korrali.com`). **Verified against the
OpenID Foundation's official OpenID4VP conformance suite — full pass**, including the encrypted
`direct_post.jwt` response mode; see `eudi-rp-mock-wallet/COMPATIBILITY.md` for the exact test plan,
what it found (5 real bugs, since fixed), and what it proves vs. doesn't. **Still not tested against
an actual EUDI wallet app** (device/emulator) or the EU reference verifier service — the conformance
suite is an independent protocol simulator, not either of those.

## Single container

```
docker build -t eudi-rp-demo .
docker run -p 8080:8080 eudi-rp-demo
```

## Testing

Backend: `mvn test` (unit + `@SpringBootTest` integration tests, including all four
failure-simulator endpoints — see `DemoApplicationSmokeTest`).

Frontend: `e2e/` — real-browser tests (Playwright + actual Chrome, not a JS-engine
reimplementation) covering the full UI flow and all four failure-simulator buttons. See
`e2e/README.md`. An earlier attempt using HtmlUnit (pure-JVM headless browser) failed outright — its
JS engine can't parse the `async () => {}` arrow functions `app.js` uses throughout; noted there in
case anyone's tempted to reach for HtmlUnit again.

Not covered by anything automated: a real EUDI wallet or the EU reference verifier (see "Real
wallet mode" above and `eudi-rp-mock-wallet/COMPATIBILITY.md`), and there's no load/fuzz/security
test suite for the demo layer specifically (some of that exists at the `eudi-rp-core` level — see
the root README).
