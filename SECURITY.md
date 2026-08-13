# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's "Report a vulnerability" flow on this
repository (Security tab → Advisories), rather than opening a public issue. This is a
single-maintainer project — response is best-effort, no SLA (see the README's "Maintenance scope").

Please include:
- The affected module/class and version.
- Whether it's a protocol-compliance gap (e.g., a validation check this library should perform but
  doesn't) or an implementation bug (e.g., a check that's present but wrong).
- A minimal reproduction if possible — a certificate fixture, request/response pair, or failing
  test is more useful than a description.

## Scope notes specific to this library

- This library does not implement cryptographic primitives itself — it uses BouncyCastle and Nimbus
  JOSE+JWT. A vulnerability in the cryptography itself likely belongs to those projects, not here;
  please report it upstream as well as here if you're not sure which side it's on.
- Credential-issuer trust (verifying who signed a *presented credential*, as opposed to the RP's own
  access certificate) is explicitly left to a caller-supplied resolver — see the README's "Honest
  limitations" section. Misconfiguration of that resolver by a consumer of this library is not a
  vulnerability in this library, but if the API design makes that misconfiguration easy to do by
  accident, that's a legitimate report.
- The demo app (`eudi-rp-demo`) generates a throwaway self-signed CA and certificate on first run
  for convenience. That behavior is intentional and documented — it is not a production credential
  provisioning mechanism, and reporting "the demo cert is self-signed" is not a vulnerability report.

## Supported versions

Pre-1.0: only the latest published version is supported. Semantic versioning starts in earnest at
1.0.0; see CHANGELOG.md.
