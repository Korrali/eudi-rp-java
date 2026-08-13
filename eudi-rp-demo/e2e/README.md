# eudi-rp-demo E2E tests

Real-browser tests (Playwright, driving your actual installed Chrome — not a bundled Chromium
download) against the frontend in `../src/main/resources/static/`. Dev/test tooling only: not part
of the Maven build (`mvn verify` never touches this directory), and the frontend itself stays
framework-free and Node-free — this is a separate verification harness, not a build dependency.

Written after an earlier attempt using HtmlUnit (a pure-JVM headless browser) failed outright:
HtmlUnit's Rhino-based JS engine can't parse `async () => {}` arrow functions, which `app.js` uses
throughout for its `fetch`-based event handlers. Real Chrome via Playwright has no such gap.

## Run it

```
npm install
npm test
```

Requires the demo app already running (defaults to `http://localhost:8080`; override with
`EUDIRP_DEMO_URL`), and Chrome installed locally (`channel: 'chrome'` in `playwright.config.js` —
change to Playwright's bundled Chromium if you'd rather not depend on a local Chrome install).

Covers: the full happy-path flow (start → QR renders → simulate scan → VERIFIED with real
disclosed claims), the raw request/response viewer, and all four failure-simulator buttons.
