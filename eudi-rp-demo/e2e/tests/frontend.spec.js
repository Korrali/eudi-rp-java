// @ts-check
const { test, expect } = require('@playwright/test');

test('clicking start renders a QR code and simulating a scan reaches VERIFIED with real disclosed claims', async ({ page }) => {
  await page.goto('/');

  await page.click('#start-btn');

  await expect(page.locator('#flow-body')).toBeVisible();
  await expect(page.locator('#qr-image')).toHaveAttribute('src', /\/api\/presentations\/.+\/qr\.png/);

  await expect(page.locator('#mock-wallet-note')).toBeVisible();
  await page.click('#simulate-scan-btn');

  await expect(page.locator('#result-panel')).toBeVisible({ timeout: 15000 });
  const resultText = await page.locator('#result-table').innerText();
  expect(resultText).toContain('given_name');
  expect(resultText).toContain('Ada');
  expect(resultText).toContain('family_name');
  expect(resultText).toContain('Lovelace');

  // status track should show VERIFIED as the active/done state, not stuck earlier
  const verifiedState = page.locator('.status-track li[data-state="VERIFIED"]');
  await expect(verifiedState).toHaveClass(/active|done/);
});

test('raw request/response view expands and shows the real signed JWT', async ({ page }) => {
  await page.goto('/');
  await page.click('#start-btn');
  await expect(page.locator('#qr-image')).toHaveAttribute('src', /\/api\/presentations\/.+\/qr\.png/);

  await page.click('#raw-view summary');
  await expect(page.locator('#raw-content')).not.toBeEmpty();
  const rawText = await page.locator('#raw-content').innerText();
  expect(rawText).toContain('requestObjectJwt');
  expect(rawText).toContain('clientId');
});

test.describe('failure simulator', () => {
  for (const [label, endpoint, expectedText] of [
    ['expired-certificate', '/api/simulate/expired-certificate', 'ExpiredCertificateException'],
    ['revoked-certificate', '/api/simulate/revoked-certificate', 'CRL'],
    ['malformed-certificate', '/api/simulate/malformed-certificate', 'tolerant fallback'],
    ['certificate-rotation', '/api/simulate/certificate-rotation', 'succeeded on retry'],
  ]) {
    test(`${label} button produces a real result card containing "${expectedText}"`, async ({ page }) => {
      await page.goto('/');
      await page.click(`button[data-endpoint="${endpoint}"]`);

      const firstCard = page.locator('#sim-results .sim-result').first();
      await expect(firstCard).toBeVisible({ timeout: 15000 });
      await expect(firstCard).toContainText(expectedText);
      // the "expected"/"unexpected" class is set from the actual response — assert it landed on
      // the expected (green) path, not the unexpected (red, bug-indicating) one
      await expect(firstCard).toHaveClass(/expected/);
    });
  }
});
