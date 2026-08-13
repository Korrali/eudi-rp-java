// @ts-check
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  timeout: 30000,
  retries: 0,
  use: {
    baseURL: process.env.EUDIRP_DEMO_URL || 'http://localhost:8080',
    channel: 'chrome', // use the machine's real installed Chrome rather than downloading Chromium
    screenshot: 'only-on-failure',
  },
});
