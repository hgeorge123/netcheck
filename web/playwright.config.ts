import { defineConfig } from '@playwright/test';

// Documentation screenshots against the lab (lab.sh gateway + deploy and a
// port-forward of the Gateway to 8443). Writes ../docs/images/*.png.
//   NETCHECK_E2E_URL        default https://netcheck.lab.test:8443
//   NETCHECK_ADMIN_PASSWORD initial admin password (chart Secret)
export default defineConfig({
  testDir: './e2e',
  timeout: 300_000,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: process.env.NETCHECK_E2E_URL ?? 'https://netcheck.lab.test:8443',
    // Lab Gateway uses a self-signed certificate.
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 900 },
    locale: 'en-US',
    timezoneId: 'UTC',
    colorScheme: 'light',
    launchOptions: { args: ['--host-resolver-rules=MAP netcheck.lab.test 127.0.0.1'] },
  },
});
