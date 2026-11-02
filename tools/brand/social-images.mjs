// Renders the GitHub images from the brand assets with the Chromium bundled
// with Playwright:
//   - social-preview.png : 1280x640 repository social preview (Settings > General)
//   - netcheck-avatar.png: 512x512 avatar for an account or organization
// Usage (from web/): node ../tools/brand/social-images.mjs
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const { chromium } = createRequire(join(ROOT, 'web/package.json'))('@playwright/test');
const brand = join(ROOT, 'docs/brand');
const dataUrl = (f) => `data:image/png;base64,${readFileSync(join(brand, f)).toString('base64')}`;

const browser = await chromium.launch();

async function render(file, width, height, html) {
  const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 });
  await page.setContent(html);
  await page.evaluate(() => Promise.all([...document.images].map((i) => i.decode())));
  await page.screenshot({ path: join(brand, file) });
  await page.close();
}

const font = "font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;";

await render(
  'social-preview.png',
  1280,
  640,
  `<body style="margin:0;width:1280px;height:640px;background:#ffffff;display:flex;flex-direction:column;
    align-items:center;justify-content:center;gap:40px;${font}">
    <img src="${dataUrl('netcheck-logo.png')}" style="width:760px">
    <div style="font-size:38px;color:#16191f;text-align:center;line-height:1.35;max-width:1080px">
      Network connectivity diagnostics from Kubernetes namespaces
    </div>
    <div style="font-size:26px;color:#5f6b7a">DNS · TCP · HTTP(S) · ping · traceroute · firewall tickets</div>
  </body>`,
);

await render(
  'netcheck-avatar.png',
  512,
  512,
  `<body style="margin:0;width:512px;height:512px;background:#ffffff;display:flex;align-items:center;justify-content:center">
    <img src="${dataUrl('netcheck-mark.png')}" style="width:380px">
  </body>`,
);

await browser.close();
console.log('wrote docs/brand/social-preview.png and docs/brand/netcheck-avatar.png');
