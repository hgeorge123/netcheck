// Derives the web/manual brand assets from docs/brand/netcheck-logo-original.webp
// using the Chromium bundled with Playwright (no image libraries needed):
//   - netcheck-logo.png : full logo, trimmed, transparent background
//   - netcheck-mark.png : hexagon symbol only, 256 px, transparent
//   - favicon.png       : 64 px symbol
// Usage (from web/): node ../tools/brand/process-logo.mjs
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
// Playwright is a dev dependency of web/.
const { chromium } = createRequire(join(ROOT, 'web/package.json'))('@playwright/test');
const src = readFileSync(join(ROOT, 'docs/brand/netcheck-logo-original.webp')).toString('base64');

const browser = await chromium.launch();
const page = await browser.newPage();
const out = await page.evaluate(async (b64) => {
  const img = new Image();
  img.src = `data:image/webp;base64,${b64}`;
  await img.decode();
  const W = img.naturalWidth, H = img.naturalHeight;
  const c = document.createElement('canvas');
  c.width = W; c.height = H;
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(img, 0, 0);
  const data = ctx.getImageData(0, 0, W, H);
  const px = data.data;
  // White background -> transparent, keeping anti-aliased edges smooth.
  for (let i = 0; i < px.length; i += 4) {
    const m = Math.min(px[i], px[i + 1], px[i + 2]);
    if (m > 235) {
      const a = Math.max(0, Math.min(255, Math.round(((255 - m) / 20) * 255)));
      px[i + 3] = a;
    }
  }
  ctx.putImageData(data, 0, 0);
  // Bounding boxes of visible pixels (whole logo, and the symbol on the left).
  // Rows/columns count as content only with several solid pixels, so faint
  // compression noise in the background does not widen the crop.
  const bbox = (x0, x1) => {
    const solid = (x, y) => px[(y * W + x) * 4 + 3] > 120;
    const rows = [], cols = [];
    for (let y = 0; y < H; y++) { let n = 0; for (let x = x0; x < x1; x++) if (solid(x, y)) n++; if (n > 4) rows.push(y); }
    for (let x = x0; x < x1; x++) { let n = 0; for (let y = 0; y < H; y++) if (solid(x, y)) n++; if (n > 4) cols.push(x); }
    const minY = rows[0], maxY = rows[rows.length - 1], minX = cols[0], maxX = cols[cols.length - 1];
    return { x: minX, y: minY, w: maxX - minX + 1, h: maxY - minY + 1 };
  };
  const full = bbox(0, W);
  // The symbol ends where the first long transparent column gap starts.
  let gapStart = full.x;
  for (let x = full.x; x < full.x + full.w; x++) {
    let empty = true;
    for (let y = full.y; y < full.y + full.h && empty; y++) if (px[(y * W + x) * 4 + 3] > 40) empty = false;
    if (empty) { gapStart = x; break; }
  }
  const mark = bbox(full.x, gapStart);
  const crop = (b, size, pad) => {
    const o = document.createElement('canvas');
    const side = size ?? null;
    if (side) {
      o.width = side; o.height = side;
      const s = (side - 2 * pad) / Math.max(b.w, b.h);
      const dw = b.w * s, dh = b.h * s;
      o.getContext('2d').drawImage(c, b.x, b.y, b.w, b.h, (side - dw) / 2, (side - dh) / 2, dw, dh);
    } else {
      o.width = b.w + 2 * pad; o.height = b.h + 2 * pad;
      o.getContext('2d').drawImage(c, b.x, b.y, b.w, b.h, pad, pad, b.w, b.h);
    }
    return o.toDataURL('image/png');
  };
  return { full: crop(full, null, 8), mark: crop(mark, 256, 8), favicon: crop(mark, 64, 2), boxes: { W, H, full, mark } };
}, src);
await browser.close();

const save = (rel, dataUrl) => {
  const file = join(ROOT, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, Buffer.from(dataUrl.split(',')[1], 'base64'));
  console.log('wrote', rel);
};
save('web/public/brand/netcheck-logo.png', out.full);
save('web/public/brand/netcheck-mark.png', out.mark);
save('web/public/favicon.png', out.favicon);
save('docs/brand/netcheck-logo.png', out.full);
save('docs/brand/netcheck-mark.png', out.mark);
console.log(JSON.stringify(out.boxes));
