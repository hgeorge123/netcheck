// Builds the PDF of a manual: node build-pdf.js <es|en>   (writes it to ../out; needs pdftotext from Poppler)
// Pass 1 renders with markers in each heading, pdftotext finds their pages,
// pass 2 renders the final PDF with the page numbers in the table of contents.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { chromium } = require(path.join(__dirname, '..', '..', '..', 'web', 'node_modules', 'playwright'));

const MANUALS = {
  es: { file: 'NetCheck-Manual-de-administracion-ES', footer: 'NetCheck · Manual de administración' },
  en: { file: 'NetCheck-Administration-manual-EN', footer: 'NetCheck · Administration manual' },
};
const lang = process.argv[2];
if (!MANUALS[lang]) throw new Error('usage: node build-pdf.js <es|en>');
const root = path.join(__dirname, '..');
const src = path.join(root, `manual-${lang}.html`);
fs.mkdirSync(path.join(root, 'out'), { recursive: true });
const out = path.join(root, 'out', `${MANUALS[lang].file}.pdf`);
const { footer } = MANUALS[lang];

function pagesOf(pdf) {
  const text = execFileSync('pdftotext', ['-enc', 'UTF-8', pdf, '-'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const pages = text.split('\f');
  const found = {};
  pages.forEach((p, i) => {
    for (const m of p.matchAll(/QQ(\d+)QQ/g)) if (!(m[1] in found)) found[m[1]] = i + 1;
  });
  return { found, total: pages.length - 1 };
}

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('file:///' + src.replace(/\\/g, '/'));
  await page.waitForLoadState('networkidle');
  await page.addStyleTag({
    content: `@page { @bottom-left { content: "${footer}"; font: 8pt "Segoe UI", Arial, sans-serif; color: #5f6b7a; }
      @bottom-right { content: counter(page); font: 8pt "Segoe UI", Arial, sans-serif; color: #5f6b7a; } }
      @page cover { @bottom-left { content: none; } @bottom-right { content: none; } }`,
  });
  // Table of contents from the headings, with a marker in each one.
  const count = await page.evaluate(() => {
    const toc = document.querySelector('#toc ol');
    let n = 0;
    for (const h of document.querySelectorAll('h1:not(.notoc), h2:not(.notoc)')) {
      if (h.closest('#toc') || h.closest('.cover')) continue;
      n += 1;
      h.id = h.id || `s${n}`;
      const marker = document.createElement('span');
      marker.className = 'pm';
      marker.textContent = `QQ${n}QQ`;
      h.appendChild(marker);
      const li = document.createElement('li');
      li.className = h.tagName === 'H1' ? `l1${h.classList.contains('part') ? ' part' : ''}` : 'l2';
      const num = h.querySelector('.num');
      const label = [...h.childNodes].filter((c) => !(c.classList && (c.classList.contains('pm') || c.classList.contains('num')))).map((c) => c.textContent).join('').trim();
      li.innerHTML = `<a href="#${h.id}"><span class="t"></span><span class="dots"></span><span class="p" data-n="${n}">00</span></a>`;
      li.querySelector('.t').textContent = label;
      if (num) { const n = document.createElement('span'); n.className = 'n'; n.textContent = num.textContent; li.querySelector('a').prepend(n); }
      toc.appendChild(li);
    }
    return n;
  });
  const opts = { format: 'A4', printBackground: true, preferCSSPageSize: true, outline: true, tagged: true };
  const tmp = out.replace(/\.pdf$/, '.pass1.pdf');
  await page.pdf({ ...opts, path: tmp });
  const { found, total } = pagesOf(tmp);
  const missing = [...Array(count).keys()].map((i) => String(i + 1)).filter((k) => !(k in found));
  if (missing.length) console.log('markers not found:', missing.join(','));
  await page.evaluate((f) => {
    for (const s of document.querySelectorAll('#toc .p')) s.textContent = f[s.dataset.n] ?? '';
  }, found);
  await page.pdf({ ...opts, path: out });
  const check = pagesOf(out);
  const moved = Object.keys(found).filter((k) => check.found[k] !== found[k]);
  console.log(`${path.basename(out)}: ${check.total} pages, ${count} headings, ${moved.length} moved`, (fs.statSync(out).size / 1048576).toFixed(1), 'MB');
  fs.unlinkSync(tmp);
  await browser.close();
})();
