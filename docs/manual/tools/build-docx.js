// Converts the manual's HTML into a real Word document: node build-docx.js <es|en>   (writes it to ../out)
// The content comes from the same HTML as the PDF; sizes are measured in a browser with the PDF's CSS.
const fs = require('fs');
const path = require('path');
const d = require('docx');
const { chromium } = require(path.join(__dirname, '..', '..', '..', 'web', 'node_modules', 'playwright'));

const lang = process.argv[2];
const ROOT = path.resolve(__dirname, '..');
const L = {
  es: { file: 'NetCheck-Manual-de-administracion-ES', fig: 'Figura', footer: 'NetCheck · Manual de administración', locale: 'es-ES', subject: 'Manual de administración de NetCheck' },
  en: { file: 'NetCheck-Administration-manual-EN', fig: 'Figure', footer: 'NetCheck · Administration manual', locale: 'en-US', subject: 'NetCheck administration manual' },
}[lang];
if (!L) throw new Error('usage: node build-docx.js <es|en>');
fs.mkdirSync(path.join(ROOT, 'out'), { recursive: true });
const out = path.join(ROOT, 'out', `${L.file}.docx`);

const CONTENT = 9978; // A4 width minus 17 mm margins, in twips.
const C = { ink: '16191F', muted: '5F6B7A', brand: '0972D3', dark: '033160', line: 'D1D5DB' };
const BOX = {
  note: { line: '0972D3', fill: 'F2F8FD' }, tip: { line: '037F0C', fill: 'E9F7EE' }, warn: { line: 'B97800', fill: 'FFF7E6' },
  danger: { line: 'D91515', fill: 'FDECEB' }, example: { line: '7D4FD6', fill: 'F5F0FF' },
};
const NONE = { style: d.BorderStyle.NONE, size: 0, color: 'auto' };
const NO_BORDERS = { top: NONE, bottom: NONE, left: NONE, right: NONE };
const NO_TABLE_BORDERS = { ...NO_BORDERS, insideHorizontal: NONE, insideVertical: NONE };

// ---------- Read the HTML into a small document tree ----------
function extract() {
  const BLOCK = new Set(['P', 'UL', 'OL', 'TABLE', 'FIGURE', 'PRE', 'DIV', 'H1', 'H2', 'H3', 'H4', 'SECTION']);
  const px = (e) => e.getBoundingClientRect();

  function inline(node, fmt, acc) {
    for (const c of node.childNodes) {
      if (c.nodeType === 3) {
        acc.push({ ...fmt, text: c.textContent.replace(/\s+/g, ' ') });
      } else if (c.nodeType === 1) {
        const f = { ...fmt };
        const t = c.tagName;
        if (t === 'STRONG' || t === 'B') f.b = true;
        if (t === 'EM' || t === 'I') f.i = true;
        if (t === 'CODE') f.code = true;
        if (t === 'A') f.link = c.getAttribute('href');
        if (c.classList.contains('ui')) f.ui = true;
        if (c.classList.contains('num')) f.num = true;
        inline(c, f, acc);
      }
    }
    return acc;
  }
  function tidy(runs) {
    const r = runs.map((x) => ({ ...x }));
    for (let i = 1; i < r.length; i++) if (r[i - 1].text.endsWith(' ') && r[i].text.startsWith(' ')) r[i].text = r[i].text.slice(1);
    while (r.length && !r[0].text.trim()) r.shift();
    while (r.length && !r[r.length - 1].text.trim()) r.pop();
    if (r.length) {
      r[0].text = r[0].text.replace(/^\s+/, '');
      r[r.length - 1].text = r[r.length - 1].text.replace(/\s+$/, '');
    }
    return r.filter((x) => x.text);
  }
  // Mixed content: groups loose inline nodes into paragraphs and walks the block children.
  function blocks(parent) {
    const res = [];
    let pending = [];
    const flush = () => {
      const runs = tidy(pending);
      pending = [];
      if (runs.length) res.push({ type: 'p', runs });
    };
    for (const c of parent.childNodes) {
      if (c.nodeType === 3) {
        pending.push({ text: c.textContent.replace(/\s+/g, ' ') });
      } else if (c.nodeType === 1) {
        if (c.tagName === 'SPAN' && c.classList.contains('t')) {
          flush();
          res.push({ type: 'p', cls: 'boxtitle', runs: tidy(inline(c, { b: true }, [])) });
        } else if (BLOCK.has(c.tagName)) {
          flush();
          res.push(block(c));
        } else {
          inline({ childNodes: [c] }, {}, pending);
        }
      }
    }
    flush();
    return res;
  }
  function block(e) {
    const t = e.tagName;
    if (/^H[1-4]$/.test(t)) {
      return { type: 'h', tag: t, part: e.classList.contains('part'), notoc: e.classList.contains('notoc'), id: e.id || null, runs: tidy(inline(e, {}, [])) };
    }
    if (t === 'P') return { type: 'p', cls: e.className || null, runs: tidy(inline(e, {}, [])) };
    if (t === 'UL' || t === 'OL') {
      return { type: 'list', ordered: t === 'OL', items: [...e.children].map((li) => blocks(li)) };
    }
    if (t === 'FIGURE') {
      const img = e.querySelector('img');
      const r = px(img);
      return { type: 'fig', src: img.getAttribute('src'), w: Math.round(r.width), h: Math.round(r.height), caption: tidy(inline(e.querySelector('figcaption'), {}, [])) };
    }
    if (t === 'PRE') {
      const lines = [[]];
      for (const c of e.childNodes) {
        const comment = c.nodeType === 1 && c.classList.contains('c');
        const parts = c.textContent.split('\n');
        parts.forEach((text, i) => {
          if (i > 0) lines.push([]);
          if (text) lines[lines.length - 1].push({ text, comment });
        });
      }
      while (lines.length && !lines[lines.length - 1].length) lines.pop();
      while (lines.length && !lines[0].length) lines.shift();
      return { type: 'pre', lines };
    }
    if (t === 'TABLE') {
      const first = e.querySelector('tr');
      const widths = [...first.children].map((c) => px(c).width);
      return {
        type: 'table', compact: e.classList.contains('compact'), keep: e.classList.contains('keep'), width: px(e).width, widths,
        rows: [...e.querySelectorAll('tr')].map((tr) => ({
          header: tr.parentElement.tagName === 'THEAD',
          cells: [...tr.children].map((c) => ({ center: c.classList.contains('c'), span: c.colSpan || 1, rowSpan: c.rowSpan || 1, header: c.tagName === 'TH', blocks: blocks(c) })),
        })),
      };
    }
    if (e.classList.contains('box')) {
      const kind = ['tip', 'warn', 'danger', 'example'].find((k) => e.classList.contains(k)) || 'note';
      return { type: 'box', kind, blocks: blocks(e) };
    }
    if (e.classList.contains('two')) {
      return { type: 'two', cols: [...e.children].map((c) => ({ width: px(c).width, blocks: c.tagName === 'FIGURE' ? [block(c)] : blocks(c) })) };
    }
    return { type: 'group', blocks: blocks(e) };
  }

  const c = document.querySelector('.cover');
  const cover = {
    brand: c.querySelector('.brand').textContent.trim(),
    title: c.querySelector('h1').textContent.trim(),
    subtitle: c.querySelector('.subtitle').textContent.trim(),
    meta: [...c.querySelectorAll('.meta div')].map((x) => x.textContent.trim()),
  };
  const toc = document.querySelector('#toc h1').textContent.trim();
  const body = [];
  for (const e of document.body.children) {
    if (e.matches('section')) continue;
    body.push(block(e));
  }
  return { cover, toc, body, docTitle: document.title };
}

// ---------- Build the Word document ----------
let listInstance = 0;
const dxa = (pxv) => Math.round(pxv * 15);

function textRuns(list, base = {}) {
  return list.map((r) => {
    const o = { text: r.text, ...base };
    if (r.b) o.bold = true;
    if (r.i) o.italics = true;
    if (r.ui) o.style = 'UILabel';
    if (r.code) { o.style = 'InlineCode'; o.noProof = true; }
    if (r.num) o.color = C.brand;
    if (r.link) return new d.InternalHyperlink({ anchor: r.link.slice(1), children: [new d.TextRun({ ...o, style: 'Hyperlink' })] });
    return new d.TextRun(o);
  });
}

function heading(b) {
  // The chapter number and its title were separate boxes in the PDF: an em space keeps them apart.
  const runs = b.runs.map((r, i) => (r.num ? { ...r, text: r.text + '\u2003' } : r));
  let children = textRuns(runs);
  if (b.id) children = [new d.Bookmark({ id: b.id, children })];
  const o = { children };
  if (b.tag === 'H1' && b.notoc) o.style = 'FrontHeading';
  else if (b.tag === 'H1' && b.part) o.heading = d.HeadingLevel.HEADING_1;
  else if (b.tag === 'H1') o.heading = d.HeadingLevel.HEADING_2;
  else if (b.tag === 'H2') o.heading = d.HeadingLevel.HEADING_3;
  else if (b.tag === 'H3') o.heading = d.HeadingLevel.HEADING_4;
  else o.heading = d.HeadingLevel.HEADING_5;
  return new d.Paragraph(o);
}

function spacer(ctx) {
  const p = new d.Paragraph({ style: 'Spacer', children: [] });
  p.isSpacer = true;
  return p;
}

function figure(b, ctx) {
  const file = path.join(ROOT, b.src);
  let w = b.w;
  let h = b.h;
  const max = (ctx.avail / 15);
  if (w > max) { h = Math.round((h * max) / w); w = Math.round(max); }
  const captionText = b.caption.map((r) => r.text).join('');
  return [
    new d.Paragraph({
      style: 'FigureImage',
      children: [new d.ImageRun({
        type: 'png', data: fs.readFileSync(file), transformation: { width: w, height: h },
        altText: { title: captionText.slice(0, 120), description: captionText, name: path.basename(file) },
        outline: { type: 'solidFill', solidFillType: 'rgb', value: C.line, width: 9525 },
      })],
    }),
    new d.Paragraph({
      style: 'Caption',
      children: [
        new d.TextRun({ children: [`${L.fig} `, new d.SequentialIdentifier(L.fig), '. '], bold: true, color: C.ink }),
        ...textRuns(b.caption),
      ],
    }),
  ];
}

function list(b, ctx, level = 0) {
  const res = [];
  const reference = b.ordered ? 'steps' : 'bullets';
  listInstance += 1;
  const instance = listInstance;
  for (const item of b.items) {
    let first = true;
    for (const inner of item) {
      if (inner.type === 'p' && first) {
        res.push(new d.Paragraph({
          style: b.ordered ? 'StepItem' : ctx.listStyle || 'ListItem',
          numbering: { reference, level, instance },
          children: textRuns(inner.runs, ctx.runBase),
        }));
        first = false;
      } else if (inner.type === 'list') {
        res.push(...list(inner, ctx, level + 1));
      } else {
        res.push(...build([inner], ctx));
      }
    }
  }
  return res;
}

function singleCell(width, fill, leftLine, margins, children) {
  return new d.Table({
    layout: d.TableLayoutType.FIXED,
    width: { size: width, type: d.WidthType.DXA },
    columnWidths: [width],
    borders: NO_TABLE_BORDERS,
    rows: [new d.TableRow({
      cantSplit: true,
      children: [new d.TableCell({
        width: { size: width, type: d.WidthType.DXA },
        shading: { type: d.ShadingType.CLEAR, color: 'auto', fill },
        margins: { ...margins, marginUnitType: d.WidthType.DXA },
        borders: leftLine ? { ...NO_BORDERS, left: { style: d.BorderStyle.SINGLE, size: 24, color: leftLine } } : NO_BORDERS,
        children,
      })],
    })],
  });
}

function box(b, ctx) {
  const colors = BOX[b.kind];
  const margins = { top: 120, bottom: 120, left: 200, right: 200 };
  const inner = { ...ctx, avail: ctx.avail - 400, pStyle: 'BoxText', listStyle: 'BoxListItem' };
  const kids = [];
  for (const x of b.blocks) {
    if (x.type === 'p' && x.cls === 'boxtitle') kids.push(new d.Paragraph({ style: 'BoxTitle', children: textRuns(x.runs) }));
    else kids.push(...build([x], inner));
  }
  return [singleCell(ctx.avail, colors.fill, colors.line, margins, kids), spacer(ctx)];
}

function pre(b, ctx) {
  const margins = { top: 110, bottom: 110, left: 220, right: 220 };
  const kids = b.lines.map((line) => new d.Paragraph({
    style: 'CodeBlock',
    children: line.map((r) => new d.TextRun({ text: r.text, color: r.comment ? '8FB3D9' : 'E6EDF3', noProof: true })),
  }));
  return [singleCell(ctx.avail, '0F1B2A', null, margins, kids), spacer(ctx)];
}

function table(b, ctx) {
  const cellM = b.compact ? { top: 50, bottom: 50, left: 110, right: 110 } : { top: 60, bottom: 60, left: 125, right: 125 };
  const total = Math.min(ctx.avail, ctx.avail >= CONTENT ? CONTENT : dxa(b.width));
  const sum = b.widths.reduce((a, x) => a + x, 0);
  const cols = b.widths.map((w) => Math.round((w / sum) * total));
  cols[cols.length - 1] += total - cols.reduce((a, x) => a + x, 0);
  const border = { style: d.BorderStyle.SINGLE, size: 4, color: C.line };
  const borders = { top: border, bottom: border, left: border, right: border };
  // Columns still taken by a cell that spans rows from above.
  const taken = new Array(cols.length).fill(0);
  return [
    new d.Table({
      layout: d.TableLayoutType.FIXED,
      width: { size: total, type: d.WidthType.DXA },
      columnWidths: cols,
      borders: { ...borders, insideHorizontal: border, insideVertical: border },
      rows: b.rows.map((row, ri) => {
        let col = 0;
        const skipTaken = () => { while (col < cols.length && taken[col] > 0) { taken[col] -= 1; col += 1; } };
        const children = row.cells.map((cell) => {
          skipTaken();
          const width = cols.slice(col, col + cell.span).reduce((a, x) => a + x, 0);
          if (cell.rowSpan > 1) for (let j = col; j < col + cell.span; j++) taken[j] = cell.rowSpan - 1;
          col += cell.span;
          const inner = {
            ...ctx, avail: width - cellM.left - cellM.right, pStyle: 'TableText', listStyle: 'BoxListItem',
            alignment: cell.center ? d.AlignmentType.CENTER : undefined,
            keepNext: b.keep && ri < b.rows.length - 1,
            runBase: cell.header ? { bold: true, color: C.dark } : undefined,
          };
          const kids = build(cell.blocks, inner);
          return new d.TableCell({
            width: { size: width, type: d.WidthType.DXA },
            columnSpan: cell.span > 1 ? cell.span : undefined,
            rowSpan: cell.rowSpan > 1 ? cell.rowSpan : undefined,
            margins: { ...cellM, marginUnitType: d.WidthType.DXA },
            shading: cell.header ? { type: d.ShadingType.CLEAR, color: 'auto', fill: 'E9EFF6' } : undefined,
            children: kids.length ? kids : [new d.Paragraph({ style: 'TableText', children: [] })],
          });
        });
        skipTaken();
        return new d.TableRow({ tableHeader: row.header, cantSplit: true, children });
      }),
    }),
    spacer(ctx),
  ];
}

function two(b, ctx) {
  const gap = 280;
  const sum = b.cols[0].width + b.cols[1].width;
  const a = Math.round(((ctx.avail - gap) * b.cols[0].width) / sum) + gap / 2;
  const widths = [a, ctx.avail - a];
  return [
    new d.Table({
      layout: d.TableLayoutType.FIXED,
      width: { size: ctx.avail, type: d.WidthType.DXA },
      columnWidths: widths,
      borders: NO_TABLE_BORDERS,
      rows: [new d.TableRow({
        cantSplit: true,
        children: b.cols.map((col, i) => {
          const margins = i === 0 ? { top: 0, bottom: 0, left: 0, right: gap / 2 } : { top: 0, bottom: 0, left: gap / 2, right: 0 };
          const kids = build(col.blocks, { ...ctx, avail: widths[i] - gap / 2 });
          return new d.TableCell({ width: { size: widths[i], type: d.WidthType.DXA }, margins: { ...margins, marginUnitType: d.WidthType.DXA }, borders: NO_BORDERS, children: kids });
        }),
      })],
    }),
    spacer(ctx),
  ];
}

function build(blocks, ctx) {
  const res = [];
  for (const b of blocks) {
    // Before a title that starts a new page the spacer is not needed, and if the table ended
    // exactly at the bottom of a page, it would be left alone on an otherwise blank page.
    if (b.type === 'h' && b.tag === 'H1' && res.length && res[res.length - 1].isSpacer) res.pop();
    if (b.type === 'h') {
      // Word ignores space before a paragraph that starts a page, so a blank paragraph pushes part titles down.
      if (b.part) res.push(new d.Paragraph({ style: 'PartSpacer', children: [] }));
      res.push(heading(b));
    } else if (b.type === 'p') {
      const style = b.cls === 'lead' ? 'Lead' : b.cls === 'part-desc' ? 'PartDesc' : ctx.pStyle;
      const o = { children: textRuns(b.runs, ctx.runBase) };
      if (style) o.style = style;
      if (ctx.alignment) o.alignment = ctx.alignment;
      if (ctx.keepNext) o.keepNext = true;
      res.push(new d.Paragraph(o));
    } else if (b.type === 'list') res.push(...list(b, ctx));
    else if (b.type === 'fig') res.push(...figure(b, ctx));
    else if (b.type === 'box') res.push(...box(b, ctx));
    else if (b.type === 'pre') res.push(...pre(b, ctx));
    else if (b.type === 'table') res.push(...table(b, ctx));
    else if (b.type === 'two') res.push(...two(b, ctx));
    else if (b.type === 'group') res.push(...build(b.blocks, ctx));
    else throw new Error('unknown block ' + b.type);
  }
  return res;
}

function styles() {
  const para = (id, name, run, paragraph, basedOn = 'Normal', extra = {}) => ({ id, name, basedOn, next: extra.next || 'Normal', quickFormat: true, run, paragraph });
  const head = (size, before, after, extra = {}) => ({
    run: { font: 'Segoe UI', size, bold: true, color: C.dark },
    paragraph: { spacing: { before, after, line: 264 }, keepNext: true, keepLines: true, ...extra },
  });
  return {
    default: {
      document: {
        run: { font: 'Segoe UI', size: 21, color: C.ink, language: { value: L.locale } },
        paragraph: { spacing: { after: 170, line: 276 } },
      },
      heading1: head(52, 0, 200),
      heading2: head(44, 0, 340, { pageBreakBefore: true, border: { bottom: { style: d.BorderStyle.SINGLE, size: 18, color: C.brand, space: 8 } } }),
      heading3: head(29, 454, 170),
      heading4: head(24, 340, 113),
      heading5: { run: { font: 'Segoe UI', size: 21, bold: true, color: C.ink }, paragraph: { spacing: { before: 227, after: 57 }, keepNext: true } },
      hyperlink: { run: { color: C.brand, underline: { type: d.UnderlineType.SINGLE, color: C.brand } } },
    },
    paragraphStyles: [
      para('FrontHeading', 'Front Heading', { size: 44, bold: true, color: C.dark }, { spacing: { before: 0, after: 340 }, pageBreakBefore: true, keepNext: true, border: { bottom: { style: d.BorderStyle.SINGLE, size: 18, color: C.brand, space: 8 } } }),
      para('Lead', 'Lead', { size: 23, color: '2B3440' }, {}),
      para('PartDesc', 'Part Description', { size: 25, color: C.muted }, { indent: { right: 2000 } }),
      para('ListItem', 'List Item', {}, { spacing: { after: 68 } }, 'Normal', { next: 'ListItem' }),
      para('StepItem', 'Step', {}, { spacing: { after: 136 } }, 'Normal', { next: 'StepItem' }),
      para('BoxText', 'Box Text', {}, { spacing: { after: 80 } }),
      para('BoxTitle', 'Box Title', { bold: true }, { spacing: { after: 57 }, keepNext: true }, 'Normal', { next: 'BoxText' }),
      para('BoxListItem', 'Box List Item', {}, { spacing: { after: 40 } }),
      para('TableText', 'Table Text', { size: 19 }, { spacing: { after: 0, line: 264 } }),
      para('CodeBlock', 'Code Block', { font: 'Consolas', size: 17, color: 'E6EDF3' }, { spacing: { after: 0, line: 240 }, keepNext: true, keepLines: true }),
      para('FigureImage', 'Figure Image', {}, { alignment: d.AlignmentType.CENTER, spacing: { before: 113, after: 85 }, keepNext: true }, 'Normal', { next: 'Caption' }),
      para('Caption', 'caption', { size: 18, color: C.muted }, { alignment: d.AlignmentType.CENTER, spacing: { after: 283 } }),
      para('Spacer', 'Spacer', { size: 8 }, { spacing: { before: 0, after: 113, line: 240 } }),
      para('PartSpacer', 'Part Spacer', { size: 8 }, { pageBreakBefore: true, keepNext: true, spacing: { before: 0, after: 3969, line: 240 } }),
      para('CoverBrand', 'Cover Brand', { size: 30, color: 'E6EDF5' }, { spacing: { before: 340, after: 0 } }),
      para('CoverTitle', 'Cover Title', { size: 68, bold: true, color: 'FFFFFF' }, { spacing: { before: 794, after: 340, line: 240 } }),
      para('CoverSubtitle', 'Cover Subtitle', { size: 28, color: 'EAF0F7' }, { indent: { right: 900 } }),
      para('CoverMeta', 'Cover Meta', { size: 20, color: 'DCE6F1' }, { spacing: { before: 57, after: 57 } }),
      para('TOC1', 'toc 1', { size: 22, bold: true, color: C.brand }, { spacing: { before: 200, after: 40 } }),
      para('TOC2', 'toc 2', { size: 21, bold: true }, { spacing: { before: 110, after: 20 } }),
      para('TOC3', 'toc 3', { size: 19 }, { spacing: { before: 0, after: 10 }, indent: { left: 400 } }),
    ],
    characterStyles: [
      { id: 'UILabel', name: 'UI Label', basedOn: 'DefaultParagraphFont', quickFormat: true, run: { bold: true, shading: { type: d.ShadingType.CLEAR, color: 'auto', fill: 'EEF3F8' } } },
      { id: 'InlineCode', name: 'Inline Code', basedOn: 'DefaultParagraphFont', quickFormat: true, run: { font: 'Consolas', size: 18, shading: { type: d.ShadingType.CLEAR, color: 'auto', fill: 'F4F4F4' } } },
    ],
  };
}

const numbering = {
  config: [
    {
      reference: 'bullets',
      levels: [
        { level: 0, format: d.LevelFormat.BULLET, text: '•', alignment: d.AlignmentType.LEFT, style: { paragraph: { indent: { left: 340, hanging: 227 } } } },
        { level: 1, format: d.LevelFormat.BULLET, text: '–', alignment: d.AlignmentType.LEFT, style: { paragraph: { indent: { left: 680, hanging: 227 } } } },
      ],
    },
    {
      reference: 'steps',
      levels: [
        { level: 0, format: d.LevelFormat.DECIMAL, text: '%1.', alignment: d.AlignmentType.LEFT, style: { run: { bold: true, color: C.brand }, paragraph: { indent: { left: 454, hanging: 454 } } } },
        { level: 1, format: d.LevelFormat.BULLET, text: '•', alignment: d.AlignmentType.LEFT, style: { paragraph: { indent: { left: 794, hanging: 227 } } } },
      ],
    },
  ],
};

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 1000 } });
  await page.goto('file:///' + path.join(ROOT, `manual-${lang}.html`).split(path.sep).join('/'));
  await page.waitForLoadState('networkidle');
  await page.emulateMedia({ media: 'print' });
  await page.addStyleTag({ content: 'body{width:176mm !important}' });
  const tree = await page.evaluate(extract);

  // Cover background: the same gradient as the PDF, as a picture behind real, editable text.
  const bgPage = await browser.newPage({ viewport: { width: 794, height: 1123 }, deviceScaleFactor: 1.5 });
  await bgPage.setContent('<body style="margin:0"><div style="width:794px;height:1123px;background:linear-gradient(160deg,#0f1b2a 0%,#0a3a6b 55%,#0972d3 100%)"></div></body>');
  const bg = await bgPage.screenshot({ type: 'png' });
  await browser.close();

  const cover = [
    new d.Paragraph({
      spacing: { after: 0 },
      children: [
        new d.ImageRun({
          type: 'png', data: bg, transformation: { width: 794, height: 1123 }, altText: { title: 'Cover background', description: 'Decorative background', name: 'cover-background' },
          floating: {
            horizontalPosition: { relative: d.HorizontalPositionRelativeFrom.PAGE, offset: 0 },
            verticalPosition: { relative: d.VerticalPositionRelativeFrom.PAGE, offset: 0 },
            behindDocument: true, allowOverlap: true, wrap: { type: d.TextWrappingType.NONE },
          },
        }),
        new d.ImageRun({ type: 'png', data: fs.readFileSync(path.join(ROOT, '..', 'brand', 'netcheck-mark.png')), transformation: { width: 128, height: 128 }, altText: { title: 'NetCheck', description: 'NetCheck logo', name: 'netcheck-logo' } }),
      ],
    }),
    new d.Paragraph({ style: 'CoverBrand', children: [new d.TextRun(tree.cover.brand)] }),
    new d.Paragraph({ style: 'CoverTitle', children: [new d.TextRun(tree.cover.title)] }),
    new d.Paragraph({ style: 'CoverSubtitle', children: [new d.TextRun(tree.cover.subtitle)] }),
    ...tree.cover.meta.map((text, i) => new d.Paragraph({
      style: 'CoverMeta',
      frame: {
        type: 'absolute', position: { x: 1247, y: 14400 }, width: 9412, height: 1000, rule: d.HeightRule.AUTO,
        anchor: { horizontal: d.FrameAnchorType.PAGE, vertical: d.FrameAnchorType.PAGE },
      },
      border: i === 0 ? { top: { style: d.BorderStyle.SINGLE, size: 6, color: '8FA8C4', space: 12 } } : undefined,
      children: [new d.TextRun(text)],
    })),
  ];

  const ctx = { avail: CONTENT };
  const main = [
    new d.Paragraph({ style: 'FrontHeading', children: [new d.TextRun(tree.toc)] }),
    new d.TableOfContents(tree.toc, { hyperlink: true, headingStyleRange: '1-3' }),
    ...build(tree.body, ctx),
  ];

  const pageSize = { width: 11906, height: 16838 };
  const doc = new d.Document({
    title: tree.docTitle, subject: L.subject, creator: 'NetCheck', description: L.subject,
    compatibility: { version: 15 },
    styles: styles(),
    numbering,
    sections: [
      {
        properties: { page: { size: pageSize, margin: { top: 3118, bottom: 1134, left: 1247, right: 1247, header: 0, footer: 0 } } },
        children: cover,
      },
      {
        properties: { type: d.SectionType.NEXT_PAGE, page: { size: pageSize, margin: { top: 1021, bottom: 1134, left: 964, right: 964, header: 400, footer: 454 } } },
        footers: {
          default: new d.Footer({
            children: [new d.Paragraph({
              tabStops: [{ type: d.TabStopType.RIGHT, position: CONTENT }],
              spacing: { after: 0 },
              children: [new d.TextRun({ size: 16, color: C.muted, children: [L.footer, new d.Tab(), d.PageNumber.CURRENT] })],
            })],
          }),
        },
        children: main,
      },
    ],
  });
  fs.writeFileSync(out, await d.Packer.toBuffer(doc));
  const figs = JSON.stringify(tree.body).match(/"type":"fig"/g).length;
  console.log(path.basename(out), (fs.statSync(out).size / 1048576).toFixed(1), 'MB,', figs, 'figures');
})().catch((e) => { console.error(e); process.exit(1); });
