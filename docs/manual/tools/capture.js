// Captures the screenshots of the administration manual from the kind lab (see ../README.md).
// Usage: NETCHECK_ADMIN_PASSWORD=... node capture.js <en|es> [only-shot-prefix...]
const fs = require('fs');
const path = require('path');
const { chromium } = require(path.join(__dirname, '..', '..', '..', 'web', 'node_modules', 'playwright'));
const L = require('./labels.js');

const lang = process.argv[2];
const only = process.argv.slice(3);
if (!['en', 'es'].includes(lang)) throw new Error('usage: node capture.js <en|es>');
const D = L[lang];
const T = (k, vars = {}) => {
  const v = D[k];
  if (v === undefined) throw new Error(`missing label ${k}`);
  return v.replace(/\{(\w+)\}/g, (_, n) => (vars[n] ?? `{${n}}`));
};
const U = process.env.NETCHECK_URL || 'http://localhost:8080';
const OUT = path.join(__dirname, '..', 'img', lang);
fs.mkdirSync(OUT, { recursive: true });
// Id of the sample test, kept between runs that capture only some of the screenshots.
const WORK = path.join(__dirname, '..', 'out');
fs.mkdirSync(WORK, { recursive: true });
const RUN_FILE = path.join(WORK, `run-custom-${lang}.txt`);
const PW = process.env.NETCHECK_ADMIN_PASSWORD;
if (!PW) throw new Error('set NETCHECK_ADMIN_PASSWORD to the password of the admin account of the lab');
const TARGET = 'echo.nc-target.svc.cluster.local';
const W = 1280;
const H = 800;

// Sample data in the language of the manual.
const DATA = {
  en: {
    groups: { 'Equipo de pagos': ['Payments team', 'Payments squad'], Plataforma: ['Platform', 'Platform administrators'] },
    roles: {
      'Equipo (ve pruebas del grupo)': ['Team (sees the group\'s tests)', 'Every check, and the tests of the people of its groups'],
      'Network on-call': ['Network on-call', 'Network on-call: TCP, ping and traceroute; manages the destination policy and the shared proxies'],
    },
  },
  es: {
    groups: { 'Payments team': ['Equipo de pagos', 'Squad de pagos'], Platform: ['Plataforma', 'Administradores de la plataforma'] },
    roles: {
      'Team (sees the group\'s tests)': ['Equipo (ve pruebas del grupo)', 'Todas las comprobaciones y las pruebas de las personas de sus grupos'],
      'Network on-call': ['Network on-call', 'Guardia de red: TCP, ping y traceroute; gestiona la política de destinos y los proxies compartidos'],
    },
  },
};

let page;
const failures = [];
const want = (name) => only.length === 0 || only.some((p) => name.startsWith(p));

async function settle(ms = 500) {
  await page.waitForLoadState('networkidle').catch(() => {});
  await page.waitForTimeout(ms);
}

async function shot(name, opts = {}) {
  await settle(opts.wait ?? 500);
  const file = path.join(OUT, `${name}.png`);
  if (opts.element) {
    await opts.element.screenshot({ path: file });
  } else if (opts.full) {
    const height = await page.evaluate(() => document.documentElement.scrollHeight);
    await page.setViewportSize({ width: W, height: Math.min(Math.max(height, H), opts.maxHeight ?? 3000) });
    await page.waitForTimeout(400);
    await page.screenshot({ path: file });
    await page.setViewportSize({ width: W, height: H });
  } else if (opts.clip) {
    await page.screenshot({ path: file, clip: opts.clip });
  } else {
    await page.screenshot({ path: file });
  }
  console.log('shot', name);
}

async function step(name, fn) {
  if (!want(name)) return;
  try {
    await fn();
  } catch (e) {
    failures.push(`${name}: ${e.message.split('\n')[0]}`);
    console.log('FAIL', name, e.message.split('\n')[0]);
    await page.keyboard.press('Escape').catch(() => {});
  }
}

// Left edge of the page content (breadcrumbs) and bottom of the content.
async function contentBox() {
  return page.evaluate(() => {
    const crumbs = document.querySelector('nav[aria-label] ol') || document.querySelector('h1');
    const left = Math.max(0, Math.floor(crumbs.getBoundingClientRect().left) - 18);
    const main = document.querySelector('main') || document.body;
    let bottom = 0;
    // Leaf elements only (text, inputs, icons), so empty layout boxes do not count.
    for (const e of main.querySelectorAll('*')) {
      const media = ['INPUT', 'BUTTON', 'svg', 'IMG', 'TEXTAREA', 'SELECT'].includes(e.tagName);
      if (e.children.length > 0 && !media) continue;
      if (!media && !e.textContent.trim()) continue;
      if (e.closest('nav') && e.closest('nav').getBoundingClientRect().height > 400) continue;
      const r = e.getBoundingClientRect();
      if (r.width > 0 && r.height > 0 && r.height < 2000 && getComputedStyle(e).visibility !== 'hidden') bottom = Math.max(bottom, r.bottom);
    }
    // Include the border of the container around the last element.
    bottom += 18;
    const header = document.querySelector('header');
    const top = header ? Math.ceil(header.getBoundingClientRect().bottom) : 0;
    return { left, bottom: Math.ceil(bottom), top };
  });
}

async function tall() {
  const height = await page.evaluate(() => document.documentElement.scrollHeight);
  await page.setViewportSize({ width: W, height: Math.min(Math.max(height, H), 6000) });
  await page.waitForTimeout(500);
}

// The page content only (no side navigation), as tall as it is.
async function mainShot(name, opts = {}) {
  await settle(opts.wait ?? 500);
  await tall();
  const b = await contentBox();
  const y = opts.withHeader ? 0 : b.top;
  const clip = { x: b.left, y, width: W - b.left, height: Math.min(b.bottom + 16, opts.maxHeight ?? 6000) - y };
  await page.screenshot({ path: path.join(OUT, `${name}.png`), clip });
  await page.setViewportSize({ width: W, height: H });
  console.log('shot', name, Math.round(clip.width), 'x', Math.round(clip.height));
}

// Slices of a long page between headings: specs = [[name, startHeading, endHeading|null], ...].
async function sections(specs) {
  await settle(600);
  await tall();
  const b = await contentBox();
  for (const [name, start, end] of specs) {
    const ys = await page.evaluate(
      ([s, e]) => {
        const hs = [...document.querySelectorAll('h1,h2,h3')];
        const find = (t) => hs.find((h) => h.textContent.trim().startsWith(t));
        const hs1 = find(s);
        const he = e ? find(e) : null;
        return { s: hs1 ? hs1.getBoundingClientRect().top + window.scrollY : null, e: he ? he.getBoundingClientRect().top + window.scrollY : null };
      },
      [start, end],
    );
    if (ys.s === null) throw new Error(`heading not found: ${start}`);
    const top = Math.max(b.top, ys.s - 30);
    const bottom = ys.e !== null ? ys.e - 32 : b.bottom + 16;
    await page.screenshot({ path: path.join(OUT, `${name}.png`), clip: { x: b.left, y: top, width: W - b.left, height: bottom - top } });
    console.log('shot', name, Math.round(bottom - top));
  }
  await page.setViewportSize({ width: W, height: H });
}

async function go(hash) {
  await page.goto(`${U}/${hash}`);
  await settle(700);
}

const api = (method, p, body) =>
  page.evaluate(
    async ([m, u, b]) => {
      const res = await fetch(u, { method: m, headers: b === undefined ? {} : { 'Content-Type': 'application/json' }, body: b === undefined ? undefined : JSON.stringify(b) });
      const text = await res.text();
      return { status: res.status, body: text ? JSON.parse(text) : null };
    },
    [method, p, body],
  );

async function selectRow(text) {
  const row = page.getByRole('row').filter({ hasText: text }).first();
  await row.locator('input[type="radio"]').check({ force: true });
}

// Tall viewport so a long modal fits, then capture only the dialog box.
async function dialogShot(name, height = 1300) {
  await page.setViewportSize({ width: W, height });
  await page.waitForTimeout(500);
  const box = page.locator('[class*="awsui_dialog_"]:visible').first();
  const target = (await box.count()) ? box : page.locator('[role="dialog"]:visible').first();
  await shot(name, { element: target });
  await page.setViewportSize({ width: W, height: H });
}

async function closeDialog() {
  await page.getByRole('dialog').getByRole('button', { name: T('common.cancel'), exact: true }).first().click().catch(async () => page.keyboard.press('Escape'));
  await page.waitForTimeout(300);
}

async function waitRun() {
  await page.waitForURL(/#\/runs\/[a-z0-9]+/, { timeout: 30000 });
  const id = /#\/runs\/([a-z0-9]+)/.exec(page.url())[1];
  for (let i = 0; i < 90; i++) {
    const r = await api('GET', `/api/v1/runs/${id}`);
    if (!['queued', 'running'].includes(r.body?.status)) break;
    await page.waitForTimeout(2000);
  }
  await page.reload();
  await settle(1200);
  return id;
}

async function chooseNamespace(ns) {
  await page.getByRole('button', { name: T('newTest.namespace') }).click();
  await page.getByRole('option', { name: ns, exact: true }).click();
}

const card = (method) => page.getByRole('checkbox', { name: `${T('newTest.checks')} ${T(`method.${method}`)}`, exact: true });

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: 1.5, locale: lang === 'es' ? 'es-ES' : 'en-US', timezoneId: 'UTC', colorScheme: 'light' });
  page = await ctx.newPage();

  // Sign-in page in the manual language.
  await page.goto(U);
  await page.evaluate((l) => window.localStorage.setItem('netcheck.language', l), lang);
  await page.reload();
  await settle(800);
  await step('01-login', () => shot('01-login', { clip: { x: 300, y: 0, width: 980, height: 500 } }));
  await page.getByLabel(T('login.username')).fill('admin');
  await page.getByLabel(T('login.password'), { exact: true }).fill(PW);
  await page.getByRole('button', { name: T('login.submit'), exact: true }).click();
  await page.waitForTimeout(1500);
  const pref = await api('PUT', '/api/v1/me/preferences', { language: lang });
  if (pref.status !== 200) throw new Error(`preferences ${pref.status}`);
  await page.evaluate((l) => window.localStorage.setItem('netcheck.language', l), lang);
  await page.reload();
  await settle(800);
  const me = await api('GET', '/api/v1/me');
  console.log('language', me.body.language, await page.evaluate(() => document.documentElement.lang));

  // Sample names in the manual language.
  const groups = (await api('GET', '/api/v1/admin/groups')).body.items;
  for (const g of groups) {
    const to = DATA[lang].groups[g.name];
    if (!to) continue;
    const { name, description, role, allNamespaces, allowNetcheckNamespace, namespaces, members } = g;
    const r = await api('PUT', `/api/v1/admin/groups/${g.id}`, { name: to[0], description: to[1], role, allNamespaces, allowNetcheckNamespace, namespaces, members });
    console.log('group', name, '->', to[0], r.status);
  }
  const roles = (await api('GET', '/api/v1/admin/roles')).body.roles;
  for (const r of roles) {
    const to = DATA[lang].roles[r.name];
    if (!to) continue;
    const res = await api('PUT', `/api/v1/admin/roles/${r.id}`, { name: to[0], description: to[1], permissions: r.permissions });
    console.log('role', r.name, '->', to[0], res.status);
  }

  await go('#/');
  await step('02-dashboard', () => shot('02-dashboard'));

  await step('03-user-menu', async () => {
    await page.locator('header').getByRole('button', { name: /Administrator|Administrador/ }).first().click();
    await shot('03-user-menu', { clip: { x: 640, y: 0, width: 640, height: 260 } });
    await page.keyboard.press('Escape');
  });

  await step('04-preferences', async () => {
    await page.locator('header').getByRole('button', { name: /Administrator|Administrador/ }).first().click();
    await page.getByRole('menuitem', { name: T('nav.userMenu.preferences') }).click();
    await page.waitForTimeout(500);
    await dialogShot('04-preferences', H);
    await closeDialog();
  });

  await step('05-change-password', async () => {
    await go('#/account/password');
    await mainShot('05-change-password');
  });

  // ---- Create test ----
  await step('06-new-test', async () => {
    await go('#/new');
    await sections([['06-new-test', T('newTest.mode'), T('newTest.checks')]]);
  });

  let customRun = '';
  await step('07-new-test-filled', async () => {
    await go('#/new');
    await chooseNamespace('nc-open');
    await page.getByLabel(T('newTest.target')).fill(TARGET);
    for (const m of ['dns', 'tcp', 'http', 'ping', 'traceroute']) await card(m).check();
    await page.getByLabel(T('newTest.port')).nth(0).fill('8080');
    await page.getByLabel(T('newTest.port')).nth(1).fill('8080');
    await page.getByRole('textbox', { name: T('newTest.path'), exact: true }).first().fill('/hostname');
    await page.getByLabel(T('newTest.pingCount')).fill('3');
    await page.getByLabel(T('newTest.maxHops')).fill('8');
    await page.getByText(T('newTest.advanced'), { exact: true }).click();
    await page.getByText(T('newTest.preview'), { exact: true }).click();
    await page.waitForTimeout(400);
    await sections([
      ['07-new-test-checks', T('newTest.checks'), T('newTest.settings')],
      ['07b-new-test-settings', T('newTest.settings'), T('newTest.advanced')],
      ['08-request-preview', T('newTest.advanced'), null],
    ]);
    await page.getByRole('button', { name: T('newTest.run'), exact: true }).click();
    customRun = await waitRun();
    fs.writeFileSync(RUN_FILE, customRun);
  });

  await step('09-result', async () => {
    if (!customRun) customRun = fs.readFileSync(RUN_FILE, 'utf8').trim();
    await go(`#/runs/${customRun}`);
    await page.waitForTimeout(1500);
    const row = page.getByRole('row').filter({ hasText: 'HTTP' }).first();
    await row.locator('input[type="radio"]').check({ force: true }).catch(() => row.click());
    await page.waitForTimeout(800);
    const detail = T('run.detailOf', { method: 'HTTP' });
    await sections([
      ['09-result-top', T('run.title', { id: customRun.slice(0, 8) }), T('path.title')],
      ['09b-result-path', T('path.title'), T('run.checks')],
      ['10-check-detail', T('run.checks'), T('missing.title')],
      ['10b-missing', T('missing.title'), null],
    ]);
    await page.getByRole('tab', { name: T('run.tab.command') }).first().click();
    await page.waitForTimeout(500);
    await sections([['11-equivalent-command', detail, T('missing.title')]]);
  });

  await step('12-firewall', async () => {
    await go('#/new');
    await page.getByRole('radio', { name: new RegExp(T('newTest.mode.firewall')) }).click();
    await chooseNamespace('nc-open');
    await page.getByLabel(T('newTest.target')).fill(TARGET);
    await page.getByLabel(T('newTest.fwPort')).fill('8080');
    await mainShot('12-firewall-form');
    await page.getByRole('button', { name: T('newTest.run'), exact: true }).click();
    await waitRun();
    await page.waitForTimeout(800);
    await sections([['13-firewall-report', T('fw.panelTitle'), T('path.title')]]);
  });

  await step('14-history', async () => {
    await go('#/runs');
    await mainShot('14-history');
  });

  await step('15-my-tokens', async () => {
    await go('#/account/tokens');
    await mainShot('15-my-tokens');
    await page.getByRole('button', { name: T('tokens.create'), exact: true }).first().click();
    await page.waitForTimeout(400);
    await dialogShot('16-create-token', H);
    await closeDialog();
  });

  await step('17-my-proxies', async () => {
    await go('#/account/proxies');
    await mainShot('17-my-proxies');
    await page.getByRole('button', { name: T('proxies.add'), exact: true }).first().click();
    await page.waitForTimeout(400);
    await dialogShot('18-add-personal-proxy');
    await closeDialog();
  });

  // ---- Administration ----
  await step('19-admin-nav', async () => {
    await go('#/admin/users');
    await shot('19-admin-nav', { clip: { x: 0, y: 0, width: 300, height: 720 } });
  });

  await step('20-users', async () => {
    await go('#/admin/users');
    await mainShot('20-users');
  });

  await step('21-user-actions', async () => {
    await go('#/admin/users');
    await selectRow('carol.white');
    await page.getByRole('button', { name: T('common.actions'), exact: true }).click();
    await page.waitForTimeout(400);
    const b = await contentBox();
    await shot('21-user-actions', { clip: { x: b.left, y: b.top, width: W - b.left, height: 360 } });
    await page.keyboard.press('Escape');
  });

  for (const [name, item] of [
    ['25-reset-password', 'users.action.reset'],
    ['26-disable-user', 'users.action.disable'],
    ['27-delete-user', 'users.action.delete'],
  ]) {
    await step(name, async () => {
      await go('#/admin/users');
      await selectRow('carol.white');
      await page.getByRole('button', { name: T('common.actions'), exact: true }).click();
      await page.getByRole('menuitem', { name: T(item), exact: true }).click();
      await page.waitForTimeout(500);
      await dialogShot(name, H);
      await closeDialog();
    });
  }

  await step('22-create-user', async () => {
    await go('#/admin/users/new');
    await page.getByRole('textbox', { name: T('users.form.username') }).fill('maria.lopez');
    await page.getByLabel(T('users.form.display')).fill('María López');
    await sections([
      ['22-create-user-account', T('users.form.account'), T('users.form.namespaces')],
      ['22b-create-user-all', T('users.form.namespaces'), null],
    ]);
    await page.getByRole('radio', { name: new RegExp(`^${T('users.form.scopeSome')}`) }).click();
    await page.waitForTimeout(300);
    await page.getByRole('button', { name: new RegExp(T('users.form.pick')) }).first().click().catch(() => {});
    await page.waitForTimeout(500);
    const b = await contentBox();
    const top = await page.getByRole('heading', { name: T('users.form.namespaces') }).first().evaluate((h) => h.getBoundingClientRect().top);
    await shot('23-create-user-selected', { clip: { x: b.left, y: top - 30, width: W - b.left, height: Math.min(H - (top - 30), 420) } });
  });

  await step('24-edit-user', async () => {
    const users = (await api('GET', '/api/v1/admin/users')).body.items;
    const carol = users.find((u) => u.username === 'carol.white');
    await go(`#/admin/users/${carol.id}`);
    await sections([
      ['24-edit-user-account', T('users.form.account'), T('users.form.namespaces')],
      ['24b-edit-user-namespaces', T('users.form.namespaces'), T('perms.title')],
      ['24c-effective-permissions', T('perms.title'), null],
    ]);
  });

  await step('28-groups', async () => {
    await go('#/admin/groups');
    await mainShot('28-groups');
    await selectRow(lang === 'en' ? 'Payments team' : 'Equipo de pagos');
    await page.getByRole('button', { name: T('groups.edit'), exact: true }).click();
    await page.waitForTimeout(500);
    await dialogShot('29-edit-group');
    await closeDialog();
  });

  await step('30-roles', async () => {
    await go('#/admin/roles');
    await mainShot('30-roles');
    await selectRow('Network on-call');
    await page.getByRole('button', { name: T('roles.edit'), exact: true }).click();
    await page.waitForTimeout(500);
    await dialogShot('31-edit-role', 1900);
    await closeDialog();
  });

  await step('32-access-rules', async () => {
    await go('#/admin/access-rules');
    await mainShot('32-access-rules');
    await page.getByRole('button', { name: T('rules.create'), exact: true }).first().click();
    await page.waitForTimeout(500);
    await dialogShot('33-create-rule');
    await closeDialog();
  });

  await step('34-namespaces', async () => {
    await go('#/admin/namespaces');
    await mainShot('34-namespaces');
    await page.getByRole('button', { name: T('ns.excludeByName'), exact: true }).click();
    await page.waitForTimeout(400);
    await page.getByRole('dialog').getByLabel(T('ns.name'), { exact: true }).fill('sandbox');
    await page.getByRole('dialog').getByLabel(T('ns.reason')).fill(lang === 'en' ? 'Shared sandbox, not representative' : 'Sandbox compartido, no representativo');
    await dialogShot('35-exclude-namespace', H);
    await closeDialog();
  });

  await step('36-policy', async () => {
    await go('#/admin/policy');
    await page.getByLabel(T('policy.checkTarget')).fill('169.254.169.254');
    await page.getByLabel(T('policy.checkPort')).fill('80');
    await page.getByRole('button', { name: T('policy.checkRun'), exact: true }).click();
    await page.waitForTimeout(800);
    await sections([
      ['36-policy-top', T('policy.title'), T('policy.allowCidrs')],
      ['36b-policy-networks', T('policy.allowCidrs'), T('policy.denyCidrs')],
      ['37-policy-protections', T('policy.denyCidrs'), null],
    ]);
  });

  await step('38-check-types', async () => {
    await go('#/admin/check-types');
    await mainShot('38-check-types');
  });

  await step('39-cas', async () => {
    await go('#/admin/trusted-cas');
    await mainShot('39-cas');
    await page.getByRole('button', { name: T('cas.add'), exact: true }).first().click();
    await page.waitForTimeout(500);
    await dialogShot('40-add-ca', H);
    await closeDialog();
  });

  await step('41-proxies', async () => {
    await go('#/admin/proxies');
    await mainShot('41-proxies');
    await selectRow('corp-egress');
    await page.getByRole('button', { name: T('proxies.edit'), exact: true }).click();
    await page.waitForTimeout(500);
    await dialogShot('42-edit-proxy');
    await closeDialog();
  });

  await step('43-retention', async () => {
    await go('#/admin/retention');
    await mainShot('43-retention');
  });

  await step('44-sessions', async () => {
    await go('#/admin/sessions');
    await mainShot('44-sessions');
  });

  await step('45-admin-tokens', async () => {
    await go('#/admin/tokens');
    await mainShot('45-admin-tokens');
  });

  await step('46-system', async () => {
    await go('#/admin/system');
    await sections([
      ['46-system-version', T('system.title'), T('system.settings')],
      ['46b-system-settings', T('system.settings'), null],
    ]);
  });


  console.log(failures.length ? `FAILURES:\n${failures.join('\n')}` : 'all shots ok');
  await browser.close();
})();
