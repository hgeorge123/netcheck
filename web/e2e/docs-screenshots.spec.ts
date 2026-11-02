import { type Browser, type Page, expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';

// Walks the real UI as a user and as an administrator, asserting each step
// and saving the screenshots used by docs/*.md. Run against the lab only: it
// creates and deletes demo users and changes the destination policy (then
// restores it).
const IMG = '../docs/images';
const ADMIN_PASSWORD = process.env.NETCHECK_ADMIN_PASSWORD ?? '';
const TEMP = 'Temporary-2026-lab';
const FINAL = 'Lab-Password-2026-ok';
const TARGET = 'echo.nc-target.svc.cluster.local';

const demoUsers = [
  { username: 'alice.smith', displayName: 'Alice Smith', role: 'user', allNamespaces: false, namespaces: ['nc-allow', 'nc-open'], allowNetcheckNamespace: false },
  { username: 'network.team', displayName: 'Network Team', role: 'user', allNamespaces: true, namespaces: [], allowNetcheckNamespace: false },
  { username: 'bob.jones', displayName: 'Bob Jones', role: 'user', allNamespaces: false, namespaces: ['nc-deny'], allowNetcheckNamespace: false },
  { username: 'qa.tests', displayName: 'QA Tests', role: 'user', allNamespaces: false, namespaces: ['nc-allow', 'nc-deny'], allowNetcheckNamespace: false },
  { username: 'platform', displayName: 'Platform Team', role: 'user', allNamespaces: true, namespaces: [], allowNetcheckNamespace: true },
  { username: 'carol.white', displayName: '', role: 'user', allNamespaces: true, namespaces: [], allowNetcheckNamespace: false },
];

const ALLOW_ALL = { allowCidrs: ['0.0.0.0/0', '::/0'], denyCidrs: [], allowHostnameSuffixes: ['*'], allowPorts: [{ from: 1, to: 65535 }] };

// API calls run inside the browser (same origin, same resolver rules and
// TLS as a real user), so no hosts-file changes are needed on the machine.
type Call = (method: string, path: string, data?: unknown) => Promise<{ status: number; body: unknown }>;

async function apiSession(browser: Browser, username: string, password: string): Promise<Call> {
  const ctx = await browser.newContext({ baseURL: test.info().project.use.baseURL, ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  await page.goto('/');
  const call: Call = (method, path, data) =>
    page.evaluate(
      async ([m, p, d]) => {
        const res = await fetch(p as string, {
          method: m as string,
          headers: d === undefined ? {} : { 'Content-Type': 'application/json' },
          body: d === undefined ? undefined : JSON.stringify(d),
        });
        const text = await res.text();
        return { status: res.status, body: text ? JSON.parse(text) : null };
      },
      [method, path, data] as const,
    );
  const res = await call('POST', '/api/v1/auth/login', { username, password });
  expect(res.status, `login ${username}`).toBe(200);
  return call;
}

async function shot(page: Page, name: string, fullPage = false) {
  await page.waitForTimeout(400); // let Cloudscape transitions settle
  if (!fullPage) {
    await page.screenshot({ path: `${IMG}/${name}.png` });
    return;
  }
  // Grow the viewport instead of fullPage capture, so the sticky top
  // navigation is drawn once at the top.
  const original = page.viewportSize() ?? { width: 1440, height: 900 };
  const height = await page.evaluate(() => document.documentElement.scrollHeight);
  await page.setViewportSize({ width: original.width, height: Math.min(Math.max(height, original.height), 4000) });
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${IMG}/${name}.png` });
  await page.setViewportSize(original);
}

async function uiLogin(page: Page, username: string, password: string) {
  await page.goto('/');
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

async function selectOption(page: Page, label: string, option: string) {
  await page.getByRole('button', { name: label }).click();
  await page.getByRole('option', { name: option, exact: true }).click();
}

// Cloudscape prefixes card checkboxes with the group label; table radios use the item label only.
const check = (page: Page, name: string) => page.getByRole('checkbox', { name: `Checks ${name}`, exact: true });
const pick = (page: Page, name: string) => page.getByRole('radio', { name, exact: true });

async function newTest(page: Page, namespace: string, target: string) {
  await page.goto('/#/new');
  await expect(page.getByRole('heading', { name: 'Create test', level: 1 })).toBeVisible();
  await selectOption(page, 'Source namespace', namespace);
  await page.getByLabel('Destination').fill(target);
}

/** DNS + TCP 8080 + HTTP 8080 /hostname against the echo Service. */
async function echoChecks(page: Page) {
  await check(page, 'DNS resolution').check();
  await check(page, 'TCP connection').check();
  await check(page, 'HTTP').check();
  await page.getByLabel('Port').nth(0).fill('8080');
  await page.getByLabel('Port').nth(1).fill('8080');
  await page.getByRole('textbox', { name: 'Path', exact: true }).first().fill('/hostname');
}

async function runAndWait(page: Page, status: string) {
  await page.getByRole('button', { name: 'Run test' }).click();
  await expect(page.getByRole('heading', { name: /^Test [a-z0-9]{8}$/ })).toBeVisible();
  await expect(page.getByText(status).first()).toBeVisible({ timeout: 120_000 });
}

/** IP of the lab echo Pod (kubectl against the local kind context only). */
function echoPodIP(): string {
  if (process.env.NETCHECK_ECHO_POD_IP) return process.env.NETCHECK_ECHO_POD_IP;
  return execFileSync('kubectl', ['--context', 'kind-netcheck-lab', '-n', 'nc-target', 'get', 'pods', '-l', 'app=echo', '-o', 'jsonpath={.items[0].status.podIP}'], {
    encoding: 'utf8',
  }).trim();
}

type UserList = { items: { id: string; username: string }[] };

test.beforeAll(async ({ browser }) => {
  expect(ADMIN_PASSWORD, 'NETCHECK_ADMIN_PASSWORD is required').not.toBe('');
  const admin = await apiSession(browser, 'admin', ADMIN_PASSWORD);
  expect((await admin('PUT', '/api/v1/me/preferences', { language: 'en' })).status).toBe(200);
  expect((await admin('PUT', '/api/v1/admin/policy', ALLOW_ALL)).status).toBe(200);
  const list = (await admin('GET', '/api/v1/admin/users')).body as UserList;
  // Remove previous demo users and leftovers of the integration tests.
  for (const u of list.items.filter((x) => demoUsers.some((d) => d.username === x.username) || x.username.startsWith('itest-'))) {
    await admin('DELETE', `/api/v1/admin/users/${u.id}`);
  }
  for (const u of demoUsers.slice(0, 5)) {
    const res = await admin('POST', '/api/v1/admin/users', { ...u, password: TEMP });
    expect(res.status, `create ${u.username}`).toBe(201);
  }
  // Everybody except alice.smith already chose a password.
  for (const name of ['network.team', 'bob.jones', 'platform']) {
    const c = await apiSession(browser, name, TEMP);
    expect((await c('POST', '/api/v1/auth/password', { currentPassword: TEMP, newPassword: FINAL })).status).toBe(204);
  }
  // bob.jones gets locked by repeated failures; qa.tests is disabled.
  for (let i = 0; i < 5; i++) await admin('POST', '/api/v1/auth/login', { username: 'bob.jones', password: 'wrong-attempt-1' });
  const users = (await admin('GET', '/api/v1/admin/users')).body as UserList;
  const qa = users.items.find((u) => u.username === 'qa.tests');
  // The username cannot be sent on update.
  const disabled = await admin('PUT', `/api/v1/admin/users/${qa?.id}`, {
    displayName: 'QA Tests',
    role: 'user',
    allNamespaces: false,
    namespaces: ['nc-allow', 'nc-deny'],
    allowNetcheckNamespace: false,
    disabled: true,
  });
  expect(disabled.status, 'disable qa.tests').toBe(200);
});

test('user guide', async ({ page }) => {
  // The sign-in page is English by default, whatever the browser language.
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  await shot(page, 'user-01-sign-in');

  // First access: forced password change.
  await uiLogin(page, 'alice.smith', TEMP);
  await expect(page.getByRole('heading', { name: 'Change your password' })).toBeVisible();
  await shot(page, 'user-02-change-password');
  await page.getByLabel('Current password').fill(TEMP);
  await page.getByLabel('New password', { exact: true }).fill(FINAL);
  await page.getByLabel('Confirm new password').fill(FINAL);
  await page.getByRole('button', { name: 'Save password' }).click();

  await expect(page.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  await shot(page, 'user-03-dashboard');

  // Create test: only the assigned namespaces are offered.
  await page.getByRole('link', { name: 'Create test' }).first().click();
  await expect(page.getByRole('heading', { name: 'Create test', level: 1 })).toBeVisible();
  await shot(page, 'user-04-create-test', true);
  await page.getByRole('button', { name: 'Source namespace' }).click();
  await expect(page.getByRole('option')).toHaveCount(2);
  await shot(page, 'user-05-assigned-namespaces');
  await page.keyboard.press('Escape');

  await newTest(page, 'nc-allow', TARGET);
  await echoChecks(page);
  await check(page, 'HTTPS').check();
  await shot(page, 'user-06-default-ports', true);
  await check(page, 'HTTPS').uncheck();
  await page.getByText('Request preview').click();
  await shot(page, 'user-09-request-preview', true);
  await runAndWait(page, 'All checks passed');
  await shot(page, 'user-11-result-succeeded', true);

  await pick(page, 'HTTP').click();
  await shot(page, 'user-16-check-detail', true);
  await page.getByRole('tab', { name: 'Equivalent command' }).click();
  await shot(page, 'user-17-equivalent-command', true);

  // Firewall ticket: destination and port only, one combined output.
  await page.goto('/#/new');
  await page.getByRole('radio', { name: /Firewall ticket troubleshooting/ }).click();
  await selectOption(page, 'Source namespace', 'nc-allow');
  await page.getByLabel('Destination').fill(TARGET);
  await page.getByLabel('Port').fill('8080');
  await shot(page, 'user-07-firewall-form', true);
  await page.getByRole('button', { name: 'Run test' }).click();
  await expect(page.getByText('Firewall ticket report')).toBeVisible({ timeout: 120_000 });
  await shot(page, 'user-08-firewall-report', true);

  // Ping and traceroute without privileges, against the echo Pod IP (ICMP
  // is answered by Pods, not by ClusterIP Services).
  const echoIP = echoPodIP();
  expect(echoIP).not.toBe('');
  await newTest(page, 'nc-open', echoIP);
  await check(page, 'Ping (ICMP)').check();
  await check(page, 'Traceroute (ICMP)').check();
  await page.getByLabel('Echo requests').fill('3');
  await page.getByLabel('Max hops').fill('8');
  await runAndWait(page, 'All checks passed');
  await shot(page, 'user-12-ping', true);
  await pick(page, 'Traceroute (ICMP)').click();
  await shot(page, 'user-13-traceroute', true);

  // Same Pod from nc-allow: TCP 8080 works, ICMP is dropped by the policy.
  await newTest(page, 'nc-allow', echoIP);
  await check(page, 'TCP connection').check();
  await check(page, 'Ping (ICMP)').check();
  await page.getByLabel('Port').fill('8080');
  await page.getByLabel('Echo requests').fill('2');
  await runAndWait(page, 'Connectivity failures');
  await pick(page, 'Ping (ICMP)').click();
  await shot(page, 'user-14-ping-filtered', true);

  await page.goto('/#/runs');
  await expect(page.getByRole('heading', { name: /Test history/ })).toBeVisible();
  await expect(page.getByText(TARGET).first()).toBeVisible();
  await shot(page, 'user-19-history');

  await page.getByRole('button', { name: /Alice Smith/ }).click();
  await shot(page, 'user-20-user-menu');
  await page.getByRole('menuitem', { name: 'Preferences' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await shot(page, 'user-21-preferences');
  await page.getByRole('button', { name: 'Cancel' }).click();
  await page.getByRole('button', { name: /Alice Smith/ }).click();
  await page.getByRole('menuitem', { name: 'Change password' }).click();
  await expect(page.getByRole('heading', { name: 'Change password' })).toBeVisible();
  await shot(page, 'user-22-change-password');

  // A user with "all namespaces" diagnosing a blocked path.
  await page.getByRole('button', { name: /Alice Smith/ }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  await expect(page.getByText('You have signed out.')).toBeVisible();
  await uiLogin(page, 'network.team', FINAL);
  await newTest(page, 'nc-deny', TARGET);
  await echoChecks(page);
  await runAndWait(page, 'Connectivity failures');
  await shot(page, 'user-15-result-blocked', true);
  await pick(page, 'TCP connection').click();
  await shot(page, 'user-18-timeout-detail', true);

  // Destination rejected by the platform protections (no traffic sent).
  await newTest(page, 'nc-allow', '169.254.169.254');
  await check(page, 'TCP connection').check();
  await page.getByLabel('Port').fill('80');
  await page.getByRole('button', { name: 'Run test' }).click();
  await expect(page.getByText(/not allowed by the NetCheck policy/).first()).toBeVisible();
  await shot(page, 'user-10-denied-destination', true);
});

test('admin guide', async ({ page, browser }) => {
  await uiLogin(page, 'admin', ADMIN_PASSWORD);
  await expect(page.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  await expect(page.getByText(TARGET).first()).toBeVisible();
  await shot(page, 'admin-01-dashboard', true);

  await page.getByRole('link', { name: 'Users' }).click();
  await expect(page.getByRole('heading', { name: /Users/ })).toBeVisible();
  await expect(page.getByText('bob.jones')).toBeVisible();
  await shot(page, 'admin-02-users');

  await pick(page, 'bob.jones').click();
  await page.getByRole('button', { name: 'Actions' }).click();
  await shot(page, 'admin-03-actions');
  await page.getByRole('menuitem', { name: 'Unlock' }).click();
  await expect(page.getByText('User bob.jones unlocked.')).toBeVisible();
  await shot(page, 'admin-04-unlocked');

  await pick(page, 'bob.jones').click();
  await page.getByRole('button', { name: 'Actions' }).click();
  await page.getByRole('menuitem', { name: 'Reset password' }).click();
  await expect(page.getByText('Reset password of bob.jones')).toBeVisible();
  await shot(page, 'admin-05-reset-password');
  await page.getByRole('button', { name: 'Cancel' }).click();

  await pick(page, 'qa.tests').click();
  await page.getByRole('button', { name: 'Actions' }).click();
  await page.getByRole('menuitem', { name: 'Delete' }).click();
  await expect(page.getByText('Delete user qa.tests')).toBeVisible();
  await shot(page, 'admin-06-delete-user');
  await page.getByRole('button', { name: 'Cancel' }).click();

  // Create a user with dynamic "all namespaces" (reload clears notifications).
  await page.reload();
  await page.getByRole('button', { name: 'Create user' }).click();
  await expect(page.getByRole('heading', { name: 'Create user', level: 1 })).toBeVisible();
  await page.getByRole('textbox', { name: 'Username' }).fill('carol.white');
  await page.getByLabel('Display name').fill('Carol White');
  await page.getByRole('button', { name: 'Generate' }).click();
  await page.getByRole('radio', { name: /All namespaces/ }).click();
  await shot(page, 'admin-07-create-user-all', true);

  // Same form with specific namespaces chosen from the live cluster list.
  await page.getByRole('radio', { name: /Selected namespaces/ }).click();
  await page.getByRole('button', { name: 'Allowed namespaces' }).click();
  await page.getByRole('option', { name: 'nc-allow', exact: true }).click();
  await shot(page, 'admin-08-create-user-selected', true);
  await page.keyboard.press('Escape');
  await page.getByRole('checkbox', { name: /Allow tests in the NetCheck namespace/ }).check();
  await shot(page, 'admin-09-netcheck-namespace', true);
  await page.getByRole('checkbox', { name: /Allow tests in the NetCheck namespace/ }).uncheck();
  await page.getByRole('radio', { name: /All namespaces/ }).click();
  await page.getByRole('button', { name: 'Create user' }).last().click();
  await expect(page.getByText(/User carol.white created/)).toBeVisible();
  await shot(page, 'admin-10-user-created');

  await pick(page, 'alice.smith').click();
  await page.getByRole('button', { name: 'Actions' }).click();
  await page.getByRole('menuitem', { name: 'Edit' }).click();
  await expect(page.getByRole('heading', { name: 'Edit user alice.smith' })).toBeVisible();
  await shot(page, 'admin-11-edit-user', true);
  await page.getByRole('button', { name: 'Cancel' }).click();

  // Connected users: open a second session as platform first.
  const other = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: test.info().project.use.baseURL });
  const otherPage = await other.newPage();
  await uiLogin(otherPage, 'platform', FINAL);
  await expect(otherPage.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  await page.getByRole('link', { name: 'Active sessions' }).click();
  await expect(page.getByText('platform').first()).toBeVisible();
  await shot(page, 'admin-12-active-sessions', true);

  await page.getByRole('link', { name: 'System and versions' }).click();
  await expect(page.getByRole('heading', { name: 'Running version' })).toBeVisible();
  await shot(page, 'admin-13-system-versions', true);

  await page.goto('/#/runs');
  await expect(page.getByText(TARGET).first()).toBeVisible();
  await shot(page, 'admin-14-full-history');

  // Destination policy: restrict, save, check a public name, then restore.
  await page.getByRole('link', { name: 'Destination policy' }).click();
  await expect(page.getByRole('heading', { name: 'Destination policy', level: 1 })).toBeVisible();
  await shot(page, 'admin-15-destination-policy', true);
  await page.getByRole('button', { name: 'Cluster and private networks only' }).click();
  await expect(page.getByText('You have unsaved changes.')).toBeVisible();
  await shot(page, 'admin-16-policy-changes', true);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Destination policy saved. It applies to new tests.')).toBeVisible();
  await page.getByLabel('Hostname or IP').fill('www.google.com');
  await page.getByLabel('Port (optional)').fill('443');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByText(/^Denied:/)).toBeVisible();
  await shot(page, 'admin-17-policy-saved', true);
  await page.getByRole('button', { name: 'Allow everything' }).click();
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('You have unsaved changes.')).toBeHidden();

  // Namespaces and the exclude dialog (cancelled, nothing changes).
  await page.getByRole('link', { name: 'Namespaces' }).click();
  await expect(page.getByRole('heading', { name: 'Namespaces', level: 1 })).toBeVisible();
  await shot(page, 'admin-18-namespaces', true);
  await page.getByRole('button', { name: 'Exclude by name' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.getByRole('dialog').getByLabel('Namespace').fill('sandbox');
  await page.getByRole('dialog').getByLabel('Reason (optional)').fill('Shared sandbox, not representative');
  await shot(page, 'admin-19-exclude-namespace');
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

  await page.getByRole('link', { name: 'Data retention' }).click();
  await expect(page.getByRole('heading', { name: 'Data retention', level: 1 })).toBeVisible();
  await shot(page, 'admin-20-data-retention', true);
  await other.close();
});
