import createWrapper from '@cloudscape-design/components/test-utils/dom';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError, type Api } from '../../services/api';
import { renderI18n } from '../../test/render';
import type { CheckTypesView, GroupView, RoleView, DestinationPolicy, PolicyView, ProxiesView, Proxy, TrustedCAsView, TrustedCertificate, UserView } from '../../types/api';
import { CheckTypesPage } from './CheckTypesPage';
import { RolesPage } from './RolesPage';
import { GroupsPage } from './GroupsPage';
import { AccessRulesPage } from './AccessRulesPage';
import { NamespacesPage } from './NamespacesPage';
import { ALLOW_ALL, PolicyPage } from './PolicyPage';
import { ProxiesPage, type ProxyCalls } from './ProxiesPage';
import { RetentionPage } from './RetentionPage';
import { browserName, SessionsPage } from './SessionsPage';
import { shortDigest, SystemPage } from './SystemPage';
import { shortFingerprint, TrustedCAsPage } from './TrustedCAsPage';
import { UserFormPage } from './UserFormPage';
import { UsersPage } from './UsersPage';

const common = { createdAt: '2026-10-21T10:00:00Z', passwordChangedAt: '2026-10-21T10:00:00Z', language: '', allowNetcheckNamespace: false, source: 'local' as const, groups: [] as string[] };
const users: UserView[] = [
  { ...common, id: 'u000000000000000000000001', username: 'admin', displayName: 'Administrator', role: 'admin', allNamespaces: true, namespaces: [], disabled: false, locked: false, mustChangePassword: false },
  { ...common, id: 'u000000000000000000000002', username: 'bob', displayName: 'Bob', role: 'user', allNamespaces: false, namespaces: ['payments'], disabled: false, locked: true, mustChangePassword: false, allowNetcheckNamespace: true },
  { ...common, id: 'u000000000000000000000003', username: 'carol', displayName: '', role: 'user', allNamespaces: true, namespaces: [], disabled: true, locked: false, mustChangePassword: true },
];

const ALL_PERMS = ['check.dns', 'check.tcp', 'check.udp', 'check.http', 'check.https', 'check.ping', 'check.traceroute', 'mode.firewall', 'runs.all', 'proxies.useShared', 'proxies.personal', 'tokens.create'];
const builtinRoles: RoleView[] = [
  { id: 'user', name: 'User', description: '', permissions: ALL_PERMS.filter((p) => p !== 'runs.all'), builtin: true, users: 0, rules: 0, groups: 0, updatedAt: common.createdAt, updatedBy: 'system' },
  { id: 'admin', name: 'Administrator', description: '', permissions: ALL_PERMS, builtin: true, users: 0, rules: 0, groups: 0, updatedAt: common.createdAt, updatedBy: 'system' },
];
const oncall: RoleView = { id: 'oncall', name: 'On-call', description: 'Network on-call', permissions: ['check.tcp', 'check.ping', 'tokens.create'], builtin: false, users: 1, rules: 0, groups: 0, updatedAt: common.createdAt, updatedBy: 'admin' };

const platformGroup: GroupView = {
  id: 'g1', name: 'Payments team', description: 'Squad de pagos', role: 'oncall', roleName: 'On-call', allNamespaces: false,
  allowNetcheckNamespace: false, namespaces: ['payments'], members: ['u000000000000000000000002'], updatedAt: common.createdAt, updatedBy: 'admin',
};

function checkTypesView(editable = true): CheckTypesView {
  const types = ['dns', 'tcp', 'udp', 'http', 'https', 'ping', 'traceroute', 'firewall'] as const;
  return { types: types.map((type) => ({ type, enabled: true })), managedBy: editable ? 'ui' : 'helm', editable, updatedAt: common.createdAt, updatedBy: 'helm (initial values)' };
}

function mockAdmin(over: Partial<Api['admin']> = {}): Api['admin'] {
  return {
    listUsers: vi.fn().mockResolvedValue({ items: users }),
    getUser: vi.fn().mockImplementation((id: string) => Promise.resolve(users.find((u) => u.id === id))),
    createUser: vi.fn().mockResolvedValue(users[1]),
    updateUser: vi.fn().mockResolvedValue(users[1]),
    deleteUser: vi.fn().mockResolvedValue(undefined),
    resetPassword: vi.fn().mockResolvedValue(undefined),
    unlock: vi.fn().mockResolvedValue(undefined),
    namespaces: vi.fn().mockResolvedValue({ items: ['orders', 'payments', 'shipping'], mode: 'all', netcheckNamespace: 'netcheck' }),
    sessions: vi.fn().mockResolvedValue({
      connectedUsers: 2,
      idleTimeoutMinutes: 30,
      items: [
        { id: 's1', userId: users[0]!.id, username: 'admin', displayName: '', role: 'admin', signedInAt: common.createdAt, lastSeenAt: common.createdAt, expiresAt: common.createdAt, clientIp: '10.0.0.1', userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/140.0 Safari/537.36', current: true },
        { id: 's2', userId: users[1]!.id, username: 'bob', displayName: 'Bob', role: 'user', signedInAt: common.createdAt, lastSeenAt: common.createdAt, expiresAt: common.createdAt, clientIp: '10.0.0.2', userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0', current: false },
      ],
    }),
    revokeSession: vi.fn().mockResolvedValue(undefined),
    system: vi.fn().mockResolvedValue({
      current: { version: '0.3.0', commit: 'abc123', buildDate: '2026-10-21', image: 'repo/netcheck@sha256:1', probeImage: 'repo/probe@sha256:2', chartVersion: '0.3.0', firstSeenAt: common.createdAt, lastStartedAt: common.createdAt, starts: 2 },
      history: [
        { version: '0.3.0', commit: 'abc123', buildDate: '2026-10-21', image: 'repo/netcheck@sha256:1', probeImage: 'repo/probe@sha256:2', chartVersion: '0.3.0', firstSeenAt: common.createdAt, lastStartedAt: common.createdAt, starts: 2 },
        { version: '0.2.0', commit: 'def456', buildDate: '2026-10-01', image: 'repo/netcheck@sha256:0', probeImage: 'repo/probe@sha256:0', chartVersion: '0.2.0', firstSeenAt: common.createdAt, lastStartedAt: common.createdAt, starts: 5 },
      ],
      clusterId: 'lab',
      namespaceScope: 'all',
      netcheckNamespace: 'netcheck',
      protectPlatformDestinations: true,
      destinationsManagedBy: 'ui',
      limits: { maxChecks: 6, maxCheckTimeoutSeconds: 10, maxJobSeconds: 90, settleSeconds: 3 },
      destinations: { allowCidrs: ['10.0.0.0/16'], denyCidrs: [], allowHostnameSuffixes: ['.svc.cluster.local'], allowPorts: [{ from: 80, to: 80 }, { from: 8080, to: 8443 }] },
      retention: { outputDays: 15, metadataDays: 45, updatedAt: common.createdAt, updatedBy: 'helm (initial values)' },
    }),
    namespaceExclusions: vi.fn().mockResolvedValue({
      mode: 'all',
      helmExcluded: ['platform'],
      items: [
        { name: 'kube-system', status: 'system', exists: true },
        { name: 'netcheck', status: 'netcheck', exists: true },
        { name: 'orders', status: 'available', exists: true },
        { name: 'payments', status: 'excluded_web', exists: true, reason: 'PCI scope', excludedBy: 'admin', excludedAt: common.createdAt },
        { name: 'platform', status: 'excluded_helm', exists: true },
      ],
    }),
    excludeNamespace: vi.fn().mockResolvedValue(undefined),
    includeNamespace: vi.fn().mockResolvedValue(undefined),
    policy: vi.fn().mockResolvedValue(policyView()),
    savePolicy: vi.fn().mockImplementation((p: DestinationPolicy) => Promise.resolve({ ...policyView(), policy: p, updatedBy: 'admin' })),
    checkDestination: vi.fn().mockResolvedValue({ allowed: false, reason: '169.254.169.254 is in denied range 169.254.0.0/16', isIp: true }),
    retention: vi.fn().mockResolvedValue({ outputDays: 15, metadataDays: 45, updatedAt: common.createdAt, updatedBy: 'helm (initial values)' }),
    saveRetention: vi.fn().mockImplementation((r: { outputDays: number; metadataDays: number }) => Promise.resolve({ ...r, updatedAt: common.createdAt, updatedBy: 'admin' })),
    trustedCAs: vi.fn().mockResolvedValue(trustedView()),
    checkTypes: vi.fn().mockResolvedValue(checkTypesView()),
    roles: vi.fn().mockResolvedValue({ roles: [...builtinRoles, oncall], permissions: ALL_PERMS }),
    groups: vi.fn().mockResolvedValue({ items: [platformGroup] }),
    createGroup: vi.fn().mockResolvedValue(platformGroup),
    updateGroup: vi.fn().mockResolvedValue(platformGroup),
    deleteGroup: vi.fn().mockResolvedValue(undefined),
    createRole: vi.fn().mockResolvedValue(oncall),
    updateRole: vi.fn().mockResolvedValue(oncall),
    deleteRole: vi.fn().mockResolvedValue(undefined),
    userPermissions: vi.fn().mockResolvedValue({
      admin: false,
      grants: [{ role: 'oncall', roleName: 'On-call', allNamespaces: false, allowNetcheckNamespace: false, namespaces: ['payments'], source: 'account' }],
      namespaces: [{ name: 'payments', canRun: true, checks: ['tcp', 'ping'], firewallMode: false }],
      permissions: ['check.tcp', 'check.ping', 'tokens.create'],
    }),
    saveCheckTypes: vi.fn().mockImplementation((disabled: string[]) =>
      Promise.resolve({ ...checkTypesView(), types: checkTypesView().types.map((x) => ({ ...x, enabled: !disabled.includes(x.type) })), updatedBy: 'admin' }),
    ),
    proxies: vi.fn().mockResolvedValue(proxiesView()),
    createProxy: vi.fn().mockResolvedValue(corpProxy),
    updateProxy: vi.fn().mockResolvedValue(corpProxy),
    deleteProxy: vi.fn().mockResolvedValue(undefined),
    saveTrustedCAs: vi.fn().mockImplementation((certificates: string[]) => Promise.resolve({ ...trustedView(), certificates: certificates.map((pem, i) => ({ ...corpCA, pem, fingerprintSha256: String(i).repeat(64) })), updatedBy: 'admin' })),
    accessRules: vi.fn().mockResolvedValue({ items: [], ssoEnabled: true }),
    createAccessRule: vi.fn().mockResolvedValue(undefined),
    updateAccessRule: vi.fn().mockResolvedValue(undefined),
    deleteAccessRule: vi.fn().mockResolvedValue(undefined),
    tokens: vi.fn().mockResolvedValue({ items: [] }),
    revokeToken: vi.fn().mockResolvedValue(undefined),
    ...over,
  };
}

const corpCA: TrustedCertificate = {
  pem: 'CORP PEM',
  subject: 'CN=Corp Root,O=Corp',
  issuer: 'CN=Corp Root,O=Corp',
  notBefore: '2020-01-01T00:00:00Z',
  notAfter: '2040-01-01T00:00:00Z',
  fingerprintSha256: 'ab12'.repeat(16),
  expired: false,
};
const oldCA: TrustedCertificate = { ...corpCA, pem: 'OLD', subject: 'CN=Old Proxy CA', issuer: 'CN=Corp Root,O=Corp', notAfter: '2025-01-01T00:00:00Z', fingerprintSha256: 'cd34'.repeat(16), expired: true };

const corpProxy: Proxy = {
  id: 'p1',
  name: 'corp',
  host: 'proxy.corp.example',
  port: 3128,
  personal: false,
  shared: true,
  certificateCount: 1,
  certificates: [{ ...{ pem: 'CORP PEM', subject: 'CN=Corp Inspection CA', issuer: 'CN=Corp Inspection CA', notBefore: common.createdAt, notAfter: '2040-01-01T00:00:00Z', fingerprintSha256: 'ef56'.repeat(16), expired: false } }],
  updatedAt: common.createdAt,
  updatedBy: 'admin',
};

function proxiesView(editable = true, proxies: Proxy[] = [corpProxy]): ProxiesView {
  return { proxies, max: 20, managedBy: editable ? 'ui' : 'helm', editable };
}

function proxyCalls(over: Partial<ProxyCalls> = {}): ProxyCalls {
  return {
    list: vi.fn().mockResolvedValue(proxiesView()),
    create: vi.fn().mockResolvedValue(corpProxy),
    update: vi.fn().mockResolvedValue(corpProxy),
    remove: vi.fn().mockResolvedValue(undefined),
    ...over,
  };
}

function trustedView(editable = true): TrustedCAsView {
  return { certificates: [corpCA, oldCA], managedBy: editable ? 'ui' : 'helm', editable, updatedAt: common.createdAt, updatedBy: 'helm (initial values)' };
}

function policyView(editable = true): PolicyView {
  return {
    policy: { allowCidrs: ['10.0.0.0/8'], denyCidrs: [], allowHostnameSuffixes: ['.svc.cluster.local'], allowPorts: [{ from: 8080, to: 8080 }] },
    platformDenies: ['169.254.0.0/16', '10.96.0.1/32'],
    protectPlatformDestinations: true,
    managedBy: editable ? 'ui' : 'helm',
    editable,
    updatedAt: common.createdAt,
    updatedBy: 'helm (initial values)',
  };
}

describe('UsersPage', () => {
  it('lists users with role, namespaces and status', async () => {
    const { container } = renderI18n(<UsersPage admin={mockAdmin()} currentUserId={users[0]!.id} onCreate={vi.fn()} onEdit={vi.fn()} notify={vi.fn()} />);
    expect(await screen.findByText('bob')).toBeInTheDocument();
    const rows = createWrapper(container).findTable()!.findRows().map((r) => r.getElement().textContent ?? '');
    expect(rows[0]).toContain('admin (you)');
    expect(rows[0]).toContain('All');
    expect(rows[1]).toContain('payments');
    expect(rows[1]).toContain('NetCheck');
    expect(rows[1]).toContain('Locked');
    expect(rows[2]).toContain('Disabled');
  });

  it('unlocks, resets and deletes the selected user', async () => {
    const admin = mockAdmin();
    const notify = vi.fn();
    const { container } = renderI18n(<UsersPage admin={admin} currentUserId={users[0]!.id} onCreate={vi.fn()} onEdit={vi.fn()} notify={notify} />);
    await screen.findByText('bob');
    const w = createWrapper(container);
    w.findTable()!.findRowSelectionArea(2)!.click();
    const actions = w.findButtonDropdown()!;

    actions.openDropdown();
    actions.findItemById('unlock')!.click();
    await waitFor(() => expect(admin.unlock).toHaveBeenCalledWith(users[1]!.id));

    w.findTable()!.findRowSelectionArea(2)!.click();
    actions.openDropdown();
    actions.findItemById('reset')!.click();
    expect(await screen.findByText('Reset password of bob')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Reset' }));
    await waitFor(() => expect(admin.resetPassword).toHaveBeenCalledWith(users[1]!.id, expect.stringMatching(/^.{20}$/)));

    w.findTable()!.findRowSelectionArea(2)!.click();
    actions.openDropdown();
    actions.findItemById('delete')!.click();
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(admin.deleteUser).toHaveBeenCalledWith(users[1]!.id));
    expect(notify).toHaveBeenCalledWith('success', 'User bob deleted.');
  });

  it('disables a user after confirming and enables a disabled one', async () => {
    const admin = mockAdmin();
    const notify = vi.fn();
    const { container } = renderI18n(<UsersPage admin={admin} currentUserId={users[0]!.id} onCreate={vi.fn()} onEdit={vi.fn()} notify={notify} />);
    await screen.findByText('bob');
    const w = createWrapper(container);
    const actions = w.findButtonDropdown()!;
    w.findTable()!.findRowSelectionArea(2)!.click();
    actions.openDropdown();
    actions.findItemById('disable')!.click();
    expect(await screen.findByText(/its API tokens stop working/)).toBeInTheDocument();
    await userEvent.click(within(screen.getByRole('dialog', { name: /Disable user bob/ })).getByRole('button', { name: 'Disable' }));
    await waitFor(() => expect(admin.updateUser).toHaveBeenCalledWith(users[1]!.id, expect.objectContaining({ disabled: true, role: 'user', namespaces: ['payments'] })));
    expect(notify).toHaveBeenCalledWith('success', 'User bob disabled.');

    w.findTable()!.findRowSelectionArea(3)!.click();
    actions.openDropdown();
    expect(actions.findItemById('disable')).toBeNull();
    actions.findItemById('enable')!.click();
    await waitFor(() => expect(admin.updateUser).toHaveBeenCalledWith(users[2]!.id, expect.objectContaining({ disabled: false })));
  });

  it('explains that a disabled SSO account does not come back', async () => {
    const sso = { ...users[1]!, source: 'oidc' as const };
    const { container } = renderI18n(
      <UsersPage admin={mockAdmin({ listUsers: vi.fn().mockResolvedValue({ items: [users[0]!, sso] }) })} currentUserId={users[0]!.id} onCreate={vi.fn()} onEdit={vi.fn()} notify={vi.fn()} />,
    );
    await screen.findByText('bob');
    const w = createWrapper(container);
    w.findTable()!.findRowSelectionArea(2)!.click();
    w.findButtonDropdown()!.openDropdown();
    w.findButtonDropdown()!.findItemById('disable')!.click();
    expect(await screen.findByText(/does not come back at the next sign-in/)).toBeInTheDocument();
  });

  it('cannot delete yourself', async () => {
    const { container } = renderI18n(<UsersPage admin={mockAdmin()} currentUserId={users[0]!.id} onCreate={vi.fn()} onEdit={vi.fn()} notify={vi.fn()} />);
    await screen.findByText('bob');
    const w = createWrapper(container);
    w.findTable()!.findRowSelectionArea(1)!.click();
    const actions = w.findButtonDropdown()!;
    actions.openDropdown();
    actions.findItemById('delete')!.click();
    expect(screen.queryByText('Delete user admin')).toBeNull();
  });
});

describe('UserFormPage', () => {
  it('creates a user with all namespaces (dynamic)', async () => {
    const admin = mockAdmin();
    const onDone = vi.fn();
    const { container } = renderI18n(<UserFormPage admin={admin} currentUserId="ux" onDone={onDone} onCancel={vi.fn()} />);
    await userEvent.type(await screen.findByLabelText('Username'), 'Dave');
    await userEvent.type(screen.getByLabelText('Temporary password'), 'temporary-pass-1');
    createWrapper(container).findRadioGroup('[aria-label="Namespaces"]')!.findInputByValue('all')!.click();
    expect(screen.getByText(/Existing and future namespaces/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Create user' }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(admin.createUser).toHaveBeenCalledWith({
      username: 'dave',
      displayName: '',
      role: 'user',
      password: 'temporary-pass-1',
      allNamespaces: true,
      namespaces: [],
      disabled: false,
      allowNetcheckNamespace: false,
    });
  });

  it('hides the NetCheck namespace unless the checkbox is ticked', async () => {
    const admin = mockAdmin();
    const { container } = renderI18n(<UserFormPage admin={admin} currentUserId="ux" onDone={vi.fn()} onCancel={vi.fn()} />);
    await userEvent.type(await screen.findByLabelText('Username'), 'erin');
    await userEvent.click(screen.getByRole('button', { name: 'Generate' }));
    await userEvent.click(screen.getByRole('button', { name: 'Create user' }));
    expect(await screen.findByText('Choose at least one namespace or "All namespaces".')).toBeInTheDocument();
    const w = createWrapper(container);
    const ms = w.findMultiselect()!;
    ms.openDropdown();
    expect(ms.findDropdown().findOptions().map((o) => o.getElement().textContent)).not.toContain('netcheck');
    ms.selectOptionByValue('orders');
    w.findCheckbox()!.findNativeInput().click();
    expect(screen.getByText('Allow tests in the NetCheck namespace (netcheck)')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Create user' }));
    await waitFor(() => expect(admin.createUser).toHaveBeenCalled());
    const arg = vi.mocked(admin.createUser).mock.calls[0]![0];
    expect(arg.namespaces).toEqual(['orders']);
    expect(arg.allowNetcheckNamespace).toBe(true);
    expect(arg.password).toHaveLength(20);
  });

  it('edits without exposing username/password and protects yourself', async () => {
    renderI18n(<UserFormPage admin={mockAdmin()} userId={users[0]!.id} currentUserId={users[0]!.id} onDone={vi.fn()} onCancel={vi.fn()} />);
    expect(await screen.findByText('Edit user admin')).toBeInTheDocument();
    expect(screen.getByLabelText('Username')).toBeDisabled();
    expect(screen.queryByLabelText('Temporary password')).toBeNull();
    expect(screen.getByText('You cannot disable your own account.')).toBeInTheDocument();
    expect(screen.getByText('Administrators can use every available namespace.')).toBeInTheDocument();
  });

  it('shows server validation errors next to the field', async () => {
    const admin = mockAdmin({
      createUser: vi
        .fn()
        .mockRejectedValue(
          new ApiError(400, 'validation_failed', 'a user with that name already exists', [{ field: 'username', code: 'username_taken', message: 'x' }]),
        ),
    });
    const { container } = renderI18n(<UserFormPage admin={admin} currentUserId="ux" onDone={vi.fn()} onCancel={vi.fn()} />, 'es');
    await userEvent.type(await screen.findByRole('textbox', { name: 'Usuario' }), 'bob');
    await userEvent.type(screen.getByLabelText('Contraseña temporal'), 'temporary-pass-1');
    createWrapper(container).findRadioGroup('[aria-label="Namespaces"]')!.findInputByValue('all')!.click();
    await userEvent.click(screen.getByRole('button', { name: 'Crear usuario' }));
    expect(await screen.findByText('Ya existe un usuario con ese nombre.')).toBeInTheDocument();
  });
});

describe('SessionsPage', () => {
  it('shows connected users and signs out another session', async () => {
    const admin = mockAdmin();
    const notify = vi.fn();
    const { container } = renderI18n(<SessionsPage admin={admin} notify={notify} />);
    expect(await screen.findByText('bob')).toBeInTheDocument();
    expect(screen.getByText('Connected users').nextSibling).toHaveTextContent('2');
    expect(screen.getByText('This session')).toBeInTheDocument();
    const w = createWrapper(container);
    const table = w.findTable()!;
    const bobRow = table.findRows().findIndex((r) => r.getElement().textContent?.includes('bob'));
    table.findRowSelectionArea(bobRow + 1)!.click();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out session' }));
    await waitFor(() => expect(admin.revokeSession).toHaveBeenCalledWith('s2'));
    expect(notify).toHaveBeenCalledWith('success', 'Session of bob signed out.');
  });

  it('names browsers compactly', () => {
    expect(browserName('Mozilla/5.0 (Windows NT 10.0) AppleWebKit Chrome/140.0 Safari/537.36 Edg/140.0')).toBe('Edge 140 · Windows');
    expect(browserName('')).toBe('—');
  });
});

describe('SystemPage', () => {
  it('shows the running version and the version history', async () => {
    const onEditPolicy = vi.fn();
    renderI18n(<SystemPage admin={mockAdmin()} onEditPolicy={onEditPolicy} />);
    expect((await screen.findAllByText('0.3.0')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('0.2.0')).toHaveLength(2);
    expect(screen.getByText('80, 8080-8443')).toBeInTheDocument();
    expect(screen.getByText(/cloud metadata, API server, loopback and link-local are always denied/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Edit policy' }));
    expect(onEditPolicy).toHaveBeenCalled();
    expect(screen.getByText('15 days')).toBeInTheDocument();
    expect(screen.getByText('45 days')).toBeInTheDocument();
    expect(screen.getByText(/image digests listed in its release notes/)).toBeInTheDocument();
    expect(shortDigest('repo/netcheck@sha256:0123456789abcdef0123')).toBe('sha256:0123456789ab');
  });
});

describe('PolicyPage', () => {
  it('loads the policy, applies a preset and saves it', async () => {
    const admin = mockAdmin();
    const notify = vi.fn();
    renderI18n(<PolicyPage admin={admin} notify={notify} />);
    expect(await screen.findByDisplayValue('10.0.0.0/8')).toBeInTheDocument();
    expect(screen.getByText(/by Helm \(initial values\)/)).toBeInTheDocument();
    expect(screen.getByText('169.254.0.0/16')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'Allow everything' }));
    expect(screen.getByText('You have unsaved changes.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(admin.savePolicy).toHaveBeenCalledWith(ALLOW_ALL));
    expect(notify).toHaveBeenCalledWith('success', 'Destination policy saved. It applies to new tests.');
  });

  it('adds an entry and shows server field errors', async () => {
    const admin = mockAdmin({
      savePolicy: vi.fn().mockRejectedValue(
        new ApiError(400, 'validation_failed', 'the policy is not valid', [{ field: 'allowHostnameSuffixes', code: 'invalid_suffix', message: 'x' }]),
      ),
    });
    renderI18n(<PolicyPage admin={admin} notify={vi.fn()} />);
    await screen.findByDisplayValue('.svc.cluster.local');
    await userEvent.click(screen.getAllByRole('button', { name: 'Add' })[0]!);
    await userEvent.type(screen.getByLabelText('Suffix 2'), 'bad host');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Invalid hostname suffix.')).toBeInTheDocument();
    expect(vi.mocked(admin.savePolicy).mock.calls[0]![0].allowHostnameSuffixes).toEqual(['.svc.cluster.local', 'bad host']);
  });

  it('checks a destination without sending traffic', async () => {
    const admin = mockAdmin();
    renderI18n(<PolicyPage admin={admin} notify={vi.fn()} />);
    await screen.findByDisplayValue('10.0.0.0/8');
    await userEvent.type(screen.getByLabelText('Hostname or IP'), '169.254.169.254');
    await userEvent.type(screen.getByLabelText('Port (optional)'), '80');
    await userEvent.click(screen.getByRole('button', { name: 'Check' }));
    expect(await screen.findByText(/Denied: 169.254.169.254 is in denied range/)).toBeInTheDocument();
    expect(admin.checkDestination).toHaveBeenCalledWith('169.254.169.254', 80);
  });

  it('is read-only when the policy is managed in Helm', async () => {
    renderI18n(<PolicyPage admin={mockAdmin({ policy: vi.fn().mockResolvedValue(policyView(false)) })} notify={vi.fn()} />);
    expect(await screen.findByText('Managed in Helm')).toBeInTheDocument();
    expect(screen.getByDisplayValue('10.0.0.0/8')).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Allow everything' })).toBeNull();
  });
});

describe('RetentionPage', () => {
  it('loads the retention, warns when shortening and saves it', async () => {
    const admin = mockAdmin();
    const notify = vi.fn();
    renderI18n(<RetentionPage admin={admin} notify={notify} />);
    const output = await screen.findByLabelText('Technical output (days)');
    expect(output).toHaveValue(15);
    expect(screen.getByText(/by Helm \(initial values\)/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    await userEvent.clear(output);
    await userEvent.type(output, '7');
    expect(screen.getByText(/Deleted data cannot be recovered/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(admin.saveRetention).toHaveBeenCalledWith({ outputDays: 7, metadataDays: 45 }));
    expect(notify).toHaveBeenCalledWith('success', 'Data retention saved. It applies within an hour.');
  });

  it('rejects a history period shorter than the output period', async () => {
    const admin = mockAdmin();
    renderI18n(<RetentionPage admin={admin} notify={vi.fn()} />);
    const metadata = await screen.findByLabelText('Test history and audit log (days)');
    await userEvent.clear(metadata);
    await userEvent.type(metadata, '10');
    expect(screen.getByText('Must be at least the technical output period.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(admin.saveRetention).not.toHaveBeenCalled();
  });
});

describe('TrustedCAsPage', () => {
  it('lists the authorities with their expiry and fingerprint', async () => {
    const { container } = renderI18n(<TrustedCAsPage admin={mockAdmin()} notify={vi.fn()} />);
    expect(await screen.findByText('CN=Old Proxy CA')).toBeInTheDocument();
    const rows = createWrapper(container).findTable()!.findRows().map((r) => r.getElement().textContent ?? '');
    expect(rows[0]).toContain('Itself (root)');
    expect(rows[0]).toContain(shortFingerprint('ab12'.repeat(16)));
    expect(rows[1]).toMatch(/Expired/);
    expect(shortFingerprint('ab12'.repeat(16))).toBe('AB12 AB12 AB12 AB12 AB12 AB12 AB12 AB12…');
  });

  it('adds pasted certificates to the existing ones', async () => {
    const admin = mockAdmin();
    const notify = vi.fn();
    renderI18n(<TrustedCAsPage admin={admin} notify={notify} />);
    await screen.findByText('CN=Old Proxy CA');
    await userEvent.click(screen.getByRole('button', { name: 'Add certificates' }));
    await userEvent.type(screen.getByLabelText('Certificates (PEM)'), 'NEW PEM');
    const dialog = screen.getByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add certificates' }));
    await waitFor(() => expect(admin.saveTrustedCAs).toHaveBeenCalledWith([corpCA.pem, 'OLD', 'NEW PEM']));
    expect(notify).toHaveBeenCalledWith('success', 'Certificate authorities saved. New tests use them at once.');
  });

  it('explains why a certificate is refused', async () => {
    const admin = mockAdmin({
      saveTrustedCAs: vi.fn().mockRejectedValue(new ApiError(400, 'validation_failed', 'x', [{ field: 'certificates[2]', code: 'not_a_ca', message: 'x' }])),
    });
    renderI18n(<TrustedCAsPage admin={admin} notify={vi.fn()} />);
    await screen.findByText('CN=Old Proxy CA');
    await userEvent.click(screen.getByRole('button', { name: 'Add certificates' }));
    await userEvent.type(screen.getByLabelText('Certificates (PEM)'), 'SERVER PEM');
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Add certificates' }));
    expect(await screen.findByText(/is not a certificate authority/)).toBeInTheDocument();
  });

  it('removes the selected authority', async () => {
    const admin = mockAdmin();
    const { container } = renderI18n(<TrustedCAsPage admin={admin} notify={vi.fn()} />);
    await screen.findByText('CN=Old Proxy CA');
    createWrapper(container).findTable()!.findRowSelectionArea(2)!.click();
    await userEvent.click(screen.getByRole('button', { name: 'Remove' }));
    expect(screen.getByText(/will stop trusting CN=Old Proxy CA/)).toBeInTheDocument();
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(admin.saveTrustedCAs).toHaveBeenCalledWith([corpCA.pem]));
  });

  it('is read-only when managed in Helm', async () => {
    renderI18n(<TrustedCAsPage admin={mockAdmin({ trustedCAs: vi.fn().mockResolvedValue(trustedView(false)) })} notify={vi.fn()} />);
    expect(await screen.findByText('Managed in the Helm values')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add certificates' })).not.toBeInTheDocument();
  });
});

describe('ProxiesPage', () => {
  it('lists the shared proxies with who may use them and their authorities', async () => {
    const admins = { ...corpProxy, id: 'p2', name: 'ops', shared: false, certificateCount: 0, certificates: [] };
    const { container } = renderI18n(
      <ProxiesPage scope="admin" calls={proxyCalls({ list: vi.fn().mockResolvedValue(proxiesView(true, [corpProxy, admins])) })} notify={vi.fn()} />,
    );
    expect(await screen.findByText('ops')).toBeInTheDocument();
    const rows = createWrapper(container).findTable()!.findRows().map((r) => r.getElement().textContent ?? '');
    expect(rows[0]).toContain('Every user');
    expect(rows[0]).toContain('CN=Corp Inspection CA');
    expect(rows[1]).toContain('Administrators only');
  });

  it('adds a shared proxy with its authority', async () => {
    const calls = proxyCalls();
    const notify = vi.fn();
    renderI18n(<ProxiesPage scope="admin" calls={calls} notify={notify} />);
    await screen.findByText('proxy.corp.example:3128');
    await userEvent.click(screen.getByRole('button', { name: 'Add proxy' }));
    const dialog = within(screen.getByRole('dialog'));
    await userEvent.type(dialog.getByLabelText('Name'), 'dmz');
    await userEvent.type(dialog.getByLabelText('Host name or IP'), '10.0.0.9');
    await userEvent.clear(dialog.getByLabelText('Port'));
    await userEvent.type(dialog.getByLabelText('Port'), '8080');
    await userEvent.click(dialog.getByRole('checkbox', { name: 'Share with every user' }));
    await userEvent.type(dialog.getByLabelText('Certificate authorities of this proxy (PEM, optional)'), 'PROXY PEM');
    await userEvent.click(dialog.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(calls.create).toHaveBeenCalledWith({ name: 'dmz', host: '10.0.0.9', port: 8080, shared: false, certificates: ['PROXY PEM'] }));
    expect(notify).toHaveBeenCalledWith('success', 'Proxies saved. Users can choose them at once.');
  });

  it('edits the selected proxy and shows field errors from the server', async () => {
    const calls = proxyCalls({
      update: vi.fn().mockRejectedValue(new ApiError(400, 'validation_failed', 'x', [{ field: 'name', code: 'invalid_proxy_name', message: 'x' }])),
    });
    const { container } = renderI18n(<ProxiesPage scope="admin" calls={calls} notify={vi.fn()} />);
    await screen.findByText('proxy.corp.example:3128');
    createWrapper(container).findTable()!.findRowSelectionArea(1)!.click();
    await userEvent.click(screen.getByRole('button', { name: 'Edit' }));
    const dialog = within(screen.getByRole('dialog'));
    expect(dialog.getByLabelText('Certificate authorities of this proxy (PEM, optional)')).toHaveValue('CORP PEM');
    await userEvent.clear(dialog.getByLabelText('Name'));
    await userEvent.type(dialog.getByLabelText('Name'), 'Corp Proxy');
    await userEvent.click(dialog.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Use 1-32 lowercase letters, digits or dashes.')).toBeInTheDocument();
    expect(calls.update).toHaveBeenCalledWith('p1', { name: 'Corp Proxy', host: 'proxy.corp.example', port: 3128, shared: true, certificates: ['CORP PEM'] });
  });

  it('deletes the selected proxy', async () => {
    const calls = proxyCalls();
    const { container } = renderI18n(<ProxiesPage scope="admin" calls={calls} notify={vi.fn()} />);
    await screen.findByText('proxy.corp.example:3128');
    createWrapper(container).findTable()!.findRowSelectionArea(1)!.click();
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(calls.remove).toHaveBeenCalledWith('p1'));
  });

  it('is read-only when managed in Helm', async () => {
    renderI18n(<ProxiesPage scope="admin" calls={proxyCalls({ list: vi.fn().mockResolvedValue(proxiesView(false)) })} notify={vi.fn()} />);
    expect(await screen.findByText('Managed in the Helm values')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add proxy' })).not.toBeInTheDocument();
  });

  it('manages personal proxies without the sharing option', async () => {
    const mine = { ...corpProxy, id: 'p9', name: 'home', personal: true, shared: false, certificateCount: 0, certificates: [] };
    const calls = proxyCalls({ list: vi.fn().mockResolvedValue({ ...proxiesView(true, [mine]), max: 10 }) });
    renderI18n(<ProxiesPage scope="personal" calls={calls} notify={vi.fn()} />);
    expect(await screen.findByRole('heading', { name: 'My proxies', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('(1/10)')).toBeInTheDocument();
    expect(screen.queryByText('Available to')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Add proxy' }));
    const dialog = within(screen.getByRole('dialog'));
    expect(dialog.queryByRole('checkbox', { name: 'Share with every user' })).not.toBeInTheDocument();
    await userEvent.type(dialog.getByLabelText('Name'), 'lab');
    await userEvent.type(dialog.getByLabelText('Host name or IP'), '10.0.0.7');
    await userEvent.click(dialog.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(calls.create).toHaveBeenCalledWith({ name: 'lab', host: '10.0.0.7', port: 3128, shared: false, certificates: [] }));
  });
});

describe('NamespacesPage', () => {
  it('shows each namespace with the source of its exclusion', async () => {
    const { container } = renderI18n(<NamespacesPage admin={mockAdmin()} notify={vi.fn()} />);
    expect(await screen.findByText('orders')).toBeInTheDocument();
    const rows = createWrapper(container).findTable()!.findRows().map((r) => r.getElement().textContent ?? '');
    expect(rows.find((r) => r.includes('kube-system'))).toContain('System (always excluded)');
    expect(rows.find((r) => r.includes('platform'))).toContain('Excluded in Helm');
    expect(rows.find((r) => r.includes('payments'))).toContain('PCI scope');
    expect(rows.find((r) => r.includes('netcheck'))).toContain('per-user checkbox');
  });

  it('excludes the selected namespace with a reason', async () => {
    const admin = mockAdmin();
    const notify = vi.fn();
    const { container } = renderI18n(<NamespacesPage admin={admin} notify={notify} />);
    await screen.findByText('orders');
    const table = createWrapper(container).findTable()!;
    table.findRowSelectionArea(table.findRows().findIndex((r) => r.getElement().textContent?.includes('orders')) + 1)!.click();
    await userEvent.click(screen.getAllByRole('button', { name: 'Exclude' })[0]!);
    expect(screen.getByLabelText('Namespace')).toHaveValue('orders');
    await userEvent.type(screen.getByLabelText('Reason (optional)'), 'freeze');
    await userEvent.click(screen.getAllByRole('button', { name: 'Exclude' }).at(-1)!);
    await waitFor(() => expect(admin.excludeNamespace).toHaveBeenCalledWith('orders', 'freeze'));
    expect(notify).toHaveBeenCalledWith('success', 'Namespace orders excluded.');
  });

  it('includes again only web exclusions', async () => {
    const admin = mockAdmin();
    const { container } = renderI18n(<NamespacesPage admin={admin} notify={vi.fn()} />);
    await screen.findByText('orders');
    const table = createWrapper(container).findTable()!;
    const row = (n: string) => table.findRows().findIndex((r) => r.getElement().textContent?.includes(n)) + 1;
    table.findRowSelectionArea(row('platform'))!.click();
    expect(screen.getAllByRole('button', { name: 'Include again' })[0]).toBeDisabled();
    table.findRowSelectionArea(row('payments'))!.click();
    await userEvent.click(screen.getAllByRole('button', { name: 'Include again' })[0]!);
    await userEvent.click(screen.getAllByRole('button', { name: 'Include again' }).at(-1)!);
    await waitFor(() => expect(admin.includeNamespace).toHaveBeenCalledWith('payments'));
  });

  it('validates the name when excluding by name', async () => {
    const admin = mockAdmin();
    renderI18n(<NamespacesPage admin={admin} notify={vi.fn()} />);
    await screen.findByText('orders');
    await userEvent.click(screen.getByRole('button', { name: 'Exclude by name' }));
    await userEvent.type(screen.getByLabelText('Namespace'), 'Bad_Name');
    await userEvent.click(screen.getAllByRole('button', { name: 'Exclude' }).at(-1)!);
    expect(await screen.findByText('Lowercase letters, digits and "-", at most 63 characters.')).toBeInTheDocument();
    expect(admin.excludeNamespace).not.toHaveBeenCalled();
  });
});

describe('AccessRulesPage', () => {
  it('creates a rule for a group with selected namespaces', async () => {
    const admin = mockAdmin({ accessRules: vi.fn().mockResolvedValue({ items: [], ssoEnabled: true }) });
    const notify = vi.fn();
    renderI18n(<AccessRulesPage admin={admin} notify={notify} />);
    expect(await screen.findByText('No rules yet')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Create rule' }));
    await userEvent.type(screen.getByRole('textbox', { name: 'Group' }), 'acme:payments');
    const w = createWrapper(document.body);
    const ms = w.findMultiselect()!;
    ms.openDropdown();
    ms.selectOptionByValue('payments');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() =>
      expect(admin.createAccessRule).toHaveBeenCalledWith({
        subjectType: 'group',
        subject: 'acme:payments',
        role: 'user',
        allNamespaces: false,
        allowNetcheckNamespace: false,
        namespaces: ['payments'],
      }),
    );
    expect(notify).toHaveBeenCalledWith('success', expect.stringContaining('Access rule saved'));
  });

  it('edits a rule sending only the editable fields', async () => {
    const rule = { id: 'r1', subjectType: 'group' as const, subject: 'CCT_Plataformas', role: 'user' as const, allNamespaces: true, allowNetcheckNamespace: false, namespaces: [], updatedAt: common.createdAt, updatedBy: 'admin' };
    const admin = mockAdmin({ accessRules: vi.fn().mockResolvedValue({ items: [rule], ssoEnabled: true }) });
    const { container } = renderI18n(<AccessRulesPage admin={admin} notify={vi.fn()} />);
    expect(await screen.findByText('Group: CCT_Plataformas')).toBeInTheDocument();
    createWrapper(container).findTable()!.findRowSelectionArea(1)!.click();
    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    await userEvent.click(screen.getByRole('radio', { name: /Administrator/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() =>
      expect(admin.updateAccessRule).toHaveBeenCalledWith('r1', {
        subjectType: 'group',
        subject: 'CCT_Plataformas',
        role: 'admin',
        allNamespaces: true,
        allowNetcheckNamespace: false,
        namespaces: [],
      }),
    );
  });

  it('edits a rule for all namespaces into selected namespaces', async () => {
    // Earlier versions of the API sent null instead of [] for a rule with all namespaces.
    const rule = { id: 'r2', subjectType: 'group' as const, subject: 'CCT_Plataformas', role: 'user' as const, allNamespaces: true, allowNetcheckNamespace: false, namespaces: null as unknown as string[], updatedAt: common.createdAt, updatedBy: 'admin' };
    const admin = mockAdmin({ accessRules: vi.fn().mockResolvedValue({ items: [rule], ssoEnabled: true }) });
    const { container } = renderI18n(<AccessRulesPage admin={admin} notify={vi.fn()} />);
    expect(await screen.findByText('Group: CCT_Plataformas')).toBeInTheDocument();
    createWrapper(container).findTable()!.findRowSelectionArea(1)!.click();
    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    await userEvent.click(screen.getByRole('radio', { name: 'Selected namespaces' }));
    const ms = createWrapper(document.body).findMultiselect()!;
    ms.openDropdown();
    ms.selectOptionByValue('payments');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() =>
      expect(admin.updateAccessRule).toHaveBeenCalledWith('r2', expect.objectContaining({ allNamespaces: false, namespaces: ['payments'] })),
    );
  });

  it('lists rules and warns when SSO is not enabled', async () => {
    const rule = { id: 'r1', subjectType: 'authenticated' as const, subject: '', role: 'user' as const, allNamespaces: true, allowNetcheckNamespace: false, namespaces: [], updatedAt: common.createdAt, updatedBy: 'admin' };
    renderI18n(<AccessRulesPage admin={mockAdmin({ accessRules: vi.fn().mockResolvedValue({ items: [rule], ssoEnabled: false }) })} notify={vi.fn()} />);
    expect(await screen.findByText('Single sign-on is not enabled')).toBeInTheDocument();
    expect(screen.getByText('Any authenticated user')).toBeInTheDocument();
    expect(screen.getByText('All namespaces')).toBeInTheDocument();
  });
});

describe('UserFormPage for an SSO account', () => {
  it('explains that role and namespaces come from the access rules', async () => {
    const sso: UserView = { ...users[1]!, id: 'u000000000000000000000009', source: 'oidc', groups: ['acme:payments'] };
    const admin = mockAdmin({ getUser: vi.fn().mockResolvedValue(sso) });
    renderI18n(<UserFormPage admin={admin} userId={sso.id} currentUserId="x" onDone={vi.fn()} onCancel={vi.fn()} />);
    expect(await screen.findByText('Single sign-on account')).toBeInTheDocument();
    expect(screen.getByText(/Groups of the last sign-in: acme:payments/)).toBeInTheDocument();
    expect(screen.queryByRole('radio', { name: /Administrator/ })).not.toBeInTheDocument();
  });
});

describe('CheckTypesPage', () => {
  it('switches a check type off for everybody', async () => {
    const admin = mockAdmin();
    const notify = vi.fn();
    renderI18n(<CheckTypesPage admin={admin} notify={notify} />);
    const traceroute = await screen.findByRole('checkbox', { name: 'Traceroute (ICMP)' });
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    await userEvent.click(traceroute);
    expect(screen.getByText('You have unsaved changes.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(admin.saveCheckTypes).toHaveBeenCalledWith(['traceroute']));
    expect(notify).toHaveBeenCalledWith('success', 'Check types saved. They apply to new tests at once.');
  });

  it('keeps at least one check enabled', async () => {
    renderI18n(<CheckTypesPage admin={mockAdmin()} notify={vi.fn()} />);
    await screen.findByRole('checkbox', { name: 'DNS resolution' });
    for (const name of ['DNS resolution', 'TCP connection', 'UDP', 'HTTP', 'HTTPS', 'Ping (ICMP)', 'Traceroute (ICMP)']) {
      await userEvent.click(screen.getByRole('checkbox', { name }));
    }
    expect(screen.getByText('At least one check type must stay enabled.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
  });

  it('is read-only when managed in Helm', async () => {
    renderI18n(<CheckTypesPage admin={mockAdmin({ checkTypes: vi.fn().mockResolvedValue(checkTypesView(false)) })} notify={vi.fn()} />);
    expect(await screen.findByText(/checkTypesManagedBy is helm/)).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'UDP' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
  });
});

describe('RolesPage', () => {
  it('lists the built-in and custom roles with what they allow', async () => {
    renderI18n(<RolesPage admin={mockAdmin()} notify={vi.fn()} />);
    expect(await screen.findByText('On-call')).toBeInTheDocument();
    expect(screen.getByText('Everything, in every namespace, plus administration')).toBeInTheDocument();
    expect(screen.getByText('1 users · 0 access rules · 0 groups')).toBeInTheDocument();
    expect(screen.getByText('TCP connection, Ping (ICMP), Create API tokens')).toBeInTheDocument();
  });

  it('creates a role with the ticked permissions', async () => {
    const admin = mockAdmin();
    const notify = vi.fn();
    renderI18n(<RolesPage admin={admin} notify={notify} />);
    await screen.findByText('On-call');
    await userEvent.click(screen.getByRole('button', { name: 'Create role' }));
    await userEvent.type(screen.getByLabelText('Name'), 'Auditors');
    const dialog = screen.getByRole('dialog');
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /^TCP connection/ }));
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /^Every test of its namespaces/ }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(admin.createRole).toHaveBeenCalledWith({ name: 'Auditors', description: '', permissions: ['check.tcp', 'runs.all'] }));
    expect(notify).toHaveBeenCalledWith('success', 'Role Auditors saved. It applies at once.');
  });

  it('explains why a role in use cannot be deleted', async () => {
    const { container } = renderI18n(<RolesPage admin={mockAdmin()} notify={vi.fn()} />);
    await screen.findByText('On-call');
    createWrapper(container).findTable()!.findRowSelectionArea(3)!.click();
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(screen.getByText(/still given to 1 users, 0 access rules and 0 groups/)).toBeInTheDocument();
  });
});

describe('GroupsPage', () => {
  it('lists the groups with their role, namespaces and members', async () => {
    renderI18n(<GroupsPage admin={mockAdmin()} notify={vi.fn()} />);
    expect(await screen.findByText('Payments team')).toBeInTheDocument();
    expect(screen.getByText('On-call')).toBeInTheDocument();
    expect(screen.getByText('bob')).toBeInTheDocument();
  });

  it('creates a group with members and a role', async () => {
    const admin = mockAdmin();
    renderI18n(<GroupsPage admin={admin} notify={vi.fn()} />);
    await screen.findByText('Payments team');
    await userEvent.click(screen.getByRole('button', { name: 'Create group' }));
    const dialog = screen.getByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Name'), 'Platform');
    await userEvent.click(within(dialog).getByRole('radio', { name: /^Administrator/ }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() =>
      expect(admin.createGroup).toHaveBeenCalledWith({ name: 'Platform', description: '', role: 'admin', allNamespaces: false, allowNetcheckNamespace: false, namespaces: [], members: [] }),
    );
  });

  it('explains why the last administrator group cannot be deleted', async () => {
    const admin = mockAdmin({ deleteGroup: vi.fn().mockRejectedValue(new ApiError(409, 'self_admin', 'x')) });
    const { container } = renderI18n(<GroupsPage admin={admin} notify={vi.fn()} />);
    await screen.findByText('Payments team');
    createWrapper(container).findTable()!.findRowSelectionArea(1)!.click();
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('You cannot take away your own administrator role.')).toBeInTheDocument();
  });
});
