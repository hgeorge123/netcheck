import createWrapper from '@cloudscape-design/components/test-utils/dom';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError, type Api } from '../../services/api';
import { renderI18n } from '../../test/render';
import type { DestinationPolicy, PolicyView, UserView } from '../../types/api';
import { AccessRulesPage } from './AccessRulesPage';
import { NamespacesPage } from './NamespacesPage';
import { ALLOW_ALL, PolicyPage } from './PolicyPage';
import { RetentionPage } from './RetentionPage';
import { browserName, SessionsPage } from './SessionsPage';
import { shortDigest, SystemPage } from './SystemPage';
import { UserFormPage } from './UserFormPage';
import { UsersPage } from './UsersPage';

const common = { createdAt: '2026-10-21T10:00:00Z', passwordChangedAt: '2026-10-21T10:00:00Z', language: '', allowNetcheckNamespace: false, source: 'local' as const, groups: [] as string[] };
const users: UserView[] = [
  { ...common, id: 'u000000000000000000000001', username: 'admin', displayName: 'Administrator', role: 'admin', allNamespaces: true, namespaces: [], disabled: false, locked: false, mustChangePassword: false },
  { ...common, id: 'u000000000000000000000002', username: 'bob', displayName: 'Bob', role: 'user', allNamespaces: false, namespaces: ['payments'], disabled: false, locked: true, mustChangePassword: false, allowNetcheckNamespace: true },
  { ...common, id: 'u000000000000000000000003', username: 'carol', displayName: '', role: 'user', allNamespaces: true, namespaces: [], disabled: true, locked: false, mustChangePassword: true },
];

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
    accessRules: vi.fn().mockResolvedValue({ items: [], ssoEnabled: true }),
    createAccessRule: vi.fn().mockResolvedValue(undefined),
    updateAccessRule: vi.fn().mockResolvedValue(undefined),
    deleteAccessRule: vi.fn().mockResolvedValue(undefined),
    ...over,
  };
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
