import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Checkbox from '@cloudscape-design/components/checkbox';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Modal from '@cloudscape-design/components/modal';
import Multiselect from '@cloudscape-design/components/multiselect';
import RadioGroup from '@cloudscape-design/components/radio-group';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import { useCallback, useEffect, useState } from 'react';
import { ErrorAlert, errorText, fieldErrors } from '../../components/errors';
import { useI18n } from '../../i18n';
import type { Api } from '../../services/api';
import type { AdminNamespaces, GroupInput, GroupView, UserView } from '../../types/api';
import { roleLabel, roleSummary, useCustomRoles } from './roles';

interface Props {
  admin: Api['admin'];
  notify: (type: 'success' | 'error', message: string) => void;
}

const EMPTY: GroupInput = { name: '', description: '', role: 'user', allNamespaces: false, allowNetcheckNamespace: false, namespaces: [], members: [] };

/** Local groups: a role with its namespaces given to every member. */
export function GroupsPage({ admin, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [groups, setGroups] = useState<GroupView[] | null>(null);
  const [users, setUsers] = useState<UserView[]>([]);
  const [ns, setNs] = useState<AdminNamespaces | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [selected, setSelected] = useState<GroupView[]>([]);
  const [editing, setEditing] = useState<{ id?: string; input: GroupInput } | null>(null);
  const [removing, setRemoving] = useState<GroupView | null>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const customRoles = useCustomRoles(admin);

  const load = useCallback(async () => {
    try {
      const [g, u, n] = await Promise.all([admin.groups(), admin.listUsers(), admin.namespaces()]);
      setGroups(g.items);
      setUsers(u.items);
      setNs(n);
      setSelected([]);
    } catch (e) {
      setLoadError(e);
    }
  }, [admin]);

  useEffect(() => {
    void load();
  }, [load]);

  if (loadError) return <ErrorAlert error={loadError} />;
  const one = selected.length === 1 ? selected[0] : undefined;
  const errs = fieldErrors(t, saveError);
  const userName = (id: string) => users.find((u) => u.id === id)?.username ?? id;
  const nsOptions = (ns?.items ?? []).map((n) => ({ value: n, label: n }));
  const userOptions = users.map((u) => ({ value: u.id, label: u.username, description: u.displayName || undefined }));
  const set = (patch: Partial<GroupInput>) => setEditing((e) => e && { ...e, input: { ...e.input, ...patch } });

  const open = (g?: GroupView) => {
    setSaveError(null);
    setEditing(
      g
        ? {
            id: g.id,
            input: {
              name: g.name,
              description: g.description,
              role: g.role,
              allNamespaces: g.allNamespaces,
              allowNetcheckNamespace: g.allowNetcheckNamespace,
              namespaces: g.namespaces,
              members: g.members,
            },
          }
        : { input: { ...EMPTY } },
    );
  };

  const save = async () => {
    if (!editing) return;
    setBusy(true);
    setSaveError(null);
    try {
      if (editing.id) await admin.updateGroup(editing.id, editing.input);
      else await admin.createGroup(editing.input);
      setEditing(null);
      notify('success', t('groups.saved', { name: editing.input.name.trim() }));
      await load();
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!removing) return;
    setBusy(true);
    setSaveError(null);
    try {
      await admin.deleteGroup(removing.id);
      setRemoving(null);
      notify('success', t('groups.deleted', { name: removing.name }));
      await load();
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };

  const scope = (g: GroupView) =>
    g.role === 'admin' || g.allNamespaces
      ? t('users.all')
      : [...g.namespaces, ...(g.allowNetcheckNamespace && ns?.netcheckNamespace ? [ns.netcheckNamespace] : [])].join(', ') || '—';

  return (
    <ContentLayout header={<Header variant="h1" description={t('groups.description')}>{t('groups.title')}</Header>}>
      <SpaceBetween size="l">
        <Table
          loading={groups === null}
          loadingText={t('common.loading')}
          items={groups ?? []}
          trackBy="id"
          wrapLines
          selectionType="single"
          selectedItems={selected}
          onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
          ariaLabels={{ itemSelectionLabel: (_, g) => g.name, selectionGroupLabel: t('groups.title') }}
          empty={
            <Box textAlign="center" color="inherit">
              <b>{t('groups.emptyTitle')}</b>
              <Box variant="p" color="inherit">
                {t('groups.empty')}
              </Box>
            </Box>
          }
          header={
            <Header
              counter={groups ? `(${groups.length})` : undefined}
              description={t('groups.listDesc')}
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button disabled={!one} onClick={() => one && open(one)}>
                    {t('groups.edit')}
                  </Button>
                  <Button disabled={!one} onClick={() => one && setRemoving(one)}>
                    {t('groups.delete')}
                  </Button>
                  <Button variant="primary" onClick={() => open()}>
                    {t('groups.add')}
                  </Button>
                </SpaceBetween>
              }
            >
              {t('groups.listTitle')}
            </Header>
          }
          columnDefinitions={[
            { id: 'name', header: t('groups.col.name'), width: 220, cell: (g) => (g.description ? <><b>{g.name}</b><Box variant="small" color="text-body-secondary">{g.description}</Box></> : <b>{g.name}</b>) },
            { id: 'role', header: t('users.form.role'), width: 180, cell: (g) => roleLabel(t, g.role, g.roleName) },
            { id: 'ns', header: t('users.form.namespaces'), cell: scope },
            { id: 'members', header: t('groups.col.members'), cell: (g) => g.members.map(userName).join(', ') || '—' },
            { id: 'updated', header: t('roles.col.updated'), width: 200, cell: (g) => `${formatDate(g.updatedAt)} · ${g.updatedBy}` },
          ]}
        />
        <Alert type="info">{t('groups.note')}</Alert>
      </SpaceBetween>

      {editing && (
        <Modal
          visible
          size="large"
          onDismiss={() => setEditing(null)}
          header={editing.id ? t('groups.editTitle') : t('groups.addTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setEditing(null)}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} disabled={!editing.input.name.trim()} onClick={() => void save()}>
                  {t('common.save')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="l">
            {saveError !== null && !errs.name && !errs.description && !errs.members && !errs.namespaces && !errs.role && (
              <Alert type="error">{errorText(t, saveError)}</Alert>
            )}
            <FormField label={t('groups.col.name')} errorText={errs.name}>
              <Input value={editing.input.name} onChange={({ detail }) => set({ name: detail.value })} ariaLabel={t('groups.col.name')} />
            </FormField>
            <FormField label={t('roles.descriptionLabel')} errorText={errs.description}>
              <Input value={editing.input.description} onChange={({ detail }) => set({ description: detail.value })} ariaLabel={t('roles.descriptionLabel')} />
            </FormField>
            <FormField label={t('groups.col.members')} description={t('groups.membersDesc')} errorText={errs.members}>
              <Multiselect
                selectedOptions={userOptions.filter((o) => editing.input.members.includes(o.value))}
                options={userOptions}
                filteringType="auto"
                placeholder={t('groups.pickMembers')}
                onChange={({ detail }) => set({ members: detail.selectedOptions.map((o) => o.value ?? '').filter(Boolean) })}
                ariaLabel={t('groups.col.members')}
                empty={t('common.noMatches')}
              />
            </FormField>
            <FormField label={t('users.form.role')} errorText={errs.role}>
              <RadioGroup
                value={editing.input.role}
                onChange={({ detail }) => set({ role: detail.value })}
                ariaLabel={t('users.form.role')}
                items={[
                  { value: 'user', label: t('users.form.role.user'), description: t('users.form.role.user.desc') },
                  { value: 'admin', label: t('users.form.role.admin'), description: t('users.form.role.admin.desc') },
                  ...customRoles.map((r) => ({ value: r.id, label: r.name, description: roleSummary(t, r) })),
                ]}
              />
            </FormField>
            {editing.input.role !== 'admin' && (
              <FormField label={t('users.form.namespaces')} errorText={errs.namespaces}>
                <SpaceBetween size="s">
                  <RadioGroup
                    value={editing.input.allNamespaces ? 'all' : 'some'}
                    onChange={({ detail }) => set({ allNamespaces: detail.value === 'all' })}
                    ariaLabel={t('users.form.namespaces')}
                    items={[
                      { value: 'all', label: t('users.form.scopeAll') },
                      { value: 'some', label: t('users.form.scopeSome') },
                    ]}
                  />
                  {!editing.input.allNamespaces && (
                    <Multiselect
                      selectedOptions={nsOptions.filter((o) => editing.input.namespaces.includes(o.value))}
                      options={nsOptions}
                      filteringType="auto"
                      filteringPlaceholder={t('users.form.searchNs')}
                      placeholder={t('users.form.pick')}
                      onChange={({ detail }) => set({ namespaces: detail.selectedOptions.map((o) => o.value ?? '').filter(Boolean) })}
                      ariaLabel={t('users.form.allowed')}
                      empty={t('users.form.noNs')}
                    />
                  )}
                </SpaceBetween>
              </FormField>
            )}
            {ns?.netcheckNamespace && (
              <Checkbox checked={editing.input.allowNetcheckNamespace} onChange={({ detail }) => set({ allowNetcheckNamespace: detail.checked })}>
                {t('users.form.ownNs', { ns: ns.netcheckNamespace })}
              </Checkbox>
            )}
          </SpaceBetween>
        </Modal>
      )}

      {removing && (
        <Modal
          visible
          onDismiss={() => setRemoving(null)}
          header={t('groups.deleteTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setRemoving(null)}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} onClick={() => void remove()}>
                  {t('groups.delete')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            {saveError !== null && <ErrorAlert error={saveError} />}
            <Box variant="p">{t('groups.deleteBody', { name: removing.name, n: removing.members.length })}</Box>
          </SpaceBetween>
        </Modal>
      )}
    </ContentLayout>
  );
}
