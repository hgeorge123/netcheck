import Alert from '@cloudscape-design/components/alert';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Checkbox from '@cloudscape-design/components/checkbox';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import Textarea from '@cloudscape-design/components/textarea';
import { useCallback, useEffect, useState } from 'react';
import { ErrorAlert, errorText, fieldErrors } from '../../components/errors';
import { lookup, useI18n, type Translate } from '../../i18n';
import type { Api } from '../../services/api';
import type { RoleInput, RoleView } from '../../types/api';
import { roleLabel } from './roles';

interface Props {
  admin: Api['admin'];
  notify: (type: 'success' | 'error', message: string) => void;
}

/** Permissions grouped as the role form shows them. */
const GROUPS: { key: string; match: (p: string) => boolean }[] = [
  { key: 'checks', match: (p) => p.startsWith('check.') || p === 'mode.firewall' },
  { key: 'runs', match: (p) => p.startsWith('runs.') },
  { key: 'proxies', match: (p) => p.startsWith('proxies.') },
  { key: 'tokens', match: (p) => p.startsWith('tokens.') },
  { key: 'admin', match: (p) => p.startsWith('admin.') },
];

/** Translated name of a permission. */
export function permissionLabel(t: Translate, p: string): string {
  if (p.startsWith('check.')) return lookup(t, `method.${p.slice(6)}`) ?? p;
  return lookup(t, `perm.${p}`) ?? p;
}

const EMPTY: RoleInput = { name: '', description: '', permissions: [] };

/** Built-in and custom roles: what each one allows. */
export function RolesPage({ admin, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [roles, setRoles] = useState<RoleView[] | null>(null);
  const [all, setAll] = useState<string[]>([]);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [selected, setSelected] = useState<RoleView[]>([]);
  const [editing, setEditing] = useState<{ id?: string; input: RoleInput } | null>(null);
  const [removing, setRemoving] = useState<RoleView | null>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const v = await admin.roles();
      setRoles(v.roles);
      setAll(v.permissions);
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

  const open = (r?: RoleView) => {
    setSaveError(null);
    setEditing(r ? { id: r.id, input: { name: r.name, description: r.description, permissions: r.permissions } } : { input: { ...EMPTY } });
  };
  const toggle = (p: string, on: boolean) =>
    setEditing((e) => e && { ...e, input: { ...e.input, permissions: on ? [...e.input.permissions, p] : e.input.permissions.filter((x) => x !== p) } });

  const save = async () => {
    if (!editing) return;
    setBusy(true);
    setSaveError(null);
    try {
      if (editing.id) await admin.updateRole(editing.id, editing.input);
      else await admin.createRole(editing.input);
      setEditing(null);
      notify('success', t('roles.saved', { name: editing.input.name.trim() }));
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
      await admin.deleteRole(removing.id);
      setRemoving(null);
      notify('success', t('roles.deleted', { name: removing.name }));
      await load();
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };

  const summary = (r: RoleView) => {
    if (r.id === 'admin') return t('roles.adminSummary');
    const checks = r.permissions.filter((p) => p.startsWith('check.')).map((p) => permissionLabel(t, p));
    const rest = r.permissions.filter((p) => !p.startsWith('check.')).map((p) => permissionLabel(t, p));
    return [...checks, ...rest].join(', ') || t('roles.nothing');
  };

  return (
    <ContentLayout header={<Header variant="h1" description={t('roles.description')}>{t('roles.title')}</Header>}>
      <SpaceBetween size="l">
        <Table
          loading={roles === null}
          loadingText={t('common.loading')}
          items={roles ?? []}
          trackBy="id"
          wrapLines
          selectionType="single"
          selectedItems={selected}
          isItemDisabled={(r) => r.builtin}
          onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
          ariaLabels={{ itemSelectionLabel: (_, r) => r.name, selectionGroupLabel: t('roles.title') }}
          header={
            <Header
              counter={roles ? `(${roles.length})` : undefined}
              description={t('roles.listDesc')}
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button disabled={!one} onClick={() => one && open(one)}>
                    {t('roles.edit')}
                  </Button>
                  <Button disabled={!one} onClick={() => one && setRemoving(one)}>
                    {t('roles.delete')}
                  </Button>
                  <Button variant="primary" onClick={() => open()}>
                    {t('roles.add')}
                  </Button>
                </SpaceBetween>
              }
            >
              {t('roles.listTitle')}
            </Header>
          }
          columnDefinitions={[
            {
              id: 'name',
              header: t('roles.col.name'),
              width: 240,
              cell: (r) => (
                <SpaceBetween direction="horizontal" size="xs">
                  <b>{roleLabel(t, r.id, r.name)}</b>
                  {r.builtin && <Badge>{t('roles.builtin')}</Badge>}
                </SpaceBetween>
              ),
            },
            { id: 'perms', header: t('roles.col.permissions'), cell: (r) => (r.description ? <>{r.description}<Box variant="small" color="text-body-secondary">{summary(r)}</Box></> : summary(r)) },
            {
              id: 'usage',
              header: t('roles.col.usage'),
              width: 200,
              cell: (r) => (r.builtin ? '—' : t('roles.usage', { users: r.users, rules: r.rules, groups: r.groups })),
            },
            { id: 'updated', header: t('roles.col.updated'), width: 200, cell: (r) => (r.builtin ? '—' : `${formatDate(r.updatedAt)} · ${r.updatedBy}`) },
          ]}
        />
        <Alert type="info">{t('roles.note')}</Alert>
      </SpaceBetween>

      {editing && (
        <Modal
          visible
          size="large"
          onDismiss={() => setEditing(null)}
          header={editing.id ? t('roles.editTitle') : t('roles.addTitle')}
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
            {saveError !== null && !errs.name && !errs.description && !errs.permissions && <Alert type="error">{errorText(t, saveError)}</Alert>}
            <FormField label={t('roles.col.name')} errorText={errs.name}>
              <Input
                value={editing.input.name}
                onChange={({ detail }) => setEditing({ ...editing, input: { ...editing.input, name: detail.value } })}
                ariaLabel={t('roles.col.name')}
              />
            </FormField>
            <FormField label={t('roles.descriptionLabel')} errorText={errs.description}>
              <Textarea
                rows={2}
                value={editing.input.description}
                onChange={({ detail }) => setEditing({ ...editing, input: { ...editing.input, description: detail.value } })}
                ariaLabel={t('roles.descriptionLabel')}
              />
            </FormField>
            <FormField label={t('roles.col.permissions')} description={t('roles.permissionsDesc')} errorText={errs.permissions}>
              <ColumnLayout columns={2}>
                {GROUPS.map((g) => (
                  <SpaceBetween key={g.key} size="xxs">
                    <Box variant="h4">{t(`roles.group.${g.key}` as Parameters<Translate>[0])}</Box>
                    {all.filter(g.match).map((p) => (
                      <Checkbox key={p} checked={editing.input.permissions.includes(p)} onChange={({ detail }) => toggle(p, detail.checked)}>
                        {permissionLabel(t, p)}
                      </Checkbox>
                    ))}
                  </SpaceBetween>
                ))}
              </ColumnLayout>
            </FormField>
          </SpaceBetween>
        </Modal>
      )}

      {removing && (
        <Modal
          visible
          onDismiss={() => setRemoving(null)}
          header={t('roles.deleteTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setRemoving(null)}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} onClick={() => void remove()}>
                  {t('roles.delete')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            {saveError !== null && <ErrorAlert error={saveError} />}
            <Box variant="p">{removing.users + removing.rules + removing.groups > 0 ? t('roles.inUse', { users: removing.users, rules: removing.rules, groups: removing.groups }) : t('roles.deleteBody', { name: removing.name })}</Box>
          </SpaceBetween>
        </Modal>
      )}
    </ContentLayout>
  );
}

