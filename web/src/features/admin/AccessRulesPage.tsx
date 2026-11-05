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
import { useI18n, type Translate } from '../../i18n';
import { ApiError, type Api } from '../../services/api';
import type { AccessRule, AccessRuleInput, AdminNamespaces, Role, RuleSubject } from '../../types/api';
import { roleLabel, roleSummary, useCustomRoles } from './roles';

interface Props {
  admin: Api['admin'];
  notify: (type: 'success' | 'error', message: string) => void;
}

const EMPTY: AccessRuleInput = { subjectType: 'group', subject: '', role: 'user', allNamespaces: false, allowNetcheckNamespace: false, namespaces: [] };

/** The editable fields of a rule: the API rejects the read-only ones (id, updatedAt, updatedBy). */
function toInput(r: AccessRule): AccessRuleInput {
  const { subjectType, subject, role, allNamespaces, allowNetcheckNamespace, namespaces } = r;
  return { subjectType, subject, role, allNamespaces, allowNetcheckNamespace, namespaces: namespaces ?? [] };
}

export function subjectText(t: Translate, r: Pick<AccessRule, 'subjectType' | 'subject'>): string {
  return r.subjectType === 'authenticated' ? t('rules.subject.authenticated') : `${t(`rules.subject.${r.subjectType}`)}: ${r.subject}`;
}

function accessText(t: Translate, r: AccessRule): string {
  if (r.role === 'admin') return t('rules.access.admin');
  const parts = [r.allNamespaces ? t('rules.access.all') : r.namespaces.join(', ') || '—'];
  if (r.allowNetcheckNamespace) parts.push(t('rules.access.own'));
  return parts.join(' + ');
}

/** Rules that grant SSO accounts their role and namespaces, before they sign in. */
export function AccessRulesPage({ admin, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [rules, setRules] = useState<AccessRule[] | null>(null);
  const [ssoEnabled, setSsoEnabled] = useState(true);
  const customRoles = useCustomRoles(admin);
  const [ns, setNs] = useState<AdminNamespaces | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [editing, setEditing] = useState<{ id?: string; input: AccessRuleInput } | null>(null);
  const [deleting, setDeleting] = useState<AccessRule | null>(null);
  const [selected, setSelected] = useState<AccessRule[]>([]);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [r, n] = await Promise.all([admin.accessRules(), admin.namespaces()]);
      setRules(r.items);
      setSsoEnabled(r.ssoEnabled);
      setNs(n);
      setSelected([]);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)));
    }
  }, [admin]);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async () => {
    if (!editing) return;
    setBusy(true);
    setSaveError(null);
    try {
      if (editing.id) await admin.updateAccessRule(editing.id, editing.input);
      else await admin.createAccessRule(editing.input);
      notify('success', t('rules.saved'));
      setEditing(null);
      await load();
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!deleting) return;
    setBusy(true);
    try {
      await admin.deleteAccessRule(deleting.id);
      notify('success', t('rules.deleted'));
      setDeleting(null);
      await load();
    } catch (e) {
      notify('error', errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  const set = (patch: Partial<AccessRuleInput>) => editing && setEditing({ ...editing, input: { ...editing.input, ...patch } });
  const errs = fieldErrors(t, saveError);
  const nsOptions = (ns?.items ?? []).map((n) => ({ value: n, label: n }));
  const input = editing?.input;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={t('rules.desc')}
          actions={
            <Button variant="primary" onClick={() => setEditing({ input: EMPTY })}>
              {t('rules.create')}
            </Button>
          }
        >
          {t('rules.title')}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {!ssoEnabled && <Alert type="info" header={t('rules.ssoOffTitle')}>{t('rules.ssoOff')}</Alert>}
        {error && <ErrorAlert error={error} header={t('rules.loadFailed')} />}
        <Table
          items={rules ?? []}
          loading={rules === null && !error}
          loadingText={t('common.loading')}
          trackBy="id"
          variant="container"
          selectionType="single"
          selectedItems={selected}
          onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
          ariaLabels={{ itemSelectionLabel: (_, r) => subjectText(t, r), selectionGroupLabel: t('rules.title') }}
          header={
            <Header
              counter={rules ? `(${rules.length})` : undefined}
              description={t('rules.unionNote')}
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button disabled={selected.length !== 1} onClick={() => selected[0] && setEditing({ id: selected[0].id, input: toInput(selected[0]) })}>
                    {t('rules.edit')}
                  </Button>
                  <Button disabled={selected.length !== 1} onClick={() => setDeleting(selected[0] ?? null)}>
                    {t('rules.delete')}
                  </Button>
                </SpaceBetween>
              }
            >
              {t('rules.listTitle')}
            </Header>
          }
          empty={
            <Box textAlign="center" color="inherit">
              <b>{t('rules.emptyTitle')}</b>
              <Box variant="p" color="inherit">
                {t('rules.empty')}
              </Box>
            </Box>
          }
          columnDefinitions={[
            { id: 'subject', header: t('rules.col.subject'), cell: (r) => subjectText(t, r) },
            { id: 'role', header: t('rules.col.role'), cell: (r) => roleLabel(t, r.role, r.roleName) },
            { id: 'access', header: t('rules.col.access'), cell: (r) => accessText(t, r) },
            { id: 'updated', header: t('rules.col.updated'), cell: (r) => `${formatDate(r.updatedAt)} · ${r.updatedBy}` },
          ]}
        />
      </SpaceBetween>

      {editing && input && (
        <Modal
          visible
          size="large"
          onDismiss={() => setEditing(null)}
          header={editing.id ? t('rules.editTitle') : t('rules.createTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setEditing(null)}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} onClick={() => void save()}>
                  {t('common.save')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="l">
            {saveError !== null && !errs.subject && !errs.namespaces && !errs.role && <Alert type="error">{errorText(t, saveError)}</Alert>}
            <FormField label={t('rules.form.appliesTo')} errorText={errs.subjectType}>
              <RadioGroup
                value={input.subjectType}
                onChange={({ detail }) => set({ subjectType: detail.value as RuleSubject })}
                ariaLabel={t('rules.form.appliesTo')}
                items={(['group', 'user', 'authenticated'] as const).map((s) => ({
                  value: s,
                  label: t(`rules.subject.${s}`),
                  description: t(`rules.subject.${s}.desc`),
                }))}
              />
            </FormField>
            {input.subjectType !== 'authenticated' && (
              <FormField
                label={t(`rules.form.${input.subjectType}`)}
                description={t(`rules.form.${input.subjectType}.desc`)}
                errorText={errs.subject}
              >
                <Input value={input.subject} onChange={({ detail }) => set({ subject: detail.value })} ariaLabel={t(`rules.form.${input.subjectType}`)} />
              </FormField>
            )}
            <FormField label={t('users.form.role')} errorText={errs.role}>
              <RadioGroup
                value={input.role}
                onChange={({ detail }) => set({ role: detail.value as Role })}
                ariaLabel={t('users.form.role')}
                items={[
                  { value: 'user', label: t('users.form.role.user'), description: t('users.form.role.user.desc') },
                  { value: 'admin', label: t('users.form.role.admin'), description: t('users.form.role.admin.desc') },
                  ...customRoles.map((x) => ({ value: x.id, label: x.name, description: roleSummary(t, x) })),
                ]}
              />
            </FormField>
            {input.role !== 'admin' && (
              <FormField label={t('users.form.namespaces')} errorText={errs.namespaces}>
                <SpaceBetween size="s">
                  <RadioGroup
                    value={input.allNamespaces ? 'all' : 'some'}
                    onChange={({ detail }) => set({ allNamespaces: detail.value === 'all' })}
                    ariaLabel={t('users.form.namespaces')}
                    items={[
                      { value: 'all', label: t('users.form.scopeAll') },
                      { value: 'some', label: t('users.form.scopeSome') },
                    ]}
                  />
                  {!input.allNamespaces && (
                    <Multiselect
                      selectedOptions={nsOptions.filter((o) => input.namespaces.includes(o.value))}
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
              <Checkbox checked={input.allowNetcheckNamespace} onChange={({ detail }) => set({ allowNetcheckNamespace: detail.checked })}>
                {t('users.form.ownNs', { ns: ns.netcheckNamespace })}
              </Checkbox>
            )}
          </SpaceBetween>
        </Modal>
      )}

      {deleting && (
        <Modal
          visible
          onDismiss={() => setDeleting(null)}
          header={t('rules.deleteTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setDeleting(null)}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} onClick={() => void remove()}>
                  {t('rules.delete')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          {t('rules.deleteBody', { subject: subjectText(t, deleting) })}
        </Modal>
      )}
    </ContentLayout>
  );
}
