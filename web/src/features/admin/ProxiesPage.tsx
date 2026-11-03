import Alert from '@cloudscape-design/components/alert';
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
import { ErrorAlert, errorText, fieldErrorText } from '../../components/errors';
import { useI18n } from '../../i18n';
import { ApiError } from '../../services/api';
import type { ProxiesView, Proxy, ProxyInput } from '../../types/api';

/** The calls of one kind of proxies: administrators' or the user's own. */
export interface ProxyCalls {
  list: () => Promise<ProxiesView>;
  create: (p: ProxyInput) => Promise<Proxy>;
  update: (id: string, p: ProxyInput) => Promise<Proxy>;
  remove: (id: string) => Promise<undefined>;
}

interface Props {
  /** admin: the administrators' proxies (shared or for administrators); personal: the user's own. */
  scope: 'admin' | 'personal';
  calls: ProxyCalls;
  notify: (type: 'success' | 'error', message: string) => void;
}

interface Draft {
  name: string;
  host: string;
  port: string;
  shared: boolean;
  pem: string;
}

const emptyDraft = (scope: Props['scope']): Draft => ({ name: '', host: '', port: '3128', shared: scope === 'admin', pem: '' });

/** HTTP proxies checks may go through, always optional per check. */
export function ProxiesPage({ scope, calls, notify }: Props) {
  const { t } = useI18n();
  const [view, setView] = useState<ProxiesView | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [selected, setSelected] = useState<Proxy[]>([]);
  // id undefined: a new proxy.
  const [editing, setEditing] = useState<{ id?: string; draft: Draft } | null>(null);
  const [removing, setRemoving] = useState<Proxy | null>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const k = scope === 'admin' ? 'proxies' : 'myProxies';

  const load = useCallback(async () => {
    try {
      setView(await calls.list());
      setSelected([]);
    } catch (e) {
      setLoadError(e);
    }
  }, [calls]);

  useEffect(() => {
    void load();
  }, [load]);

  if (loadError) return <ErrorAlert error={loadError} />;
  const current = view?.proxies ?? [];
  const readOnly = view !== null && !view.editable;
  const full = view !== null && current.length >= view.max;
  const fieldError = (field: string) => {
    if (!(saveError instanceof ApiError)) return undefined;
    const d = saveError.details.find((x) => x.field === field || x.field.endsWith(`.${field}`));
    return d ? fieldErrorText(t, d) : undefined;
  };
  const generalError =
    saveError !== null && !['name', 'host', 'port', 'certificates'].some((f) => fieldError(f)) ? errorText(t, saveError) : undefined;

  const submit = async () => {
    if (!editing) return;
    const { id, draft } = editing;
    // Each certificate block is sent as is; the server splits bundles.
    const certificates = draft.pem.trim() ? [draft.pem] : [];
    const input: ProxyInput = { name: draft.name.trim(), host: draft.host.trim(), port: Number(draft.port), shared: scope === 'admin' && draft.shared, certificates };
    setBusy(true);
    setSaveError(null);
    try {
      if (id) await calls.update(id, input);
      else await calls.create(input);
      setEditing(null);
      notify('success', t(`${k}.saved`));
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
      await calls.remove(removing.id);
      setRemoving(null);
      notify('success', t('proxies.deleted'));
      await load();
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };

  const edit = (p: Proxy) => {
    setSaveError(null);
    setEditing({
      id: p.id,
      draft: { name: p.name, host: p.host, port: String(p.port), shared: p.shared, pem: (p.certificates ?? []).map((c) => c.pem.trim()).join('\n') },
    });
  };

  return (
    <ContentLayout
      header={
        <Header variant="h1" description={t(`${k}.description`)}>
          {t(`${k}.title`)}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {readOnly && (
          <Alert type="info" header={t('proxies.helmTitle')}>
            {t('proxies.helmBody')}
          </Alert>
        )}
        <Table
          items={current}
          loading={view === null}
          loadingText={t('common.loading')}
          trackBy="id"
          variant="container"
          selectionType={readOnly ? undefined : 'single'}
          selectedItems={selected}
          onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
          ariaLabels={{ itemSelectionLabel: (_, p) => p.name, selectionGroupLabel: t(`${k}.title`) }}
          header={
            <Header
              counter={view ? `(${current.length}/${view.max})` : undefined}
              description={t(`${k}.listDesc`)}
              actions={
                !readOnly && (
                  <SpaceBetween direction="horizontal" size="xs">
                    <Button disabled={selected.length !== 1} onClick={() => selected[0] && edit(selected[0])}>
                      {t('proxies.edit')}
                    </Button>
                    <Button disabled={selected.length !== 1} onClick={() => setRemoving(selected[0] ?? null)}>
                      {t('proxies.delete')}
                    </Button>
                    <Button
                      variant="primary"
                      disabled={full}
                      onClick={() => {
                        setSaveError(null);
                        setEditing({ draft: emptyDraft(scope) });
                      }}
                    >
                      {t('proxies.add')}
                    </Button>
                  </SpaceBetween>
                )
              }
            >
              {t('proxies.listTitle')}
            </Header>
          }
          empty={
            <Box textAlign="center" color="inherit">
              <b>{t('proxies.emptyTitle')}</b>
              <Box variant="p" color="inherit">
                {t(`${k}.empty`)}
              </Box>
            </Box>
          }
          columnDefinitions={[
            { id: 'name', header: t('proxies.col.name'), cell: (p) => p.name },
            { id: 'address', header: t('proxies.col.address'), cell: (p) => <Box variant="code">{`${p.host}:${p.port}`}</Box> },
            ...(scope === 'admin'
              ? [{ id: 'shared', header: t('proxies.col.shared'), cell: (p: Proxy) => t(p.shared ? 'proxies.sharedAll' : 'proxies.sharedAdmins') }]
              : []),
            {
              id: 'cas',
              header: t('proxies.col.certificates'),
              cell: (p) => (p.certificateCount > 0 ? (p.certificates ?? []).map((c) => c.subject).join('; ') || String(p.certificateCount) : '—'),
            },
          ]}
        />
        <Alert type="info">{t(`${k}.note`)}</Alert>
      </SpaceBetween>

      {editing && (
        <Modal
          visible
          size="large"
          onDismiss={() => setEditing(null)}
          header={editing.id ? t('proxies.editTitle') : t('proxies.addTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setEditing(null)}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} disabled={!editing.draft.name.trim() || !editing.draft.host.trim()} onClick={() => void submit()}>
                  {t('common.save')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            {generalError && <Alert type="error">{generalError}</Alert>}
            <FormField label={t('proxies.col.name')} description={t('proxies.nameDesc')} errorText={fieldError('name')}>
              <Input
                value={editing.draft.name}
                onChange={({ detail }) => setEditing({ ...editing, draft: { ...editing.draft, name: detail.value } })}
                placeholder="corp"
                ariaLabel={t('proxies.col.name')}
              />
            </FormField>
            <ColumnLayout columns={2}>
              <FormField label={t('proxies.host')} errorText={fieldError('host')}>
                <Input
                  value={editing.draft.host}
                  onChange={({ detail }) => setEditing({ ...editing, draft: { ...editing.draft, host: detail.value } })}
                  placeholder="proxy.example.com"
                  ariaLabel={t('proxies.host')}
                />
              </FormField>
              <FormField label={t('newTest.port')} errorText={fieldError('port')}>
                <Input
                  value={editing.draft.port}
                  inputMode="numeric"
                  onChange={({ detail }) => setEditing({ ...editing, draft: { ...editing.draft, port: detail.value } })}
                  ariaLabel={t('newTest.port')}
                />
              </FormField>
            </ColumnLayout>
            {scope === 'admin' && (
              <FormField description={t('proxies.sharedDesc')}>
                <Checkbox
                  checked={editing.draft.shared}
                  onChange={({ detail }) => setEditing({ ...editing, draft: { ...editing.draft, shared: detail.checked } })}
                >
                  {t('proxies.sharedLabel')}
                </Checkbox>
              </FormField>
            )}
            <FormField label={t('proxies.pem')} description={t('proxies.pemDesc')} errorText={fieldError('certificates')}>
              <Textarea
                value={editing.draft.pem}
                rows={8}
                spellcheck={false}
                placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----'}
                onChange={({ detail }) => setEditing({ ...editing, draft: { ...editing.draft, pem: detail.value } })}
                ariaLabel={t('proxies.pem')}
              />
            </FormField>
          </SpaceBetween>
        </Modal>
      )}

      {removing && (
        <Modal
          visible
          onDismiss={() => setRemoving(null)}
          header={t('proxies.deleteTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setRemoving(null)}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} onClick={() => void remove()}>
                  {t('proxies.delete')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="s">
            {saveError !== null && <Alert type="error">{errorText(t, saveError)}</Alert>}
            <Box variant="p">{t(`${k}.deleteBody`, { name: removing.name })}</Box>
          </SpaceBetween>
        </Modal>
      )}
    </ContentLayout>
  );
}
