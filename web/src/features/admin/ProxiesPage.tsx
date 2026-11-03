import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import { useCallback, useEffect, useState } from 'react';
import { ErrorAlert, errorText, fieldErrorText } from '../../components/errors';
import { useI18n } from '../../i18n';
import { ApiError, type Api } from '../../services/api';
import type { ProxiesView, Proxy } from '../../types/api';

interface Props {
  admin: Api['admin'];
  notify: (type: 'success' | 'error', message: string) => void;
}

// Author of the list copied from the Helm values on the first start.
const SEED_ACTOR = 'helm (initial values)';

interface Draft {
  name: string;
  host: string;
  port: string;
}

/** HTTP proxies TCP and HTTPS checks may go through, always optional. */
export function ProxiesPage({ admin, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [view, setView] = useState<ProxiesView | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [selected, setSelected] = useState<Proxy[]>([]);
  // index -1: a new proxy; otherwise the position being edited.
  const [editing, setEditing] = useState<{ index: number; draft: Draft } | null>(null);
  const [removing, setRemoving] = useState<Proxy | null>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setView(await admin.proxies());
      setSelected([]);
    } catch (e) {
      setLoadError(e);
    }
  }, [admin]);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (proxies: Proxy[], message: string) => {
    setBusy(true);
    setSaveError(null);
    try {
      setView(await admin.saveProxies(proxies));
      setSelected([]);
      setEditing(null);
      setRemoving(null);
      notify('success', message);
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };

  if (loadError) return <ErrorAlert error={loadError} />;
  const current = view?.proxies ?? [];
  const readOnly = view !== null && !view.editable;
  // Server errors name the field as proxies[i].name|host|port.
  const fieldError = (field: keyof Draft) => {
    if (!(saveError instanceof ApiError)) return undefined;
    const d = saveError.details.find((x) => x.field.endsWith(`.${field}`));
    return d ? fieldErrorText(t, d) : undefined;
  };
  const generalError = saveError !== null && !fieldError('name') && !fieldError('host') && !fieldError('port') ? errorText(t, saveError) : undefined;

  const submit = () => {
    if (!editing) return;
    const { index, draft } = editing;
    const proxy: Proxy = { name: draft.name.trim(), host: draft.host.trim(), port: Number(draft.port) };
    const list = index < 0 ? [...current, proxy] : current.map((p, i) => (i === index ? proxy : p));
    void save(list, t('proxies.saved'));
  };

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={t('proxies.description')}
          info={
            view && (
              <Box variant="small" color="text-body-secondary">
                {t('policy.updated', { date: formatDate(view.updatedAt), user: view.updatedBy === SEED_ACTOR ? t('policy.seedActor') : view.updatedBy })}
              </Box>
            )
          }
        >
          {t('proxies.title')}
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
          trackBy="name"
          variant="container"
          selectionType={readOnly ? undefined : 'single'}
          selectedItems={selected}
          onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
          ariaLabels={{ itemSelectionLabel: (_, p) => p.name, selectionGroupLabel: t('proxies.title') }}
          header={
            <Header
              counter={view ? `(${current.length})` : undefined}
              description={t('proxies.listDesc')}
              actions={
                !readOnly && (
                  <SpaceBetween direction="horizontal" size="xs">
                    <Button
                      disabled={selected.length !== 1}
                      onClick={() => {
                        const p = selected[0];
                        if (!p) return;
                        setSaveError(null);
                        setEditing({ index: current.indexOf(p), draft: { name: p.name, host: p.host, port: String(p.port) } });
                      }}
                    >
                      {t('proxies.edit')}
                    </Button>
                    <Button disabled={selected.length !== 1} onClick={() => setRemoving(selected[0] ?? null)}>
                      {t('proxies.delete')}
                    </Button>
                    <Button
                      variant="primary"
                      onClick={() => {
                        setSaveError(null);
                        setEditing({ index: -1, draft: { name: '', host: '', port: '3128' } });
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
                {t('proxies.empty')}
              </Box>
            </Box>
          }
          columnDefinitions={[
            { id: 'name', header: t('proxies.col.name'), cell: (p) => p.name },
            { id: 'address', header: t('proxies.col.address'), cell: (p) => <Box variant="code">{`${p.host}:${p.port}`}</Box> },
          ]}
        />
        <Alert type="info">{t('proxies.note')}</Alert>
      </SpaceBetween>

      {editing && (
        <Modal
          visible
          onDismiss={() => setEditing(null)}
          header={editing.index < 0 ? t('proxies.addTitle') : t('proxies.editTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setEditing(null)}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} disabled={!editing.draft.name.trim() || !editing.draft.host.trim()} onClick={submit}>
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
                <Button
                  variant="primary"
                  loading={busy}
                  onClick={() =>
                    void save(
                      current.filter((p) => p.name !== removing.name),
                      t('proxies.deleted'),
                    )
                  }
                >
                  {t('proxies.delete')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="s">
            {saveError !== null && <Alert type="error">{errorText(t, saveError)}</Alert>}
            <Box variant="p">{t('proxies.deleteBody', { name: removing.name })}</Box>
          </SpaceBetween>
        </Modal>
      )}
    </ContentLayout>
  );
}
