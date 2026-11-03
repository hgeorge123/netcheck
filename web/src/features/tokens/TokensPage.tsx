import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import CopyToClipboard from '@cloudscape-design/components/copy-to-clipboard';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Modal from '@cloudscape-design/components/modal';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import { useCallback, useEffect, useState } from 'react';
import { ErrorAlert, errorText, fieldErrors } from '../../components/errors';
import { useI18n } from '../../i18n';
import { ApiError } from '../../services/api';
import type { ApiToken } from '../../types/api';

const EXPIRY_DAYS = [30, 90, 180, 365];

interface Props {
  /** Own tokens (create and revoke) or, for administrators, everybody's (revoke only). */
  scope: 'mine' | 'all';
  list: () => Promise<{ items: ApiToken[] }>;
  revoke: (id: string) => Promise<unknown>;
  create?: (name: string, expiresInDays: number) => Promise<{ token: string; item: ApiToken }>;
  notify: (type: 'success' | 'error', message: string) => void;
}

export function cliExample(origin: string): string {
  return [
    `export NETCHECK_URL=${origin}`,
    'export NETCHECK_TOKEN=<token>',
    'netcheck-cli run -n <namespace> -t <destination> -c dns -c tcp:443',
  ].join('\n');
}

export function TokensPage({ scope, list, revoke, create, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [items, setItems] = useState<ApiToken[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [selected, setSelected] = useState<ApiToken[]>([]);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [days, setDays] = useState(90);
  const [createError, setCreateError] = useState<unknown>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<ApiToken | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setItems((await list()).items);
      setSelected([]);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)));
    }
  }, [list]);

  useEffect(() => {
    void load();
  }, [load]);

  const submit = async () => {
    if (!create) return;
    setBusy(true);
    setCreateError(null);
    try {
      const res = await create(name.trim(), days);
      setCreating(false);
      setSecret(res.token);
      setName('');
      await load();
    } catch (e) {
      setCreateError(e);
    } finally {
      setBusy(false);
    }
  };

  const doRevoke = async () => {
    if (!revoking) return;
    setBusy(true);
    try {
      await revoke(revoking.id);
      notify('success', t('tokens.revoked', { name: revoking.name }));
      setRevoking(null);
      await load();
    } catch (e) {
      notify('error', errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  const errs = fieldErrors(t, createError);
  const expired = (tk: ApiToken) => new Date(tk.expiresAt).getTime() < Date.now();
  const dayOptions = EXPIRY_DAYS.map((d) => ({ value: String(d), label: t('tokens.days', { n: d }) }));

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={scope === 'mine' ? t('tokens.desc') : t('tokens.adminDesc')}
          actions={
            create && (
              <Button variant="primary" onClick={() => setCreating(true)}>
                {t('tokens.create')}
              </Button>
            )
          }
        >
          {t('tokens.title')}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {error && <ErrorAlert error={error} header={t('tokens.loadFailed')} />}
        {secret && (
          <Alert type="success" dismissible onDismiss={() => setSecret(null)} header={t('tokens.createdTitle')}>
            <SpaceBetween size="s">
              <Box>{t('tokens.createdOnce')}</Box>
              <SpaceBetween direction="horizontal" size="xs" alignItems="center">
                <Box variant="code" data-testid="token-secret">
                  {secret}
                </Box>
                <CopyToClipboard variant="icon" textToCopy={secret} copySuccessText={t('common.copied')} copyErrorText={t('common.copyFailed')} />
              </SpaceBetween>
              <Box variant="small">{t('tokens.cliIntro')}</Box>
              <Box variant="code">
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{cliExample(window.location.origin)}</pre>
              </Box>
            </SpaceBetween>
          </Alert>
        )}
        <Table
          items={items ?? []}
          loading={items === null && !error}
          loadingText={t('common.loading')}
          trackBy="id"
          variant="container"
          selectionType="single"
          selectedItems={selected}
          onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
          ariaLabels={{ itemSelectionLabel: (_, tk) => tk.name, selectionGroupLabel: t('tokens.title') }}
          header={
            <Header
              counter={items ? `(${items.length})` : undefined}
              actions={
                <Button disabled={selected.length !== 1} onClick={() => setRevoking(selected[0] ?? null)}>
                  {t('tokens.revoke')}
                </Button>
              }
            >
              {t('tokens.listTitle')}
            </Header>
          }
          empty={
            <Box textAlign="center" color="inherit">
              <b>{t('tokens.emptyTitle')}</b>
              <Box variant="p" color="inherit">
                {t('tokens.empty')}
              </Box>
            </Box>
          }
          columnDefinitions={[
            { id: 'name', header: t('tokens.col.name'), cell: (tk) => tk.name },
            { id: 'prefix', header: t('tokens.col.prefix'), cell: (tk) => <Box variant="code">{`${tk.prefix}…`}</Box> },
            ...(scope === 'all' ? [{ id: 'owner', header: t('tokens.col.owner'), cell: (tk: ApiToken) => tk.owner }] : []),
            { id: 'created', header: t('tokens.col.created'), cell: (tk) => formatDate(tk.createdAt) },
            { id: 'expires', header: t('tokens.col.expires'), cell: (tk) => (expired(tk) ? t('tokens.expired') : formatDate(tk.expiresAt)) },
            { id: 'used', header: t('tokens.col.used'), cell: (tk) => (tk.lastUsedAt ? formatDate(tk.lastUsedAt) : t('common.never')) },
          ]}
        />
      </SpaceBetween>

      {creating && (
        <Modal
          visible
          onDismiss={() => setCreating(false)}
          header={t('tokens.createTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setCreating(false)}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} onClick={() => void submit()}>
                  {t('tokens.create')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="l">
            <Box>{t('tokens.scope')}</Box>
            {createError !== null && !errs.name && !errs.expiresInDays && <Alert type="error">{errorText(t, createError)}</Alert>}
            <FormField label={t('tokens.col.name')} description={t('tokens.nameDesc')} errorText={errs.name}>
              <Input value={name} onChange={({ detail }) => setName(detail.value)} ariaLabel={t('tokens.col.name')} />
            </FormField>
            <FormField label={t('tokens.expiry')} errorText={errs.expiresInDays}>
              <Select
                selectedOption={dayOptions.find((o) => o.value === String(days)) ?? null}
                options={dayOptions}
                onChange={({ detail }) => setDays(Number(detail.selectedOption.value))}
                ariaLabel={t('tokens.expiry')}
              />
            </FormField>
          </SpaceBetween>
        </Modal>
      )}

      {revoking && (
        <Modal
          visible
          onDismiss={() => setRevoking(null)}
          header={t('tokens.revokeTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setRevoking(null)}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} onClick={() => void doRevoke()}>
                  {t('tokens.revoke')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          {t('tokens.revokeBody', { name: revoking.name, owner: revoking.owner })}
        </Modal>
      )}
    </ContentLayout>
  );
}
