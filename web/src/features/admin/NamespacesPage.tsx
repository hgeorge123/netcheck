import { useCollection } from '@cloudscape-design/collection-hooks';
import Alert from '@cloudscape-design/components/alert';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Modal from '@cloudscape-design/components/modal';
import Pagination from '@cloudscape-design/components/pagination';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator, { type StatusIndicatorProps } from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';
import { useCallback, useEffect, useState } from 'react';
import { ErrorAlert, errorText, fieldErrorText } from '../../components/errors';
import { useI18n } from '../../i18n';
import { ApiError, type Api } from '../../services/api';
import type { NamespaceExclusions, NamespaceRow, NamespaceStatus } from '../../types/api';

interface Props {
  admin: Api['admin'];
  notify: (type: 'success' | 'error', message: string) => void;
}

const statusType: Record<NamespaceStatus, StatusIndicatorProps.Type> = {
  available: 'success',
  excluded_web: 'warning',
  excluded_helm: 'stopped',
  system: 'stopped',
  netcheck: 'info',
};

const dnsLabel = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;

export function NamespacesPage({ admin, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [data, setData] = useState<NamespaceExclusions | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [excludeOpen, setExcludeOpen] = useState(false);
  const [name, setName] = useState('');
  const [reason, setReason] = useState('');
  const [formError, setFormError] = useState<{ name?: string; reason?: string; form?: string }>({});
  const [includeFor, setIncludeFor] = useState<NamespaceRow | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    admin
      .namespaceExclusions()
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e: unknown) => setError(e))
      .finally(() => setLoading(false));
  }, [admin]);
  useEffect(load, [load]);

  const { items, collectionProps, filterProps, paginationProps, filteredItemsCount, actions } = useCollection(data?.items ?? [], {
    filtering: {
      filteringFunction: (n, text) => {
        const q = text.trim().toLowerCase();
        return !q || n.name.includes(q) || (n.reason ?? '').toLowerCase().includes(q) || t(`ns.status.${n.status}`).toLowerCase().includes(q);
      },
      empty: <Box textAlign="center">{t('ns.empty')}</Box>,
      noMatch: (
        <Box textAlign="center">
          <SpaceBetween size="xs">
            <b>{t('common.noMatches')}</b>
            <Button onClick={() => actions.setFiltering('')}>{t('common.clearFilter')}</Button>
          </SpaceBetween>
        </Box>
      ),
    },
    pagination: { pageSize: 25 },
    sorting: { defaultState: { sortingColumn: { sortingField: 'name' } } },
    selection: { trackBy: 'name' },
  });
  const sel = collectionProps.selectedItems?.[0];

  const openExclude = (preset: string) => {
    setName(preset);
    setReason('');
    setFormError({});
    setExcludeOpen(true);
  };

  const exclude = async () => {
    const n = name.trim();
    if (!dnsLabel.test(n)) {
      setFormError({ name: t('ns.invalidName') });
      return;
    }
    setBusy(true);
    try {
      await admin.excludeNamespace(n, reason.trim());
      notify('success', t('ns.excluded', { name: n }));
      setExcludeOpen(false);
      actions.setSelectedItems([]);
      load();
    } catch (e) {
      const d = e instanceof ApiError ? e.details[0] : undefined;
      setFormError(d?.field === 'reason' ? { reason: fieldErrorText(t, d) } : d ? { name: fieldErrorText(t, d) } : { form: errorText(t, e) });
    } finally {
      setBusy(false);
    }
  };

  const include = async (row: NamespaceRow) => {
    setBusy(true);
    try {
      await admin.includeNamespace(row.name);
      notify('success', t('ns.included', { name: row.name }));
      setIncludeFor(null);
      actions.setSelectedItems([]);
      load();
    } catch (e) {
      notify('error', errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <ContentLayout header={<Header variant="h1" description={t('ns.description')}>{t('ns.title')}</Header>}>
      <SpaceBetween size="l">
        {error ? <ErrorAlert error={error} /> : null}
        <Alert type="info" header={t('ns.layersTitle')}>
          {t('ns.layersBody')}
          {data?.mode === 'list' && <Box variant="small">{t('ns.listMode')}</Box>}
        </Alert>
        <Table
          {...collectionProps}
          variant="container"
          items={items}
          loading={loading}
          loadingText={t('common.loading')}
          trackBy="name"
          selectionType="single"
          ariaLabels={{ selectionGroupLabel: t('ns.title'), itemSelectionLabel: (_, n) => n.name }}
          header={
            <Header
              variant="h2"
              counter={data ? `(${data.items.length})` : undefined}
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button iconName="refresh" ariaLabel={t('common.refresh')} onClick={load} />
                  <Button disabled={busy || sel?.status !== 'excluded_web'} onClick={() => sel && setIncludeFor(sel)}>
                    {t('ns.include')}
                  </Button>
                  <Button disabled={busy || (!!sel && sel.status !== 'available')} variant="primary" onClick={() => openExclude(sel?.status === 'available' ? sel.name : '')}>
                    {sel?.status === 'available' ? t('ns.exclude') : t('ns.excludeByName')}
                  </Button>
                </SpaceBetween>
              }
            >
              {t('ns.title')}
            </Header>
          }
          filter={
            <TextFilter
              {...filterProps}
              filteringPlaceholder={t('ns.filter')}
              filteringAriaLabel={t('ns.filter')}
              countText={filterProps.filteringText ? t('common.items', { n: filteredItemsCount ?? 0 }) : undefined}
            />
          }
          pagination={<Pagination {...paginationProps} ariaLabels={{ nextPageLabel: t('common.next'), previousPageLabel: t('common.previous') }} />}
          columnDefinitions={[
            {
              id: 'name',
              header: t('ns.col.name'),
              sortingField: 'name',
              cell: (n) => (
                <SpaceBetween direction="horizontal" size="xs">
                  <Box fontWeight="bold">{n.name}</Box>
                  {!n.exists && <Badge>{t('ns.notFound')}</Badge>}
                </SpaceBetween>
              ),
            },
            {
              id: 'status',
              header: t('ns.col.status'),
              sortingField: 'status',
              cell: (n) => <StatusIndicator type={statusType[n.status]}>{t(`ns.status.${n.status}`)}</StatusIndicator>,
            },
            { id: 'reason', header: t('ns.col.reason'), cell: (n) => n.reason || '—' },
            { id: 'by', header: t('ns.col.by'), cell: (n) => n.excludedBy || '—' },
            { id: 'at', header: t('ns.col.at'), cell: (n) => (n.excludedAt ? formatDate(n.excludedAt) : '—') },
          ]}
        />
      </SpaceBetween>

      <Modal
        visible={excludeOpen}
        onDismiss={() => setExcludeOpen(false)}
        header={t('ns.excludeTitle')}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setExcludeOpen(false)}>
                {t('common.cancel')}
              </Button>
              <Button variant="primary" loading={busy} onClick={() => void exclude()}>
                {t('ns.exclude')}
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box>{t('ns.excludeBody')}</Box>
          {formError.form && <Alert type="error">{formError.form}</Alert>}
          <FormField label={t('ns.name')} description={t('ns.nameDesc')} errorText={formError.name}>
            <Input value={name} onChange={({ detail }) => setName(detail.value)} ariaLabel={t('ns.name')} placeholder="payments" />
          </FormField>
          <FormField label={t('ns.reason')} errorText={formError.reason}>
            <Input value={reason} onChange={({ detail }) => setReason(detail.value)} ariaLabel={t('ns.reason')} placeholder={t('ns.reasonPlaceholder')} />
          </FormField>
        </SpaceBetween>
      </Modal>

      <Modal
        visible={includeFor !== null}
        onDismiss={() => setIncludeFor(null)}
        header={t('ns.includeTitle', { name: includeFor?.name ?? '' })}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setIncludeFor(null)}>
                {t('common.cancel')}
              </Button>
              <Button variant="primary" loading={busy} onClick={() => includeFor && void include(includeFor)}>
                {t('ns.include')}
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        {t('ns.includeBody')}
      </Modal>
    </ContentLayout>
  );
}
