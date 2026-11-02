import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import CollectionPreferences, { type CollectionPreferencesProps } from '@cloudscape-design/components/collection-preferences';
import Header from '@cloudscape-design/components/header';
import Link from '@cloudscape-design/components/link';
import Pagination from '@cloudscape-design/components/pagination';
import Select, { type SelectProps } from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import { useEffect, useState } from 'react';
import { ErrorAlert } from '../../components/errors';
import { categoryLabel, RunStatusBadge } from '../../components/status';
import { useI18n } from '../../i18n';
import type { ListRunsParams } from '../../services/api';
import { RUN_STATUSES, type NamespaceGrant, type RunStatus, type RunSummary } from '../../types/api';

interface Props {
  namespaces: NamespaceGrant[];
  list: (p: ListRunsParams) => Promise<{ items: RunSummary[]; nextCursor: string }>;
  onOpen: (id: string) => void;
  onCreate?: () => void;
}

const PREFS_KEY = 'netcheck.history.prefs';
const defaultPrefs: CollectionPreferencesProps.Preferences = {
  pageSize: 20,
  contentDisplay: ['created', 'namespace', 'target', 'status', 'category', 'actor'].map((id) => ({ id, visible: true })),
};

function loadPrefs(): CollectionPreferencesProps.Preferences {
  try {
    const raw = window.localStorage.getItem(PREFS_KEY);
    return raw ? { ...defaultPrefs, ...(JSON.parse(raw) as CollectionPreferencesProps.Preferences) } : defaultPrefs;
  } catch {
    return defaultPrefs;
  }
}

export function HistoryPage({ namespaces, list, onOpen, onCreate }: Props) {
  const { t, formatDate } = useI18n();
  const [namespace, setNamespace] = useState('');
  const [status, setStatus] = useState('');
  const [prefs, setPrefs] = useState(loadPrefs);
  // cursors[i] is the cursor that loads page i (page 0 has none).
  const [cursors, setCursors] = useState<string[]>(['']);
  const [page, setPage] = useState(0);
  const [items, setItems] = useState<RunSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [reload, setReload] = useState(0);

  const nsOptions: SelectProps.Option[] = [{ value: '', label: t('history.allNamespaces') }, ...namespaces.map((n) => ({ value: n.name, label: n.name }))];
  const statusOptions: SelectProps.Option[] = [
    { value: '', label: t('history.allStatuses') },
    ...RUN_STATUSES.map((s) => ({ value: s, label: t(`runStatus.${s}`) })),
  ];
  const cursor = cursors[page] ?? '';
  const pageSize = prefs.pageSize ?? 20;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    list({ namespace: namespace || undefined, status: (status || undefined) as RunStatus | undefined, pageSize, cursor: cursor || undefined })
      .then((res) => {
        if (cancelled) return;
        setItems(res.items);
        setError(null);
        setCursors((cs) => {
          const next = cs.slice(0, page + 1);
          if (res.nextCursor) next.push(res.nextCursor);
          return next;
        });
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [list, namespace, status, page, cursor, pageSize, reload]);

  const resetTo = (fn: () => void) => {
    fn();
    setPage(0);
    setCursors(['']);
  };

  const savePrefs = (p: CollectionPreferencesProps.Preferences) => {
    resetTo(() => setPrefs(p));
    try {
      window.localStorage.setItem(PREFS_KEY, JSON.stringify(p));
    } catch {
      // Preferences are a convenience only.
    }
  };

  const columns = [
    {
      id: 'created',
      header: t('history.col.created'),
      cell: (r: RunSummary) => (
        <Link
          href={`#/runs/${r.id}`}
          onFollow={(e) => {
            e.preventDefault();
            onOpen(r.id);
          }}
        >
          {formatDate(r.createdAt)}
        </Link>
      ),
    },
    { id: 'namespace', header: t('history.col.namespace'), cell: (r: RunSummary) => r.namespace },
    { id: 'target', header: t('history.col.target'), cell: (r: RunSummary) => r.target },
    { id: 'status', header: t('history.col.status'), cell: (r: RunSummary) => <RunStatusBadge status={r.status} /> },
    { id: 'category', header: t('history.col.category'), cell: (r: RunSummary) => categoryLabel(t, r.failureCategory) },
    { id: 'actor', header: t('history.col.actor'), cell: (r: RunSummary) => r.actor },
  ];

  return (
    <SpaceBetween size="m">
      {error ? <ErrorAlert error={error} header={t('history.loadFailed')} /> : null}
      <Table
        variant="full-page"
        stickyHeader
        header={
          <Header
            variant="awsui-h1-sticky"
            counter={items.length > 0 ? `(${items.length}${cursors.length > page + 1 ? '+' : ''})` : undefined}
            description={t('history.description')}
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button iconName="refresh" ariaLabel={t('common.refresh')} onClick={() => setReload((n) => n + 1)} />
                {onCreate && (
                  <Button variant="primary" onClick={onCreate}>
                    {t('nav.newTest')}
                  </Button>
                )}
              </SpaceBetween>
            }
          >
            {t('history.title')}
          </Header>
        }
        items={items}
        loading={loading}
        loadingText={t('common.loading')}
        trackBy="id"
        columnDefinitions={columns}
        columnDisplay={prefs.contentDisplay}
        filter={
          <SpaceBetween direction="horizontal" size="xs">
            <Select
              selectedOption={nsOptions.find((o) => o.value === namespace) ?? null}
              options={nsOptions}
              onChange={({ detail }) => resetTo(() => setNamespace(detail.selectedOption.value ?? ''))}
              ariaLabel={t('history.filterNamespace')}
              filteringType={nsOptions.length > 8 ? 'auto' : 'none'}
            />
            <Select
              selectedOption={statusOptions.find((o) => o.value === status) ?? null}
              options={statusOptions}
              onChange={({ detail }) => resetTo(() => setStatus(detail.selectedOption.value ?? ''))}
              ariaLabel={t('history.filterStatus')}
            />
          </SpaceBetween>
        }
        pagination={
          <Pagination
            currentPageIndex={page + 1}
            pagesCount={cursors.length}
            openEnd={cursors.length > page + 1}
            onChange={({ detail }) => setPage(detail.currentPageIndex - 1)}
            ariaLabels={{ nextPageLabel: t('common.next'), previousPageLabel: t('common.previous'), pageLabel: (n) => t('common.page', { n }) }}
          />
        }
        preferences={
          <CollectionPreferences
            title={t('common.preferences')}
            confirmLabel={t('common.save')}
            cancelLabel={t('common.cancel')}
            preferences={prefs}
            onConfirm={({ detail }) => savePrefs(detail)}
            pageSizePreference={{
              title: t('common.pageSize'),
              options: [10, 20, 50, 100].map((n) => ({ value: n, label: t('common.items', { n }) })),
            }}
            contentDisplayPreference={{
              title: t('common.visibleColumns'),
              options: columns.map((c) => ({ id: c.id, label: c.header, alwaysVisible: c.id === 'created' })),
            }}
          />
        }
        empty={<Box textAlign="center">{t('history.empty')}</Box>}
      />
    </SpaceBetween>
  );
}
