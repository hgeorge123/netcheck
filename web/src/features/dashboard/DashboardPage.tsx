import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Link from '@cloudscape-design/components/link';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import { useEffect, useState } from 'react';
import { ErrorAlert } from '../../components/errors';
import { methodKey, RunStatusBadge } from '../../components/status';
import { useI18n } from '../../i18n';
import type { ListRunsParams } from '../../services/api';
import { METHODS, type Me, type RunSummary, type Stats } from '../../types/api';

interface Props {
  me: Me;
  stats: () => Promise<Stats>;
  list: (p: ListRunsParams) => Promise<{ items: RunSummary[] }>;
  onOpen: (id: string) => void;
  onCreate: () => void;
  onHistory: () => void;
}

function Counter({ label, value, href }: { label: string; value: number | string; href?: () => void }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      {href ? (
        <Link variant="awsui-value-large" onFollow={(e) => (e.preventDefault(), href())} href="#/runs">
          {value}
        </Link>
      ) : (
        <Box variant="awsui-value-large">{value}</Box>
      )}
    </div>
  );
}

export function DashboardPage({ me, stats, list, onOpen, onCreate, onHistory }: Props) {
  const { t, formatDate } = useI18n();
  const [st, setSt] = useState<Stats | null>(null);
  const [recent, setRecent] = useState<RunSummary[] | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let alive = true;
    Promise.all([stats(), list({ pageSize: 5 })])
      .then(([s, r]) => {
        if (!alive) return;
        setSt(s);
        setRecent(r.items);
      })
      .catch((e: unknown) => alive && setError(e));
    return () => {
      alive = false;
    };
  }, [stats, list]);

  const by = st?.byStatus ?? {};
  const methodRows = METHODS.map((m) => {
    const s = st?.byMethodStatus?.[m] ?? {};
    return { method: m, ok: s.succeeded ?? 0, ko: s.failed ?? 0, timeout: s.timed_out ?? 0 };
  }).filter((r) => r.ok + r.ko + r.timeout > 0);
  const runnable = me.namespaces.filter((n) => n.canRun);

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={t('dashboard.description')}
          actions={
            <Button variant="primary" onClick={onCreate}>
              {t('nav.newTest')}
            </Button>
          }
        >
          {t('dashboard.title')}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {error ? <ErrorAlert error={error} /> : null}
        <Container header={<Header variant="h2" description={t('dashboard.last24h')}>{t('dashboard.overview')}</Header>}>
          <ColumnLayout columns={4} variant="text-grid">
            <Counter label={t('dashboard.total')} value={st ? st.total : '—'} href={onHistory} />
            <Counter label={t('dashboard.succeeded')} value={st ? (by.succeeded ?? 0) : '—'} />
            <Counter label={t('dashboard.failed')} value={st ? (by.failed ?? 0) : '—'} />
            <Counter label={t('dashboard.infra')} value={st ? (by.infra_error ?? 0) : '—'} />
          </ColumnLayout>
        </Container>
        <ColumnLayout columns={2}>
          <Table
            variant="container"
            header={<Header variant="h2" description={t('dashboard.last24h')}>{t('dashboard.byMethod')}</Header>}
            loading={!st && !error}
            loadingText={t('common.loading')}
            items={methodRows}
            trackBy="method"
            columnDefinitions={[
              { id: 'method', header: t('dashboard.method'), cell: (r) => t(methodKey(r.method)) },
              { id: 'ok', header: t('dashboard.ok'), cell: (r) => r.ok },
              { id: 'ko', header: t('dashboard.ko'), cell: (r) => r.ko },
              { id: 'timeout', header: t('dashboard.timeout'), cell: (r) => r.timeout },
            ]}
            empty={<Box textAlign="center" color="text-body-secondary">{t('dashboard.noTests')}</Box>}
          />
          <Container header={<Header variant="h2">{t('dashboard.access')}</Header>}>
            <SpaceBetween size="s">
              <Counter label={t('dashboard.namespacesCount')} value={runnable.length} />
              <Box color="text-body-secondary">{runnable.map((n) => n.name).join(', ') || '—'}</Box>
            </SpaceBetween>
          </Container>
        </ColumnLayout>
        <Table
          variant="container"
          header={
            <Header variant="h2" actions={<Button onClick={onHistory}>{t('dashboard.viewAll')}</Button>}>
              {t('dashboard.recent')}
            </Header>
          }
          loading={!recent && !error}
          loadingText={t('common.loading')}
          items={recent ?? []}
          trackBy="id"
          columnDefinitions={[
            {
              id: 'created',
              header: t('history.col.created'),
              cell: (r) => (
                <Link href={`#/runs/${r.id}`} onFollow={(e) => (e.preventDefault(), onOpen(r.id))}>
                  {formatDate(r.createdAt)}
                </Link>
              ),
            },
            { id: 'namespace', header: t('history.col.namespace'), cell: (r) => r.namespace },
            { id: 'target', header: t('history.col.target'), cell: (r) => r.target },
            { id: 'status', header: t('history.col.status'), cell: (r) => <RunStatusBadge status={r.status} /> },
            { id: 'actor', header: t('history.col.actor'), cell: (r) => r.actor },
          ]}
          empty={<Box textAlign="center" color="text-body-secondary">{t('dashboard.noTests')}</Box>}
        />
      </SpaceBetween>
    </ContentLayout>
  );
}
