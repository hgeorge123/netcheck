import { useCollection } from '@cloudscape-design/collection-hooks';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Pagination from '@cloudscape-design/components/pagination';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import { useCallback, useEffect, useState } from 'react';
import { ErrorAlert, errorText } from '../../components/errors';
import { useI18n } from '../../i18n';
import type { Api } from '../../services/api';
import type { SessionsResponse, SessionView } from '../../types/api';

interface Props {
  admin: Api['admin'];
  notify: (type: 'success' | 'error', message: string) => void;
}

/** Short, human readable browser name; the full User-Agent is in the tooltip. */
export function browserName(ua: string): string {
  // Most specific first: Edge and Opera also announce Chrome and Safari.
  const browsers: [RegExp, string][] = [
    [/Edg\/(\d+)/, 'Edge'],
    [/OPR\/(\d+)/, 'Opera'],
    [/Firefox\/(\d+)/, 'Firefox'],
    [/Chrome\/(\d+)/, 'Chrome'],
    [/Version\/(\d+).*Safari/, 'Safari'],
  ];
  for (const [re, browser] of browsers) {
    const m = re.exec(ua);
    if (!m) continue;
    const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /Linux/.test(ua) ? 'Linux' : '';
    return `${browser} ${m[1]}${os ? ` · ${os}` : ''}`;
  }
  return ua ? ua.slice(0, 40) : '—';
}

function Counter({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <Box variant="awsui-value-large">{value}</Box>
    </div>
  );
}

export function SessionsPage({ admin, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [data, setData] = useState<SessionsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    admin
      .sessions()
      .then((r) => {
        setData(r);
        setError(null);
      })
      .catch((e: unknown) => setError(e))
      .finally(() => setLoading(false));
  }, [admin]);
  useEffect(load, [load]);

  const { items, collectionProps, paginationProps, actions } = useCollection(data?.items ?? [], {
    pagination: { pageSize: 20 },
    sorting: { defaultState: { sortingColumn: { sortingField: 'lastSeenAt' }, isDescending: true } },
    selection: { trackBy: 'id' },
  });
  const sel = collectionProps.selectedItems?.[0];

  const revoke = async (s: SessionView) => {
    setBusy(true);
    try {
      await admin.revokeSession(s.id);
      notify('success', t('sessions.revoked', { name: s.username }));
      actions.setSelectedItems([]);
      load();
    } catch (e) {
      notify('error', errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <ContentLayout
      header={
        <Header variant="h1" description={t('sessions.description')}>
          {t('sessions.title')}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {error ? <ErrorAlert error={error} /> : null}
        <Container header={<Header variant="h2">{t('dashboard.overview')}</Header>}>
          <ColumnLayout columns={3} variant="text-grid">
            <Counter label={t('sessions.connectedUsers')} value={data ? data.connectedUsers : '—'} />
            <Counter label={t('sessions.activeSessions')} value={data ? data.items.length : '—'} />
            <Counter label={t('sessions.idleTimeout')} value={data ? t('sessions.minutes', { n: data.idleTimeoutMinutes }) : '—'} />
          </ColumnLayout>
        </Container>
        <Table
          {...collectionProps}
          variant="container"
          items={items}
          loading={loading}
          loadingText={t('common.loading')}
          trackBy="id"
          selectionType="single"
          isItemDisabled={(s) => s.current}
          ariaLabels={{ selectionGroupLabel: t('sessions.title'), itemSelectionLabel: (_, s) => s.username }}
          header={
            <Header
              variant="h2"
              counter={data ? `(${data.items.length})` : undefined}
              description={t('sessions.note')}
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button iconName="refresh" ariaLabel={t('common.refresh')} onClick={load} />
                  <Button disabled={!sel || sel.current} loading={busy} onClick={() => sel && void revoke(sel)}>
                    {t('sessions.revoke')}
                  </Button>
                </SpaceBetween>
              }
            >
              {t('sessions.activeSessions')}
            </Header>
          }
          pagination={<Pagination {...paginationProps} ariaLabels={{ nextPageLabel: t('common.next'), previousPageLabel: t('common.previous') }} />}
          columnDefinitions={[
            {
              id: 'user',
              header: t('sessions.col.user'),
              sortingField: 'username',
              cell: (s) => (
                <SpaceBetween direction="horizontal" size="xs">
                  <Box fontWeight="bold">{s.username}</Box>
                  {s.current && <Badge color="green">{t('sessions.current')}</Badge>}
                </SpaceBetween>
              ),
            },
            { id: 'role', header: t('sessions.col.role'), cell: (s) => t(s.role === 'admin' ? 'nav.role.admin' : 'nav.role.user') },
            { id: 'signedIn', header: t('sessions.col.signedIn'), sortingField: 'signedInAt', cell: (s) => formatDate(s.signedInAt) },
            { id: 'lastSeen', header: t('sessions.col.lastSeen'), sortingField: 'lastSeenAt', cell: (s) => formatDate(s.lastSeenAt) },
            { id: 'ip', header: t('sessions.col.ip'), cell: (s) => s.clientIp || '—' },
            { id: 'browser', header: t('sessions.col.browser'), cell: (s) => <span title={s.userAgent}>{browserName(s.userAgent)}</span> },
          ]}
          empty={<Box textAlign="center">{t('sessions.empty')}</Box>}
        />
      </SpaceBetween>
    </ContentLayout>
  );
}
