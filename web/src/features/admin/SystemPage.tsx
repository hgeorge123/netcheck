import Alert from '@cloudscape-design/components/alert';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import { useEffect, useState } from 'react';
import { ErrorAlert } from '../../components/errors';
import { useI18n } from '../../i18n';
import type { Api } from '../../services/api';
import type { SystemInfo, VersionView } from '../../types/api';

interface Props {
  admin: Api['admin'];
  /** Opens Administration > Destination policy. */
  onEditPolicy?: () => void;
  onEditRetention?: () => void;
}

const mono = (s: string) => (s ? <Box variant="code">{s}</Box> : '—');
/** "repo@sha256:abcdef0123…" → "sha256:abcdef012345" (full reference in the tooltip). */
export const shortDigest = (image: string): string => {
  const m = /@(sha256:[0-9a-f]{12})/.exec(image);
  return m?.[1] ?? (image || '—');
};
const sameBuild =(a: VersionView, b: VersionView) => a.version === b.version && a.commit === b.commit && a.image === b.image;

export function SystemPage({ admin, onEditPolicy, onEditRetention }: Props) {
  const { t, formatDate } = useI18n();
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let alive = true;
    admin
      .system()
      .then((r) => alive && setInfo(r))
      .catch((e: unknown) => alive && setError(e));
    return () => {
      alive = false;
    };
  }, [admin]);

  if (error) return <ErrorAlert error={error} />;
  if (!info) {
    return (
      <Box textAlign="center" padding="xxl">
        <Spinner size="large" />
      </Box>
    );
  }
  const c = info.current;
  const d = info.destinations;

  return (
    <ContentLayout header={<Header variant="h1" description={t('system.description')}>{t('system.title')}</Header>}>
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">{t('system.running')}</Header>}>
          <KeyValuePairs
            columns={3}
            items={[
              { label: t('system.version'), value: <Badge color="blue">{c.version || '—'}</Badge> },
              { label: t('system.commit'), value: mono(c.commit) },
              { label: t('system.buildDate'), value: c.buildDate || '—' },
              { label: t('system.chart'), value: c.chartVersion || '—' },
              { label: t('system.image'), value: mono(c.image) },
              { label: t('system.probeImage'), value: mono(c.probeImage) },
            ]}
          />
        </Container>

        <Table
          variant="container"
          header={<Header variant="h2" counter={`(${info.history.length})`}>{t('system.history')}</Header>}
          items={info.history}
          trackBy={(v) => `${v.version}|${v.commit}|${v.image}|${v.chartVersion}`}
          wrapLines
          columnDefinitions={[
            {
              id: 'version',
              header: t('system.version'),
              cell: (v) => (
                <SpaceBetween direction="horizontal" size="xs">
                  <span>{v.version || '—'}</span>
                  {sameBuild(v, c) && <Badge color="green">{t('system.running')}</Badge>}
                </SpaceBetween>
              ),
            },
            { id: 'chart', header: t('system.chart'), cell: (v) => v.chartVersion || '—' },
            { id: 'commit', header: t('system.commit'), cell: (v) => v.commit || '—' },
            { id: 'image', header: t('system.image'), cell: (v) => <span title={v.image}>{shortDigest(v.image)}</span> },
            { id: 'first', header: t('system.firstSeen'), cell: (v) => formatDate(v.firstSeenAt) },
            { id: 'last', header: t('system.started'), cell: (v) => formatDate(v.lastStartedAt) },
            { id: 'starts', header: t('system.starts'), cell: (v) => v.starts },
          ]}
        />

        <Container header={<Header variant="h2" description={t('system.settingsDesc')}>{t('system.settings')}</Header>}>
          <KeyValuePairs
            columns={3}
            items={[
              { label: t('system.cluster'), value: info.clusterId },
              { label: t('system.scope'), value: t(info.namespaceScope === 'all' ? 'system.scope.all' : 'system.scope.list') },
              { label: t('system.ownNs'), value: info.netcheckNamespace || '—' },
              { label: t('system.maxChecks'), value: String(info.limits.maxChecks) },
              { label: t('system.maxJob'), value: t('common.seconds', { n: info.limits.maxJobSeconds }) },
              { label: t('system.settle'), value: t('common.seconds', { n: info.limits.settleSeconds }) },
            ]}
          />
        </Container>

        <Container
          header={
            <Header
              variant="h2"
              description={t(info.destinationsManagedBy === 'helm' ? 'system.destinationsHelm' : 'system.destinationsUi')}
              actions={
                onEditPolicy && (
                  <Button onClick={onEditPolicy}>{t(info.destinationsManagedBy === 'helm' ? 'system.viewPolicy' : 'system.editPolicy')}</Button>
                )
              }
            >
              {t('nav.policy')}
            </Header>
          }
        >
          <KeyValuePairs
            columns={3}
            items={[
              { label: t('system.allowCidrs'), value: d.allowCidrs?.join(', ') || '—' },
              { label: t('system.allowPorts'), value: d.allowPorts?.map((p) => (p.from === p.to ? `${p.from}` : `${p.from}-${p.to}`)).join(', ') || '—' },
              { label: t('system.allowSuffixes'), value: d.allowHostnameSuffixes?.join(', ') || '—' },
              {
                label: t('system.protections'),
                value: (
                  <StatusIndicator type={info.protectPlatformDestinations ? 'success' : 'warning'}>
                    {t(info.protectPlatformDestinations ? 'system.protections.on' : 'system.protections.off')}
                  </StatusIndicator>
                ),
              },
            ]}
          />
        </Container>

        {info.retention && (
          <Container
            header={
              <Header
                variant="h2"
                description={t('system.retentionDesc')}
                actions={onEditRetention && <Button onClick={onEditRetention}>{t('system.editRetention')}</Button>}
              >
                {t('nav.retention')}
              </Header>
            }
          >
            <KeyValuePairs
              columns={3}
              items={[
                { label: t('retention.output'), value: t('retention.nDays', { n: info.retention.outputDays }) },
                { label: t('retention.metadata'), value: t('retention.nDays', { n: info.retention.metadataDays }) },
              ]}
            />
          </Container>
        )}

        <Alert type="info">{t('system.upgradeNote')}</Alert>
      </SpaceBetween>
    </ContentLayout>
  );
}
