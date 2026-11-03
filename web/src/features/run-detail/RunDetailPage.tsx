import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import CopyToClipboard from '@cloudscape-design/components/copy-to-clipboard';
import Header from '@cloudscape-design/components/header';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import Tabs from '@cloudscape-design/components/tabs';
import { useEffect, useState } from 'react';
import { ErrorAlert } from '../../components/errors';
import { FidelityAlert } from '../../components/FidelityAlert';
import { CheckStatusBadge, diagnosisText, isTerminal, methodKey, RunStatusBadge } from '../../components/status';
import { useI18n, type Translate } from '../../i18n';
import { ApiError } from '../../services/api';
import type { ExecutionView, HTTPResult, PingResult, RunDetail, TracerouteResult } from '../../types/api';
import { blockedChecks, firewallRequest, hasEgressPolicies, suggestNetworkPolicy } from './blockedHelp';
import { buildFirewallReport } from './firewallReport';
import { PathView } from './PathView';

interface Props {
  id: string;
  load: (id: string) => Promise<RunDetail>;
  onRunAgain?: (id: string) => void;
  pollMs?: number;
}

/** Quotes argv for display only; it is never executed. */
export function shellQuote(argv: string[]): string {
  return argv.map((a) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`)).join(' ');
}

const ms = (v?: number) => (v === undefined ? '—' : `${Math.round(v * 100) / 100} ms`);

function PingTable({ p, t }: { p: PingResult; t: Translate }) {
  return (
    <SpaceBetween size="s">
      <KeyValuePairs
        columns={2}
        items={[
          { label: t('run.checks'), value: t('run.ping.stats', { tx: p.transmitted, rx: p.received, loss: Math.round(p.lossPercent) }) },
          { label: t('run.ping.rtt'), value: p.received > 0 ? `${ms(p.minMs)} / ${ms(p.avgMs)} / ${ms(p.maxMs)}` : '—' },
        ]}
      />
      <Table
        variant="embedded"
        items={p.replies}
        trackBy="seq"
        columnDefinitions={[
          { id: 'seq', header: t('run.ping.seq'), cell: (r) => r.seq },
          {
            id: 'reply',
            header: t('run.ping.reply'),
            cell: (r) =>
              r.lost || r.error ? (
                <StatusIndicator type="warning">{r.error ? `${r.error}${r.errorFrom ? ` (${r.errorFrom})` : ''}` : t('run.ping.lost')}</StatusIndicator>
              ) : (
                <StatusIndicator type="success">{ms(r.rttMs)}</StatusIndicator>
              ),
          },
        ]}
      />
    </SpaceBetween>
  );
}

function TraceTable({ tr, t }: { tr: TracerouteResult; t: Translate }) {
  return (
    <SpaceBetween size="s">
      <StatusIndicator type={tr.reached ? 'success' : 'warning'}>{t(tr.reached ? 'run.trace.reached' : 'run.trace.notReached')}</StatusIndicator>
      <Table
        variant="embedded"
        items={tr.hops}
        trackBy="ttl"
        columnDefinitions={[
          { id: 'ttl', header: t('run.trace.hop'), cell: (h) => h.ttl },
          { id: 'address', header: t('run.trace.address'), cell: (h) => h.address || t('run.trace.silent') },
          { id: 'rtt', header: t('run.trace.rtt'), cell: (h) => (h.address ? ms(h.rttMs) : '—') },
          { id: 'note', header: t('common.info'), cell: (h) => h.note || '' },
        ]}
      />
    </SpaceBetween>
  );
}

/** Every certificate problem the probe found, whether the request stopped or they were ignored. */
function CertificateAlert({ http, t }: { http: HTTPResult; t: Translate }) {
  return (
    <Alert type={http.tlsIgnored ? 'warning' : 'error'} header={t(http.tlsIgnored ? 'run.tlsIgnoredTitle' : 'run.tlsFailedTitle')}>
      <ul style={{ margin: 0 }}>
        {(http.tlsProblems ?? []).map((p) => (
          <li key={p}>{t(`run.tlsProblem.${p}`)}</li>
        ))}
      </ul>
      {http.tlsProblemDetail && <Box variant="small">{http.tlsProblemDetail}</Box>}
      <Box variant="p">{t(http.tlsIgnored ? 'run.tlsIgnoredBody' : 'run.tlsFailedBody')}</Box>
    </Alert>
  );
}

function CheckDetail({ c, actor }: { c: ExecutionView; actor: string }) {
  const { t, formatDate } = useI18n();
  const r = c.result;
  const cmd = c.equivalentArgv.length > 0 ? shellQuote(c.equivalentArgv) : '';
  const dx = c.diagnosis ? diagnosisText(t, c.method, c.diagnosis) : undefined;
  const pairs = [
    { label: t('run.resolvedIps'), value: c.resolvedIps.length > 0 ? c.resolvedIps.join(', ') : '—' },
    { label: t('run.usedIp'), value: c.usedIp || '—' },
    { label: t('run.col.port'), value: r?.port ? String(r.port) : '—' },
    { label: t('run.deniedIps'), value: r?.deniedIps?.length ? r.deniedIps.join(', ') : '—' },
  ];
  if (r?.proxy) {
    const p = r.proxy;
    // Only the author of the test receives the details of a personal proxy.
    const name = p.name
      ? t('run.proxyValue', { name: p.name, address: p.address ?? '—', ip: p.usedIp ?? '—' })
      : t('run.proxyPersonalOf', { user: actor });
    pairs.push({ label: p.personal ? t('run.proxyPersonal') : t('run.proxy'), value: name });
    let reply: string;
    if (p.statusText) reply = p.mode === 'forward' ? t('run.proxyAnsweredItself', { status: p.statusText }) : `CONNECT → ${p.statusText}`;
    else if (p.mode === 'forward') reply = t(p.reached ? 'run.proxyForwarded' : 'run.proxyNotReached');
    else reply = t(p.reached ? 'run.proxyNoReply' : 'run.proxyNotReached');
    pairs.push({ label: t('run.proxyReply'), value: reply });
    if (p.via) pairs.push({ label: 'Via', value: p.via });
  }
  if (r?.dns?.cname) pairs.push({ label: t('run.cname'), value: r.dns.cname });
  if (r?.http?.statusCode !== undefined) pairs.push({ label: t('run.httpStatus'), value: `${r.http.statusCode} (${r.http.proto ?? ''})` });
  if (r?.http?.location) pairs.push({ label: t('run.location'), value: r.http.location });
  if (r?.http?.tlsVersion) {
    pairs.push({ label: t('run.tls'), value: t('run.tlsValue', { version: r.http.tlsVersion, cn: r.http.tlsPeerCn ?? '—', date: formatDate(r.http.tlsNotAfter) }) });
  }
  if (r?.http?.tlsNames?.length) pairs.push({ label: t('run.tlsNames'), value: r.http.tlsNames.join(', ') });
  if (r?.http?.tlsIssuer) pairs.push({ label: t('run.tlsIssuer'), value: r.http.tlsIssuer });
  if (r?.http?.tlsTrustedCa) pairs.push({ label: t('run.tlsTrustedCa'), value: t('run.tlsTrustedCaValue', { name: r.http.tlsTrustedCa }) });
  if (r?.udp) {
    const u = r.udp;
    pairs.push({ label: t('run.udp.protocol'), value: t(`newTest.udp.${u.protocol}`) });
    pairs.push({ label: t('run.udp.attempts'), value: String(u.attempts) });
    if (u.replyBytes) pairs.push({ label: t('run.udp.reply'), value: t('run.udp.replyValue', { bytes: u.replyBytes, ms: Math.round((u.rttMs ?? 0) * 100) / 100 }) });
    if (u.dnsRcode) pairs.push({ label: t('run.udp.dns'), value: t('run.udp.dnsValue', { rcode: u.dnsRcode, answers: u.dnsAnswers ?? 0 }) });
    if (u.ntpStratum !== undefined) {
      pairs.push({ label: t('run.udp.ntp'), value: t('run.udp.ntpValue', { stratum: u.ntpStratum, ref: u.ntpReference || '—', offset: u.ntpOffsetMs ?? 0 }) });
    }
  }
  if (r?.http?.connectMs !== undefined) {
    pairs.push({ label: t('run.timings'), value: `${r.http.connectMs} / ${r.http.tlsMs ?? 0} / ${r.http.firstByteMs ?? 0} ms` });
  }

  return (
    <Container header={<Header variant="h2">{t('run.detailOf', { method: t(methodKey(c.method)) })}</Header>}>
      <Tabs
        tabs={[
          {
            id: 'summary',
            label: t('run.tab.summary'),
            content: (
              <SpaceBetween size="m">
                {c.diagnosis && dx && (
                  <Alert type={c.diagnosis.severity} header={dx.summary}>
                    {dx.detail}
                    {!c.diagnosis.conclusive && c.status !== 'succeeded' && ` ${t('run.notConclusive')}`}
                  </Alert>
                )}
                {r?.http?.tlsProblems?.length ? <CertificateAlert http={r.http} t={t} /> : null}
                {r?.ping && <PingTable p={r.ping} t={t} />}
                {r?.traceroute && <TraceTable tr={r.traceroute} t={t} />}
                {c.method !== 'ping' && c.method !== 'traceroute' && <KeyValuePairs columns={4} items={pairs} />}
                {(c.method === 'ping' || c.method === 'traceroute') && <KeyValuePairs columns={4} items={pairs.slice(0, 2)} />}
              </SpaceBetween>
            ),
          },
          {
            id: 'output',
            label: t('run.tab.output'),
            content: (
              <SpaceBetween size="s">
                {c.error && (
                  <Alert type="info" header={t('run.errorReturned')}>
                    {c.error}
                  </Alert>
                )}
                <Box variant="code">
                  <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{c.output || t('run.noOutput')}</pre>
                </Box>
              </SpaceBetween>
            ),
          },
          {
            id: 'command',
            label: t('run.tab.command'),
            content: cmd ? (
              <SpaceBetween size="s">
                <Box variant="small">{t('run.commandNote')}</Box>
                <Box variant="code">{cmd}</Box>
                <CopyToClipboard textToCopy={cmd} copyButtonText={t('common.copy')} copySuccessText={t('common.copied')} copyErrorText={t('common.copyFailed')} />
              </SpaceBetween>
            ) : (
              <Box>{t('run.notAvailable')}</Box>
            ),
          },
          {
            id: 'json',
            label: t('run.tab.json'),
            content: (
              <Box variant="code">
                <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{JSON.stringify(c, null, 2)}</pre>
              </Box>
            ),
          },
        ]}
      />
    </Container>
  );
}

/** Single output for firewall tickets, with copy and download. */
function FirewallReportPanel({ run }: { run: RunDetail }) {
  const { t, formatDate } = useI18n();
  const report = buildFirewallReport(run, t, formatDate);
  const download = () => {
    const url = URL.createObjectURL(new Blob([report], { type: 'text/plain;charset=utf-8' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `netcheck-firewall-${run.target.replace(/[^\w.-]/g, '_')}-${run.id.slice(0, 8)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <Container
      header={
        <Header
          variant="h2"
          description={t('fw.panelDesc')}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <CopyToClipboard
                variant="button"
                textToCopy={report}
                copyButtonText={t('fw.copy')}
                copySuccessText={t('common.copied')}
                copyErrorText={t('common.copyFailed')}
              />
              <Button iconName="download" onClick={download}>
                {t('fw.download')}
              </Button>
            </SpaceBetween>
          }
        >
          {t('fw.panelTitle')}
        </Header>
      }
    >
      <Box variant="code">
        <pre data-testid="firewall-report" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>
          {report}
        </pre>
      </Box>
    </Container>
  );
}

/**
 * What is missing for the traffic to flow, stated in every case: nothing,
 * a NetworkPolicy (when the namespace policies select the probe) or a change
 * outside the cluster, with a request for the firewall team.
 */
function MissingPanel({ run }: { run: RunDetail }) {
  const { t, formatDate } = useI18n();
  const header = <Header variant="h2" description={t('missing.desc')}>{t('missing.title')}</Header>;
  if (blockedChecks(run).length === 0) {
    return (
      <Container header={header}>
        <Alert type="success" header={t('missing.nothingTitle')}>
          {t('missing.nothing')}
        </Alert>
      </Container>
    );
  }
  const policies = hasEgressPolicies(run);
  const request = firewallRequest(run, t, formatDate);
  const block = (text: string, copy: string, testId: string) => (
    <SpaceBetween size="s">
      <Box variant="code">
        <pre data-testid={testId} style={{ whiteSpace: 'pre-wrap', margin: 0 }}>
          {text}
        </pre>
      </Box>
      <CopyToClipboard variant="button" textToCopy={text} copyButtonText={copy} copySuccessText={t('common.copied')} copyErrorText={t('common.copyFailed')} />
    </SpaceBetween>
  );
  const requestTab = {
    id: 'request',
    label: t('missing.tab.request'),
    content: (
      <SpaceBetween size="s">
        {!policies && (
          <Alert type="info" header={t('missing.policyNotNeeded')}>
            {t('missing.noPolicyIntro', { namespace: run.namespace })}
          </Alert>
        )}
        {block(request, t('missing.copyRequest'), 'missing-request')}
      </SpaceBetween>
    ),
  };
  const tabs = policies
    ? [
        {
          id: 'policy',
          label: t('missing.tab.policy'),
          content: (
            <SpaceBetween size="s">
              <Alert type="warning" header={t('missing.policyNeeded')}>
                {t('missing.policyIntro', { namespace: run.namespace })}
              </Alert>
              {block(suggestNetworkPolicy(run), t('missing.copyPolicy'), 'missing-policy')}
            </SpaceBetween>
          ),
        },
        requestTab,
      ]
    : [requestTab];
  return (
    <Container header={header}>
      <Tabs tabs={tabs} />
    </Container>
  );
}

export function RunDetailPage({ id, load, onRunAgain, pollMs = 2000 }: Props) {
  const { t, formatDate } = useI18n();
  const [run, setRun] = useState<RunDetail | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [selectedId, setSelectedId] = useState<string | undefined>();

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        const r = await load(id);
        if (cancelled) return;
        setRun(r);
        setError(null);
        if (!isTerminal(r.status)) timer = setTimeout(() => void tick(), pollMs);
      } catch (err) {
        if (cancelled) return;
        const e = err instanceof ApiError ? err : new ApiError(0, 'unknown', String(err));
        setError(e);
        // Retry transient failures; stop on missing run or expired session.
        if (e.status !== 404 && e.status !== 401) timer = setTimeout(() => void tick(), pollMs * 2);
      }
    };
    void tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [id, load, pollMs]);

  if (!run) {
    return error ? (
      <ErrorAlert error={error} header={error.status === 404 ? t('run.notFound') : t('run.loadFailed')} />
    ) : (
      <Box textAlign="center" padding="xxl">
        <Spinner size="large" /> {t('common.loading')}
      </Box>
    );
  }

  const first = run.checks.find((c) => c.podIp || c.nodeName);
  const done = isTerminal(run.status);
  const detailed = run.checks.filter((c) => c.diagnosis || c.output);
  const selected = detailed.find((c) => c.checkId === selectedId) ?? detailed[0];

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={t('run.subtitle', { target: run.target, namespace: run.namespace })}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <CopyToClipboard
                variant="button"
                textToCopy={JSON.stringify(run, null, 2)}
                copyButtonText={t('run.copyJson')}
                copySuccessText={t('common.copied')}
                copyErrorText={t('common.copyFailed')}
              />
              {onRunAgain && (
                <Button iconName="refresh" disabled={!done} onClick={() => onRunAgain(run.id)}>
                  {t('run.again')}
                </Button>
              )}
            </SpaceBetween>
          }
        >
          {t('run.title', { id: run.id.slice(0, 8) })}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {error && <ErrorAlert error={error} header={t('run.updateInterrupted')} />}
        <Container header={<Header variant="h2">{t('run.details')}</Header>}>
          <KeyValuePairs
            columns={4}
            items={[
              { label: t('run.status'), value: <RunStatusBadge status={run.status} /> },
              { label: t('run.namespace'), value: run.namespace },
              { label: t('run.target'), value: run.target },
              { label: t('run.actor'), value: run.actor },
              { label: t('run.created'), value: formatDate(run.createdAt) },
              { label: t('run.finished'), value: formatDate(run.finishedAt) },
              { label: t('run.podIp'), value: first?.podIp || '—' },
              { label: t('run.node'), value: first?.nodeName || '—' },
              { label: t('run.job'), value: run.jobName || '—' },
              { label: t('run.cluster'), value: run.clusterId },
              { label: t('run.id'), value: <CopyToClipboard variant="inline" textToCopy={run.id} copySuccessText={t('common.copied')} copyErrorText={t('common.copyFailed')} /> },
            ]}
          />
        </Container>

        {done && run.request.mode === 'firewall' && run.checks.length > 0 && <FirewallReportPanel run={run} />}

        {run.status === 'infra_error' && (
          <Alert type="warning" header={t('run.infraTitle')}>
            {run.errorMessage || t('run.infraBody')}
          </Alert>
        )}

        <FidelityAlert fidelity={run.fidelity} />

        {done && run.status !== 'infra_error' && first && <PathView run={run} />}

        <Table
          header={<Header variant="h2" counter={`(${run.checks.length})`}>{t('run.checks')}</Header>}
          items={run.checks}
          trackBy="checkId"
          variant="container"
          selectionType={done && detailed.length > 1 ? 'single' : undefined}
          selectedItems={selected ? [selected] : []}
          onSelectionChange={({ detail }) => setSelectedId(detail.selectedItems[0]?.checkId)}
          isItemDisabled={(c) => !detailed.includes(c)}
          ariaLabels={{ itemSelectionLabel: (_, c) => t(methodKey(c.method)), selectionGroupLabel: t('run.checks') }}
          loading={!done}
          loadingText={t('run.running')}
          columnDefinitions={[
            { id: 'method', header: t('run.col.method'), cell: (c) => t(methodKey(c.method)) },
            { id: 'status', header: t('run.col.status'), cell: (c) => <CheckStatusBadge status={c.status} diagnosis={c.diagnosis} /> },
            { id: 'diagnosis', header: t('run.col.diagnosis'), cell: (c) => (c.diagnosis ? diagnosisText(t, c.method, c.diagnosis).summary : '—') },
            { id: 'ip', header: t('run.col.ip'), cell: (c) => c.usedIp || '—' },
            { id: 'port', header: t('run.col.port'), cell: (c) => (c.result?.port ? String(c.result.port) : '—') },
            { id: 'duration', header: t('run.col.duration'), cell: (c) => (c.durationMs !== undefined ? t('common.ms', { n: c.durationMs }) : '—') },
          ]}
        />

        {done && selected && <CheckDetail key={selected.checkId} c={selected} actor={run.actor} />}

        {done && run.status !== 'infra_error' && run.checks.length > 0 && <MissingPanel run={run} />}
      </SpaceBetween>
    </ContentLayout>
  );
}
