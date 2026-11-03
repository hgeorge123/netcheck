import Box from '@cloudscape-design/components/box';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Steps, { type StepsProps } from '@cloudscape-design/components/steps';
import { methodKey } from '../../components/status';
import { useI18n, type Translate } from '../../i18n';
import type { ExecutionView, RunDetail } from '../../types/api';
import { isBlocked } from './blockedHelp';

// The measured path of a test: probe Pod and node (from the Kubernetes API),
// the traceroute hops when a traceroute ran, and the destination with the
// result of every check. What was not measured is shown as such.

type Step = StepsProps.Step;

type Status = StepsProps.Status;

/** Result of one check at the destination: no answer is "stopped", an answer with an error is "error". */
function checkStatus(c: ExecutionView): Status {
  if (c.status === 'succeeded') return c.diagnosis?.severity === 'warning' ? 'warning' : 'success';
  if (c.status === 'queued' || c.status === 'running') return 'in-progress';
  return isBlocked(c) ? 'stopped' : 'error';
}

function checkLabel(t: Translate, c: ExecutionView): string {
  const port = c.result?.port ? ` ${c.result.port}` : '';
  return `${t(methodKey(c.method))}${port}`;
}

/** Collapses runs of silent hops so long paths stay readable. */
export function pathSteps(run: RunDetail, t: Translate): Step[] {
  const src = run.checks.find((c) => c.podIp || c.nodeName);
  const steps: Step[] = [
    { status: 'info', header: t('path.pod'), details: [run.namespace, src?.podIp].filter(Boolean).join(' · ') },
    { status: 'info', header: t('path.node'), details: [src?.nodeName, src?.nodeIp].filter(Boolean).join(' · ') || '—' },
  ];

  const trace = run.checks.find((c) => c.method === 'traceroute' && c.result?.traceroute)?.result?.traceroute;
  if (!trace) {
    steps.push({ status: 'pending', header: t('path.notMeasured'), details: t('path.addTraceroute') });
  } else {
    let silent = 0;
    const flush = () => {
      if (silent > 0) steps.push({ status: 'pending', header: t('path.silentHops', { n: silent }), details: t('path.silentDetail') });
      silent = 0;
    };
    const hops = trace.hops.filter((_, i) => !(trace.reached && i === trace.hops.length - 1)); // the last hop is the destination
    for (const h of hops) {
      if (!h.address) {
        silent++;
        continue;
      }
      flush();
      steps.push({ status: 'success', header: t('path.hop', { ttl: h.ttl, address: h.address }), details: h.rttMs !== undefined ? t('common.ms', { n: Math.round(h.rttMs * 100) / 100 }) : h.note });
    }
    flush();
    if (!trace.reached) steps.push({ status: 'stopped', header: t('path.noAnswerBeyond'), details: t('path.icmpNote') });
  }

  const checks = run.checks.filter((c) => c.method !== 'traceroute' || !trace);
  const statuses = checks.map(checkStatus);
  const dest: Status = statuses.every((s) => s === 'success')
    ? 'success'
    : statuses.some((s) => s === 'in-progress')
      ? 'in-progress'
      : statuses.some((s) => s === 'success' || s === 'warning')
        ? 'warning'
        : 'error';
  const ip = src?.usedIp || checks.find((c) => c.usedIp)?.usedIp;
  steps.push({
    status: dest,
    header: `${t('path.destination')}: ${run.target}${ip && ip !== run.target ? ` (${ip})` : ''}`,
    details: (
      <SpaceBetween size="xxxs">
        {checks.map((c) => (
          <StatusIndicator key={c.checkId} type={checkStatus(c)}>
            {checkLabel(t, c)}
          </StatusIndicator>
        ))}
      </SpaceBetween>
    ),
  });
  return steps;
}

export function PathView({ run }: { run: RunDetail }) {
  const { t } = useI18n();
  const steps = pathSteps(run, t);
  return (
    <Container header={<Header variant="h2" description={t('path.desc')}>{t('path.title')}</Header>}>
      <SpaceBetween size="s">
        <Steps steps={steps} orientation={steps.length <= 6 ? 'horizontal' : 'vertical'} ariaLabel={t('path.title')} />
        {run.checks.some((c) => c.method === 'traceroute') && <Box variant="small">{t('path.icmpPathNote')}</Box>}
      </SpaceBetween>
    </Container>
  );
}
