import { describe, expect, it } from 'vitest';
import { en } from '../../i18n/en';
import type { ExecutionView, RunDetail } from '../../types/api';
import { pathSteps } from './PathView';

const t = (key: keyof typeof en, params?: Record<string, string | number>) =>
  en[key].replace(/\{(\w+)\}/g, (_, k: string) => String(params?.[k] ?? ''));

const check = (over: Partial<ExecutionView>): ExecutionView => ({
  checkId: over.method ?? 'x',
  method: 'tcp',
  status: 'succeeded',
  category: 'ok',
  output: '',
  equivalentArgv: [],
  resolvedIps: [],
  podIp: '10.1.4.23',
  nodeName: 'node-a',
  nodeIp: '10.1.2.10',
  usedIp: '10.30.5.8',
  ...over,
});

const run = (checks: ExecutionView[]): RunDetail => ({
  id: 'abcdef0123456789',
  createdAt: '2026-11-03T10:00:00Z',
  actor: 'Dev',
  actorId: 'dev',
  namespace: 'payments',
  target: 'db.corp.example',
  status: 'failed',
  clusterId: 'prod',
  request: { namespace: 'payments', target: 'db.corp.example', checks: [] },
  checks,
});

const headers = (r: RunDetail) => pathSteps(r, t).map((s) => s.header);

describe('pathSteps', () => {
  it('marks the path as not measured without a traceroute', () => {
    const steps = pathSteps(run([check({ result: { port: 5432 } })]), t);
    expect(steps.map((s) => s.header)).toEqual(['Probe Pod', 'Node', 'Path not measured', 'Destination: db.corp.example (10.30.5.8)']);
    expect(steps[0]?.details).toBe('payments · 10.1.4.23');
    expect(steps[1]?.details).toBe('node-a · 10.1.2.10');
    expect(steps[3]?.status).toBe('success');
  });

  it('shows the hops, collapses silent ones and stops where ICMP stops', () => {
    const trace = check({
      method: 'traceroute',
      status: 'failed',
      category: 'traceroute_incomplete',
      result: {
        traceroute: { protocol: 'icmp', maxHops: 6, reached: false, hops: [{ ttl: 1, address: '10.1.0.1', rttMs: 0.4 }, { ttl: 2 }, { ttl: 3 }, { ttl: 4, address: '10.20.0.1', rttMs: 3.2 }, { ttl: 5 }] },
      },
    });
    const tcp = check({ method: 'tcp', status: 'timed_out', category: 'timeout', result: { port: 443 } });
    expect(headers(run([trace, tcp]))).toEqual([
      'Probe Pod',
      'Node',
      'Hop 1: 10.1.0.1',
      '2 silent hop(s)',
      'Hop 4: 10.20.0.1',
      '1 silent hop(s)',
      'No answer beyond this point',
      'Destination: db.corp.example (10.30.5.8)',
    ]);
    const dest = pathSteps(run([trace, tcp]), t).at(-1);
    expect(dest?.status).toBe('error'); // TCP got no answer
  });

  it('does not repeat the destination when the traceroute reached it', () => {
    const trace = check({
      method: 'traceroute',
      result: { traceroute: { protocol: 'icmp', maxHops: 4, reached: true, hops: [{ ttl: 1, address: '10.1.0.1', rttMs: 0.4 }, { ttl: 2, address: '10.30.5.8', rttMs: 1 }] } },
    });
    expect(headers(run([trace, check({ result: { port: 5432 } })]))).toEqual(['Probe Pod', 'Node', 'Hop 1: 10.1.0.1', 'Destination: db.corp.example (10.30.5.8)']);
  });

  it('flags a destination with mixed results as a warning', () => {
    const steps = pathSteps(run([check({ result: { port: 443 } }), check({ checkId: 'u', method: 'udp', status: 'timed_out', category: 'udp_no_reply', result: { port: 514 } })]), t);
    expect(steps.at(-1)?.status).toBe('warning');
  });
});
