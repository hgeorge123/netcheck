import { describe, expect, it } from 'vitest';
import { en } from '../../i18n/en';
import type { ExecutionView, RunDetail } from '../../types/api';
import { blockedChecks, firewallRequest, hasEgressPolicies, suggestNetworkPolicy } from './blockedHelp';

const t = (key: keyof typeof en, params?: Record<string, string | number>) =>
  en[key].replace(/\{(\w+)\}/g, (_, k: string) => String(params?.[k] ?? ''));
const fmt = (iso?: string) => iso ?? '—';

const check = (over: Partial<ExecutionView>): ExecutionView => ({
  checkId: 'x',
  method: 'tcp',
  status: 'timed_out',
  category: 'timeout',
  output: '',
  equivalentArgv: [],
  resolvedIps: [],
  ...over,
});

const run = (checks: ExecutionView[], selectsProbe = true): RunDetail => ({
  id: 'abcdef0123456789',
  createdAt: '2026-11-03T10:00:00Z',
  actor: 'Dev',
  actorId: 'dev',
  namespace: 'payments',
  target: 'db.corp.example',
  status: 'failed',
  clusterId: 'prod',
  request: { namespace: 'payments', target: 'db.corp.example', checks: [] },
  fidelity: { level: 'namespace-wide-likely', egressPolicies: [{ name: 'default-deny', podSelector: '{}', selectsProbe }], notes: [] },
  checks,
});

describe('blocked help', () => {
  const blocked = run([
    check({ checkId: '1', method: 'tcp', usedIp: '10.30.5.8', result: { port: 5432 }, durationMs: 5000, podIp: '10.1.4.23', nodeIp: '10.1.2.10', nodeName: 'node-a' }),
    check({ checkId: '2', method: 'udp', usedIp: '10.30.5.8', category: 'udp_no_reply', result: { port: 514 } }),
    check({ checkId: '3', method: 'ping', usedIp: '10.30.5.8', category: 'icmp_no_reply' }),
    check({ checkId: '4', method: 'dns', status: 'succeeded', category: 'ok', resolvedIps: ['10.30.5.8'] }),
  ]);

  it('only counts checks that got no answer', () => {
    const refused = run([check({ category: 'tcp_refused', status: 'failed' }), check({ status: 'succeeded', category: 'ok' })]);
    expect(blockedChecks(refused)).toHaveLength(0);
    expect(blockedChecks(blocked).map((c) => c.checkId)).toEqual(['1', '2', '3']);
  });

  it('suggests an egress policy with the measured IPs and ports', () => {
    const yaml = suggestNetworkPolicy(blocked);
    expect(yaml).toContain('name: allow-egress-db-corp-example');
    expect(yaml).toContain('namespace: payments');
    expect(yaml).toContain('- ipBlock: {cidr: 10.30.5.8/32}');
    expect(yaml).toContain('- {port: 5432, protocol: TCP}');
    expect(yaml).toContain('- {port: 514, protocol: UDP}');
    expect(yaml).toContain('ICMP (ping, traceroute) to 10.30.5.8 cannot be allowed');
    expect(yaml).not.toContain('kube-dns'); // name resolution worked
  });

  it('adds cluster DNS when resolution timed out and uses /128 for IPv6', () => {
    const yaml = suggestNetworkPolicy(
      run([check({ method: 'dns', category: 'dns_timeout' }), check({ method: 'https', usedIp: 'fd00::5', result: { port: 443 } })]),
    );
    expect(yaml).toContain('k8s-app: kube-dns');
    expect(yaml).toContain('{cidr: fd00::5/128}');
  });

  it('tells whether namespace policies apply to the probe', () => {
    expect(hasEgressPolicies(blocked)).toBe(true);
    expect(hasEgressPolicies(run([], false))).toBe(false);
  });

  it('writes a firewall request with source IPs, blocked and working paths', () => {
    const text = firewallRequest(blocked, t, fmt);
    expect(text).toContain('Connectivity request (NetCheck test abcdef01)');
    expect(text).toContain('Source: namespace payments, cluster prod');
    expect(text).toContain('Pod IP: 10.1.4.23');
    expect(text).toContain('Node IP: 10.1.2.10 (node-a)');
    expect(text).toContain('- TCP 10.30.5.8:5432 (db.corp.example): no answer after 5000 ms');
    expect(text).toContain('- UDP 10.30.5.8:514');
    expect(text).toContain('Working from the same Pod:');
    expect(text).toContain('- DNS 10.30.5.8');
  });
});
