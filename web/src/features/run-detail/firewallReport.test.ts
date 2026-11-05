import { describe, expect, it } from 'vitest';
import { translator } from '../../i18n';
import type { ExecutionView, RunDetail } from '../../types/api';
import { autoScheme, buildFirewallReport, unixDate } from './firewallReport';

const t = translator('en');
const fmt = (iso?: string) => iso ?? '';
const src = { podIp: '192.168.1.5', podName: 'netcheck-abc-x1', nodeName: 'worker-1', nodeIp: '10.0.1.20' };

function check(over: Partial<ExecutionView>): ExecutionView {
  return { checkId: over.method ?? 'x', method: 'tcp', status: 'succeeded', output: '', equivalentArgv: [], resolvedIps: ['10.20.0.5'], usedIp: '10.20.0.5', ...src, ...over };
}

const base: RunDetail = {
  id: 'abcdef0123456789',
  createdAt: '2026-10-22T10:15:00Z',
  actor: 'Ana',
  actorId: 'u1',
  namespace: 'payments',
  target: 'api.example.com',
  status: 'succeeded',
  clusterId: 'prod-eks',
  request: {
    mode: 'firewall',
    namespace: 'payments',
    target: 'api.example.com',
    checks: [
      { method: 'ping', ping: { count: 4 } },
      { method: 'traceroute', traceroute: { maxHops: 20 } },
      { method: 'tcp', port: 443 },
      { method: 'https', port: 443, http: { method: 'GET', path: '/' } },
    ],
  },
  checks: [
    check({
      method: 'ping',
      startedAt: '2026-10-22T10:15:03Z',
      durationMs: 3004,
      result: { ping: { transmitted: 4, received: 3, lossPercent: 25, replies: [{ seq: 1, rttMs: 1 }, { seq: 2, rttMs: 2 }, { seq: 3, lost: true }, { seq: 4, rttMs: 3 }] } },
    }),
    check({
      method: 'traceroute',
      result: { traceroute: { protocol: 'icmp', maxHops: 20, reached: true, hops: [{ ttl: 1, address: '10.0.0.1', rttMs: 0.4 }, { ttl: 2 }, { ttl: 3, address: '10.20.0.5', rttMs: 1.3 }] } },
    }),
    check({ method: 'tcp', durationMs: 8 }),
    check({
      method: 'https',
      durationMs: 40,
      result: { port: 443, http: { url: 'https://api.example.com:443/', method: 'GET', statusCode: 200, proto: 'HTTP/1.1', tlsVersion: 'TLS 1.3', tlsPeerCn: 'api.example.com', tlsNotAfter: '2027-01-01T00:00:00Z' } },
    }),
  ],
};

describe('buildFirewallReport', () => {
  it('renders every command with the measured values and the real source', () => {
    const r = buildFirewallReport(base, t, fmt);
    expect(r).toContain('NetCheck - firewall ticket troubleshooting');
    expect(r).toContain('Destination: api.example.com:443');
    expect(r).toContain('Probe Pod: netcheck-abc-x1    IP: 192.168.1.5');
    expect(r).toContain('Node (server): worker-1    IP: 10.0.1.20');
    expect(r).toContain('$ date\nThu Oct 22 10:15:03 UTC 2026');
    expect(r).toContain('$ hostname\nnetcheck-abc-x1');
    expect(r).toContain('PING api.example.com (10.20.0.5) 14(42) bytes of data.');
    expect(r).toContain('22 bytes from 10.20.0.5: icmp_seq=1 time=1.000 ms');
    expect(r).not.toContain('icmp_seq=3');
    expect(r).toContain('4 packets transmitted, 3 received, 25% packet loss, time 3004ms');
    expect(r).toContain('rtt min/avg/max/mdev = 1.000/2.000/3.000/0.816 ms');
    expect(r).toContain('traceroute to api.example.com (10.20.0.5), 20 hops max, 42 byte packets');
    expect(r).toContain(' 2  *');
    expect(r).toContain("$ telnet api.example.com 443\nTrying 10.20.0.5...\nConnected to api.example.com.\nEscape character is '^]'.");
    expect(r).toContain('$ curl -v https://api.example.com:443/');
    expect(r).toContain('* SSL connection using TLSv1.3');
    expect(r).toContain('< HTTP/1.1 200 OK');
  });

  it('renders failures like the real tools', () => {
    const failed: RunDetail = {
      ...base,
      checks: [
        check({ method: 'ping', status: 'failed', category: 'icmp_no_reply', durationMs: 4000, result: { ping: { transmitted: 4, received: 0, lossPercent: 100, replies: [{ seq: 1, lost: true }] } } }),
        check({ method: 'tcp', status: 'timed_out', category: 'timeout' }),
        check({ method: 'https', status: 'failed', category: 'tcp_refused', durationMs: 3 }),
      ],
    };
    const r = buildFirewallReport(failed, t, fmt);
    expect(r).toContain('4 packets transmitted, 0 received, 100% packet loss');
    expect(r).not.toContain('rtt min/avg/max');
    expect(r).toContain('telnet: Unable to connect to remote host: Connection timed out');
    expect(r).toContain('curl: (7) Failed to connect to api.example.com port 443 after 3 ms: Connection refused');
  });

  it('renders DNS failures and policy denials', () => {
    const r = buildFirewallReport(
      { ...base, checks: [check({ method: 'tcp', status: 'failed', category: 'dns_nxdomain', usedIp: undefined }), check({ method: 'https', status: 'failed', category: 'destination_denied', error: '169.254.169.254 is in denied range' })] },
      t,
      fmt,
    );
    expect(r).toContain('telnet: could not resolve api.example.com/443: Name or service not known');
    expect(r).toContain('curl: not executed: destination denied by the NetCheck policy (169.254.169.254 is in denied range)');
  });

  it('says which parts an administrator disabled', () => {
    const r = buildFirewallReport({ ...base, checks: base.checks.filter((c) => c.method !== 'ping' && c.method !== 'traceroute') }, t, fmt);
    expect(r).toContain('# ping: not run (disabled by an administrator)');
    expect(r).toContain('# traceroute: not run (disabled by an administrator)');
    expect(r).toContain('Connected to api.example.com');
  });
});

it('formats date like date(1) and chooses the curl protocol by port', () => {
  expect(unixDate('2026-01-05T03:04:05Z')).toBe('Mon Jan 05 03:04:05 UTC 2026');
  expect(autoScheme(443)).toBe('https');
  expect(autoScheme(8443)).toBe('https');
  expect(autoScheme(8080)).toBe('http');
});
