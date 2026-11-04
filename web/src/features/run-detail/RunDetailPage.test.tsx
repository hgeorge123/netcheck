import { screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../services/api';
import { renderI18n } from '../../test/render';
import type { RunDetail } from '../../types/api';
import { RunDetailPage, shellQuote } from './RunDetailPage';

const base: RunDetail = {
  id: 'abcdef0123456789',
  createdAt: '2026-10-21T10:00:00Z',
  actor: 'Dev',
  actorId: 'dev-user',
  namespace: 'payments',
  target: '10.20.30.40',
  status: 'running',
  clusterId: 'lab',
  request: { namespace: 'payments', target: '10.20.30.40', checks: [{ method: 'tcp', port: 443 }, { method: 'http', port: 443 }] },
  checks: [
    { checkId: '1-tcp', method: 'tcp', status: 'running', output: '', equivalentArgv: [], resolvedIps: [] },
    { checkId: '2-http', method: 'http', status: 'running', output: '', equivalentArgv: [], resolvedIps: [] },
  ],
};

const done: RunDetail = {
  ...base,
  status: 'failed',
  finishedAt: '2026-10-21T10:00:05Z',
  jobName: 'netcheck-abcdef0123456789',
  fidelity: { level: 'specific-selectors-detected', egressPolicies: [{ name: 'app-only', podSelector: 'app=api', selectsProbe: false }], notes: [] },
  checks: [
    {
      checkId: '1-tcp',
      method: 'tcp',
      status: 'timed_out',
      category: 'timeout',
      durationMs: 5000,
      output: 'connecting tcp 10.20.30.40:443',
      equivalentArgv: ['nc', '-z', '-v', '-w', '5', '10.20.30.40', '443'],
      resolvedIps: ['10.20.30.40'],
      usedIp: '10.20.30.40',
      podIp: '10.1.1.9',
      nodeName: 'node-a',
      diagnosis: { category: 'timeout', severity: 'error', summary: 'Timed out without an answer.', detail: '', conclusive: false },
      result: { port: 443 },
    },
    {
      checkId: '2-http',
      method: 'http',
      status: 'succeeded',
      category: 'http_response',
      durationMs: 20,
      output: '',
      equivalentArgv: ['curl', '-sS', '--', 'http://10.20.30.40:443/'],
      resolvedIps: ['10.20.30.40'],
      diagnosis: { category: 'http_response', severity: 'warning', summary: 'x', detail: '', conclusive: false, httpStatus: 404 },
      result: { port: 443, http: { url: 'http://10.20.30.40:443/', method: 'GET', statusCode: 404, proto: 'HTTP/1.1' } },
    },
  ],
};

const icmp: RunDetail = {
  ...base,
  status: 'succeeded',
  finishedAt: '2026-10-21T10:00:09Z',
  checks: [
    {
      checkId: '1-ping',
      method: 'ping',
      status: 'succeeded',
      category: 'icmp_partial_loss',
      output: '',
      equivalentArgv: ['ping', '-c', '2', '10.20.30.40'],
      resolvedIps: ['10.20.30.40'],
      diagnosis: { category: 'icmp_partial_loss', severity: 'warning', summary: '', detail: '', conclusive: false },
      result: {
        ping: { transmitted: 2, received: 1, lossPercent: 50, minMs: 1.2, avgMs: 1.2, maxMs: 1.2, replies: [{ seq: 1, rttMs: 1.2 }, { seq: 2, lost: true }] },
      },
    },
    {
      checkId: '2-traceroute',
      method: 'traceroute',
      status: 'failed',
      category: 'traceroute_incomplete',
      output: '',
      equivalentArgv: [],
      resolvedIps: ['10.20.30.40'],
      diagnosis: { category: 'traceroute_incomplete', severity: 'warning', summary: '', detail: '', conclusive: false },
      result: { traceroute: { protocol: 'icmp', maxHops: 2, reached: false, hops: [{ ttl: 1, address: '10.1.0.1', rttMs: 0.5 }, { ttl: 2 }] } },
    },
  ],
};

describe('RunDetailPage certificate problems', () => {
  const tlsRun = (ignored: boolean): RunDetail => ({
    ...done,
    status: ignored ? 'succeeded' : 'failed',
    checks: [
      {
        checkId: '1-https',
        method: 'https',
        status: ignored ? 'succeeded' : 'failed',
        category: ignored ? 'http_response' : 'tls_cert_failure',
        output: '',
        equivalentArgv: [],
        resolvedIps: ['10.20.30.40'],
        usedIp: '10.20.30.40',
        diagnosis: { category: ignored ? 'http_response' : 'tls_cert_failure', severity: ignored ? 'warning' : 'error', summary: '', detail: '', conclusive: false, httpStatus: ignored ? 200 : undefined, tlsIgnored: ignored },
        result: {
          port: 443,
          http: { url: 'https://api.example.com/', method: 'GET', statusCode: ignored ? 200 : undefined, tlsProblems: ['expired', 'hostname_mismatch'],
            tlsProblemDetail: 'the certificate expired on 2026-01-01T00:00:00Z; the certificate does not cover api.example.com: it is for www.example.com',
            tlsIgnored: ignored, tlsNames: ['www.example.com'], tlsIssuer: 'Corp Root' },
        },
      },
    ],
  });

  it('explains why the request stopped', async () => {
    renderI18n(<RunDetailPage id={done.id} load={vi.fn().mockResolvedValue(tlsRun(false))} />);
    expect(await screen.findByText('The certificate is not valid')).toBeInTheDocument();
    expect(screen.getByText('The certificate has expired.')).toBeInTheDocument();
    expect(screen.getByText('The certificate does not cover the destination name.')).toBeInTheDocument();
    expect(screen.getByText(/it is for www.example.com/)).toBeInTheDocument();
  });

  it('warns when the errors were ignored', async () => {
    renderI18n(<RunDetailPage id={done.id} load={vi.fn().mockResolvedValue(tlsRun(true))} />);
    expect(await screen.findByText('Certificate errors ignored')).toBeInTheDocument();
    expect(screen.getByText('Corp Root')).toBeInTheDocument();
  });
});

describe('RunDetailPage through a proxy', () => {
  const proxied = (ok: boolean): RunDetail => ({
    ...done,
    status: ok ? 'succeeded' : 'failed',
    checks: [
      {
        checkId: '1-tcp',
        method: 'tcp',
        status: ok ? 'succeeded' : 'failed',
        category: ok ? 'ok' : 'proxy_denied',
        output: '',
        equivalentArgv: [],
        resolvedIps: [],
        diagnosis: { category: ok ? 'ok' : 'proxy_denied', severity: ok ? 'success' : 'error', summary: '', detail: '', conclusive: !ok, proxy: 'corp' },
        result: {
          port: 5432,
          proxy: { name: 'corp', address: 'proxy.corp.example:3128', usedIp: '10.0.0.9', reached: true, status: ok ? 200 : 403, statusText: ok ? '200 Connection established' : '403 Forbidden' },
        },
      },
    ],
  });

  it('says the tunnel worked and that the direct path was not tested', async () => {
    renderI18n(<RunDetailPage id={done.id} load={vi.fn().mockResolvedValue(proxied(true))} />);
    expect(await screen.findAllByText('TCP tunnel established through the proxy.')).not.toHaveLength(0);
    expect(screen.getAllByText(/the direct path from the Pod was not tested/)).not.toHaveLength(0);
    expect(screen.getByText('corp (proxy.corp.example:3128, IP 10.0.0.9)')).toBeInTheDocument();
    expect(screen.getByText('CONNECT → 200 Connection established')).toBeInTheDocument();
  });

  it('shows only that a personal proxy was used to anyone but its owner', async () => {
    const hidden = proxied(false);
    hidden.checks[0]!.result = { port: 5432, proxy: { personal: true, mode: 'connect', reached: true, status: 403, statusText: '403 Forbidden' } };
    renderI18n(<RunDetailPage id={done.id} load={vi.fn().mockResolvedValue(hidden)} />);
    expect(await screen.findByText('Personal proxy of Dev (details visible only to them)')).toBeInTheDocument();
    expect(screen.getByText('Personal proxy')).toBeInTheDocument();
    expect(screen.queryByText(/proxy.corp.example/)).not.toBeInTheDocument();
  });

  it('tells a forwarded HTTP request from an error the proxy answered', async () => {
    const fwd = proxied(true);
    fwd.checks[0]!.result = { port: 80, proxy: { name: 'corp', address: 'proxy.corp.example:3128', usedIp: '10.0.0.9', mode: 'forward', reached: true, via: '1.1 squid' } };
    renderI18n(<RunDetailPage id={done.id} load={vi.fn().mockResolvedValue(fwd)} />);
    expect(await screen.findByText('Request forwarded by the proxy')).toBeInTheDocument();
    expect(screen.getByText('1.1 squid')).toBeInTheDocument();
  });

  it('renders a check whose Pod resolved nothing (stored before the fix as null)', async () => {
    const fwd = proxied(true);
    fwd.checks[0]!.resolvedIps = null as unknown as string[];
    fwd.checks[0]!.result = { port: 80, proxy: { name: 'corp', address: 'proxy.corp.example:3128', usedIp: '10.0.0.9', mode: 'forward', reached: true } };
    renderI18n(<RunDetailPage id={done.id} load={vi.fn().mockResolvedValue(fwd)} />);
    expect(await screen.findByText('Request forwarded by the proxy')).toBeInTheDocument();
  });

  it('explains a refusal of the proxy', async () => {
    renderI18n(<RunDetailPage id={done.id} load={vi.fn().mockResolvedValue(proxied(false))} />);
    expect(await screen.findAllByText('The proxy refused the tunnel (its policy).')).not.toHaveLength(0);
    expect(screen.getByText('CONNECT → 403 Forbidden')).toBeInTheDocument();
  });
});

describe('RunDetailPage what is missing', () => {
  it('says no NetworkPolicy is needed when none applies to the probe', async () => {
    renderI18n(<RunDetailPage id={done.id} load={vi.fn().mockResolvedValue(done)} />);
    expect(await screen.findByText('What is missing')).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Suggested NetworkPolicy' })).not.toBeInTheDocument();
    expect(screen.getByText('No NetworkPolicy change is needed')).toBeInTheDocument();
    expect(screen.getByTestId('missing-request')).toHaveTextContent('TCP 10.20.30.40:443');
  });

  it('suggests a NetworkPolicy when the namespace policies select the probe', async () => {
    const withPolicy: RunDetail = { ...done, fidelity: { level: 'namespace-wide-likely', egressPolicies: [{ name: 'deny', podSelector: '{}', selectsProbe: true }], notes: [] } };
    renderI18n(<RunDetailPage id={done.id} load={vi.fn().mockResolvedValue(withPolicy)} />);
    expect(await screen.findByRole('tab', { name: 'Suggested NetworkPolicy' })).toBeInTheDocument();
    expect(screen.getByTestId('missing-policy')).toHaveTextContent('- ipBlock: {cidr: 10.20.30.40/32}');
    expect(screen.getByText('A NetworkPolicy change is probably needed')).toBeInTheDocument();
  });

  it('says nothing is missing when every check got an answer', async () => {
    renderI18n(<RunDetailPage id={icmp.id} load={vi.fn().mockResolvedValue({ ...icmp, checks: [icmp.checks[0]] })} />);
    expect(await screen.findByText('Nothing is missing')).toBeInTheDocument();
    expect(screen.queryByTestId('missing-request')).not.toBeInTheDocument();
  });
});

describe('RunDetailPage', () => {
  it('polls until the run is terminal', async () => {
    const load = vi.fn().mockResolvedValueOnce(base).mockResolvedValue(done);
    renderI18n(<RunDetailPage id={base.id} load={load} pollMs={5} />);
    expect(await screen.findByText('Connectivity failures')).toBeInTheDocument();
    const calls = load.mock.calls.length;
    await new Promise((r) => setTimeout(r, 50));
    expect(load.mock.calls.length).toBe(calls); // no polling after terminal state
    expect(screen.getByText('10.1.1.9')).toBeInTheDocument();
    expect(screen.getAllByText('node-a').length).toBeGreaterThan(0); // details and path
  });

  it('does not paint an HTTP 404 as a network error', async () => {
    renderI18n(<RunDetailPage id={base.id} load={vi.fn().mockResolvedValue(done)} />);
    const row = (await screen.findAllByText(/HTTP answered 404/))[0]!.closest('tr')!;
    expect(within(row).getByLabelText('Warning')).toBeInTheDocument();
    expect(within(row).queryByLabelText('Error')).toBeNull();
    const tcpRow = screen.getAllByText('Timed out without an answer.')[0]!.closest('tr')!;
    expect(within(tcpRow).getByText('Timed out')).toBeInTheDocument();
  });

  it('translates diagnoses by category', async () => {
    renderI18n(<RunDetailPage id={base.id} load={vi.fn().mockResolvedValue(done)} />, 'es');
    expect((await screen.findAllByText('Tiempo agotado sin respuesta.')).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/HTTP respondió 404/).length).toBeGreaterThan(0);
  });

  it('shows fidelity warnings and never claims equivalence', async () => {
    renderI18n(<RunDetailPage id={base.id} load={vi.fn().mockResolvedValue(done)} />);
    expect(await screen.findByText('Fidelity: some policies use specific selectors')).toBeInTheDocument();
    expect(screen.getByText(/does not imply full equivalence/)).toBeInTheDocument();
    expect(screen.getByText(/app-only \(app=api, does not apply to the probe\)/)).toBeInTheDocument();
  });

  it('renders ping replies and traceroute hops', async () => {
    renderI18n(<RunDetailPage id={base.id} load={vi.fn().mockResolvedValue(icmp)} />);
    expect(await screen.findByText('2 transmitted, 1 received, 50% loss')).toBeInTheDocument();
    expect(screen.getByText('No reply')).toBeInTheDocument();
  });

  it('shows the single firewall ticket report for firewall-mode runs', async () => {
    const fw: RunDetail = { ...done, request: { ...done.request, mode: 'firewall' } };
    renderI18n(<RunDetailPage id={base.id} load={vi.fn().mockResolvedValue(fw)} />);
    expect(await screen.findByText('Firewall ticket report')).toBeInTheDocument();
    expect(screen.getByTestId('firewall-report').textContent).toContain('$ telnet 10.20.30.40 443');
    expect(screen.getByRole('button', { name: 'Download .txt' })).toBeInTheDocument();
  });

  it('separates infrastructure errors from network results', async () => {
    const infra: RunDetail = { ...base, status: 'infra_error', errorMessage: 'probe could not start: ImagePullBackOff', checks: [] };
    renderI18n(<RunDetailPage id={base.id} load={vi.fn().mockResolvedValue(infra)} />);
    expect(await screen.findByText('NetCheck infrastructure error (not a network result)')).toBeInTheDocument();
    expect(screen.getByText(/ImagePullBackOff/)).toBeInTheDocument();
  });

  it('reports a missing run without retrying', async () => {
    const load = vi.fn().mockRejectedValue(new ApiError(404, 'not_found', 'run not found'));
    renderI18n(<RunDetailPage id={base.id} load={load} pollMs={5} />);
    expect(await screen.findByText('Test not found')).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 40));
    expect(load).toHaveBeenCalledTimes(1);
  });
});

describe('shellQuote', () => {
  it('quotes arguments for display', () => {
    expect(shellQuote(['curl', '-w', '%{http_code}\\n', '--', "http://x/a'b"])).toBe("curl -w '%{http_code}\\n' -- 'http://x/a'\\''b'");
  });
});
