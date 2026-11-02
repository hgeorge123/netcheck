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

describe('RunDetailPage', () => {
  it('polls until the run is terminal', async () => {
    const load = vi.fn().mockResolvedValueOnce(base).mockResolvedValue(done);
    renderI18n(<RunDetailPage id={base.id} load={load} pollMs={5} />);
    expect(await screen.findByText('Connectivity failures')).toBeInTheDocument();
    const calls = load.mock.calls.length;
    await new Promise((r) => setTimeout(r, 50));
    expect(load.mock.calls.length).toBe(calls); // no polling after terminal state
    expect(screen.getByText('10.1.1.9')).toBeInTheDocument();
    expect(screen.getByText('node-a')).toBeInTheDocument();
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
