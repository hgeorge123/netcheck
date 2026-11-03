import createWrapper from '@cloudscape-design/components/test-utils/dom';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../services/api';
import { renderI18n } from '../../test/render';
import type { Catalog, RunRequest } from '../../types/api';
import { NewRunPage } from './NewRunPage';

const catalog: Catalog = {
  items: [
    { method: 'dns', label: 'DNS', description: '', requiresPort: false, hostnameOnly: true },
    { method: 'tcp', label: 'TCP', description: '', requiresPort: true, hostnameOnly: false },
    { method: 'http', label: 'HTTP', description: '', requiresPort: true, defaultPort: 80, hostnameOnly: false },
    { method: 'https', label: 'HTTPS', description: '', requiresPort: true, defaultPort: 443, hostnameOnly: false },
    { method: 'ping', label: 'Ping', description: '', requiresPort: false, hostnameOnly: false },
    { method: 'traceroute', label: 'Traceroute', description: '', requiresPort: false, hostnameOnly: false },
    { method: 'udp', label: 'UDP', description: '', requiresPort: true, hostnameOnly: false },
  ],
  limits: { maxChecks: 7, defaultCheckTimeoutSeconds: 5, maxCheckTimeoutSeconds: 10, maxJobSeconds: 90, settleSeconds: 0 },
};
const namespaces = [
  { name: 'payments', canRun: true },
  { name: 'orders', canRun: true },
  { name: 'readonly', canRun: false },
];

function setup(submit = vi.fn().mockResolvedValue({ id: 'abcdef0123456789' }), lang: 'en' | 'es' = 'en') {
  const onCreated = vi.fn();
  const { container } = renderI18n(<NewRunPage namespaces={namespaces} catalog={catalog} submit={submit} onCreated={onCreated} />, lang);
  const w = createWrapper(container);
  const selectNamespace = () => {
    const sel = w.findSelect()!;
    sel.openDropdown();
    sel.selectOption(1);
  };
  const toggle = (index: number) => w.findCards()!.findItems()[index]!.findSelectionArea()!.click();
  return { w, submit, onCreated, selectNamespace, toggle };
}

describe('NewRunPage', () => {
  it('offers only namespaces where the user can run probes', () => {
    const { w } = setup();
    const sel = w.findSelect()!;
    sel.openDropdown();
    expect(sel.findDropdown().findOptions().map((o) => o.getElement().textContent)).toEqual(['payments', 'orders']);
  });

  it('shows an empty state when no namespace is runnable', () => {
    renderI18n(<NewRunPage namespaces={[{ name: 'readonly', canRun: false }]} catalog={catalog} submit={vi.fn()} onCreated={vi.fn()} />);
    expect(screen.getByText('No namespaces assigned')).toBeInTheDocument();
  });

  it('validates on the client before calling the API', async () => {
    const { submit } = setup();
    await userEvent.click(screen.getByRole('button', { name: 'Run test' }));
    expect(await screen.findByText('Choose the source namespace.')).toBeInTheDocument();
    expect(screen.getByText('Enter a hostname or IP address.')).toBeInTheDocument();
    expect(screen.getByText('Select at least one check.')).toBeInTheDocument();
    expect(submit).not.toHaveBeenCalled();
  });

  it('requires a TCP port and has no default for it', async () => {
    const { selectNamespace, toggle, submit } = setup();
    selectNamespace();
    await userEvent.type(screen.getByLabelText('Destination'), '10.20.30.40');
    toggle(1);
    expect(screen.getByLabelText('Port')).toHaveValue('');
    await userEvent.click(screen.getByRole('button', { name: 'Run test' }));
    expect(await screen.findByText('TCP needs a port (there is no default).')).toBeInTheDocument();
    expect(submit).not.toHaveBeenCalled();
  });

  it('submits per-check ports with HTTP 80 and HTTPS 443 by default', async () => {
    const { submit, onCreated, selectNamespace, toggle } = setup();
    selectNamespace();
    await userEvent.type(screen.getByLabelText('Destination'), 'api.example.com');
    toggle(1);
    toggle(2);
    toggle(3);
    toggle(4);
    const ports = screen.getAllByLabelText('Port');
    expect(ports.map((p) => (p as HTMLInputElement).value)).toEqual(['', '80', '443']);
    await userEvent.type(ports[0]!, '5432');
    expect(screen.getByTestId('request-preview').textContent).toContain('"port": 5432');
    await userEvent.click(screen.getByRole('button', { name: 'Run test' }));
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith('abcdef0123456789'));
    expect(submit).toHaveBeenCalledWith({
      namespace: 'payments',
      target: 'api.example.com',
      checks: [
        { method: 'tcp', port: 5432 },
        { method: 'http', port: 80, http: { method: 'GET', path: '/' } },
        { method: 'https', port: 443, http: { method: 'GET', path: '/' } },
        { method: 'ping', ping: { count: 4 } },
      ],
    });
  });

  it('lets TCP and HTTPS go through a configured proxy, direct by default', async () => {
    const submit = vi.fn().mockResolvedValue({ id: 'abcdef0123456789' });
    const withProxies: Catalog = { ...catalog, proxies: [{ name: 'corp', host: 'proxy.corp.example', port: 3128 }] };
    const { container } = renderI18n(<NewRunPage namespaces={namespaces} catalog={withProxies} submit={submit} onCreated={vi.fn()} />);
    const w = createWrapper(container);
    w.findSelect()!.openDropdown();
    w.findSelect()!.selectOption(1);
    await userEvent.type(screen.getByLabelText('Destination'), 'api.example.com');
    w.findCards()!.findItems()[1]!.findSelectionArea()!.click();
    w.findCards()!.findItems()[3]!.findSelectionArea()!.click();
    await userEvent.type(screen.getAllByLabelText('Port')[0]!, '443');
    const selects = w.findAllSelects();
    // The proxy selects start on Direct (segmented controls may render selects too).
    const [tcpProxy, httpsProxy] = selects.filter((s) => s.findTrigger().getElement().textContent?.includes('Direct'));
    expect(httpsProxy).toBeDefined();
    expect(tcpProxy!.findTrigger().getElement().textContent).toContain('Direct');
    httpsProxy!.openDropdown();
    httpsProxy!.selectOptionByValue('corp');
    await userEvent.click(screen.getByRole('button', { name: 'Run test' }));
    await waitFor(() => expect(submit).toHaveBeenCalled());
    expect(submit.mock.calls[0]![0].checks).toEqual([
      { method: 'tcp', port: 443 },
      { method: 'https', port: 443, http: { method: 'GET', path: '/' }, proxy: 'corp' },
    ]);
  });

  it('hides the connection choice when no proxy is configured', () => {
    const { toggle } = setup();
    toggle(1);
    expect(screen.queryByText('Connection')).not.toBeInTheDocument();
  });

  it('offers only what can be tested over UDP, with the port of each mode', async () => {
    const { submit, onCreated, selectNamespace, toggle } = setup();
    selectNamespace();
    await userEvent.type(screen.getByLabelText('Destination'), '10.20.30.40');
    toggle(6);
    for (const mode of [/Generic port/, /DNS server/, /NTP server/]) expect(screen.getByRole('radio', { name: mode })).toBeInTheDocument();
    expect(screen.getByText('Required, for example 514 (syslog) or 161 (SNMP).')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Run test' }));
    expect(await screen.findByText('A generic UDP check needs a port.')).toBeInTheDocument();
    expect(submit).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('radio', { name: /DNS server/ }));
    expect(screen.getByText('Default 53.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Run test' }));
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
    expect(submit).toHaveBeenCalledWith({ namespace: 'payments', target: '10.20.30.40', checks: [{ method: 'udp', port: 53, udp: { protocol: 'dns' } }] });
  });

  it('disables DNS for IP destinations', async () => {
    const { w } = setup();
    await userEvent.type(screen.getByLabelText('Destination'), '10.0.0.1');
    await userEvent.click(screen.getByRole('button', { name: 'Select all' }));
    const selected = w.findCards()!.findSelectedItems().map((i) => i.findCardHeader()!.getElement().textContent);
    expect(selected).toEqual(['TCP connection', 'HTTP', 'HTTPS', 'Ping (ICMP)', 'Traceroute (ICMP)', 'UDP']);
  });

  it('shows server-side policy rejections next to the field', async () => {
    const submit = vi.fn().mockRejectedValue(
      new ApiError(
        403,
        'destination_denied',
        'the destination is not allowed by the NetCheck policy',
        [{ field: 'target', code: 'destination_denied', message: '169.254.169.254 is in denied range 169.254.0.0/16' }],
        'req-123',
      ),
    );
    const { selectNamespace, toggle } = setup(submit);
    selectNamespace();
    await userEvent.type(screen.getByLabelText('Destination'), '169.254.169.254');
    toggle(4);
    await userEvent.click(screen.getByRole('button', { name: 'Run test' }));
    expect((await screen.findAllByText(/Not allowed by the NetCheck destination policy. Reason: 169.254.169.254 is in denied range/)).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/request id: req-123/).length).toBeGreaterThan(0);
  });

  it('firewall ticket mode asks only for destination and port', async () => {
    const { submit, onCreated, selectNamespace, w } = setup();
    w.findTiles()!.findItemByValue('firewall')!.findNativeInput().click();
    expect(w.findCards()).toBeNull();
    selectNamespace();
    await userEvent.type(screen.getByLabelText('Destination'), 'api.example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Run test' }));
    expect(await screen.findByText('Enter the port of the firewall ticket (1-65535).')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Port'), '443');
    expect(screen.getByText(/curl -v https:\/\/destination:443/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Run test' }));
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
    const req = submit.mock.calls[0]![0] as RunRequest;
    expect(req.mode).toBe('firewall');
    expect(req.checks.map((c) => c.method)).toEqual(['ping', 'traceroute', 'tcp', 'https']);
  });

  it('renders in Spanish when the account language is Spanish', () => {
    setup(undefined, 'es');
    expect(screen.getByRole('button', { name: 'Ejecutar prueba' })).toBeInTheDocument();
    expect(screen.getByText('Conexión TCP')).toBeInTheDocument();
  });
});
