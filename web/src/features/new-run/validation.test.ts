import { describe, expect, it } from 'vitest';
import { buildRequest, emptyForm, formFromRun, isIPLiteral, mapServerErrors, type RunForm, validateForm, validateTarget } from './validation';

const base: RunForm = { ...emptyForm('payments'), target: '10.20.30.40', methods: ['tcp'], tcpPort: '5432' };
const key = (e: unknown) => (e && typeof e === 'object' && 'key' in e ? (e as { key: string }).key : undefined);

describe('validateTarget', () => {
  it.each(['10.20.30.40', '2001:db8::1', '[2001:db8::1]', 'api.example.com', 'my-svc'])('accepts %s', (t) => expect(validateTarget(t)).toBeUndefined());

  it.each([
    ['', 'validation.target'],
    ['-oProxyCommand=id', 'validation.targetFlag'],
    ['host name', 'validation.targetChars'],
    ['a;id', 'validation.hostname'],
    ['$(id)', 'validation.hostname'],
    ['10.0.0.1:443', 'validation.targetUrl'],
    ['010.0.0.1', 'validation.ipv4'],
    ['999.1.1.1', 'validation.ipv4'],
    ['https://api.example.com/', 'validation.targetUrl'],
    ['user@example.com', 'validation.targetUrl'],
    ['example.com/path', 'validation.targetUrl'],
    ['fe80::1%eth0', 'validation.zone'],
    ['münchen.de', 'validation.targetChars'],
  ])('rejects %s', (t, k) => expect(validateTarget(t)).toBe(k));
});

describe('validateForm', () => {
  it('accepts a valid TCP form', () => expect(validateForm(base, 10)).toEqual({}));

  it('requires namespace and methods', () => {
    const e = validateForm({ ...base, namespace: '', methods: [] }, 10);
    expect(key(e.namespace)).toBe('validation.namespace');
    expect(key(e.methods)).toBe('validation.methods');
  });

  it('requires a TCP port: there is no default', () => {
    expect(emptyForm().tcpPort).toBe('');
    expect(key(validateForm({ ...base, tcpPort: '' }, 10).tcpPort)).toBe('validation.tcpPort');
    expect(key(validateForm({ ...base, tcpPort: '70000' }, 10).tcpPort)).toBe('validation.port');
  });

  it('defaults HTTP to 80 and HTTPS to 443', () => {
    const f = emptyForm();
    expect(f.httpPort).toBe('80');
    expect(f.httpsPort).toBe('443');
    expect(validateForm({ ...base, methods: ['http', 'https'], httpPort: '', httpsPort: '' }, 10)).toEqual({});
    expect(key(validateForm({ ...base, methods: ['https'], httpsPort: '0' }, 10).httpsPort)).toBe('validation.port');
  });

  it('rejects DNS on an IP target', () => expect(key(validateForm({ ...base, methods: ['dns'] }, 10).methods)).toBe('validation.dnsOnIp'));

  it('bounds the timeout, ping count and max hops', () => {
    expect(validateForm({ ...base, timeoutSeconds: '11' }, 10).timeoutSeconds).toBeDefined();
    expect(validateForm({ ...base, timeoutSeconds: '2.5' }, 10).timeoutSeconds).toBeDefined();
    expect(validateForm({ ...base, methods: ['ping'], pingCount: '11' }, 10).pingCount).toBeDefined();
    expect(validateForm({ ...base, methods: ['ping'], pingCount: '0' }, 10).pingCount).toBeDefined();
    expect(validateForm({ ...base, methods: ['traceroute'], maxHops: '31' }, 10).maxHops).toBeDefined();
    expect(validateForm({ ...base, methods: ['ping', 'traceroute'] }, 10)).toEqual({});
  });

  it('validates HTTP and HTTPS paths independently', () => {
    expect(validateForm({ ...base, methods: ['http'], httpPath: 'no-slash' }, 10).httpPath).toBeDefined();
    expect(validateForm({ ...base, methods: ['https'], httpsPath: '/a b' }, 10).httpsPath).toBeDefined();
    expect(validateForm({ ...base, methods: ['https'], httpsPath: '/a?b' }, 10).httpsPath).toBeDefined();
  });
});

describe('buildRequest', () => {
  it('builds typed checks with per-check ports in catalog order', () => {
    const req = buildRequest({
      ...base,
      target: ' api.example.com ',
      methods: ['https', 'dns', 'tcp', 'http', 'traceroute', 'ping'],
      tcpPort: '5432',
      httpPort: '8080',
      httpMethod: 'HEAD',
      httpPath: '/health',
      httpsPort: '',
      timeoutSeconds: '3',
      pingCount: '3',
      maxHops: '15',
    });
    expect(req).toEqual({
      namespace: 'payments',
      target: 'api.example.com',
      timeoutSeconds: 3,
      checks: [
        { method: 'dns', dns: { family: 'ip' } },
        { method: 'tcp', port: 5432 },
        { method: 'http', port: 8080, http: { method: 'HEAD', path: '/health' } },
        { method: 'https', port: 443, http: { method: 'GET', path: '/' } },
        { method: 'ping', ping: { count: 3 } },
        { method: 'traceroute', traceroute: { maxHops: 15 } },
      ],
    });
  });

  it('round-trips through formFromRun ("Run again")', () => {
    const req = buildRequest({ ...base, methods: ['tcp', 'https', 'ping'], httpsPort: '8443', httpsPath: '/x' });
    const f = formFromRun({ request: req });
    expect(buildRequest(f)).toEqual(req);
  });
});

describe('mapServerErrors', () => {
  it('maps indexed check errors to the field of that method', () => {
    const req = buildRequest({ ...base, methods: ['tcp', 'https', 'ping'] });
    const e = mapServerErrors(
      [
        { field: 'checks[1].port', code: 'destination_denied', message: 'x' },
        { field: 'checks[2].ping.count', code: 'out_of_range', message: 'y' },
        { field: 'checks', code: 'budget_exceeded', message: 'z' },
        { field: 'target', code: 'invalid_hostname', message: 't' },
      ],
      req,
      (d) => d.message,
    );
    expect(e).toEqual({ httpsPort: { text: 'x' }, pingCount: { text: 'y' }, methods: { text: 'z' }, target: { text: 't' } });
  });
});

it('detects IP literals', () => {
  expect(isIPLiteral('10.0.0.1')).toBe(true);
  expect(isIPLiteral('2001:db8::1')).toBe(true);
  expect(isIPLiteral('api.example.com')).toBe(false);
});

describe('firewall ticket mode', () => {
  const fw = { ...emptyForm('payments'), mode: 'firewall' as const, target: 'api.example.com', fwPort: '443' };

  it('only needs namespace, destination and port', () => {
    expect(validateForm(fw, 10)).toEqual({});
    expect(key(validateForm({ ...fw, fwPort: '' }, 10).fwPort)).toBe('validation.fwPort');
    expect(validateForm({ ...fw, fwPort: '70000' }, 10).fwPort).toBeDefined();
  });

  it('builds the fixed bundle with the curl protocol chosen by port', () => {
    expect(buildRequest(fw)).toEqual({
      mode: 'firewall',
      namespace: 'payments',
      target: 'api.example.com',
      checks: [
        { method: 'ping', ping: { count: 4 } },
        { method: 'traceroute', traceroute: { maxHops: 20 } },
        { method: 'tcp', port: 443 },
        { method: 'https', port: 443, http: { method: 'GET', path: '/' } },
      ],
    });
    expect(buildRequest({ ...fw, fwPort: '8080' }).checks[3]).toEqual({ method: 'http', port: 8080, http: { method: 'GET', path: '/' } });
    expect(buildRequest({ ...fw, fwPort: '8080', fwScheme: 'https' }).checks[3]?.method).toBe('https');
  });

  it('round-trips through formFromRun and maps port errors', () => {
    const req = buildRequest({ ...fw, fwPort: '8443', fwScheme: 'http' });
    const back = formFromRun({ request: req });
    expect(back.mode).toBe('firewall');
    expect(buildRequest(back)).toEqual(req);
    expect(mapServerErrors([{ field: 'checks[2].port', code: 'destination_denied', message: 'p' }], req, (d) => d.message)).toEqual({ fwPort: { text: 'p' } });
  });
});

describe('UDP checks', () => {
  const udp = (patch: Partial<RunForm>): RunForm => ({ ...base, methods: ['udp'], ...patch });

  it('requires a port only for the generic mode', () => {
    expect(key(validateForm(udp({ udpProtocol: 'generic', udpPort: '' }), 10).udpPort)).toBe('validation.udpPort');
    expect(validateForm(udp({ udpProtocol: 'dns', udpPort: '' }), 10)).toEqual({});
    expect(validateForm(udp({ udpProtocol: 'ntp', udpPort: '' }), 10)).toEqual({});
    expect(key(validateForm(udp({ udpProtocol: 'dns', udpPort: '70000' }), 10).udpPort)).toBe('validation.port');
  });

  it('defaults DNS to 53 and NTP to 123, and sends the mode', () => {
    expect(buildRequest(udp({ udpProtocol: 'dns' })).checks).toEqual([{ method: 'udp', port: 53, udp: { protocol: 'dns' } }]);
    expect(buildRequest(udp({ udpProtocol: 'ntp', udpPort: '1123' })).checks).toEqual([{ method: 'udp', port: 1123, udp: { protocol: 'ntp' } }]);
    expect(buildRequest(udp({ udpProtocol: 'generic', udpPort: '514' })).checks).toEqual([{ method: 'udp', port: 514, udp: { protocol: 'generic' } }]);
  });

  it('round-trips through formFromRun and maps port errors', () => {
    const req = buildRequest(udp({ udpProtocol: 'ntp' }));
    const f = formFromRun({ request: req });
    expect(f.udpProtocol).toBe('ntp');
    expect(buildRequest(f)).toEqual(req);
    expect(mapServerErrors([{ field: 'checks[0].port', code: 'destination_denied', message: 'x' }], req, (d) => d.message)).toEqual({ udpPort: { text: 'x' } });
  });
});

describe('ignore certificate errors', () => {
  const https: RunForm = { ...emptyForm(), namespace: 'payments', target: 'api.example.com', methods: ['https'] };
  it('is only sent when chosen, and survives "Run again"', () => {
    expect(buildRequest(https).checks[0]?.http?.ignoreTlsErrors).toBeUndefined();
    const req = buildRequest({ ...https, httpsIgnoreTls: true });
    expect(req.checks[0]?.http).toEqual({ method: 'GET', path: '/', ignoreTlsErrors: true });
    const again = formFromRun({ request: req } as Parameters<typeof formFromRun>[0]);
    expect(again.httpsIgnoreTls).toBe(true);
  });
});
