import type { MessageKey } from '../../i18n';
import { METHODS, type CheckRequest, type FieldError, type Method, type RunDetail, type RunRequest, type UDPProtocol } from '../../types/api';

// Client-side validation is a usability aid only; the server is the authority.

export const DEFAULT_PORTS = { http: 80, https: 443 } as const;
/** Generic UDP has no default port on purpose, like TCP. */
export const DEFAULT_UDP_PORTS: Record<UDPProtocol, number | undefined> = { generic: undefined, dns: 53, ntp: 123 };
export const DEFAULT_PING_COUNT = 4;
export const MAX_PING_COUNT = 10;
export const DEFAULT_MAX_HOPS = 20;
export const MAX_HOPS = 30;

type HTTPMethod = 'GET' | 'HEAD';

/** custom: user-selected checks. firewall: fixed bundle for firewall tickets. */
export type RunMode = 'custom' | 'firewall';
export type FirewallScheme = 'auto' | 'http' | 'https';

// Firewall ticket bundle: ping, traceroute, telnet (TCP) and curl (HTTP/S).
export const FIREWALL_PING_COUNT = 4;
export const FIREWALL_MAX_HOPS = 20;

export interface RunForm {
  mode: RunMode;
  /** Port of the firewall ticket (telnet and curl). */
  fwPort: string;
  fwScheme: FirewallScheme;
  namespace: string;
  target: string;
  timeoutSeconds: string;
  methods: Method[];
  // TCP has no default port on purpose: the user must choose one.
  tcpPort: string;
  udpProtocol: UDPProtocol;
  udpPort: string;
  httpPort: string;
  httpsPort: string;
  httpMethod: HTTPMethod;
  httpPath: string;
  httpsMethod: HTTPMethod;
  httpsPath: string;
  httpsIgnoreTls: boolean;
  /** Name of the proxy for TCP / HTTPS; '' is the direct path (default). */
  tcpProxy: string;
  httpsProxy: string;
  dnsFamily: 'ip' | 'ip4' | 'ip6';
  pingCount: string;
  maxHops: string;
}

export const emptyForm = (namespace = ''): RunForm => ({
  mode: 'custom',
  fwPort: '',
  fwScheme: 'auto',
  namespace,
  target: '',
  timeoutSeconds: '',
  methods: [],
  tcpPort: '',
  udpProtocol: 'generic',
  udpPort: '',
  httpPort: String(DEFAULT_PORTS.http),
  httpsPort: String(DEFAULT_PORTS.https),
  httpMethod: 'GET',
  httpPath: '/',
  httpsMethod: 'GET',
  httpsPath: '/',
  httpsIgnoreTls: false,
  tcpProxy: '',
  httpsProxy: '',
  dnsFamily: 'ip',
  pingCount: String(DEFAULT_PING_COUNT),
  maxHops: String(DEFAULT_MAX_HOPS),
});

export type FormField =
  | 'fwPort'
  | 'namespace'
  | 'target'
  | 'methods'
  | 'timeoutSeconds'
  | 'tcpPort'
  | 'udpPort'
  | 'httpPort'
  | 'httpsPort'
  | 'httpPath'
  | 'httpsPath'
  | 'tcpProxy'
  | 'httpsProxy'
  | 'pingCount'
  | 'maxHops';

/** A translatable error: key plus optional parameters, or a server text. */
export type FormError = { key: MessageKey; params?: Record<string, number | string> } | { text: string };
export type FormErrors = Partial<Record<FormField, FormError>>;

const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const hostname = /^(?=.{1,253}\.?$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$/i;
const pathPattern = /^\/[\w\-._~!$&'()*+,;=:@/%]*$/;

export function isIPv6(s: string): boolean {
  const v = s.startsWith('[') && s.endsWith(']') ? s.slice(1, -1) : s;
  if (!v.includes(':') || v.includes('%') || !/^[0-9a-f:.]+$/i.test(v)) return false;
  try {
    new URL(`http://[${v}]/`);
    return true;
  } catch {
    return false;
  }
}

export const isIPLiteral = (s: string): boolean => ipv4.test(s) || isIPv6(s);

export function validateTarget(raw: string): MessageKey | undefined {
  const t = raw.trim();
  if (!t) return 'validation.target';
  if (t.length > 253) return 'validation.hostname';
  if ([...t].some((c) => c.charCodeAt(0) <= 0x20 || c.charCodeAt(0) >= 0x7f)) return 'validation.targetChars';
  if (t.startsWith('-')) return 'validation.targetFlag';
  if (t.includes('://') || /[/?#@]/.test(t)) return 'validation.targetUrl';
  if (isIPLiteral(t)) return undefined;
  if (/^[\d.]+$/.test(t)) return 'validation.ipv4';
  if (t.includes('%')) return 'validation.zone';
  if (t.includes(':')) return 'validation.targetUrl';
  if (!hostname.test(t) || /^\d+$/.test(t.split('.').filter(Boolean).pop() ?? '')) return 'validation.hostname';
  return undefined;
}

const intIn = (v: string, min: number, max: number): boolean => {
  const n = Number(v);
  return v.trim() !== '' && Number.isInteger(n) && n >= min && n <= max;
};

export function validateForm(f: RunForm, maxTimeout: number): FormErrors {
  const e: FormErrors = {};
  const has = (m: Method) => f.methods.includes(m);
  if (!f.namespace) e.namespace = { key: 'validation.namespace' };
  const targetErr = validateTarget(f.target);
  if (targetErr) e.target = { key: targetErr };
  if (f.mode === 'firewall') {
    if (!intIn(f.fwPort, 1, 65535)) e.fwPort = { key: 'validation.fwPort' };
    return e;
  }
  if (f.methods.length === 0) e.methods = { key: 'validation.methods' };
  else if (has('dns') && isIPLiteral(f.target.trim())) e.methods = { key: 'validation.dnsOnIp' };
  if (has('tcp')) {
    if (f.tcpPort.trim() === '') e.tcpPort = { key: 'validation.tcpPort' };
    else if (!intIn(f.tcpPort, 1, 65535)) e.tcpPort = { key: 'validation.port' };
  }
  if (has('udp')) {
    if (f.udpPort.trim() === '' && f.udpProtocol === 'generic') e.udpPort = { key: 'validation.udpPort' };
    else if (f.udpPort.trim() !== '' && !intIn(f.udpPort, 1, 65535)) e.udpPort = { key: 'validation.port' };
  }
  if (has('http') && f.httpPort.trim() !== '' && !intIn(f.httpPort, 1, 65535)) e.httpPort = { key: 'validation.port' };
  if (has('https') && f.httpsPort.trim() !== '' && !intIn(f.httpsPort, 1, 65535)) e.httpsPort = { key: 'validation.port' };
  if (has('http') && !pathPattern.test(f.httpPath || '/')) e.httpPath = { key: 'validation.path' };
  if (has('https') && !pathPattern.test(f.httpsPath || '/')) e.httpsPath = { key: 'validation.path' };
  if (has('ping') && !intIn(f.pingCount, 1, MAX_PING_COUNT)) e.pingCount = { key: 'validation.count', params: { max: MAX_PING_COUNT } };
  if (has('traceroute') && !intIn(f.maxHops, 1, MAX_HOPS)) e.maxHops = { key: 'validation.count', params: { max: MAX_HOPS } };
  if (f.timeoutSeconds.trim() !== '' && !intIn(f.timeoutSeconds, 1, maxTimeout)) {
    e.timeoutSeconds = { key: 'validation.timeout', params: { max: maxTimeout } };
  }
  return e;
}

/** curl protocol for the firewall bundle: 443/8443 use HTTPS unless chosen. */
export function firewallScheme(f: Pick<RunForm, 'fwPort' | 'fwScheme'>): 'http' | 'https' {
  if (f.fwScheme !== 'auto') return f.fwScheme;
  const p = Number(f.fwPort);
  return p === 443 || p === 8443 ? 'https' : 'http';
}

export function buildRequest(f: RunForm): RunRequest {
  if (f.mode === 'firewall') {
    const port = Number(f.fwPort);
    const req: RunRequest = {
      mode: 'firewall',
      namespace: f.namespace,
      target: f.target.trim(),
      checks: [
        { method: 'ping', ping: { count: FIREWALL_PING_COUNT } },
        { method: 'traceroute', traceroute: { maxHops: FIREWALL_MAX_HOPS } },
        { method: 'tcp', port },
        { method: firewallScheme(f), port, http: { method: 'GET', path: '/' } },
      ],
    };
    if (f.timeoutSeconds.trim() !== '') req.timeoutSeconds = Number(f.timeoutSeconds);
    return req;
  }
  const port = (v: string, def: number) => (v.trim() === '' ? def : Number(v));
  const checks: CheckRequest[] = METHODS.filter((m) => f.methods.includes(m)).map((method): CheckRequest => {
    switch (method) {
      case 'dns':
        return { method, dns: { family: f.dnsFamily } };
      case 'tcp':
        return { method, port: Number(f.tcpPort), ...(f.tcpProxy ? { proxy: f.tcpProxy } : {}) };
      case 'udp': {
        const def = DEFAULT_UDP_PORTS[f.udpProtocol];
        return { method, port: def === undefined ? Number(f.udpPort) : port(f.udpPort, def), udp: { protocol: f.udpProtocol } };
      }
      case 'http':
        return { method, port: port(f.httpPort, DEFAULT_PORTS.http), http: { method: f.httpMethod, path: f.httpPath || '/' } };
      case 'https':
        return {
          method,
          port: port(f.httpsPort, DEFAULT_PORTS.https),
          http: { method: f.httpsMethod, path: f.httpsPath || '/', ...(f.httpsIgnoreTls ? { ignoreTlsErrors: true } : {}) },
          ...(f.httpsProxy ? { proxy: f.httpsProxy } : {}),
        };
      case 'ping':
        return { method, ping: { count: Number(f.pingCount) } };
      case 'traceroute':
        return { method, traceroute: { maxHops: Number(f.maxHops) } };
    }
  });
  const req: RunRequest = { namespace: f.namespace, target: f.target.trim(), checks };
  if (f.timeoutSeconds.trim() !== '') req.timeoutSeconds = Number(f.timeoutSeconds);
  return req;
}

/** Rebuilds the form from a previous run ("Run again"). */
export function formFromRun(run: Pick<RunDetail, 'request'>): RunForm {
  const f = emptyForm(run.request.namespace);
  f.target = run.request.target ?? '';
  if (run.request.mode === 'firewall') {
    const web = run.request.checks.find((c) => c.method === 'http' || c.method === 'https');
    f.mode = 'firewall';
    f.fwPort = String(run.request.checks.find((c) => c.method === 'tcp')?.port ?? web?.port ?? '');
    f.fwScheme = web ? (firewallScheme({ fwPort: f.fwPort, fwScheme: 'auto' }) === web.method ? 'auto' : (web.method as 'http' | 'https')) : 'auto';
    if (run.request.timeoutSeconds) f.timeoutSeconds = String(run.request.timeoutSeconds);
    return f;
  }
  if (run.request.timeoutSeconds) f.timeoutSeconds = String(run.request.timeoutSeconds);
  for (const c of run.request.checks ?? []) {
    if (!METHODS.includes(c.method) || f.methods.includes(c.method)) continue;
    f.methods.push(c.method);
    if (c.method === 'tcp' && c.port) f.tcpPort = String(c.port);
    if (c.method === 'tcp') f.tcpProxy = c.proxy ?? '';
    if (c.method === 'https') f.httpsProxy = c.proxy ?? '';
    if (c.method === 'udp') {
      f.udpProtocol = c.udp?.protocol ?? 'generic';
      if (c.port) f.udpPort = String(c.port);
    }
    if (c.method === 'http') {
      if (c.port) f.httpPort = String(c.port);
      f.httpMethod = c.http?.method ?? 'GET';
      f.httpPath = c.http?.path ?? '/';
    }
    if (c.method === 'https') {
      if (c.port) f.httpsPort = String(c.port);
      f.httpsMethod = c.http?.method ?? 'GET';
      f.httpsPath = c.http?.path ?? '/';
      f.httpsIgnoreTls = c.http?.ignoreTlsErrors ?? false;
    }
    if (c.method === 'dns' && c.dns) f.dnsFamily = c.dns.family;
    if (c.method === 'ping' && c.ping) f.pingCount = String(c.ping.count);
    if (c.method === 'traceroute' && c.traceroute) f.maxHops = String(c.traceroute.maxHops);
  }
  return f;
}

/**
 * Maps server field errors ("checks[2].port") to form fields, using the
 * submitted request to know which method each index refers to.
 */
export function mapServerErrors(details: FieldError[], req: RunRequest, text: (fe: FieldError) => string): FormErrors {
  const e: FormErrors = {};
  for (const d of details) {
    const m = /^checks\[(\d+)\](?:\.(.+))?$/.exec(d.field);
    let field: FormField = 'methods';
    if (d.field === 'target' || d.field === 'namespace' || d.field === 'timeoutSeconds') field = d.field;
    else if (m && req.mode === 'firewall' && m[2] === 'port') field = 'fwPort';
    else if (m) {
      const method = req.checks[Number(m[1])]?.method;
      const sub = m[2];
      if ((sub === 'port' || sub === 'udp.protocol') && (method === 'tcp' || method === 'udp' || method === 'http' || method === 'https')) field = `${method}Port`;
      else if (sub === 'http.path' && (method === 'http' || method === 'https')) field = `${method}Path`;
      else if (sub === 'proxy' && (method === 'tcp' || method === 'https')) field = `${method}Proxy`;
      else if (sub === 'ping.count') field = 'pingCount';
      else if (sub === 'traceroute.maxHops') field = 'maxHops';
    }
    e[field] ??= { text: text(d) };
  }
  return e;
}
