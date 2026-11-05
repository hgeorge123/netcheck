import type { Translate } from '../../i18n';
import type { ExecutionView, Method, RunDetail } from '../../types/api';

// Builds the single plain-text report for firewall tickets. Each block
// reproduces the layout of the usual command (date, hostname, ping,
// traceroute, telnet, curl) with the values MEASURED by the NetCheck probe;
// nothing is invented: unknown values are omitted, and the header states that
// the output comes from the NetCheck probe, not from those binaries.

// Values of the probe implementation (internal/probes/runner).
const ECHO_PAYLOAD = 14; // "netcheck-probe"
const USER_AGENT = 'netcheck-probe/1';

const HTTP_REASONS: Record<number, string> = {
  200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content', 301: 'Moved Permanently', 302: 'Found', 303: 'See Other',
  304: 'Not Modified', 307: 'Temporary Redirect', 308: 'Permanent Redirect', 400: 'Bad Request', 401: 'Unauthorized',
  403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed', 408: 'Request Timeout', 429: 'Too Many Requests',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout',
};

const isIPv6 = (ip?: string) => !!ip && ip.includes(':');
const ms = (v?: number) => (v === undefined ? '' : (Math.round(v * 1000) / 1000).toFixed(3));

/** `date` style: "Thu Oct 22 10:15:03 UTC 2026". */
export function unixDate(iso: string): string {
  const d = new Date(iso);
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const p = (n: number) => String(n).padStart(2, '0');
  return `${days[d.getUTCDay()]} ${months[d.getUTCMonth()]} ${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC ${d.getUTCFullYear()}`;
}

const dnsFailure = (c: ExecutionView) =>
  c.category === 'dns_nxdomain' || c.category === 'dns_no_address' ? 'Name or service not known' : 'Temporary failure in name resolution';
const isDNSFailure = (c: ExecutionView) => !!c.category?.startsWith('dns_');

function socketError(category?: string): string {
  switch (category) {
    case 'tcp_refused':
      return 'Connection refused';
    case 'timeout':
      return 'Connection timed out';
    case 'no_route':
      return 'No route to host';
    case 'network_unreachable':
      return 'Network is unreachable';
    case 'connection_reset':
      return 'Connection reset by peer';
    default:
      return category ?? 'error';
  }
}

function denied(c: ExecutionView, tool: string): string | undefined {
  if (c.category !== 'destination_denied') return undefined;
  return `${tool}: not executed: destination denied by the NetCheck policy (${c.error ?? ''})`.trim();
}

function ping(target: string, c: ExecutionView): string[] {
  const out = [`$ ping -c ${c.result?.ping?.transmitted ?? 4} ${target}`];
  const d = denied(c, 'ping');
  if (d) return [...out, d];
  if (c.category === 'icmp_not_permitted') return [...out, 'ping: socket: Operation not permitted'];
  if (isDNSFailure(c)) return [...out, `ping: ${target}: ${dnsFailure(c)}`];
  const p = c.result?.ping;
  const ip = c.usedIp ?? '';
  const total = ECHO_PAYLOAD + 8 + (isIPv6(ip) ? 40 : 20);
  out.push(`PING ${target} (${ip}) ${ECHO_PAYLOAD}(${total}) bytes of data.`);
  if (!p) return [...out, c.error ?? ''];
  for (const r of p.replies) {
    if (r.errorFrom || r.error) out.push(`From ${r.errorFrom ?? ip} icmp_seq=${r.seq} ${r.error ?? ''}`.trimEnd());
    else if (!r.lost) out.push(`${ECHO_PAYLOAD + 8} bytes from ${ip}: icmp_seq=${r.seq} time=${ms(r.rttMs)} ms`);
  }
  out.push('', `--- ${target} ping statistics ---`);
  out.push(`${p.transmitted} packets transmitted, ${p.received} received, ${Math.round(p.lossPercent)}% packet loss, time ${c.durationMs ?? 0}ms`);
  const rtts = p.replies.filter((r) => !r.lost && !r.error && r.rttMs !== undefined).map((r) => r.rttMs as number);
  if (rtts.length > 0) {
    const avg = rtts.reduce((a, b) => a + b, 0) / rtts.length;
    const mdev = Math.sqrt(rtts.reduce((a, b) => a + (b - avg) ** 2, 0) / rtts.length);
    out.push(`rtt min/avg/max/mdev = ${ms(Math.min(...rtts))}/${ms(avg)}/${ms(Math.max(...rtts))}/${ms(mdev)} ms`);
  }
  return out;
}

const unreachableFlag = (note?: string): string => {
  const code = /code (\d+)/.exec(note ?? '')?.[1];
  return ({ '0': ' !N', '1': ' !H', '2': ' !P', '3': '', '9': ' !X', '10': ' !X', '13': ' !X' } as Record<string, string>)[code ?? ''] ?? (note ? ` (${note})` : '');
};

function traceroute(target: string, c: ExecutionView): string[] {
  const tr = c.result?.traceroute;
  const out = [`$ traceroute -I -n -q 1 -m ${tr?.maxHops ?? 20} ${target}`];
  const d = denied(c, 'traceroute');
  if (d) return [...out, d];
  if (c.category === 'icmp_not_permitted') return [...out, 'socket: Operation not permitted'];
  if (isDNSFailure(c)) return [...out, `${target}: ${dnsFailure(c)}`];
  const ip = c.usedIp ?? '';
  out.push(`traceroute to ${target} (${ip}), ${tr?.maxHops ?? 20} hops max, ${ECHO_PAYLOAD + 8 + (isIPv6(ip) ? 40 : 20)} byte packets`);
  for (const h of tr?.hops ?? []) {
    const n = String(h.ttl).padStart(2, ' ');
    out.push(h.address ? `${n}  ${h.address}  ${ms(h.rttMs)} ms${unreachableFlag(h.note)}` : `${n}  *`);
  }
  return out;
}

function telnet(target: string, port: number, c: ExecutionView): string[] {
  const out = [`$ telnet ${target} ${port}`];
  const d = denied(c, 'telnet');
  if (d) return [...out, d];
  if (isDNSFailure(c)) return [...out, `telnet: could not resolve ${target}/${port}: ${dnsFailure(c)}`];
  out.push(`Trying ${c.usedIp ?? target}...`);
  if (c.status === 'succeeded') return [...out, `Connected to ${target}.`, "Escape character is '^]'.", 'Connection closed.'];
  return [...out, `telnet: Unable to connect to remote host: ${socketError(c.category)}`];
}

function curl(target: string, port: number, method: Method, c: ExecutionView, path: string): string[] {
  const scheme = method === 'https' ? 'https' : 'http';
  const hostPart = isIPv6(target) && !target.startsWith('[') ? `[${target}]` : target;
  const url = `${scheme}://${hostPart}:${port}${path}`;
  const out = [`$ curl -v ${url}`];
  const d = denied(c, 'curl');
  if (d) return [...out, d];
  if (isDNSFailure(c)) return [...out, `* Could not resolve host: ${target}`, `curl: (6) Could not resolve host: ${target}`];
  const ip = c.usedIp ?? target;
  const h = c.result?.http;
  const after = c.durationMs ?? 0;
  out.push(`*   Trying ${isIPv6(ip) ? `[${ip}]` : ip}:${port}...`);
  switch (c.category) {
    case 'tcp_refused':
    case 'no_route':
    case 'network_unreachable':
      return [...out, `* connect to ${ip} port ${port} failed: ${socketError(c.category)}`, `curl: (7) Failed to connect to ${target} port ${port} after ${after} ms: ${socketError(c.category)}`];
    case 'timeout':
      if (h?.connectMs === undefined) return [...out, `curl: (28) Failed to connect to ${target} port ${port} after ${after} ms: Timeout was reached`];
      break;
  }
  out.push(`* Connected to ${target} (${ip}) port ${port}`);
  if (c.category === 'tls_cert_failure') return [...out, `curl: (60) SSL certificate problem: ${c.error ?? 'certificate verify failed'}`];
  if (c.category === 'tls_handshake_failure') return [...out, `curl: (35) ${c.error ?? 'TLS handshake failure'}`];
  if (h?.tlsVersion) {
    out.push(`* SSL connection using ${h.tlsVersion.replace(/^TLS /, 'TLSv')}`, '* Server certificate:');
    if (h.tlsPeerCn) out.push(`*  subject: CN=${h.tlsPeerCn}`);
    if (h.tlsNotAfter) out.push(`*  expire date: ${unixDate(h.tlsNotAfter)}`);
  }
  out.push(`> ${h?.method ?? 'GET'} ${path} HTTP/1.1`, `> Host: ${hostPart}${(scheme === 'https' && port === 443) || (scheme === 'http' && port === 80) ? '' : `:${port}`}`, `> User-Agent: ${USER_AGENT}`, '>');
  if (c.category === 'timeout') return [...out, `curl: (28) Operation timed out after ${after} milliseconds with 0 bytes received`];
  if (c.category === 'connection_reset') return [...out, 'curl: (56) Recv failure: Connection reset by peer'];
  if (c.category === 'http_protocol_error') return [...out, `curl: (8) Weird server reply${c.error ? `: ${c.error}` : ''}`];
  if (h?.statusCode !== undefined) {
    out.push(`< ${h.proto ?? 'HTTP/1.1'} ${h.statusCode} ${HTTP_REASONS[h.statusCode] ?? ''}`.trimEnd());
    if (h.location) out.push(`< Location: ${h.location}`);
    out.push('<');
  } else if (c.error) {
    out.push(`curl: ${c.error}`);
  }
  return out;
}

/** Plain-text report of a firewall-mode run (see buildRequest in validation.ts). */
export function buildFirewallReport(run: RunDetail, t: Translate, formatDate: (iso?: string) => string): string {
  const find = (m: Method) => run.checks.find((c) => c.method === m);
  const any = run.checks.find((c) => c.podName || c.nodeIp || c.podIp) ?? run.checks[0];
  const tcp = find('tcp');
  const web = find('https') ?? find('http');
  const port = run.request.checks.find((c) => c.method === 'tcp')?.port ?? run.request.checks.find((c) => c.port)?.port ?? 0;
  const path = run.request.checks.find((c) => c.method === 'http' || c.method === 'https')?.http?.path ?? '/';
  const started = run.checks.map((c) => c.startedAt).filter((s): s is string => !!s).sort()[0] ?? run.startedAt ?? run.createdAt;
  const target = run.target;

  const lines: string[] = [
    `===== ${t('fw.reportTitle')} =====`,
    t('fw.reportIntro'),
    `${t('fw.destination')}: ${target}:${port}    ${t('run.id')}: ${run.id}`,
    `${t('run.actor')}: ${run.actor}    ${t('run.created')}: ${formatDate(run.createdAt)}`,
    '',
    `# ${t('fw.source')}`,
    `#   ${t('fw.cluster')}: ${run.clusterId}    ${t('fw.namespace')}: ${run.namespace}`,
    `#   ${t('fw.pod')}: ${any?.podName || '—'}    IP: ${any?.podIp || '—'}`,
    `#   ${t('fw.node')}: ${any?.nodeName || '—'}    IP: ${any?.nodeIp || '—'}`,
    `#   ${t('fw.snat', { node: any?.nodeIp || '—', pod: any?.podIp || '—' })}`,
    '',
    '$ date',
    unixDate(started),
    '',
    '$ hostname',
    any?.podName || '—',
  ];
  // A part missing from the run was disabled by an administrator.
  const blocks: [string, ExecutionView | undefined, (c: ExecutionView) => string[]][] = [
    ['ping', find('ping'), (c) => ping(target, c)],
    ['traceroute', find('traceroute'), (c) => traceroute(target, c)],
    ['telnet', tcp, (c) => telnet(target, port, c)],
    ['curl', web, (c) => curl(target, port, c.method, c, path)],
  ];
  for (const [tool, c, render] of blocks) {
    lines.push('', ...(c ? render(c) : [`# ${tool}: ${t('fw.notRun')}`]));
  }
  return lines.join('\n') + '\n';
}

/** curl protocol for a port when the user leaves it on automatic. */
export const autoScheme = (port: number): 'http' | 'https' => (port === 443 || port === 8443 ? 'https' : 'http');
