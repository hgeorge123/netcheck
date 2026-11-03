import type { Translate } from '../../i18n';
import type { ExecutionView, RunDetail } from '../../types/api';

// Turns a blocked result into the two things the user asks for next: the
// NetworkPolicy the namespace owner would need, and a request for the
// firewall team. Both are built only from measured values (IPs, ports,
// categories); NetCheck never applies them.

/** Categories where packets got no answer: what a policy or firewall drop looks like. */
const BLOCKED = new Set(['timeout', 'dns_timeout', 'udp_no_reply', 'icmp_no_reply', 'no_route', 'network_unreachable', 'connection_reset']);

export const isBlocked = (c: ExecutionView) => c.status !== 'succeeded' && !!c.category && BLOCKED.has(c.category);

export const blockedChecks = (run: RunDetail) => run.checks.filter(isBlocked);

/** Whether egress NetworkPolicies of the source namespace also select the probe. */
export const hasEgressPolicies = (run: RunDetail) => !!run.fidelity?.egressPolicies.some((p) => p.selectsProbe);

const isIPv6 = (ip: string) => ip.includes(':');
const cidr = (ip: string) => `${ip}/${isIPv6(ip) ? 128 : 32}`;

function protocolOf(c: ExecutionView): 'TCP' | 'UDP' | undefined {
  if (c.method === 'tcp' || c.method === 'http' || c.method === 'https') return 'TCP';
  if (c.method === 'udp') return 'UDP';
  return undefined;
}

const ipsOf = (c: ExecutionView) => (c.usedIp ? [c.usedIp] : (c.result?.resolvedIps ?? c.resolvedIps ?? []));

const yamlName = (target: string) =>
  `allow-egress-${target.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'destination'}`;

/**
 * Egress NetworkPolicy that would let the namespace reach what the blocked
 * checks could not. Rules are grouped by destination IP; ICMP cannot be
 * expressed in a NetworkPolicy and is listed as a comment.
 */
export function suggestNetworkPolicy(run: RunDetail): string {
  const blocked = blockedChecks(run);
  const ports = new Map<string, Set<string>>(); // cidr -> "PROTO/port"
  const icmp = new Set<string>();
  let needsDNS = false;
  for (const c of blocked) {
    if (c.method === 'dns' || c.category === 'dns_timeout') needsDNS = true;
    const proto = protocolOf(c);
    for (const ip of ipsOf(c)) {
      if (!proto) {
        if (c.method === 'ping' || c.method === 'traceroute') icmp.add(ip);
        continue;
      }
      const port = c.result?.port;
      if (!port) continue;
      const key = cidr(ip);
      if (!ports.has(key)) ports.set(key, new Set());
      ports.get(key)?.add(`${proto}/${port}`);
    }
  }

  const lines = [
    '# Suggested by NetCheck from a blocked test. Review it before applying:',
    '# narrow podSelector to the labels of your application.',
    'apiVersion: networking.k8s.io/v1',
    'kind: NetworkPolicy',
    'metadata:',
    `  name: ${yamlName(run.target)}`,
    `  namespace: ${run.namespace}`,
    'spec:',
    '  podSelector: {}',
    '  policyTypes: [Egress]',
    '  egress:',
  ];
  if (needsDNS) {
    lines.push(
      '    # Cluster DNS',
      '    - to:',
      '        - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}',
      '          podSelector: {matchLabels: {k8s-app: kube-dns}}',
      '      ports:',
      '        - {port: 53, protocol: UDP}',
      '        - {port: 53, protocol: TCP}',
    );
  }
  for (const [block, set] of ports) {
    lines.push(`    # ${run.target}`, '    - to:', `        - ipBlock: {cidr: ${block}}`, '      ports:');
    for (const p of [...set].sort()) {
      const [proto, port] = p.split('/');
      lines.push(`        - {port: ${port}, protocol: ${proto}}`);
    }
  }
  if (icmp.size > 0) {
    lines.push(`    # ICMP (ping, traceroute) to ${[...icmp].join(', ')} cannot be allowed with a NetworkPolicy.`);
  }
  if (!needsDNS && ports.size === 0) {
    lines.push('    [] # nothing to allow: no blocked TCP or UDP destination was measured');
  }
  lines.push(
    '# For a Service inside the cluster, select the destination Pods with',
    '# namespaceSelector/podSelector instead of its ClusterIP.',
  );
  return lines.join('\n') + '\n';
}

/** Plain-text request for the firewall team, in the UI language. */
export function firewallRequest(run: RunDetail, t: Translate, formatDate: (iso?: string) => string): string {
  const src = run.checks.find((c) => c.podIp || c.nodeIp);
  const lines = [
    t('missing.req.title', { id: run.id.slice(0, 8) }),
    '',
    t('missing.req.source', { namespace: run.namespace, cluster: run.clusterId }),
  ];
  if (src?.podIp) lines.push(`  ${t('missing.req.podIp', { ip: src.podIp })}`);
  if (src?.nodeIp) lines.push(`  ${t('missing.req.nodeIp', { ip: src.nodeIp, node: src.nodeName ?? '' })}`);
  lines.push(`  ${t('missing.req.snat')}`, '', t('missing.req.blocked'));
  for (const c of blockedChecks(run)) {
    const proto = protocolOf(c) ?? (c.method === 'dns' ? 'DNS' : 'ICMP');
    const where = ipsOf(c).join(', ') || run.target;
    const port = c.result?.port ? `:${c.result.port}` : '';
    lines.push(`  - ${proto} ${where}${port} (${run.target}): ${t('missing.req.noAnswer', { ms: c.durationMs ?? 0, at: formatDate(c.startedAt) })}`);
  }
  const ok = run.checks.filter((c) => c.status === 'succeeded');
  if (ok.length > 0) {
    lines.push('', t('missing.req.working'));
    for (const c of ok) {
      const proto = protocolOf(c) ?? (c.method === 'dns' ? 'DNS' : 'ICMP');
      const port = c.result?.port ? `:${c.result.port}` : '';
      lines.push(`  - ${proto} ${ipsOf(c).join(', ') || run.target}${port}`);
    }
  }
  lines.push('', t('missing.req.evidence'));
  return lines.join('\n') + '\n';
}
