// Mirrors the JSON contract of the Go API (/api/v1). Keep in sync with
// internal/api/*.go and internal/probes/types.go (schema netcheck.probe/v2).

export type Method = 'dns' | 'tcp' | 'udp' | 'http' | 'https' | 'ping' | 'traceroute';
export const METHODS: Method[] = ['dns', 'tcp', 'udp', 'http', 'https', 'ping', 'traceroute'];

/** UDP checks only send fixed datagrams: generic, a DNS query or an NTP request. */
export type UDPProtocol = 'generic' | 'dns' | 'ntp';
export const UDP_PROTOCOLS: UDPProtocol[] = ['generic', 'dns', 'ntp'];
export type RunStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled' | 'infra_error';
export const RUN_STATUSES: RunStatus[] = ['queued', 'running', 'succeeded', 'failed', 'cancelled', 'infra_error'];
export type CheckStatus = RunStatus | 'timed_out';
export type Severity = 'success' | 'info' | 'warning' | 'error';
export type Role = 'admin' | 'user';
export type ScopeMode = 'all' | 'list';
export type Language = 'en' | 'es';

export interface NamespaceGrant {
  name: string;
  canRun: boolean;
}

export interface Me {
  id: string;
  username: string;
  display: string;
  role: Role;
  allNamespaces: boolean;
  mustChangePassword: boolean;
  namespaces: NamespaceGrant[];
  clusterId: string;
  namespaceScope: ScopeMode;
  language: Language | '';
  allowNetcheckNamespace: boolean;
  version: string;
  /** 'oidc': single sign-on account, without a NetCheck password. */
  source: AccountSource;
}

export type AccountSource = 'local' | 'oidc';

export interface Providers {
  oidc: { enabled: boolean; name?: string };
}

export type RuleSubject = 'group' | 'user' | 'authenticated';

export interface AccessRuleInput {
  subjectType: RuleSubject;
  subject: string;
  role: Role;
  allNamespaces: boolean;
  allowNetcheckNamespace: boolean;
  namespaces: string[];
}

export interface AccessRule extends AccessRuleInput {
  id: string;
  updatedAt: string;
  updatedBy: string;
}

export interface UserView {
  id: string;
  username: string;
  displayName: string;
  role: Role;
  allNamespaces: boolean;
  namespaces: string[];
  disabled: boolean;
  locked: boolean;
  lockedUntil?: string;
  mustChangePassword: boolean;
  createdAt: string;
  lastLoginAt?: string;
  passwordChangedAt: string;
  language: string;
  allowNetcheckNamespace: boolean;
  source: AccountSource;
  /** Groups of the last SSO sign-in. */
  groups: string[];
}

export interface UserInput {
  username?: string;
  displayName: string;
  role: Role;
  password?: string;
  allNamespaces: boolean;
  namespaces: string[];
  disabled: boolean;
  allowNetcheckNamespace: boolean;
}

export interface CatalogEntry {
  method: Method;
  label: string;
  description: string;
  requiresPort: boolean;
  defaultPort?: number;
  hostnameOnly: boolean;
}

export interface Limits {
  maxChecks: number;
  defaultCheckTimeoutSeconds: number;
  maxCheckTimeoutSeconds: number;
  maxJobSeconds: number;
  settleSeconds: number;
}

export interface Catalog {
  items: CatalogEntry[];
  limits: Limits;
}

export interface CheckRequest {
  method: Method;
  port?: number;
  dns?: { family: 'ip' | 'ip4' | 'ip6' };
  http?: { method?: 'GET' | 'HEAD'; path?: string };
  udp?: { protocol: UDPProtocol };
  ping?: { count: number };
  traceroute?: { maxHops: number };
}

export interface RunRequest {
  /** 'firewall': created by the firewall-ticket form (single report). */
  mode?: 'firewall';
  namespace: string;
  target: string;
  timeoutSeconds?: number;
  checks: CheckRequest[];
}

export interface RunSummary {
  id: string;
  createdAt: string;
  finishedAt?: string;
  actor: string;
  namespace: string;
  target: string;
  status: RunStatus;
  failureCategory?: string;
}

export interface Diagnosis {
  category: string;
  severity: Severity;
  summary: string;
  detail: string;
  conclusive: boolean;
  httpStatus?: number;
}

export interface HTTPResult {
  url: string;
  method: string;
  statusCode?: number;
  proto?: string;
  location?: string;
  tlsVersion?: string;
  tlsPeerCn?: string;
  tlsNotAfter?: string;
  connectMs?: number;
  tlsMs?: number;
  firstByteMs?: number;
}

export interface UDPResult {
  protocol: UDPProtocol;
  attempts: number;
  replyBytes?: number;
  rttMs?: number;
  dnsRcode?: string;
  dnsAnswers?: number;
  ntpStratum?: number;
  ntpReference?: string;
  ntpOffsetMs?: number;
}

export interface PingReply {
  seq: number;
  rttMs?: number;
  lost?: boolean;
  errorFrom?: string;
  error?: string;
}

export interface PingResult {
  transmitted: number;
  received: number;
  lossPercent: number;
  minMs?: number;
  avgMs?: number;
  maxMs?: number;
  replies: PingReply[];
}

export interface TracerouteHop {
  ttl: number;
  address?: string;
  rttMs?: number;
  note?: string;
}

export interface TracerouteResult {
  protocol: string;
  maxHops: number;
  reached: boolean;
  hops: TracerouteHop[];
}

export interface CheckResultDetail {
  resolvedIps?: string[];
  deniedIps?: string[];
  usedIp?: string;
  port?: number;
  dns?: { cname?: string; addresses?: string[]; family: string };
  http?: HTTPResult;
  udp?: UDPResult;
  ping?: PingResult;
  traceroute?: TracerouteResult;
}

export interface ExecutionView {
  checkId: string;
  method: Method;
  status: CheckStatus;
  category?: string;
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  exitCode?: number;
  output: string;
  error?: string;
  equivalentArgv: string[];
  resolvedIps: string[];
  usedIp?: string;
  podIp?: string;
  nodeName?: string;
  nodeIp?: string;
  podName?: string;
  jobName?: string;
  diagnosis?: Diagnosis;
  result?: CheckResultDetail;
}

export interface PolicyRef {
  name: string;
  podSelector: string;
  selectsProbe: boolean;
}

export type FidelityLevel = 'namespace-wide-likely' | 'specific-selectors-detected' | 'no-native-egress-policies' | 'unknown';

export interface Fidelity {
  level: FidelityLevel;
  egressPolicies: PolicyRef[];
  notes: string[];
}

export interface RunDetail extends RunSummary {
  clusterId: string;
  startedAt?: string;
  actorId: string;
  jobName?: string;
  errorMessage?: string;
  request: RunRequest;
  fidelity?: Fidelity;
  checks: ExecutionView[];
}

export interface Stats {
  hours: number;
  total: number;
  byStatus: Partial<Record<RunStatus, number>>;
  byMethodStatus: Partial<Record<Method, Partial<Record<CheckStatus, number>>>>;
}

export interface SessionView {
  id: string;
  userId: string;
  username: string;
  displayName: string;
  role: Role;
  signedInAt: string;
  lastSeenAt: string;
  expiresAt: string;
  clientIp: string;
  userAgent: string;
  current: boolean;
}

export interface SessionsResponse {
  items: SessionView[];
  connectedUsers: number;
  idleTimeoutMinutes: number;
}

export interface VersionView {
  version: string;
  commit: string;
  buildDate: string;
  image: string;
  probeImage: string;
  chartVersion: string;
  firstSeenAt: string;
  lastStartedAt: string;
  starts: number;
}

export interface PortRange {
  from: number;
  to: number;
}

export interface SystemInfo {
  current: VersionView;
  history: VersionView[];
  clusterId: string;
  namespaceScope: ScopeMode;
  netcheckNamespace: string;
  protectPlatformDestinations: boolean;
  limits: Omit<Limits, 'defaultCheckTimeoutSeconds'>;
  destinations: DestinationPolicy;
  destinationsManagedBy: 'ui' | 'helm';
  retention: RetentionView;
}

export interface RetentionView {
  outputDays: number;
  metadataDays: number;
  updatedAt: string;
  updatedBy: string;
}

export interface DestinationPolicy {
  allowCidrs: string[];
  denyCidrs: string[];
  allowHostnameSuffixes: string[];
  allowPorts: PortRange[];
}

export interface PolicyView {
  policy: DestinationPolicy;
  platformDenies: string[];
  protectPlatformDestinations: boolean;
  managedBy: 'ui' | 'helm';
  editable: boolean;
  updatedAt: string;
  updatedBy: string;
}

export interface PolicyCheck {
  allowed: boolean;
  reason: string;
  isIp: boolean;
}

export type NamespaceStatus = 'available' | 'excluded_web' | 'excluded_helm' | 'system' | 'netcheck';

export interface NamespaceRow {
  name: string;
  status: NamespaceStatus;
  exists: boolean;
  reason?: string;
  excludedBy?: string;
  excludedAt?: string;
}

export interface NamespaceExclusions {
  items: NamespaceRow[];
  mode: ScopeMode;
  helmExcluded: string[];
}

export interface AdminNamespaces {
  items: string[];
  mode: ScopeMode;
  netcheckNamespace: string;
}

export interface FieldError {
  field: string;
  code: string;
  message: string;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  details?: FieldError[];
  requestId?: string;
}
