import type {
  AccessRule,
  AccessRuleInput,
  AdminNamespaces,
  ApiToken,
  ApiErrorBody,
  Catalog,
  DestinationPolicy,
  FieldError,
  Language,
  Me,
  NamespaceExclusions,
  NamespaceGrant,
  PolicyCheck,
  PolicyView,
  ProxiesView,
  Providers,
  Proxy,
  ProxyInput,
  RetentionView,
  RunDetail,
  RunRequest,
  RunStatus,
  RunSummary,
  SessionsResponse,
  Stats,
  SystemInfo,
  TrustedCAsView,
  CheckTypesView,
  UserInput,
  UserView,
} from '../types/api';

/**
 * API failure. `message` is the server's English text; the UI shows a
 * translation chosen by `code` (see errorText in components/errors.tsx).
 */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details: FieldError[] = [],
    readonly requestId?: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  get sessionExpired(): boolean {
    return this.status === 401 && this.code !== 'invalid_credentials';
  }
}

type Listener = (e: ApiError) => void;
let onSessionLost: Listener | undefined;

/** Registers the handler called when the session expires or a password change is required. */
export function setSessionListener(l: Listener | undefined): void {
  onSessionLost = l;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (init.body !== undefined) headers['Content-Type'] = 'application/json';
  let res: Response;
  try {
    res = await fetch(path, { credentials: 'same-origin', ...init, headers });
  } catch {
    throw new ApiError(0, 'network_error', 'could not reach the NetCheck API');
  }
  if (!res.ok) {
    let body: { error?: ApiErrorBody } | undefined;
    try {
      body = (await res.json()) as { error?: ApiErrorBody };
    } catch {
      body = undefined;
    }
    const e = body?.error;
    const err = new ApiError(res.status, e?.code ?? 'http_error', e?.message ?? `HTTP ${res.status}`, e?.details ?? [], e?.requestId);
    if (err.sessionExpired || err.code === 'password_change_required') onSessionLost?.(err);
    throw err;
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

const post = <T>(path: string, body: unknown = {}) => request<T>(path, { method: 'POST', body: JSON.stringify(body) });
const put = <T>(path: string, body: unknown) => request<T>(path, { method: 'PUT', body: JSON.stringify(body) });
const del = (path: string) => request<undefined>(path, { method: 'DELETE' });
const id = (s: string) => encodeURIComponent(s);

export interface ListRunsParams {
  namespace?: string;
  status?: RunStatus;
  pageSize?: number;
  cursor?: string;
}

export const api = {
  login: (username: string, password: string) => post<{ mustChangePassword: boolean }>('/api/v1/auth/login', { username, password }),
  logout: () => post<undefined>('/api/v1/auth/logout'),
  changePassword: (currentPassword: string, newPassword: string) => post<undefined>('/api/v1/auth/password', { currentPassword, newPassword }),
  me: () => request<Me>('/api/v1/me'),
  providers: () => request<Providers>('/api/v1/auth/providers'),
  tokens: {
    list: () => request<{ items: ApiToken[] }>('/api/v1/me/tokens'),
    create: (name: string, expiresInDays: number) => post<{ token: string; item: ApiToken }>('/api/v1/me/tokens', { name, expiresInDays }),
    revoke: (tokenId: string) => del(`/api/v1/me/tokens/${id(tokenId)}`),
  },
  /** Personal proxies: only the signed-in user sees and uses them. */
  myProxies: {
    list: () => request<ProxiesView>('/api/v1/proxies'),
    create: (p: ProxyInput) => post<Proxy>('/api/v1/proxies', p),
    update: (proxyId: string, p: ProxyInput) => put<Proxy>(`/api/v1/proxies/${id(proxyId)}`, p),
    remove: (proxyId: string) => del(`/api/v1/proxies/${id(proxyId)}`),
  },
  setLanguage: (language: Language) => put<{ language: Language }>('/api/v1/me/preferences', { language }),
  namespaces: () => request<{ items: NamespaceGrant[] }>('/api/v1/namespaces'),
  catalog: () => request<Catalog>('/api/v1/probes/catalog'),
  stats: (hours = 24) => request<Stats>(`/api/v1/stats?hours=${hours}`),
  createRun: (req: RunRequest) => post<{ id: string; status: RunStatus }>('/api/v1/runs', req),
  getRun: (runId: string) => request<RunDetail>(`/api/v1/runs/${id(runId)}`),
  listRuns: (p: ListRunsParams) => {
    const q = new URLSearchParams();
    if (p.namespace) q.set('namespace', p.namespace);
    if (p.status) q.set('status', p.status);
    if (p.pageSize) q.set('pageSize', String(p.pageSize));
    if (p.cursor) q.set('cursor', p.cursor);
    const qs = q.toString();
    return request<{ items: RunSummary[]; nextCursor: string }>(`/api/v1/runs${qs ? `?${qs}` : ''}`);
  },
  admin: {
    listUsers: () => request<{ items: UserView[] }>('/api/v1/admin/users'),
    getUser: (userId: string) => request<UserView>(`/api/v1/admin/users/${id(userId)}`),
    createUser: (u: UserInput) => post<UserView>('/api/v1/admin/users', u),
    updateUser: (userId: string, u: UserInput) => put<UserView>(`/api/v1/admin/users/${id(userId)}`, u),
    deleteUser: (userId: string) => del(`/api/v1/admin/users/${id(userId)}`),
    resetPassword: (userId: string, password: string) => post<undefined>(`/api/v1/admin/users/${id(userId)}/password`, { password }),
    unlock: (userId: string) => post<undefined>(`/api/v1/admin/users/${id(userId)}/unlock`),
    namespaces: () => request<AdminNamespaces>('/api/v1/admin/namespaces'),
    sessions: () => request<SessionsResponse>('/api/v1/admin/sessions'),
    revokeSession: (sessionId: string) => del(`/api/v1/admin/sessions/${id(sessionId)}`),
    system: () => request<SystemInfo>('/api/v1/admin/system'),
    namespaceExclusions: () => request<NamespaceExclusions>('/api/v1/admin/namespace-exclusions'),
    excludeNamespace: (name: string, reason: string) => post<undefined>('/api/v1/admin/namespace-exclusions', { name, reason }),
    includeNamespace: (name: string) => del(`/api/v1/admin/namespace-exclusions/${id(name)}`),
    policy: () => request<PolicyView>('/api/v1/admin/policy'),
    savePolicy: (p: DestinationPolicy) => put<PolicyView>('/api/v1/admin/policy', p),
    checkDestination: (target: string, port?: number) => post<PolicyCheck>('/api/v1/admin/policy/check', port ? { target, port } : { target }),
    trustedCAs: () => request<TrustedCAsView>('/api/v1/admin/trusted-cas'),
    saveTrustedCAs: (certificates: string[]) => put<TrustedCAsView>('/api/v1/admin/trusted-cas', { certificates }),
    checkTypes: () => request<CheckTypesView>('/api/v1/admin/check-types'),
    saveCheckTypes: (disabled: string[]) => put<CheckTypesView>('/api/v1/admin/check-types', { disabled }),
    proxies: () => request<ProxiesView>('/api/v1/admin/proxies'),
    createProxy: (p: ProxyInput) => post<Proxy>('/api/v1/admin/proxies', p),
    updateProxy: (proxyId: string, p: ProxyInput) => put<Proxy>(`/api/v1/admin/proxies/${id(proxyId)}`, p),
    deleteProxy: (proxyId: string) => del(`/api/v1/admin/proxies/${id(proxyId)}`),
    retention: () => request<RetentionView>('/api/v1/admin/retention'),
    saveRetention: (r: { outputDays: number; metadataDays: number }) => put<RetentionView>('/api/v1/admin/retention', r),
    accessRules: () => request<{ items: AccessRule[]; ssoEnabled: boolean }>('/api/v1/admin/access-rules'),
    createAccessRule: (r: AccessRuleInput) => post<AccessRule>('/api/v1/admin/access-rules', r),
    updateAccessRule: (ruleId: string, r: AccessRuleInput) => put<AccessRule>(`/api/v1/admin/access-rules/${id(ruleId)}`, r),
    deleteAccessRule: (ruleId: string) => del(`/api/v1/admin/access-rules/${id(ruleId)}`),
    tokens: () => request<{ items: ApiToken[] }>('/api/v1/admin/tokens'),
    revokeToken: (tokenId: string) => del(`/api/v1/admin/tokens/${id(tokenId)}`),
  },
};

export type Api = typeof api;
