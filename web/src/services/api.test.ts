import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseHash } from '../app/router';
import { ApiError, api, setSessionListener } from './api';

afterEach(() => vi.unstubAllGlobals());

function stubFetch(status: number, body: unknown) {
  const fn = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })));
  vi.stubGlobal('fetch', fn);
  return fn;
}

describe('api client', () => {
  it('sends JSON with same-origin credentials', async () => {
    const fn = stubFetch(202, { id: 'abc', status: 'queued' });
    await api.createRun({ namespace: 'payments', target: '10.0.0.1', checks: [{ method: 'tcp', port: 443 }] });
    const [url, init] = fn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/runs');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('same-origin');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
  });

  it('maps error envelopes to ApiError', async () => {
    stubFetch(400, { error: { code: 'validation_failed', message: 'the request is not valid', details: [{ field: 'port', code: 'required', message: 'x' }], requestId: 'r1' } });
    const err = await api.getRun('abcdef0123456789').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 400, code: 'validation_failed', requestId: 'r1' });
    expect((err as ApiError).details).toHaveLength(1);
  });

  it('flags expired sessions and notifies the listener', async () => {
    const listener = vi.fn();
    setSessionListener(listener);
    stubFetch(401, { error: { code: 'unauthenticated', message: 'x' } });
    const err = (await api.me().catch((e: unknown) => e)) as ApiError;
    expect(err.sessionExpired).toBe(true);
    expect(listener).toHaveBeenCalledTimes(1);
    setSessionListener(undefined);
  });

  it('does not treat bad credentials as an expired session', async () => {
    const listener = vi.fn();
    setSessionListener(listener);
    stubFetch(401, { error: { code: 'invalid_credentials', message: 'invalid username or password' } });
    const err = (await api.login('a', 'b').catch((e: unknown) => e)) as ApiError;
    expect(err.sessionExpired).toBe(false);
    expect(err.message).toBe('invalid username or password');
    expect(listener).not.toHaveBeenCalled();
    setSessionListener(undefined);
  });

  it('sends DELETE without a body and handles 204', async () => {
    const fn = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fn);
    await expect(api.admin.deleteUser('u1')).resolves.toBeUndefined();
    const [, init] = fn.mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe('DELETE');
    expect(init.body).toBeUndefined();
  });

  it('reports network failures', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('failed')));
    const err = (await api.me().catch((e: unknown) => e)) as ApiError;
    expect(err.code).toBe('network_error');
  });

  it('saves the language preference and calls the admin endpoints', async () => {
    const fn = stubFetch(200, { language: 'es' });
    await api.setLanguage('es');
    const [url, init] = fn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/me/preferences');
    expect(init.method).toBe('PUT');
    expect(init.body).toBe('{"language":"es"}');
    await api.admin.revokeSession('s 1');
    expect(fn.mock.calls[1]![0]).toBe('/api/v1/admin/sessions/s%201');
    expect((fn.mock.calls[1]![1] as RequestInit).method).toBe('DELETE');
  });

  it('encodes list filters', async () => {
    const fn = stubFetch(200, { items: [], nextCursor: '' });
    await api.listRuns({ namespace: 'payments', status: 'failed', pageSize: 20, cursor: 'a b' });
    expect(fn.mock.calls[0]![0]).toBe('/api/v1/runs?namespace=payments&status=failed&pageSize=20&cursor=a+b');
  });
});

describe('router', () => {
  it('parses known routes and ignores malformed ids', () => {
    expect(parseHash('#/runs/abcdef0123456789')).toEqual({ page: 'run', id: 'abcdef0123456789' });
    expect(parseHash('#/runs')).toEqual({ page: 'history' });
    expect(parseHash('#/runs/<script>')).toEqual({ page: 'dashboard' });
    expect(parseHash('')).toEqual({ page: 'dashboard' });
    expect(parseHash('#/new')).toEqual({ page: 'new' });
    expect(parseHash('#/new?from=abcdef0123456789')).toEqual({ page: 'new', from: 'abcdef0123456789' });
    expect(parseHash('#/new?from=../x')).toEqual({ page: 'new' });
    expect(parseHash('#/admin/sessions')).toEqual({ page: 'sessions' });
    expect(parseHash('#/admin/system')).toEqual({ page: 'system' });
    expect(parseHash('#/admin/policy')).toEqual({ page: 'policy' });
    expect(parseHash('#/admin/namespaces')).toEqual({ page: 'namespaces' });
    expect(parseHash('#/admin/users')).toEqual({ page: 'users' });
    expect(parseHash('#/admin/users/new')).toEqual({ page: 'user-new' });
    expect(parseHash('#/admin/users/u0123456789abcdef01234567')).toEqual({ page: 'user-edit', id: 'u0123456789abcdef01234567' });
    expect(parseHash('#/admin/users/../../x')).toEqual({ page: 'dashboard' });
    expect(parseHash('#/account/password')).toEqual({ page: 'password' });
  });
});
