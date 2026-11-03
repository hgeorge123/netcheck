import { useEffect, useState } from 'react';

export type Route =
  | { page: 'dashboard' }
  | { page: 'new'; from?: string }
  | { page: 'history' }
  | { page: 'run'; id: string }
  | { page: 'password' }
  | { page: 'users' }
  | { page: 'user-new' }
  | { page: 'user-edit'; id: string }
  | { page: 'sessions' }
  | { page: 'system' }
  | { page: 'policy' }
  | { page: 'retention' }
  | { page: 'trusted-cas' }
  | { page: 'proxies' }
  | { page: 'my-proxies' }
  | { page: 'access-rules' }
  | { page: 'tokens' }
  | { page: 'admin-tokens' }
  | { page: 'namespaces' };

const runIdPattern = /^[a-z0-9]{8,40}$/;
const userIdPattern = /^u[a-f0-9]{24}$/;

export function parseHash(hash: string): Route {
  const [path = '', query = ''] = hash.replace(/^#/, '').split('?', 2);
  const run = /^\/runs\/([^/]+)$/.exec(path);
  if (run?.[1] && runIdPattern.test(run[1])) return { page: 'run', id: run[1] };
  const user = /^\/admin\/users\/([^/]+)$/.exec(path);
  if (user?.[1] === 'new') return { page: 'user-new' };
  if (user?.[1] && userIdPattern.test(user[1])) return { page: 'user-edit', id: user[1] };
  switch (path) {
    case '/new': {
      // "Run again" pre-fills the form from an existing run.
      const from = new URLSearchParams(query).get('from');
      return from && runIdPattern.test(from) ? { page: 'new', from } : { page: 'new' };
    }
    case '/runs':
      return { page: 'history' };
    case '/account/password':
      return { page: 'password' };
    case '/admin/users':
      return { page: 'users' };
    case '/admin/sessions':
      return { page: 'sessions' };
    case '/admin/system':
      return { page: 'system' };
    case '/admin/policy':
      return { page: 'policy' };
    case '/admin/retention':
      return { page: 'retention' };
    case '/admin/trusted-cas':
      return { page: 'trusted-cas' };
    case '/admin/proxies':
      return { page: 'proxies' };
    case '/admin/access-rules':
      return { page: 'access-rules' };
    case '/account/proxies':
      return { page: 'my-proxies' };
    case '/account/tokens':
      return { page: 'tokens' };
    case '/admin/tokens':
      return { page: 'admin-tokens' };
    case '/admin/namespaces':
      return { page: 'namespaces' };
    default:
      return { page: 'dashboard' };
  }
}

export function hrefFor(r: Route): string {
  switch (r.page) {
    case 'new':
      return r.from ? `#/new?from=${r.from}` : '#/new';
    case 'run':
      return `#/runs/${r.id}`;
    case 'history':
      return '#/runs';
    case 'password':
      return '#/account/password';
    case 'users':
      return '#/admin/users';
    case 'user-new':
      return '#/admin/users/new';
    case 'user-edit':
      return `#/admin/users/${r.id}`;
    case 'sessions':
      return '#/admin/sessions';
    case 'system':
      return '#/admin/system';
    case 'policy':
      return '#/admin/policy';
    case 'retention':
      return '#/admin/retention';
    case 'access-rules':
      return '#/admin/access-rules';
    case 'trusted-cas':
      return '#/admin/trusted-cas';
    case 'proxies':
      return '#/admin/proxies';
    case 'my-proxies':
      return '#/account/proxies';
    case 'tokens':
      return '#/account/tokens';
    case 'admin-tokens':
      return '#/admin/tokens';
    case 'namespaces':
      return '#/admin/namespaces';
    default:
      return '#/';
  }
}

export const isAdminRoute = (r: Route): boolean => ['users', 'user-new', 'user-edit', 'sessions', 'system', 'policy', 'retention', 'namespaces', 'access-rules', 'admin-tokens', 'trusted-cas', 'proxies'].includes(r.page);

export function useHashRoute(): [Route, (r: Route) => void] {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return [route, (r: Route) => (window.location.hash = hrefFor(r))];
}
