import { describe, expect, it } from 'vitest';
import { adminPermission, isAdminRoute, type Route } from './router';

describe('adminPermission', () => {
  it('keeps users, groups, roles and access rules with Administrator', () => {
    for (const page of ['users', 'user-new', 'groups', 'roles', 'access-rules'] as const) {
      expect(adminPermission({ page } as Route)).toBe('admin');
    }
    expect(adminPermission({ page: 'user-edit', id: 'u1' })).toBe('admin');
  });

  it('gives every other administration page its own permission', () => {
    const pages = ['namespaces', 'policy', 'check-types', 'trusted-cas', 'proxies', 'retention', 'sessions', 'admin-tokens', 'system'] as const;
    for (const page of pages) {
      const r = { page } as Route;
      expect(isAdminRoute(r) || page === 'admin-tokens').toBe(true);
      expect(adminPermission(r)).toMatch(/^admin\.[a-zA-Z]+$/);
    }
    expect(adminPermission({ page: 'new' })).toBeUndefined();
  });
});
