import { useEffect, useState } from 'react';
import type { Translate } from '../../i18n';
import type { Api } from '../../services/api';
import type { RoleView } from '../../types/api';

/** The custom roles, for the role choice of users and access rules. */
export function useCustomRoles(admin: Api['admin']): RoleView[] {
  const [roles, setRoles] = useState<RoleView[]>([]);
  useEffect(() => {
    let alive = true;
    admin
      .roles()
      .then((v) => alive && setRoles(v.roles.filter((r) => !r.builtin)))
      .catch(() => {
        // Without the list only the built-in roles are offered.
      });
    return () => {
      alive = false;
    };
  }, [admin]);
  return roles;
}

/** Display name of a role: built-in ones are translated. */
export function roleLabel(t: Translate, role: string, name?: string): string {
  if (role === 'admin') return t('users.form.role.admin');
  if (role === 'user') return t('users.form.role.user');
  return name || role;
}

/** Short description of a custom role for a choice list. */
export function roleSummary(t: Translate, r: RoleView): string {
  if (r.description) return r.description;
  return t('roles.permissionCount', { n: r.permissions.length });
}
