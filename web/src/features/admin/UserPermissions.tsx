import Box from '@cloudscape-design/components/box';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import { useEffect, useState } from 'react';
import { ErrorAlert } from '../../components/errors';
import { methodKey } from '../../components/status';
import { useI18n, type Translate } from '../../i18n';
import type { Api } from '../../services/api';
import type { UserPermissionsView } from '../../types/api';
import { permissionLabel } from './RolesPage';
import { roleLabel } from './roles';

/** Where a grant comes from, in words. */
function sourceText(t: Translate, source: string): string {
  if (source === 'account') return t('perms.source.account');
  if (source === 'authenticated') return t('perms.source.authenticated');
  const [kind, name] = [source.slice(0, source.indexOf(':')), source.slice(source.indexOf(':') + 1)];
  return kind === 'group' ? t('perms.source.group', { name }) : t('perms.source.user', { name });
}

/**
 * Effective permissions of a user: what it can do in each namespace and
 * where it comes from (its account or the access rules of single sign-on).
 * The reload key refreshes it after the form is saved.
 */
export function UserPermissions({ admin, userId, reload }: { admin: Api['admin']; userId: string; reload: number }) {
  const { t } = useI18n();
  const [view, setView] = useState<UserPermissionsView | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let alive = true;
    admin
      .userPermissions(userId)
      .then((v) => alive && setView(v))
      .catch((e: unknown) => alive && setError(e));
    return () => {
      alive = false;
    };
  }, [admin, userId, reload]);

  if (error) return <ErrorAlert error={error} />;
  const other = (view?.permissions ?? []).filter((p) => !p.startsWith('check.') && p !== 'mode.firewall');

  return (
    <Container header={<Header variant="h2" description={t('perms.description')}>{t('perms.title')}</Header>}>
      <SpaceBetween size="l">
        <Table
          variant="embedded"
          loading={view === null}
          loadingText={t('common.loading')}
          items={view?.grants ?? []}
          wrapLines
          header={<Header variant="h3">{t('perms.grants')}</Header>}
          columnDefinitions={[
            { id: 'role', header: t('users.form.role'), cell: (g) => <b>{roleLabel(t, g.role, g.roleName)}</b> },
            {
              id: 'ns',
              header: t('users.form.namespaces'),
              cell: (g) =>
                g.role === 'admin' || g.allNamespaces
                  ? t('users.all')
                  : [...g.namespaces, ...(g.allowNetcheckNamespace ? [t('rules.access.own')] : [])].join(', ') || '—',
            },
            { id: 'source', header: t('perms.source'), cell: (g) => sourceText(t, g.source) },
          ]}
        />
        <Table
          variant="embedded"
          loading={view === null}
          loadingText={t('common.loading')}
          items={view?.namespaces ?? []}
          wrapLines
          empty={<Box color="text-body-secondary">{t('perms.noNamespaces')}</Box>}
          header={<Header variant="h3">{t('perms.byNamespace')}</Header>}
          columnDefinitions={[
            { id: 'ns', header: t('users.form.namespaces'), width: 220, cell: (n) => n.name },
            {
              id: 'checks',
              header: t('perms.checks'),
              cell: (n) => (n.checks && n.checks.length > 0 ? n.checks.map((m) => t(methodKey(m))).join(', ') : <StatusIndicator type="stopped">{t('perms.noChecks')}</StatusIndicator>),
            },
            {
              id: 'fw',
              header: t('newTest.mode.firewall'),
              width: 200,
              cell: (n) => (n.firewallMode ? <StatusIndicator type="success">{t('checkTypes.on')}</StatusIndicator> : <StatusIndicator type="stopped">{t('checkTypes.off')}</StatusIndicator>),
            },
          ]}
        />
        <div>
          <Box variant="awsui-key-label">{t('perms.other')}</Box>
          <div>{view ? (view.admin ? t('roles.adminSummary') : other.map((p) => permissionLabel(t, p)).join(', ') || '—') : '…'}</div>
        </div>
      </SpaceBetween>
    </Container>
  );
}
