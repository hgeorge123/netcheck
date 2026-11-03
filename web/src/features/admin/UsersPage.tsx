import { useCollection } from '@cloudscape-design/collection-hooks';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import CollectionPreferences from '@cloudscape-design/components/collection-preferences';
import CopyToClipboard from '@cloudscape-design/components/copy-to-clipboard';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Modal from '@cloudscape-design/components/modal';
import Pagination from '@cloudscape-design/components/pagination';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';
import { useCallback, useEffect, useState } from 'react';
import { ErrorAlert, errorText } from '../../components/errors';
import { useI18n } from '../../i18n';
import type { Api } from '../../services/api';
import type { UserView } from '../../types/api';
import { generatePassword, MIN_PASSWORD_LENGTH } from '../auth/password';

interface Props {
  admin: Api['admin'];
  currentUserId: string;
  onCreate: () => void;
  onEdit: (id: string) => void;
  notify: (type: 'success' | 'error', message: string) => void;
}

function UserStatus({ u }: { u: UserView }) {
  const { t } = useI18n();
  if (u.disabled) return <StatusIndicator type="stopped">{t('users.status.disabled')}</StatusIndicator>;
  if (u.locked) return <StatusIndicator type="warning">{t('users.status.locked')}</StatusIndicator>;
  if (u.mustChangePassword) return <StatusIndicator type="pending">{t('users.status.temporary')}</StatusIndicator>;
  return <StatusIndicator type="success">{t('users.status.active')}</StatusIndicator>;
}

export function UsersPage({ admin, currentUserId, onCreate, onEdit, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [users, setUsers] = useState<UserView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [pageSize, setPageSize] = useState(20);
  const [resetFor, setResetFor] = useState<UserView | null>(null);
  const [resetPassword, setResetPassword] = useState('');
  const [resetError, setResetError] = useState<string | null>(null);
  const [deleteFor, setDeleteFor] = useState<UserView | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    admin
      .listUsers()
      .then((r) => {
        setUsers(r.items);
        setError(null);
      })
      .catch((err: unknown) => setError(err))
      .finally(() => setLoading(false));
  }, [admin]);

  useEffect(load, [load]);

  const { items, collectionProps, filterProps, paginationProps, filteredItemsCount, actions } = useCollection(users, {
    filtering: {
      filteringFunction: (u, text) => {
        const q = text.trim().toLowerCase();
        return !q || u.username.includes(q) || u.displayName.toLowerCase().includes(q) || u.namespaces.some((n) => n.includes(q));
      },
      empty: <Box textAlign="center">{t('users.empty')}</Box>,
      noMatch: (
        <Box textAlign="center">
          <SpaceBetween size="xs">
            <b>{t('common.noMatches')}</b>
            <Button onClick={() => actions.setFiltering('')}>{t('common.clearFilter')}</Button>
          </SpaceBetween>
        </Box>
      ),
    },
    pagination: { pageSize },
    sorting: { defaultState: { sortingColumn: { sortingField: 'username' } } },
    selection: { keepSelection: false, trackBy: 'id' },
  });
  const sel = collectionProps.selectedItems?.[0];
  const name = (u: UserView) => u.username;

  const run = async (fn: () => Promise<void>, ok: string) => {
    setBusy(true);
    try {
      await fn();
      notify('success', ok);
      load();
      return true;
    } catch (err) {
      notify('error', errorText(t, err));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const onAction = (id: string) => {
    if (!sel) return;
    if (id === 'edit') onEdit(sel.id);
    if (id === 'reset') {
      setResetPassword(generatePassword());
      setResetError(null);
      setResetFor(sel);
    }
    if (id === 'unlock') void run(() => admin.unlock(sel.id), t('users.unlocked', { name: name(sel) }));
    if (id === 'delete') setDeleteFor(sel);
  };

  return (
    <SpaceBetween size="m">
      {error ? <ErrorAlert error={error} header={t('users.loadFailed')} /> : null}
      <Table
        {...collectionProps}
        variant="full-page"
        stickyHeader
        items={items}
        loading={loading}
        loadingText={t('common.loading')}
        trackBy="id"
        selectionType="single"
        ariaLabels={{ selectionGroupLabel: t('users.title'), itemSelectionLabel: (_, u) => u.username }}
        header={
          <Header
            variant="awsui-h1-sticky"
            counter={`(${users.length})`}
            description={t('users.description')}
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button iconName="refresh" ariaLabel={t('common.refresh')} onClick={load} />
                <ButtonDropdown
                  disabled={!sel || busy}
                  onItemClick={({ detail }) => onAction(detail.id)}
                  items={[
                    { id: 'edit', text: t('users.action.edit') },
                    { id: 'reset', text: t('users.action.reset'), disabled: sel?.source === 'oidc' },
                    { id: 'unlock', text: t('users.action.unlock'), disabled: !sel?.locked },
                    { id: 'delete', text: t('users.action.delete'), disabled: sel?.id === currentUserId },
                  ]}
                >
                  {t('common.actions')}
                </ButtonDropdown>
                <Button variant="primary" onClick={onCreate}>
                  {t('users.create')}
                </Button>
              </SpaceBetween>
            }
          >
            {t('users.title')}
          </Header>
        }
        filter={
          <TextFilter
            {...filterProps}
            filteringPlaceholder={t('users.filter')}
            filteringAriaLabel={t('users.filter')}
            countText={filterProps.filteringText ? t('common.items', { n: filteredItemsCount ?? 0 }) : undefined}
          />
        }
        pagination={
          <Pagination
            {...paginationProps}
            ariaLabels={{ nextPageLabel: t('common.next'), previousPageLabel: t('common.previous'), pageLabel: (n) => t('common.page', { n }) }}
          />
        }
        preferences={
          <CollectionPreferences
            title={t('common.preferences')}
            confirmLabel={t('common.save')}
            cancelLabel={t('common.cancel')}
            preferences={{ pageSize }}
            onConfirm={({ detail }) => setPageSize(detail.pageSize ?? 20)}
            pageSizePreference={{ title: t('common.pageSize'), options: [10, 20, 50].map((n) => ({ value: n, label: t('common.items', { n }) })) }}
          />
        }
        columnDefinitions={[
          {
            id: 'username',
            header: t('users.col.username'),
            sortingField: 'username',
            cell: (u) => (
              <Box fontWeight="bold">
                {u.username}
                {u.id === currentUserId ? ` ${t('users.you')}` : ''}
              </Box>
            ),
          },
          { id: 'display', header: t('users.col.name'), sortingField: 'displayName', cell: (u) => u.displayName || '—' },
          {
            id: 'role',
            header: t('users.col.role'),
            sortingField: 'role',
            cell: (u) => <Badge color={u.role === 'admin' ? 'blue' : 'grey'}>{t(u.role === 'admin' ? 'nav.role.admin' : 'nav.role.user')}</Badge>,
          },
          {
            id: 'namespaces',
            header: t('users.col.namespaces'),
            cell: (u) => (
              <SpaceBetween direction="horizontal" size="xxs">
                {u.role === 'admin' || u.allNamespaces ? <Badge color="green">{t('users.all')}</Badge> : <span>{u.namespaces.join(', ') || '—'}</span>}
                {u.allowNetcheckNamespace && <Badge color="red">NetCheck</Badge>}
              </SpaceBetween>
            ),
          },
          {
            id: 'source',
            header: t('users.col.source'),
            cell: (u) => (u.source === 'oidc' ? <Badge color="severity-low">{t('users.source.oidc')}</Badge> : t('users.source.local')),
          },
          { id: 'status', header: t('users.col.status'), cell: (u) => <UserStatus u={u} /> },
          { id: 'login', header: t('users.col.lastLogin'), sortingField: 'lastLoginAt', cell: (u) => (u.lastLoginAt ? formatDate(u.lastLoginAt) : t('common.never')) },
        ]}
      />

      <Modal
        visible={resetFor !== null}
        onDismiss={() => setResetFor(null)}
        header={t('users.reset.title', { name: resetFor?.username ?? '' })}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setResetFor(null)}>
                {t('common.cancel')}
              </Button>
              <Button
                variant="primary"
                loading={busy}
                onClick={() => {
                  if (!resetFor) return;
                  if ([...resetPassword].length < MIN_PASSWORD_LENGTH) {
                    setResetError(t('password.tooShort', { n: MIN_PASSWORD_LENGTH }));
                    return;
                  }
                  void run(() => admin.resetPassword(resetFor.id, resetPassword), t('users.resetDone', { name: name(resetFor) })).then(
                    (ok) => ok && setResetFor(null),
                  );
                }}
              >
                {t('users.reset.submit')}
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box>{t('users.reset.body')}</Box>
          <FormField
            label={t('users.form.tempPassword')}
            errorText={resetError}
            secondaryControl={
              <SpaceBetween direction="horizontal" size="xs">
                <Button onClick={() => setResetPassword(generatePassword())}>{t('password.generate')}</Button>
                <CopyToClipboard variant="icon" textToCopy={resetPassword} copySuccessText={t('common.copied')} copyErrorText={t('common.copyFailed')} />
              </SpaceBetween>
            }
          >
            <Input value={resetPassword} onChange={({ detail }) => setResetPassword(detail.value)} ariaLabel={t('users.form.tempPassword')} />
          </FormField>
        </SpaceBetween>
      </Modal>

      <Modal
        visible={deleteFor !== null}
        onDismiss={() => setDeleteFor(null)}
        header={t('users.delete.title', { name: deleteFor?.username ?? '' })}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setDeleteFor(null)}>
                {t('common.cancel')}
              </Button>
              <Button
                variant="primary"
                loading={busy}
                onClick={() => {
                  if (!deleteFor) return;
                  void run(() => admin.deleteUser(deleteFor.id), t('users.deleted', { name: name(deleteFor) })).then(() => {
                    setDeleteFor(null);
                    actions.setSelectedItems([]);
                  });
                }}
              >
                {t('users.delete.submit')}
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        {t('users.delete.body')}
      </Modal>
    </SpaceBetween>
  );
}
