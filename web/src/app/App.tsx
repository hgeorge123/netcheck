import Alert from '@cloudscape-design/components/alert';
import AppLayout from '@cloudscape-design/components/app-layout';
import Box from '@cloudscape-design/components/box';
import BreadcrumbGroup, { type BreadcrumbGroupProps } from '@cloudscape-design/components/breadcrumb-group';
import Button from '@cloudscape-design/components/button';
import Flashbar, { type FlashbarProps } from '@cloudscape-design/components/flashbar';
import FormField from '@cloudscape-design/components/form-field';
import HelpPanel from '@cloudscape-design/components/help-panel';
import Modal from '@cloudscape-design/components/modal';
import RadioGroup from '@cloudscape-design/components/radio-group';
import SideNavigation, { type SideNavigationProps } from '@cloudscape-design/components/side-navigation';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import TopNavigation from '@cloudscape-design/components/top-navigation';
import { useCallback, useEffect, useRef, useState } from 'react';
import { ErrorAlert, errorText } from '../components/errors';
import { DashboardPage } from '../features/dashboard/DashboardPage';
import { AccessRulesPage } from '../features/admin/AccessRulesPage';
import { NamespacesPage } from '../features/admin/NamespacesPage';
import { PolicyPage } from '../features/admin/PolicyPage';
import { RetentionPage } from '../features/admin/RetentionPage';
import { TrustedCAsPage } from '../features/admin/TrustedCAsPage';
import { CheckTypesPage } from '../features/admin/CheckTypesPage';
import { ProxiesPage, type ProxyCalls } from '../features/admin/ProxiesPage';
import { SessionsPage } from '../features/admin/SessionsPage';
import { SystemPage } from '../features/admin/SystemPage';
import { UserFormPage } from '../features/admin/UserFormPage';
import { UsersPage } from '../features/admin/UsersPage';
import { ChangePasswordPage } from '../features/auth/ChangePasswordPage';
import { LoginPage } from '../features/auth/LoginPage';
import { HistoryPage } from '../features/history/HistoryPage';
import { TokensPage } from '../features/tokens/TokensPage';
import { NewRunPage } from '../features/new-run/NewRunPage';
import { formFromRun } from '../features/new-run/validation';
import { RunDetailPage } from '../features/run-detail/RunDetailPage';
import { isLanguage, LANGUAGES, useI18n, type Language, type Translate } from '../i18n';
import { ApiError, api, setSessionListener } from '../services/api';
import type { Catalog, Me } from '../types/api';
import { hrefFor, isAdminRoute, type Route, useHashRoute } from './router';

// Stable call sets, so the pages do not reload on every render.
const adminProxyCalls: ProxyCalls = {
  list: api.admin.proxies,
  create: api.admin.createProxy,
  update: api.admin.updateProxy,
  remove: api.admin.deleteProxy,
};
const myProxyCalls: ProxyCalls = api.myProxies;

function Help({ t }: { t: Translate }) {
  return (
    <HelpPanel header={<h2>{t('help.title')}</h2>}>
      <p>{t('help.intro')}</p>
      <ul>
        <li>{t('help.namespace')}</li>
        <li>{t('help.target')}</li>
        <li>{t('help.timeout')}</li>
        <li>{t('help.refused')}</li>
        <li>{t('help.http')}</li>
        <li>{t('help.icmp')}</li>
        <li>{t('help.infra')}</li>
        <li>{t('help.ownNs')}</li>
      </ul>
    </HelpPanel>
  );
}

type Session = { state: 'loading' } | { state: 'anonymous'; notice?: string } | { state: 'ready'; me: Me; catalog: Catalog | null };

let flashId = 0;

const SSO_RESULTS = ['no_access', 'username_taken', 'failed', 'unavailable'] as const;

/** Outcome of a failed single sign-on, passed back by the server in the URL (#/?sso=...). */
function ssoResult(): (typeof SSO_RESULTS)[number] | undefined {
  const query = window.location.hash.split('?', 2)[1] ?? '';
  const code = new URLSearchParams(query).get('sso');
  return SSO_RESULTS.find((c) => c === code);
}

function breadcrumbs(route: Route, t: Translate): BreadcrumbGroupProps.Item[] {
  const items = [{ text: 'NetCheck', href: '#/' }];
  switch (route.page) {
    case 'dashboard':
      items.push({ text: t('nav.dashboard'), href: '#/' });
      break;
    case 'new':
      items.push({ text: t('nav.newTest'), href: '#/new' });
      break;
    case 'history':
      items.push({ text: t('nav.history'), href: '#/runs' });
      break;
    case 'run':
      items.push({ text: t('nav.history'), href: '#/runs' }, { text: route.id.slice(0, 8), href: hrefFor(route) });
      break;
    case 'password':
      items.push({ text: t('password.title'), href: '#/account/password' });
      break;
    case 'sessions':
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('nav.sessions'), href: '#/admin/sessions' });
      break;
    case 'system':
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('nav.system'), href: '#/admin/system' });
      break;
    case 'namespaces':
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('nav.namespaces'), href: '#/admin/namespaces' });
      break;
    case 'policy':
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('nav.policy'), href: '#/admin/policy' });
      break;
    case 'retention':
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('nav.retention'), href: '#/admin/retention' });
      break;
    case 'trusted-cas':
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('nav.trustedCas'), href: '#/admin/trusted-cas' });
      break;
    case 'check-types':
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('nav.checkTypes'), href: '#/admin/check-types' });
      break;
    case 'proxies':
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('nav.proxies'), href: '#/admin/proxies' });
      break;
    case 'my-proxies':
      items.push({ text: t('myProxies.title'), href: '#/account/proxies' });
      break;
    case 'tokens':
      items.push({ text: t('tokens.title'), href: '#/account/tokens' });
      break;
    case 'admin-tokens':
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('tokens.title'), href: '#/admin/tokens' });
      break;
    case 'access-rules':
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('nav.accessRules'), href: '#/admin/access-rules' });
      break;
    default:
      items.push({ text: t('nav.administration'), href: '#/admin/users' }, { text: t('nav.users'), href: '#/admin/users' });
      if (route.page === 'user-new') items.push({ text: t('users.create'), href: '#/admin/users/new' });
      if (route.page === 'user-edit') items.push({ text: t('users.action.edit'), href: hrefFor(route) });
  }
  return items;
}

function activeHref(route: Route): string {
  if (route.page === 'run') return '#/runs';
  if (route.page === 'user-new' || route.page === 'user-edit') return '#/admin/users';
  return hrefFor({ ...route, ...(route.page === 'new' ? { from: undefined } : {}) } as Route);
}

export function App() {
  const { t, lang, setLanguage } = useI18n();
  const [route, navigate] = useHashRoute();
  const [session, setSession] = useState<Session>({ state: 'loading' });
  const [flash, setFlash] = useState<FlashbarProps.MessageDefinition[]>([]);
  const [toolsOpen, setToolsOpen] = useState(false);
  const [prefsOpen, setPrefsOpen] = useState(false);
  const [prefsLang, setPrefsLang] = useState<Language>(lang);
  const [prefsError, setPrefsError] = useState<string | null>(null);
  // Language picked on the sign-in page, saved to the account after sign-in.
  const pendingLanguage = useRef<Language | null>(null);

  const notify = useCallback((type: 'success' | 'error', content: string) => {
    const id = `f${++flashId}`;
    setFlash((f) => [...f, { id, type, content, dismissible: true, onDismiss: () => setFlash((x) => x.filter((m) => m.id !== id)) }]);
  }, []);

  // A notification is shown on the page where it appears (often the page
  // navigated to after an action) and dropped when the user moves on.
  const flashPage = useRef(new Map<string, string>());
  const page = hrefFor(route);
  useEffect(() => {
    setFlash((f) => {
      const keep = f.filter((m) => {
        const seen = flashPage.current.get(m.id ?? '');
        return seen === undefined || seen === page;
      });
      for (const m of keep) if (!flashPage.current.has(m.id ?? '')) flashPage.current.set(m.id ?? '', page);
      return keep.length === f.length ? f : keep;
    });
  }, [page, flash.length]);

  const load = useCallback(async () => {
    try {
      const me = await api.me();
      // The account preference decides the language (English when unset),
      // unless the user has just picked one on the sign-in page.
      let language: Language = isLanguage(me.language) ? me.language : 'en';
      const pending = pendingLanguage.current;
      if (pending) {
        language = pending;
        try {
          if (pending !== me.language) await api.setLanguage(pending);
          pendingLanguage.current = null;
        } catch {
          // Retried on the next profile load; the choice applies meanwhile.
        }
      }
      setLanguage(language);
      const catalog = me.mustChangePassword ? null : await api.catalog();
      setSession({ state: 'ready', me: { ...me, language }, catalog });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setSession({ state: 'anonymous' });
      else setSession({ state: 'anonymous', notice: errorText(t, err) });
    }
    // t is only used for an error notice; reloading on language change is not wanted.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [setLanguage]);

  useEffect(() => {
    setSessionListener((e) => {
      if (e.code === 'password_change_required') void load();
      else setSession({ state: 'anonymous', notice: 'expired' });
    });
    void load();
    return () => setSessionListener(undefined);
  }, [load]);

  // The catalog lists the proxies the user may choose: refresh it whenever
  // the new-test form opens, so a proxy added a moment ago (by the user or an
  // administrator) is offered without reloading the page.
  const onNewTest = route.page === 'new';
  const hasCatalog = session.state === 'ready' && session.catalog !== null;
  useEffect(() => {
    if (!onNewTest || !hasCatalog) return;
    let current = true;
    api
      .catalog()
      .then((catalog) => {
        if (current) setSession((s) => (s.state === 'ready' && s.catalog ? { ...s, catalog } : s));
      })
      .catch(() => {
        // Keep the catalog loaded at sign-in; the server validates every request anyway.
      });
    return () => {
      current = false;
    };
  }, [onNewTest, hasCatalog]);

  if (session.state === 'loading') {
    return (
      <Box textAlign="center" padding="xxxl">
        <Spinner size="large" />
      </Box>
    );
  }
  if (session.state === 'anonymous') {
    const sso = ssoResult();
    const notice = sso
      ? t(`login.ssoError.${sso}`)
      : session.notice === 'expired'
        ? t('error.unauthenticated')
        : session.notice === 'signedOut'
          ? t('login.signedOut')
          : session.notice;
    return (
      <LoginPage
        login={api.login}
        onLoggedIn={() => void load()}
        onLanguageChange={(l) => {
          pendingLanguage.current = l;
          setLanguage(l);
        }}
        notice={notice}
        providers={api.providers}
      />
    );
  }

  const { me, catalog } = session;
  const isAdmin = me.role === 'admin';
  const logout = async () => {
    try {
      await api.logout();
    } finally {
      setFlash([]);
      setSession({ state: 'anonymous', notice: 'signedOut' });
    }
  };

  const savePrefs = async () => {
    setPrefsError(null);
    try {
      await api.setLanguage(prefsLang);
      setLanguage(prefsLang);
      setSession({ ...session, me: { ...me, language: prefsLang } });
      setPrefsOpen(false);
    } catch (e) {
      setPrefsError(errorText(t, e));
    }
  };

  const openRun = (id: string) => navigate({ page: 'run', id });
  let content;
  if (me.mustChangePassword) {
    content = <ChangePasswordPage forced change={api.changePassword} onChanged={() => void load()} />;
  } else if (isAdminRoute(route) && !isAdmin) {
    content = (
      <Alert type="error" header={t('error.forbiddenTitle')}>
        {t('error.forbiddenBody')}
      </Alert>
    );
  } else if (route.page === 'dashboard') {
    content = (
      <DashboardPage
        me={me}
        stats={api.stats}
        list={api.listRuns}
        onOpen={openRun}
        onCreate={() => navigate({ page: 'new' })}
        onHistory={() => navigate({ page: 'history' })}
      />
    );
  } else if (route.page === 'run') {
    content = <RunDetailPage id={route.id} load={api.getRun} onRunAgain={(id) => navigate({ page: 'new', from: id })} />;
  } else if (route.page === 'history') {
    content = <HistoryPage namespaces={me.namespaces} list={api.listRuns} onOpen={openRun} onCreate={() => navigate({ page: 'new' })} />;
  } else if (route.page === 'password') {
    content = (
      <ChangePasswordPage
        forced={false}
        change={api.changePassword}
        onChanged={() => notify('success', t('password.done'))}
        onCancel={() => navigate({ page: 'dashboard' })}
      />
    );
  } else if (route.page === 'users') {
    content = (
      <UsersPage
        admin={api.admin}
        currentUserId={me.id}
        onCreate={() => navigate({ page: 'user-new' })}
        onEdit={(id) => navigate({ page: 'user-edit', id })}
        notify={notify}
      />
    );
  } else if (route.page === 'user-new' || route.page === 'user-edit') {
    content = (
      <UserFormPage
        key={route.page === 'user-edit' ? route.id : 'new'}
        admin={api.admin}
        userId={route.page === 'user-edit' ? route.id : undefined}
        currentUserId={me.id}
        onDone={(msg) => {
          notify('success', msg);
          navigate({ page: 'users' });
        }}
        onCancel={() => navigate({ page: 'users' })}
      />
    );
  } else if (route.page === 'sessions') {
    content = <SessionsPage admin={api.admin} notify={notify} />;
  } else if (route.page === 'system') {
    content = <SystemPage admin={api.admin} onEditPolicy={() => navigate({ page: 'policy' })} onEditRetention={() => navigate({ page: 'retention' })} />;
  } else if (route.page === 'namespaces') {
    content = <NamespacesPage admin={api.admin} notify={notify} />;
  } else if (route.page === 'policy') {
    content = <PolicyPage admin={api.admin} notify={notify} />;
  } else if (route.page === 'retention') {
    content = <RetentionPage admin={api.admin} notify={notify} />;
  } else if (route.page === 'check-types') {
    content = <CheckTypesPage admin={api.admin} notify={notify} />;
  } else if (route.page === 'trusted-cas') {
    content = <TrustedCAsPage admin={api.admin} notify={notify} />;
  } else if (route.page === 'proxies') {
    content = <ProxiesPage scope="admin" calls={adminProxyCalls} notify={notify} />;
  } else if (route.page === 'my-proxies') {
    content = <ProxiesPage scope="personal" calls={myProxyCalls} notify={notify} />;
  } else if (route.page === 'tokens') {
    content = <TokensPage scope="mine" list={api.tokens.list} create={api.tokens.create} revoke={api.tokens.revoke} notify={notify} />;
  } else if (route.page === 'admin-tokens') {
    content = <TokensPage scope="all" list={api.admin.tokens} revoke={api.admin.revokeToken} notify={notify} />;
  } else if (route.page === 'access-rules') {
    content = <AccessRulesPage admin={api.admin} notify={notify} />;
  } else if (catalog) {
    const from = route.page === 'new' ? route.from : undefined;
    content = (
      <NewRunPage
        key={from ?? 'new'}
        namespaces={me.namespaces}
        catalog={catalog}
        submit={api.createRun}
        onCreated={openRun}
        prefill={from ? () => api.getRun(from).then(formFromRun) : undefined}
        onInfo={() => setToolsOpen(true)}
      />
    );
  } else {
    content = <ErrorAlert error={new ApiError(0, 'generic', '')} header={t('error.startFailed')} />;
  }

  const navItems: SideNavigationProps.Item[] = [
    { type: 'link', text: t('nav.dashboard'), href: '#/' },
    { type: 'link', text: t('nav.newTest'), href: '#/new' },
    { type: 'link', text: t('nav.history'), href: '#/runs' },
    // Also in the user menu: both places lead to the same pages.
    { type: 'link', text: t('myProxies.title'), href: '#/account/proxies' },
    { type: 'link', text: t('nav.myTokens'), href: '#/account/tokens' },
  ];
  if (isAdmin) {
    navItems.push(
      { type: 'divider' },
      {
        type: 'section',
        text: t('nav.administration'),
        items: [
          { type: 'link', text: t('nav.users'), href: '#/admin/users' },
          { type: 'link', text: t('nav.accessRules'), href: '#/admin/access-rules' },
          { type: 'link', text: t('nav.namespaces'), href: '#/admin/namespaces' },
          { type: 'link', text: t('nav.policy'), href: '#/admin/policy' },
          { type: 'link', text: t('nav.checkTypes'), href: '#/admin/check-types' },
          { type: 'link', text: t('nav.trustedCas'), href: '#/admin/trusted-cas' },
          { type: 'link', text: t('nav.proxies'), href: '#/admin/proxies' },
          { type: 'link', text: t('nav.retention'), href: '#/admin/retention' },
          { type: 'link', text: t('nav.sessions'), href: '#/admin/sessions' },
          { type: 'link', text: t('tokens.title'), href: '#/admin/tokens' },
          { type: 'link', text: t('nav.system'), href: '#/admin/system' },
        ],
      },
    );
  }
  const langOptions = LANGUAGES.map((l) => ({ value: l, label: t(`lang.${l}`) }));
  const noNamespaces = !me.mustChangePassword && me.namespaces.length === 0;

  return (
    <>
      <div id="top-nav" style={{ position: 'sticky', top: 0, zIndex: 1002 }}>
        <TopNavigation
          identity={{ href: '#/', title: 'NetCheck', logo: { src: '/brand/netcheck-mark.png', alt: 'NetCheck' } }}
          utilities={[
            {
              type: 'button',
              iconName: 'settings',
              ariaLabel: t('prefs.title'),
              title: t('prefs.title'),
              onClick: () => {
                setPrefsLang(lang);
                setPrefsError(null);
                setPrefsOpen(true);
              },
            },
            {
              type: 'menu-dropdown',
              text: me.display || me.username,
              description: `${me.username} · ${t(isAdmin ? 'nav.role.admin' : 'nav.role.user')}${me.version ? ` · v${me.version}` : ''}`,
              iconName: 'user-profile',
              onItemClick: ({ detail }) => {
                if (detail.id === 'prefs') {
                  setPrefsLang(lang);
                  setPrefsError(null);
                  setPrefsOpen(true);
                }
                if (detail.id === 'password') navigate({ page: 'password' });
                if (detail.id === 'tokens') navigate({ page: 'tokens' });
                if (detail.id === 'proxies') navigate({ page: 'my-proxies' });
                if (detail.id === 'logout') void logout();
              },
              items: [
                { id: 'prefs', text: t('nav.userMenu.preferences') },
                // SSO accounts have no NetCheck password.
                ...(me.source === 'oidc' ? [] : [{ id: 'password', text: t('nav.userMenu.password'), disabled: me.mustChangePassword }]),
                { id: 'tokens', text: t('tokens.title'), disabled: me.mustChangePassword },
                { id: 'proxies', text: t('myProxies.title'), disabled: me.mustChangePassword },
                { id: 'logout', text: t('nav.userMenu.signOut') },
              ],
            },
          ]}
        />
      </div>
      <AppLayout
        headerSelector="#top-nav"
        navigationHide={me.mustChangePassword}
        navigation={<SideNavigation header={{ text: 'NetCheck', href: '#/' }} activeHref={activeHref(route)} items={navItems} />}
        breadcrumbs={me.mustChangePassword ? undefined : <BreadcrumbGroup items={breadcrumbs(route, t)} ariaLabel={t('nav.breadcrumbs')} />}
        notifications={
          <Flashbar items={noNamespaces ? [...flash, { type: 'info', content: t('newTest.noNamespacesBody'), id: 'no-ns' }] : flash} />
        }
        tools={<Help t={t} />}
        toolsOpen={toolsOpen}
        onToolsChange={({ detail }) => setToolsOpen(detail.open)}
        content={content}
      />
      <Modal
        visible={prefsOpen}
        onDismiss={() => setPrefsOpen(false)}
        header={t('prefs.title')}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setPrefsOpen(false)}>
                {t('common.cancel')}
              </Button>
              <Button variant="primary" onClick={() => void savePrefs()}>
                {t('common.save')}
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <FormField label={t('prefs.language')} description={t('prefs.languageHint')} errorText={prefsError}>
          <RadioGroup value={prefsLang} onChange={({ detail }) => setPrefsLang(detail.value as Language)} items={langOptions} ariaLabel={t('prefs.language')} />
        </FormField>
      </Modal>
    </>
  );
}
