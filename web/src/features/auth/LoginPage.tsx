import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Container from '@cloudscape-design/components/container';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import { useEffect, useState } from 'react';
import { errorText } from '../../components/errors';
import { LANGUAGES, useI18n, type Language } from '../../i18n';
import type { Providers } from '../../types/api';

interface Props {
  login: (username: string, password: string) => Promise<unknown>;
  onLoggedIn: () => void;
  /** Called when the visitor picks a language before signing in. */
  onLanguageChange?: (l: Language) => void;
  notice?: string;
  /** Sign-in methods offered besides the local form (single sign-on). */
  providers?: () => Promise<Providers>;
}

export function LoginPage({ login, onLoggedIn, onLanguageChange, notice, providers }: Props) {
  const { t, lang } = useI18n();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const langOptions = LANGUAGES.map((l) => ({ value: l, label: t(`lang.${l}`) }));
  const [sso, setSso] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    providers?.()
      .then((p) => !cancelled && p.oidc.enabled && setSso(p.oidc.name || 'SSO'))
      .catch(() => undefined); // the local form keeps working
    return () => {
      cancelled = true;
    };
  }, [providers]);

  const submit = async () => {
    if (!username.trim() || !password) {
      setError(t('login.required'));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
      setPassword('');
      onLoggedIn();
    } catch (err) {
      setError(errorText(t, err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="nc-login">
      <div className="nc-login__lang">
        <Select
          selectedOption={langOptions.find((o) => o.value === lang) ?? null}
          options={langOptions}
          onChange={({ detail }) => onLanguageChange?.(detail.selectedOption.value as Language)}
          inlineLabelText={t('login.language')}
          ariaLabel={t('login.language')}
        />
      </div>
      <div className="nc-login__inner">
        <img className="nc-login__logo" src="/brand/netcheck-logo.png" alt="NetCheck" />
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <Container header={<Header variant="h1" description={t('app.tagline')}>{t('login.title')}</Header>}>
            <SpaceBetween size="l">
              {notice && <Alert type="info">{notice}</Alert>}
              {error && <Alert type="error">{error}</Alert>}
              <FormField label={t('login.username')}>
                <Input value={username} onChange={({ detail }) => setUsername(detail.value)} autoComplete="username" ariaLabel={t('login.username')} autoFocus />
              </FormField>
              <FormField label={t('login.password')}>
                <Input
                  value={password}
                  type="password"
                  onChange={({ detail }) => setPassword(detail.value)}
                  autoComplete="current-password"
                  ariaLabel={t('login.password')}
                />
              </FormField>
              <Button variant="primary" formAction="submit" loading={busy} fullWidth>
                {t('login.submit')}
              </Button>
              {sso && (
                <>
                  <Box textAlign="center" color="text-body-secondary">
                    {t('login.or')}
                  </Box>
                  {/* A full-page navigation: the provider page cannot be loaded with fetch. */}
                  <Button href="/api/v1/auth/oidc/start" iconName="external" fullWidth>
                    {t('login.sso', { name: sso })}
                  </Button>
                </>
              )}
              <Box variant="small" color="text-body-secondary">
                {t(sso ? 'login.forgotSso' : 'login.forgot')}
              </Box>
            </SpaceBetween>
          </Container>
        </form>
      </div>
    </main>
  );
}
