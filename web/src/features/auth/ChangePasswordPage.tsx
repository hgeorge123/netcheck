import Alert from '@cloudscape-design/components/alert';
import Button from '@cloudscape-design/components/button';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import SpaceBetween from '@cloudscape-design/components/space-between';
import { useState } from 'react';
import { errorText, fieldErrorText } from '../../components/errors';
import { useI18n } from '../../i18n';
import { ApiError } from '../../services/api';
import { MIN_PASSWORD_LENGTH } from './password';

interface Props {
  forced: boolean;
  change: (current: string, next: string) => Promise<void>;
  onChanged: () => void;
  onCancel?: () => void;
}

export function ChangePasswordPage({ forced, change, onChanged, onCancel }: Props) {
  const { t } = useI18n();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  const submit = async () => {
    const e: Record<string, string> = {};
    if (!current) e.current = t('password.currentRequired');
    if ([...next].length < MIN_PASSWORD_LENGTH) e.next = t('password.tooShort', { n: MIN_PASSWORD_LENGTH });
    if (next !== confirm) e.confirm = t('password.mismatch');
    setErrors(e);
    if (Object.keys(e).length > 0) return;
    setBusy(true);
    try {
      await change(current, next);
      setDone(true);
      setCurrent('');
      setNext('');
      setConfirm('');
      onChanged();
    } catch (err) {
      const d = err instanceof ApiError ? err.details[0] : undefined;
      const text = d ? fieldErrorText(t, d) : errorText(t, err);
      setErrors(d?.field === 'currentPassword' ? { current: text } : d?.field === 'newPassword' ? { next: text } : { form: text });
    } finally {
      setBusy(false);
    }
  };

  return (
    <ContentLayout header={<Header variant="h1">{forced ? t('password.forcedTitle') : t('password.title')}</Header>}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Form
          errorText={errors.form}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              {!forced && onCancel && (
                <Button formAction="none" variant="link" onClick={onCancel}>
                  {t('common.cancel')}
                </Button>
              )}
              <Button variant="primary" formAction="submit" loading={busy}>
                {t('password.submit')}
              </Button>
            </SpaceBetween>
          }
        >
          <SpaceBetween size="m">
            {forced && <Alert type="warning">{t('password.forcedBody')}</Alert>}
            {done && <Alert type="success">{t('password.done')}</Alert>}
            <Container>
              <SpaceBetween size="m">
                <FormField label={t('password.current')} errorText={errors.current}>
                  <Input
                    type="password"
                    value={current}
                    onChange={({ detail }) => setCurrent(detail.value)}
                    autoComplete="current-password"
                    ariaLabel={t('password.current')}
                  />
                </FormField>
                <FormField label={t('password.new')} errorText={errors.next} description={t('password.newHint', { n: MIN_PASSWORD_LENGTH })}>
                  <Input type="password" value={next} onChange={({ detail }) => setNext(detail.value)} autoComplete="new-password" ariaLabel={t('password.new')} />
                </FormField>
                <FormField label={t('password.confirm')} errorText={errors.confirm}>
                  <Input
                    type="password"
                    value={confirm}
                    onChange={({ detail }) => setConfirm(detail.value)}
                    autoComplete="new-password"
                    ariaLabel={t('password.confirm')}
                  />
                </FormField>
              </SpaceBetween>
            </Container>
          </SpaceBetween>
        </Form>
      </form>
    </ContentLayout>
  );
}
