import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import { useEffect, useState } from 'react';
import { ErrorAlert, errorText, fieldErrorText } from '../../components/errors';
import { useI18n } from '../../i18n';
import { ApiError, type Api } from '../../services/api';
import type { RetentionView } from '../../types/api';

interface Props {
  admin: Api['admin'];
  notify: (type: 'success' | 'error', message: string) => void;
}

// Author of the retention copied from the Helm values on the first start.
const SEED_ACTOR = 'helm (initial values)';
export const MAX_RETENTION_DAYS = 3650;

const validDays = (v: string) => /^\d+$/.test(v) && Number(v) >= 1 && Number(v) <= MAX_RETENTION_DAYS;

export function RetentionPage({ admin, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [view, setView] = useState<RetentionView | null>(null);
  const [output, setOutput] = useState('');
  const [metadata, setMetadata] = useState('');
  const [loadError, setLoadError] = useState<unknown>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const reset = (v: RetentionView) => {
    setView(v);
    setOutput(String(v.outputDays));
    setMetadata(String(v.metadataDays));
  };

  useEffect(() => {
    let alive = true;
    admin
      .retention()
      .then((v) => alive && reset(v))
      .catch((e: unknown) => alive && setLoadError(e));
    return () => {
      alive = false;
    };
  }, [admin]);

  if (loadError) return <ErrorAlert error={loadError} />;
  if (!view) {
    return (
      <Box textAlign="center" padding="xxl">
        <Spinner size="large" />
      </Box>
    );
  }

  const dirty = output !== String(view.outputDays) || metadata !== String(view.metadataDays);
  const outputHint = output && !validDays(output) ? t('field.invalid_days') : undefined;
  const metadataHint =
    metadata && !validDays(metadata)
      ? t('field.invalid_days')
      : validDays(output) && validDays(metadata) && Number(metadata) < Number(output)
        ? t('field.metadata_shorter_than_output')
        : undefined;
  const shorter = (validDays(output) && Number(output) < view.outputDays) || (validDays(metadata) && Number(metadata) < view.metadataDays);
  const fieldError = (field: string) => {
    if (!(saveError instanceof ApiError)) return undefined;
    const d = saveError.details.find((x) => x.field === field);
    return d ? fieldErrorText(t, d) : undefined;
  };

  const save = async () => {
    setBusy(true);
    setSaveError(null);
    try {
      reset(await admin.saveRetention({ outputDays: Number(output), metadataDays: Number(metadata) }));
      notify('success', t('retention.saved'));
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={t('retention.description')}
          info={
            <Box variant="small" color="text-body-secondary">
              {t('policy.updated', { date: formatDate(view.updatedAt), user: view.updatedBy === SEED_ACTOR ? t('policy.seedActor') : view.updatedBy })}
            </Box>
          }
        >
          {t('retention.title')}
        </Header>
      }
    >
      <form onSubmit={(e) => e.preventDefault()}>
        <Form
          errorText={saveError && !(saveError instanceof ApiError && saveError.details.length > 0) ? errorText(t, saveError) : undefined}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" disabled={!dirty} onClick={() => reset(view)}>
                {t('common.cancel')}
              </Button>
              <Button variant="primary" loading={busy} disabled={!dirty || !!outputHint || !!metadataHint || !output || !metadata} onClick={() => void save()}>
                {t('common.save')}
              </Button>
            </SpaceBetween>
          }
        >
          <SpaceBetween size="l">
            {dirty && shorter && <Alert type="warning">{t('retention.shorterWarning')}</Alert>}
            <Container header={<Header variant="h2">{t('retention.periods')}</Header>}>
              <ColumnLayout columns={2}>
                <FormField label={t('retention.output')} description={t('retention.outputDesc')} errorText={outputHint ?? fieldError('outputDays')}>
                  <Input value={output} inputMode="numeric" type="number" onChange={({ detail }) => setOutput(detail.value)} ariaLabel={t('retention.output')} />
                </FormField>
                <FormField label={t('retention.metadata')} description={t('retention.metadataDesc')} errorText={metadataHint ?? fieldError('metadataDays')}>
                  <Input value={metadata} inputMode="numeric" type="number" onChange={({ detail }) => setMetadata(detail.value)} ariaLabel={t('retention.metadata')} />
                </FormField>
              </ColumnLayout>
            </Container>
            <Alert type="info">{t('retention.note')}</Alert>
          </SpaceBetween>
        </Form>
      </form>
    </ContentLayout>
  );
}
