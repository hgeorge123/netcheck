import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import Textarea from '@cloudscape-design/components/textarea';
import { useCallback, useEffect, useState } from 'react';
import { ErrorAlert, errorText, fieldErrorText } from '../../components/errors';
import { useI18n } from '../../i18n';
import { ApiError, type Api } from '../../services/api';
import type { TrustedCAsView, TrustedCertificate } from '../../types/api';

interface Props {
  admin: Api['admin'];
  notify: (type: 'success' | 'error', message: string) => void;
}

// Author of the list copied from the Helm values on the first start.
const SEED_ACTOR = 'helm (initial values)';

/** Groups of four hex digits, so a fingerprint can be compared by eye. */
export function shortFingerprint(fp: string): string {
  return (fp.match(/.{1,4}/g) ?? []).slice(0, 8).join(' ').toUpperCase() + '…';
}

/** Certificate authorities HTTPS checks trust on top of the public ones. */
export function TrustedCAsPage({ admin, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [view, setView] = useState<TrustedCAsView | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [selected, setSelected] = useState<TrustedCertificate[]>([]);
  const [adding, setAdding] = useState(false);
  const [pem, setPem] = useState('');
  const [removing, setRemoving] = useState<TrustedCertificate | null>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setView(await admin.trustedCAs());
      setSelected([]);
    } catch (e) {
      setLoadError(e);
    }
  }, [admin]);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (certificates: string[], message: string) => {
    setBusy(true);
    setSaveError(null);
    try {
      setView(await admin.saveTrustedCAs(certificates));
      setSelected([]);
      setAdding(false);
      setRemoving(null);
      setPem('');
      notify('success', message);
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };

  if (loadError) return <ErrorAlert error={loadError} />;
  const current = view?.certificates ?? [];
  const readOnly = view !== null && !view.editable;
  const pemError = saveError instanceof ApiError && saveError.details[0] ? fieldErrorText(t, saveError.details[0]) : undefined;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={t('cas.description')}
          info={
            view && (
              <Box variant="small" color="text-body-secondary">
                {t('policy.updated', { date: formatDate(view.updatedAt), user: view.updatedBy === SEED_ACTOR ? t('policy.seedActor') : view.updatedBy })}
              </Box>
            )
          }
        >
          {t('cas.title')}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {readOnly && (
          <Alert type="info" header={t('cas.helmTitle')}>
            {t('cas.helmBody')}
          </Alert>
        )}
        <Table
          items={current}
          loading={view === null}
          loadingText={t('common.loading')}
          trackBy="fingerprintSha256"
          variant="container"
          selectionType={readOnly ? undefined : 'single'}
          selectedItems={selected}
          onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
          ariaLabels={{ itemSelectionLabel: (_, c) => c.subject, selectionGroupLabel: t('cas.title') }}
          header={
            <Header
              counter={view ? `(${current.length})` : undefined}
              description={t('cas.listDesc')}
              actions={
                !readOnly && (
                  <SpaceBetween direction="horizontal" size="xs">
                    <Button disabled={selected.length !== 1} onClick={() => setRemoving(selected[0] ?? null)}>
                      {t('cas.remove')}
                    </Button>
                    <Button
                      variant="primary"
                      onClick={() => {
                        setSaveError(null);
                        setAdding(true);
                      }}
                    >
                      {t('cas.add')}
                    </Button>
                  </SpaceBetween>
                )
              }
            >
              {t('cas.listTitle')}
            </Header>
          }
          empty={
            <Box textAlign="center" color="inherit">
              <b>{t('cas.emptyTitle')}</b>
              <Box variant="p" color="inherit">
                {t('cas.empty')}
              </Box>
            </Box>
          }
          columnDefinitions={[
            { id: 'subject', header: t('cas.col.subject'), cell: (c) => c.subject },
            { id: 'issuer', header: t('cas.col.issuer'), cell: (c) => (c.issuer === c.subject ? t('cas.selfIssued') : c.issuer) },
            {
              id: 'expires',
              header: t('cas.col.expires'),
              cell: (c) =>
                c.expired ? <StatusIndicator type="error">{t('cas.expired', { date: formatDate(c.notAfter) })}</StatusIndicator> : formatDate(c.notAfter),
            },
            { id: 'fingerprint', header: t('cas.col.fingerprint'), cell: (c) => <Box variant="code">{shortFingerprint(c.fingerprintSha256)}</Box> },
          ]}
        />
        <Alert type="info">{t('cas.note')}</Alert>
      </SpaceBetween>

      {adding && view && (
        <Modal
          visible
          size="large"
          onDismiss={() => setAdding(false)}
          header={t('cas.addTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setAdding(false)}>
                  {t('common.cancel')}
                </Button>
                <Button
                  variant="primary"
                  loading={busy}
                  disabled={!pem.trim()}
                  onClick={() => void save([...current.map((c) => c.pem), pem], t('cas.saved'))}
                >
                  {t('cas.add')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            {saveError !== null && !pemError && <Alert type="error">{errorText(t, saveError)}</Alert>}
            <FormField label={t('cas.pem')} description={t('cas.pemDesc')} errorText={pemError}>
              <Textarea
                value={pem}
                rows={12}
                spellcheck={false}
                placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----'}
                onChange={({ detail }) => setPem(detail.value)}
                ariaLabel={t('cas.pem')}
              />
            </FormField>
          </SpaceBetween>
        </Modal>
      )}

      {removing && (
        <Modal
          visible
          onDismiss={() => setRemoving(null)}
          header={t('cas.removeTitle')}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setRemoving(null)}>
                  {t('common.cancel')}
                </Button>
                <Button
                  variant="primary"
                  loading={busy}
                  onClick={() =>
                    void save(
                      current.filter((c) => c.fingerprintSha256 !== removing.fingerprintSha256).map((c) => c.pem),
                      t('cas.removed'),
                    )
                  }
                >
                  {t('cas.remove')}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="s">
            {saveError !== null && <Alert type="error">{errorText(t, saveError)}</Alert>}
            <Box variant="p">{t('cas.removeBody', { subject: removing.subject })}</Box>
          </SpaceBetween>
        </Modal>
      )}
    </ContentLayout>
  );
}
