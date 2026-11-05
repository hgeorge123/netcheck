import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import Toggle from '@cloudscape-design/components/toggle';
import { useCallback, useEffect, useState } from 'react';
import { ErrorAlert, fieldErrorText } from '../../components/errors';
import { useI18n } from '../../i18n';
import { ApiError, type Api } from '../../services/api';
import type { CheckType, CheckTypesView } from '../../types/api';

interface Props {
  admin: Api['admin'];
  notify: (type: 'success' | 'error', message: string) => void;
}

// Author of the setting copied from the Helm values on the first start.
const SEED_ACTOR = 'helm (initial values)';

const isMethod = (t: CheckType) => t !== 'firewall';

/** Check types switched off for everybody, administrators included. */
export function CheckTypesPage({ admin, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [view, setView] = useState<CheckTypesView | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [draft, setDraft] = useState<Record<string, boolean>>({});
  const [saveError, setSaveError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const reset = (v: CheckTypesView) => setDraft(Object.fromEntries(v.types.map((x) => [x.type, x.enabled])));

  const load = useCallback(async () => {
    try {
      const v = await admin.checkTypes();
      setView(v);
      reset(v);
    } catch (e) {
      setLoadError(e);
    }
  }, [admin]);

  useEffect(() => {
    void load();
  }, [load]);

  if (loadError) return <ErrorAlert error={loadError} />;
  const types = view?.types ?? [];
  const readOnly = view !== null && !view.editable;
  const changed = types.some((x) => draft[x.type] !== x.enabled);
  const noneLeft = types.length > 0 && !types.some((x) => isMethod(x.type) && draft[x.type]);
  const errorText = saveError instanceof ApiError && saveError.details[0] ? fieldErrorText(t, saveError.details[0]) : undefined;

  const save = async () => {
    setBusy(true);
    setSaveError(null);
    try {
      const v = await admin.saveCheckTypes(types.filter((x) => !draft[x.type]).map((x) => x.type));
      setView(v);
      reset(v);
      notify('success', t('checkTypes.saved'));
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
          description={t('checkTypes.description')}
          info={
            view && (
              <Box variant="small" color="text-body-secondary">
                {t('policy.updated', { date: formatDate(view.updatedAt), user: view.updatedBy === SEED_ACTOR ? t('policy.seedActor') : view.updatedBy })}
              </Box>
            )
          }
          actions={
            !readOnly && (
              <SpaceBetween direction="horizontal" size="xs">
                <Button disabled={!changed || busy} onClick={() => view && reset(view)}>
                  {t('checkTypes.discard')}
                </Button>
                <Button variant="primary" loading={busy} disabled={!changed || noneLeft} onClick={() => void save()}>
                  {t('common.save')}
                </Button>
              </SpaceBetween>
            )
          }
        >
          {t('checkTypes.title')}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {readOnly && (
          <Alert type="info" header={t('checkTypes.helmTitle')}>
            {t('checkTypes.helmBody')}
          </Alert>
        )}
        {changed && !readOnly && <Alert type="warning">{t('policy.unsaved')}</Alert>}
        {noneLeft && <Alert type="error">{t('field.all_checks_disabled')}</Alert>}
        {saveError !== null && (errorText ? <Alert type="error">{errorText}</Alert> : <ErrorAlert error={saveError} />)}
        <Table
          loading={view === null}
          loadingText={t('common.loading')}
          variant="container"
          items={types}
          trackBy="type"
          wrapLines
          header={
            <Header variant="h2" description={t('checkTypes.listDesc')}>
              {t('checkTypes.listTitle')}
            </Header>
          }
          columnDefinitions={[
            {
              id: 'type',
              header: t('checkTypes.col.type'),
              width: 260,
              cell: (x) => <b>{isMethod(x.type) ? t(`method.${x.type}`) : t('newTest.mode.firewall')}</b>,
            },
            {
              id: 'desc',
              header: t('checkTypes.col.description'),
              cell: (x) => (isMethod(x.type) ? t(`method.${x.type}.desc`) : t('checkTypes.firewallDesc')),
            },
            {
              id: 'enabled',
              header: t('checkTypes.col.enabled'),
              minWidth: 170,
              cell: (x) => (
                <Toggle
                  checked={!!draft[x.type]}
                  disabled={readOnly || busy}
                  ariaLabel={isMethod(x.type) ? t(`method.${x.type}`) : t('newTest.mode.firewall')}
                  onChange={({ detail }) => setDraft((d) => ({ ...d, [x.type]: detail.checked }))}
                >
                  {draft[x.type] ? t('checkTypes.on') : t('checkTypes.off')}
                </Toggle>
              ),
            },
          ]}
        />
        <Alert type="info">{t('checkTypes.note')}</Alert>
      </SpaceBetween>
    </ContentLayout>
  );
}
