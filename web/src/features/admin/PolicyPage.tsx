import Alert from '@cloudscape-design/components/alert';
import Badge from '@cloudscape-design/components/badge';
import AttributeEditor from '@cloudscape-design/components/attribute-editor';
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
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import { useEffect, useState } from 'react';
import { ErrorAlert, errorText, fieldErrorText } from '../../components/errors';
import { useI18n, type MessageKey } from '../../i18n';
import { ApiError, type Api } from '../../services/api';
import type { DestinationPolicy, PolicyCheck, PolicyView } from '../../types/api';

interface Props {
  admin: Api['admin'];
  notify: (type: 'success' | 'error', message: string) => void;
}

/** Form state: every value is a string so partially typed entries survive. */
interface PolicyForm {
  allowCidrs: string[];
  denyCidrs: string[];
  allowHostnameSuffixes: string[];
  allowPorts: { from: string; to: string }[];
}

// Author of the policy copied from the Helm values on the first start.
const SEED_ACTOR = 'helm (initial values)';

export const ALLOW_ALL: DestinationPolicy = {
  allowCidrs: ['0.0.0.0/0', '::/0'],
  denyCidrs: [],
  allowHostnameSuffixes: ['*'],
  allowPorts: [{ from: 1, to: 65535 }],
};

const CLUSTER_ONLY: DestinationPolicy = {
  allowCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
  denyCidrs: [],
  allowHostnameSuffixes: ['.svc.cluster.local'],
  allowPorts: [{ from: 1, to: 65535 }],
};

const toForm = (p: DestinationPolicy): PolicyForm => ({
  allowCidrs: [...p.allowCidrs],
  denyCidrs: [...p.denyCidrs],
  allowHostnameSuffixes: [...p.allowHostnameSuffixes],
  allowPorts: p.allowPorts.map((r) => ({ from: String(r.from), to: String(r.to) })),
});

const toPolicy = (f: PolicyForm): DestinationPolicy => ({
  allowCidrs: f.allowCidrs.map((s) => s.trim()).filter(Boolean),
  denyCidrs: f.denyCidrs.map((s) => s.trim()).filter(Boolean),
  allowHostnameSuffixes: f.allowHostnameSuffixes.map((s) => s.trim()).filter(Boolean),
  allowPorts: f.allowPorts.filter((r) => r.from.trim() || r.to.trim()).map((r) => ({ from: Number(r.from), to: Number(r.to || r.from) })),
});

// Client-side hints only; the server validates with the real parser.
const cidrPattern = /^([0-9.]+\/\d{1,2}|[0-9a-f:.]+\/\d{1,3})$/i;
const validPort = (v: string) => /^\d+$/.test(v) && Number(v) >= 1 && Number(v) <= 65535;

export function PolicyPage({ admin, notify }: Props) {
  const { t, formatDate } = useI18n();
  const [view, setView] = useState<PolicyView | null>(null);
  const [form, setForm] = useState<PolicyForm | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [checkTarget, setCheckTarget] = useState('');
  const [checkPort, setCheckPort] = useState('');
  const [check, setCheck] = useState<PolicyCheck | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    admin
      .policy()
      .then((v) => {
        if (!alive) return;
        setView(v);
        setForm(toForm(v.policy));
      })
      .catch((e: unknown) => alive && setLoadError(e));
    return () => {
      alive = false;
    };
  }, [admin]);

  if (loadError) return <ErrorAlert error={loadError} />;
  if (!view || !form) {
    return (
      <Box textAlign="center" padding="xxl">
        <Spinner size="large" />
      </Box>
    );
  }

  const readOnly = !view.editable;
  const dirty = JSON.stringify(toPolicy(form)) !== JSON.stringify(view.policy);
  const fieldError = (field: string) => {
    if (!(saveError instanceof ApiError)) return undefined;
    const d = saveError.details.find((x) => x.field === field);
    return d ? fieldErrorText(t, d) : undefined;
  };
  const set = (patch: Partial<PolicyForm>) => setForm({ ...form, ...patch });

  const save = async () => {
    setBusy(true);
    setSaveError(null);
    try {
      const v = await admin.savePolicy(toPolicy(form));
      setView(v);
      setForm(toForm(v.policy));
      setCheck(null);
      notify('success', t('policy.saved'));
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };

  const runCheck = async () => {
    setCheckError(null);
    setCheck(null);
    try {
      setCheck(await admin.checkDestination(checkTarget.trim(), checkPort.trim() ? Number(checkPort) : undefined));
    } catch (e) {
      const d = e instanceof ApiError ? e.details[0] : undefined;
      setCheckError(d ? fieldErrorText(t, d) : errorText(t, e));
    }
  };

  const stringList = (key: 'allowCidrs' | 'denyCidrs' | 'allowHostnameSuffixes', label: MessageKey, isCidr: boolean, placeholder: string) => (
    <AttributeEditor
      items={form[key].map((value, i) => ({ value, i }))}
      definition={[
        {
          label: t(label),
          control: (item) => (
            <Input
              value={item.value}
              disabled={readOnly}
              placeholder={placeholder}
              onChange={({ detail }) => set({ [key]: form[key].map((v, j) => (j === item.i ? detail.value : v)) })}
              ariaLabel={`${t(label)} ${item.i + 1}`}
            />
          ),
          errorText: (item) => (isCidr && item.value.trim() && !cidrPattern.test(item.value.trim()) ? t('policy.invalidCidr') : undefined),
        },
      ]}
      addButtonText={t('policy.add')}
      removeButtonText={t('policy.remove')}
      isItemRemovable={() => !readOnly}
      disableAddButton={readOnly}
      onAddButtonClick={() => set({ [key]: [...form[key], ''] })}
      onRemoveButtonClick={({ detail }) => set({ [key]: form[key].filter((_, j) => j !== detail.itemIndex) })}
      empty={t(key === 'denyCidrs' ? 'policy.emptyList' : 'policy.emptyAllow')}
    />
  );

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={t('policy.description')}
          info={
            <Box variant="small" color="text-body-secondary">
              {t('policy.updated', { date: formatDate(view.updatedAt), user: view.updatedBy === SEED_ACTOR ? t('policy.seedActor') : view.updatedBy })}
            </Box>
          }
        >
          {t('policy.title')}
        </Header>
      }
    >
      <form onSubmit={(e) => e.preventDefault()}>
        <Form
          errorText={saveError && !(saveError instanceof ApiError && saveError.details.length > 0) ? errorText(t, saveError) : undefined}
          actions={
            !readOnly && (
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" disabled={!dirty} onClick={() => setForm(toForm(view.policy))}>
                  {t('common.cancel')}
                </Button>
                <Button variant="primary" loading={busy} disabled={!dirty} onClick={() => void save()}>
                  {t('common.save')}
                </Button>
              </SpaceBetween>
            )
          }
        >
          <SpaceBetween size="l">
            {readOnly && (
              <Alert type="info" header={t('policy.helmTitle')}>
                {t('policy.helmBody')}
              </Alert>
            )}
            {dirty && <Alert type="warning">{t('policy.unsaved')}</Alert>}

            {!readOnly && (
              <Container header={<Header variant="h2">{t('policy.presets')}</Header>}>
                <ColumnLayout columns={2}>
                  <SpaceBetween size="xs">
                    <Button onClick={() => set(toForm(ALLOW_ALL))}>{t('policy.allowAll')}</Button>
                    <Box variant="small" color="text-body-secondary">
                      {t('policy.allowAllDesc')}
                    </Box>
                  </SpaceBetween>
                  <SpaceBetween size="xs">
                    <Button onClick={() => set(toForm(CLUSTER_ONLY))}>{t('policy.clusterOnly')}</Button>
                    <Box variant="small" color="text-body-secondary">
                      {t('policy.clusterOnlyDesc')}
                    </Box>
                  </SpaceBetween>
                </ColumnLayout>
              </Container>
            )}

            <Container header={<Header variant="h2" description={t('policy.suffixesDesc')}>{t('policy.suffixes')}</Header>}>
              <FormField errorText={fieldError('allowHostnameSuffixes')} stretch>
                {stringList('allowHostnameSuffixes', 'policy.suffix', false, '.example.com')}
              </FormField>
            </Container>

            <Container header={<Header variant="h2" description={t('policy.allowCidrsDesc')}>{t('policy.allowCidrs')}</Header>}>
              <FormField errorText={fieldError('allowCidrs')} stretch>
                {stringList('allowCidrs', 'policy.cidr', true, '10.0.0.0/16')}
              </FormField>
            </Container>

            <Container header={<Header variant="h2" description={t('policy.portsDesc')}>{t('policy.ports')}</Header>}>
              <FormField errorText={fieldError('allowPorts')} stretch>
                <AttributeEditor
                  items={form.allowPorts.map((r, i) => ({ ...r, i }))}
                  definition={[
                    {
                      label: t('policy.from'),
                      control: (item) => (
                        <Input
                          value={item.from}
                          disabled={readOnly}
                          inputMode="numeric"
                          onChange={({ detail }) => set({ allowPorts: form.allowPorts.map((r, j) => (j === item.i ? { ...r, from: detail.value } : r)) })}
                          ariaLabel={`${t('policy.from')} ${item.i + 1}`}
                        />
                      ),
                      errorText: (item) =>
                        (item.from || item.to) && (!validPort(item.from) || (item.to !== '' && (!validPort(item.to) || Number(item.to) < Number(item.from))))
                          ? t('policy.invalidPort')
                          : undefined,
                    },
                    {
                      label: t('policy.to'),
                      control: (item) => (
                        <Input
                          value={item.to}
                          disabled={readOnly}
                          inputMode="numeric"
                          onChange={({ detail }) => set({ allowPorts: form.allowPorts.map((r, j) => (j === item.i ? { ...r, to: detail.value } : r)) })}
                          ariaLabel={`${t('policy.to')} ${item.i + 1}`}
                        />
                      ),
                    },
                  ]}
                  addButtonText={t('policy.add')}
                  removeButtonText={t('policy.remove')}
                  isItemRemovable={() => !readOnly}
                  disableAddButton={readOnly}
                  onAddButtonClick={() => set({ allowPorts: [...form.allowPorts, { from: '', to: '' }] })}
                  onRemoveButtonClick={({ detail }) => set({ allowPorts: form.allowPorts.filter((_, j) => j !== detail.itemIndex) })}
                  empty={t('policy.emptyAllow')}
                />
              </FormField>
            </Container>

            <Container header={<Header variant="h2" description={t('policy.denyCidrsDesc')}>{t('policy.denyCidrs')}</Header>}>
              <FormField errorText={fieldError('denyCidrs')} stretch>
                {stringList('denyCidrs', 'policy.cidr', true, '10.20.0.0/16')}
              </FormField>
            </Container>

            <Container header={<Header variant="h2" description={t('policy.platformDesc')}>{t('policy.platform')}</Header>}>
              <SpaceBetween size="s">
                <StatusIndicator type={view.protectPlatformDestinations ? 'success' : 'warning'}>
                  {t(view.protectPlatformDestinations ? 'policy.platformOn' : 'policy.platformOff')}
                </StatusIndicator>
                <Box color="text-body-secondary">{t('policy.platformWhy')}</Box>
                {view.platformDenies.length > 0 && (
                  <SpaceBetween direction="horizontal" size="xs">
                    {view.platformDenies.map((c) => (
                      <Badge key={c}>{c}</Badge>
                    ))}
                  </SpaceBetween>
                )}
              </SpaceBetween>
            </Container>

            <Container header={<Header variant="h2" description={t('policy.checkDesc')}>{t('policy.check')}</Header>}>
              <SpaceBetween size="m">
                <ColumnLayout columns={3}>
                  <FormField label={t('policy.checkTarget')} errorText={checkError}>
                    <Input value={checkTarget} onChange={({ detail }) => setCheckTarget(detail.value)} placeholder="www.example.com" />
                  </FormField>
                  <FormField label={t('policy.checkPort')}>
                    <Input value={checkPort} onChange={({ detail }) => setCheckPort(detail.value)} inputMode="numeric" placeholder="443" />
                  </FormField>
                  <FormField label=" ">
                    <Button formAction="none" disabled={!checkTarget.trim()} onClick={() => void runCheck()}>
                      {t('policy.checkRun')}
                    </Button>
                  </FormField>
                </ColumnLayout>
                {check && (
                  <StatusIndicator type={check.allowed ? 'success' : 'error'}>
                    {check.allowed ? t('policy.checkAllowed') : t('policy.checkDenied', { reason: check.reason })}
                  </StatusIndicator>
                )}
              </SpaceBetween>
            </Container>
          </SpaceBetween>
        </Form>
      </form>
    </ContentLayout>
  );
}
