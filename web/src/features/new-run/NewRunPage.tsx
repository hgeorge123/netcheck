import Alert from '@cloudscape-design/components/alert';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Cards from '@cloudscape-design/components/cards';
import Checkbox from '@cloudscape-design/components/checkbox';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Link from '@cloudscape-design/components/link';
import RadioGroup from '@cloudscape-design/components/radio-group';
import SegmentedControl from '@cloudscape-design/components/segmented-control';
import Select, { type SelectProps } from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Tiles from '@cloudscape-design/components/tiles';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { ErrorAlert, fieldErrorText } from '../../components/errors';
import { methodKey } from '../../components/status';
import { useI18n } from '../../i18n';
import { ApiError } from '../../services/api';
import { UDP_PROTOCOLS, type Catalog, type CatalogEntry, type Method, type NamespaceGrant, type RunRequest, type UDPProtocol } from '../../types/api';
import {
  buildRequest,
  DEFAULT_UDP_PORTS,
  emptyForm,
  firewallScheme,
  isIPLiteral,
  mapServerErrors,
  MAX_HOPS,
  MAX_PING_COUNT,
  validateForm,
  type FormError,
  type FirewallScheme,
  type FormErrors,
  type FormField as Field,
  type RunForm,
  type RunMode,
} from './validation';

interface Props {
  namespaces: NamespaceGrant[];
  catalog: Catalog;
  submit: (req: RunRequest) => Promise<{ id: string }>;
  onCreated: (id: string) => void;
  /** Loads a previous run to pre-fill the form ("Run again"). */
  prefill?: () => Promise<RunForm>;
  onInfo?: () => void;
}

const httpMethodOptions: SelectProps.Option[] = [
  { value: 'GET', label: 'GET' },
  { value: 'HEAD', label: 'HEAD' },
];

export function NewRunPage({ namespaces, catalog, submit, onCreated, prefill, onInfo }: Props) {
  const { t } = useI18n();
  const runnable = namespaces.filter((n) => n.canRun);
  const [form, setForm] = useState<RunForm>(() => emptyForm(runnable.length === 1 ? runnable[0]?.name : ''));
  const [errors, setErrors] = useState<FormErrors>({});
  const [serverError, setServerError] = useState<unknown>(null);
  const [submitting, setSubmitting] = useState(false);
  const set = <K extends keyof RunForm>(k: K, v: RunForm[K]) => setForm((f) => ({ ...f, [k]: v }));

  useEffect(() => {
    if (!prefill) return;
    let alive = true;
    prefill()
      .then((f) => alive && setForm(f))
      .catch((e: unknown) => alive && setServerError(e));
    return () => {
      alive = false;
    };
  }, [prefill]);

  const msg = (e?: FormError) => (e ? ('text' in e ? e.text : t(e.key, e.params)) : undefined);
  const err = (f: Field) => msg(errors[f]);
  const nsOptions: SelectProps.Option[] = runnable.map((n) => ({ value: n.name, label: n.name }));
  const preview = useMemo(() => buildRequest(form), [form]);
  const { limits } = catalog;
  const targetIsIP = isIPLiteral(form.target.trim());
  const selected = catalog.items.filter((c) => form.methods.includes(c.method));
  const familyOptions: SelectProps.Option[] = [
    { value: 'ip', label: t('newTest.family.ip') },
    { value: 'ip4', label: t('newTest.family.ip4') },
    { value: 'ip6', label: t('newTest.family.ip6') },
  ];

  const selectAll = () => {
    const all = catalog.items.filter((c) => !(c.hostnameOnly && targetIsIP)).map((c) => c.method);
    set('methods', all.slice(0, limits.maxChecks));
  };

  const onSubmit = async () => {
    setServerError(null);
    const e = validateForm(form, limits.maxCheckTimeoutSeconds);
    setErrors(e);
    if (Object.keys(e).length > 0) return;
    const req = buildRequest(form);
    setSubmitting(true);
    try {
      const { id } = await submit(req);
      onCreated(id);
    } catch (ex) {
      if (ex instanceof ApiError && ex.details.length > 0) setErrors(mapServerErrors(ex.details, req, (d) => fieldErrorText(t, d)));
      setServerError(ex);
    } finally {
      setSubmitting(false);
    }
  };

  if (runnable.length === 0) {
    return (
      <ContentLayout header={<Header variant="h1">{t('newTest.title')}</Header>}>
        <Alert type="info" header={t('newTest.noNamespacesTitle')}>
          {t('newTest.noNamespacesBody')}
        </Alert>
      </ContentLayout>
    );
  }

  const cardBadges = (c: CatalogEntry) => {
    const badges: ReactNode[] = [];
    if (c.method === 'udp') badges.push(<Badge key="u">{t('newTest.udpModes')}</Badge>);
    else if (c.defaultPort) badges.push(<Badge key="p">{t('newTest.defaultPort', { port: c.defaultPort })}</Badge>);
    else if (c.requiresPort) badges.push(<Badge key="r" color="blue">{t('newTest.portRequired')}</Badge>);
    if (c.hostnameOnly) badges.push(<Badge key="h">{t('newTest.hostnameOnly')}</Badge>);
    return badges.length > 0 ? <SpaceBetween direction="horizontal" size="xs">{badges}</SpaceBetween> : null;
  };

  const settings: Record<Method, ReactNode> = {
    dns: (
      <FormField label={t('newTest.dnsFamily')}>
        <Select
          selectedOption={familyOptions.find((o) => o.value === form.dnsFamily) ?? null}
          onChange={({ detail }) => set('dnsFamily', detail.selectedOption.value as RunForm['dnsFamily'])}
          options={familyOptions}
        />
      </FormField>
    ),
    tcp: (
      <FormField label={t('newTest.port')} description={t('newTest.tcpPortDesc')} errorText={err('tcpPort')}>
        <Input value={form.tcpPort} onChange={({ detail }) => set('tcpPort', detail.value)} inputMode="numeric" placeholder="5432" ariaRequired />
      </FormField>
    ),
    udp: (
      <ColumnLayout columns={2}>
        <FormField label={t('newTest.udpProtocol')} description={t('newTest.udpProtocolDesc')}>
          <RadioGroup
            value={form.udpProtocol}
            onChange={({ detail }) => set('udpProtocol', detail.value as UDPProtocol)}
            items={UDP_PROTOCOLS.map((p) => ({ value: p, label: t(`newTest.udp.${p}`), description: t(`newTest.udp.${p}.desc`) }))}
            ariaLabel={t('newTest.udpProtocol')}
          />
        </FormField>
        <FormField
          label={t('newTest.port')}
          description={
            form.udpProtocol === 'generic' ? t('newTest.udpPortGenericDesc') : t('newTest.udpPortDefaultDesc', { port: DEFAULT_UDP_PORTS[form.udpProtocol] ?? '' })
          }
          errorText={err('udpPort')}
        >
          <Input
            value={form.udpPort}
            onChange={({ detail }) => set('udpPort', detail.value)}
            inputMode="numeric"
            placeholder={String(DEFAULT_UDP_PORTS[form.udpProtocol] ?? 514)}
            ariaRequired={form.udpProtocol === 'generic'}
          />
        </FormField>
      </ColumnLayout>
    ),
    http: (
      <ColumnLayout columns={3}>
        <FormField label={t('newTest.port')} description={t('newTest.httpPortDesc')} errorText={err('httpPort')}>
          <Input value={form.httpPort} onChange={({ detail }) => set('httpPort', detail.value)} inputMode="numeric" placeholder="80" />
        </FormField>
        <FormField label={t('newTest.httpMethod')}>
          <SegmentedControl
            selectedId={form.httpMethod}
            onChange={({ detail }) => set('httpMethod', detail.selectedId as RunForm['httpMethod'])}
            options={httpMethodOptions.map((o) => ({ id: o.value ?? '', text: o.label ?? '' }))}
            label={`HTTP ${t('newTest.httpMethod')}`}
          />
        </FormField>
        <FormField label={t('newTest.path')} errorText={err('httpPath')}>
          <Input value={form.httpPath} onChange={({ detail }) => set('httpPath', detail.value)} placeholder="/healthz" />
        </FormField>
      </ColumnLayout>
    ),
    https: (
      <ColumnLayout columns={3}>
        <FormField label={t('newTest.port')} description={t('newTest.httpsPortDesc')} errorText={err('httpsPort')}>
          <Input value={form.httpsPort} onChange={({ detail }) => set('httpsPort', detail.value)} inputMode="numeric" placeholder="443" />
        </FormField>
        <FormField label={t('newTest.httpMethod')}>
          <SegmentedControl
            selectedId={form.httpsMethod}
            onChange={({ detail }) => set('httpsMethod', detail.selectedId as RunForm['httpsMethod'])}
            options={httpMethodOptions.map((o) => ({ id: o.value ?? '', text: o.label ?? '' }))}
            label={`HTTPS ${t('newTest.httpMethod')}`}
          />
        </FormField>
        <FormField label={t('newTest.path')} errorText={err('httpsPath')}>
          <Input value={form.httpsPath} onChange={({ detail }) => set('httpsPath', detail.value)} placeholder="/healthz" />
        </FormField>
        <FormField description={t('newTest.ignoreTlsDesc')}>
          <Checkbox checked={form.httpsIgnoreTls} onChange={({ detail }) => set('httpsIgnoreTls', detail.checked)}>
            {t('newTest.ignoreTls')}
          </Checkbox>
        </FormField>
      </ColumnLayout>
    ),
    ping: (
      <FormField label={t('newTest.pingCount')} description={t('newTest.pingCountDesc', { max: MAX_PING_COUNT })} errorText={err('pingCount')}>
        <Input value={form.pingCount} onChange={({ detail }) => set('pingCount', detail.value)} inputMode="numeric" />
      </FormField>
    ),
    traceroute: (
      <FormField label={t('newTest.maxHops')} description={t('newTest.maxHopsDesc', { max: MAX_HOPS })} errorText={err('maxHops')}>
        <Input value={form.maxHops} onChange={({ detail }) => set('maxHops', detail.value)} inputMode="numeric" />
      </FormField>
    ),
  };

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={t('newTest.description')}
          info={onInfo && <Link variant="info" onFollow={onInfo}>{t('common.info')}</Link>}
        >
          {t('newTest.title')}
        </Header>
      }
    >
      <form onSubmit={(e) => e.preventDefault()}>
        <Form
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button
                variant="link"
                formAction="none"
                onClick={() => {
                  setForm({ ...emptyForm(form.namespace), mode: form.mode });
                  setErrors({});
                  setServerError(null);
                }}
              >
                {t('newTest.clear')}
              </Button>
              <Button variant="primary" loading={submitting} onClick={() => void onSubmit()}>
                {t('newTest.run')}
              </Button>
            </SpaceBetween>
          }
          errorText={serverError ? <ErrorAlert error={serverError} /> : undefined}
        >
          <SpaceBetween size="l">
            <Container header={<Header variant="h2">{t('newTest.mode')}</Header>}>
              <Tiles
                value={form.mode}
                onChange={({ detail }) => {
                  set('mode', detail.value as RunMode);
                  setErrors({});
                }}
                ariaLabel={t('newTest.mode')}
                columns={2}
                items={[
                  { value: 'custom', label: t('newTest.mode.custom'), description: t('newTest.mode.customDesc') },
                  { value: 'firewall', label: t('newTest.mode.firewall'), description: t('newTest.mode.firewallDesc') },
                ]}
              />
            </Container>

            <Container header={<Header variant="h2">{t('newTest.sourceDest')}</Header>}>
              <ColumnLayout columns={2}>
                <FormField label={t('newTest.namespace')} description={t('newTest.namespaceDesc')} errorText={err('namespace')}>
                  <Select
                    selectedOption={nsOptions.find((o) => o.value === form.namespace) ?? null}
                    onChange={({ detail }) => set('namespace', detail.selectedOption.value ?? '')}
                    options={nsOptions}
                    placeholder={t('newTest.namespacePlaceholder')}
                    filteringType={nsOptions.length > 8 ? 'auto' : 'none'}
                    empty={t('common.noMatches')}
                  />
                </FormField>
                <FormField label={t('newTest.target')} description={t('newTest.targetDesc')} errorText={err('target')}>
                  <Input
                    value={form.target}
                    onChange={({ detail }) => set('target', detail.value)}
                    placeholder={t('newTest.targetPlaceholder')}
                    spellcheck={false}
                    autoComplete={false}
                  />
                </FormField>
              </ColumnLayout>
            </Container>

            {form.mode === 'firewall' && (
              <Container header={<Header variant="h2" description={t('newTest.fwDesc')}>{t('newTest.fwTitle')}</Header>}>
                <SpaceBetween size="m">
                  <ColumnLayout columns={2}>
                    <FormField label={t('newTest.fwPort')} description={t('newTest.fwPortDesc')} errorText={err('fwPort')}>
                      <Input value={form.fwPort} onChange={({ detail }) => set('fwPort', detail.value)} inputMode="numeric" placeholder="443" ariaRequired />
                    </FormField>
                    <FormField label={t('newTest.fwScheme')}>
                      <SegmentedControl
                        selectedId={form.fwScheme}
                        onChange={({ detail }) => set('fwScheme', detail.selectedId as FirewallScheme)}
                        label={t('newTest.fwScheme')}
                        options={[
                          { id: 'auto', text: t('newTest.fwScheme.auto', { scheme: firewallScheme({ ...form, fwScheme: 'auto' }).toUpperCase() }) },
                          { id: 'http', text: 'HTTP' },
                          { id: 'https', text: 'HTTPS' },
                        ]}
                      />
                    </FormField>
                  </ColumnLayout>
                  <Box variant="small" color="text-body-secondary">
                    {t('newTest.fwIncludes', { port: form.fwPort || '<port>', scheme: firewallScheme(form) })}
                  </Box>
                </SpaceBetween>
              </Container>
            )}

            {form.mode === 'custom' && (
              <FormField stretch errorText={err('methods')}>
                <Cards<CatalogEntry>
                  items={catalog.items}
                  trackBy="method"
                  selectionType="multi"
                  selectedItems={selected}
                  onSelectionChange={({ detail }) => set('methods', detail.selectedItems.map((c) => c.method))}
                  isItemDisabled={(c) => (c.hostnameOnly && targetIsIP) || (!form.methods.includes(c.method) && form.methods.length >= limits.maxChecks)}
                  cardsPerRow={[{ cards: 1 }, { minWidth: 600, cards: 2 }, { minWidth: 960, cards: 3 }]}
                  cardDefinition={{
                    header: (c) => t(methodKey(c.method)),
                    sections: [{ id: 'desc', content: (c) => t(`method.${c.method}.desc`) }, { id: 'badges', content: cardBadges }],
                  }}
                  ariaLabels={{
                    itemSelectionLabel: (_, c) => t(methodKey(c.method)),
                    selectionGroupLabel: t('newTest.checks'),
                  }}
                  header={
                    <Header
                      variant="h2"
                      counter={`(${form.methods.length}/${limits.maxChecks})`}
                      description={t('newTest.checksDesc')}
                      actions={<Button onClick={selectAll}>{t('newTest.fullDiagnosis')}</Button>}
                    >
                      {t('newTest.checks')}
                    </Header>
                  }
                />
              </FormField>
            )}

            {form.mode === 'custom' && selected.length > 0 && (
              <Container header={<Header variant="h2">{t('newTest.settings')}</Header>}>
                <SpaceBetween size="l">
                  {selected.map((c) => (
                    <SpaceBetween key={c.method} size="xs">
                      <Box variant="h3">{t(methodKey(c.method))}</Box>
                      {settings[c.method]}
                    </SpaceBetween>
                  ))}
                </SpaceBetween>
              </Container>
            )}

            <ExpandableSection variant="container" headerText={t('newTest.advanced')}>
              <SpaceBetween size="m">
                <FormField
                  label={t('newTest.timeout')}
                  description={t('newTest.timeoutDesc', { def: limits.defaultCheckTimeoutSeconds, max: limits.maxCheckTimeoutSeconds })}
                  errorText={err('timeoutSeconds')}
                >
                  <Input
                    value={form.timeoutSeconds}
                    onChange={({ detail }) => set('timeoutSeconds', detail.value)}
                    inputMode="numeric"
                    placeholder={String(limits.defaultCheckTimeoutSeconds)}
                  />
                </FormField>
                {limits.settleSeconds > 0 && <Box color="text-body-secondary">{t('newTest.settleNote', { n: limits.settleSeconds })}</Box>}
              </SpaceBetween>
            </ExpandableSection>

            <ExpandableSection variant="container" headerText={t('newTest.preview')} headerDescription={t('newTest.previewDesc')}>
              <Box variant="code">
                <pre data-testid="request-preview" style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{JSON.stringify(preview, null, 2)}</pre>
              </Box>
            </ExpandableSection>
          </SpaceBetween>
        </Form>
      </form>
    </ContentLayout>
  );
}
