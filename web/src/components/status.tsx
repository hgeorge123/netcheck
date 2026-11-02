import StatusIndicator, { type StatusIndicatorProps } from '@cloudscape-design/components/status-indicator';
import { lookup, useI18n, type MessageKey, type Translate } from '../i18n';
import type { CheckStatus, Diagnosis, Method, RunStatus, Severity } from '../types/api';

export const methodKey = (m: Method): MessageKey => `method.${m}`;

const runStatusType: Record<RunStatus, StatusIndicatorProps.Type> = {
  queued: 'pending',
  running: 'in-progress',
  succeeded: 'success',
  failed: 'error',
  cancelled: 'stopped',
  // Infrastructure errors are not network results: never shown as red.
  infra_error: 'warning',
};

const severityType: Record<Severity, StatusIndicatorProps.Type> = {
  success: 'success',
  info: 'info',
  warning: 'warning',
  error: 'error',
};

export const isTerminal = (s: RunStatus): boolean => s !== 'queued' && s !== 'running';

// Screen readers announce the severity, not only the colour.
const iconLabel = (t: Translate, type: StatusIndicatorProps.Type) => lookup(t, `severity.${type}`);

export function RunStatusBadge({ status }: { status: RunStatus }) {
  const { t } = useI18n();
  const type = runStatusType[status] ?? 'info';
  return (
    <StatusIndicator type={type} iconAriaLabel={iconLabel(t, type)}>
      {lookup(t, `runStatus.${status}`) ?? status}
    </StatusIndicator>
  );
}

/** Check status driven by the diagnosis severity so that e.g. HTTP 404 is not red. */
export function CheckStatusBadge({ status, diagnosis }: { status: CheckStatus; diagnosis?: Diagnosis }) {
  const { t } = useI18n();
  let type: StatusIndicatorProps.Type;
  if (status === 'queued') type = 'pending';
  else if (status === 'running') type = 'in-progress';
  else if (status === 'infra_error') type = 'warning';
  else if (status === 'cancelled') type = 'stopped';
  else if (diagnosis) type = severityType[diagnosis.severity];
  else type = status === 'succeeded' ? 'success' : 'error';
  return (
    <StatusIndicator type={type} iconAriaLabel={iconLabel(t, type)}>
      {lookup(t, `checkStatus.${status}`) ?? status}
    </StatusIndicator>
  );
}

/** Translated diagnosis texts, chosen by category (and HTTP status). */
export function diagnosisText(t: Translate, method: Method, d: Diagnosis): { summary: string; detail: string } {
  if (d.category === 'ok') {
    return { summary: lookup(t, `diag.ok.${method}`) ?? t('diag.ok'), detail: lookup(t, `diag.ok.${method}.detail`) ?? '' };
  }
  if (d.category === 'http_response' && d.httpStatus) {
    const c = d.httpStatus;
    let detail: MessageKey | undefined;
    if (c >= 300 && c < 400) detail = 'diag.http.3xx';
    else if (c === 401 || c === 403) detail = 'diag.http.auth';
    else if (c === 404) detail = 'diag.http.404';
    else if (c >= 400 && c < 500) detail = 'diag.http.4xx';
    else if (c >= 500) detail = 'diag.http.5xx';
    return { summary: t('diag.http_response', { code: c }), detail: detail ? t(detail) : '' };
  }
  return {
    summary: lookup(t, `diag.${d.category}`) ?? d.summary,
    detail: lookup(t, `diag.${d.category}.detail`) ?? d.detail,
  };
}

/** Short label for a failure category in lists. */
export const categoryLabel = (t: Translate, category?: string): string =>
  category ? (lookup(t, `diag.${category}`) ?? category) : '—';
