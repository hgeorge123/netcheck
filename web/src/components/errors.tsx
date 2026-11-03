import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import { lookup, useI18n, type Translate } from '../i18n';
import { ApiError } from '../services/api';
import type { FieldError } from '../types/api';

/** Translated message for an API failure, chosen by its error code. */
export function errorText(t: Translate, err: unknown): string {
  if (err instanceof ApiError) return lookup(t, `error.${err.code}`) ?? (err.message || t('error.generic'));
  return t('error.generic');
}

/**
 * Translated message for a server field error, chosen by its code. Policy
 * denials keep the server's technical reason (which range, suffix or port).
 */
export function fieldErrorText(t: Translate, fe: FieldError): string {
  const text = lookup(t, `field.${fe.code}`);
  if (!text) return fe.message;
  return fe.code === 'destination_denied' && fe.message ? `${text} ${t('field.deniedReason', { reason: fe.message })}` : text;
}

/** Translated server field errors keyed by field name, for FormField errorText. */
export function fieldErrors(t: Translate, err: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (err instanceof ApiError) for (const d of err.details) out[d.field] ??= fieldErrorText(t, d);
  return out;
}

/** Error alert with the field details and the request id for support. */
export function ErrorAlert({ error, header }: { error: unknown; header?: string }) {
  const { t } = useI18n();
  const details = error instanceof ApiError ? error.details : [];
  const requestId = error instanceof ApiError ? error.requestId : undefined;
  return (
    <Alert type="error" header={header}>
      {errorText(t, error)}
      {details.length > 0 && (
        <ul>
          {details.map((d) => (
            <li key={`${d.field}:${d.code}`}>
              <code>{d.field}</code>: {fieldErrorText(t, d)}
            </li>
          ))}
        </ul>
      )}
      {requestId && (
        <Box variant="small" color="text-body-secondary">
          {t('common.requestId', { id: requestId })}
        </Box>
      )}
    </Alert>
  );
}
