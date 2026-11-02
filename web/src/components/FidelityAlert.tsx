import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import { useI18n } from '../i18n';
import type { Fidelity, FidelityLevel } from '../types/api';

const levelType: Record<FidelityLevel, 'info' | 'warning'> = {
  'namespace-wide-likely': 'info',
  'specific-selectors-detected': 'warning',
  'no-native-egress-policies': 'info',
  unknown: 'warning',
};

export function FidelityAlert({ fidelity }: { fidelity?: Fidelity }) {
  const { t } = useI18n();
  if (!fidelity) {
    return (
      <Alert type="warning" header={t('fidelity.notEvaluated')}>
        {t('fidelity.probeNote')}
      </Alert>
    );
  }
  const level: FidelityLevel = fidelity.level in levelType ? fidelity.level : 'unknown';
  return (
    <Alert type={levelType[level]} header={t(`fidelity.${level}`)}>
      <SpaceBetween size="xs">
        <Box>{t('fidelity.probeNote')}</Box>
        <Box>{t(`fidelity.note.${level}`)}</Box>
        {fidelity.egressPolicies.length > 0 && (
          <Box>
            {t('fidelity.policies', {
              list: fidelity.egressPolicies
                .map((p) => `${p.name} (${p.podSelector || '{}'}, ${t(p.selectsProbe ? 'fidelity.appliesToProbe' : 'fidelity.notAppliesToProbe')})`)
                .join('; '),
            })}
          </Box>
        )}
        <Box variant="small">{t('fidelity.note.cni')}</Box>
        <Box variant="small">{t('fidelity.note.destination')}</Box>
      </SpaceBetween>
    </Alert>
  );
}
