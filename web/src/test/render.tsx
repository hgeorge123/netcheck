import { render, type RenderResult } from '@testing-library/react';
import type { ReactElement } from 'react';
import { I18nProvider, type Language } from '../i18n';

/** Renders inside the i18n provider (English unless stated). */
export function renderI18n(ui: ReactElement, lang: Language = 'en'): RenderResult {
  return render(<I18nProvider initial={lang}>{ui}</I18nProvider>);
}
