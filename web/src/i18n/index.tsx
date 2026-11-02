import { I18nProvider as CloudscapeI18n } from '@cloudscape-design/components/i18n';
import cloudscapeEn from '@cloudscape-design/components/i18n/messages/all.en';
import cloudscapeEs from '@cloudscape-design/components/i18n/messages/all.es';
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { en, type MessageKey } from './en';
import { es } from './es';

export type Language = 'en' | 'es';
export const LANGUAGES: Language[] = ['en', 'es'];
export type { MessageKey };

const dictionaries: Record<Language, Record<MessageKey, string>> = { en, es };
const cloudscapeMessages = { en: cloudscapeEn, es: cloudscapeEs };
// Remembers the last choice only to render the sign-in page; once signed in
// the language stored in the user's account wins. Browser settings are
// deliberately ignored: English is the default.
const STORAGE_KEY = 'netcheck.language';

export const isLanguage = (v: unknown): v is Language => v === 'en' || v === 'es';

function storedLanguage(): Language {
  try {
    const v = window.localStorage.getItem(STORAGE_KEY);
    return isLanguage(v) ? v : 'en';
  } catch {
    return 'en';
  }
}

export type Params = Record<string, string | number>;
export type Translate = (key: MessageKey, params?: Params) => string;

export function format(template: string, params?: Params): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (m, k: string) => (k in params ? String(params[k]) : m));
}

export function translator(lang: Language): Translate {
  const dict = dictionaries[lang];
  return (key, params) => format(dict[key] ?? en[key] ?? key, params);
}

/** Looks up a key built at runtime (e.g. a server error code); undefined when unknown. */
export function lookup(t: Translate, key: string, params?: Params): string | undefined {
  return key in en ? t(key as MessageKey, params) : undefined;
}

interface I18nValue {
  lang: Language;
  t: Translate;
  setLanguage: (l: Language) => void;
  formatDate: (iso?: string) => string;
}

const I18nContext = createContext<I18nValue | undefined>(undefined);

export function I18nProvider({ children, initial }: { children: ReactNode; initial?: Language }) {
  const [lang, setLang] = useState<Language>(() => initial ?? storedLanguage());
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);
  const setLanguage = useCallback((l: Language) => {
    setLang(l);
    try {
      window.localStorage.setItem(STORAGE_KEY, l);
    } catch {
      // Storage unavailable: the choice lasts until reload (the account keeps it).
    }
  }, []);
  const value = useMemo<I18nValue>(() => {
    const dtf = new Intl.DateTimeFormat(lang === 'es' ? 'es-ES' : 'en-US', { dateStyle: 'medium', timeStyle: 'medium' });
    return {
      lang,
      t: translator(lang),
      setLanguage,
      formatDate: (iso?: string) => (iso ? dtf.format(new Date(iso)) : '—'),
    };
  }, [lang, setLanguage]);
  return (
    <I18nContext.Provider value={value}>
      <CloudscapeI18n locale={lang} messages={[cloudscapeMessages[lang]]}>
        {children}
      </CloudscapeI18n>
    </I18nContext.Provider>
  );
}

export function useI18n(): I18nValue {
  const v = useContext(I18nContext);
  if (!v) throw new Error('useI18n outside I18nProvider');
  return v;
}
