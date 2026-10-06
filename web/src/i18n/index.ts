import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

import { setDisplayLocale } from '@/lib/format'

import en from './locales/en/common.json'

/**
 * VarmanWAF serves an English-only console. The language list is exported for
 * the pickers, which therefore render a single option; the i18n stack stays in
 * place so future locales can be added deliberately.
 */
export const supportedLanguages = ['en'] as const
export type SupportedLanguage = (typeof supportedLanguages)[number]

void i18n.use(initReactI18next).init({
  resources: { en: { common: en } },
  lng: 'en',
  fallbackLng: 'en',
  supportedLngs: ['en'],
  defaultNS: 'common',
  ns: ['common'],
  load: 'currentOnly',
  interpolation: {
    escapeValue: false, // React already escapes rendered output
  },
  react: {
    useSuspense: false,
  },
})

/** Always resolves to the sole supported base code. */
export function normalizeLanguage(_code?: string): SupportedLanguage {
  return 'en'
}

/** Region-tagged locale the date formatters use. */
setDisplayLocale('en-US')

export default i18n
