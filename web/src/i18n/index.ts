import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

import { setDisplayLocale } from '@/lib/format'

import en from './locales/en/common.json'
import zh from './locales/zh/common.json'
import ja from './locales/ja/common.json'

export const supportedLanguages = ['en', 'zh', 'ja'] as const
export type SupportedLanguage = (typeof supportedLanguages)[number]

const resources = {
  en: { common: en },
  zh: { common: zh },
  ja: { common: ja },
}

/** Normalise variants such as zh-CN / zh-TW / en-US to a supported base code. */
function normalizeLanguage(code?: string): SupportedLanguage {
  if (!code) return 'en'
  const base = code.toLowerCase().split('-')[0]
  return (supportedLanguages as readonly string[]).includes(base)
    ? (base as SupportedLanguage)
    : 'en'
}

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: 'en',
    supportedLngs: supportedLanguages as unknown as string[],
    defaultNS: 'common',
    ns: ['common'],
    load: 'currentOnly',
    interpolation: {
      escapeValue: false, // React already escapes rendered output
    },
    detection: {
      // browser → localStorage → fallback
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'pingwaf.lang',
      caches: ['localStorage'],
    },
    react: {
      useSuspense: false,
    },
  })

// Ensure the active language is always a supported base code.
const normalized = normalizeLanguage(i18n.language)
if (i18n.language !== normalized) {
  void i18n.changeLanguage(normalized)
}

/**
 * Region-tagged locale the date formatters use.
 *
 * Dates follow the chosen UI language rather than the browser locale: a
 * console in Chinese reads `2026年9月30日` even on an English machine.
 */
function intlLocale(language: string): string {
  switch (normalizeLanguage(language)) {
    case 'zh':
      return 'zh-CN'
    case 'ja':
      return 'ja-JP'
    default:
      return 'en-US'
  }
}

i18n.on('languageChanged', (language) =>
  setDisplayLocale(intlLocale(language)),
)
setDisplayLocale(intlLocale(normalized))

export { normalizeLanguage }
export default i18n
