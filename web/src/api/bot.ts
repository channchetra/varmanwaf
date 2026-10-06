import { apiClient } from './client'
import type { BotConfig, UpdateBotRequest } from './types'

/**
 * Bot protection — `/api/v1/sites/{siteId}/bot-protection`.
 *
 * One per-site record: the toggle, the User-Agent analysis method, the action
 * for non-browser clients and a whitelist of verified-bot UA substrings. The
 * whole record is saved with a single PUT.
 */
export const botApi = {
  get: (siteId: string) => apiClient.get<BotConfig>(`/sites/${siteId}/bot-protection`),

  update: (siteId: string, data: UpdateBotRequest) =>
    apiClient.put<BotConfig>(`/sites/${siteId}/bot-protection`, data),
}

/** Defaults matching the server-side `find_or_create` row. */
export function defaultBotConfig(siteId: string): BotConfig {
  return {
    id: '',
    site_id: siteId,
    enabled: false,
    ua_analysis: true,
    js_detection: true,
    tls_fingerprint: false,
    behavioral_analysis: false,
    action: 'challenge',
    known_bots_whitelist: [],
    updated_at: '',
  }
}

/** Well-known good crawlers offered as one-click whitelist entries. */
export const COMMON_KNOWN_BOTS = [
  'Googlebot',
  'bingbot',
  'DuckDuckBot',
  'YandexBot',
  'Baiduspider',
  'Slackbot',
  'Twitterbot',
  'facebookexternalhit',
]

export const botKeys = {
  all: (siteId: string) => ['sites', siteId, 'bot-protection'] as const,
  config: (siteId: string) => ['sites', siteId, 'bot-protection', 'config'] as const,
}

export default botApi
