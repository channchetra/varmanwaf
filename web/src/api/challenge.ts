import { apiClient } from './client'
import type { ChallengeConfig, UpdateChallengeRequest } from './types'

/**
 * CC protection / challenge — `/api/v1/sites/{siteId}/challenge`.
 *
 * A single per-site record: the master toggle, under-attack mode, the default
 * challenge level, clearance duration, the per-IP rate threshold and the path
 * exemptions. `GET` creates the row with defaults when absent.
 */
export const challengeApi = {
  get: (siteId: string) =>
    apiClient.get<ChallengeConfig>(`/sites/${siteId}/challenge`),

  update: (siteId: string, data: UpdateChallengeRequest) =>
    apiClient.put<ChallengeConfig>(`/sites/${siteId}/challenge`, data),
}

/** Sensible defaults matching the server-side `find_or_create` row. */
export function defaultChallengeConfig(): ChallengeConfig {
  return {
    enabled: false,
    under_attack_mode: false,
    default_level: 'non_interactive',
    clearance_duration_secs: 1800,
    rate_threshold: 100,
    exempt_paths: [],
    browser_integrity_check: true,
    tls_fingerprint_check: false,
  }
}

export const challengeKeys = {
  all: (siteId: string) => ['sites', siteId, 'challenge'] as const,
  config: (siteId: string) => ['sites', siteId, 'challenge', 'config'] as const,
}

export default challengeApi
