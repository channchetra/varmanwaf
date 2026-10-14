import { apiClient } from './client'
import type { FailoverPolicy, FailoverSettings } from './types'

/**
 * Site-level failover policy - `/api/v1/sites/{siteId}/failover`.
 *
 * Decides how the site behaves while the control plane is unreachable and
 * the host has no synced rule bundle: `inherit` follows the control
 * plane's `default_fail_open`, `open` keeps proxying through the base
 * engine, `closed` answers 503.
 */
export const failoverApi = {
  get: (siteId: string) =>
    apiClient.get<FailoverSettings>(`/sites/${siteId}/failover`),

  update: (siteId: string, policy: FailoverPolicy) =>
    apiClient.put<FailoverSettings>(`/sites/${siteId}/failover`, {
      policy,
    }),
}

export const failoverKeys = {
  all: (siteId: string) => ['sites', siteId, 'failover'] as const,
}

export default failoverApi
