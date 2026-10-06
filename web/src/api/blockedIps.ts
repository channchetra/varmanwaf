import { apiClient } from './client'
import type { BlockedIp, UnblockIpResponse } from './types'

/**
 * Auto-blocked IPs — `/api/v1/sites/{siteId}/blocked-ips`.
 *
 * Dynamic blocks the edge enforces for a site (WAF/rate-limit auto-blocks
 * plus server-issued block commands). The list is reconciled from every
 * agent heartbeat; the UI polls it because blocks appear and expire without
 * any user action.
 */
export const blockedIpsApi = {
  list: (siteId: string) =>
    apiClient.get<BlockedIp[]>(`/sites/${siteId}/blocked-ips`),

  unblock: (siteId: string, ip: string) =>
    apiClient.post<UnblockIpResponse>(
      `/sites/${siteId}/blocked-ips/unblock`,
      { ip },
    ),
}

export const blockedIpKeys = {
  all: (siteId: string) => ['sites', siteId, 'blocked-ips'] as const,
  list: (siteId: string) =>
    ['sites', siteId, 'blocked-ips', 'list'] as const,
}

export default blockedIpsApi
