import { apiClient } from './client'
import type { SiteBasicAuth, UpdateBasicAuthRequest } from './types'

/**
 * Per-site HTTP basic authentication — `/api/v1/sites/{siteId}/basic-auth`.
 *
 * The credentials are enforced by the data plane before the cache, so a
 * stored response can never answer an unauthenticated request. Passwords are
 * masked with `***` in responses: send the mask back to keep a stored
 * password unchanged.
 */
export const siteBasicAuthApi = {
  get: (siteId: string) =>
    apiClient.get<SiteBasicAuth>(`/sites/${siteId}/basic-auth`),

  update: (siteId: string, data: UpdateBasicAuthRequest) =>
    apiClient.put<SiteBasicAuth>(`/sites/${siteId}/basic-auth`, data),
}

export const siteBasicAuthKeys = {
  all: ['site-basic-auth'] as const,
  detail: (siteId: string) => [...siteBasicAuthKeys.all, siteId] as const,
}

/** The shape the server creates for a site that never saved credentials. */
export function defaultSiteBasicAuth(siteId: string): SiteBasicAuth {
  const now = new Date().toISOString()
  return {
    id: '',
    site_id: siteId,
    enabled: false,
    realm: 'Restricted',
    credentials: [],
    delay_seconds: 1,
    hide_credentials: false,
    created_at: now,
    updated_at: now,
  }
}

export default siteBasicAuthApi
