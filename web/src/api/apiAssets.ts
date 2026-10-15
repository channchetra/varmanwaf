import { apiClient } from './client'

/** The site's declared OpenAPI document, as far as the inventory uses it. */
export interface ApiAssetsSpec {
  configured: boolean
  title: string | null
  version: string | null
  paths: number
  operations: number
  parse_error: string | null
}

export interface ObservedEndpoint {
  method: string
  path: string
  count: number
  errors: number
  first_seen: string
  last_seen: string
  in_spec: boolean
  spec_path: string | null
}

export interface SpecOperation {
  method: string
  path: string
}

export interface ApiAssets {
  site_id: string
  from: string
  to: string
  window_days: number
  spec: ApiAssetsSpec
  observed: ObservedEndpoint[]
  observed_truncated: boolean
  spec_only: SpecOperation[]
  limitations: string[]
}

export const apiAssetsApi = {
  list: (siteId: string, days: number) =>
    apiClient.get<ApiAssets>(`/sites/${siteId}/api-assets?days=${days}`),
}

export const apiAssetsKeys = {
  all: ['api-assets'] as const,
  list: (siteId: string, days: number) =>
    [...apiAssetsKeys.all, siteId, days] as const,
}

export default apiAssetsApi
