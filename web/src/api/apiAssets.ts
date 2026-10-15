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

/** One learned endpoint structure (keys, types and counts only). */
export interface LearnedSchema {
  id: string
  site_id: string
  method: string
  path: string
  request_schema: {
    types?: string[]
    keys?: Record<string, unknown>
    items?: unknown
    presence?: number
  } | null
  query_schema: Record<string, { types: string[]; count: number }>
  /** Response structures per status class (`2xx`, `4xx`, ...). */
  response_schema: Record<string, unknown> | null
  /** JSON response bodies merged into the response structures. */
  response_samples: number
  sample_count: number
  /** Per-operation API control: `off`, `observe` or `enforce`. */
  mode: string
  first_seen: string | null
  last_seen: string | null
  updated_at: string
}

export interface LearnSummary {
  window_days: number
  endpoints: number
  samples: number
  skipped_truncated: number
  skipped_non_json: number
  /** JSON response bodies merged into the response structures. */
  response_samples: number
  /** Response bodies skipped (truncated or not JSON). */
  response_skipped: number
  rows_scanned: number
  truncated_scan: boolean
}

export const apiAssetsApi = {
  list: (siteId: string, days: number) =>
    apiClient.get<ApiAssets>(`/sites/${siteId}/api-assets?days=${days}`),

  learn: (siteId: string, days: number) =>
    apiClient.post<LearnSummary>(`/sites/${siteId}/api-assets/learn`, {
      days,
    }),

  learned: (siteId: string) =>
    apiClient.get<LearnedSchema[]>(`/sites/${siteId}/api-assets/learned`),

  setOperationMode: (siteId: string, rowId: string, mode: string) =>
    apiClient.put<LearnedSchema>(
      `/sites/${siteId}/api-assets/learned/${rowId}/mode`,
      { mode },
    ),

  /** Fetches the draft with the caller's token and saves it as a file. */
  downloadDraft: async (siteId: string, filename: string) => {
    const draft = await apiClient.get<Record<string, unknown>>(
      `/sites/${siteId}/api-assets/openapi-draft`,
    )
    const blob = new Blob([JSON.stringify(draft, null, 2)], {
      type: 'application/json',
    })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    document.body.removeChild(anchor)
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  },
}

export const apiAssetsKeys = {
  all: ['api-assets'] as const,
  list: (siteId: string, days: number) =>
    [...apiAssetsKeys.all, siteId, days] as const,
  learned: (siteId: string) =>
    [...apiAssetsKeys.all, 'learned', siteId] as const,
}

export default apiAssetsApi
