import { apiClient } from './client'

/**
 * CRS ruleset import and catalogue - `/api/v1/crs/*`.
 *
 * Imports fetch an archive (GitHub release tag, direct URL or an uploaded
 * base64 archive), parse it with the engine's SecLang parser and store the
 * rule catalogue with file/line provenance; unsupported rules keep their
 * parser error instead of disappearing.
 */

export interface CrsRelease {
  tag: string
  name: string
  published_at: string | null
  prerelease: boolean
}

export interface CrsRuleset {
  id: string
  name: string
  version: string
  source: string
  fingerprint: string
  rule_count: number
  supported_count: number
  unsupported_count: number
  directive_count: number
  imported_at: string
  used_by_policies: number
  deduplicated: boolean
}

export interface CrsRule {
  id: string
  rule_id: string
  kind: string
  file: string
  line: number
  phase: number | null
  severity: string
  paranoia_level: number | null
  category: string
  message: string
  supported: boolean
  error: string
  source: string
}

export interface CrsRulePage {
  items: CrsRule[]
  total: number
  page: number
  page_size: number
}

export interface CrsRulesetDetail extends CrsRuleset {
  rules: CrsRulePage
}

export interface CrsImportRequest {
  name?: string
  github_tag?: string
  url?: string
  archive_base64?: string
}

export const crsApi = {
  releases: () => apiClient.get<CrsRelease[]>('/crs/releases'),

  import: (data: CrsImportRequest) =>
    apiClient.post<CrsRuleset>('/crs/import', data),

  rulesets: () => apiClient.get<CrsRuleset[]>('/crs/rulesets'),

  ruleset: (id: string, query?: object) =>
    apiClient.get<CrsRulesetDetail>(`/crs/rulesets/${id}`, { query }),

  remove: (id: string) => apiClient.delete<void>(`/crs/rulesets/${id}`),
}

export const crsKeys = {
  all: ['crs'] as const,
  releases: () => [...crsKeys.all, 'releases'] as const,
  list: () => [...crsKeys.all, 'rulesets'] as const,
  detail: (id: string, query?: object) =>
    [...crsKeys.all, 'detail', id, query ?? {}] as const,
}

export default crsApi
