import { apiClient } from './client'

/** One package entry: a rule id or selector plus excluded targets. */
export interface ExclusionEntry {
  rule_id?: string
  tags?: string[]
  severity_min?: number
  targets: string[]
  note?: string
}

export interface ExclusionPackage {
  id: string
  key: string
  name: string
  description: string
  source_url: string
  version: string
  builtin: boolean
  /** `entries` (our target model) or `seclang` (an imported upstream file). */
  kind: 'entries' | 'seclang'
  entries: ExclusionEntry[]
  /** What an import recognised (seclang packages). */
  import_report: ImportReport | null
  updated_at: string
}

export interface ImportReport {
  directives: number
  /** `SecRule` lines the file defines (the plugin's own rules). */
  rules: number
  update_target_by_id: number
  remove_by_id: number
  /** Inline `ctl:ruleRemoveTargetById` / `ByTag` / `ruleRemoveById` controls. */
  exclusion_controls: number
  /** Rule ids the file addresses (bounded). */
  rule_ids: number[]
  valid: boolean
  version: string | null
}

export interface ExclusionBinding {
  id: string
  package_id: string
  package_key: string
  package_name: string
  package_version: string
  /** True when the package changed since the binding was installed. */
  stale: boolean
  path_prefix: string
  enabled: boolean
  created_at: string
}

export const exclusionsApi = {
  packages: () =>
    apiClient.get<ExclusionPackage[]>('/exclusion-packages'),

  importPackage: (url: string, key?: string, name?: string) =>
    apiClient.post<ExclusionPackage>('/exclusion-packages/import', {
      url,
      key: key || undefined,
      name: name || undefined,
    }),

  removePackage: (key: string) =>
    apiClient.delete<{ deleted: string }>(
      `/exclusion-packages/${encodeURIComponent(key)}`,
    ),

  bindings: (siteId: string) =>
    apiClient.get<ExclusionBinding[]>(
      `/sites/${siteId}/exclusion-bindings`,
    ),

  attach: (siteId: string, packageKey: string, pathPrefix: string) =>
    apiClient.post<ExclusionBinding>(
      `/sites/${siteId}/exclusion-bindings`,
      { package_key: packageKey, path_prefix: pathPrefix },
    ),

  updateBinding: (
    siteId: string,
    bindingId: string,
    payload: { path_prefix?: string; enabled?: boolean; reinstall?: boolean },
  ) =>
    apiClient.put<ExclusionBinding>(
      `/sites/${siteId}/exclusion-bindings/${bindingId}`,
      payload,
    ),

  removeBinding: (siteId: string, bindingId: string) =>
    apiClient.delete<{ deleted: string }>(
      `/sites/${siteId}/exclusion-bindings/${bindingId}`,
    ),
}

export const exclusionsKeys = {
  all: ['exclusions'] as const,
  packages: () => [...exclusionsKeys.all, 'packages'] as const,
  bindings: (siteId: string) =>
    [...exclusionsKeys.all, 'bindings', siteId] as const,
}

export default exclusionsApi
