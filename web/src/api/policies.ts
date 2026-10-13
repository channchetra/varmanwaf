import { apiClient } from './client'

/**
 * WAF policies - `/api/v1/policies` and the site assignment endpoints.
 *
 * A policy is a named, revisioned document shared by sites. It carries up to
 * one layer per kind: `engine` (the posture knobs of `waf_settings`), `crs`
 * (managed-rule monitor list) and `custom_rules` (a reusable rule list).
 * A site points at one policy and may add a sparse per-site overlay on top;
 * without an assignment the site keeps its own settings, so nothing changes
 * by accident.
 */

export type PolicyLayerKind =
  | 'engine'
  | 'crs'
  | 'custom_rules'
  | 'rule_overrides'

export interface PolicyRef {
  id: string
  name: string
  revision: number
  enabled: boolean
}

export interface PolicySummary {
  id: string
  name: string
  description: string
  enabled: boolean
  revision: number
  layer_kinds: string[]
  site_count: number
  created_at: string
  updated_at: string
}

export interface PolicyLayer {
  kind: string
  config: Record<string, unknown>
  updated_at: string
}

export interface PolicySiteRef {
  id: string
  domain: string
}

export interface PolicyDetail extends PolicySummary {
  layers: PolicyLayer[]
  sites: PolicySiteRef[]
}

/** One custom rule authored inside a policy's `custom_rules` layer. */
export interface PolicyRule {
  name: string
  description?: string
  expression: string
  action: string
  severity?: number
  tags?: string[]
  enabled?: boolean
  mode?: string
  priority?: number
}

/** `engine` layer payload; every key optional, absent = keep inheriting. */
export interface EngineLayerConfig {
  waf_enabled?: boolean
  mode?: string
  paranoia_level?: number
  advanced_mode?: boolean
  engine_mode?: string
  monitor_categories?: string[]
  monitor_stacks?: string[]
}

/** `crs` layer payload. */
export interface CrsLayerConfig {
  monitor_managed_rules?: string[]
}

/** `custom_rules` layer payload. */
export interface CustomRulesLayerConfig {
  rules?: PolicyRule[]
}

/**
 * One managed-rule tuning entry inside a `rule_overrides` layer. The entry
 * addresses rules by exactly one of `rule_id`, `tags` or `severity_min`.
 * `score` is required for `score_override` and rejected otherwise.
 */
export interface RuleOverrideEntry {
  rule_id?: string
  tags?: string[]
  severity_min?: number
  action: 'default' | 'disable' | 'monitor' | 'score_override'
  score?: number
  /** Request targets excluded from the addressed rules' evaluation. */
  exclude_targets?: string[]
}

/** Request targets a rule override may exclude. */
export const EXCLUSION_TARGETS = [
  'path',
  'query',
  'body',
  'header',
  'cookie',
  'user_agent',
  'host',
  'method',
] as const

/** `rule_overrides` layer payload. */
export interface RuleOverridesLayerConfig {
  overrides?: RuleOverrideEntry[]
}

/** `GET /managed-rules` - the built-in managed-rule catalogue. */
export interface ManagedRuleInfo {
  id: string
  name: string
  action: string
  severity: number
  tags: string[]
  stacks: string[]
}

/** The engine knobs the next bundle will actually carry for a site. */
export interface EffectiveEngine {
  waf_enabled: boolean
  mode: string | null
  paranoia_level: number
  advanced_mode: boolean
  engine_mode: string
  monitor_categories: string[]
  monitor_stacks: string[]
  monitor_managed_rules: string[]
  disabled_rules: string[]
  rule_scores: Record<string, number>
  rule_target_exclusions: Record<string, string[]>
}

/** One row of the compiled managed-rule plan. */
export interface RulePlanEntry {
  id: string
  name: string
  severity: number
  action: string
  tags: string[]
  stacks: string[]
  strict_only: boolean
  effective: 'enforce' | 'monitor' | 'disabled'
  score: number
  exclusions: string[]
}

export interface EffectiveConfig {
  site_id: string
  policy: PolicyRef | null
  source: 'policy' | 'site'
  overridden: boolean
  override_kinds: string[]
  engine: EngineLayerConfig
  crs: CrsLayerConfig
  rules: PolicyRule[]
  overrides: RuleOverrideEntry[]
  effective: EffectiveEngine
  /** Compiled managed-rule plan for the effective engine. */
  plan: RulePlanEntry[]
}

/** Draft preview request (`POST /policies/preview`). */
export interface PreviewPolicyRequest {
  policy_id?: string
  site_id?: string
  layers?: Partial<Record<PolicyLayerKind, unknown>>
}

export interface PolicyPreview {
  engine: EngineLayerConfig
  crs: CrsLayerConfig
  rules: PolicyRule[]
  overrides: RuleOverrideEntry[]
  effective: EffectiveEngine
  plan: RulePlanEntry[]
}

export interface SitePolicyView {
  site_id: string
  policy: PolicyRef | null
  overridden: boolean
  override_kinds: string[]
}

export interface SitePolicyOverrideView {
  site_id: string
  config: Record<string, unknown>
}

export interface CreatePolicyRequest {
  name: string
  description?: string
  enabled?: boolean
  layers?: Partial<Record<PolicyLayerKind, unknown>>
}

export interface UpdatePolicyRequest {
  name?: string
  description?: string
  enabled?: boolean
  /** Optimistic concurrency: a stale value is rejected with 409. */
  expected_revision?: number
}

export const policiesApi = {
  list: () => apiClient.get<PolicySummary[]>('/policies'),  get: (id: string) => apiClient.get<PolicyDetail>(`/policies/${id}`),

  create: (data: CreatePolicyRequest) =>
    apiClient.post<PolicyDetail>('/policies', data),

  update: (id: string, data: UpdatePolicyRequest) =>
    apiClient.put<PolicyDetail>(`/policies/${id}`, data),

  remove: (id: string) => apiClient.delete<void>(`/policies/${id}`),

  putLayer: (id: string, kind: PolicyLayerKind, config: unknown) =>
    apiClient.put<PolicyLayer>(`/policies/${id}/layers/${kind}`, { config }),

  deleteLayer: (id: string, kind: PolicyLayerKind) =>
    apiClient.delete<void>(`/policies/${id}/layers/${kind}`),

  getSitePolicy: (siteId: string) =>
    apiClient.get<SitePolicyView>(`/sites/${siteId}/policy`),

  setSitePolicy: (siteId: string, policyId: string | null) =>
    apiClient.put<SitePolicyView>(`/sites/${siteId}/policy`, {
      policy_id: policyId,
    }),

  getSiteOverride: (siteId: string) =>
    apiClient.get<SitePolicyOverrideView>(`/sites/${siteId}/policy-override`),

  putSiteOverride: (siteId: string, config: Record<string, unknown>) =>
    apiClient.put<SitePolicyOverrideView>(
      `/sites/${siteId}/policy-override`,
      { config },
    ),

  deleteSiteOverride: (siteId: string) =>
    apiClient.delete<void>(`/sites/${siteId}/policy-override`),

  effectiveConfig: (siteId: string) =>
    apiClient.get<EffectiveConfig>(`/sites/${siteId}/effective-config`),

  preview: (payload: PreviewPolicyRequest) =>
    apiClient.post<PolicyPreview>('/policies/preview', payload),
}

export const policyKeys = {
  all: ['policies'] as const,
  list: () => [...policyKeys.all, 'list'] as const,
  detail: (id: string) => [...policyKeys.all, 'detail', id] as const,
  sitePolicy: (siteId: string) => ['sites', siteId, 'policy'] as const,
  siteOverride: (siteId: string) =>
    ['sites', siteId, 'policy-override'] as const,
  siteEffective: (siteId: string) =>
    ['sites', siteId, 'effective-config'] as const,
}

/** Built-in managed-rule catalogue (`GET /managed-rules`). */
export const managedRulesApi = {
  list: () => apiClient.get<ManagedRuleInfo[]>('/managed-rules'),
}

export const managedRuleKeys = {
  all: ['managed-rules'] as const,
}

/**
 * Built-in managed rules the CRS layer may downgrade to monitor-only.
 * Mirrors `varman_waf::MANAGED_RULE_IDS`; the server rejects ids outside
 * this set, so the picker and the engine stay in lockstep.
 */
export const MANAGED_RULE_IDS: string[] = [
  'VARMAN-1001',
  'VARMAN-1002',
  'VARMAN-1003',
  'VARMAN-1004',
  'VARMAN-1010',
  'VARMAN-1011',
  'VARMAN-1020',
  'VARMAN-1021',
  'VARMAN-1030',
  'VARMAN-1031',
  'VARMAN-1040',
  'VARMAN-1050',
  'VARMAN-1051',
  'VARMAN-1061',
]

export default policiesApi
