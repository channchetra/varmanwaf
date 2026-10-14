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
  | 'virtual_patches'
  | 'api_schema'
  | 'rate_limit'
  | 'ip_access'
  | 'bot'

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

/** `virtual_patches` layer payload (SecLang source). */
export interface VirtualPatchesLayerConfig {
  source?: string
}

/** `api_schema` layer payload (OpenAPI document as a JSON string). */
export interface ApiSchemaLayerConfig {
  openapi_spec?: string
}

/** One rate-limit rule inside a `rate_limit` layer. */
export interface RateLimitLayerRule {
  name: string
  expression?: string
  characteristics?: string[]
  period_seconds?: number
  threshold?: number
  action?: string
  mitigation_timeout_seconds?: number
  enabled?: boolean
  priority?: number
}

/** `rate_limit` layer payload (shared rate limits). */
export interface RateLimitLayerConfig {
  rules?: RateLimitLayerRule[]
}

/** One IP-access rule inside an `ip_access` layer. */
export interface IpAccessLayerRule {
  name: string
  ip_ranges: string[]
  action?: string
  note?: string
  enabled?: boolean
}

/** `ip_access` layer payload (shared allow/block rules). */
export interface IpAccessLayerConfig {
  rules?: IpAccessLayerRule[]
}

/** `bot` layer payload (bot posture overrides). */
export interface BotLayerConfig {
  enabled?: boolean
  action?: string
  known_bots_whitelist?: string[]
  js_detection?: boolean
  tls_fingerprint?: boolean
  behavioral_analysis?: boolean
  ip_verification_enabled?: boolean
  dns_verification_enabled?: boolean
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
  /** Effective payloads of the extra layers (P6 kinds). */
  layers: Record<string, unknown>
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
  layers: Record<string, unknown>
  effective: EffectiveEngine
  plan: RulePlanEntry[]
}

/** One version in a policy's history. */
export interface PolicyVersion {
  id: number
  revision: number
  config_hash: string
  source: string
  actor: string | null
  summary: Record<string, number> | null
  created_at: string
}

export interface PolicyVersionDetail extends PolicyVersion {
  snapshot: Record<string, unknown>
}

export interface LayerDiff {
  kind: string
  added: string[]
  removed: string[]
  changed: string[]
}

export interface PolicyVersionDiff {
  from: number
  to: number
  fields: string[]
  layers: LayerDiff[]
}

/** Built-in starter policy (`GET /policies/templates`). */
export interface PolicyTemplate {
  id: string
  name: string
  description: string
  layers: Record<string, unknown>
}

/** One parameter of a rule recipe. */
export interface RecipeParam {
  name: string
  label: string
  placeholder: string
  required: boolean
}

/** Built-in rule recipe (`GET /policies/recipes`). */
export interface Recipe {
  id: string
  name: string
  description: string
  params: RecipeParam[]
}

/** Result of applying a recipe: the rendered rule + updated policy. */
export interface RecipeApplied {
  rule: PolicyRule
  policy: PolicyDetail
}

/** A sample request for the rule tester. */
export interface TestRequestInput {
  method?: string
  path: string
  query?: string
  headers?: Record<string, string>
  body?: string
  client_ip?: string
  host?: string
}

/** One rule that contributed to a tester verdict. */
export interface PolicyTestHit {
  id: string
  name: string
  source: 'managed' | 'policy' | 'site' | 'patch' | string
  action: string
  tuned: boolean
}

/** The rule tester's verdict. */
export interface PolicyTestResult {
  action: 'pass' | 'monitor' | 'block' | 'challenge'
  score: number
  details: string
  matched_rules: PolicyTestHit[]
  notes: string[]
  simulated: string[]
  skipped: string[]
}

export interface PolicyTestView {
  result: PolicyTestResult
  effective: EffectiveEngine
  plan: RulePlanEntry[]
}

/** Per-node application state for one site. */
export interface ApplyStatus {  site_id: string
  published: {
    config_hash: string
    policy_revision: number
    version_id: number | null
    recorded_at: string | null
  }
  policy: PolicyRef | null
  agents: Array<{
    id: string
    hostname: string
    status: string
    applied_config_hash: string | null
    applied_policy_revision: number | null
    last_heartbeat: string | null
    last_config_sync_at: string | null
    state: 'applied' | 'pending' | 'unknown'
  }>
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

  versions: (id: string) =>
    apiClient.get<PolicyVersion[]>(`/policies/${id}/versions`),

  version: (id: string, versionId: number) =>
    apiClient.get<PolicyVersionDetail>(
      `/policies/${id}/versions/${versionId}`,
    ),

  versionDiff: (id: string, from: number, to: number) =>
    apiClient.get<PolicyVersionDiff>(`/policies/${id}/versions/diff`, {
      query: { from, to },
    }),

  rollback: (id: string, versionId: number) =>
    apiClient.post<PolicyDetail>(`/policies/${id}/rollback`, {
      version_id: versionId,
    }),

  applyStatus: (siteId: string) =>
    apiClient.get<ApplyStatus>(`/sites/${siteId}/apply-status`),

  templates: () => apiClient.get<PolicyTemplate[]>('/policies/templates'),

  recipes: () => apiClient.get<Recipe[]>('/policies/recipes'),

  fromTemplate: (data: {
    template_id: string
    name: string
    description?: string
  }) => apiClient.post<PolicyDetail>('/policies/from-template', data),

  applyRecipe: (
    id: string,
    data: { recipe_id: string; params: Record<string, string> },
  ) => apiClient.post<RecipeApplied>(`/policies/${id}/recipes`, data),

  test: (payload: {
    policy_id?: string
    site_id?: string
    layers?: Partial<Record<PolicyLayerKind, unknown>>
    request: TestRequestInput
  }) => apiClient.post<PolicyTestView>('/policies/test', payload),
}

export const policyKeys = {
  all: ['policies'] as const,
  list: () => [...policyKeys.all, 'list'] as const,
  detail: (id: string) => [...policyKeys.all, 'detail', id] as const,
  versions: (id: string) => [...policyKeys.all, 'versions', id] as const,
  versionDiff: (id: string, from: number, to: number) =>
    [...policyKeys.all, 'versions', id, 'diff', from, to] as const,
  sitePolicy: (siteId: string) => ['sites', siteId, 'policy'] as const,
  siteOverride: (siteId: string) =>
    ['sites', siteId, 'policy-override'] as const,
  siteEffective: (siteId: string) =>
    ['sites', siteId, 'effective-config'] as const,
  applyStatus: (siteId: string) =>
    ['sites', siteId, 'apply-status'] as const,
  templates: () => [...policyKeys.all, 'templates'] as const,
  recipes: () => [...policyKeys.all, 'recipes'] as const,
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
