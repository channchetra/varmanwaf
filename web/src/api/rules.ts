import { apiClient } from './client'
import type {
  CreateGroupRequest,
  CreateRuleRequest,
  DerivedWafConfig,
  Page,
  Rule,
  RuleGroup,
  RuleListQuery,
  RuleMode,
  UpdateGroupRequest,
  UpdateRuleRequest,
} from './types'

/**
 * WAF rule groups and rules — `/api/v1/sites/{site_id}/rules`.
 *
 * The control plane does **not** persist a site-level WAF record: the posture
 * pushed to agents is derived from the enabled rule set. `deriveWafConfig`
 * mirrors `grpc::config::waf_config_to_proto` so the console shows exactly what
 * the agents will enforce.
 */
export const rulesApi = {
  /* ── Groups ──────────────────────────────────────────────────────── */
  listGroups: (siteId: string, query: RuleListQuery = {}) =>
    apiClient.get<Page<RuleGroup>>(`/sites/${siteId}/rule-groups`, {
      query: { page_size: 200, ...query },
    }),

  createGroup: (siteId: string, data: CreateGroupRequest) =>
    apiClient.post<RuleGroup>(`/sites/${siteId}/rule-groups`, data),

  updateGroup: (siteId: string, groupId: string, data: UpdateGroupRequest) =>
    apiClient.put<RuleGroup>(`/sites/${siteId}/rule-groups/${groupId}`, data),

  deleteGroup: (siteId: string, groupId: string) =>
    apiClient.delete<void>(`/sites/${siteId}/rule-groups/${groupId}`),

  /* ── Rules ───────────────────────────────────────────────────────── */
  list: (siteId: string, query: RuleListQuery = {}) =>
    apiClient.get<Page<Rule>>(`/sites/${siteId}/rules`, {
      query: { page_size: 200, ...query },
    }),

  get: (siteId: string, ruleId: string) =>
    apiClient.get<Rule>(`/sites/${siteId}/rules/${ruleId}`),

  create: (siteId: string, data: CreateRuleRequest) =>
    apiClient.post<Rule>(`/sites/${siteId}/rules`, data),

  update: (siteId: string, ruleId: string, data: UpdateRuleRequest) =>
    apiClient.put<Rule>(`/sites/${siteId}/rules/${ruleId}`, data),

  delete: (siteId: string, ruleId: string) =>
    apiClient.delete<void>(`/sites/${siteId}/rules/${ruleId}`),

  /** Shorthand for the enable/disable switch on a rule row. */
  toggleEnabled: (siteId: string, ruleId: string, enabled: boolean) =>
    apiClient.put<Rule>(`/sites/${siteId}/rules/${ruleId}`, { enabled }),

  /** Shorthand for changing the enforcement mode of a single rule. */
  setMode: (siteId: string, ruleId: string, mode: RuleMode) =>
    apiClient.put<Rule>(`/sites/${siteId}/rules/${ruleId}`, { mode }),

  /** Re-adds missing built-in rules; edited ones are left untouched. */
  restoreDefaults: (siteId: string) =>
    apiClient.post<SeedWafDefaultsResult>(`/sites/${siteId}/waf/defaults`),
}

/** `POST /sites/{site_id}/waf/defaults` ack. */
export interface SeedWafDefaultsResult {
  inserted: number
  total: number
}

/* ────────────────────────────────────────────────────────────────
   Derived site WAF posture
   ──────────────────────────────────────────────────────────────── */

/**
 * Computes the site-wide WAF switches exactly the way the control plane does
 * when it builds the agent `RuleBundle`.
 */
export function deriveWafConfig(rules: Rule[], groups: RuleGroup[]): DerivedWafConfig {
  const active = rules.filter((r) => r.enabled)

  // Blocking wins over monitoring, monitoring wins over off.
  let mode: RuleMode = 'off'
  if (active.some((r) => r.mode === 'block')) mode = 'block'
  else if (active.some((r) => r.mode === 'monitor')) mode = 'monitor'

  const anyGroupEnabled = groups.length === 0 || groups.some((g) => g.enabled)

  const maxSeverity = active.reduce((max, r) => Math.max(max, r.severity), 0)

  return {
    enabled: active.length > 0 && anyGroupEnabled,
    mode,
    paranoia_level: active.length > 0 ? Math.min(Math.max(maxSeverity, 1), 4) : 1,
    active_rules: active.length,
    total_rules: rules.length,
  }
}

export const ruleKeys = {
  all: (siteId: string) => ['sites', siteId, 'rules'] as const,
  list: (siteId: string, query?: RuleListQuery) =>
    ['sites', siteId, 'rules', 'list', query ?? {}] as const,
  detail: (siteId: string, ruleId: string) =>
    ['sites', siteId, 'rules', 'detail', ruleId] as const,
  groups: (siteId: string) => ['sites', siteId, 'rule-groups'] as const,
}

export default rulesApi
