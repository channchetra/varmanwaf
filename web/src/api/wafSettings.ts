import { apiClient } from './client'
import type {
  UpdateWafSettingsRequest,
  VirtualPatchTemplate,
  WafSettings,
} from './types'

/**
 * Site-level WAF grading settings - `/api/v1/sites/{siteId}/waf/settings`.
 *
 * One per-site record holding the advanced (strict + body inspection) mode
 * switch and the attack-category / backend-stack monitor lists. `GET` creates
 * the row with defaults when absent; `PUT` has patch semantics.
 */
export const wafSettingsApi = {
  get: (siteId: string) =>
    apiClient.get<WafSettings>(`/sites/${siteId}/waf/settings`),

  update: (siteId: string, data: UpdateWafSettingsRequest) =>
    apiClient.put<WafSettings>(`/sites/${siteId}/waf/settings`, data),

  /** Built-in virtual patches (SecLang sources) the console can insert. */
  virtualPatchTemplates: () =>
    apiClient.get<VirtualPatchTemplate[]>('/virtual-patch-templates'),
}

export const wafSettingsKeys = {
  all: (siteId: string) => ['sites', siteId, 'waf-settings'] as const,
  settings: (siteId: string) =>
    ['sites', siteId, 'waf-settings', 'settings'] as const,
  templates: () => ['virtual-patch-templates'] as const,
}

export default wafSettingsApi
