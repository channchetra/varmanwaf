import type { ManagedRuleInfo } from '@/api/policies'
import type { UpdateWafSettingsRequest, WafSettings } from '@/api/types'

/**
 * Turning a category to log-only must also downgrade the managed rules of the
 * same family: the engine's per-category switch covers the signature surface,
 * but literal-expression family rules only react to the per-rule list. This
 * returns one PUT payload carrying both arrays; toggling the category back
 * removes the family ids again, resetting any per-rule override.
 */
export function applyCategoryLinkage(
  category: string,
  logOnly: boolean,
  settings: Pick<WafSettings, 'monitor_categories' | 'monitor_managed_rules'>,
  managedRules: ManagedRuleInfo[],
): UpdateWafSettingsRequest {
  const familyIds = managedRules
    .filter((r) => r.category === category)
    .map((r) => r.id)
  const withoutCategory = (settings.monitor_categories ?? []).filter(
    (c) => c !== category,
  )
  const withoutFamily = (settings.monitor_managed_rules ?? []).filter(
    (id) => !familyIds.includes(id),
  )
  return {
    monitor_categories: logOnly ? [...withoutCategory, category] : withoutCategory,
    monitor_managed_rules: logOnly
      ? [...new Set([...withoutFamily, ...familyIds])]
      : withoutFamily,
  }
}

/** The categories whose managed rules follow the category switch. */
export function linkageCategories(managedRules: ManagedRuleInfo[]): Set<string> {
  return new Set(
    managedRules.filter((r) => r.category !== null).map((r) => r.category as string),
  )
}
