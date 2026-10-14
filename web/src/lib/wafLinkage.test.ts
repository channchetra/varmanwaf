import { describe, expect, it } from 'vitest'
import { applyCategoryLinkage } from './wafLinkage'
import type { ManagedRuleInfo } from '@/api/policies'
import type { WafSettings } from '@/api/types'

function rule(id: string, category: string | null): ManagedRuleInfo {
  return {
    id,
    name: id,
    action: 'block',
    severity: 3,
    tags: [],
    stacks: [],
    category,
    strict_only: false,
  }
}

const CATALOGUE: ManagedRuleInfo[] = [
  rule('VARMAN-1002', 'sqli'),
  rule('VARMAN-1003', 'xss'),
  rule('VARMAN-1050', 'rce'),
  rule('VARMAN-1061', 'rce'),
  rule('VARMAN-1001', null),
  rule('VARMAN-1030', null),
]

function settings(
  monitor_categories: string[],
  monitor_managed_rules: string[],
): Pick<WafSettings, 'monitor_categories' | 'monitor_managed_rules'> {
  return { monitor_categories, monitor_managed_rules }
}

describe('applyCategoryLinkage', () => {
  it('turning a category to log-only adds the category and its family ids', () => {
    const payload = applyCategoryLinkage('sqli', true, settings([], []), CATALOGUE)
    expect(payload.monitor_categories).toEqual(['sqli'])
    expect(payload.monitor_managed_rules).toEqual(['VARMAN-1002'])
  })

  it('turning a category back removes the category and its family ids', () => {
    const payload = applyCategoryLinkage(
      'rce',
      false,
      settings(['rce', 'lfi'], ['VARMAN-1050', 'VARMAN-1061', 'VARMAN-1001']),
      CATALOGUE,
    )
    expect(payload.monitor_categories).toEqual(['lfi'])
    expect(payload.monitor_managed_rules).toEqual(['VARMAN-1001'])
  })

  it('is idempotent: re-adding a linked category does not duplicate ids', () => {
    const once = applyCategoryLinkage('xss', true, settings([], []), CATALOGUE)
    const twice = applyCategoryLinkage('xss', true, once as never, CATALOGUE)
    expect(twice.monitor_categories).toEqual(['xss'])
    expect(twice.monitor_managed_rules).toEqual(['VARMAN-1003'])
  })

  it('keeps unrelated per-rule overrides untouched', () => {
    const payload = applyCategoryLinkage(
      'sqli',
      true,
      settings(['lfi'], ['VARMAN-1030']),
      CATALOGUE,
    )
    expect(payload.monitor_categories).toEqual(['lfi', 'sqli'])
    expect(payload.monitor_managed_rules).toEqual(['VARMAN-1030', 'VARMAN-1002'])
  })

  it('switching a category back resets per-rule overrides of its family', () => {
    // The user downgraded VARMAN-1002 alone, then also turned the sqli
    // category to log-only; switching the category back must remove the
    // family id even though it was originally an independent override.
    const payload = applyCategoryLinkage(
      'sqli',
      false,
      settings(['sqli'], ['VARMAN-1002', 'VARMAN-1001']),
      CATALOGUE,
    )
    expect(payload.monitor_categories).toEqual([])
    expect(payload.monitor_managed_rules).toEqual(['VARMAN-1001'])
  })

  it('batch covering all ids is just the linkage applied family by family', () => {
    // Every family category on → every family rule monitored; policy rules
    // only enter through the per-rule switch.
    let current = settings([], [])
    for (const category of ['sqli', 'xss', 'rce']) {
      current = applyCategoryLinkage(
        category,
        true,
        current as never,
        CATALOGUE,
      ) as never
    }
    expect(current.monitor_categories).toEqual(['sqli', 'xss', 'rce'])
    expect(current.monitor_managed_rules).toEqual([
      'VARMAN-1002',
      'VARMAN-1003',
      'VARMAN-1050',
      'VARMAN-1061',
    ])
  })
})
