import { describe, expect, it } from 'vitest'
import { scopeLabel, summaryRows, summaryTotals } from './configHistory'

describe('config history helpers', () => {
  it('summaryTotals counts tables and sums rows, tolerating null', () => {
    expect(summaryTotals({ sites: 3, waf_policies: 12 })).toEqual({
      tables: 2,
      rows: 15,
    })
    expect(summaryTotals(null)).toEqual({ tables: 0, rows: 0 })
    expect(summaryTotals(undefined)).toEqual({ tables: 0, rows: 0 })
    expect(summaryTotals({})).toEqual({ tables: 0, rows: 0 })
  })

  it('summaryRows sorts by size and optionally trims', () => {
    const summary = { small: 1, big: 9, medium: 5 }
    expect(summaryRows(summary)).toEqual([
      { name: 'big', count: 9 },
      { name: 'medium', count: 5 },
      { name: 'small', count: 1 },
    ])
    expect(summaryRows(summary, 2)).toEqual([
      { name: 'big', count: 9 },
      { name: 'medium', count: 5 },
    ])
    expect(summaryRows({ b: 2, a: 2 })).toEqual([
      { name: 'a', count: 2 },
      { name: 'b', count: 2 },
    ])
    expect(summaryRows(null)).toEqual([])
  })

  it('scopeLabel prefers the site name, then the domain, then the id', () => {
    const site = { site_id: 'abc', site_domain: 'e2e.varman.local' }
    expect(scopeLabel(site, 'E2E Site')).toBe('E2E Site')
    expect(scopeLabel(site)).toBe('e2e.varman.local')
    expect(scopeLabel({ site_id: 'abc', site_domain: null })).toBe('abc')
    expect(scopeLabel({ site_id: null, site_domain: null })).toBe('global')
  })
})
