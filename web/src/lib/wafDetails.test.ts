import { describe, expect, it } from 'vitest'
import { decidingRule } from './wafDetails'

describe('decidingRule', () => {
  it('picks the action=block rule, not the first signature', () => {
    expect(
      decidingRule(
        "likely-clean: SSRF-006 [ssrf sev=3] in header 'user-agent'; " +
          'VARMAN-1020 [Block sensitive dotfile probes] action=block sev=5',
      ),
    ).toEqual({
      id: 'VARMAN-1020',
      name: 'Block sensitive dotfile probes',
      action: 'block',
    })
  })

  it('handles challenge actions and namespaced rule ids', () => {
    expect(
      decidingRule(
        'attack: policy:abc:0 [JS challenge] action=js_challenge sev=3',
      ),
    ).toEqual({
      id: 'policy:abc:0',
      name: 'JS challenge',
      action: 'js_challenge',
    })
  })

  it('returns null when no rule forced an action', () => {
    expect(
      decidingRule(
        "likely-clean: SSRF-006 [ssrf sev=3] in header 'user-agent'",
      ),
    ).toBeNull()
    expect(decidingRule(null)).toBeNull()
    expect(decidingRule('')).toBeNull()
  })
})
