import { describe, expect, it } from 'vitest'
import { rangeDays, rangeForPreset } from './reportRange'

const NOW = new Date('2026-10-14T12:00:00Z')

describe('report ranges', () => {
  it('rangeDays returns inclusive UTC date bounds', () => {
    expect(rangeDays(1, NOW)).toEqual({
      from: '2026-10-13',
      to: '2026-10-14',
    })
    expect(rangeDays(30, NOW)).toEqual({
      from: '2026-09-14',
      to: '2026-10-14',
    })
  })

  it('presets map to their windows and custom has none', () => {
    expect(rangeForPreset('24h', NOW)).toEqual(rangeDays(1, NOW))
    expect(rangeForPreset('7d', NOW)).toEqual(rangeDays(7, NOW))
    expect(rangeForPreset('30d', NOW)).toEqual(rangeDays(30, NOW))
    expect(rangeForPreset('90d', NOW)).toEqual(rangeDays(90, NOW))
    expect(rangeForPreset('custom', NOW)).toBeNull()
  })
})
