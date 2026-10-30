import { describe, expect, it } from 'vitest'
import { protectionModeLabelKey, protectionModeOf } from './protectionMode'

describe('protectionModeLabelKey', () => {
  it('uses the progressive status labels in the list', () => {
    expect(protectionModeLabelKey('block')).toBe('status.blocking')
    expect(protectionModeLabelKey('monitor')).toBe('status.monitoring')
    expect(protectionModeLabelKey('paused')).toBe('status.paused')
    expect(protectionModeLabelKey('off')).toBe('status.off')
    expect(protectionModeLabelKey('pending')).toBe('status.pending')
  })
})

describe('protectionModeOf', () => {
  it('prefers the server field and falls back to the lifecycle row', () => {
    expect(
      protectionModeOf({ protection_mode: 'monitor', status: 'active' }),
    ).toBe('monitor')
    expect(
      protectionModeOf({ protection_mode: '', status: 'paused' }),
    ).toBe('paused')
    expect(
      protectionModeOf({ protection_mode: '', status: 'active' }),
    ).toBe('block')
  })
})
