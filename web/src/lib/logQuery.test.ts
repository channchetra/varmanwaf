import { describe, expect, it } from 'vitest'
import { formatLogQuery, isRequestId, parseLogQuery } from './logQuery'

describe('parseLogQuery request ids', () => {
  it('treats a bare 16-hex id as a request id, not free text', () => {
    const parsed = parseLogQuery('557e63198ceaf5b0', 'security')
    expect(parsed.params.request_id).toBe('557e63198ceaf5b0')
    expect(parsed.params.q).toBeUndefined()
    expect(parsed.unknown).toEqual([])
  })

  it('normalises an explicit request_id and a pasted id to lower case', () => {
    expect(
      parseLogQuery('request_id:557E63198CEAF5B0', 'access').params.request_id,
    ).toBe('557e63198ceaf5b0')
    expect(
      parseLogQuery('557E63198CEAF5B0', 'control').params.request_id,
    ).toBe('557e63198ceaf5b0')
  })

  it('keeps a normal free-text term as free text', () => {
    const parsed = parseLogQuery('/api/v1/users', 'security')
    expect(parsed.params.request_id).toBeUndefined()
    expect(parsed.params.q).toBe('/api/v1/users')
  })

  it('round-trips a request id through formatLogQuery', () => {
    const parsed = parseLogQuery('557e63198ceaf5b0', 'security')
    expect(formatLogQuery(parsed.params, 'security')).toBe(
      'request_id:557e63198ceaf5b0',
    )
  })

  it('only accepts exactly 16 hex characters', () => {
    expect(isRequestId('557e63198ceaf5b0')).toBe(true)
    expect(isRequestId('557E63198CEAF5B0')).toBe(true)
    expect(isRequestId('557e63198ceaf5b')).toBe(false)
    expect(isRequestId('zzze63198ceaf5b0')).toBe(false)
  })
})
