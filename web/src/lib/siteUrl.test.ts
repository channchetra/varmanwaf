import { describe, expect, it } from 'vitest'
import { liveSiteUrl } from './siteUrl'

describe('liveSiteUrl', () => {
  it('defaults public domains to HTTPS', () => {
    expect(liveSiteUrl('varman.unitywork.space')).toBe('https://varman.unitywork.space')
  })

  it('uses HTTP for development hosts', () => {
    expect(liveSiteUrl('e2e.varman.local')).toBe('http://e2e.varman.local')
    expect(liveSiteUrl('localhost')).toBe('http://localhost')
  })

  it('honours the certificate/TLS signal from the site detail', () => {
    expect(liveSiteUrl('example.test', true)).toBe('https://example.test')
    expect(liveSiteUrl('varman.unitywork.space', false)).toBe(
      'http://varman.unitywork.space',
    )
  })
})
