import { afterEach, describe, expect, it, vi } from 'vitest'
import { dismissBanner, isBannerDismissed, resetBanner } from './banners'

const DAY = 24 * 60 * 60 * 1000

function installStorage() {
  const map = new Map<string, string>()
  vi.stubGlobal('window', {
    localStorage: {
      getItem: (key: string) => map.get(key) ?? null,
      setItem: (key: string, value: string) => {
        map.set(key, value)
      },
      removeItem: (key: string) => {
        map.delete(key)
      },
    },
  })
  return map
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('banner dismissal', () => {
  it('treats an unknown banner as visible', () => {
    installStorage()
    expect(isBannerDismissed('dashboard')).toBe(false)
  })

  it('remembers a dismissal and expires it after the TTL', () => {
    const map = installStorage()
    dismissBanner('dashboard')
    expect(isBannerDismissed('dashboard')).toBe(true)

    // Six days old is still dismissed; eight days old is visible again.
    map.set('varman.banner.dashboard', String(Date.now() - 6 * DAY))
    expect(isBannerDismissed('dashboard')).toBe(true)
    map.set('varman.banner.dashboard', String(Date.now() - 8 * DAY))
    expect(isBannerDismissed('dashboard')).toBe(false)
  })

  it('respects an explicit TTL', () => {
    const map = installStorage()
    map.set('varman.banner.dashboard', String(Date.now() - 2 * DAY))
    expect(isBannerDismissed('dashboard', 3)).toBe(true)
    expect(isBannerDismissed('dashboard', 1)).toBe(false)
  })

  it('ignores malformed timestamps', () => {
    const map = installStorage()
    map.set('varman.banner.dashboard', 'not-a-number')
    expect(isBannerDismissed('dashboard')).toBe(false)
  })

  it('forgets a dismissal on reset', () => {
    installStorage()
    dismissBanner('dashboard')
    resetBanner('dashboard')
    expect(isBannerDismissed('dashboard')).toBe(false)
  })

  it('degrades quietly when storage is unavailable', () => {
    vi.stubGlobal('window', {
      get localStorage(): Storage {
        throw new Error('blocked')
      },
    })
    expect(isBannerDismissed('dashboard')).toBe(false)
    expect(() => dismissBanner('dashboard')).not.toThrow()
    expect(() => resetBanner('dashboard')).not.toThrow()
  })
})
