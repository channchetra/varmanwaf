import { describe, expect, it } from 'vitest'
import { isChunkLoadError } from './chunkReload'

describe('isChunkLoadError', () => {
  it('recognises the Vite dynamic-import failure', () => {
    expect(
      isChunkLoadError(
        new TypeError(
          'Failed to fetch dynamically imported module: https://example.test/assets/RewritePage-old.js',
        ),
      ),
    ).toBe(true)
  })

  it('recognises a webpack-style chunk error', () => {
    const error = new Error('Loading chunk 42 failed')
    error.name = 'ChunkLoadError'
    expect(isChunkLoadError(error)).toBe(true)
  })

  it('leaves ordinary application errors alone', () => {
    expect(isChunkLoadError(new Error('Invalid input'))).toBe(false)
    expect(isChunkLoadError('network down')).toBe(false)
  })
})
