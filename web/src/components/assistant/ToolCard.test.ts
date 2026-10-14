import { describe, expect, it } from 'vitest'
import { formatJson, isToolError, parseJson } from './ToolCard'

describe('tool payload helpers', () => {
  it('parseJson parses valid JSON and passes raw text through', () => {
    expect(parseJson('{"a":1}')).toEqual({ a: 1 })
    expect(parseJson('not json')).toBe('not json')
    expect(parseJson('')).toBeUndefined()
    expect(parseJson(null)).toBeUndefined()
    expect(parseJson(undefined)).toBeUndefined()
  })

  it('formatJson pretty-prints objects and returns strings verbatim', () => {
    expect(formatJson({ a: 1 })).toBe('{\n  "a": 1\n}')
    expect(formatJson('plain')).toBe('plain')
    expect(formatJson(null)).toBe('null')
    expect(formatJson(undefined)).toBe('undefined')
  })

  it('isToolError detects only a lone-error object', () => {
    expect(isToolError({ error: 'x' })).toBe(true)
    expect(isToolError({ error: 'x', detail: 'y' })).toBe(false)
    expect(isToolError({ ok: true })).toBe(false)
    expect(isToolError(['error'])).toBe(false)
    expect(isToolError('error')).toBe(false)
    expect(isToolError(null)).toBe(false)
  })
})
