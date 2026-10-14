import { describe, expect, it } from 'vitest'
import { reduceTurn, type PendingTurn } from './turn'

function turn(partial: Partial<PendingTurn> = {}): PendingTurn {
  return { content: 'hello', parts: [], streaming: true, ...partial }
}

describe('reduceTurn', () => {
  it('starts a text part on the first delta and appends later deltas', () => {
    const first = reduceTurn(turn(), { type: 'delta', text: 'Hel' })
    expect(first.parts).toEqual([{ kind: 'text', key: 't0', text: 'Hel' }])
    const second = reduceTurn(first, { type: 'delta', text: 'lo' })
    expect(second.parts).toEqual([{ kind: 'text', key: 't0', text: 'Hello' }])
  })

  it('opens a new text part after a tool step', () => {
    const withTool = reduceTurn(turn(), {
      type: 'tool_call',
      id: 'call-1',
      name: 'get_sites',
      arguments: { limit: 5 },
    })
    const withText = reduceTurn(withTool, { type: 'delta', text: 'ok' })
    expect(withText.parts.map((p) => p.kind)).toEqual(['tool', 'text'])
    expect(withText.parts[1]).toEqual({ kind: 'text', key: 't1', text: 'ok' })
  })

  it('marks the matching tool step done on its result and ignores unknown ids', () => {
    const withTool = reduceTurn(turn(), {
      type: 'tool_call',
      id: 'call-1',
      name: 'get_sites',
      arguments: null,
    })
    const resolved = reduceTurn(withTool, {
      type: 'tool_result',
      id: 'call-1',
      name: 'get_sites',
      result: { sites: 3 },
      is_error: false,
    })
    const step = resolved.parts[0]
    expect(step.kind).toBe('tool')
    if (step.kind === 'tool') {
      expect(step.step.pending).toBe(false)
      expect(step.step.result).toEqual({ sites: 3 })
      expect(step.step.isError).toBe(false)
    }

    const foreign = reduceTurn(resolved, {
      type: 'tool_result',
      id: 'call-9',
      name: 'other',
      result: null,
      is_error: true,
    })
    expect(foreign.parts).toEqual(resolved.parts)
  })

  it('keeps the streamed text when done arrives and stops streaming', () => {
    const streamed = reduceTurn(turn(), { type: 'delta', text: 'answer' })
    const done = reduceTurn(streamed, { type: 'done', content: 'answer' })
    expect(done.streaming).toBe(false)
    expect(done.parts).toHaveLength(1)
    expect(done.parts[0]).toEqual({ kind: 'text', key: 't0', text: 'answer' })
  })

  it('falls back to the done payload when no deltas carried text', () => {
    const withTool = reduceTurn(turn(), {
      type: 'tool_call',
      id: 'call-1',
      name: 'get_sites',
      arguments: null,
    })
    const done = reduceTurn(withTool, { type: 'done', content: 'final answer' })
    expect(done.parts.map((p) => p.kind)).toEqual(['tool', 'text'])
    expect(done.parts[1]).toEqual({
      kind: 'text',
      key: 't1',
      text: 'final answer',
    })
    // An empty done payload adds nothing.
    const empty = reduceTurn(withTool, { type: 'done', content: '  ' })
    expect(empty.parts).toHaveLength(1)
  })

  it('leaves the turn untouched for conversation and error events', () => {
    const base = turn()
    expect(reduceTurn(base, { type: 'conversation', id: 'c1', title: 't' })).toBe(base)
    expect(reduceTurn(base, { type: 'error', message: 'boom' })).toBe(base)
  })
})
