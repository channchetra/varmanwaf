import type { AiChatEvent } from '@/api/types'

/**
 * Turn model shared by the assistant page and the floating widget: the
 * streamed preview of the running turn, folded from SSE events by
 * {@link reduceTurn}.
 */

export interface ToolStep {
  id: string
  name: string
  args: unknown
  result?: unknown
  isError?: boolean
  pending: boolean
}

export type TurnPart =
  | { kind: 'text'; key: string; text: string }
  | { kind: 'tool'; key: string; step: ToolStep }

export interface PendingTurn {
  /** The user message being sent; rendered optimistically until refetch. */
  content: string
  parts: TurnPart[]
  streaming: boolean
}

/** Folds one SSE event into the streamed preview of the running turn. */
export function reduceTurn(
  turn: PendingTurn,
  event: AiChatEvent,
): PendingTurn {
  switch (event.type) {
    case 'delta': {
      const parts = [...turn.parts]
      const last = parts[parts.length - 1]
      if (last?.kind === 'text') {
        parts[parts.length - 1] = { ...last, text: last.text + event.text }
      } else {
        parts.push({ kind: 'text', key: `t${parts.length}`, text: event.text })
      }
      return { ...turn, parts }
    }
    case 'tool_call':
      return {
        ...turn,
        parts: [
          ...turn.parts,
          {
            kind: 'tool',
            key: event.id,
            step: {
              id: event.id,
              name: event.name,
              args: event.arguments,
              pending: true,
            },
          },
        ],
      }
    case 'tool_result':
      return {
        ...turn,
        parts: turn.parts.map((part) =>
          part.kind === 'tool' && part.step.id === event.id
            ? {
                ...part,
                step: {
                  ...part.step,
                  result: event.result,
                  isError: event.is_error,
                  pending: false,
                },
              }
            : part,
        ),
      }
    case 'done': {
      const parts = [...turn.parts]
      // Deltas carry the whole answer in every streaming mode; this is only a
      // safety net for a provider that sent none.
      const hasText = parts.some((p) => p.kind === 'text' && p.text.trim() !== '')
      if (!hasText && event.content.trim() !== '') {
        parts.push({ kind: 'text', key: `t${parts.length}`, text: event.content })
      }
      return { ...turn, parts, streaming: false }
    }
    case 'conversation':
    case 'error':
      return turn
  }
}
