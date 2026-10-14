import { useMemo, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { CircleNotch, Sparkle } from '@phosphor-icons/react'
import { EmptyState } from '@/components/ui/EmptyState'
import type { AiMessage } from '@/api/types'
import { ToolCard, isToolError, parseJson } from './ToolCard'

/**
 * Message rendering shared by the assistant page and the floating widget.
 *
 * Rendering contract: model/tool output is ALWAYS rendered as React text
 * nodes ({text} interpolation) — never `dangerouslySetInnerHTML`, never an
 * HTML-producing markdown renderer. That contract is the XSS boundary for
 * untrusted model output; if rich rendering is ever added it must produce
 * React elements, not HTML strings.
 */

function UserBubble({ content }: { content: string }) {
  return (
    <div className="flex justify-end">
      <div className="max-w-[85%] whitespace-pre-wrap break-words rounded-2xl rounded-br-md bg-brand px-3.5 py-2.5 text-sm leading-relaxed text-white">
        {content}
      </div>
    </div>
  )
}

function AssistantText({ text }: { text: string }) {
  return (
    <div className="max-w-full whitespace-pre-wrap break-words rounded-2xl rounded-bl-md border border-line bg-base px-3.5 py-2.5 text-sm leading-relaxed text-fg">
      {text}
    </div>
  )
}

function ThinkingIndicator() {
  const { t } = useTranslation()
  return (
    <div className="flex items-center gap-2 text-xs text-fg-subtle">
      <CircleNotch weight="bold" className="h-3.5 w-3.5 animate-spin" />
      {t('pages.assistant.thinking')}
    </div>
  )
}

function renderMessages(
  messages: AiMessage[],
  t: (key: string) => string,
): ReactNode[] {
  // Results are addressed by the tool call they answer; cards render the
  // pair together, so the standalone tool rows are skipped afterwards.
  const consumedCalls = new Set<string>()
  for (const message of messages) {
    if (message.role === 'assistant' && Array.isArray(message.tool_calls)) {
      for (const call of message.tool_calls) consumedCalls.add(call.id)
    }
  }
  const resultByCall = new Map<string, AiMessage>()
  for (const message of messages) {
    if (message.role === 'tool' && message.tool_call_id) {
      resultByCall.set(message.tool_call_id, message)
    }
  }

  return messages.map((message) => {
    if (message.role === 'tool') {
      if (message.tool_call_id && consumedCalls.has(message.tool_call_id)) return null
      // An orphaned tool row (its call is gone) still deserves to be seen.
      const orphan = parseJson(message.content)
      return (
        <div key={message.id} className="flex justify-start">
          <ToolCard
            name={message.tool_name ?? t('pages.assistant.tool')}
            result={orphan}
            isError={isToolError(orphan)}
            pending={false}
          />
        </div>
      )
    }

    if (message.role === 'assistant') {
      const calls = Array.isArray(message.tool_calls) ? message.tool_calls : []
      return (
        <div key={message.id} className="flex flex-col items-start gap-2">
          {message.content.trim() !== '' && <AssistantText text={message.content} />}
          {calls.map((call) => {
            const resultRow = resultByCall.get(call.id)
            const result = resultRow ? parseJson(resultRow.content) : undefined
            return (
              <ToolCard
                key={call.id}
                name={call.function?.name ?? t('pages.assistant.tool')}
                args={parseJson(call.function?.arguments)}
                result={result}
                isError={isToolError(result)}
                pending={false}
              />
            )
          })}
        </div>
      )
    }

    return <UserBubble key={message.id} content={message.content} />
  })
}

/** The persisted thread plus the optimistic in-flight turn. */
export function ThreadBody({
  messages,
  pendingTurn,
  isStreaming,
}: {
  messages: AiMessage[]
  pendingTurn: import('./turn').PendingTurn | null
  isStreaming: boolean
}) {
  const { t } = useTranslation()
  const nodes = useMemo(() => renderMessages(messages, t), [messages, t])

  if (nodes.length === 0 && !pendingTurn) {
    return (
      <div className="flex h-full items-center justify-center">
        <EmptyState
          className="border-0 bg-transparent py-0"
          icon={<Sparkle weight="duotone" />}
          title={t('pages.assistant.welcome')}
          description={t('pages.assistant.welcomeDescription')}
        />
      </div>
    )
  }

  const trailingThinking =
    isStreaming &&
    pendingTurn !== null &&
    (pendingTurn.parts.length === 0 ||
      pendingTurn.parts[pendingTurn.parts.length - 1].kind === 'tool')

  return (
    <div className="flex flex-col gap-4">
      {nodes}
      {pendingTurn && (
        <div className="flex flex-col gap-3">
          <UserBubble content={pendingTurn.content} />
          {pendingTurn.parts.length > 0 && (
            <div className="flex max-w-[95%] flex-col items-start gap-2">
              {pendingTurn.parts.map((part) =>
                part.kind === 'text' ? (
                  <AssistantText key={part.key} text={part.text} />
                ) : (
                  <ToolCard
                    key={part.key}
                    name={part.step.name}
                    args={part.step.args}
                    result={part.step.result}
                    isError={part.step.isError}
                    pending={part.step.pending}
                  />
                ),
              )}
            </div>
          )}
          {trailingThinking && <ThinkingIndicator />}
        </div>
      )}
    </div>
  )
}
