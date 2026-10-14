import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  CaretRight,
  Checks,
  CircleNotch,
  Warning,
  Wrench,
} from '@phosphor-icons/react'
import { cn } from '@/lib/utils'

/**
 * Tool-call card: one assistant tool invocation with its collapsible
 * arguments/result payload.
 *
 * Rendering contract: tool output is ALWAYS rendered as React text nodes
 * (`{formatJson(value)}` inside `<pre>`) — never through
 * `dangerouslySetInnerHTML` or a markdown-to-HTML renderer. Model and tool
 * output is untrusted input; the text-node contract is what keeps prompt
 * injection from becoming XSS.
 */
export function ToolCard({
  name,
  args,
  result,
  isError = false,
  pending,
}: {
  name: string
  args?: unknown
  result?: unknown
  isError?: boolean
  pending: boolean
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const hasPayload = args !== undefined || result !== undefined

  return (
    <div className="w-full max-w-xl overflow-hidden rounded-lg border border-line bg-recessed/50">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
      >
        <CaretRight
          weight="bold"
          className={cn(
            'h-3 w-3 shrink-0 text-fg-subtle transition-transform duration-150',
            open && 'rotate-90',
          )}
        />
        <Wrench weight="duotone" className="h-3.5 w-3.5 shrink-0 text-fg-subtle" />
        <span className="pw-mono min-w-0 truncate text-xs text-fg">{name}</span>
        <span className="ml-auto flex shrink-0 items-center gap-1.5 text-[11px]">
          {pending ? (
            <>
              <CircleNotch weight="bold" className="h-3.5 w-3.5 animate-spin text-fg-subtle" />
              <span className="text-fg-subtle">{t('pages.assistant.toolRunning')}</span>
            </>
          ) : isError ? (
            <>
              <Warning weight="fill" className="h-3.5 w-3.5 text-fg-danger" />
              <span className="text-fg-danger">{t('pages.assistant.toolFailed')}</span>
            </>
          ) : (
            <>
              <Checks weight="bold" className="h-3.5 w-3.5 text-fg-success" />
              <span className="text-fg-subtle">{t('pages.assistant.toolDone')}</span>
            </>
          )}
        </span>
      </button>
      {open && hasPayload && (
        <div className="flex flex-col gap-2 border-t border-line px-3 py-2">
          {args !== undefined && (
            <div>
              <p className="mb-1 text-[11px] font-medium text-fg-subtle">
                {t('pages.assistant.toolArguments')}
              </p>
              <pre className="pw-mono max-h-48 overflow-auto whitespace-pre-wrap break-words rounded bg-base/60 px-2 py-1.5 text-[11px] leading-relaxed text-fg">
                {formatJson(args)}
              </pre>
            </div>
          )}
          {result !== undefined && (
            <div>
              <p className="mb-1 text-[11px] font-medium text-fg-subtle">
                {t('pages.assistant.toolResult')}
              </p>
              <pre className="pw-mono max-h-64 overflow-auto whitespace-pre-wrap break-words rounded bg-base/60 px-2 py-1.5 text-[11px] leading-relaxed text-fg">
                {formatJson(result)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function parseJson(text: string | null | undefined): unknown {
  if (!text) return undefined
  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

export function formatJson(value: unknown): string {
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, 2) ?? String(value)
}

/** Tool failures are stored as a lone `{"error": …}` object. */
export function isToolError(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    'error' in value
  )
}
