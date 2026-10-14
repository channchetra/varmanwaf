import { useTranslation } from 'react-i18next'
import { ChatCircleDots, Trash } from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ErrorState'
import { useNow } from '@/hooks'
import { cn } from '@/lib/utils'
import { formatRelative } from '@/lib/format'
import type { AiConversation } from '@/api/types'

/**
 * Conversation list shared by the assistant page's side card and the
 * floating widget's collapsible history area. Pure rendering — the caller
 * owns selection state and the delete confirmation dialog.
 */
export function ConversationList({
  conversations,
  selectedId,
  isStreaming,
  loading,
  error,
  retrying,
  onRetry,
  draftMode,
  onSelect,
  onDelete,
  className,
}: {
  conversations: AiConversation[]
  selectedId: string | null
  isStreaming: boolean
  loading: boolean
  error: unknown
  retrying: boolean
  onRetry: () => void
  draftMode?: boolean
  onSelect: (id: string) => void
  onDelete: (conversation: AiConversation) => void
  className?: string
}) {
  const { t } = useTranslation()
  const now = useNow(60_000)

  return (
    <div className={cn('flex flex-col', className)}>
      {loading ? (
        <SkeletonRows rows={5} columns={1} className="p-1.5" />
      ) : error && conversations.length === 0 ? (
        <div className="p-1.5">
          <ErrorState
            variant="inline"
            error={error}
            onRetry={onRetry}
            retrying={retrying}
          />
        </div>
      ) : conversations.length === 0 ? (
        <p className="px-2.5 py-8 text-center text-xs leading-relaxed text-fg-subtle">
          {t('pages.assistant.empty')}
        </p>
      ) : (
        <div className="flex flex-col gap-0.5">
          {draftMode && (
            <div className="px-2.5 py-1.5">
              <Badge tone="brand">{t('pages.assistant.newChat')}</Badge>
            </div>
          )}
          {conversations.map((conversation) => {
            const active = conversation.id === selectedId
            return (
              <div
                key={conversation.id}
                className={cn('group relative rounded-md', active && 'bg-brand-soft')}
              >
                <button
                  type="button"
                  disabled={isStreaming}
                  onClick={() => onSelect(conversation.id)}
                  className={cn(
                    'flex w-full items-start gap-2 rounded-md px-2.5 py-2 pr-8 text-left transition-colors',
                    !active && 'hover:bg-recessed',
                    isStreaming && !active && 'opacity-60',
                  )}
                >
                  <ChatCircleDots
                    weight="duotone"
                    className={cn(
                      'mt-0.5 h-4 w-4 shrink-0',
                      active ? 'text-brand' : 'text-fg-subtle',
                    )}
                  />
                  <span className="min-w-0 flex-1">
                    <span
                      className={cn(
                        'block truncate text-[13px]',
                        active ? 'font-medium text-brand' : 'text-fg',
                      )}
                    >
                      {conversation.title || t('pages.assistant.untitled')}
                    </span>
                    <span
                      className="mt-0.5 block truncate text-[11px] text-fg-subtle"
                      title={conversation.updated_at}
                    >
                      {formatRelative(conversation.updated_at, now)}
                    </span>
                  </span>
                </button>
                <button
                  type="button"
                  disabled={isStreaming}
                  aria-label={t('pages.assistant.deleteTitle')}
                  onClick={() => onDelete(conversation)}
                  className="absolute right-1.5 top-1.5 rounded p-1 text-fg-subtle opacity-0 transition-opacity hover:text-fg-danger focus-visible:opacity-100 group-hover:opacity-100 disabled:cursor-not-allowed"
                >
                  <Trash weight="duotone" className="h-3.5 w-3.5" />
                </button>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
