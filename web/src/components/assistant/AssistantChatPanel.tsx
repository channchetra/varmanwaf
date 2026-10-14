import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Gear,
  PaperPlaneTilt,
  Stop,
  Warning,
  X,
} from '@phosphor-icons/react'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ErrorState'
import { ThreadBody } from './messages'
import type { AssistantChat } from '@/hooks/useAssistantChat'
import { cn } from '@/lib/utils'

/**
 * The assistant chat workspace: header, thread, error bar, composer and the
 * delete confirmation. Shared by the /assistant page (inside its two-column
 * layout, with a mobile conversation `Select` as `headerExtra`) and the
 * floating widget (compact, `headerExtra` unused).
 *
 * Layout knob: the page stretches the card to fill its column; the widget
 * lets it grow inside the sliding panel.
 */
export function AssistantChatPanel({
  chat,
  headerExtra,
  disabledTitle,
  disabledDescription,
  disabledAction,
  className,
}: {
  chat: AssistantChat
  /** Rendered next to the header title (page: mobile conversation picker). */
  headerExtra?: ReactNode
  /** Content of the "assistant not enabled" state (callers differentiate). */
  disabledTitle?: string
  disabledDescription?: string
  disabledAction?: ReactNode
  className?: string
}) {
  const { t } = useTranslation()
  const {
    settingsQuery,
    settings,
    enabled,
    detailQuery,
    storedMessages,
    selectedId,
    selectedTitle,
    pendingTurn,
    isStreaming,
    turnError,
    setTurnError,
    threadRef,
    input,
    setInput,
    handleSend,
    stopStreaming,
    pendingDelete,
    setPendingDelete,
    removeConversation,
  } = chat

  return (
    <Card className={cn('flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden', className)}>
      <div className="flex shrink-0 items-center gap-3 border-b border-line px-4 py-2.5">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-fg-strong">{selectedTitle}</p>
          {settings && (
            <p className="truncate text-[11px] text-fg-subtle">
              {settings.model} ·{' '}
              {settings.allow_write_tools
                ? t('pages.assistant.writeToolsOn')
                : t('pages.assistant.writeToolsOff')}
            </p>
          )}
        </div>
        {headerExtra}
      </div>

      {settingsQuery.isError && !settings ? (
        <div className="p-4">
          <ErrorState
            variant="inline"
            error={settingsQuery.error}
            onRetry={() => settingsQuery.refetch()}
            retrying={settingsQuery.isFetching}
          />
        </div>
      ) : settingsQuery.isPending ? (
        <div className="p-4">
          <SkeletonRows rows={6} columns={1} />
        </div>
      ) : !enabled ? (
        <div className="flex min-h-0 flex-1 items-center justify-center p-6">
          <EmptyState
            icon={<Gear weight="duotone" />}
            title={disabledTitle ?? t('pages.assistant.notConfigured')}
            description={
              disabledDescription ?? t('pages.assistant.notConfiguredDescription')
            }
            action={disabledAction}
          />
        </div>
      ) : (
        <>
          <div ref={threadRef} className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
            {detailQuery.isPending && selectedId !== null && !pendingTurn ? (
              <SkeletonRows rows={5} columns={1} />
            ) : detailQuery.isError && selectedId !== null ? (
              <ErrorState
                variant="inline"
                error={detailQuery.error}
                onRetry={() => detailQuery.refetch()}
                retrying={detailQuery.isFetching}
              />
            ) : (
              <ThreadBody
                messages={storedMessages}
                pendingTurn={pendingTurn}
                isStreaming={isStreaming}
              />
            )}
          </div>

          {turnError && (
            <div
              role="alert"
              className="mx-3 flex items-start gap-2 rounded-md border border-danger/30 bg-danger/8 px-3 py-2 text-[13px] text-fg"
            >
              <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-danger" />
              <span className="min-w-0 flex-1 break-words">{turnError}</span>
              <button
                type="button"
                aria-label={t('common.close')}
                className="shrink-0 text-fg-subtle transition-colors hover:text-fg"
                onClick={() => setTurnError(null)}
              >
                <X weight="bold" className="h-3.5 w-3.5" />
              </button>
            </div>
          )}

          <div className="shrink-0 border-t border-line p-3">
            <div className="flex items-end gap-2 rounded-lg border border-line bg-elevated px-3 py-2 transition-colors focus-within:border-focus">
              <textarea
                value={input}
                rows={2}
                maxLength={8000}
                disabled={isStreaming}
                aria-label={t('pages.assistant.placeholder')}
                placeholder={t('pages.assistant.placeholder')}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
                    e.preventDefault()
                    void handleSend()
                  }
                }}
                className="max-h-40 min-h-10 w-full resize-none bg-transparent text-sm leading-relaxed text-fg placeholder:text-fg-subtle/60 focus:outline-none disabled:cursor-not-allowed disabled:opacity-70"
              />
              {isStreaming ? (
                <Button
                  variant="secondary"
                  size="sm"
                  className="mb-0.5 shrink-0"
                  icon={<Stop weight="fill" className="h-3.5 w-3.5" />}
                  onClick={stopStreaming}
                >
                  {t('pages.assistant.stop')}
                </Button>
              ) : (
                <Button
                  variant="primary"
                  size="sm"
                  className="mb-0.5 shrink-0"
                  disabled={!input.trim()}
                  icon={<PaperPlaneTilt weight="fill" className="h-4 w-4" />}
                  onClick={() => void handleSend()}
                >
                  {t('pages.assistant.send')}
                </Button>
              )}
            </div>
            <p className="mt-1.5 px-1 text-[11px] text-fg-subtle">
              {t('pages.assistant.composerHint')}
            </p>
          </div>
        </>
      )}

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && removeConversation.mutate(pendingDelete.id)}
        title={t('pages.assistant.deleteTitle')}
        description={t('pages.assistant.deleteDescription')}
        confirmLabel={t('common.delete')}
        loading={removeConversation.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="truncate text-[13px] font-medium text-fg-strong">
              {pendingDelete.title || t('pages.assistant.untitled')}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </Card>
  )
}
