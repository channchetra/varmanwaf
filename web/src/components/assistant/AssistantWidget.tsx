import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  ClockCounterClockwise,
  Gear,
  Plus,
  X,
} from '@phosphor-icons/react'
import { Button } from '@/components/ui/Button'
import { useAuthStore } from '@/stores/authStore'
import { useAssistantWidgetStore } from '@/stores/assistantWidgetStore'
import { useAssistantChat } from '@/hooks/useAssistantChat'
import { AssistantChatPanel } from './AssistantChatPanel'
import { AssistantBall } from './AssistantBall'
import { ConversationList } from './ConversationList'
import { cn } from '@/lib/utils'

/**
 * The floating AI assistant: a bottom-right ball and a right-hand sliding
 * panel, both entries driven by one shared store.
 *
 * Non-blocking by design — the panel renders NO overlay, so the console
 * stays fully interactive while chatting. The panel is mounted persistently
 * and hidden with a transform (never unmounted) so a running stream and the
 * in-flight turn survive open/close cycles; Escape closes it, clicking
 * outside intentionally does not (the outside click *is* console work).
 */
export function AssistantWidget() {
  const { t } = useTranslation()
  const location = useLocation()
  const navigate = useNavigate()
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'
  const open = useAssistantWidgetStore((s) => s.open)
  const toggle = useAssistantWidgetStore((s) => s.toggle)
  const close = useAssistantWidgetStore((s) => s.close)
  const [historyOpen, setHistoryOpen] = useState(false)
  const chat = useAssistantChat()

  const { enabled, isStreaming } = chat

  // Escape closes the panel (only while open).
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, close])

  // The /assistant page already shows the full console; hide the ball there
  // so the page is not decorated with a duplicate entry point.
  const onAssistantPage = location.pathname.startsWith('/assistant')

  return (
    <>
      {!onAssistantPage && (
        <button
          type="button"
          onClick={toggle}
          aria-label={t('pages.assistant.open')}
          title={t('pages.assistant.open')}
          className={cn(
            'fixed bottom-5 right-5 z-40 flex h-12 w-12 items-center justify-center rounded-full',
            'bg-brand text-white shadow-lg transition-transform duration-150 hover:scale-105',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus',
          )}
        >
          <AssistantBall className="h-8 w-8" />
        </button>
      )}

      <aside
        role="complementary"
        aria-label={t('pages.assistant.title')}
        aria-hidden={!open}
        className={cn(
          'fixed bottom-0 right-0 top-14 z-40 flex w-full flex-col border-l border-line bg-elevated shadow-xl',
          'transition-transform duration-200 ease-out sm:w-[420px]',
          open
            ? 'translate-x-0 animate-slide-in-right'
            : 'pointer-events-none translate-x-full',
        )}
      >
        {/* Panel header */}
        <div className="flex shrink-0 items-center gap-1.5 border-b border-line px-3 py-2">
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-brand text-white">
            <AssistantBall className="h-5 w-5" />
          </span>
          <span className="min-w-0 flex-1 truncate text-[13px] font-semibold text-fg-strong">
            {t('pages.assistant.title')}
          </span>
          <Button
            size="icon"
            variant="ghost"
            aria-label={
              historyOpen ? t('pages.assistant.hideHistory') : t('pages.assistant.showHistory')
            }
            title={t('pages.assistant.history')}
            aria-expanded={historyOpen}
            onClick={() => setHistoryOpen((o) => !o)}
            icon={
              <ClockCounterClockwise
                weight="duotone"
                className={cn('h-4.5 w-4.5', historyOpen && 'text-brand')}
              />
            }
          />
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('pages.assistant.newChat')}
            title={t('pages.assistant.newChat')}
            disabled={!enabled || isStreaming}
            onClick={chat.startNewChat}
            icon={<Plus weight="bold" className="h-4.5 w-4.5" />}
          />
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('pages.assistant.close')}
            title={t('pages.assistant.close')}
            onClick={close}
            icon={<X weight="bold" className="h-4.5 w-4.5" />}
          />
        </div>

        {/* Collapsible history area — hidden until the history button is clicked. */}
        {historyOpen && (
          <div className="max-h-48 shrink-0 animate-slide-up overflow-y-auto border-b border-line p-1.5">
            <ConversationList
              conversations={chat.conversations}
              selectedId={chat.selectedId}
              isStreaming={isStreaming}
              loading={chat.conversationsQuery.isPending}
              error={
                chat.conversationsQuery.isError ? chat.conversationsQuery.error : null
              }
              retrying={chat.conversationsQuery.isFetching}
              onRetry={() => chat.conversationsQuery.refetch()}
              onSelect={(id) => {
                chat.openConversation(id)
                setHistoryOpen(false)
              }}
              onDelete={chat.setPendingDelete}
            />
          </div>
        )}

        {/* Chat workspace */}
        <AssistantChatPanel
          chat={chat}
          className="border-0"
          disabledTitle={t('pages.assistant.notConfigured')}
          disabledDescription={
            isAdmin
              ? t('pages.assistant.notConfiguredDescription')
              : t('pages.assistant.disabledForUsers')
          }
          disabledAction={
            isAdmin ? (
              <Button variant="primary" onClick={() => navigate('/settings')}>
                <Gear weight="duotone" className="h-4 w-4" />
                {t('pages.assistant.openSettings')}
              </Button>
            ) : undefined
          }
        />
      </aside>
    </>
  )
}
