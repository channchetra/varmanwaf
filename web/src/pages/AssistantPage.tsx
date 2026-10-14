import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Plus, Robot } from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Select } from '@/components/ui/Select'
import { EmptyState } from '@/components/ui/EmptyState'
import { useAssistantChat } from '@/hooks/useAssistantChat'
import { AssistantChatPanel } from '@/components/assistant/AssistantChatPanel'
import { ConversationList } from '@/components/assistant/ConversationList'
import { useAuthStore } from '@/stores/authStore'

/**
 * The full-page AI assistant console.
 *
 * All state and rendering live in the shared assistant modules
 * (`components/assistant/` + `hooks/useAssistantChat`) so this page and the
 * floating widget behave identically; this file is the page-shaped assembly:
 * header, desktop conversation sidebar, mobile conversation picker.
 *
 * Fork divergence: the page stays administrator-gated - the provider key is
 * shared fleet-wide and the write tools can reach every site - while
 * upstream opened it to every signed-in user.
 */
export function AssistantPage() {
  const { t } = useTranslation()
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'

  if (!isAdmin) {
    return (
      <div className="animate-slide-up">
        <PageHeader
          title={t('pages.assistant.title')}
          description={t('pages.assistant.description')}
        />
        <EmptyState
          icon={<Robot weight="duotone" />}
          title={t('pages.assistant.adminOnly')}
          description={t('pages.assistant.adminOnlyDescription')}
        />
      </div>
    )
  }

  return <AssistantWorkspace />
}

function AssistantWorkspace() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const chat = useAssistantChat({ autoSelect: true })
  const {
    enabled,
    isStreaming,
    conversationsQuery,
    conversations,
    selectedId,
    draftMode,
    openConversation,
    startNewChat,
    setPendingDelete,
  } = chat

  const mobileOptions = [
    ...(draftMode ? [{ value: '', label: t('pages.assistant.newChat') }] : []),
    ...conversations.map((c) => ({
      value: c.id,
      label: c.title || t('pages.assistant.untitled'),
    })),
  ]

  return (
    <div className="animate-slide-up flex h-[calc(100vh-6.5rem)] flex-col">
      <PageHeader
        title={t('pages.assistant.title')}
        description={t('pages.assistant.description')}
        actions={
          <Button
            variant="secondary"
            icon={<Plus weight="bold" className="h-4 w-4" />}
            disabled={!enabled || isStreaming}
            onClick={startNewChat}
          >
            {t('pages.assistant.newChat')}
          </Button>
        }
      />

      <div className="flex min-h-0 flex-1 gap-4">
        {/* Conversation list (desktop) */}
        <Card className="hidden w-72 shrink-0 flex-col overflow-hidden md:flex">
          <div className="flex shrink-0 items-center justify-between gap-2 border-b border-line px-3.5 py-3">
            <span className="text-[13px] font-semibold text-fg-strong">
              {t('pages.assistant.conversations')}
            </span>
            {draftMode && (
              <span className="text-[11px] text-fg-subtle">
                {t('pages.assistant.newChat')}
              </span>
            )}
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-1.5">
            <ConversationList
              className="p-1.5"
              conversations={conversations}
              selectedId={selectedId}
              isStreaming={isStreaming}
              loading={conversationsQuery.isPending}
              error={conversationsQuery.isError ? conversationsQuery.error : null}
              retrying={conversationsQuery.isFetching}
              onRetry={() => conversationsQuery.refetch()}
              onSelect={openConversation}
              onDelete={setPendingDelete}
            />
          </div>
        </Card>

        {/* Thread */}
        <AssistantChatPanel
          chat={chat}
          headerExtra={
            <Select
              className="h-8 w-40 md:hidden"
              aria-label={t('pages.assistant.conversations')}
              value={selectedId ?? ''}
              options={mobileOptions}
              disabled={isStreaming}
              onChange={(e) => {
                if (e.target.value) openConversation(e.target.value)
              }}
            />
          }
          disabledAction={
            <Button variant="primary" onClick={() => navigate('/settings')}>
              {t('pages.assistant.openSettings')}
            </Button>
          }
        />
      </div>
    </div>
  )
}

export default AssistantPage
