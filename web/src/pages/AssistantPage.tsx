import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  CaretRight,
  ChatCircleDots,
  Checks,
  CircleNotch,
  Gear,
  PaperPlaneTilt,
  Plus,
  Robot,
  Sparkle,
  Stop,
  Trash,
  Warning,
  Wrench,
  X,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Select } from '@/components/ui/Select'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { aiApi, aiKeys, streamChatMessage } from '@/api/ai'
import { errorMessage, handleApiError } from '@/api/errors'
import { useAuthStore } from '@/stores/authStore'
import { useNow } from '@/hooks'
import { cn } from '@/lib/utils'
import { formatRelative } from '@/lib/format'
import type {
  AiChatEvent,
  AiConversation,
  AiMessage,
  Page,
} from '@/api/types'

/**
 * The built-in AI assistant console.
 *
 * Everything here talks to administrator-only endpoints: the provider key is
 * shared fleet-wide and the tools can reach every site, so the page gates
 * itself the same way the settings cards do, before issuing any request.
 *
 * A chat turn streams over SSE (`streamChatMessage`) and is rendered from a
 * small reducer that folds the event stream into renderable parts — text
 * bubbles and tool cards — while the persisted transcript is only re-fetched
 * once the turn ends, so the streamed preview never flickers.
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

/* ── Turn model ─────────────────────────────────────────────────────── */

interface ToolStep {
  id: string
  name: string
  args: unknown
  result?: unknown
  isError?: boolean
  pending: boolean
}

type TurnPart =
  | { kind: 'text'; key: string; text: string }
  | { kind: 'tool'; key: string; step: ToolStep }

interface PendingTurn {
  /** The user message being sent; rendered optimistically until refetch. */
  content: string
  parts: TurnPart[]
  streaming: boolean
}

/** Folds one SSE event into the streamed preview of the running turn. */
function reduceTurn(turn: PendingTurn, event: AiChatEvent): PendingTurn {
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

/* ── Workspace ──────────────────────────────────────────────────────── */

function AssistantWorkspace() {
  const { t } = useTranslation()
  const toast = useToast()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const now = useNow(60_000)

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [draftMode, setDraftMode] = useState(false)
  const [input, setInput] = useState('')
  const [pendingTurn, setPendingTurn] = useState<PendingTurn | null>(null)
  const [turnError, setTurnError] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<AiConversation | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const threadRef = useRef<HTMLDivElement>(null)

  const settingsQuery = useQuery({
    queryKey: aiKeys.settings(),
    queryFn: () => aiApi.getSettings(),
  })
  const conversationsQuery = useQuery({
    queryKey: aiKeys.conversations(),
    queryFn: () => aiApi.listConversations({ page_size: 100 }),
  })
  const detailQuery = useQuery({
    queryKey: aiKeys.conversation(selectedId ?? ''),
    queryFn: () => aiApi.getConversation(selectedId as string),
    enabled: selectedId !== null,
  })

  const settings = settingsQuery.data
  const enabled = settings?.enabled ?? false
  const conversations = conversationsQuery.data?.items ?? []

  // Render-phase reseed on new list data (identity changes only when the
  // payload really differs — TanStack Query keeps structural sharing). Picks
  // the most recent conversation on first load but never overrides an
  // explicit "new chat" or an open conversation.
  const listData = conversationsQuery.data
  const [lastListData, setLastListData] = useState<typeof listData | null>(null)
  if (listData && listData !== lastListData) {
    setLastListData(listData)
    if (!selectedId && !draftMode && listData.items.length > 0) {
      setSelectedId(listData.items[0].id)
    }
  }

  const isStreaming = pendingTurn?.streaming ?? false
  const storedMessages = detailQuery.data?.messages ?? []

  // Keep the newest content in view while the answer streams.
  useEffect(() => {
    const el = threadRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [detailQuery.data, pendingTurn])

  const selectedTitle =
    detailQuery.data?.title ||
    conversations.find((c) => c.id === selectedId)?.title ||
    (draftMode ? t('pages.assistant.newChat') : t('pages.assistant.title'))

  const openConversation = (id: string) => {
    if (isStreaming || id === selectedId) return
    setDraftMode(false)
    setSelectedId(id)
    setTurnError(null)
  }

  const startNewChat = () => {
    if (isStreaming) return
    setDraftMode(true)
    setSelectedId(null)
    setTurnError(null)
    setInput('')
  }

  const stopStreaming = () => abortRef.current?.abort()

  const handleSend = async () => {
    const content = input.trim()
    if (!content || isStreaming || !enabled) return

    setTurnError(null)
    let conversationId = selectedId
    if (!conversationId) {
      try {
        const created = await aiApi.createConversation()
        conversationId = created.id
        setDraftMode(false)
        setSelectedId(created.id)
        void queryClient.invalidateQueries({ queryKey: aiKeys.conversations() })
      } catch (err) {
        handleApiError(err)
        return
      }
    }

    setInput('')
    let turn: PendingTurn = { content, parts: [], streaming: true }
    setPendingTurn(turn)

    const controller = new AbortController()
    abortRef.current = controller
    // A refusal before the first event means no work happened server-side:
    // the message was not stored, so it goes back into the composer.
    let sawEvent = false

    try {
      await streamChatMessage(conversationId, content, {
        signal: controller.signal,
        onEvent: (event) => {
          sawEvent = true
          if (event.type === 'conversation') {
            // The first message names the conversation; reflect it in place.
            queryClient.setQueryData<Page<AiConversation>>(
              aiKeys.conversations(),
              (prev) =>
                prev
                  ? {
                      ...prev,
                      items: prev.items.map((c) =>
                        c.id === event.id ? { ...c, title: event.title } : c,
                      ),
                    }
                  : prev,
            )
            return
          }
          if (event.type === 'error') {
            setTurnError(event.message)
            return
          }
          turn = reduceTurn(turn, event)
          setPendingTurn(turn)
        },
      })
    } catch (err) {
      if (!sawEvent) {
        setPendingTurn(null)
        setInput(content)
        handleApiError(err)
        return
      }
      setTurnError(errorMessage(err))
    } finally {
      abortRef.current = null
      // Re-read the persisted transcript before dropping the streamed
      // preview, so the thread never blanks out between the two.
      await queryClient.invalidateQueries({
        queryKey: aiKeys.conversation(conversationId),
      })
      await queryClient.invalidateQueries({ queryKey: aiKeys.conversations() })
      setPendingTurn(null)
    }
  }

  const removeConversation = useMutation({
    mutationFn: (id: string) => aiApi.deleteConversation(id),
    onSuccess: (_data, id) => {
      toast.success(t('pages.assistant.deleted'))
      setPendingDelete(null)
      queryClient.removeQueries({ queryKey: aiKeys.conversation(id) })
      if (selectedId === id) {
        setDraftMode(true)
        setSelectedId(null)
        setTurnError(null)
      }
      void queryClient.invalidateQueries({ queryKey: aiKeys.conversations() })
    },
    onError: (err) => {
      setPendingDelete(null)
      handleApiError(err)
    },
  })

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
            {draftMode && <Badge tone="brand">{t('pages.assistant.newChat')}</Badge>}
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-1.5">
            {conversationsQuery.isPending ? (
              <SkeletonRows rows={5} columns={1} className="p-1.5" />
            ) : conversationsQuery.isError && conversations.length === 0 ? (
              <div className="p-1.5">
                <ErrorState
                  variant="inline"
                  error={conversationsQuery.error}
                  onRetry={() => conversationsQuery.refetch()}
                  retrying={conversationsQuery.isFetching}
                />
              </div>
            ) : conversations.length === 0 ? (
              <p className="px-2.5 py-8 text-center text-xs leading-relaxed text-fg-subtle">
                {t('pages.assistant.empty')}
              </p>
            ) : (
              <div className="flex flex-col gap-0.5">
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
                        onClick={() => openConversation(conversation.id)}
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
                        onClick={() => setPendingDelete(conversation)}
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
        </Card>

        {/* Thread */}
        <Card className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
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
                title={t('pages.assistant.notConfigured')}
                description={t('pages.assistant.notConfiguredDescription')}
                action={
                  <Button variant="primary" onClick={() => navigate('/settings')}>
                    {t('pages.assistant.openSettings')}
                  </Button>
                }
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
        </Card>
      </div>

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
    </div>
  )
}

/* ── Thread rendering ───────────────────────────────────────────────── */

function ThreadBody({
  messages,
  pendingTurn,
  isStreaming,
}: {
  messages: AiMessage[]
  pendingTurn: PendingTurn | null
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

function ToolCard({
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

/* ── Helpers ────────────────────────────────────────────────────────── */

function parseJson(text: string | null | undefined): unknown {
  if (!text) return undefined
  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

function formatJson(value: unknown): string {
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, 2) ?? String(value)
}

/** Tool failures are stored as a lone `{"error": …}` object. */
function isToolError(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    'error' in value
  )
}

export default AssistantPage
