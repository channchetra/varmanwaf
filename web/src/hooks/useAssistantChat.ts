import { useEffect, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { aiApi, aiKeys, streamChatMessage } from '@/api/ai'
import { errorMessage, handleApiError } from '@/api/errors'
import { useToast } from '@/components/ui/Toast'
import type { AiChatEvent, AiConversation, Page } from '@/api/types'
import { reduceTurn, type PendingTurn } from '@/components/assistant/turn'

/**
 * All conversation/chat state for the AI assistant, shared verbatim by the
 * /assistant page and the floating widget. Only data and stream state live
 * here — layout is the caller's job.
 *
 * Instances share the react-query cache (same `aiKeys`), so a turn started
 * in the widget appears in the page's thread once refetched; selection
 * state is per-instance by design.
 *
 * Every message carries the page the user is currently viewing as
 * `page_path`, so the model can ground its answer in the operator's
 * context. The hint is derived locally (route label + pathname) and is
 * purely informational — it is never used for authorization.
 */

/** Top-level route prefixes mapped to their nav labels. */
const NAV_ROUTES: Array<[RegExp, string]> = [
  [/^\/dashboard/, 'nav.dashboard'],
  [/^\/sites/, 'nav.sites'],
  [/^\/ip-groups/, 'nav.ipGroups'],
  [/^\/ssl/, 'nav.ssl'],
  [/^\/traffic/, 'nav.traffic'],
  [/^\/logs/, 'nav.logs'],
  [/^\/assistant/, 'nav.assistant'],
  [/^\/agents/, 'nav.agents'],
  [/^\/lifecycle/, 'nav.lifecycle'],
  [/^\/account/, 'nav.account'],
  [/^\/settings/, 'nav.settings'],
]

/** Human-readable "label (path)" description of the current console page. */
function describeCurrentPage(pathname: string, t: (key: string) => string) {
  const labelKey = NAV_ROUTES.find(([pattern]) => pattern.test(pathname))?.[1]
  const label = labelKey ? t(labelKey) : 'PingWAF console'
  return `${label} (${pathname})`
}

export interface AssistantChatOptions {
  /** Picks the most recent conversation on first load (page behaviour). */
  autoSelect?: boolean
}

export function useAssistantChat(options: AssistantChatOptions = {}) {
  const { t } = useTranslation()
  const toast = useToast()
  const location = useLocation()
  const queryClient = useQueryClient()

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
  if (options.autoSelect && listData && listData !== lastListData) {
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

  // Abort a running stream when this instance unmounts (e.g. the /assistant
  // page being navigated away from). The widget stays mounted by design, so
  // closing the panel does not interrupt its stream. The server finishes the
  // turn regardless and persists it; refetch picks the result up.
  useEffect(() => {
    return () => abortRef.current?.abort()
  }, [])

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
      await streamChatMessage(
        conversationId,
        content,
        {
          signal: controller.signal,
          onEvent: (event: AiChatEvent) => {
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
        },
        describeCurrentPage(location.pathname, t),
      )
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

  return {
    // queries
    settingsQuery,
    conversationsQuery,
    detailQuery,
    settings,
    enabled,
    conversations,
    storedMessages,
    // selection
    selectedId,
    draftMode,
    selectedTitle,
    openConversation,
    startNewChat,
    // composer / stream
    input,
    setInput,
    pendingTurn,
    isStreaming,
    turnError,
    setTurnError,
    threadRef,
    handleSend,
    stopStreaming,
    // deletion
    pendingDelete,
    setPendingDelete,
    removeConversation,
  }
}

export type AssistantChat = ReturnType<typeof useAssistantChat>
