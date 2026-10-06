import {
  ApiError,
  BASE_URL,
  apiClient,
  refreshAccessToken,
} from './client'
import { getAuthToken } from '@/stores/authStore'
import type {
  AiChatEvent,
  AiConversation,
  AiConversationDetail,
  AiSettings,
  AiTestResult,
  Page,
  PaginationQuery,
  UpdateAiSettingsRequest,
} from './types'

/**
 * The built-in AI assistant — `/api/v1/settings/ai` and
 * `/api/v1/ai/conversations` (administrators only).
 *
 * The chat turn is a Server-Sent Event stream; `streamChatMessage` consumes it
 * with `fetch` (not `EventSource`, which cannot send the `Authorization`
 * header) and reports each `ChatEvent` to the caller.
 */
export const aiApi = {
  getSettings: () => apiClient.get<AiSettings>('/settings/ai'),

  saveSettings: (payload: UpdateAiSettingsRequest) =>
    apiClient.put<AiSettings>('/settings/ai', payload),

  /** Probes a draft (or the stored configuration when no body is sent). */
  test: (payload?: UpdateAiSettingsRequest) =>
    apiClient.post<AiTestResult>('/settings/ai/test', payload),

  listConversations: (query: PaginationQuery = {}) =>
    apiClient.get<Page<AiConversation>>('/ai/conversations', { query }),

  createConversation: (title?: string) =>
    apiClient.post<AiConversation>('/ai/conversations', { title: title ?? null }),

  getConversation: (id: string) =>
    apiClient.get<AiConversationDetail>(`/ai/conversations/${id}`),

  deleteConversation: (id: string) =>
    apiClient.delete<void>(`/ai/conversations/${id}`),
}

export const aiKeys = {
  all: ['ai'] as const,
  settings: () => [...aiKeys.all, 'settings'] as const,
  conversations: () => [...aiKeys.all, 'conversations'] as const,
  conversation: (id: string) => [...aiKeys.all, 'conversation', id] as const,
}

export interface ChatStreamHandlers {
  onEvent: (event: AiChatEvent) => void
  /** Aborting ends the local stream; the server stops at its next boundary. */
  signal?: AbortSignal
}

/**
 * Runs one chat turn and feeds its SSE events to `onEvent`.
 *
 * Resolves when the stream ends (`done`/`error` arrive as events); rejects
 * only when the request itself could not start — the server validates the
 * settings before opening the stream, so those refusals arrive as the usual
 * JSON error envelope and are thrown as an {@link ApiError}.
 */
export async function streamChatMessage(
  conversationId: string,
  content: string,
  handlers: ChatStreamHandlers,
): Promise<void> {
  const send = (token: string | null) =>
    fetch(`${BASE_URL}/ai/conversations/${conversationId}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ content }),
      signal: handlers.signal,
    })

  let response: Response
  try {
    response = await send(getAuthToken())
    if (response.status === 401) {
      const fresh = await refreshAccessToken()
      if (fresh) response = await send(fresh)
    }
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') return
    throw new ApiError(
      err instanceof Error ? err.message : 'Network request failed',
      0,
      'network_error',
      true,
    )
  }

  if (!response.ok || !response.body) {
    let message = `Request failed (${response.status})`
    try {
      const parsed = (await response.json()) as {
        error?: { message?: string }
      }
      if (parsed?.error?.message) message = parsed.error.message
    } catch {
      /* non-JSON error body — keep the generic message */
    }
    throw new ApiError(message, response.status)
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })

      // SSE frames are separated by a blank line; keep-alive comments carry
      // no `data:` line and are skipped.
      let boundary = buffer.indexOf('\n\n')
      while (boundary >= 0) {
        const frame = buffer.slice(0, boundary)
        buffer = buffer.slice(boundary + 2)
        const data = frame
          .split('\n')
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).trim())
          .join('\n')
        if (data) {
          try {
            handlers.onEvent(JSON.parse(data) as AiChatEvent)
          } catch {
            /* ignore a frame we cannot parse */
          }
        }
        boundary = buffer.indexOf('\n\n')
      }
    }
  } catch (err) {
    // A user-initiated stop ends the stream; it is not a failure.
    if (err instanceof DOMException && err.name === 'AbortError') return
    throw err
  } finally {
    reader.releaseLock()
  }
}

export default aiApi
