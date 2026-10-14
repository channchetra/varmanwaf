import { apiClient } from './client'

/**
 * Notification channels and history - `/api/v1/notifications/*`.
 *
 * Channels are the delivery targets behind every alert (security rules,
 * certificate expiry, agents). Secrets are sealed at rest and redacted in
 * responses; send the `__REDACTED__` placeholder back to keep the stored
 * value.
 */

export type ChannelKind = 'email' | 'wecom' | 'dingtalk' | 'webhook'

export interface NotificationChannel {
  id: string
  name: string
  kind: ChannelKind
  config: Record<string, unknown>
  /** Event types the channel receives; empty = everything. */
  events: string[]
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface ChannelRequest {
  name: string
  kind: ChannelKind
  config: Record<string, unknown>
  events: string[]
  enabled: boolean
}

export interface NotificationEvent {
  id: string
  event_type: string
  severity: string
  title: string
  message: string
  details: Record<string, unknown> | null
  created_at: string
}

export const REDACTED = '__REDACTED__'

export const notificationsApi = {
  channels: () =>
    apiClient.get<NotificationChannel[]>('/notifications/channels'),

  createChannel: (data: ChannelRequest) =>
    apiClient.post<NotificationChannel>('/notifications/channels', data),

  updateChannel: (id: string, data: ChannelRequest) =>
    apiClient.put<NotificationChannel>(`/notifications/channels/${id}`, data),

  removeChannel: (id: string) =>
    apiClient.delete<void>(`/notifications/channels/${id}`),

  testChannel: (id: string) =>
    apiClient.post<{ ok: boolean; error?: string }>(
      `/notifications/channels/${id}/test`,
      {},
    ),

  events: (limit = 100) =>
    apiClient.get<NotificationEvent[]>('/notifications/events', {
      query: { limit },
    }),

  eventTypes: () =>
    apiClient.get<string[]>('/notifications/event-types'),
}

export const notificationsKeys = {
  all: ['notifications'] as const,
  channels: () => [...notificationsKeys.all, 'channels'] as const,
  events: () => [...notificationsKeys.all, 'events'] as const,
  eventTypes: () => [...notificationsKeys.all, 'event-types'] as const,
}

export default notificationsApi
