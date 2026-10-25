import { apiClient } from './client'

/**
 * Notification channels, thresholds and history - `/api/v1/notifications/*`.
 *
 * Channels are the delivery targets behind every alert (security rules,
 * certificate expiry, agents). Secrets are sealed at rest and redacted in
 * responses; send the `__REDACTED__` placeholder back to keep the stored
 * value.
 */
export type ChannelKind =
  | 'email'
  | 'wecom'
  | 'dingtalk'
  | 'webhook'
  | 'telegram'

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

/** Thresholds, per-event delivery toggles and suppression windows. */
export interface NotificationSettings {
  /** Noise master switch: false stops channel delivery (history stays). */
  enabled: boolean
  cpu_percent: number
  memory_percent: number
  disk_percent: number
  dedup_window_secs: number
  notify_agent_offline: boolean
  notify_agent_online: boolean
  notify_agent_resource: boolean
  notify_control_plane_resource: boolean
  notify_cert_expiry: boolean
  notify_cert_renewal_failed: boolean
  notify_config_sync_failed: boolean
  notify_site_failover_changed: boolean
  notify_auth_login_anomaly: boolean
  cert_expiry_warn_days: number
}

/**
 * The event types the control plane can raise, mirroring the server's
 * `event_type` constants. `security.alert` is emitted by our WAF pipeline
 * in addition to the upstream list.
 */
export const NOTIFICATION_EVENT_TYPES = [
  'agent.offline',
  'agent.online',
  'agent.resource',
  'control_plane.resource',
  'cert.renewal_failed',
  'cert.expiring',
  'cert.expired',
  'config.sync_failed',
  'site.failover_changed',
  'auth.login_anomaly',
  'security.alert',
  'report.scheduled',
] as const

export const notificationsApi = {
  channels: () =>
    apiClient.get<NotificationChannel[]>('/notifications/channels'),

  createChannel: (data: ChannelRequest) =>
    apiClient.post<NotificationChannel>('/notifications/channels', data),

  updateChannel: (id: string, data: ChannelRequest) =>
    apiClient.put<NotificationChannel>(`/notifications/channels/${id}`, data),

  removeChannel: (id: string) =>
    apiClient.delete<void>(`/notifications/channels/${id}`),

  /** Sends a test alert through the channel; `ok` reports the delivery. */
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

  getSettings: () =>
    apiClient.get<NotificationSettings>('/notifications/settings'),

  saveSettings: (settings: NotificationSettings) =>
    apiClient.put<NotificationSettings>('/notifications/settings', settings),

  listEvents: (limit = 100, offset = 0, eventType?: string) => {
    const params = new URLSearchParams()
    params.set('limit', String(limit))
    params.set('offset', String(offset))
    if (eventType) params.set('event_type', eventType)
    return apiClient.get<NotificationEvent[]>(
      `/notifications/events?${params.toString()}`,
    )
  },
}

export const notificationsKeys = {
  all: ['notifications'] as const,
  channels: () => [...notificationsKeys.all, 'channels'] as const,
  events: () => [...notificationsKeys.all, 'events'] as const,
  eventTypes: () => [...notificationsKeys.all, 'event-types'] as const,
}

/** Alias kept from the upstream port: settings and paged history. */
export const notificationKeys = {
  all: ['notifications'] as const,
  channels: () => [...notificationKeys.all, 'channels'] as const,
  settings: () => [...notificationKeys.all, 'settings'] as const,
  events: (offset?: number) =>
    [...notificationKeys.all, 'events', offset ?? 0] as const,
}

export default notificationsApi
