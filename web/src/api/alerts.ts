import { apiClient } from './client'

/**
 * Security alert rules and silences - `/api/v1/alerts/*`.
 *
 * Rules watch stored security events over a sliding window. `event_count`
 * fires at a raw count; `blocked_ratio` fires at a percentage of requests
 * once the window holds `min_samples` requests, so a single blocked probe in
 * a quiet minute cannot page anyone. The preview endpoint reports what the
 * rule sees right now without dispatching anything.
 */

export type AlertMetric = 'event_count' | 'blocked_ratio'

export interface AlertRule {
  id: string
  name: string
  enabled: boolean
  metric: AlertMetric
  threshold: number
  window_seconds: number
  min_samples: number
  site_id: string | null
  event_type: string
  rule_id_contains: string
  severity: 'info' | 'warning' | 'critical'
  /** Notification channel ids; empty = every subscribed channel. */
  channels: string[]
  cooldown_seconds: number
  last_fired_at: string | null
  last_value: number | null
  last_samples: number | null
  last_evaluated_at: string | null
  created_at: string
  updated_at: string
}

export interface AlertRuleRequest {
  name: string
  enabled?: boolean
  metric: AlertMetric
  threshold: number
  window_seconds: number
  min_samples?: number
  site_id?: string | null
  event_type?: string
  rule_id_contains?: string
  severity?: string
  channels?: string[]
  cooldown_seconds?: number
}

export interface AlertPreview {
  metric: AlertMetric
  value: number
  hits: number
  samples: number
  threshold: number
  min_samples: number
  window_seconds: number
  threshold_met: boolean
  silenced: boolean
  silence_reason: string | null
  samples_basis: string
  evaluated_at: string
}

export interface AlertSilence {
  id: string
  site_id: string | null
  reason: string
  starts_at: string
  ends_at: string | null
  created_by: string
  created_at: string
}

export interface AlertSilenceRequest {
  site_id?: string | null
  reason?: string
  starts_at?: string
  ends_at?: string | null
}

export const alertMetrics: AlertMetric[] = ['event_count', 'blocked_ratio']

export const alertsApi = {
  rules: () => apiClient.get<AlertRule[]>('/alerts/rules'),

  createRule: (data: AlertRuleRequest) =>
    apiClient.post<AlertRule>('/alerts/rules', data),

  updateRule: (id: string, data: AlertRuleRequest) =>
    apiClient.put<AlertRule>(`/alerts/rules/${id}`, data),

  removeRule: (id: string) => apiClient.delete<void>(`/alerts/rules/${id}`),

  previewRule: (id: string) =>
    apiClient.post<AlertPreview>(`/alerts/rules/${id}/preview`, {}),

  silences: () => apiClient.get<AlertSilence[]>('/alerts/silences'),

  createSilence: (data: AlertSilenceRequest) =>
    apiClient.post<AlertSilence>('/alerts/silences', data),

  removeSilence: (id: string) =>
    apiClient.delete<void>(`/alerts/silences/${id}`),
}

export const alertKeys = {
  all: ['alerts'] as const,
  rules: () => [...alertKeys.all, 'rules'] as const,
  silences: () => [...alertKeys.all, 'silences'] as const,
}

export default alertsApi
