import { apiClient } from './client'
import type {
  AccessLog,
  LogQueryParams,
  Page,
  PurgeResult,
  SecurityEvent,
} from './types'

/**
 * Logs — `/api/v1/logs/*`.
 *
 * Backed by PostgreSQL for recent events and Elasticsearch for the long tail;
 * the API hides which one answered. `from`/`to` are RFC 3339, defaulting to the
 * trailing 24h with a hard cap of 90 days.
 */
export const logsApi = {
  securityEvents: (params: LogQueryParams = {}) =>
    apiClient.get<Page<SecurityEvent>>('/logs/security', { query: params }),

  accessLogs: (params: LogQueryParams = {}) =>
    apiClient.get<Page<AccessLog>>('/logs/access', { query: params }),

  purge: (params: { site_id?: string; older_than_days?: number } = {}) =>
    apiClient.delete<PurgeResult>('/logs/purge', { query: params }),

  /**
   * `GET /security-events/{id}/why` - the resolved decision chain behind
   * one security event (auto-block, rate limit, producing rule with
   * provenance, policy binding, tuning). Unknowns are reported as such.
   */
  whySecurity: (eventId: number) =>
    apiClient.get<EventExplanation>(`/security-events/${eventId}/why`),
}

/** One resolved stage of an event's decision chain. */
export interface ExplanationStep {
  stage: string
  status: 'hit' | 'miss' | 'unknown'
  title: string
  detail: string
  data: unknown
}

/** One rule or signature that fired while evaluating the request. */
export interface MatchedRule {
  id: string
  name: string
  /** managed | signature | crs_import | policy | site_rule | patch | detector | unknown */
  source: string
  status: 'hit' | 'unknown'
  severity: number | null
  action: string | null
  category: string | null
  /** The rule whose action produced the verdict. */
  deciding: boolean
  evidence: string | null
  detail: string
  data: unknown
}

export interface EventExplanation {
  verdict: string
  blocked_by: string | null
  /** Absent on older control planes; treat as an empty list. */
  matched_rules?: MatchedRule[]
  steps: ExplanationStep[]
  notes: string[]
}

/**
 * Triggers a client-side download of the current result set as JSON.
 *
 * There is no server-side export endpoint, so we serialise the page the user is
 * looking at — which is exactly what an operator expects from an "export"
 * button on a filtered table.
 */
export function downloadJson(filename: string, payload: unknown): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: 'application/json',
  })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename.endsWith('.json') ? filename : `${filename}.json`
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  // Give the browser a tick to start the download before revoking.
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** ISO-ish stamp safe for filenames: `2026-09-25T10-30-00`. */
export function fileTimestamp(date = new Date()): string {
  return date.toISOString().replace(/[:.]/g, '-').slice(0, 19)
}

export const logKeys = {
  all: ['logs'] as const,
  security: (params: LogQueryParams) => [...logKeys.all, 'security', params] as const,
  access: (params: LogQueryParams) => [...logKeys.all, 'access', params] as const,
}

export default logsApi
