import { ApiError, BASE_URL, apiClient, refreshAccessToken } from './client'
import { getAuthToken } from '@/stores/authStore'

/** One labelled count in the summary (top type / country / IP). */
export interface ReportLabelCount {
  label: string
  count: number
}

/** One day of the report's timeline. */
export interface ReportDailyPoint {
  date: string
  total: number
  blocked: number
}

/** `GET /reports/summary` - light aggregates for the dashboard and page. */
export interface ReportSummary {
  from: string
  to: string
  site_id: string | null
  events: number
  blocked: number
  monitored: number
  unique_ips: number
  unique_paths: number
  top_type: ReportLabelCount | null
  top_country: ReportLabelCount | null
  top_ip: ReportLabelCount | null
  daily: ReportDailyPoint[]
}

export type ReportActionFilter = 'all' | 'blocked' | 'monitor'

export interface ReportQuery {
  /** Inclusive start, `YYYY-MM-DD` or RFC 3339. */
  from?: string
  /** End, `YYYY-MM-DD` (whole day) or RFC 3339. */
  to?: string
  site_id?: string
  /** `all` | `blocked` | `monitor`; omit for all. */
  action?: ReportActionFilter
  /** Substring filter over the client IP and the request path. */
  q?: string
}

/** Operator-customizable report presentation. */
export interface ReportSettings {
  title: string
  footer_note: string | null
}

export const reportsApi = {
  summary: (params: ReportQuery = {}) =>
    apiClient.get<ReportSummary>('/reports/summary', { query: params }),

  getSettings: () => apiClient.get<ReportSettings>('/reports/settings'),

  saveSettings: (settings: ReportSettings) =>
    apiClient.put<ReportSettings>('/reports/settings', settings),
}

export const reportKeys = {
  all: ['reports'] as const,
  summary: (params: ReportQuery) =>
    [...reportKeys.all, 'summary', params] as const,
  settings: () => [...reportKeys.all, 'settings'] as const,
}

/** The report's HTML and its server-chosen file name. */
export interface FetchedReport {
  html: string
  filename: string
}

function queryString(params: ReportQuery): string {
  const query = new URLSearchParams()
  if (params.from) query.set('from', params.from)
  if (params.to) query.set('to', params.to)
  if (params.site_id) query.set('site_id', params.site_id)
  if (params.action && params.action !== 'all') {
    query.set('action', params.action)
  }
  if (params.q) query.set('q', params.q)
  return query.toString()
}

/**
 * Fetches the generated report with the auth header. Used both by the
 * online preview (rendered in a sandboxed iframe) and by the download.
 */
export async function fetchInterceptionReport(
  params: ReportQuery = {},
): Promise<FetchedReport> {
  const suffix = queryString(params)
  const url = `${BASE_URL}/reports/interception${suffix ? `?${suffix}` : ''}`

  const send = (token: string | null) =>
    fetch(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
  let response = await send(getAuthToken())
  if (response.status === 401) {
    const fresh = await refreshAccessToken()
    if (fresh) response = await send(fresh)
  }
  if (!response.ok) {
    let message = `Report generation failed (${response.status})`
    try {
      const parsed = (await response.json()) as {
        error?: { message?: string }
      }
      if (parsed.error?.message) message = parsed.error.message
    } catch {
      // Keep the status-based message when the body is not the envelope.
    }
    throw new ApiError(message, response.status, 'unknown', false)
  }

  const html = await response.text()
  const disposition = response.headers.get('Content-Disposition') ?? ''
  const filename =
    /filename="([^"]+)"/.exec(disposition)?.[1] ??
    'varmanwaf-interception.html'
  return { html, filename }
}

/** Downloads the report as a self-contained HTML file. */
export async function downloadInterceptionReport(
  params: ReportQuery = {},
): Promise<void> {
  const { html, filename } = await fetchInterceptionReport(params)
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
  const objectUrl = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = objectUrl
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(objectUrl)
}

export default reportsApi
