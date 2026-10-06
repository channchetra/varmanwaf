import { apiClient } from './client'
import { analyticsApi } from './analytics'
import type {
  AnalyticsSummary,
  RangeQuery,
  StatusCodeCount,
  TimeBucket,
  TopIp,
  TopPath,
  TopRule,
  TrafficOverview,
  TrafficRange,
} from './types'

/**
 * Site traffic analytics — `/api/v1/analytics/traffic`.
 *
 * A thin site-scoped wrapper over the analytics endpoints. Omitting `siteId`
 * asks for the fleet-wide aggregate, which is what the global traffic page
 * shows; administrators may span every site, other roles only their own.
 */
export const trafficApi = {
  overview: (siteId?: string, range: TrafficRange = '24h') =>
    fetchTrafficOverview(siteId, range),

  summary: (siteId: string, params: RangeQuery = {}) =>
    apiClient.get<AnalyticsSummary>('/analytics/summary', {
      query: { site_id: siteId, ...params },
    }),

  series: (siteId: string, params: RangeQuery = {}) =>
    apiClient.get<TimeBucket[]>('/analytics/requests-over-time', {
      query: { site_id: siteId, ...params },
    }),

  topPaths: (siteId: string, params: RangeQuery = {}) =>
    apiClient.get<TopPath[]>('/analytics/top-paths', {
      query: { site_id: siteId, limit: 10, ...params },
    }),

  topIps: (siteId: string, params: RangeQuery = {}) =>
    apiClient.get<TopIp[]>('/analytics/top-ips', {
      query: { site_id: siteId, limit: 10, ...params },
    }),

  topRules: (siteId: string, params: RangeQuery = {}) =>
    apiClient.get<TopRule[]>('/analytics/top-rules', {
      query: { site_id: siteId, limit: 10, ...params },
    }),

  statusCodes: (siteId: string, params: RangeQuery = {}) =>
    apiClient.get<StatusCodeCount[]>('/analytics/status-codes', {
      query: { site_id: siteId, ...params },
    }),
}

/** Hours spanned by each preset range label. */
export const RANGE_HOURS: Record<TrafficRange, number> = {
  '1h': 1,
  '6h': 6,
  '24h': 24,
  '7d': 24 * 7,
  '30d': 24 * 30,
}

/**
 * Bucket width (seconds) per preset range for the egress chart. Short windows
 * get the finest 5s resolution; wider ones widen the step so the series stays
 * under the server's bucket cap (~8k) and readable on screen.
 */
export const TRAFFIC_STEP: Record<TrafficRange, number> = {
  '1h': 5,
  '6h': 30,
  '24h': 300,
  '7d': 900,
  '30d': 3600,
}

/** Builds the `{from,to,interval}` query for a preset range. */
export function rangeQueryFor(range: TrafficRange): RangeQuery {
  const hours = RANGE_HOURS[range]
  const to = new Date()
  const from = new Date(to.getTime() - hours * 3600_000)
  const interval = hours <= 2 ? 'minute' : hours <= 72 ? 'hour' : 'day'
  return { from: from.toISOString(), to: to.toISOString(), interval }
}

/** Resolves every widget the traffic page renders in one pass. */
export async function fetchTrafficOverview(
  siteId?: string,
  range: TrafficRange = '24h',
): Promise<TrafficOverview> {
  const params: RangeQuery = { ...(siteId ? { site_id: siteId } : {}), ...rangeQueryFor(range) }
  const [summary, series, egress, topPaths, topIps, topRules, statusCodes] =
    await Promise.all([
      analyticsApi.summary(params),
      analyticsApi.requestsOverTime(params),
      analyticsApi.traffic({ ...params, step: TRAFFIC_STEP[range] }),
      analyticsApi.topPaths({ ...params, limit: 10 }),
      analyticsApi.topIps({ ...params, limit: 10 }),
      analyticsApi.topRules({ ...params, limit: 10 }),
      analyticsApi.statusCodes(params),
    ])
  return { summary, series, egress, topPaths, topIps, topRules, statusCodes }
}

/**
 * Buckets raw status-code counts into the 2xx/3xx/4xx/5xx families the pie
 * chart renders. Returns entries sorted by share, descending.
 */
export function groupStatusCodes(
  counts: StatusCodeCount[],
): { family: string; requests: number }[] {
  const families: Record<string, number> = {
    '2xx': 0,
    '3xx': 0,
    '4xx': 0,
    '5xx': 0,
  }
  for (const entry of counts) {
    const family = `${Math.floor(entry.status_code / 100)}xx`
    if (family in families) families[family] += entry.requests
  }
  return Object.entries(families)
    .map(([family, requests]) => ({ family, requests }))
    .filter((f) => f.requests > 0)
    .sort((a, b) => b.requests - a.requests)
}

export const trafficKeys = {
  all: (siteId?: string) => ['traffic', siteId ?? 'all'] as const,
  overview: (siteId: string | undefined, range: TrafficRange) =>
    ['traffic', siteId ?? 'all', 'overview', range] as const,
}

export default trafficApi
