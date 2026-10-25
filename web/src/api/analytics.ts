import { apiClient } from './client'
import type {
  AnalyticsSummary,
  RangeQuery,
  SiteOverview,
  SiteTrafficBucket,
  StatusCodeCount,
  TimeBucket,
  TopIp,
  TopPath,
  TopRule,
  TrafficSeries,
} from './types'

/**
 * Analytics — `/api/v1/analytics/*`.
 *
 * Every endpoint accepts the same `RangeQuery`. Defaults are a trailing 24h
 * window and `interval=hour`; the server rejects ranges wider than 31 days.
 */
export const analyticsApi = {
  summary: (params: RangeQuery = {}) =>
    apiClient.get<AnalyticsSummary>('/analytics/summary', { query: params }),

  requestsOverTime: (params: RangeQuery = {}) =>
    apiClient.get<TimeBucket[]>('/analytics/requests-over-time', { query: params }),

  /**
   * Egress bytes bucketed at a fixed width (default 5s). `step` must be one of
   * the server whitelist (5/10/30/60/300/900/3600/86400) and small enough that
   * the window yields at most ~8k buckets.
   */
  traffic: (params: RangeQuery & { step?: number } = {}) =>
    apiClient.get<TrafficSeries>('/analytics/traffic', { query: params }),

  sitesOverTime: (params: RangeQuery = {}) =>
    apiClient.get<SiteTrafficBucket[]>('/analytics/sites-over-time', { query: params }),

  topRules: (params: RangeQuery = {}) =>
    apiClient.get<TopRule[]>('/analytics/top-rules', { query: { limit: 10, ...params } }),

  topIps: (params: RangeQuery = {}) =>
    apiClient.get<TopIp[]>('/analytics/top-ips', { query: { limit: 10, ...params } }),

  topPaths: (params: RangeQuery = {}) =>
    apiClient.get<TopPath[]>('/analytics/top-paths', { query: { limit: 10, ...params } }),

  statusCodes: (params: RangeQuery = {}) =>
    apiClient.get<StatusCodeCount[]>('/analytics/status-codes', { query: params }),

  sitesOverview: (params: RangeQuery = {}) =>
    apiClient.get<SiteOverview[]>('/analytics/sites', { query: params }),
}

export const analyticsKeys = {
  all: ['analytics'] as const,
  summary: (params: RangeQuery) => [...analyticsKeys.all, 'summary', params] as const,
  traffic: (params: RangeQuery) => [...analyticsKeys.all, 'traffic', params] as const,
  bandwidth: (params: RangeQuery & { step?: number }) =>
    [...analyticsKeys.all, 'bandwidth', params] as const,
  sitesOverTime: (params: RangeQuery) => [...analyticsKeys.all, 'sites-over-time', params] as const,
  topRules: (params: RangeQuery) => [...analyticsKeys.all, 'top-rules', params] as const,
  topIps: (params: RangeQuery) => [...analyticsKeys.all, 'top-ips', params] as const,
  topPaths: (params: RangeQuery) => [...analyticsKeys.all, 'top-paths', params] as const,
  statusCodes: (params: RangeQuery) => [...analyticsKeys.all, 'status-codes', params] as const,
  sites: (params: RangeQuery) => [...analyticsKeys.all, 'sites', params] as const,
  overview: (params: RangeQuery) => [...analyticsKeys.all, 'overview', params] as const,
}

export default analyticsApi
