import { apiClient } from './client'
import type {
  CreateRateLimitRequest,
  Page,
  PaginationQuery,
  RateLimitRule,
  UpdateRateLimitRequest,
} from './types'

/**
 * Rate limiting — `/api/v1/sites/{site_id}/rate-limit-rules`.
 *
 * A rule counts requests matching `expression` per combination of
 * `characteristics` within `period_seconds`; once `threshold` is exceeded the
 * `action` is applied for `mitigation_timeout_seconds`.
 */
export const rateLimitApi = {
  list: (siteId: string, query: PaginationQuery = {}) =>
    apiClient.get<Page<RateLimitRule>>(`/sites/${siteId}/rate-limit-rules`, {
      query: { page_size: 200, ...query },
    }),

  create: (siteId: string, data: CreateRateLimitRequest) =>
    apiClient.post<RateLimitRule>(`/sites/${siteId}/rate-limit-rules`, data),

  update: (siteId: string, id: string, data: UpdateRateLimitRequest) =>
    apiClient.put<RateLimitRule>(`/sites/${siteId}/rate-limit-rules/${id}`, data),

  delete: (siteId: string, id: string) =>
    apiClient.delete<void>(`/sites/${siteId}/rate-limit-rules/${id}`),

  /** Shorthand for the enable/disable switch on a rule row. */
  toggleEnabled: (siteId: string, id: string, enabled: boolean) =>
    apiClient.put<RateLimitRule>(`/sites/${siteId}/rate-limit-rules/${id}`, { enabled }),
}

export const rateLimitKeys = {
  all: (siteId: string) => ['sites', siteId, 'rate-limit-rules'] as const,
  list: (siteId: string, query?: PaginationQuery) =>
    ['sites', siteId, 'rate-limit-rules', 'list', query ?? {}] as const,
}

export default rateLimitApi
