import { apiClient } from './client'
import type {
  CreateRewriteRuleRequest,
  Page,
  PaginationQuery,
  RewriteRule,
  UpdateRewriteRuleRequest,
} from './types'

/**
 * Rewrite rules — `/api/v1/sites/{siteId}/rewrite-rules`.
 *
 * Each rule matches a wirefilter `condition` and applies an ordered list of
 * operations (header / path / query / body mutations) on the request or the
 * response. Lower `priority` runs first.
 */
export const rewriteApi = {
  list: (siteId: string, query: PaginationQuery = {}) =>
    apiClient.get<Page<RewriteRule>>(`/sites/${siteId}/rewrite-rules`, {
      query: { page_size: 200, ...query },
    }),

  create: (siteId: string, data: CreateRewriteRuleRequest) =>
    apiClient.post<RewriteRule>(`/sites/${siteId}/rewrite-rules`, data),

  update: (siteId: string, id: string, data: UpdateRewriteRuleRequest) =>
    apiClient.put<RewriteRule>(`/sites/${siteId}/rewrite-rules/${id}`, data),

  delete: (siteId: string, id: string) =>
    apiClient.delete<void>(`/sites/${siteId}/rewrite-rules/${id}`),

  toggleEnabled: (siteId: string, id: string, enabled: boolean) =>
    apiClient.put<RewriteRule>(`/sites/${siteId}/rewrite-rules/${id}`, { enabled }),

  /** Persists a new priority ordering after a drag-to-reorder. */
  reorder: (siteId: string, orderedIds: string[]) =>
    Promise.all(
      orderedIds.map((id, index) =>
        apiClient.put<RewriteRule>(`/sites/${siteId}/rewrite-rules/${id}`, {
          priority: (index + 1) * 10,
        }),
      ),
    ),
}

export const rewriteKeys = {
  all: (siteId: string) => ['sites', siteId, 'rewrite-rules'] as const,
  list: (siteId: string, query?: PaginationQuery) =>
    ['sites', siteId, 'rewrite-rules', 'list', query ?? {}] as const,
}

export default rewriteApi
