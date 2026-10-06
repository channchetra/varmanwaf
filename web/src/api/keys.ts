import { apiClient } from './client'
import type { ApiKey, CreateApiKeyRequest, Page, PaginationQuery } from './types'

/**
 * API keys — `/api/v1/keys`.
 *
 * Keys authenticate agents and automation. The plaintext value (`pwk_…`) is
 * returned exactly once, by `POST /keys`; afterwards only `key_prefix` survives.
 */
export const keysApi = {
  list: (query: PaginationQuery = {}) =>
    apiClient.get<Page<ApiKey>>('/keys', { query: { page_size: 200, ...query } }),

  create: (data: CreateApiKeyRequest) => apiClient.post<ApiKey>('/keys', data),

  revoke: (id: string) => apiClient.delete<void>(`/keys/${id}`),
}

export const KEY_PERMISSIONS = ['agent', 'read', 'write'] as const

export const keyKeys = {
  all: ['keys'] as const,
  list: (query?: PaginationQuery) => [...keyKeys.all, 'list', query ?? {}] as const,
}

export default keysApi
