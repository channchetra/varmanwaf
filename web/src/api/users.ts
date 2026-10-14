import { apiClient } from './client'
import type {
  CreateUserRequest,
  Page,
  PaginationQuery,
  UpdateUserRequest,
  User,
} from './types'

/**
 * Dashboard user administration - `/api/v1/users`.
 *
 * Admin-only: create accounts, assign roles and disable users. The
 * signed-in user's own profile goes through `/auth/me` instead.
 */
export const usersApi = {
  list: (query: PaginationQuery = {}) =>
    apiClient.get<Page<User>>('/users', { query: { page_size: 200, ...query } }),

  create: (data: CreateUserRequest) => apiClient.post<User>('/users', data),

  update: (id: string, data: UpdateUserRequest) =>
    apiClient.put<User>(`/users/${id}`, data),

  /**
   * Sets a temporary password: the account must replace it at first sign-in
   * and every outstanding session is revoked. One's own password stays on
   * `/auth/password` (current password required).
   */
  resetPassword: (id: string, password: string) =>
    apiClient.post<User>(`/users/${id}/reset-password`, { password }),
}

export const usersKeys = {
  all: ['users'] as const,
  list: (query?: PaginationQuery) => [...usersKeys.all, 'list', query ?? {}] as const,
}

export default usersApi
