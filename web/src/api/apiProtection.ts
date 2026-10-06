import { apiClient } from './client'
import type {
  ApiProtectionView,
  ControlPlaneAccessLog,
  ControlPlaneLogQuery,
  DefenseSettings,
  Page,
  UpdateApiProtectionRequest,
} from './types'

/**
 * The control plane's own protection — `/api/v1/settings/api-protection`,
 * `/api/v1/logs/control-plane` and `/api/v1/settings/defense`.
 *
 * These endpoints are administrators-only and describe the 9080 listener
 * itself: every write rebuilds the in-process policy immediately, so the next
 * request already sees the change. A write that would enable the allowlist
 * without covering the calling connection is refused with a 422 unless
 * `force` is set — surface the returned message instead of swallowing it.
 *
 * The observation mode flag lives apart because it steers the data plane
 * (agents), not the control plane: it rides inside every rule bundle and is
 * pushed to the agents on the next configuration sync.
 */
export const apiProtectionApi = {
  get: () => apiClient.get<ApiProtectionView>('/settings/api-protection'),

  update: (payload: UpdateApiProtectionRequest) =>
    apiClient.put<ApiProtectionView>('/settings/api-protection', payload),

  logs: (query: ControlPlaneLogQuery = {}) =>
    apiClient.get<Page<ControlPlaneAccessLog>>('/logs/control-plane', { query }),

  getDefense: () => apiClient.get<DefenseSettings>('/settings/defense'),

  updateDefense: (observation_mode: boolean) =>
    apiClient.put<DefenseSettings>('/settings/defense', { observation_mode }),
}

export const apiProtectionKeys = {
  all: ['api-protection'] as const,
  settings: () => [...apiProtectionKeys.all, 'settings'] as const,
  logs: (query: ControlPlaneLogQuery) =>
    [...apiProtectionKeys.all, 'logs', query] as const,
  defense: () => [...apiProtectionKeys.all, 'defense'] as const,
}

export default apiProtectionApi
