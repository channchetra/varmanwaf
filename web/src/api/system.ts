import { apiClient } from './client'
import type { HealthResponse, VersionResponse } from './types'

/** Unauthenticated liveness/build metadata endpoints. */
export const systemApi = {
  health: () => apiClient.get<HealthResponse>('/health', { skipAuth: true }),
  version: () => apiClient.get<VersionResponse>('/version', { skipAuth: true }),
}

export default systemApi
