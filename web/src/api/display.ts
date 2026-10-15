import { apiClient } from './client'

/** Instance display settings: the timezone the console and reports use. */
export interface DisplaySettings {
  /** IANA timezone name; `UTC` by default. */
  timezone: string
}

export const displayApi = {
  get: () => apiClient.get<DisplaySettings>('/settings/display'),

  save: (settings: DisplaySettings) =>
    apiClient.put<DisplaySettings>('/settings/display', settings),
}

export const displayKeys = {
  all: ['display'] as const,
  settings: () => [...displayKeys.all, 'settings'] as const,
}

export default displayApi
