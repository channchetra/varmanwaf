import { apiClient } from './client'

/** Control-plane login anomaly detection settings. */
export interface LoginSecuritySettings {
  /** Run the country-baseline check on password logins. */
  anomaly_enabled: boolean
  /** How many recent resolved logins form the baseline. */
  baseline_count: number
  /** Forwarding header trusted for the client IP; null = TCP peer only. */
  trusted_header: string | null
  /** Use the last header hop (closest proxy) instead of the first. */
  trust_last_hop: boolean
  /** Online geo API template; `{ip}` is replaced with the address. */
  online_geo_url: string
  /** Prefer the uploaded mmdb over the online API. */
  geoip_local_enabled: boolean
}

export type LoginSecurityInput = Partial<LoginSecuritySettings>

/** One row of the login audit history. */
export interface LoginHistoryEntry {
  id: string
  user_id: string
  email: string
  ip: string
  user_agent: string | null
  country_code: string | null
  region: string | null
  city: string | null
  geo_source: 'local' | 'online' | 'private' | 'unknown'
  created_at: string
}

export const loginSecurityApi = {
  getSettings: () =>
    apiClient.get<LoginSecuritySettings>('/login-security'),

  saveSettings: (payload: LoginSecurityInput) =>
    apiClient.put<LoginSecuritySettings>('/login-security', payload),

  /** Uploads a MaxMind-format mmdb; validated server-side before it
   * replaces the previous database. */
  uploadGeoip: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return apiClient.post<{ uploaded: boolean; bytes: number }>(
      '/login-security/geoip',
      form,
    )
  },

  listHistory: (limit = 50, offset = 0, email?: string) => {
    const params = new URLSearchParams()
    params.set('limit', String(limit))
    params.set('offset', String(offset))
    if (email) params.set('email', email)
    return apiClient.get<LoginHistoryEntry[]>(
      `/login-history?${params.toString()}`,
    )
  },
}

export default loginSecurityApi
