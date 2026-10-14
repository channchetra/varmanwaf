import { apiClient } from './client'
import type { IpGroup } from './types'

/**
 * IP list catalog - `/api/v1/ip-lists/*`.
 *
 * The catalog lists ready-to-import sources (ipverse country / crawler /
 * ASN lists, an X4BNet VPN list, custom URLs). An import creates a normal
 * IP group subscription, so the daily sync scheduler keeps it fresh and the
 * existing site bindings apply it.
 */

export interface IpListCatalogEntry {
  id: string
  name: string
  category: 'country' | 'bot' | 'vpn' | 'asn' | 'custom' | string
  description: string
  source_url: string
  selector: string
  suggested_action: 'block' | 'allow' | string
  attribution: string
  prefix_count: number | null
  /** `false` = the list covers more than the service (prefilter only). */
  authoritative: boolean | null
}

export interface IpListCatalog {
  entries: IpListCatalogEntry[]
  notes: string[]
}

export interface IpListImportRequest {
  catalog_id?: string
  variant?: 'compact' | 'detailed'
  url?: string
  selector?: string
  name?: string
  action?: 'block' | 'allow'
  sync_interval_minutes?: number
}

export interface IpListImportView {
  group: IpGroup
  synced: boolean
  error: string | null
}

export const ipListsApi = {
  catalog: (query: { q?: string; category?: string } = {}) =>
    apiClient.get<IpListCatalog>('/ip-lists/catalog', { query }),

  import: (data: IpListImportRequest) =>
    apiClient.post<IpListImportView>('/ip-lists/import', data),
}

export const ipListKeys = {
  all: ['ip-lists'] as const,
  catalog: (query: { q?: string; category?: string } = {}) =>
    [...ipListKeys.all, 'catalog', query] as const,
}

export default ipListsApi
