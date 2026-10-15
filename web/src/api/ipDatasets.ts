import { apiClient } from './client'

/** A synced ipverse dataset (country or ASN ranges). */
export interface IpDataset {
  kind: 'country' | 'asn'
  key: string
  ipv4_ranges: number
  ipv6_ranges: number
  source_url: string
  synced_at: string | null
  last_error: string | null
  refresh_interval_minutes: number | null
  referenced: boolean
}

/** A key a geo policy lists, with whether its dataset exists. */
export interface ReferencedKey {
  kind: 'country' | 'asn'
  key: string
  synced: boolean
  synced_at: string | null
}

export interface IpDatasetsView {
  items: IpDataset[]
  referenced: ReferencedKey[]
}

export interface IpDatasetSyncResult {
  key: string
  synced: boolean
  ipv4_ranges: number
  ipv6_ranges: number
  error: string | null
}

export interface IpDatasetSyncResponse {
  results: IpDatasetSyncResult[]
  pushed_sites: number
}

export const ipDatasetsApi = {
  list: () => apiClient.get<IpDatasetsView>('/ip-datasets'),

  sync: (kind: 'country' | 'asn', keys: string[]) =>
    apiClient.post<IpDatasetSyncResponse>('/ip-datasets/sync', {
      kind,
      keys,
    }),

  syncReferenced: () =>
    apiClient.post<IpDatasetSyncResponse>('/ip-datasets/sync-referenced', {}),
}

export const ipDatasetsKeys = {
  all: ['ip-datasets'] as const,
  list: () => [...ipDatasetsKeys.all, 'list'] as const,
}

export default ipDatasetsApi
