import { apiClient } from './client'

/** Why an address would be allowed or blocked, from the stored config. */
export interface IpAnalysisVerdict {
  /** `pass`, `allow`, `block`, `challenge`, `basic_auth` or `monitor`. */
  action: string
  /** Which layer decided: `ip_rule`, `group`, `geo` or `none`. */
  decided_by: string
  /** Observation mode is on: the decision is recorded, not enforced. */
  observed: boolean
}

export interface IpAnalysisGeo {
  enabled: boolean
  mode: string
  action: string
  matched: boolean
  reason: string
  /** Where the enforcement data comes from: always `ipverse`. */
  source: string
  /** False when a listed country/ASN has no synced dataset. */
  synced: boolean
  /** Listed keys whose dataset is missing: not enforced until synced. */
  missing_keys: string[]
}

export interface IpAnalysisRule {
  id: string
  name: string
  action: string
  /** `site` (an IP access rule) or `group` (an IP group). */
  source: string
}

export interface IpAnalysisGroup {
  id: string
  name: string
  action: string
  matched: boolean
}

export interface IpAnalysis {
  ip: string
  /** Display label from the built-in table (not used for enforcement). */
  country: string | null
  /** Blocked ASNs whose synced ranges contain the address. */
  asn_matches: string[]
  geo: IpAnalysisGeo
  ip_rule: IpAnalysisRule | null
  groups: IpAnalysisGroup[]
  verdict: IpAnalysisVerdict
  /** What the analysis cannot see, stated instead of guessed. */
  limitations: string[]
}

export const ipAnalysisApi = {
  analyze: (siteId: string, ip: string) =>
    apiClient.get<IpAnalysis>(
      `/sites/${siteId}/ip-analysis?ip=${encodeURIComponent(ip)}`,
    ),
}

export default ipAnalysisApi
