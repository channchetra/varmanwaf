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
  country: string | null
  asn: number | null
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
