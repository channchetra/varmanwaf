import { apiClient } from './client'
import type {
  BulkImportIpRequest,
  CreateIpRuleRequest,
  IpRule,
  Page,
  PaginationQuery,
  UpdateIpRuleRequest,
} from './types'

/**
 * IP access rules — `/api/v1/sites/{siteId}/ip-rules`.
 *
 * Allow / block / challenge traffic from an explicit IP/CIDR list or by
 * referencing an IP group. Rules are evaluated before the WAF, so an explicit
 * allow short-circuits everything downstream.
 */
export const ipRulesApi = {
  list: (siteId: string, query: PaginationQuery = {}) =>
    apiClient.get<Page<IpRule>>(`/sites/${siteId}/ip-rules`, {
      query: { page_size: 200, ...query },
    }),

  create: (siteId: string, data: CreateIpRuleRequest) =>
    apiClient.post<IpRule>(`/sites/${siteId}/ip-rules`, data),

  update: (siteId: string, id: string, data: UpdateIpRuleRequest) =>
    apiClient.put<IpRule>(`/sites/${siteId}/ip-rules/${id}`, data),

  delete: (siteId: string, id: string) =>
    apiClient.delete<void>(`/sites/${siteId}/ip-rules/${id}`),

  toggleEnabled: (siteId: string, id: string, enabled: boolean) =>
    ipRulesSafePut(siteId, id, { enabled }),

  bulkImport: (siteId: string, data: BulkImportIpRequest) =>
    apiClient.post<{ id: string; imported: number }>(
      `/sites/${siteId}/ip-rules/bulk`,
      data,
    ),
}

/** Kept separate so `toggleEnabled` reads cleanly at the call site. */
function ipRulesSafePut(siteId: string, id: string, data: UpdateIpRuleRequest) {
  return apiClient.put<IpRule>(`/sites/${siteId}/ip-rules/${id}`, data)
}

/* ────────────────────────────────────────────────────────────────
   Validation
   ──────────────────────────────────────────────────────────────── */

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/** True for a dotted-quad with every octet in 0..255. */
export function isValidIpv4(value: string): boolean {
  const m = IPV4_RE.exec(value.trim())
  if (!m) return false
  return [m[1], m[2], m[3], m[4]].every((oct) => {
    const n = Number(oct)
    return Number.isInteger(n) && n >= 0 && n <= 255
  })
}

/** True for any IPv6 address (best-effort: colon-separated hex groups). */
export function isValidIpv6(value: string): boolean {
  const v = value.trim()
  if (!v.includes(':')) return false
  // Allow the `::` shorthand and up to 8 groups of 1-4 hex digits.
  const groups = v.split(':')
  if (groups.length < 3 || groups.length > 8) return false
  let seenDoubleColon = false
  for (const g of groups) {
    if (g === '') {
      // Leading/trailing/compressed empties are only valid around `::`.
      seenDoubleColon = true
      continue
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return false
  }
  return seenDoubleColon || groups.length === 8
}

/**
 * Validates a single address or CIDR range. Returns `null` when valid, or a
 * short reason string the form can surface.
 */
export function validateIpCidr(value: string): string | null {
  const v = value.trim()
  if (!v) return 'empty'
  const [addr, prefix, ...rest] = v.split('/')
  if (rest.length > 0) return 'malformed'
  if (prefix !== undefined) {
    const bits = Number(prefix)
    const isV6 = addr.includes(':')
    const max = isV6 ? 128 : 32
    if (!Number.isInteger(bits) || bits < 0 || bits > max) return 'prefix'
    if (isV6 ? !isValidIpv6(addr) : !isValidIpv4(addr)) return 'address'
    return null
  }
  if (isValidIpv4(addr) || isValidIpv6(addr)) return null
  return 'address'
}

/** Splits a bulk-import textarea into unique, valid IP/CIDR entries. */
export function parseIpList(raw: string): { valid: string[]; invalid: string[] } {
  const valid: string[] = []
  const invalid: string[] = []
  const seen = new Set<string>()
  for (const line of raw.split(/[\n,;]/)) {
    const entry = line.trim()
    if (!entry) continue
    if (seen.has(entry)) continue
    seen.add(entry)
    if (validateIpCidr(entry) === null) valid.push(entry)
    else invalid.push(entry)
  }
  return { valid, invalid }
}

export const ipRuleKeys = {
  all: (siteId: string) => ['sites', siteId, 'ip-rules'] as const,
  list: (siteId: string, query?: PaginationQuery) =>
    ['sites', siteId, 'ip-rules', 'list', query ?? {}] as const,
}

export default ipRulesApi
