import type { ConfigVersionSummary } from '@/api/configVersions'

/** Totals behind the list's summary column: tables captured and rows in them. */
export function summaryTotals(
  summary: Record<string, number> | null | undefined,
): { tables: number; rows: number } {
  if (!summary) return { tables: 0, rows: 0 }
  const values = Object.values(summary)
  return {
    tables: values.length,
    rows: values.reduce((total, count) => total + count, 0),
  }
}

/**
 * The per-table counts as rows sorted by size, for the detail dialog.
 * `limit` trims the tail and reports how many tables were omitted.
 */
export function summaryRows(
  summary: Record<string, number> | null | undefined,
  limit?: number,
): { name: string; count: number }[] {
  if (!summary) return []
  const rows = Object.entries(summary)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
  return limit === undefined ? rows : rows.slice(0, limit)
}

/** A version's scope label: the site name/domain, or the deployment-wide one. */
export function scopeLabel(
  version: Pick<ConfigVersionSummary, 'site_id' | 'site_domain'>,
  siteName?: string,
): string {
  if (!version.site_id) return 'global'
  return siteName || version.site_domain || version.site_id
}
