export type ReportPreset = '24h' | '7d' | '30d' | '90d' | 'custom'

export const REPORT_PRESETS: Exclude<ReportPreset, 'custom'>[] = [
  '24h',
  '7d',
  '30d',
  '90d',
]

const DAY_MS = 24 * 60 * 60 * 1000

/** The last `days` days as `YYYY-MM-DD` (UTC) bounds, inclusive of today. */
export function rangeDays(
  days: number,
  now: Date = new Date(),
): { from: string; to: string } {
  const format = (value: Date) => value.toISOString().slice(0, 10)
  return {
    from: format(new Date(now.getTime() - days * DAY_MS)),
    to: format(now),
  }
}

/** Preset → query bounds; `custom` has none (the caller supplies dates). */
export function rangeForPreset(
  preset: ReportPreset,
  now: Date = new Date(),
): { from: string; to: string } | null {
  switch (preset) {
    case '24h':
      return rangeDays(1, now)
    case '7d':
      return rangeDays(7, now)
    case '30d':
      return rangeDays(30, now)
    case '90d':
      return rangeDays(90, now)
    case 'custom':
      return null
  }
}
