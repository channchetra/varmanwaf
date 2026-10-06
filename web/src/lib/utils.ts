/**
 * Minimal class-name composer (no external deps).
 * Accepts strings, falsy values and objects of { className: boolean }.
 */
export type ClassValue =
  | string
  | number
  | null
  | undefined
  | false
  | Record<string, boolean | null | undefined>

export function cn(...inputs: ClassValue[]): string {
  const out: string[] = []
  for (const input of inputs) {
    if (!input) continue
    if (typeof input === 'string' || typeof input === 'number') {
      out.push(String(input))
    } else if (typeof input === 'object') {
      for (const [key, val] of Object.entries(input)) {
        if (val) out.push(key)
      }
    }
  }
  return out.join(' ')
}

/** Format bytes into a human readable string. */
export function formatBytes(bytes: number, decimals = 1): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1)
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`
}

/** Format a compact number (1200 -> 1.2K). */
export function formatCompact(value: number): string {
  return new Intl.NumberFormat('en', { notation: 'compact' }).format(value)
}
