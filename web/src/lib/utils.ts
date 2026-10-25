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
