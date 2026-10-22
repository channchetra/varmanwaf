/**
 * "Dismiss this banner" state, persisted per key.
 *
 * Page-level notes (fleet summary, site list hints, topology overview) can be
 * closed with an X. The dismissal is remembered for a while - the user asked
 * for "never show again for some time or session" - so we keep a timestamp in
 * localStorage and treat the banner as closed for `ttlDays` (default 7). A
 * storage failure (private mode, quota) is swallowed: the banner still closes
 * for the current view.
 */
const PREFIX = 'varman.banner.'
const DEFAULT_TTL_DAYS = 7
const DAY_MS = 24 * 60 * 60 * 1000

export function isBannerDismissed(
  key: string,
  ttlDays = DEFAULT_TTL_DAYS,
): boolean {
  try {
    const raw = window.localStorage.getItem(PREFIX + key)
    if (!raw) return false
    const at = Number(raw)
    if (!Number.isFinite(at) || at <= 0) return false
    return Date.now() - at < ttlDays * DAY_MS
  } catch {
    return false
  }
}

export function dismissBanner(key: string): void {
  try {
    window.localStorage.setItem(PREFIX + key, String(Date.now()))
  } catch {
    // Storage unavailable: the banner still closes for this render.
  }
}

/** Forgets one banner (used by tests and by "reset hints" surfaces). */
export function resetBanner(key: string): void {
  try {
    window.localStorage.removeItem(PREFIX + key)
  } catch {
    // Nothing to do.
  }
}
