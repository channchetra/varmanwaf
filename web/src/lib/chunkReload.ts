const RELOAD_KEY = 'varman:chunk-reload-at'
const RELOAD_WINDOW_MS = 10_000

/**
 * True for the errors a deployment produces when an open tab asks for a
 * hashed chunk that the new build no longer ships.
 */
export function isChunkLoadError(error: unknown): boolean {
  if (error instanceof Error) {
    const message = error.message.toLowerCase()
    return (
      error.name === 'ChunkLoadError' ||
      message.includes('failed to fetch dynamically imported module') ||
      message.includes('importing a module script failed') ||
      message.includes('loading chunk') ||
      message.includes('dynamically imported module')
    )
  }
  return (
    typeof error === 'string' &&
    error.toLowerCase().includes('dynamically imported module')
  )
}

/**
 * Reloads the page once for a stale chunk. The sessionStorage timestamp
 * stops a broken deployment from turning into a reload loop: a second
 * failure inside the window falls through to the branded error page.
 */
export function reloadOnceForChunkError(): boolean {
  try {
    const last = Number(sessionStorage.getItem(RELOAD_KEY) ?? '0')
    if (Number.isFinite(last) && Date.now() - last < RELOAD_WINDOW_MS) {
      return false
    }
    sessionStorage.setItem(RELOAD_KEY, String(Date.now()))
    window.location.reload()
    return true
  } catch {
    // Storage can be unavailable in hardened browsers; show the error page
    // rather than risk an unbounded reload loop.
    return false
  }
}
