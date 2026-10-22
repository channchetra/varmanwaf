import { useCallback, useEffect, useState } from 'react'

/**
 * Fullscreen for one element, with Escape/OS exits reflected in state.
 *
 * The topology canvas is the page: expanding it hides the console chrome so a
 * large fleet fits without zooming out. The browser may refuse (permissions,
 * iframe policy) - the toggle then stays a no-op instead of throwing.
 *
 * The host element is held in state rather than a ref so render-time reads of
 * `fullscreen` are plain values (the React Compiler lint rule forbids touching
 * ref objects while rendering). `attach` is the callback ref to spread onto
 * the element.
 */
export function useFullscreen<T extends HTMLElement>() {
  const [host, setHost] = useState<T | null>(null)
  const [fullscreen, setFullscreen] = useState(false)

  const attach = useCallback((element: T | null) => {
    setHost(element)
  }, [])

  useEffect(() => {
    const onChange = () => {
      setFullscreen(host !== null && document.fullscreenElement === host)
    }
    document.addEventListener('fullscreenchange', onChange)
    onChange()
    return () => document.removeEventListener('fullscreenchange', onChange)
  }, [host])

  const toggle = useCallback(async () => {
    if (!host) return
    try {
      if (document.fullscreenElement === host) {
        await document.exitFullscreen()
      } else {
        await host.requestFullscreen()
      }
    } catch {
      // Refused by the browser: leave the layout as it is.
    }
  }, [host])

  return { attach, fullscreen, toggle }
}
