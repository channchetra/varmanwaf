import { create } from 'zustand'

export type ThemeMode = 'light' | 'dark' | 'system'
export type ResolvedTheme = 'light' | 'dark'

const STORAGE_KEY = 'pingwaf.theme'

function getSystemTheme(): ResolvedTheme {
  if (typeof window === 'undefined' || !window.matchMedia) return 'light'
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function resolve(mode: ThemeMode): ResolvedTheme {
  return mode === 'system' ? getSystemTheme() : mode
}

function readInitial(): ThemeMode {
  if (typeof localStorage === 'undefined') return 'system'
  const stored = localStorage.getItem(STORAGE_KEY) as ThemeMode | null
  return stored === 'light' || stored === 'dark' || stored === 'system' ? stored : 'system'
}

function applyTheme(resolved: ResolvedTheme) {
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('data-theme', resolved)
}

interface ThemeState {
  mode: ThemeMode
  resolved: ResolvedTheme
  setMode: (mode: ThemeMode) => void
  toggle: () => void
  syncSystem: () => void
}

const initialMode = readInitial()

export const useThemeStore = create<ThemeState>((set, get) => {
  // Apply the initial theme immediately.
  applyTheme(resolve(initialMode))

  return {
    mode: initialMode,
    resolved: resolve(initialMode),
    setMode: (mode) => {
      const resolved = resolve(mode)
      localStorage.setItem(STORAGE_KEY, mode)
      applyTheme(resolved)
      set({ mode, resolved })
    },
    toggle: () => {
      const next: ThemeMode = get().resolved === 'dark' ? 'light' : 'dark'
      get().setMode(next)
    },
    syncSystem: () => {
      if (get().mode !== 'system') return
      const resolved = getSystemTheme()
      applyTheme(resolved)
      set({ resolved })
    },
  }
})

// Listen for OS theme changes when in "system" mode.
if (typeof window !== 'undefined' && window.matchMedia) {
  window
    .matchMedia('(prefers-color-scheme: dark)')
    .addEventListener('change', () => useThemeStore.getState().syncSystem())
}
