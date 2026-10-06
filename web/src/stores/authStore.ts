import { create } from 'zustand'
import type { User } from '@/api/types'

const TOKEN_KEY = 'pingwaf.token'
const REFRESH_KEY = 'pingwaf.refreshToken'
const USER_KEY = 'pingwaf.user'

function read<T>(key: string, parse: (raw: string) => T): T | null {
  if (typeof localStorage === 'undefined') return null
  const raw = localStorage.getItem(key)
  if (!raw) return null
  try {
    return parse(raw)
  } catch {
    return null
  }
}

export interface AuthState {
  /** Access token (JWT). Persisted so a reload keeps the session. */
  token: string | null
  /** Long-lived refresh token used for silent session extension. */
  refreshToken: string | null
  user: User | null
  isAuthenticated: boolean
  /** Flipped once the stored token has been validated against `/auth/me`. */
  initialized: boolean

  login: (token: string, user: User, refreshToken?: string | null) => void
  setTokens: (token: string, refreshToken?: string | null) => void
  setUser: (user: User) => void
  setInitialized: (value: boolean) => void
  logout: () => void
}

const initialToken = read<string>(TOKEN_KEY, (raw) => raw)
const initialRefresh = read<string>(REFRESH_KEY, (raw) => raw)
const initialUser = read<User>(USER_KEY, (raw) => JSON.parse(raw) as User)

export const useAuthStore = create<AuthState>((set) => ({
  token: initialToken,
  refreshToken: initialRefresh,
  user: initialUser,
  // Optimistic: the router trusts a persisted token, `bootstrapSession()` then
  // confirms it (and logs out if the server rejects it).
  isAuthenticated: Boolean(initialToken),
  initialized: false,

  login: (token, user, refreshToken) => {
    try {
      localStorage.setItem(TOKEN_KEY, token)
      if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken)
      localStorage.setItem(USER_KEY, JSON.stringify(user))
    } catch {
      /* storage full / private mode — keep the session in memory only */
    }
    set({
      token,
      refreshToken: refreshToken ?? null,
      user,
      isAuthenticated: true,
      initialized: true,
    })
  },

  setTokens: (token, refreshToken) => {
    try {
      localStorage.setItem(TOKEN_KEY, token)
      if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken)
    } catch {
      /* ignore */
    }
    set((state) => ({
      token,
      refreshToken: refreshToken ?? state.refreshToken,
      isAuthenticated: true,
    }))
  },

  setUser: (user) => {
    try {
      localStorage.setItem(USER_KEY, JSON.stringify(user))
    } catch {
      /* ignore */
    }
    set({ user })
  },

  setInitialized: (value) => set({ initialized: value }),

  logout: () => {
    try {
      localStorage.removeItem(TOKEN_KEY)
      localStorage.removeItem(REFRESH_KEY)
      localStorage.removeItem(USER_KEY)
    } catch {
      /* ignore */
    }
    set({
      token: null,
      refreshToken: null,
      user: null,
      isAuthenticated: false,
      initialized: true,
    })
  },
}))

/** Non-reactive accessors for use inside the API client. */
export function getAuthToken(): string | null {
  return useAuthStore.getState().token
}

export function getRefreshToken(): string | null {
  return useAuthStore.getState().refreshToken
}

/** True when the signed-in account may perform write operations. */
export function canWrite(): boolean {
  const user = useAuthStore.getState().user
  return user?.role === 'admin'
}
