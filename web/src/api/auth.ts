import { apiClient } from './client'
import { useAuthStore } from '@/stores/authStore'
import type {
  AuthStatus,
  ChangePasswordRequest,
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  UpdateProfileRequest,
  User,
} from './types'

export const authApi = {
  /** Bootstrap probe: does the console need a first account? */
  status: () => apiClient.get<AuthStatus>('/auth/status', { skipAuth: true }),

  login: (data: LoginRequest) =>
    apiClient.post<LoginResponse>('/auth/login', data, { skipAuth: true }),

  register: (data: RegisterRequest) =>
    apiClient.post<LoginResponse>('/auth/register', data, { skipAuth: true }),

  /** Silent session extension using the persisted refresh token. */
  refresh: (refreshToken: string) =>
    apiClient.post<LoginResponse>('/auth/refresh', { refresh_token: refreshToken }, { skipAuth: true }),

  me: () => apiClient.get<User>('/auth/me'),

  updateProfile: (data: UpdateProfileRequest) => apiClient.put<User>('/auth/me', data),

  // Answers 204; a wrong current password is a 400 the form renders inline.
  changePassword: (data: ChangePasswordRequest) =>
    apiClient.put<void>('/auth/password', data),
}

/**
 * Validates a persisted session on app load.
 *
 * A token in `localStorage` only proves the user logged in *at some point*; the
 * access token may have expired while the tab was closed. We optimistically
 * render the authenticated shell (so there is no flash of the login page) and
 * then confirm with `/auth/me`. The API client transparently refreshes an
 * expired access token, so this only logs out when the refresh token is dead
 * too — in which case `RequireAuth` redirects to `/login`.
 */
export async function bootstrapSession(): Promise<boolean> {
  const store = useAuthStore.getState()
  if (!store.token) {
    store.setInitialized(true)
    return false
  }
  try {
    const user = await authApi.me()
    useAuthStore.getState().setUser(user)
    useAuthStore.getState().setInitialized(true)
    return true
  } catch (err: unknown) {
    // Only clear the session on a definitive auth rejection (401/403).
    // A network error means the server is temporarily unreachable — the token
    // may still be valid, so we keep the session and let the pages show their
    // own error states.
    const isAuthFailure =
      err instanceof Error &&
      'status' in err &&
      ((err as { status: number }).status === 401 || (err as { status: number }).status === 403)
    if (isAuthFailure) {
      useAuthStore.getState().logout()
    }
    useAuthStore.getState().setInitialized(true)
    return !isAuthFailure
  }
}

export default authApi
