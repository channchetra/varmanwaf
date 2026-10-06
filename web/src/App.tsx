import { useEffect } from 'react'
import {
  MutationCache,
  QueryCache,
  QueryClient,
  QueryClientProvider,
} from '@tanstack/react-query'
import { RouterProvider } from 'react-router-dom'
import { router } from '@/router'
import { ToastProvider } from '@/components/ui/Toast'
import { bootstrapSession } from '@/api/auth'
import { handleApiError, shouldRetry } from '@/api/errors'

/**
 * One client for the whole console.
 *
 * - `staleTime: 30s` — the dashboard polls on the same cadence, so switching
 *   tabs should not stampede the API.
 * - `retry: shouldRetry` — transient failures (offline, 5xx) are retried twice;
 *   a 4xx will keep failing, so retrying only delays the error state.
 * - Errors are routed through `handleApiError`, which classifies them and
 *   raises a toast over the shared notice bus.
 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30 * 1000,
      gcTime: 5 * 60 * 1000,
      retry: shouldRetry,
      refetchOnWindowFocus: true,
      refetchOnReconnect: true,
    },
    mutations: {
      retry: false,
    },
  },
  queryCache: new QueryCache({
    onError: (error, query) => {
      // First-load failures are rendered inline by the page (`<ErrorState>`),
      // so only shout about a background refresh that broke a working view.
      const hadData = query.state.data !== undefined
      const silent = query.meta?.silentToast === true || !hadData
      handleApiError(error, { silent })
    },
  }),
  mutationCache: new MutationCache({
    onError: (error, _variables, _context, mutation) => {
      // A mutation may opt out by setting `meta.silentToast` and rendering its
      // own inline validation message instead.
      handleApiError(error, { silent: mutation.meta?.silentToast === true })
    },
  }),
})

export default function App() {
  // Validate a persisted session once, on boot. `RequireAuth` trusts the stored
  // token immediately so there is no login-page flash on a hard reload.
  useEffect(() => {
    void bootstrapSession()
  }, [])

  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <RouterProvider router={router} />
      </ToastProvider>
    </QueryClientProvider>
  )
}
