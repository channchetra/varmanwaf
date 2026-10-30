import { useEffect, useState } from 'react'
import { isRouteErrorResponse, useRouteError } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ErrorState } from '@/components/ErrorState'
import { Button } from '@/components/ui/Button'
import { isChunkLoadError, reloadOnceForChunkError } from '@/lib/chunkReload'

/**
 * Route-level fallback. The common real-world case is a tab opened before a
 * deployment: its hashed lazy chunk no longer exists. Reloading once pulls
 * the new index and chunks; if that fails too, show a branded retry panel
 * instead of React Router's developer screen.
 */
export function RouteErrorPage() {
  const { t } = useTranslation()
  const error = useRouteError()
  const chunkError = isChunkLoadError(error)
  const [reloading, setReloading] = useState(chunkError)

  useEffect(() => {
    if (!chunkError) {
      setReloading(false)
      return
    }
    setReloading(reloadOnceForChunkError())
  }, [chunkError])

  if (reloading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-canvas text-sm text-fg-subtle">
        {t('common.loading')}
      </div>
    )
  }

  const title = chunkError ? t('errors.staleBuildTitle') : undefined
  const description = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : chunkError
      ? t('errors.staleBuildHint')
      : undefined

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas p-6">
      <div className="w-full max-w-xl">
        <ErrorState
          error={error}
          title={title}
          description={description}
          action={
            <Button variant="primary" onClick={() => window.location.reload()}>
              {t('common.reload')}
            </Button>
          }
        />
      </div>
    </div>
  )
}
