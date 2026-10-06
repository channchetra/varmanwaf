import type { ReactNode } from 'react'
import {
  CloudSlash,
  Lock,
  MagnifyingGlass,
  Warning,
  WarningOctagon,
} from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/Button'
import { classifyError, errorMessage, type ErrorKind } from '@/api/errors'
import { cn } from '@/lib/utils'

export interface ErrorStateProps {
  /** The value thrown by the query. Classified into a friendly message. */
  error: unknown
  /** Retry affordance; omit to render a read-only error panel. */
  onRetry?: () => void
  retrying?: boolean
  title?: ReactNode
  /** Overrides the classified detail line. */
  description?: ReactNode
  action?: ReactNode
  className?: string
  /** `inline` renders a compact strip instead of a centred panel. */
  variant?: 'panel' | 'inline'
}

const KIND_ICON: Record<ErrorKind, ReactNode> = {
  unauthorized: <Lock weight="duotone" className="h-6 w-6" />,
  forbidden: <Lock weight="duotone" className="h-6 w-6" />,
  not_found: <MagnifyingGlass weight="duotone" className="h-6 w-6" />,
  conflict: <Warning weight="duotone" className="h-6 w-6" />,
  validation: <Warning weight="duotone" className="h-6 w-6" />,
  server_error: <WarningOctagon weight="duotone" className="h-6 w-6" />,
  network: <CloudSlash weight="duotone" className="h-6 w-6" />,
  unknown: <WarningOctagon weight="duotone" className="h-6 w-6" />,
}

const KIND_TITLE_KEY: Record<ErrorKind, string> = {
  unauthorized: 'errors.sessionExpiredTitle',
  forbidden: 'errors.forbiddenTitle',
  not_found: 'errors.notFoundTitle',
  conflict: 'errors.conflictTitle',
  validation: 'errors.validationTitle',
  server_error: 'errors.serverErrorTitle',
  network: 'errors.networkTitle',
  unknown: 'errors.unknownTitle',
}

const KIND_HINT_KEY: Record<ErrorKind, string> = {
  unauthorized: 'errors.sessionExpiredHint',
  forbidden: 'errors.forbiddenHint',
  not_found: 'errors.notFoundHint',
  conflict: 'errors.conflictHint',
  validation: 'errors.validationHint',
  server_error: 'errors.serverErrorHint',
  network: 'errors.networkHint',
  unknown: 'errors.unknownHint',
}

/**
 * A specific, actionable failure panel.
 *
 * "Error" is never a good enough message: the control plane tells us *why* a
 * request failed (403 vs 404 vs 503 vs offline) and each of those needs a
 * different response from the operator, so we surface the distinction.
 */
export function ErrorState({
  error,
  onRetry,
  retrying = false,
  title,
  description,
  action,
  className,
  variant = 'panel',
}: ErrorStateProps) {
  const { t } = useTranslation()
  const kind = classifyError(error)
  const detail = description ?? errorMessage(error)

  const heading = title ?? t(KIND_TITLE_KEY[kind])
  const hint = t(KIND_HINT_KEY[kind])

  if (variant === 'inline') {
    return (
      <div
        role="alert"
        className={cn(
          'flex flex-wrap items-center gap-3 rounded-lg border border-danger/30 bg-danger/8 px-4 py-3 text-[13px]',
          className,
        )}
      >
        <span className="flex items-center gap-2 font-medium text-fg-danger">
          <Warning weight="fill" className="h-4 w-4 shrink-0" />
          {heading}
        </span>
        {detail && <span className="min-w-0 flex-1 truncate text-fg-subtle">{detail}</span>}
        <span className="ml-auto flex items-center gap-2">
          {action}
          {onRetry && (
            <Button size="sm" variant="secondary" loading={retrying} onClick={onRetry}>
              {t('common.retry')}
            </Button>
          )}
        </span>
      </div>
    )
  }

  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col items-center justify-center rounded-xl border border-line bg-elevated px-6 py-12 text-center',
        className,
      )}
    >
      <span className="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-danger/10 text-fg-danger">
        {KIND_ICON[kind]}
      </span>
      <h3 className="text-[15px] font-semibold text-fg-strong">{heading}</h3>
      <p className="mt-1.5 max-w-md text-[13px] leading-relaxed text-fg-subtle">{hint}</p>
      {detail && (
        <p className="pw-mono mt-3 max-w-lg break-words rounded-md bg-recessed px-3 py-2 text-xs text-fg-subtle">
          {detail}
        </p>
      )}
      {(onRetry || action) && (
        <div className="mt-5 flex items-center gap-2">
          {action}
          {onRetry && (
            <Button variant="primary" loading={retrying} onClick={onRetry}>
              {t('common.retry')}
            </Button>
          )}
        </div>
      )}
    </div>
  )
}

export default ErrorState
