import { useState, type ReactNode } from 'react'
import { X } from '@phosphor-icons/react'
import { cn } from '@/lib/utils'
import { dismissBanner, isBannerDismissed } from '@/lib/banners'

export type CalloutTone =
  | 'brand'
  | 'info'
  | 'warning'
  | 'danger'
  | 'success'
  | 'neutral'

/**
 * The console's single "box" primitive: a message box with an icon, a title
 * and body text, tinted by tone. Page overviews use `brand` (the product
 * accent), operational notes `info`, cautions `warning`, failures `danger`.
 *
 * A page-level note can pass `dismissKey`: it then renders a close button and
 * remembers the dismissal for a week (see `lib/banners`). Alerts that carry a
 * live state (a disabled TLS listener, an expiring certificate) should not be
 * dismissible - the operator needs them until the state changes.
 */
const toneClasses: Record<CalloutTone, string> = {
  brand: 'border-brand/30 bg-brand/8',
  info: 'border-focus/30 bg-focus/5',
  warning: 'border-warning/40 bg-warning/10',
  danger: 'border-danger/40 bg-danger/8',
  success: 'border-success/40 bg-success/10',
  neutral: 'border-line bg-recessed/60',
}

const iconClasses: Record<CalloutTone, string> = {
  brand: 'text-brand',
  info: 'text-link',
  warning: 'text-fg',
  danger: 'text-fg-danger',
  success: 'text-fg-success',
  neutral: 'text-fg-subtle',
}

export interface CalloutProps {
  tone?: CalloutTone
  /** Leading icon; sized by the caller (h-4/h-5). */
  icon?: ReactNode
  title?: ReactNode
  children?: ReactNode
  /** Trailing actions (a link or button). */
  actions?: ReactNode
  /**
   * Makes the note closable and remembers the choice for a week. Use only for
   * informational notes, never for live warnings.
   */
  dismissKey?: string
  /** Accessible label for the close button. */
  dismissLabel?: string
  className?: string
}

export function Callout({
  tone = 'brand',
  icon,
  title,
  children,
  actions,
  dismissKey,
  dismissLabel = 'Dismiss',
  className,
}: CalloutProps) {
  const [closed, setClosed] = useState(false)
  if (dismissKey && (closed || isBannerDismissed(dismissKey))) {
    return null
  }
  return (
    <div
      role="note"
      className={cn(
        'flex items-start gap-3 rounded-xl border px-4 py-3',
        toneClasses[tone],
        className,
      )}
    >
      {icon && (
        <span className={cn('mt-0.5 shrink-0', iconClasses[tone])}>{icon}</span>
      )}
      <div className="min-w-0 flex-1 space-y-1">
        {title && (
          <p className="text-[13px] font-semibold text-fg-strong">{title}</p>
        )}
        {children && (
          <div className="text-[13px] leading-relaxed text-fg-subtle">
            {children}
          </div>
        )}
      </div>
      {actions && <div className="shrink-0">{actions}</div>}
      {dismissKey && (
        <button
          type="button"
          aria-label={dismissLabel}
          title={dismissLabel}
          className="-mr-1 -mt-1 shrink-0 rounded-md p-1 text-fg-subtle transition-colors hover:bg-black/10 hover:text-fg focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-brand"
          onClick={() => {
            setClosed(true)
            dismissBanner(dismissKey)
          }}
        >
          <X weight="bold" className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  )
}

export default Callout
