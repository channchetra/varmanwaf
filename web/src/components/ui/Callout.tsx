import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

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
  className?: string
}

export function Callout({
  tone = 'brand',
  icon,
  title,
  children,
  actions,
  className,
}: CalloutProps) {
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
    </div>
  )
}

export default Callout
