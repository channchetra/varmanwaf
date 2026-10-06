import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from '@/lib/utils'

export type BadgeTone =
  | 'neutral'
  | 'success'
  | 'warning'
  | 'danger'
  | 'info'
  | 'brand'

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone
  /** Renders a leading status dot. */
  dot?: boolean
  size?: 'sm' | 'md'
  children?: ReactNode
}

const toneClasses: Record<BadgeTone, string> = {
  neutral: 'bg-recessed text-fg-subtle border-line',
  success: 'bg-success/12 text-fg-success border-success/30',
  warning: 'bg-warning/15 text-fg border-warning/40',
  danger: 'bg-danger/12 text-fg-danger border-danger/30',
  info: 'bg-focus/10 text-link border-focus/30',
  brand: 'bg-brand/12 text-brand border-brand/30',
}

const dotClasses: Record<BadgeTone, string> = {
  neutral: 'bg-fg-subtle',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
  info: 'bg-focus',
  brand: 'bg-brand',
}

export function Badge({
  tone = 'neutral',
  dot = false,
  size = 'md',
  className,
  children,
  ...props
}: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border font-medium whitespace-nowrap',
        size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-0.5 text-xs',
        toneClasses[tone],
        className,
      )}
      {...props}
    >
      {dot && (
        <span className={cn('h-1.5 w-1.5 rounded-full', dotClasses[tone])} aria-hidden />
      )}
      {children}
    </span>
  )
}
