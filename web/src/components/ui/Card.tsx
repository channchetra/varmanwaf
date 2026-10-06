import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode
  /** Adds a subtle hover lift — useful for clickable cards. */
  interactive?: boolean
  padded?: boolean
}

export function Card({
  className,
  children,
  interactive = false,
  padded = false,
  ...props
}: CardProps) {
  return (
    <div
      className={cn(
        'rounded-lg border border-line bg-elevated shadow-sm',
        padded && 'p-5',
        interactive &&
          'transition-[box-shadow,transform,border-color] duration-150 hover:-translate-y-0.5 hover:border-fill hover:shadow-md',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}

export interface CardHeaderProps extends Omit<HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: ReactNode
  description?: ReactNode
  action?: ReactNode
}

export function CardHeader({
  className,
  title,
  description,
  action,
  children,
  ...props
}: CardHeaderProps) {
  return (
    <div
      className={cn(
        'flex items-start justify-between gap-4 border-b border-line px-5 py-4',
        className,
      )}
      {...props}
    >
      {children ?? (
        <div className="min-w-0">
          {title && (
            <h3 className="truncate text-[15px] font-semibold text-fg-strong">{title}</h3>
          )}
          {description && (
            <p className="mt-0.5 text-[13px] leading-relaxed text-fg-subtle">
              {description}
            </p>
          )}
        </div>
      )}
      {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
    </div>
  )
}

export function CardBody({ className, children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn('px-5 py-4', className)} {...props}>
      {children}
    </div>
  )
}

export function CardFooter({ className, children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'flex items-center justify-end gap-2 border-t border-line px-5 py-3',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}
