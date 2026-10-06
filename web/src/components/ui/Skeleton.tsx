import type { HTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

/**
 * Loading placeholders.
 *
 * A skeleton keeps the page geometry stable while data streams in, which reads
 * far calmer than a spinner that reflows the layout on arrival. The shimmer is
 * defined once in `index.css` (`@keyframes pw-shimmer`) and respects
 * `prefers-reduced-motion` through the global rule there.
 */

export interface SkeletonProps extends HTMLAttributes<HTMLDivElement> {
  /** Convenience shorthand for a full-width block of `n` text lines. */
  lines?: number
}

export function Skeleton({ className, lines, ...props }: SkeletonProps) {
  if (lines && lines > 0) {
    return (
      <div className={cn('flex flex-col gap-2', className)} {...props} aria-hidden>
        {Array.from({ length: lines }).map((_, i) => (
          <span
            key={i}
            className="pw-skeleton block h-3 rounded"
            // Stagger the widths so a paragraph does not look like a barcode.
            style={{ width: i === lines - 1 ? '62%' : `${88 - (i % 3) * 11}%` }}
          />
        ))}
      </div>
    )
  }
  return <div className={cn('pw-skeleton rounded-md', className)} aria-hidden {...props} />
}

/** Card-shaped placeholder matching `Card` + `CardHeader` + `CardBody`. */
export function SkeletonCard({ className }: { className?: string }) {
  return (
    <div
      className={cn('rounded-xl border border-line bg-elevated', className)}
      aria-hidden
    >
      <div className="border-b border-line px-5 py-4">
        <Skeleton className="h-4 w-32" />
      </div>
      <div className="space-y-3 px-5 py-4">
        <Skeleton lines={3} />
      </div>
    </div>
  )
}

/** Row-shaped placeholder matching a dense `Table` body. */
export function SkeletonRows({
  rows = 5,
  columns = 4,
  className,
}: {
  rows?: number
  columns?: number
  className?: string
}) {
  return (
    <div className={cn('flex flex-col', className)} aria-hidden>
      {Array.from({ length: rows }).map((_, r) => (
        <div
          key={r}
          className="grid gap-4 border-b border-line px-4 py-3 last:border-b-0"
          style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}
        >
          {Array.from({ length: columns }).map((_, c) => (
            <Skeleton key={c} className="h-3.5 w-full" />
          ))}
        </div>
      ))}
    </div>
  )
}

/** Stat-tile placeholder used by the dashboard hero row. */
export function SkeletonStat({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'rounded-xl border border-line bg-elevated px-5 py-4',
        className,
      )}
      aria-hidden
    >
      <Skeleton className="h-3 w-24" />
      <Skeleton className="mt-3 h-7 w-20" />
      <Skeleton className="mt-3 h-3 w-16" />
    </div>
  )
}
