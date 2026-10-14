import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface StatItem {
  label: ReactNode
  value: ReactNode
  hint?: ReactNode
}

const columnClasses: Record<number, string> = {
  2: 'sm:grid-cols-2',
  3: 'sm:grid-cols-3',
  4: 'sm:grid-cols-2 lg:grid-cols-4',
  5: 'sm:grid-cols-3 lg:grid-cols-5',
  6: 'sm:grid-cols-3 lg:grid-cols-6',
}

/**
 * A grid of label/value tiles - the console's "stat strip" (effective
 * policy summary, telemetry readouts, posture counters). Values render in
 * the strong foreground; hints carry the unit or context.
 */
export function StatGrid({
  items,
  columns = 3,
  className,
}: {
  items: StatItem[]
  columns?: 2 | 3 | 4 | 5 | 6
  className?: string
}) {
  return (
    <dl className={cn('grid gap-3', columnClasses[columns], className)}>
      {items.map((item, index) => (
        <div
          key={index}
          className="rounded-lg border border-line bg-recessed px-3 py-2"
        >
          <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">
            {item.label}
          </dt>
          <dd className="mt-0.5 truncate text-[13px] font-medium text-fg-strong">
            {item.value}
          </dd>
          {item.hint && (
            <p className="mt-0.5 text-[11px] text-fg-subtle">{item.hint}</p>
          )}
        </div>
      ))}
    </dl>
  )
}

export default StatGrid
