import { Fragment, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { CaretRight } from '@phosphor-icons/react'
import { cn } from '@/lib/utils'

export interface BreadcrumbItem {
  label: ReactNode
  to?: string
}

export interface BreadcrumbProps {
  items: BreadcrumbItem[]
  className?: string
}

export function Breadcrumb({ items, className }: BreadcrumbProps) {
  return (
    <nav aria-label="Breadcrumb" className={cn('flex items-center', className)}>
      <ol className="flex items-center gap-1 text-[13px]">
        {items.map((item, i) => {
          const isLast = i === items.length - 1
          return (
            <Fragment key={i}>
              <li className="flex items-center">
                {item.to && !isLast ? (
                  <Link
                    to={item.to}
                    className="text-fg-subtle transition-colors hover:text-link"
                  >
                    {item.label}
                  </Link>
                ) : (
                  <span
                    className={cn(
                      isLast ? 'font-medium text-fg-strong' : 'text-fg-subtle',
                    )}
                  >
                    {item.label}
                  </span>
                )}
              </li>
              {!isLast && (
                <li aria-hidden className="text-fg-subtle/50">
                  <CaretRight weight="bold" className="h-3 w-3" />
                </li>
              )}
            </Fragment>
          )
        })}
      </ol>
    </nav>
  )
}
