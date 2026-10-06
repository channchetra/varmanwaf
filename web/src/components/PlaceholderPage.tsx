import type { ReactNode } from 'react'
import { PageHeader } from '@/components/PageHeader'
import { EmptyState } from '@/components/ui/EmptyState'
import { Button } from '@/components/ui/Button'

export interface PlaceholderPageProps {
  title: string
  description?: string
  icon: ReactNode
  emptyTitle?: string
  emptyDescription?: string
  actionLabel?: string
  onAction?: () => void
  /** Optional extra content rendered above the empty state. */
  children?: ReactNode
}

/**
 * Reusable shell for routes that share the same "title + description +
 * empty state" structure. Focus pages override this with richer content.
 */
export function PlaceholderPage({
  title,
  description,
  icon,
  emptyTitle,
  emptyDescription,
  actionLabel,
  onAction,
  children,
}: PlaceholderPageProps) {
  return (
    <div className="animate-slide-up">
      <PageHeader
        title={title}
        description={description}
        actions={
          actionLabel ? (
            <Button variant="primary" onClick={onAction}>
              {actionLabel}
            </Button>
          ) : undefined
        }
      />
      {children}
      <EmptyState
        icon={icon}
        title={emptyTitle ?? title}
        description={emptyDescription ?? description}
      />
    </div>
  )
}
