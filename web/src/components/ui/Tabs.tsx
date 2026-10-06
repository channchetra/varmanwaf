import { useState, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface TabItem {
  value: string
  label: ReactNode
  icon?: ReactNode
  content?: ReactNode
  disabled?: boolean
}

export interface TabsProps {
  items: TabItem[]
  value?: string
  defaultValue?: string
  onChange?: (value: string) => void
  variant?: 'underline' | 'pill'
  className?: string
}

export function Tabs({
  items,
  value,
  defaultValue,
  onChange,
  variant = 'underline',
  className,
}: TabsProps) {
  const isControlled = value !== undefined
  const [internal, setInternal] = useState(defaultValue ?? items[0]?.value ?? '')
  const active = isControlled ? value : internal

  const select = (v: string) => {
    if (!isControlled) setInternal(v)
    onChange?.(v)
  }

  const activeItem = items.find((i) => i.value === active)

  return (
    <div className={cn('flex flex-col', className)}>
      <div
        role="tablist"
        className={cn(
          variant === 'underline'
            ? 'flex gap-1 border-b border-line'
            : 'inline-flex w-fit gap-1 rounded-lg bg-recessed p-1',
        )}
      >
        {items.map((item) => {
          const isActive = item.value === active
          return (
            <button
              key={item.value}
              role="tab"
              type="button"
              aria-selected={isActive}
              disabled={item.disabled}
              onClick={() => select(item.value)}
              className={cn(
                'inline-flex items-center gap-2 text-sm font-medium transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50',
                variant === 'underline'
                  ? cn(
                      '-mb-px border-b-2 px-3 py-2.5',
                      isActive
                        ? 'border-brand text-fg-strong'
                        : 'border-transparent text-fg-subtle hover:text-fg',
                    )
                  : cn(
                      'rounded-md px-3 py-1.5',
                      isActive
                        ? 'bg-elevated text-fg-strong shadow-sm'
                        : 'text-fg-subtle hover:text-fg',
                    ),
              )}
            >
              {item.icon}
              {item.label}
            </button>
          )
        })}
      </div>
      {activeItem?.content !== undefined && (
        <div role="tabpanel" className="pt-4">
          {activeItem.content}
        </div>
      )}
    </div>
  )
}
