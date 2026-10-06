import { forwardRef, useId, type ReactNode, type SelectHTMLAttributes } from 'react'
import { CaretDown } from '@phosphor-icons/react'
import { cn } from '@/lib/utils'

export interface SelectOption {
  label: string
  value: string
  disabled?: boolean
}

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: ReactNode
  hint?: ReactNode
  error?: ReactNode
  options?: SelectOption[]
  containerClassName?: string
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  (
    { label, hint, error, options, containerClassName, className, id, children, ...props },
    ref,
  ) => {
    const generatedId = useId()
    const selectId = id ?? generatedId

    return (
      <div className={cn('flex flex-col gap-1.5', containerClassName)}>
        {label && (
          <label htmlFor={selectId} className="text-[13px] font-medium text-fg-subtle">
            {label}
          </label>
        )}
        <div className="relative">
          <select
            ref={ref}
            id={selectId}
            aria-invalid={error ? true : undefined}
            className={cn(
              'h-9 w-full appearance-none rounded-md border bg-elevated pl-3 pr-9 text-sm text-fg',
              'transition-[border-color,box-shadow] duration-150',
              'focus:border-focus focus:outline-none focus:ring-2 focus:ring-focus/25',
              'disabled:cursor-not-allowed disabled:opacity-60',
              error ? 'border-danger' : 'border-line',
              className,
            )}
            {...props}
          >
            {options
              ? options.map((opt) => (
                  <option key={opt.value} value={opt.value} disabled={opt.disabled}>
                    {opt.label}
                  </option>
                ))
              : children}
          </select>
          <CaretDown
            weight="bold"
            className="pointer-events-none absolute right-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-fg-subtle"
          />
        </div>
        {error ? (
          <p className="text-xs text-fg-danger">{error}</p>
        ) : hint ? (
          <p className="text-xs text-fg-subtle">{hint}</p>
        ) : null}
      </div>
    )
  },
)

Select.displayName = 'Select'
