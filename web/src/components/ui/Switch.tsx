import { forwardRef, useId, useState, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface SwitchProps {
  checked?: boolean
  defaultChecked?: boolean
  onCheckedChange?: (checked: boolean) => void
  disabled?: boolean
  label?: ReactNode
  description?: ReactNode
  size?: 'sm' | 'md'
  className?: string
  id?: string
}

export const Switch = forwardRef<HTMLButtonElement, SwitchProps>(
  (
    {
      checked,
      defaultChecked = false,
      onCheckedChange,
      disabled = false,
      label,
      description,
      size = 'md',
      className,
      id,
    },
    ref,
  ) => {
    const generatedId = useId()
    const switchId = id ?? generatedId
    const isControlled = checked !== undefined
    const [internal, setInternal] = useState(defaultChecked)
    const isOn = isControlled ? checked : internal

    const dims =
      size === 'sm'
        ? { track: 'h-5 w-9', thumb: 'h-4 w-4', translate: 'translate-x-4' }
        : { track: 'h-6 w-11', thumb: 'h-5 w-5', translate: 'translate-x-5' }

    const toggle = () => {
      if (disabled) return
      const next = !isOn
      if (!isControlled) setInternal(next)
      onCheckedChange?.(next)
    }

    const control = (
      <button
        ref={ref}
        id={switchId}
        type="button"
        role="switch"
        aria-checked={isOn}
        disabled={disabled}
        onClick={toggle}
        className={cn(
          'relative inline-flex shrink-0 items-center rounded-full border transition-colors duration-200',
          dims.track,
          isOn ? 'border-transparent bg-brand' : 'border-line bg-fill',
          disabled && 'cursor-not-allowed opacity-50',
        )}
      >
        <span
          className={cn(
            'pointer-events-none absolute left-0.5 inline-block rounded-full bg-white shadow-sm transition-transform duration-200',
            dims.thumb,
            isOn ? dims.translate : 'translate-x-0',
          )}
        />
      </button>
    )

    if (!label && !description) {
      return <span className={className}>{control}</span>
    }

    return (
      <div className={cn('flex items-start gap-3', className)}>
        {control}
        <label
          htmlFor={switchId}
          className="flex cursor-pointer flex-col pt-0.5 leading-tight"
        >
          {label && <span className="text-sm font-medium text-fg">{label}</span>}
          {description && (
            <span className="mt-0.5 text-xs text-fg-subtle">{description}</span>
          )}
        </label>
      </div>
    )
  },
)

Switch.displayName = 'Switch'
