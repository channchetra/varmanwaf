import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost' | 'link'
export type ButtonSize = 'sm' | 'md' | 'lg' | 'icon'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  loading?: boolean
  icon?: ReactNode
  fullWidth?: boolean
}

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    'bg-brand text-white border border-transparent hover:bg-brand-hover active:brightness-95 shadow-sm disabled:bg-brand/50',
  secondary:
    'bg-elevated text-fg border border-line hover:bg-recessed active:bg-recessed shadow-sm',
  danger:
    'bg-danger text-white border border-transparent hover:brightness-110 active:brightness-95 shadow-sm disabled:bg-danger/50',
  ghost:
    'bg-transparent text-fg-subtle border border-transparent hover:bg-recessed hover:text-fg',
  link: 'bg-transparent text-link border border-transparent hover:underline px-0',
}

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-[13px] gap-1.5 rounded-md',
  md: 'h-9 px-4 text-sm gap-2 rounded-md',
  lg: 'h-11 px-5 text-[15px] gap-2 rounded-lg',
  icon: 'h-9 w-9 justify-center rounded-md',
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = 'secondary',
      size = 'md',
      loading = false,
      icon,
      fullWidth = false,
      children,
      disabled,
      type = 'button',
      ...props
    },
    ref,
  ) => {
    return (
      <button
        ref={ref}
        type={type}
        disabled={disabled || loading}
        className={cn(
          'inline-flex items-center font-medium transition-[background-color,color,border-color,box-shadow,transform] duration-150 select-none',
          'disabled:cursor-not-allowed disabled:opacity-60 active:translate-y-px',
          variantClasses[variant],
          sizeClasses[size],
          fullWidth && 'w-full',
          className,
        )}
        {...props}
      >
        {loading ? (
          <span
            className="h-3.5 w-3.5 animate-spin-slow rounded-full border-2 border-current border-t-transparent opacity-80"
            aria-hidden
          />
        ) : (
          icon
        )}
        {children}
      </button>
    )
  },
)

Button.displayName = 'Button'
