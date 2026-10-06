import { forwardRef, useId, type ReactNode, type TextareaHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

export interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: ReactNode
  hint?: ReactNode
  error?: ReactNode
  containerClassName?: string
  /** Renders the value in the mono face — right for expressions and PEM blobs. */
  mono?: boolean
}

/**
 * Multiline field used for rule expressions, TLS material and log details.
 * Mirrors `Input`'s label/hint/error treatment so forms stay consistent.
 */
export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  function Textarea(
    { label, hint, error, containerClassName, mono = false, className, id, ...props },
    ref,
  ) {
    const generatedId = useId()
    const fieldId = id ?? generatedId
    const hintId = `${fieldId}-hint`
    const errorId = `${fieldId}-error`

    return (
      <div className={cn('flex flex-col gap-1.5', containerClassName)}>
        {label && (
          <label
            htmlFor={fieldId}
            className="text-[13px] font-medium text-fg"
          >
            {label}
          </label>
        )}
        <textarea
          ref={ref}
          id={fieldId}
          aria-invalid={error ? true : undefined}
          aria-describedby={
            error ? errorId : hint ? hintId : undefined
          }
          className={cn(
            'w-full resize-y rounded-md border bg-elevated px-3 py-2 text-sm text-fg',
            'placeholder:text-fg-subtle/60 transition-colors duration-150',
            'disabled:cursor-not-allowed disabled:bg-recessed disabled:text-fg-subtle',
            error
              ? 'border-danger focus:border-danger'
              : 'border-line hover:border-fill focus:border-focus',
            mono && 'pw-mono text-[13px] leading-relaxed',
            className,
          )}
          {...props}
        />
        {hint && !error && (
          <p id={hintId} className="text-xs leading-relaxed text-fg-subtle">
            {hint}
          </p>
        )}
        {error && (
          <p id={errorId} className="text-xs font-medium text-fg-danger">
            {error}
          </p>
        )}
      </div>
    )
  },
)

export default Textarea
