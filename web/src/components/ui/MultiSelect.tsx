import { useState, type ReactNode } from 'react'
import { Check, X } from '@phosphor-icons/react'
import { cn } from '@/lib/utils'

/* ────────────────────────────────────────────────────────────────
   Pill multi-select
   ──────────────────────────────────────────────────────────────── */

export interface PillOption {
  value: string
  label: string
  /** Optional one-line explainer shown under the label. */
  hint?: string
  disabled?: boolean
}

export interface PillMultiSelectProps {
  options: PillOption[]
  value: string[]
  onChange: (value: string[]) => void
  label?: ReactNode
  hint?: ReactNode
  error?: ReactNode
  disabled?: boolean
  className?: string
  /** At least this many options must stay selected. */
  min?: number
}

/**
 * Checkbox pills.
 *
 * Rate-limit characteristics and rule tags are small closed vocabularies; a row
 * of toggleable pills beats a native multi-select, which hides its own state
 * behind platform-specific chrome.
 */
export function PillMultiSelect({
  options,
  value,
  onChange,
  label,
  hint,
  error,
  disabled = false,
  className,
  min = 0,
}: PillMultiSelectProps) {
  const toggle = (next: string) => {
    const has = value.includes(next)
    if (has && value.length <= min) return
    onChange(has ? value.filter((v) => v !== next) : [...value, next])
  }

  return (
    <fieldset className={cn('flex flex-col gap-2', className)} disabled={disabled}>
      {label && (
        <legend className="mb-1 text-[13px] font-medium text-fg">{label}</legend>
      )}
      <div className="flex flex-wrap gap-1.5">
        {options.map((option) => {
          const selected = value.includes(option.value)
          return (
            <button
              key={option.value}
              type="button"
              role="checkbox"
              aria-checked={selected}
              title={option.hint}
              disabled={disabled || option.disabled}
              onClick={() => toggle(option.value)}
              className={cn(
                'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-[13px] font-medium',
                'transition-all duration-150 disabled:cursor-not-allowed disabled:opacity-50',
                selected
                  ? 'border-brand bg-brand-soft text-brand'
                  : 'border-line bg-elevated text-fg-subtle hover:border-fill hover:text-fg',
              )}
            >
              {selected && <Check weight="bold" className="h-3 w-3" />}
              {option.label}
            </button>
          )
        })}
      </div>
      {error ? (
        <p className="text-xs font-medium text-fg-danger">{error}</p>
      ) : hint ? (
        <p className="text-xs leading-relaxed text-fg-subtle">{hint}</p>
      ) : null}
    </fieldset>
  )
}

/* ────────────────────────────────────────────────────────────────
   Free-form tag input
   ──────────────────────────────────────────────────────────────── */

export interface TagInputProps {
  value: string[]
  onChange: (value: string[]) => void
  label?: ReactNode
  hint?: ReactNode
  error?: ReactNode
  placeholder?: string
  disabled?: boolean
  max?: number
  className?: string
  /** Suggested tags rendered as clickable chips below the field. */
  suggestions?: string[]
}

/**
 * Chip editor for `rules.tags`.
 *
 * Tags drive the derived detection families (`sqli`, `xss`, `rce`, `lfi`,
 * `ssrf`, `bot`), so getting them in easily matters — Enter or comma commits,
 * Backspace on an empty field removes the last chip.
 */
export function TagInput({
  value,
  onChange,
  label,
  hint,
  error,
  placeholder,
  disabled = false,
  max = 32,
  className,
  suggestions = [],
}: TagInputProps) {
  const [draft, setDraft] = useState('')

  const commit = (raw: string) => {
    const tag = raw.trim().toLowerCase()
    if (!tag || tag.length > 64) return
    if (value.includes(tag) || value.length >= max) {
      setDraft('')
      return
    }
    onChange([...value, tag])
    setDraft('')
  }

  const remove = (tag: string) => onChange(value.filter((v) => v !== tag))

  return (
    <div className={cn('flex flex-col gap-1.5', className)}>
      {label && <span className="text-[13px] font-medium text-fg">{label}</span>}
      <div
        className={cn(
          'flex min-h-9 flex-wrap items-center gap-1.5 rounded-md border bg-elevated px-2 py-1.5',
          error ? 'border-danger' : 'border-line focus-within:border-focus',
          disabled && 'cursor-not-allowed bg-recessed',
        )}
      >
        {value.map((tag) => (
          <span
            key={tag}
            className="inline-flex items-center gap-1 rounded bg-recessed px-2 py-0.5 text-xs font-medium text-fg"
          >
            {tag}
            {!disabled && (
              <button
                type="button"
                aria-label={`Remove ${tag}`}
                onClick={() => remove(tag)}
                className="text-fg-subtle transition-colors hover:text-fg-danger"
              >
                <X weight="bold" className="h-3 w-3" />
              </button>
            )}
          </span>
        ))}
        <input
          value={draft}
          disabled={disabled}
          placeholder={value.length === 0 ? placeholder : undefined}
          onChange={(e) => {
            const next = e.target.value
            if (next.endsWith(',') || next.endsWith(' ')) commit(next.slice(0, -1))
            else setDraft(next)
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              commit(draft)
            } else if (e.key === 'Backspace' && !draft && value.length) {
              remove(value[value.length - 1])
            }
          }}
          onBlur={() => draft && commit(draft)}
          className="min-w-24 flex-1 bg-transparent py-0.5 text-sm text-fg outline-none placeholder:text-fg-subtle/60"
        />
      </div>

      {suggestions.length > 0 && !disabled && (
        <div className="flex flex-wrap items-center gap-1">
          {suggestions
            .filter((s) => !value.includes(s))
            .slice(0, 8)
            .map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => commit(s)}
                className="rounded-full border border-dashed border-line px-2 py-0.5 text-xs text-fg-subtle transition-colors hover:border-brand hover:text-brand"
              >
                + {s}
              </button>
            ))}
        </div>
      )}

      {error ? (
        <p className="text-xs font-medium text-fg-danger">{error}</p>
      ) : hint ? (
        <p className="text-xs leading-relaxed text-fg-subtle">{hint}</p>
      ) : null}
    </div>
  )
}
