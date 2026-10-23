import { useEffect, useId, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { X } from '@phosphor-icons/react'
import { cn } from '@/lib/utils'
import { Button } from './Button'

export interface DialogProps {
  open: boolean
  onClose: () => void
  title?: ReactNode
  description?: ReactNode
  children?: ReactNode
  footer?: ReactNode
  size?: 'sm' | 'md' | 'lg' | 'xl'
  className?: string
}

const sizeClasses = {
  sm: 'max-w-sm',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-5xl',
} as const

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'

/**
 * Every open modal makes the app root inert, so focus and pointer events
 * cannot reach the page behind it. A counter keeps stacked dialogs safe.
 */
let openDialogs = 0

function lockBackground(root: HTMLElement | null) {
  if (!root) return
  openDialogs += 1
  root.setAttribute('inert', '')
}

function unlockBackground(root: HTMLElement | null) {
  if (!root) return
  openDialogs = Math.max(0, openDialogs - 1)
  if (openDialogs === 0) root.removeAttribute('inert')
}

export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = 'md',
  className,
}: DialogProps) {
  const panelRef = useRef<HTMLDivElement>(null)
  const closeRef = useRef(onClose)
  const titleId = useId()
  const descriptionId = useId()

  // Keep the latest close handler without re-running the focus effect when
  // the parent re-renders (e.g. while choosing a protection mode).
  useEffect(() => {
    closeRef.current = onClose
  }, [onClose])

  useEffect(() => {
    if (!open) return

    const previouslyFocused =
      document.activeElement instanceof HTMLElement ? document.activeElement : null
    const panel = panelRef.current
    const root = document.getElementById('root')
    const previousOverflow = document.body.style.overflow

    document.body.style.overflow = 'hidden'
    lockBackground(root)

    const focusFrame = window.requestAnimationFrame(() => {
      panel?.focus({ preventScroll: true })
    })

    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        closeRef.current()
        return
      }
      if (event.key !== 'Tab' || !panel) return
      const focusables = Array.from(
        panel.querySelectorAll<HTMLElement>(FOCUSABLE),
      ).filter((element) => element.offsetParent !== null)
      if (focusables.length === 0) {
        event.preventDefault()
        panel.focus()
        return
      }
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      const inside = panel.contains(document.activeElement)
      if (!inside) {
        event.preventDefault()
        first.focus()
      } else if (
        event.shiftKey &&
        (document.activeElement === first || document.activeElement === panel)
      ) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKey)
    return () => {
      window.cancelAnimationFrame(focusFrame)
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = previousOverflow
      unlockBackground(root)
      if (previouslyFocused?.isConnected) {
        previouslyFocused.focus({ preventScroll: true })
      }
    }
  }, [open])

  if (!open) return null

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 animate-fade-in bg-overlay"
        onClick={() => closeRef.current()}
        aria-hidden
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        aria-describedby={description ? descriptionId : undefined}
        tabIndex={-1}
        className={cn(
          'relative z-10 flex max-h-[calc(100dvh-2rem)] w-full animate-scale-in flex-col rounded-xl border border-line bg-elevated shadow-lg focus:outline-none',
          sizeClasses[size],
          className,
        )}
      >
        {(title || description) && (
          <div className="flex shrink-0 items-start justify-between gap-4 border-b border-line px-5 py-4">
            <div className="min-w-0">
              {title && (
                <h2 id={titleId} className="text-base font-semibold text-fg-strong">
                  {title}
                </h2>
              )}
              {description && (
                <p id={descriptionId} className="mt-0.5 text-[13px] text-fg-subtle">
                  {description}
                </p>
              )}
            </div>
            <Button
              size="icon"
              variant="ghost"
              aria-label="Close"
              onClick={() => closeRef.current()}
              icon={<X weight="bold" className="h-4 w-4" />}
            />
          </div>
        )}
        {children && (
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
            {children}
          </div>
        )}
        {footer && (
          <div className="flex shrink-0 items-center justify-end gap-2 border-t border-line px-5 py-3">
            {footer}
          </div>
        )}
      </div>
    </div>,
    document.body,
  )
}
