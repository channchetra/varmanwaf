import { useEffect, useRef, type ReactNode } from 'react'
import { Warning } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { Dialog } from './Dialog'
import { Button } from './Button'
import { cn } from '@/lib/utils'

export interface ConfirmDialogProps {
  open: boolean
  onClose: () => void
  onConfirm: () => void
  title: ReactNode
  description?: ReactNode
  /** Label of the destructive/primary action. Defaults to `common:confirm`. */
  confirmLabel?: ReactNode
  cancelLabel?: ReactNode
  /** `danger` paints the confirm button red — use for deletes. */
  tone?: 'danger' | 'primary'
  loading?: boolean
  disabled?: boolean
  /** Extra context rendered under the description, e.g. the affected row. */
  children?: ReactNode
}

/**
 * Two-button confirmation used before every destructive call.
 *
 * Autofocuses the cancel button (never the destructive one) and confirms on
 * `Enter` so keyboard users cannot delete something by reflex.
 */
export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel,
  cancelLabel,
  tone = 'danger',
  loading = false,
  disabled = false,
  children,
}: ConfirmDialogProps) {
  const { t } = useTranslation()
  const cancelRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    // Let the dialog mount before stealing focus.
    const id = window.setTimeout(() => cancelRef.current?.focus(), 0)
    return () => window.clearTimeout(id)
  }, [open])

  return (
    <Dialog
      open={open}
      onClose={loading ? () => undefined : onClose}
      size="sm"
      title={
        <span className="flex items-center gap-2">
          <span
            className={cn(
              'flex h-7 w-7 shrink-0 items-center justify-center rounded-full',
              tone === 'danger' ? 'bg-danger/12 text-fg-danger' : 'bg-brand-soft text-brand',
            )}
          >
            <Warning weight="fill" className="h-4 w-4" />
          </span>
          {title}
        </span>
      }
      footer={
        <>
          <Button
            ref={cancelRef}
            variant="secondary"
            onClick={onClose}
            disabled={loading}
          >
            {cancelLabel ?? t('common.cancel')}
          </Button>
          <Button
            variant={tone === 'danger' ? 'danger' : 'primary'}
            onClick={onConfirm}
            loading={loading}
            disabled={disabled || loading}
            autoFocus={false}
          >
            {confirmLabel ?? t('common.confirm')}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {description && (
          <p className="text-sm leading-relaxed text-fg-subtle">{description}</p>
        )}
        {children}
      </div>
    </Dialog>
  )
}

export default ConfirmDialog
