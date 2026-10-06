import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'
import {
  CheckCircle,
  WarningCircle,
  XCircle,
  Info,
  X,
} from '@phosphor-icons/react'
import { cn } from '@/lib/utils'
import { onErrorNotice } from '@/api/errors'

export type ToastTone = 'success' | 'error' | 'warning' | 'info'

export interface ToastInput {
  title: string
  description?: string
  tone?: ToastTone
  duration?: number
}

interface ToastItem extends Required<Omit<ToastInput, 'description'>> {
  id: number
  description?: string
}

interface ToastContextValue {
  toast: (input: ToastInput) => void
  success: (title: string, description?: string) => void
  error: (title: string, description?: string) => void
  warning: (title: string, description?: string) => void
  info: (title: string, description?: string) => void
  dismiss: (id: number) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

const toneConfig: Record<ToastTone, { icon: ReactNode; accent: string }> = {
  success: { icon: <CheckCircle weight="fill" className="h-5 w-5" />, accent: 'text-fg-success' },
  error: { icon: <XCircle weight="fill" className="h-5 w-5" />, accent: 'text-fg-danger' },
  warning: { icon: <WarningCircle weight="fill" className="h-5 w-5" />, accent: 'text-warning' },
  info: { icon: <Info weight="fill" className="h-5 w-5" />, accent: 'text-link' },
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const counter = useRef(0)

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const toast = useCallback(
    (input: ToastInput) => {
      const id = ++counter.current
      const item: ToastItem = {
        id,
        title: input.title,
        description: input.description,
        tone: input.tone ?? 'info',
        duration: input.duration ?? 4000,
      }
      // Cap the stack: a flapping endpoint must not bury the screen.
      setToasts((prev) => [...prev.slice(-3), item])
      if (item.duration > 0) {
        window.setTimeout(() => dismiss(id), item.duration)
      }
    },
    [dismiss],
  )

  // Bridge for errors raised outside React (the API client, query defaults).
  useEffect(
    () =>
      onErrorNotice((notice) =>
        toast({
          title: notice.title,
          description: notice.description,
          tone: notice.tone,
          duration: notice.tone === 'error' ? 6000 : 4000,
        }),
      ),
    [toast],
  )

  const value = useMemo<ToastContextValue>(
    () => ({
      toast,
      dismiss,
      success: (title, description) => toast({ title, description, tone: 'success' }),
      error: (title, description) => toast({ title, description, tone: 'error' }),
      warning: (title, description) => toast({ title, description, tone: 'warning' }),
      info: (title, description) => toast({ title, description, tone: 'info' }),
    }),
    [toast, dismiss],
  )

  return (
    <ToastContext.Provider value={value}>
      {children}
      {createPortal(
        <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2">
          {toasts.map((t) => {
            const cfg = toneConfig[t.tone]
            return (
              <div
                key={t.id}
                role="status"
                className="pointer-events-auto flex animate-toast-in items-start gap-3 rounded-lg border border-line bg-elevated p-3 shadow-lg"
              >
                <span className={cn('mt-0.5 shrink-0', cfg.accent)}>{cfg.icon}</span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-fg-strong">{t.title}</p>
                  {t.description && (
                    <p className="mt-0.5 text-[13px] leading-relaxed text-fg-subtle">
                      {t.description}
                    </p>
                  )}
                </div>
                <button
                  onClick={() => dismiss(t.id)}
                  aria-label="Dismiss"
                  className="shrink-0 rounded p-0.5 text-fg-subtle transition-colors hover:bg-recessed hover:text-fg"
                >
                  <X weight="bold" className="h-3.5 w-3.5" />
                </button>
              </div>
            )
          })}
        </div>,
        document.body,
      )}
    </ToastContext.Provider>
  )
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within a ToastProvider')
  return ctx
}
