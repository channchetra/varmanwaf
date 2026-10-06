import i18n from '@/i18n'
import { ApiError } from './client'

/**
 * Centralised REST error handling.
 *
 * The control plane returns a single envelope (`{"error":{"code","message"}}`)
 * so every failure can be classified the same way. Classification drives two
 * things:
 *
 *  1. side effects — a 401 clears the session (handled inside `client.ts`) and
 *     the router then redirects to `/login`;
 *  2. presentation — a human readable toast pushed through {@link notifyError}.
 *
 * Toasts are delivered over a tiny pub/sub bus because API modules run outside
 * the React tree; `ToastProvider` subscribes on mount.
 */

export type ErrorKind =
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'validation'
  | 'server_error'
  | 'network'
  | 'unknown'

export type NoticeTone = 'success' | 'error' | 'warning' | 'info'

export interface ErrorNotice {
  title: string
  description?: string
  tone: NoticeTone
}

type Listener = (notice: ErrorNotice) => void

const listeners = new Set<Listener>()

/** Subscribe to error notices. Returns an unsubscribe function. */
export function onErrorNotice(listener: Listener): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/** Push a notice to every subscriber (used by `ToastProvider`). */
export function emitNotice(notice: ErrorNotice): void {
  for (const listener of listeners) listener(notice)
}

/** Convenience wrapper so non-API code can raise the same toasts. */
export function notifyError(title: string, description?: string): void {
  emitNotice({ title, description, tone: 'error' })
}

export function notifyInfo(title: string, description?: string): void {
  emitNotice({ title, description, tone: 'info' })
}

/* ──────────────────────────────────────────────────────────────── */

const t = (key: string, fallback: string): string => {
  const value = i18n.t(key)
  return typeof value === 'string' && value !== key ? value : fallback
}

/** Maps an `ApiError` (or any thrown value) onto a coarse category. */
export function classifyError(err: unknown): ErrorKind {
  if (err instanceof ApiError) {
    if (err.networkError || err.status === 0) return 'network'
    switch (err.status) {
      case 401:
        return 'unauthorized'
      case 403:
        return 'forbidden'
      case 404:
        return 'not_found'
      case 409:
        return 'conflict'
      case 400:
      case 422:
        return 'validation'
      default:
        return err.status >= 500 ? 'server_error' : 'unknown'
    }
  }
  if (err instanceof TypeError) return 'network'
  return 'unknown'
}

/** True when the failure is worth retrying (transient network / 5xx). */
export function isRetryableError(err: unknown): boolean {
  const kind = classifyError(err)
  return kind === 'network' || kind === 'server_error'
}

/** Human readable message for any thrown value. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message
  if (err instanceof Error) return err.message
  return String(err ?? '')
}

interface NoticeSpec {
  titleKey: string
  titleFallback: string
  tone: NoticeTone
}

const NOTICE_BY_KIND: Record<ErrorKind, NoticeSpec> = {
  unauthorized: {
    titleKey: 'errors.unauthorized',
    titleFallback: 'Session expired',
    tone: 'warning',
  },
  forbidden: {
    titleKey: 'errors.forbidden',
    titleFallback: 'Permission denied',
    tone: 'error',
  },
  not_found: {
    titleKey: 'errors.notFound',
    titleFallback: 'Not found',
    tone: 'warning',
  },
  conflict: {
    titleKey: 'errors.conflict',
    titleFallback: 'Already exists',
    tone: 'error',
  },
  validation: {
    titleKey: 'errors.validation',
    titleFallback: 'Invalid input',
    tone: 'error',
  },
  server_error: {
    titleKey: 'errors.serverError',
    titleFallback: 'Server error',
    tone: 'error',
  },
  network: {
    titleKey: 'errors.network',
    titleFallback: 'Connection lost',
    tone: 'error',
  },
  unknown: {
    titleKey: 'errors.unknown',
    titleFallback: 'Something went wrong',
    tone: 'error',
  },
}

/**
 * Duplicate-suppression window: TanStack Query fans a single failure out to
 * every mounted consumer, and four identical toasts help nobody.
 */
const DEDUPE_MS = 3000
const recentlyShown = new Map<string, number>()

function shouldShow(signature: string): boolean {
  const now = Date.now()
  const last = recentlyShown.get(signature)
  if (last && now - last < DEDUPE_MS) return false
  recentlyShown.set(signature, now)
  if (recentlyShown.size > 64) {
    for (const [key, at] of recentlyShown) {
      if (now - at > DEDUPE_MS) recentlyShown.delete(key)
    }
  }
  return true
}

export interface HandleErrorOptions {
  /** Suppress the toast (the caller renders its own error state). */
  silent?: boolean
  /** Overrides the classified title, e.g. "Failed to delete site". */
  title?: string
  /** Overrides the detail line; defaults to the server message. */
  description?: string
}

/**
 * Classifies `err`, surfaces a toast unless silenced, and returns the original
 * error so callers can `throw handleApiError(err)` from a mutation.
 */
export function handleApiError(err: unknown, options: HandleErrorOptions = {}): unknown {
  const kind = classifyError(err)
  const spec = NOTICE_BY_KIND[kind]
  const detail =
    options.description ??
    (kind === 'unauthorized' || kind === 'network' || kind === 'server_error'
      ? undefined
      : errorMessage(err))

  if (!options.silent) {
    const title = options.title ?? t(spec.titleKey, spec.titleFallback)
    if (shouldShow(`${title}|${detail ?? ''}`)) {
      emitNotice({ title, description: detail, tone: spec.tone })
    }
  }

  return err
}

/**
 * TanStack Query `retry` predicate: retry transient failures only, never a
 * 4xx (which will keep failing and just spam toasts).
 */
export function shouldRetry(failureCount: number, err: unknown): boolean {
  if (failureCount >= 2) return false
  return isRetryableError(err)
}
