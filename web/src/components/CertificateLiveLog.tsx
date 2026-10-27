import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowDown,
  Copy,
  DownloadSimple,
  PauseCircle,
  Play,
  Terminal,
} from '@phosphor-icons/react'
import { Dialog } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Badge, type BadgeTone } from '@/components/ui/Badge'
import { sslApi, sslKeys } from '@/api/ssl'
import type { CertificateEvent } from '@/api/types'
import { formatDateTime } from '@/lib/format'
import { cn } from '@/lib/utils'

const EVENT_TONE: Record<string, BadgeTone> = {
  created: 'success',
  renewal_requested: 'info',
  renewed: 'success',
  failed: 'danger',
  issuance_failed: 'danger',
  deleted: 'warning',
  acme_raw: 'brand',
}

/** How often the open log asks for new rows and the certificate status. */
const EVENT_POLL_MS = 1500
const STATUS_POLL_MS = 2500

export interface CertificateLiveLogProps {
  open: boolean
  certificateId: string | null
  domain?: string | null
  onClose: () => void
}

/**
 * Live certificate issuance log.
 *
 * Polls the certificate event trail while the dialog is open and appends new
 * rows, so an ACME application or renewal can be watched instead of waiting
 * for the toast and refreshing the table. The first poll seeds the latest 200
 * rows; subsequent polls send `since=<last timestamp>` and only return new
 * lines. Polling stops while paused and resumes on request.
 */
export function CertificateLiveLog({
  open,
  certificateId,
  domain,
  onClose,
}: CertificateLiveLogProps) {
  const { t } = useTranslation()
  const [events, setEvents] = useState<CertificateEvent[]>([])
  const [paused, setPaused] = useState(false)
  const [follow, setFollow] = useState(true)
  const [copied, setCopied] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const lastStamp = useRef<string | null>(null)

  // A different certificate starts a fresh transcript.
  useEffect(() => {
    if (!open) return
    setEvents([])
    setPaused(false)
    setFollow(true)
    setCopied(false)
    lastStamp.current = null
  }, [open, certificateId])

  const eventsQuery = useQuery({
    queryKey: [...sslKeys.certEvents(certificateId ?? ''), 'live'],
    queryFn: () => {
      const stamp = lastStamp.current
      return sslApi.listCertEvents(certificateId!, {
        page_size: 200,
        ...(stamp ? { since: stamp, order: 'asc' as const } : {}),
      })
    },
    enabled: open && Boolean(certificateId) && !paused,
    refetchInterval: EVENT_POLL_MS,
    refetchIntervalInBackground: true,
  })

  // The certificate row tells us whether the attempt is still pending; the
  // event trail is appended separately because it carries the raw ACME lines.
  const certQuery = useQuery({
    queryKey: ['ssl', 'live-status', certificateId],
    queryFn: () => sslApi.getGlobal(certificateId!),
    enabled: open && Boolean(certificateId),
    refetchInterval: paused ? false : STATUS_POLL_MS,
    refetchIntervalInBackground: true,
  })

  useEffect(() => {
    const items = eventsQuery.data?.items
    if (!items?.length) return
    setEvents((prev) => {
      // `since` is inclusive so rows sharing a timestamp are not lost; skip
      // the re-render when a poll only returns rows already on screen.
      const known = new Set(prev.map((event) => event.id))
      if (items.every((event) => known.has(event.id))) return prev
      const merged = new Map(prev.map((event) => [event.id, event]))
      for (const event of items) merged.set(event.id, event)
      return [...merged.values()].sort((a, b) =>
        a.created_at === b.created_at
          ? a.id.localeCompare(b.id)
          : a.created_at.localeCompare(b.created_at),
      )
    })
    const newest = items.reduce(
      (max, event) => (event.created_at > max ? event.created_at : max),
      lastStamp.current ?? '',
    )
    if (newest) lastStamp.current = newest
  }, [eventsQuery.data])

  // Keep the viewport pinned to the newest line unless the operator scrolled
  // up to read an earlier failure.
  useEffect(() => {
    if (!follow || !open) return
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [events.length, follow, open])

  const status = certQuery.data?.status ?? 'pending'
  const statusTone: BadgeTone =
    status === 'active'
      ? 'success'
      : status === 'failed' || status === 'expired'
        ? 'danger'
        : 'info'
  const statusLabel =
    status === 'active'
      ? t('pages.ssl.liveActive')
      : status === 'failed' || status === 'expired'
        ? t('pages.ssl.liveFailed')
        : t('pages.ssl.liveIssuing')

  const transcript = useMemo(
    () =>
      events
        .map(
          (event) =>
            `[${formatDateTime(event.created_at)}] ${event.event_type.toUpperCase()} ${event.message}`,
        )
        .join('\n'),
    [events],
  )

  const copy = async () => {
    if (!transcript) return
    try {
      await navigator.clipboard.writeText(transcript)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard permission denied: leave the button silent rather than
      // showing a toast over the log.
    }
  }

  const download = () => {
    if (!transcript) return
    const blob = new Blob([`${transcript}\n`], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${domain ?? certificateId ?? 'certificate'}-issuance.log`
    anchor.click()
    // Give the browser a tick to start the download before releasing the blob.
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const onScroll = () => {
    const el = scrollRef.current
    if (!el) return
    setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 40)
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="xl"
      title={
        <span className="flex items-center gap-2">
          <Terminal weight="duotone" className="h-5 w-5 text-brand-ink" />
          {t('pages.ssl.liveTitle')}
        </span>
      }
      description={
        <span className="flex flex-wrap items-center gap-2">
          <span className="pw-mono text-[13px] text-fg">{domain ?? certificateId}</span>
          <Badge tone={statusTone} dot size="sm">
            {statusLabel}
          </Badge>
          <Badge tone={paused ? 'warning' : 'success'} dot size="sm">
            {paused ? t('pages.ssl.livePaused') : t('pages.ssl.liveLive')}
          </Badge>
          {certQuery.data?.expires_at && (
            <span className="text-xs text-fg-subtle">
              {t('pages.ssl.expires')}: {formatDateTime(certQuery.data.expires_at)}
            </span>
          )}
        </span>
      }
      footer={
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setPaused((value) => !value)}
            >
              {paused ? (
                <Play weight="fill" className="h-4 w-4" />
              ) : (
                <PauseCircle weight="duotone" className="h-4 w-4" />
              )}
              {paused ? t('pages.ssl.liveResume') : t('pages.ssl.livePause')}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={events.length === 0}
              onClick={copy}
            >
              <Copy className="h-4 w-4" />
              {copied ? t('pages.ssl.liveCopied') : t('pages.ssl.liveCopy')}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={events.length === 0}
              onClick={download}
            >
              <DownloadSimple className="h-4 w-4" />
              {t('pages.ssl.liveDownload')}
            </Button>
          </div>
          <Button variant="secondary" onClick={onClose}>
            {t('common.close')}
          </Button>
        </div>
      }
    >
      <div className="relative">
        <div
          ref={scrollRef}
          onScroll={onScroll}
          className="pw-mono max-h-[52vh] min-h-[220px] overflow-auto rounded-lg border border-line bg-recessed px-3 py-2 text-[12px] leading-relaxed"
        >
          {events.length === 0 ? (
            <div className="flex h-[200px] flex-col items-center justify-center gap-1 text-center">
              <p className="text-[13px] font-medium text-fg">
                {t('pages.ssl.liveEmpty')}
              </p>
              <p className="max-w-md text-xs text-fg-subtle">
                {t('pages.ssl.liveEmptyHint')}
              </p>
            </div>
          ) : (
            events.map((event) => (
              <div
                key={event.id}
                className="flex items-start gap-2 border-b border-line/50 py-1 last:border-0"
              >
                <span
                  className="shrink-0 whitespace-nowrap text-[11px] text-fg-subtle"
                  title={formatDateTime(event.created_at)}
                >
                  {new Date(event.created_at).toLocaleTimeString(undefined, {
                    hour12: false,
                  })}
                </span>
                <Badge
                  tone={EVENT_TONE[event.event_type] ?? 'neutral'}
                  size="sm"
                  className="shrink-0"
                >
                  {t(`pages.sslGlobal.event_${event.event_type}`, {
                    defaultValue: event.event_type,
                  })}
                </Badge>
                <span
                  className={cn(
                    'min-w-0 whitespace-pre-wrap break-words',
                    event.event_type === 'acme_raw'
                      ? 'text-fg-subtle'
                      : 'text-fg',
                  )}
                >
                  {event.message}
                </span>
              </div>
            ))
          )}
        </div>
        {!follow && events.length > 0 && (
          <Button
            size="sm"
            variant="secondary"
            className="absolute bottom-3 right-3 shadow-md"
            onClick={() => {
              setFollow(true)
              const el = scrollRef.current
              if (el) el.scrollTop = el.scrollHeight
            }}
          >
            <ArrowDown className="h-4 w-4" />
            {t('pages.ssl.liveLatest')}
          </Button>
        )}
      </div>
      <p className="mt-2 text-[11px] text-fg-subtle">
        {t('pages.ssl.liveFootHint')}
      </p>
    </Dialog>
  )
}
