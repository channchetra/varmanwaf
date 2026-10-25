import { Fragment, useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  ShieldWarning,
  ListDashes,
  MagnifyingGlass,
  DownloadSimple,
  ArrowClockwise,
  Trash,
  Funnel,
  Terminal,
  LockKey,
  FileMagnifyingGlass,
  Copy,
  Info,
  MinusCircle,
  Question,
  ArrowSquareOut,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Callout } from '@/components/ui/Callout'
import { Card, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { Pagination } from '@/components/ui/Pagination'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import {
  downloadJson,
  fileTimestamp,
  logKeys,
  logsApi,
  type EventExplanation,
  type ExplanationStep,
  type MatchedRule,
} from '@/api/logs'
import { apiProtectionApi, apiProtectionKeys } from '@/api/apiProtection'
import { useCanWrite, useSitesList } from '@/hooks'
import { useAuthStore } from '@/stores/authStore'
import { cn } from '@/lib/utils'
import { buildCurlCommand } from '@/lib/curl'
import { parseLogQuery } from '@/lib/logQuery'
import { decidingRule } from '@/lib/wafDetails'
import { requestLines, responseLines, type RawLine } from '@/lib/rawHttp'
import {
  formatDateTime,
  formatLatency,
  formatNumber,
  formatSize,
  fromLocalInputValue,
  statusTone,
  toLocalInputValue,
} from '@/lib/format'
import type {
  AccessLog,
  ControlPlaneAccessLog,
  ControlPlaneLogQuery,
  LogQueryParams,
  SecurityEvent,
} from '@/api/types'

type Tab = 'security' | 'access' | 'control'

const RANGE_PRESETS = [
  { value: '1', label: '1h' },
  { value: '6', label: '6h' },
  { value: '24', label: '24h' },
  { value: '72', label: '3d' },
  { value: '168', label: '7d' },
  { value: '720', label: '30d' },
  { value: 'custom', label: '…' },
]

const PAGE_SIZES = [25, 50, 100, 200]

const ACTION_TONE: Record<string, 'danger' | 'warning' | 'info' | 'success' | 'neutral'> = {
  block: 'danger',
  blocked: 'danger',
  challenge: 'warning',
  js_challenge: 'warning',
  log: 'info',
  allow: 'success',
  allowed: 'success',
  pass: 'success',
}

/** Decisions recorded on `control_plane_access_logs.action`. */
const CONTROL_ACTION_TONE: Record<string, 'danger' | 'warning' | 'info' | 'success' | 'neutral'> = {
  allowed: 'success',
  blocked_allowlist: 'danger',
  blocked_waf: 'danger',
  observed_waf: 'warning',
}

/** Time window used when the URL carries none: the trailing 24 hours. */
function defaultWindow(): { from: string; to: string } {
  const now = new Date()
  const from = new Date(now.getTime() - 24 * 3600_000)
  // datetime-local is minute-precision. A `to` of the current minute excludes
  // an event that arrived seconds later in that same minute (exactly the
  // "I just got blocked and cannot find the request" case), so round up one
  // minute. The upper bound is harmless and keeps the current minute visible.
  const to = new Date(now.getTime() + 60_000)
  return { from: toLocalInputValue(from), to: toLocalInputValue(to) }
}

export function LogsPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const canWrite = useCanWrite()
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'
  const [searchParams, setSearchParams] = useSearchParams()

  // The URL is the source of truth for the query (tab/q/site/from/to), so a
  // drill-down link or a browser reload restores the exact result set. The
  // text box keeps a local draft until Enter commits it.
  const [window] = useState(defaultWindow)
  const tabParam = searchParams.get('tab')
  // The control plane tab is administrators-only (the endpoint is too); a
  // viewer landing on a shared link silently falls back to the default tab.
  const tab: Tab =
    tabParam === 'access'
      ? 'access'
      : tabParam === 'control' && isAdmin
        ? 'control'
        : 'security'
  const searchText = searchParams.get('q') ?? ''
  const siteId = searchParams.get('site_id') ?? ''
  const fromValue = searchParams.get('from') ?? window.from
  const toValue = searchParams.get('to') ?? window.to
  const preset =
    searchParams.get('preset') ??
    (searchParams.has('from') || searchParams.has('to') ? 'custom' : '24')

  const [draft, setDraft] = useState(searchText)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)
  const [selectedLog, setSelectedLog] = useState<AccessLog | null>(null)
  const [selectedControl, setSelectedControl] = useState<ControlPlaneAccessLog | null>(null)
  const [purgeOpen, setPurgeOpen] = useState(false)
  const [purgeDays, setPurgeDays] = useState(30)

  // Adopt the URL text when it changes without the box (drill-down, history).
  const [lastSearchText, setLastSearchText] = useState(searchText)
  if (searchText !== lastSearchText) {
    setLastSearchText(searchText)
    setDraft(searchText)
  }

  const { data: sites } = useSitesList()

  // Any query change must drop back to the first page, otherwise the request
  // asks for page 5 of a completely different result set.
  const queryFingerprint = JSON.stringify([tab, searchText, siteId, fromValue, toValue, pageSize])
  const [lastQueryFingerprint, setLastQueryFingerprint] = useState(queryFingerprint)
  if (queryFingerprint !== lastQueryFingerprint) {
    setLastQueryFingerprint(queryFingerprint)
    setPage(1)
  }

  const parsedQuery = useMemo(
    () => parseLogQuery(searchText, tab),
    [searchText, tab],
  )

  const params = useMemo<LogQueryParams>(() => {
    const base: LogQueryParams = {
      ...parsedQuery.params,
      page,
      page_size: pageSize,
      from: fromLocalInputValue(fromValue),
      to: fromLocalInputValue(toValue),
    }
    if (siteId) base.site_id = siteId
    return base
  }, [parsedQuery, page, pageSize, fromValue, toValue, siteId])

  // Control plane rows are cross-tenant and carry no site column, so the site
  // filter is dropped (and hidden) on that tab.
  const controlParams = useMemo<ControlPlaneLogQuery>(() => {
    const { site_id: _siteId, ...rest } = parsedQuery.params
    return {
      ...rest,
      page,
      page_size: pageSize,
      from: fromLocalInputValue(fromValue),
      to: fromLocalInputValue(toValue),
    }
  }, [parsedQuery, page, pageSize, fromValue, toValue])

  const securityQuery = useQuery({
    queryKey: logKeys.security(params),
    queryFn: () => logsApi.securityEvents(params),
    enabled: tab === 'security',
    placeholderData: (prev) => prev,
  })

  const accessQuery = useQuery({
    queryKey: logKeys.access(params),
    queryFn: () => logsApi.accessLogs(params),
    enabled: tab === 'access',
    placeholderData: (prev) => prev,
  })

  const controlQuery = useQuery({
    queryKey: apiProtectionKeys.logs(controlParams),
    queryFn: () => apiProtectionApi.logs(controlParams),
    enabled: tab === 'control',
    placeholderData: (prev) => prev,
  })

  const active =
    tab === 'security' ? securityQuery : tab === 'access' ? accessQuery : controlQuery
  const total = active.data?.total ?? 0
  const rows = active.data?.items ?? []

  const purge = useMutation({
    mutationFn: () =>
      logsApi.purge({
        older_than_days: purgeDays,
        ...(siteId ? { site_id: siteId } : {}),
      }),
    onSuccess: (result) => {
      toast.success(
        t('pages.logs.purgeDone'),
        t('pages.logs.purgeResult', {
          events: formatNumber(result.deleted_security_events),
          logs: formatNumber(result.deleted_access_logs),
        }),
      )
      setPurgeOpen(false)
      void securityQuery.refetch()
      void accessQuery.refetch()
    },
  })

  /** Rewrites the query string; empty values drop their key. */
  const updateQuery = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(searchParams)
    for (const [key, value] of Object.entries(patch)) {
      if (value === null || value === '') next.delete(key)
      else next.set(key, value)
    }
    setSearchParams(next, { replace: true })
  }

  const setPreset = (value: string) => {
    if (value === 'custom') {
      updateQuery({ preset: 'custom' })
      return
    }
    const hours = Number(value)
    if (!Number.isFinite(hours)) return
    const to = new Date()
    updateQuery({
      preset: value,
      to: toLocalInputValue(to),
      from: toLocalInputValue(new Date(to.getTime() - hours * 3600_000)),
    })
  }

  /** Enter in the search box: commit the draft and fold in any date filters. */
  const commitSearch = () => {
    const parsed = parseLogQuery(draft, tab)
    const patch: Record<string, string | null> = { q: draft.trim() }
    if (parsed.params.from) {
      patch.from = toLocalInputValue(new Date(parsed.params.from))
    }
    if (parsed.params.to) {
      patch.to = toLocalInputValue(new Date(parsed.params.to))
    }
    if (parsed.params.from || parsed.params.to) patch.preset = 'custom'
    if (parsed.params.site_id) patch.site_id = parsed.params.site_id
    updateQuery(patch)
  }

  const resetQuery = () => {
    updateQuery({ q: null, site_id: null, from: null, to: null, preset: null })
  }

  const copyCurl = async (log: AccessLog) => {
    try {
      await navigator.clipboard.writeText(buildCurlCommand(log))
      toast.success(t('pages.logs.copied'))
    } catch {
      toast.error(t('pages.logs.copyFailed'))
    }
  }

  // The security dialog replays the raw request captured by the matching
  // access row, so one capture (headers, cookies, body) serves both views.
  const rawRequestQuery = useQuery({
    queryKey: logKeys.access({
      request_id: selectedEvent?.request_id ?? undefined,
      from: params.from,
      to: params.to,
      page_size: 1,
    }),
    queryFn: () =>
      logsApi.accessLogs({
        request_id: selectedEvent?.request_id ?? undefined,
        from: params.from,
        to: params.to,
        page_size: 1,
      }),
    enabled: Boolean(selectedEvent?.request_id),
  })
  const rawRequest = rawRequestQuery.data?.items[0] ?? null

  // The why-chain is the investigation summary, so the dialog fetches it as
  // soon as an event opens (not only when the details are expanded). The
  // matched-rule list and the deciding-rule label feed the whole dialog.
  const explanationQuery = useQuery({
    queryKey: ['logs', 'why', selectedEvent?.id],
    queryFn: () => logsApi.whySecurity(selectedEvent!.id),
    enabled: selectedEvent !== null,
    retry: false,
  })
  const explanation = explanationQuery.data ?? null
  const selectedRequestId = selectedEvent?.request_id ?? ''
  const selectedLogRequestId = selectedLog?.request_id ?? ''
  const selectedControlRequestId = selectedControl?.request_id ?? ''
  const selectedRuleId = selectedEvent?.rule_id ?? ''
  const selectedSite = selectedEvent?.site_id
    ? sites?.find((site) => site.id === selectedEvent.site_id)
    : undefined
  const primaryRule = selectedRuleId
    ? explanation?.matched_rules?.find(
        (rule) => rule.id.toLowerCase() === selectedRuleId.toLowerCase(),
      )
    : undefined
  const ruleLabel =
    selectedRuleId &&
    explanation?.blocked_by &&
    selectedRuleId.toLowerCase() !== explanation.blocked_by.toLowerCase()
      ? t('pages.logs.firstMatch')
      : t('pages.logs.rule')

  /** Jump from any id to the log rows for that request. */
  const searchByRequestId = (id: string, timestamp?: string, tab?: Tab) => {
    setSelectedEvent(null)
    setSelectedLog(null)
    setSelectedControl(null)
    const at = timestamp ? new Date(timestamp) : new Date()
    const center = Number.isNaN(at.getTime()) ? new Date() : at
    const patch: Record<string, string | null> = {
      q: `request_id:${id}`,
      from: toLocalInputValue(new Date(center.getTime() - 5 * 60_000)),
      to: toLocalInputValue(new Date(center.getTime() + 5 * 60_000)),
      preset: 'custom',
    }
    if (tab) patch.tab = tab === 'security' ? null : tab
    updateQuery(patch)
  }

  /** Jump from a matched rule to the security events that carry its id. */
  const searchByRule = (ruleId: string) => {
    setSelectedEvent(null)
    setSelectedLog(null)
    setSelectedControl(null)
    const now = new Date()
    updateQuery({
      q: `rule:${ruleId}`,
      tab: null,
      from: toLocalInputValue(new Date(now.getTime() - 24 * 3600_000)),
      to: toLocalInputValue(new Date(now.getTime() + 60_000)),
      preset: '24',
    })
  }

  const exportJson = () => {
    if (rows.length === 0) {
      toast.warning(t('pages.logs.exportEmpty'))
      return
    }
    const name = `varman-${tab}-${fileTimestamp()}`
    downloadJson(name, {
      exported_at: new Date().toISOString(),
      kind: tab,
      filters: params,
      total,
      count: rows.length,
      items: rows,
    })
    toast.success(t('pages.logs.exported'), `${rows.length} → ${name}.json`)
  }

  const siteOptions = useMemo(
    () => [
      { value: '', label: t('pages.logs.allSites') },
      ...(sites ?? []).map((s) => ({ value: s.id, label: s.domain })),
    ],
    [sites, t],
  )

  const securityColumns: Column<SecurityEvent>[] = [
    {
      key: 'timestamp',
      header: t('pages.logs.time'),
      accessor: (r) => r.timestamp,
      sortable: true,
      width: '1%',
      cell: (r) => (
        <span className="pw-mono whitespace-nowrap text-xs text-fg-subtle">
          {formatDateTime(r.timestamp)}
        </span>
      ),
    },
    {
      key: 'client_ip',
      header: t('pages.logs.clientIp'),
      accessor: (r) => r.client_ip,
      sortable: true,
      cell: (r) => (
        <div className="min-w-0">
          <p className="pw-mono truncate text-[13px] text-fg">{r.client_ip}</p>
          {r.country_code && (
            <p className="text-[11px] text-fg-subtle">{r.country_code.toUpperCase()}</p>
          )}
        </div>
      ),
    },
    {
      key: 'method',
      header: t('pages.logs.method'),
      accessor: (r) => r.method,
      width: '1%',
      cell: (r) => <span className="pw-mono text-xs text-fg-subtle">{r.method}</span>,
    },
    {
      key: 'path',
      header: t('pages.logs.path'),
      accessor: (r) => r.path ?? '',
      cell: (r) => (
        <div className="min-w-0">
          <p className="pw-mono truncate text-[13px]">{r.path ?? '—'}</p>
          {r.host && <p className="truncate text-[11px] text-fg-subtle">{r.host}</p>}
        </div>
      ),
    },
    {
      key: 'rule',
      header: t('pages.logs.rule'),
      accessor: (r) =>
        decidingRule(r.waf_details)?.id ?? r.rule_name ?? r.rule_id ?? '',
      cell: (r) => {
        const decision = decidingRule(r.waf_details)
        const primaryId = decision?.id ?? r.rule_id
        const primaryName = decision?.name ?? r.rule_name ?? primaryId
        const firstId =
          decision &&
          r.rule_id &&
          decision.id.toLowerCase() !== r.rule_id.toLowerCase()
            ? r.rule_id
            : null
        if (!primaryName) {
          return <span className="text-fg-subtle">—</span>
        }
        const showId = Boolean(primaryId && primaryName !== primaryId)
        const secondary = [
          showId ? primaryId : null,
          firstId
            ? t('pages.logs.firstMatchInline', { id: firstId })
            : null,
        ]
          .filter(Boolean)
          .join(' · ')
        return (
          <div className="min-w-0" title={r.waf_details ?? undefined}>
            <p className="truncate text-[13px]">{primaryName}</p>
            {secondary && (
              <p className="pw-mono truncate text-[11px] text-fg-subtle">
                {secondary}
              </p>
            )}
          </div>
        )
      },
    },
    {
      key: 'action',
      header: t('pages.logs.action'),
      accessor: (r) => r.action,
      width: '1%',
      cell: (r) => (
        <Badge tone={ACTION_TONE[r.action] ?? 'neutral'}>
          {t(`actions.${r.action}`, r.action)}
        </Badge>
      ),
    },
    {
      key: 'score',
      header: t('pages.logs.wafScore'),
      accessor: (r) => r.score ?? 0,
      sortable: true,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span
          className={cn(
            'tabular-nums text-[13px]',
            (r.score ?? 0) >= 50 ? 'font-medium text-fg-danger' : 'text-fg-subtle',
          )}
        >
          {r.score ?? '—'}
        </span>
      ),
    },
  ]

  const accessColumns: Column<AccessLog>[] = [
    {
      key: 'timestamp',
      header: t('pages.logs.time'),
      accessor: (r) => r.timestamp,
      sortable: true,
      width: '1%',
      cell: (r) => (
        <span className="pw-mono whitespace-nowrap text-xs text-fg-subtle">
          {formatDateTime(r.timestamp)}
        </span>
      ),
    },
    {
      key: 'client_ip',
      header: t('pages.logs.clientIp'),
      accessor: (r) => r.client_ip,
      sortable: true,
      cell: (r) => (
        <div className="min-w-0">
          <p className="pw-mono truncate text-[13px] text-fg">{r.client_ip}</p>
          {r.country_code && (
            <p className="text-[11px] text-fg-subtle">{r.country_code.toUpperCase()}</p>
          )}
        </div>
      ),
    },
    {
      key: 'method',
      header: t('pages.logs.method'),
      accessor: (r) => r.method,
      width: '1%',
      cell: (r) => <span className="pw-mono text-xs text-fg-subtle">{r.method}</span>,
    },
    {
      key: 'path',
      header: t('pages.logs.path'),
      accessor: (r) => r.path ?? '',
      cell: (r) => (
        <div className="min-w-0">
          <p className="pw-mono truncate text-[13px]">{r.path ?? '—'}</p>
          {r.host && <p className="truncate text-[11px] text-fg-subtle">{r.host}</p>}
        </div>
      ),
    },
    {
      key: 'status_code',
      header: t('pages.logs.statusCode'),
      accessor: (r) => r.status_code ?? 0,
      sortable: true,
      align: 'center',
      width: '1%',
      cell: (r) =>
        r.status_code ? (
          <Badge tone={statusTone(r.status_code)}>{r.status_code}</Badge>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
    },
    {
      key: 'cache_status',
      header: t('pages.logs.cacheStatus'),
      accessor: (r) => r.cache_status ?? '',
      width: '1%',
      cell: (r) =>
        r.cache_status ? (
          <span
            className={cn(
              'pw-mono text-xs',
              r.cache_status === 'hit' ? 'text-fg-success' : 'text-fg-subtle',
            )}
          >
            {r.cache_status}
          </span>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
    },
    {
      key: 'size',
      header: t('pages.logs.size'),
      accessor: (r) => r.response_size ?? 0,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span className="tabular-nums text-[13px] text-fg-subtle">
          {r.response_size != null ? formatSize(r.response_size) : '—'}
        </span>
      ),
    },
    {
      key: 'latency',
      header: t('pages.logs.latency'),
      accessor: (r) => r.total_latency_ms ?? 0,
      sortable: true,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span className="tabular-nums text-[13px]">
          {r.total_latency_ms != null ? formatLatency(r.total_latency_ms) : '—'}
        </span>
      ),
    },
  ]

  const controlColumns: Column<ControlPlaneAccessLog>[] = [
    {
      key: 'timestamp',
      header: t('pages.logs.time'),
      accessor: (r) => r.timestamp,
      sortable: true,
      width: '1%',
      cell: (r) => (
        <span className="pw-mono whitespace-nowrap text-xs text-fg-subtle">
          {formatDateTime(r.timestamp)}
        </span>
      ),
    },
    {
      key: 'client_ip',
      header: t('pages.logs.clientIp'),
      accessor: (r) => r.client_ip,
      sortable: true,
      cell: (r) => (
        <div className="min-w-0">
          <p className="pw-mono truncate text-[13px] text-fg">{r.client_ip}</p>
          {r.reason && (
            <p className="truncate text-[11px] text-fg-subtle">{r.reason}</p>
          )}
        </div>
      ),
    },
    {
      key: 'method',
      header: t('pages.logs.method'),
      accessor: (r) => r.method,
      width: '1%',
      cell: (r) => <span className="pw-mono text-xs text-fg-subtle">{r.method}</span>,
    },
    {
      key: 'path',
      header: t('pages.logs.path'),
      accessor: (r) => r.path,
      cell: (r) => (
        <div className="min-w-0">
          <p className="pw-mono truncate text-[13px]">
            {r.path}
            {r.query_string ? `?${r.query_string}` : ''}
          </p>
          {r.host && <p className="truncate text-[11px] text-fg-subtle">{r.host}</p>}
        </div>
      ),
    },
    {
      key: 'user_email',
      header: t('pages.logs.userEmail'),
      accessor: (r) => r.user_email ?? '',
      cell: (r) =>
        r.user_email ? (
          <span className="truncate text-[13px]">{r.user_email}</span>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
    },
    {
      key: 'action',
      header: t('pages.logs.action'),
      accessor: (r) => r.action,
      width: '1%',
      cell: (r) => (
        <Badge tone={CONTROL_ACTION_TONE[r.action] ?? 'neutral'}>
          {t(`actions.${r.action}`, r.action)}
        </Badge>
      ),
    },
    {
      key: 'status_code',
      header: t('pages.logs.statusCode'),
      accessor: (r) => r.status_code ?? 0,
      sortable: true,
      align: 'center',
      width: '1%',
      cell: (r) =>
        r.status_code ? (
          <Badge tone={statusTone(r.status_code)}>{r.status_code}</Badge>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
    },
    {
      key: 'latency',
      header: t('pages.logs.latency'),
      accessor: (r) => r.latency_ms ?? 0,
      sortable: true,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span className="tabular-nums text-[13px]">
          {r.latency_ms != null ? formatLatency(r.latency_ms) : '—'}
        </span>
      ),
    },
  ]

  const tabs: { value: Tab; label: string; icon: typeof ShieldWarning; count?: number }[] = [
    { value: 'security', label: t('pages.logs.securityTab'), icon: ShieldWarning },
    { value: 'access', label: t('pages.logs.accessTab'), icon: ListDashes },
    ...(isAdmin
      ? [
          {
            value: 'control' as Tab,
            label: t('pages.logs.controlTab'),
            icon: LockKey,
          },
        ]
      : []),
  ]

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.logs.title')}
        description={t('pages.logs.description')}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              loading={active.isFetching}
              onClick={() => active.refetch()}
              icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
            >
              {t('common.refresh')}
            </Button>
            <Button
              variant="secondary"
              onClick={exportJson}
              disabled={rows.length === 0}
              icon={<DownloadSimple weight="duotone" className="h-4 w-4" />}
            >
              {t('pages.logs.export')}
            </Button>
            {canWrite && tab !== 'control' && (
              <Button
                variant="ghost"
                className="hover:text-fg-danger"
                onClick={() => setPurgeOpen(true)}
                icon={<Trash weight="duotone" className="h-4 w-4" />}
              >
                {t('pages.logs.purge')}
              </Button>
            )}
          </div>
        }
      />

      <Callout
        dismissKey="logs"
        className="mb-4"
        tone="brand"
        icon={<FileMagnifyingGlass weight="duotone" className="h-5 w-5" />}
        title={t('pages.logs.overviewTitle')}
      >
        {t('pages.logs.overview')}
      </Callout>

      {/* Tabs */}
      <div className="mb-4 flex gap-1 border-b border-line">
        {tabs.map((entry) => {
          const Icon = entry.icon
          return (
            <button
              key={entry.value}
              type="button"
              onClick={() =>
                updateQuery({
                  tab: entry.value === 'security' ? null : entry.value,
                })
              }
              className={cn(
                '-mb-px inline-flex items-center gap-2 border-b-2 px-3 py-2.5 text-sm font-medium transition-colors',
                tab === entry.value
                  ? 'border-brand text-fg-strong'
                  : 'border-transparent text-fg-subtle hover:text-fg',
              )}
            >
              <Icon weight="duotone" className="h-4 w-4" />
              {entry.label}
            </button>
          )
        })}
      </div>

      {/* Filter bar */}
      <Card className="mb-4">
        <CardBody>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="sm:col-span-2 lg:col-span-4">
              <label
                htmlFor="log-search"
                className="mb-1.5 block text-[13px] font-medium text-fg-subtle"
              >
                {t('pages.logs.search')}
              </label>
              <div className="flex items-center gap-2">
                <Input
                  id="log-search"
                  containerClassName="flex-1"
                  value={draft}
                  placeholder={t('pages.logs.searchPlaceholder')}
                  prefixIcon={<MagnifyingGlass weight="duotone" />}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') commitSearch()
                  }}
                />
                <Button variant="secondary" onClick={commitSearch}>
                  {t('common.search')}
                </Button>
              </div>
              {parsedQuery.unknown.length > 0 && (
                <p className="mt-1.5 text-xs text-fg-warning">
                  {t('pages.logs.searchUnknown', {
                    tokens: parsedQuery.unknown.join(' '),
                  })}
                </p>
              )}
              <p className="mt-1.5 text-xs text-fg-subtle">
                {t('pages.logs.searchHint')}
              </p>
            </div>
            <Select
              label={t('pages.logs.timeRange')}
              value={preset}
              options={RANGE_PRESETS.map((p) => ({
                value: p.value,
                label:
                  p.value === 'custom'
                    ? t('pages.logs.customRange')
                    : t('pages.logs.lastN', { range: p.label }),
              }))}
              onChange={(e) => setPreset(e.target.value)}
            />
            <Input
              type="datetime-local"
              label={t('pages.logs.from')}
              value={fromValue}
              max={toValue}
              onChange={(e) =>
                updateQuery({ from: e.target.value, preset: 'custom' })
              }
            />
            <Input
              type="datetime-local"
              label={t('pages.logs.to')}
              value={toValue}
              min={fromValue}
              onChange={(e) =>
                updateQuery({ to: e.target.value, preset: 'custom' })
              }
            />
            <Select
              label={t('pages.logs.site')}
              value={siteId}
              options={siteOptions}
              onChange={(e) => updateQuery({ site_id: e.target.value })}
              disabled={tab === 'control'}
              hint={tab === 'control' ? t('pages.logs.controlNoSite') : undefined}
            />
          </div>

          <div className="mt-3 flex items-center justify-between gap-3 border-t border-line pt-3">
            <span className="inline-flex items-center gap-1.5 text-xs text-fg-subtle">
              <Funnel weight="duotone" className="h-3.5 w-3.5" />
              {t('pages.logs.resultCount', { total: formatNumber(total) })}
            </span>
            <Button size="sm" variant="ghost" onClick={resetQuery}>
              {t('common.reset')}
            </Button>
          </div>
        </CardBody>
      </Card>

      {/* Results */}
      {active.isError && !active.data ? (
        <ErrorState
          error={active.error}
          onRetry={() => active.refetch()}
          retrying={active.isFetching}
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            {active.isPending ? (
              <SkeletonRows rows={10} columns={tab === 'security' ? 7 : 8} />
            ) : rows.length === 0 ? (
              <EmptyState
                className="py-14"
                icon={
                  tab === 'security' ? (
                    <ShieldWarning weight="duotone" className="h-8 w-8" />
                  ) : tab === 'access' ? (
                    <ListDashes weight="duotone" className="h-8 w-8" />
                  ) : (
                    <LockKey weight="duotone" className="h-8 w-8" />
                  )
                }
                title={t('pages.logs.empty')}
                description={
                  tab === 'control'
                    ? t('pages.logs.controlEmptyDescription')
                    : t('pages.logs.emptyDescription')
                }
                action={
                  <Button variant="secondary" onClick={resetQuery}>
                    {t('common.reset')}
                  </Button>
                }
              />
            ) : (
              <>
                {tab === 'security' ? (
                  <Table
                    columns={securityColumns}
                    data={rows as SecurityEvent[]}
                    rowKey={(r) => String(r.id)}
                    dense
                    onRowClick={(r) => setSelectedEvent(r)}
                  />
                ) : tab === 'access' ? (
                  <Table
                    columns={accessColumns}
                    data={rows as AccessLog[]}
                    rowKey={(r) => String(r.id)}
                    dense
                    onRowClick={(r) => setSelectedLog(r)}
                  />
                ) : (
                  <Table
                    columns={controlColumns}
                    data={rows as ControlPlaneAccessLog[]}
                    rowKey={(r) => String(r.id)}
                    dense
                    onRowClick={(r) => setSelectedControl(r)}
                  />
                )}
                <Pagination
                  page={page}
                  pageSize={pageSize}
                  total={total}
                  onChange={setPage}
                  pageSizeOptions={PAGE_SIZES}
                  onPageSizeChange={setPageSize}
                />
              </>
            )}
          </CardBody>
        </Card>
      )}

      {/* Security event detail */}
      <Dialog
        open={selectedEvent !== null}
        onClose={() => setSelectedEvent(null)}
        size="lg"
        title={t('pages.logs.eventDetail')}
        description={
          selectedEvent
            ? `${selectedEvent.method} ${selectedEvent.path ?? ''}`.trim()
            : undefined
        }
        footer={
          <Button variant="ghost" onClick={() => setSelectedEvent(null)}>
            {t('common.close')}
          </Button>
        }
      >
        {selectedEvent && (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={ACTION_TONE[selectedEvent.action] ?? 'neutral'}>
                {t(`actions.${selectedEvent.action}`, selectedEvent.action)}
              </Badge>
              {selectedEvent.score != null && (
                <Badge tone={selectedEvent.score >= 50 ? 'danger' : 'neutral'}>
                  {t('pages.logs.wafScore')}: {selectedEvent.score}
                </Badge>
              )}
            </div>
            {selectedRequestId && (
              <RequestIdBar
                value={selectedRequestId}
                onSearch={() =>
                  searchByRequestId(
                    selectedRequestId,
                    selectedEvent.timestamp,
                  )
                }
                secondary={{
                  label: t('pages.logs.accessTab'),
                  onClick: () =>
                    searchByRequestId(
                      selectedRequestId,
                      selectedEvent.timestamp,
                      'access',
                    ),
                }}
              />
            )}
            <WhyPanel
              event={selectedEvent}
              explanation={explanation}
              loading={explanationQuery.isPending}
              error={explanationQuery.isError}
              onRetry={() => explanationQuery.refetch()}
              onSearchRule={searchByRule}
            />
            <DefinitionGrid
              rows={[
                [t('pages.logs.time'), formatDateTime(selectedEvent.timestamp)],
                [t('pages.logs.clientIp'), selectedEvent.client_ip],
                [t('pages.logs.country'), selectedEvent.country_code?.toUpperCase()],
                [t('pages.logs.method'), selectedEvent.method],
                [t('pages.logs.host'), selectedEvent.host],
                [t('pages.logs.path'), selectedEvent.path],
                [
                  ruleLabel,
                  selectedEvent.rule_id ? (
                    <RuleValue
                      event={selectedEvent}
                      matched={primaryRule}
                    />
                  ) : undefined,
                ],
                [
                  t('pages.logs.agent'),
                  selectedEvent.agent_id ? (
                    <Link
                      to="/agents"
                      className="text-link hover:underline"
                    >
                      {selectedEvent.agent_id}
                    </Link>
                  ) : undefined,
                ],
                [
                  t('pages.logs.site'),
                  selectedEvent.site_id ? (
                    <Link
                      to={`/sites/${selectedEvent.site_id}`}
                      className="text-link hover:underline"
                    >
                      {selectedSite?.domain ?? selectedEvent.site_id}
                    </Link>
                  ) : undefined,
                ],
              ]}
            />
            {selectedEvent.waf_details && (
              <div>
                <p className="mb-1.5 text-[13px] font-medium text-fg">
                  {t('pages.logs.wafDetails')}
                </p>
                <pre className="pw-mono max-h-56 overflow-auto rounded-md border border-line bg-recessed px-3 py-2 text-xs text-fg-subtle">
                  {selectedEvent.waf_details}
                </pre>
              </div>
            )}
            <div>
              <p className="mb-1.5 text-[13px] font-medium text-fg">
                {t('pages.logs.rawCapture')}
              </p>
              {rawRequestQuery.isPending ? (
                <p className="text-xs text-fg-subtle">{t('common.loading')}</p>
              ) : rawRequest ? (
                <RawRequestPanel
                  log={rawRequest}
                  onCopy={() => copyCurl(rawRequest)}
                />
              ) : (
                <p className="text-xs text-fg-subtle">
                  {t('pages.logs.rawRequestMissing')}
                </p>
              )}
            </div>
          </div>
        )}
      </Dialog>

      {/* Access log detail */}
      <Dialog
        open={selectedLog !== null}
        onClose={() => setSelectedLog(null)}
        size="lg"
        title={
          <span className="flex items-center gap-2">
            {t('pages.logs.accessDetail')}
            {selectedLog?.status_code != null && (
              <Badge tone={statusTone(selectedLog.status_code)} size="sm">
                {selectedLog.status_code}
              </Badge>
            )}
          </span>
        }
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" onClick={() => setSelectedLog(null)}>
              {t('common.close')}
            </Button>
            <Button
              variant="secondary"
              icon={<Terminal weight="duotone" className="h-4 w-4" />}
              onClick={() => selectedLog && copyCurl(selectedLog)}
            >
              {t('pages.logs.copyCurl')}
            </Button>
          </div>
        }
      >
        {selectedLog && (
          <div className="flex flex-col gap-4">
            {(selectedLog.cache_status || selectedLog.tls_version) && (
              <div className="flex flex-wrap items-center gap-2">
                {selectedLog.cache_status && (
                  <Badge tone={selectedLog.cache_status === 'hit' ? 'success' : 'neutral'}>
                    {selectedLog.cache_status}
                  </Badge>
                )}
                {selectedLog.tls_version && <Badge tone="info">{selectedLog.tls_version}</Badge>}
              </div>
            )}
            {selectedLogRequestId && (
              <RequestIdBar
                value={selectedLogRequestId}
                onSearch={() =>
                  searchByRequestId(
                    selectedLogRequestId,
                    selectedLog.timestamp,
                  )
                }
                secondary={{
                  label: t('pages.logs.securityTab'),
                  onClick: () =>
                    searchByRequestId(
                      selectedLogRequestId,
                      selectedLog.timestamp,
                      'security',
                    ),
                }}
              />
            )}
            <DefinitionGrid
              rows={[
                [t('pages.logs.time'), formatDateTime(selectedLog.timestamp)],
                [t('pages.logs.clientIp'), selectedLog.client_ip],
                [t('pages.logs.country'), selectedLog.country_code?.toUpperCase()],
                [t('pages.logs.host'), selectedLog.host],
                [t('pages.logs.size'), selectedLog.response_size != null ? formatSize(selectedLog.response_size) : undefined],
                [t('pages.logs.upstream'), selectedLog.upstream_addr],
                [
                  t('pages.logs.upstreamLatency'),
                  selectedLog.upstream_latency_ms != null
                    ? formatLatency(selectedLog.upstream_latency_ms)
                    : undefined,
                ],
                [
                  t('pages.logs.latency'),
                  selectedLog.total_latency_ms != null
                    ? formatLatency(selectedLog.total_latency_ms)
                    : undefined,
                ],
                [t('pages.logs.cacheStatus'), selectedLog.cache_status],
              ]}
            />
            <RawSection
              title={t('pages.logs.request')}
              truncated={selectedLog.request_body_truncated}
              lines={requestLines(selectedLog, t('pages.logs.noRequestBody'))}
            />
            <RawSection
              title={t('pages.logs.response')}
              size={
                selectedLog.response_body_size != null
                  ? formatSize(selectedLog.response_body_size)
                  : null
              }
              truncated={selectedLog.response_body_truncated}
              lines={responseLines(selectedLog, t('pages.logs.noResponseBody'))}
            />
          </div>
        )}
      </Dialog>

      {/* Control plane request detail */}
      <Dialog
        open={selectedControl !== null}
        onClose={() => setSelectedControl(null)}
        size="lg"
        title={t('pages.logs.controlDetail')}
        description={
          selectedControl
            ? `${selectedControl.method} ${selectedControl.path}`.trim()
            : undefined
        }
        footer={
          <Button variant="ghost" onClick={() => setSelectedControl(null)}>
            {t('common.close')}
          </Button>
        }
      >
        {selectedControl && (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-2">
              {selectedControl.status_code && (
                <Badge tone={statusTone(selectedControl.status_code)}>
                  {selectedControl.status_code}
                </Badge>
              )}
              <Badge tone={CONTROL_ACTION_TONE[selectedControl.action] ?? 'neutral'}>
                {t(`actions.${selectedControl.action}`, selectedControl.action)}
              </Badge>
            </div>
            {selectedControlRequestId && (
              <RequestIdBar
                value={selectedControlRequestId}
                onSearch={() =>
                  searchByRequestId(
                    selectedControlRequestId,
                    selectedControl.timestamp,
                  )
                }
              />
            )}
            <DefinitionGrid
              rows={[
                [t('pages.logs.time'), formatDateTime(selectedControl.timestamp)],
                [t('pages.logs.clientIp'), selectedControl.client_ip],
                [t('pages.logs.method'), selectedControl.method],
                [t('pages.logs.host'), selectedControl.host],
                [t('pages.logs.path'), selectedControl.path],
                [t('pages.logs.queryString'), selectedControl.query_string],
                [t('pages.logs.statusCode'), selectedControl.status_code?.toString()],
                [
                  t('pages.logs.latency'),
                  selectedControl.latency_ms != null
                    ? formatLatency(selectedControl.latency_ms)
                    : undefined,
                ],
                [t('pages.logs.userEmail'), selectedControl.user_email],
                [t('pages.logs.userId'), selectedControl.user_id],
                [t('pages.logs.referer'), selectedControl.referer],
              ]}
            />
            {selectedControl.reason && (
              <div>
                <p className="mb-1.5 text-[13px] font-medium text-fg">
                  {t('pages.logs.reason')}
                </p>
                <p className="pw-mono break-all rounded-md border border-line bg-recessed px-3 py-2 text-xs text-fg-subtle">
                  {selectedControl.reason}
                </p>
              </div>
            )}
            {selectedControl.user_agent && (
              <div>
                <p className="mb-1.5 text-[13px] font-medium text-fg">
                  {t('pages.logs.userAgent')}
                </p>
                <p className="pw-mono break-all rounded-md border border-line bg-recessed px-3 py-2 text-xs text-fg-subtle">
                  {selectedControl.user_agent}
                </p>
              </div>
            )}
          </div>
        )}
      </Dialog>

      {/* Purge */}
      <ConfirmDialog
        open={purgeOpen}
        onClose={() => setPurgeOpen(false)}
        onConfirm={() => purge.mutate()}
        title={t('pages.logs.purgeTitle')}
        description={t('pages.logs.purgeDescription')}
        confirmLabel={t('pages.logs.purge')}
        loading={purge.isPending}
      >
        <div className="flex flex-col gap-3">
          <Input
            type="number"
            label={t('pages.logs.olderThanDays')}
            value={purgeDays}
            min={1}
            max={3650}
            hint={t('pages.logs.purgeScope', {
              scope: siteId
                ? (sites ?? []).find((s) => s.id === siteId)?.domain ?? siteId
                : t('pages.logs.allSites'),
            })}
            onChange={(e) => setPurgeDays(Number(e.target.value))}
          />
        </div>
      </ConfirmDialog>
    </div>
  )
}

/** Two-column label/value list used by both detail dialogs. */
function DefinitionGrid({ rows }: { rows: [string, ReactNode][] }) {
  const visible = rows.filter(([, value]) => value !== null && value !== undefined && value !== '')
  if (visible.length === 0) return null
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
      {visible.map(([label, value]) => (
        <div key={label} className="flex min-w-0 items-baseline justify-between gap-3 border-b border-line/60 pb-1.5">
          <dt className="shrink-0 text-xs text-fg-subtle">{label}</dt>
          <dd className="pw-mono min-w-0 break-all text-right text-[13px] text-fg">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

/**
 * One raw HTTP message, colored per token. Every piece renders as a React text
 * node — never markup — so bytes from the wire stay inert by construction.
 */
function RawMessage({ lines }: { lines: RawLine[] }) {
  return (
    <pre className="pw-mono max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md border border-line bg-recessed px-3 py-2 text-xs leading-relaxed text-fg">
      {lines.map((line, index) => (
        <Fragment key={index}>
          {line.map((token, tokenIndex) => (
            <span key={tokenIndex} className={token.tone}>
              {token.text}
            </span>
          ))}
          {'\n'}
        </Fragment>
      ))}
    </pre>
  )
}

/** A captioned raw message with its capture notes (size, truncation). */
function RawSection({
  title,
  size,
  truncated,
  lines,
}: {
  title: string
  size?: string | null
  truncated?: boolean | null
  lines: RawLine[]
}) {
  const { t } = useTranslation()
  return (
    <div>
      <p className="mb-1.5 flex flex-wrap items-center gap-2 text-[13px] font-medium text-fg">
        {title}
        {size && <span className="text-xs font-normal text-fg-subtle">{size}</span>}
        {truncated && <Badge tone="warning">{t('pages.logs.bodyTruncated')}</Badge>}
      </p>
      <RawMessage lines={lines} />
    </div>
  )
}

/** Raw request/response captured for a security event, plus a curl replay button. */
function RawRequestPanel({ log, onCopy }: { log: AccessLog; onCopy: () => void }) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-col gap-3 rounded-md border border-line px-3 py-3">
      <div className="flex items-center justify-between gap-2">
        <span className="pw-mono flex min-w-0 items-center gap-2 text-xs text-fg-subtle">
          {log.status_code != null && (
            <Badge tone={statusTone(log.status_code)}>{log.status_code}</Badge>
          )}
          <span className="truncate">
            {log.method} {log.path ?? '/'}
            {log.scheme ? ` · ${log.scheme}` : ''}
          </span>
        </span>
        <Button
          size="sm"
          variant="ghost"
          icon={<Terminal weight="duotone" className="h-4 w-4" />}
          onClick={onCopy}
        >
          {t('pages.logs.copyCurl')}
        </Button>
      </div>
      <RawSection
        title={t('pages.logs.request')}
        truncated={log.request_body_truncated}
        lines={requestLines(log, t('pages.logs.noRequestBody'))}
      />
      <RawSection
        title={t('pages.logs.response')}
        size={log.response_body_size != null ? formatSize(log.response_body_size) : null}
        truncated={log.response_body_truncated}
        lines={responseLines(log, t('pages.logs.noResponseBody'))}
      />
    </div>
  )
}

/** Copy and jump actions for a request id, shared by all three detail dialogs. */
function RequestIdBar({
  value,
  onSearch,
  secondary,
}: {
  value: string
  onSearch: () => void
  secondary?: { label: string; onClick: () => void }
}) {
  const { t } = useTranslation()
  const toast = useToast()

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      toast.success(t('pages.logs.copied'))
    } catch {
      toast.error(t('pages.logs.copyFailed'))
    }
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-line bg-recessed px-3 py-2">
      <div className="min-w-0">
        <p className="text-[10px] font-medium uppercase tracking-wide text-fg-subtle">
          {t('pages.logs.requestId')}
        </p>
        <code className="pw-mono block break-all text-[13px] text-fg">
          {value}
        </code>
      </div>
      <div className="flex items-center gap-1">
        <Button
          size="sm"
          variant="secondary"
          icon={<MagnifyingGlass weight="duotone" className="h-4 w-4" />}
          onClick={onSearch}
        >
          {t('pages.logs.searchLogs')}
        </Button>
        {secondary && (
          <Button size="sm" variant="ghost" onClick={secondary.onClick}>
            {secondary.label}
          </Button>
        )}
        <Button
          size="icon"
          variant="ghost"
          aria-label={t('pages.logs.copyRequestId')}
          title={t('pages.logs.copyRequestId')}
          icon={<Copy weight="duotone" className="h-4 w-4" />}
          onClick={copy}
        />
      </div>
    </div>
  )
}

/** The rule id plus its provenance, without linking a built-in id to a page
 * that cannot show it. Only a site custom rule has a reachable editor. */
function RuleValue({
  event,
  matched,
}: {
  event: SecurityEvent
  matched?: MatchedRule
}) {
  const { t } = useTranslation()
  if (!event.rule_id) return null
  const source = matched?.source
  const body = (
    <span className="inline-flex min-w-0 flex-wrap items-center justify-end gap-1.5">
      <code className="pw-mono break-all">{event.rule_id}</code>
      {source && (
        <span className="text-[11px] text-fg-subtle">
          {t(`pages.logs.ruleSources.${source}`, source)}
        </span>
      )}
    </span>
  )
  if (matched?.source === 'site_rule' && event.site_id) {
    return (
      <Link
        to={`/sites/${event.site_id}/security/protection?rule=${encodeURIComponent(event.rule_id)}`}
        className="text-link hover:underline"
      >
        {body}
      </Link>
    )
  }
  return body
}

const WHY_VERDICT_TONE: Record<
  string,
  'danger' | 'warning' | 'info' | 'success' | 'neutral'
> = {
  blocked: 'danger',
  monitored: 'warning',
  challenged: 'info',
  allowed: 'success',
  unknown: 'neutral',
}

type RuleSourceTone = 'neutral' | 'brand' | 'info' | 'warning' | 'danger' | 'success'

const RULE_SOURCE_TONE: Record<string, RuleSourceTone> = {
  managed: 'brand',
  signature: 'info',
  crs_import: 'info',
  policy: 'neutral',
  site_rule: 'neutral',
  patch: 'info',
  detector: 'neutral',
  unknown: 'warning',
}

function severityTone(severity: number): RuleSourceTone {
  if (severity >= 5) return 'danger'
  if (severity >= 4) return 'warning'
  return 'neutral'
}

function StepIcon({ status }: { status: string }) {
  if (status === 'unknown') {
    return (
      <Question
        weight="duotone"
        className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning"
        aria-hidden
      />
    )
  }
  if (status === 'miss') {
    return (
      <MinusCircle
        weight="duotone"
        className="mt-0.5 h-4 w-4 shrink-0 text-fg-subtle"
        aria-hidden
      />
    )
  }
  return (
    <Info
      weight="duotone"
      className="mt-0.5 h-4 w-4 shrink-0 text-fg-subtle"
      aria-hidden
    />
  )
}

function DecisionStep({ step }: { step: ExplanationStep }) {
  const { t } = useTranslation()
  return (
    <li className="grid grid-cols-[72px_1fr] items-start gap-2 sm:grid-cols-[92px_1fr]">
      <span className="pt-0.5 text-[10px] font-medium uppercase tracking-wide text-fg-subtle">
        {t(`pages.logs.stages.${step.stage}`, step.stage)}
      </span>
      <div className="min-w-0">
        <p className="flex items-start gap-1.5 text-[13px] font-medium text-fg">
          <StepIcon status={step.status} />
          <span>{step.title}</span>
        </p>
        <p className="mt-0.5 text-[12px] text-fg-subtle">{step.detail}</p>
      </div>
    </li>
  )
}

function MatchedRuleRow({
  rule,
  event,
  onSearchRule,
}: {
  rule: MatchedRule
  event: SecurityEvent
  onSearchRule: (ruleId: string) => void
}) {
  const { t } = useTranslation()
  return (
    <li className="flex flex-col gap-1 py-2 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-[13px] font-medium text-fg">{rule.name}</span>
        <code className="text-[11px] text-fg-subtle">{rule.id}</code>
        <Badge size="sm" tone={RULE_SOURCE_TONE[rule.source] ?? 'neutral'}>
          {t(`pages.logs.ruleSources.${rule.source}`, rule.source)}
        </Badge>
        {rule.deciding && (
          <Badge size="sm" tone="danger">
            {t('pages.logs.deciding')}
          </Badge>
        )}
        {rule.severity != null && (
          <Badge size="sm" tone={severityTone(rule.severity)}>
            {t('pages.logs.severity', { severity: rule.severity })}
          </Badge>
        )}
        {rule.action && (
          <Badge size="sm" tone={ACTION_TONE[rule.action] ?? 'neutral'}>
            {rule.action}
          </Badge>
        )}
      </div>
      <p className="text-[12px] text-fg-subtle">{rule.detail}</p>
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          className="text-[12px] text-link hover:underline"
          onClick={() => onSearchRule(rule.id)}
        >
          {t('pages.logs.searchRuleEvents')}
        </button>
        {rule.source === 'site_rule' && event.site_id && (
          <Link
            to={`/sites/${event.site_id}/security/protection?rule=${encodeURIComponent(rule.id)}`}
            className="inline-flex w-fit items-center gap-1 text-[12px] text-link hover:underline"
          >
            {t('pages.logs.openRule')}
            <ArrowSquareOut weight="duotone" className="h-3.5 w-3.5" aria-hidden />
          </Link>
        )}
      </div>
    </li>
  )
}

/**
 * "Why was this blocked?" - names the rule that actually decided the verdict,
 * lists every other match with its source, and keeps the non-events behind a
 * disclosure. The old panel showed the first stored rule id (often a weak
 * signature) and every miss, which buried the real cause.
 */
function WhyPanel({
  event,
  explanation,
  loading,
  error,
  onRetry,
  onSearchRule,
}: {
  event: SecurityEvent
  explanation: EventExplanation | null
  loading: boolean
  error: boolean
  onRetry: () => void
  onSearchRule: (ruleId: string) => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const verdict =
    explanation?.verdict ??
    (event.action === 'block' ? 'blocked' : event.action)
  const isBlocked = verdict === 'blocked' || verdict === 'challenged'
  const matched = explanation?.matched_rules ?? []
  const deciding = matched.find((rule) => rule.deciding)
  const title = isBlocked
    ? t('pages.logs.whyTitle')
    : t('pages.logs.whyTitleOther')
  const heading = deciding
    ? null
    : explanation
      ? t('pages.logs.noSingleRule')
      : null
  const firstMatchNote =
    explanation?.blocked_by &&
    event.rule_id &&
    event.rule_id.toLowerCase() !== explanation.blocked_by.toLowerCase()
      ? t('pages.logs.firstMatchNote', {
          first: event.rule_id,
          deciding: explanation.blocked_by,
        })
      : null
  // With the richer matched-rule list the chain step for the deciding rule is
  // redundant. Keep it when an older control plane returns no list.
  const chain = explanation
    ? explanation.steps.filter(
        (step) =>
          step.stage !== 'event' &&
          (step.stage !== 'waf_rule' || matched.length === 0),
      )
    : []
  const hits = chain.filter((step) => step.status !== 'miss')
  const misses = chain.filter((step) => step.status === 'miss')

  return (
    <section className="rounded-md border border-line">
      <div className="flex items-start justify-between gap-3 px-3 py-3">
        <div className="min-w-0 flex-1">
          <p className="text-[13px] font-medium text-fg">{title}</p>
          {loading ? (
            <p className="mt-2 text-xs text-fg-subtle">
              {t('pages.logs.whyLoading')}
            </p>
          ) : error ? (
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <p className="text-xs text-fg-danger">
                {t('pages.logs.whyFailed')}
              </p>
              <Button size="sm" variant="secondary" onClick={onRetry}>
                {t('common.retry')}
              </Button>
            </div>
          ) : explanation ? (
            <>
              <p className="mt-1 flex flex-wrap items-baseline gap-1.5 text-[14px] font-medium text-fg-strong">
                {deciding ? (
                  <>
                    <code className="pw-mono text-[13px]">{deciding.id}</code>
                    <span>{deciding.name}</span>
                  </>
                ) : (
                  heading
                )}
              </p>
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <Badge
                  tone={WHY_VERDICT_TONE[verdict] ?? 'neutral'}
                  dot
                >
                  {t(`pages.logs.verdicts.${verdict}`, verdict)}
                </Badge>
                {deciding && (
                  <>
                    <Badge
                      size="sm"
                      tone={RULE_SOURCE_TONE[deciding.source] ?? 'neutral'}
                    >
                      {t(
                        `pages.logs.ruleSources.${deciding.source}`,
                        deciding.source,
                      )}
                    </Badge>
                    {deciding.severity != null && (
                      <Badge
                        size="sm"
                        tone={severityTone(deciding.severity)}
                      >
                        {t('pages.logs.severity', {
                          severity: deciding.severity,
                        })}
                      </Badge>
                    )}
                  </>
                )}
                {matched.length > 0 && (
                  <span className="text-[11px] text-fg-subtle">
                    {t('pages.logs.matchedRuleCount', {
                      count: matched.length,
                    })}
                  </span>
                )}
              </div>
              {firstMatchNote && (
                <p className="mt-2 text-[12px] text-fg-subtle">
                  {firstMatchNote}
                </p>
              )}
            </>
          ) : null}
        </div>
        {explanation && (
          <Button
            size="sm"
            variant="ghost"
            className="shrink-0"
            aria-expanded={open}
            onClick={() => setOpen((value) => !value)}
          >
            {open ? t('pages.logs.whyHide') : t('pages.logs.whyDetails')}
          </Button>
        )}
      </div>

      {open && explanation && (
        <div className="space-y-4 border-t border-line px-3 py-3">
          {matched.length > 0 && (
            <div>
              <p className="mb-1.5 text-[10px] font-medium uppercase tracking-wide text-fg-subtle">
                {t('pages.logs.matchedRules')}
              </p>
              <ul className="divide-y divide-line rounded-md border border-line px-3">
                {matched.map((rule) => (
                  <MatchedRuleRow
                    key={rule.id}
                    rule={rule}
                    event={event}
                    onSearchRule={onSearchRule}
                  />
                ))}
              </ul>
            </div>
          )}

          {hits.length > 0 && (
            <div>
              <p className="mb-1.5 text-[10px] font-medium uppercase tracking-wide text-fg-subtle">
                {t('pages.logs.decisionChain')}
              </p>
              <ul className="space-y-3">
                {hits.map((step, index) => (
                  <DecisionStep key={`${step.stage}-${index}`} step={step} />
                ))}
              </ul>
            </div>
          )}

          {misses.length > 0 && (
            <details className="rounded-md border border-line">
              <summary className="cursor-pointer px-3 py-2 text-[12px] text-fg-subtle hover:text-fg">
                {t('pages.logs.whyChecks', { count: misses.length })}
              </summary>
              <ul className="space-y-3 border-t border-line px-3 py-3">
                {misses.map((step, index) => (
                  <DecisionStep key={`${step.stage}-${index}`} step={step} />
                ))}
              </ul>
            </details>
          )}

          {explanation.notes.length > 0 && (
            <div>
              <p className="mb-1 text-[10px] font-medium uppercase tracking-wide text-fg-subtle">
                {t('pages.logs.whyNotes')}
              </p>
              <ul className="list-disc space-y-1 pl-4 text-[12px] text-fg-subtle">
                {explanation.notes.map((note, index) => (
                  <li key={index}>{note}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </section>
  )
}

export default LogsPage
