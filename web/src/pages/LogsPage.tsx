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
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
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
import { downloadJson, fileTimestamp, logKeys, logsApi } from '@/api/logs'
import { apiProtectionApi, apiProtectionKeys } from '@/api/apiProtection'
import { useCanWrite, useSitesList } from '@/hooks'
import { useAuthStore } from '@/stores/authStore'
import { cn } from '@/lib/utils'
import { buildCurlCommand } from '@/lib/curl'
import { parseLogQuery } from '@/lib/logQuery'
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
  const to = new Date()
  const from = new Date(to.getTime() - 24 * 3600_000)
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

  const exportJson = () => {
    if (rows.length === 0) {
      toast.warning(t('pages.logs.exportEmpty'))
      return
    }
    const name = `pingwaf-${tab}-${fileTimestamp()}`
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
      accessor: (r) => r.rule_name ?? '',
      cell: (r) =>
        r.rule_name || r.rule_id ? (
          <div className="min-w-0">
            <p className="truncate text-[13px]">{r.rule_name ?? r.rule_id}</p>
            {r.rule_name && r.rule_id && (
              <p className="pw-mono truncate text-[11px] text-fg-subtle">{r.rule_id}</p>
            )}
          </div>
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
              {selectedEvent.rule_name && <Badge tone="info">{selectedEvent.rule_name}</Badge>}
            </div>
            <DefinitionGrid
              rows={[
                [t('pages.logs.time'), formatDateTime(selectedEvent.timestamp)],
                [t('pages.logs.clientIp'), selectedEvent.client_ip],
                [t('pages.logs.country'), selectedEvent.country_code?.toUpperCase()],
                [t('pages.logs.method'), selectedEvent.method],
                [t('pages.logs.host'), selectedEvent.host],
                [t('pages.logs.path'), selectedEvent.path],
                [
                  t('pages.logs.rule'),
                  selectedEvent.rule_id ? (
                    selectedEvent.site_id ? (
                      <Link
                        to={`/sites/${selectedEvent.site_id}/security/waf?rule=${selectedEvent.rule_id}`}
                        className="text-link hover:underline"
                      >
                        {selectedEvent.rule_id}
                      </Link>
                    ) : (
                      selectedEvent.rule_id
                    )
                  ) : undefined,
                ],
                [t('pages.logs.requestId'), selectedEvent.request_id],
                [t('pages.logs.agent'), selectedEvent.agent_id],
                [t('pages.logs.site'), selectedEvent.site_id],
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
                [t('pages.logs.requestId'), selectedLog.request_id],
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
                [t('pages.logs.requestId'), selectedControl.request_id],
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
          <dd className="pw-mono min-w-0 truncate text-right text-[13px] text-fg">{value}</dd>
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

export default LogsPage
