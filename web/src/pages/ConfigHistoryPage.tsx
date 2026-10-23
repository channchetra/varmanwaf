import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  ArrowCounterClockwise,
  ClockCounterClockwise,
  Info,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Callout } from '@/components/ui/Callout'
import { Card, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import {
  configVersionsApi,
  configVersionKeys,
  type ConfigVersionSummary,
} from '@/api/configVersions'
import { useAuthStore } from '@/stores/authStore'
import { useSitesList } from '@/hooks'
import { errorMessage } from '@/api/errors'
import { formatDateTime, formatNumber, formatRelative } from '@/lib/format'
import { scopeLabel, summaryRows, summaryTotals } from '@/lib/configHistory'

/** Source badge tones: routine edits, CLI, and operator rollbacks. */
const SOURCE_TONE: Record<string, 'neutral' | 'info' | 'warning'> = {
  api: 'neutral',
  cli: 'info',
  rollback: 'warning',
}

/**
 * Configuration history: every recorded configuration version - the
 * deployment-wide scope and each site - with its snapshot summary, and a
 * rollback that restores a scope exactly, records itself as a new version
 * and pushes the change to the agents.
 *
 * Administrator-only, mirroring the server routes; the page states that
 * rather than surfacing 403s.
 */
export function ConfigHistoryPage() {
  const { t } = useTranslation()
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'

  if (!isAdmin) {
    return (
      <div className="animate-slide-up">
        <PageHeader
          title={t('pages.configHistory.title')}
          description={t('pages.configHistory.description')}
        />
        <EmptyState
          icon={<ClockCounterClockwise weight="duotone" />}
          title={t('pages.configHistory.adminOnlyTitle')}
          description={t('pages.configHistory.adminOnly')}
        />
      </div>
    )
  }

  return <ConfigHistoryWorkspace />
}

function ConfigHistoryWorkspace() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  // `all` | `global` | a site id.
  const [scope, setScope] = useState('all')
  const [detailId, setDetailId] = useState<number | null>(null)
  const [pendingRollback, setPendingRollback] =
    useState<ConfigVersionSummary | null>(null)

  const { data: sites } = useSitesList()
  const siteName = useMemo(() => {
    const names = new Map<string, string>()
    for (const site of sites ?? []) {
      names.set(site.id, site.name || site.domain)
    }
    return names
  }, [sites])

  const scopeFilter = scope === 'all' ? undefined : scope
  const listQuery = useQuery({
    queryKey: configVersionKeys.list(scopeFilter),
    queryFn: () => configVersionsApi.list(scopeFilter, 100, 0),
  })
  const versions = useMemo(() => listQuery.data ?? [], [listQuery.data])

  const detailQuery = useQuery({
    queryKey: configVersionKeys.detail(detailId ?? 0),
    queryFn: () => configVersionsApi.get(detailId ?? 0),
    enabled: detailId !== null,
  })

  const rollback = useMutation({
    mutationFn: (id: number) => configVersionsApi.rollback(id),
    onSuccess: (result) => {
      toast.success(
        t('pages.configHistory.rolledBackTitle'),
        t('pages.configHistory.rolledBack', {
          restored: result.restored_version,
          created: result.new_version ?? '—',
          scope:
            result.scope === 'global'
              ? t('pages.configHistory.scopeGlobal')
              : siteName.get(result.scope) ?? result.scope,
        }),
      )
      setPendingRollback(null)
      void queryClient.invalidateQueries({ queryKey: configVersionKeys.all })
    },
    onError: (error) =>
      toast.error(t('pages.configHistory.rollbackFailed'), errorMessage(error)),
  })

  const columns: Column<ConfigVersionSummary>[] = useMemo(
    () => [
      {
        key: 'id',
        header: t('pages.configHistory.colVersion'),
        accessor: (row) => row.id,
        sortable: true,
        width: '86px',
        cell: (row) => (
          <span className="pw-mono text-[13px] font-medium text-fg-strong">
            #{row.id}
          </span>
        ),
      },
      {
        key: 'scope',
        header: t('pages.configHistory.colScope'),
        accessor: (row) => scopeLabel(row, row.site_id ? siteName.get(row.site_id) : undefined),
        cell: (row) =>
          row.site_id ? (
            <div className="min-w-0">
              <p className="truncate text-[13px] text-fg-strong">
                {scopeLabel(row, siteName.get(row.site_id))}
              </p>
              {row.site_domain && (
                <p className="truncate text-xs text-fg-subtle">
                  {row.site_domain}
                </p>
              )}
            </div>
          ) : (
            <Badge tone="brand">{t('pages.configHistory.scopeGlobal')}</Badge>
          ),
      },
      {
        key: 'source',
        header: t('pages.configHistory.colSource'),
        accessor: (row) => row.source,
        width: '104px',
        cell: (row) => (
          <Badge tone={SOURCE_TONE[row.source] ?? 'neutral'}>
            {t(`pages.configHistory.source_${row.source}`, row.source)}
          </Badge>
        ),
      },
      {
        key: 'actor',
        header: t('pages.configHistory.colActor'),
        accessor: (row) => row.actor ?? '',
        width: '220px',
        className: 'truncate',
        cell: (row) =>
          row.actor ? (
            <span className="text-[13px] text-fg">{row.actor}</span>
          ) : (
            <span className="text-[13px] text-fg-subtle">—</span>
          ),
      },
      {
        key: 'summary',
        header: t('pages.configHistory.colSummary'),
        accessor: (row) => summaryTotals(row.summary).rows,
        sortable: true,
        width: '150px',
        className: 'whitespace-nowrap',
        cell: (row) => {
          const totals = summaryTotals(row.summary)
          return (
            <span className="text-[13px] text-fg-subtle">
              {t('pages.configHistory.summaryLine', {
                tables: formatNumber(totals.tables),
                rows: formatNumber(totals.rows),
              })}
            </span>
          )
        },
      },
      {
        key: 'created_at',
        header: t('pages.configHistory.colRecorded'),
        accessor: (row) => row.created_at,
        sortable: true,
        width: '186px',
        className: 'whitespace-nowrap',
        cell: (row) => (
          <div className="min-w-0">
            <p
              className="text-[13px] text-fg-strong"
              title={formatDateTime(row.created_at)}
            >
              {formatRelative(row.created_at)}
            </p>
            <p className="text-xs text-fg-subtle">
              {formatDateTime(row.created_at)}
            </p>
          </div>
        ),
      },
      {
        key: 'actions',
        header: t('pages.configHistory.colActions'),
        align: 'right',
        width: '196px',
        className: 'whitespace-nowrap',
        cell: (row) => (
          <div className="flex items-center justify-end gap-1.5">
            <Button
              size="sm"
              variant="secondary"
              icon={<Info className="h-4 w-4" />}
              onClick={() => setDetailId(row.id)}
            >
              {t('pages.configHistory.detail')}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              disabled={rollback.isPending}
              icon={
                <ArrowCounterClockwise
                  weight="bold"
                  className="h-4 w-4 text-fg-warning"
                />
              }
              onClick={() => setPendingRollback(row)}
            >
              {t('pages.configHistory.rollback')}
            </Button>
          </div>
        ),
      },
    ],
    [t, siteName, rollback.isPending],
  )

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.configHistory.title')}
        description={t('pages.configHistory.description')}
      />

      <Callout
        dismissKey="confighistory"
        className="mb-4"
        tone="brand"
        icon={<ClockCounterClockwise weight="duotone" className="h-5 w-5" />}
        title={t('pages.configHistory.overviewTitle')}
      >
        {t('pages.configHistory.overview')}
      </Callout>

      <Card>
        <CardBody>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <Select
              containerClassName="w-64"
              value={scope}
              onChange={(event) => setScope(event.target.value)}
              options={[
                { value: 'all', label: t('pages.configHistory.filterAll') },
                { value: 'global', label: t('pages.configHistory.scopeGlobal') },
                ...(sites ?? []).map((site) => ({
                  value: site.id,
                  label: site.name || site.domain,
                })),
              ]}
            />
            <Button
              size="sm"
              variant="ghost"
              className="ml-auto"
              onClick={() => listQuery.refetch()}
            >
              <ArrowClockwise className="h-4 w-4" />
            </Button>
          </div>

          {listQuery.isError && !listQuery.data ? (
            <ErrorState
              error={listQuery.error}
              onRetry={() => listQuery.refetch()}
              retrying={listQuery.isFetching}
            />
          ) : listQuery.isPending ? (
            <SkeletonRows columns={7} rows={6} />
          ) : versions.length === 0 ? (
            <EmptyState
              icon={<ClockCounterClockwise weight="duotone" className="h-8 w-8" />}
              title={t('pages.configHistory.empty')}
              description={t('pages.configHistory.emptyDescription')}
            />
          ) : (
            <Table
              columns={columns}
              data={versions}
              rowKey={(row) => String(row.id)}
              dense
              fixed
            />
          )}
        </CardBody>
      </Card>

      {detailId !== null && (
        <Dialog
          open
          onClose={() => setDetailId(null)}
          title={t('pages.configHistory.detailTitle', { id: detailId })}
          className="max-w-2xl"
        >
          {detailQuery.isPending ? (
            <SkeletonRows rows={5} />
          ) : detailQuery.isError ? (
            <ErrorState
              error={detailQuery.error}
              onRetry={() => detailQuery.refetch()}
              retrying={detailQuery.isFetching}
            />
          ) : detailQuery.data ? (
            <div className="space-y-4">
              <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
                <DetailField
                  label={t('pages.configHistory.detailScope')}
                  value={
                    detailQuery.data.site_id
                      ? siteName.get(detailQuery.data.site_id) ??
                        detailQuery.data.site_id
                      : t('pages.configHistory.scopeGlobal')
                  }
                />
                <DetailField
                  label={t('pages.configHistory.detailSource')}
                  value={t(
                    `pages.configHistory.source_${detailQuery.data.source}`,
                    detailQuery.data.source,
                  )}
                />
                <DetailField
                  label={t('pages.configHistory.detailActor')}
                  value={detailQuery.data.actor ?? '—'}
                />
                <DetailField
                  label={t('pages.configHistory.detailRecorded')}
                  value={formatDateTime(detailQuery.data.created_at)}
                />
                <DetailField
                  label={t('pages.configHistory.detailHash')}
                  value={detailQuery.data.config_hash || '—'}
                  mono
                />
              </dl>

              <div>
                <p className="mb-2 text-sm font-medium text-fg">
                  {t('pages.configHistory.detailTables')}
                </p>
                {summaryRows(detailQuery.data.summary).length === 0 ? (
                  <p className="text-[13px] text-fg-subtle">
                    {t('pages.configHistory.detailEmpty')}
                  </p>
                ) : (
                  <div className="max-h-64 overflow-y-auto rounded-md border border-line">
                    <table className="w-full text-[13px]">
                      <tbody className="divide-y divide-line">
                        {summaryRows(detailQuery.data.summary).map((row) => (
                          <tr key={row.name}>
                            <td className="pw-mono px-3 py-1.5 text-fg">
                              {row.name}
                            </td>
                            <td className="px-3 py-1.5 text-right tabular-nums text-fg-subtle">
                              {formatNumber(row.count)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <p className="mt-2 text-[11px] text-fg-subtle">
                  {t('pages.configHistory.detailNote')}
                </p>
              </div>
            </div>
          ) : null}
        </Dialog>
      )}

      <ConfirmDialog
        open={pendingRollback !== null}
        onClose={() => setPendingRollback(null)}
        onConfirm={() =>
          pendingRollback && rollback.mutate(pendingRollback.id)
        }
        title={t('pages.configHistory.rollbackTitle', {
          id: pendingRollback?.id ?? 0,
        })}
        description={t('pages.configHistory.rollbackDescription', {
          scope: pendingRollback?.site_id
            ? scopeLabel(
                pendingRollback,
                siteName.get(pendingRollback.site_id),
              )
            : t('pages.configHistory.scopeGlobal'),
        })}
        confirmLabel={t('pages.configHistory.rollbackConfirm')}
        loading={rollback.isPending}
        tone="danger"
      />
    </div>
  )
}

function DetailField({
  label,
  value,
  mono = false,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-medium uppercase tracking-wide text-fg-subtle">
        {label}
      </dt>
      <dd
        className={`truncate text-[13px] text-fg ${mono ? 'pw-mono' : ''}`}
        title={value}
      >
        {value}
      </dd>
    </div>
  )
}

export default ConfigHistoryPage
