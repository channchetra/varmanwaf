import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Brain,
  BracketsCurly,
  CheckCircle,
  DownloadSimple,
  Info,
  WarningCircle,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Callout } from '@/components/ui/Callout'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Select } from '@/components/ui/Select'
import { SkeletonStat } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ErrorState'
import { useToast } from '@/components/ui/Toast'
import { errorMessage } from '@/api/errors'
import { apiAssetsApi, apiAssetsKeys } from '@/api/apiAssets'
import { formatDateTime, formatNumber } from '@/lib/format'
import { useCanWrite } from '@/hooks'

const WINDOW_OPTIONS = ['7', '14', '30']

/**
 * The observed API inventory: method+path aggregates from stored access logs,
 * each marked against the site's OpenAPI document, plus the declared
 * operations that saw no traffic. It is traffic, not a declaration - the
 * page says so where it matters.
 */
export function ApiAssetsPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()
  const [days, setDays] = useState('7')
  const [learnDays, setLearnDays] = useState('7')

  const query = useQuery({
    queryKey: apiAssetsKeys.list(siteId, Number(days)),
    queryFn: () => apiAssetsApi.list(siteId, Number(days)),
    enabled: Boolean(siteId),
  })
  const learnedQuery = useQuery({
    queryKey: apiAssetsKeys.learned(siteId),
    queryFn: () => apiAssetsApi.learned(siteId),
    enabled: Boolean(siteId),
  })

  const learn = useMutation({
    mutationFn: () => apiAssetsApi.learn(siteId, Number(learnDays)),
    onSuccess: (summary) => {
      toast.success(
        t('pages.apiAssets.learnDone', {
          endpoints: summary.endpoints,
          samples: summary.samples,
        }),
      )
      void queryClient.invalidateQueries({ queryKey: apiAssetsKeys.all })
    },
    onError: (error) =>
      toast.error(t('pages.apiAssets.learnFailed'), errorMessage(error)),
  })

  const setMode = useMutation({
    mutationFn: (payload: { id: string; mode: string }) =>
      apiAssetsApi.setOperationMode(siteId, payload.id, payload.mode),
    onSuccess: (saved) => {
      toast.success(
        t('pages.apiAssets.modeSaved', {
          path: saved.path,
          mode: t(`pages.apiAssets.mode_${saved.mode}`),
        }),
      )
      void queryClient.invalidateQueries({ queryKey: apiAssetsKeys.all })
    },
    onError: (error) =>
      toast.error(t('pages.apiAssets.modeFailed'), errorMessage(error)),
  })

  const data = query.data

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.apiAssets.title')}
        description={t('pages.apiAssets.description')}
      />

      <Callout
        className="mb-4"
        tone="brand"
        icon={<BracketsCurly weight="duotone" className="h-5 w-5" />}
        title={t('pages.apiAssets.overviewTitle')}
      >
        {t('pages.apiAssets.overview')}
      </Callout>

      {query.isError && !data ? (
        <ErrorState
          error={query.error}
          onRetry={() => query.refetch()}
          retrying={query.isFetching}
        />
      ) : !data ? (
        <SkeletonStat />
      ) : (
        <div className="flex flex-col gap-4">
          {/* Declared side */}
          <Card>
            <CardHeader
              title={t('pages.apiAssets.spec')}
              description={t('pages.apiAssets.specHint')}
              action={
                <Badge
                  tone={data.spec.configured ? 'success' : 'neutral'}
                  dot
                  size="sm"
                >
                  {data.spec.configured
                    ? t('pages.apiAssets.specConfigured')
                    : t('pages.apiAssets.specNotConfiguredBadge')}
                </Badge>
              }
            />
            <CardBody className="flex flex-col gap-2">
              {data.spec.parse_error ? (
                <p className="flex items-start gap-1.5 text-[13px] text-fg-warning">
                  <WarningCircle weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
                  {t('pages.apiAssets.specParseError', {
                    error: data.spec.parse_error,
                  })}
                </p>
              ) : data.spec.configured ? (
                <p className="text-[13px] text-fg">
                  {data.spec.title ?? t('pages.apiAssets.untitledSpec')}
                  {data.spec.version ? ` · v${data.spec.version}` : ''}
                  {' — '}
                  {t('pages.apiAssets.specCounts', {
                    paths: data.spec.paths,
                    operations: data.spec.operations,
                  })}
                </p>
              ) : (
                <p className="flex flex-wrap items-center gap-1.5 text-[13px] text-fg-subtle">
                  <Info weight="duotone" className="h-4 w-4" />
                  {t('pages.apiAssets.specNotConfigured')}
                  <Link
                    to={`/sites/${siteId}/security/protection`}
                    className="text-link hover:underline"
                  >
                    {t('pages.apiAssets.specSetLink')}
                  </Link>
                </p>
              )}
            </CardBody>
          </Card>

          {/* Observed side */}
          <Card>
            <CardHeader
              title={t('pages.apiAssets.observed')}
              description={t('pages.apiAssets.observedHint')}
              action={
                <Select
                  containerClassName="w-40"
                  value={days}
                  options={WINDOW_OPTIONS.map((value) => ({
                    value,
                    label: t('pages.apiAssets.windowDays', {
                      count: Number(value),
                    }),
                  }))}
                  onChange={(event) => setDays(event.target.value)}
                />
              }
            />
            <CardBody>
              {data.observed.length === 0 ? (
                <p className="py-8 text-center text-sm text-fg-subtle">
                  {t('pages.apiAssets.observedEmpty')}
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[13px]">
                    <thead>
                      <tr className="border-b border-line text-[11px] uppercase tracking-wide text-fg-subtle">
                        <th className="py-2 pr-3 font-semibold">
                          {t('pages.apiAssets.method')}
                        </th>
                        <th className="py-2 pr-3 font-semibold">
                          {t('pages.apiAssets.path')}
                        </th>
                        <th className="py-2 pr-3 font-semibold">
                          {t('pages.apiAssets.coverage')}
                        </th>
                        <th className="py-2 pr-3 text-right font-semibold">
                          {t('pages.apiAssets.requests')}
                        </th>
                        <th className="py-2 pr-3 text-right font-semibold">
                          {t('pages.apiAssets.errors')}
                        </th>
                        <th className="py-2 font-semibold">
                          {t('pages.apiAssets.lastSeen')}
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.observed.map((row) => (
                        <tr
                          key={`${row.method} ${row.path}`}
                          className="border-b border-line/60 last:border-0"
                        >
                          <td className="py-1.5 pr-3">
                            <span className="pw-mono font-medium text-fg-strong">
                              {row.method}
                            </span>
                          </td>
                          <td className="py-1.5 pr-3">
                            <span className="pw-mono text-fg">{row.path}</span>
                            {row.spec_path && row.spec_path !== row.path && (
                              <span className="ml-2 text-[11px] text-fg-subtle">
                                {t('pages.apiAssets.matches', {
                                  template: row.spec_path,
                                })}
                              </span>
                            )}
                          </td>
                          <td className="py-1.5 pr-3">
                            {row.in_spec ? (
                              <Badge tone="success" size="sm">
                                {t('pages.apiAssets.inSpec')}
                              </Badge>
                            ) : (
                              <Badge tone="warning" size="sm">
                                {t('pages.apiAssets.notInSpec')}
                              </Badge>
                            )}
                          </td>
                          <td className="py-1.5 pr-3 text-right tabular-nums text-fg">
                            {formatNumber(row.count)}
                          </td>
                          <td className="py-1.5 pr-3 text-right tabular-nums text-fg-subtle">
                            {row.errors > 0 ? formatNumber(row.errors) : '-'}
                          </td>
                          <td className="py-1.5 text-fg-subtle">
                            {formatDateTime(row.last_seen)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardBody>
          </Card>

          {/* Bounded learning: structures and counts, never values */}
          <Card>
            <CardHeader
              title={t('pages.apiAssets.learn')}
              description={t('pages.apiAssets.learnHint')}
              action={
                <div className="flex items-center gap-2">
                  <Select
                    containerClassName="w-36"
                    value={learnDays}
                    options={WINDOW_OPTIONS.map((value) => ({
                      value,
                      label: t('pages.apiAssets.windowDays', {
                        count: Number(value),
                      }),
                    }))}
                    onChange={(event) => setLearnDays(event.target.value)}
                  />
                  {canWrite && (
                    <Button
                      variant="secondary"
                      icon={<Brain weight="bold" className="h-4 w-4" />}
                      loading={learn.isPending}
                      onClick={() => learn.mutate()}
                    >
                      {t('pages.apiAssets.learnRun')}
                    </Button>
                  )}
                </div>
              }
            />
            <CardBody className="flex flex-col gap-3">
              {learn.data && (
                <p className="text-[13px] text-fg">
                  {t('pages.apiAssets.learnSummary', {
                    endpoints: learn.data.endpoints,
                    samples: learn.data.samples,
                    skipped:
                      learn.data.skipped_truncated +
                      learn.data.skipped_non_json,
                  })}
                  {learn.data.truncated_scan && (
                    <span className="ml-2 text-fg-warning">
                      {t('pages.apiAssets.learnTruncated')}
                    </span>
                  )}
                </p>
              )}
              {!learnedQuery.data || learnedQuery.data.length === 0 ? (
                <p className="py-4 text-center text-sm text-fg-subtle">
                  {t('pages.apiAssets.learnedEmpty')}
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[13px]">
                    <thead>
                      <tr className="border-b border-line text-[11px] uppercase tracking-wide text-fg-subtle">
                        <th className="py-2 pr-3 font-semibold">
                          {t('pages.apiAssets.method')}
                        </th>
                        <th className="py-2 pr-3 font-semibold">
                          {t('pages.apiAssets.path')}
                        </th>
                        <th className="py-2 pr-3 text-right font-semibold">
                          {t('pages.apiAssets.learnSamples')}
                        </th>
                        <th className="py-2 pr-3 text-right font-semibold">
                          {t('pages.apiAssets.learnKeys')}
                        </th>
                        <th className="py-2 pr-3 font-semibold">
                          {t('pages.apiAssets.control')}
                        </th>
                        <th className="py-2 font-semibold">
                          {t('pages.apiAssets.lastSeen')}
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {learnedQuery.data.map((row) => (
                        <tr
                          key={row.id}
                          className="border-b border-line/60 last:border-0"
                        >
                          <td className="py-1.5 pr-3">
                            <span className="pw-mono font-medium text-fg-strong">
                              {row.method}
                            </span>
                          </td>
                          <td className="py-1.5 pr-3">
                            <span className="pw-mono text-fg">
                              {row.path}
                            </span>
                          </td>
                          <td className="py-1.5 pr-3 text-right tabular-nums text-fg">
                            {formatNumber(row.sample_count)}
                          </td>
                          <td className="py-1.5 pr-3 text-right tabular-nums text-fg-subtle">
                            {Object.keys(row.request_schema?.keys ?? {})
                              .length +
                              Object.keys(row.query_schema ?? {}).length}
                          </td>
                          <td className="py-1.5 pr-3">
                            {canWrite ? (
                              <Select
                                containerClassName="w-32"
                                value={row.mode}
                                options={['off', 'observe', 'enforce'].map(
                                  (mode) => ({
                                    value: mode,
                                    label: t(
                                      `pages.apiAssets.mode_${mode}`,
                                    ),
                                  }),
                                )}
                                onChange={(event) =>
                                  setMode.mutate({
                                    id: row.id,
                                    mode: event.target.value,
                                  })
                                }
                              />
                            ) : (
                              <Badge
                                tone={
                                  row.mode === 'enforce'
                                    ? 'warning'
                                    : 'neutral'
                                }
                                size="sm"
                              >
                                {t(`pages.apiAssets.mode_${row.mode}`)}
                              </Badge>
                            )}
                          </td>
                          <td className="py-1.5 text-fg-subtle">
                            {row.last_seen ? formatDateTime(row.last_seen) : '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <div className="flex justify-end">
                <Button
                  variant="secondary"
                  icon={
                    <DownloadSimple weight="bold" className="h-4 w-4" />
                  }
                  disabled={!learnedQuery.data?.length}
                  onClick={() =>
                    apiAssetsApi
                      .downloadDraft(siteId, `openapi-draft-${siteId}.json`)
                      .catch((error) =>
                        toast.error(
                          t('pages.apiAssets.draftFailed'),
                          errorMessage(error),
                        ),
                      )
                  }
                >
                  {t('pages.apiAssets.downloadDraft')}
                </Button>
              </div>
              <p className="text-[11px] text-fg-subtle">
                {t('pages.apiAssets.learnNote')}
              </p>
              <p className="text-[11px] text-fg-subtle">
                {t('pages.apiAssets.modeNote')}
              </p>
            </CardBody>
          </Card>

          {/* The other direction: declared but unused */}
          <Card>
            <CardHeader
              title={t('pages.apiAssets.specOnly')}
              description={t('pages.apiAssets.specOnlyHint')}
            />
            <CardBody>
              {data.observed_truncated ? (
                <p className="flex items-center gap-1.5 text-[13px] text-fg-subtle">
                  <Info weight="duotone" className="h-4 w-4" />
                  {t('pages.apiAssets.specOnlyTruncated')}
                </p>
              ) : data.spec_only.length === 0 ? (
                <p className="flex items-center gap-1.5 py-2 text-[13px] text-fg-subtle">
                  <CheckCircle weight="duotone" className="h-4 w-4" />
                  {t('pages.apiAssets.specOnlyEmpty')}
                </p>
              ) : (
                <ul className="flex flex-wrap gap-1.5">
                  {data.spec_only.map((op) => (
                    <li
                      key={`${op.method} ${op.path}`}
                      className="inline-flex items-center gap-1.5 rounded-full border border-line bg-recessed/40 px-2.5 py-1"
                    >
                      <span className="pw-mono text-[11px] font-semibold uppercase text-fg-subtle">
                        {op.method}
                      </span>
                      <span className="pw-mono text-[13px] text-fg-strong">
                        {op.path}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardBody>
          </Card>

          {/* What this cannot see */}
          <Card>
            <CardHeader title={t('pages.apiAssets.limitations')} />
            <CardBody>
              <ul className="list-disc space-y-0.5 pl-4 text-[12px] text-fg-subtle">
                {data.limitations.map((limitation) => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  )
}

export default ApiAssetsPage
