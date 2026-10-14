import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery } from '@tanstack/react-query'
import { DownloadSimple, FileText } from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Callout } from '@/components/ui/Callout'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Select } from '@/components/ui/Select'
import { Input } from '@/components/ui/Input'
import { StatGrid } from '@/components/ui/StatGrid'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import {
  reportsApi,
  reportKeys,
  downloadInterceptionReport,
  type ReportQuery,
} from '@/api/reports'
import {
  REPORT_PRESETS,
  rangeForPreset,
  type ReportPreset,
} from '@/lib/reportRange'
import { useAuthStore } from '@/stores/authStore'
import { useSitesList } from '@/hooks'
import { errorMessage } from '@/api/errors'
import { formatNumber } from '@/lib/format'

/**
 * Interception reports: a light summary in the console and the full report
 * generated and downloaded on demand - the dashboard never loads the full
 * data, which keeps the control plane light.
 *
 * Administrator-only, mirroring the server routes.
 */
export function ReportsPage() {
  const { t } = useTranslation()
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'

  if (!isAdmin) {
    return (
      <div className="animate-slide-up">
        <PageHeader
          title={t('pages.reports.title')}
          description={t('pages.reports.description')}
        />
        <EmptyState
          icon={<FileText weight="duotone" />}
          title={t('pages.reports.adminOnlyTitle')}
          description={t('pages.reports.adminOnly')}
        />
      </div>
    )
  }

  return <ReportsWorkspace />
}

function ReportsWorkspace() {
  const { t } = useTranslation()
  const toast = useToast()
  const { data: sites } = useSitesList()

  const [preset, setPreset] = useState<ReportPreset>('30d')
  const [customFrom, setCustomFrom] = useState('')
  const [customTo, setCustomTo] = useState('')
  const [siteId, setSiteId] = useState('')

  const params: ReportQuery = useMemo(() => {
    const range = rangeForPreset(preset)
    return {
      ...(range ?? {
        from: customFrom || undefined,
        to: customTo || undefined,
      }),
      site_id: siteId || undefined,
    }
  }, [preset, customFrom, customTo, siteId])

  const summaryQuery = useQuery({
    queryKey: reportKeys.summary(params),
    queryFn: () => reportsApi.summary(params),
  })

  const generate = useMutation({
    mutationFn: () => downloadInterceptionReport(params),
    onSuccess: () => toast.success(t('pages.reports.generated')),
    onError: (error) =>
      toast.error(t('pages.reports.generateFailed'), errorMessage(error)),
  })

  const data = summaryQuery.data
  const customIncomplete =
    preset === 'custom' && (!customFrom || !customTo)

  const items = data
    ? [
        {
          label: t('pages.reports.events'),
          value: formatNumber(data.events),
        },
        {
          label: t('pages.reports.blocked'),
          value: formatNumber(data.blocked),
        },
        {
          label: t('pages.reports.monitored'),
          value: formatNumber(data.monitored),
        },
        {
          label: t('pages.reports.uniqueIps'),
          value: formatNumber(data.unique_ips),
        },
        {
          label: t('pages.reports.uniquePaths'),
          value: formatNumber(data.unique_paths),
        },
      ]
    : []

  const topLine = data
    ? [
        data.top_type &&
          `${t('pages.reports.topType')}: ${data.top_type.label} (${formatNumber(data.top_type.count)})`,
        data.top_country &&
          `${t('pages.reports.topCountry')}: ${data.top_country.label.toUpperCase()} (${formatNumber(data.top_country.count)})`,
        data.top_ip &&
          `${t('pages.reports.topIp')}: ${data.top_ip.label} (${formatNumber(data.top_ip.count)})`,
      ]
        .filter(Boolean)
        .join(' · ')
    : ''

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.reports.title')}
        description={t('pages.reports.description')}
      />

      <Callout
        className="mb-4"
        tone="brand"
        icon={<FileText weight="duotone" className="h-5 w-5" />}
        title={t('pages.reports.overviewTitle')}
      >
        {t('pages.reports.overview')}
      </Callout>

      <Card className="mb-4">
        <CardBody>
          <div className="flex flex-wrap items-end gap-3">
            <Select
              containerClassName="w-44"
              label={t('pages.reports.range')}
              value={preset}
              options={[
                ...REPORT_PRESETS.map((value) => ({
                  value,
                  label: t(`pages.reports.preset_${value}`),
                })),
                { value: 'custom', label: t('pages.reports.preset_custom') },
              ]}
              onChange={(event) =>
                setPreset(event.target.value as ReportPreset)
              }
            />
            {preset === 'custom' && (
              <>
                <Input
                  containerClassName="w-40"
                  type="date"
                  label={t('pages.reports.from')}
                  value={customFrom}
                  onChange={(event) => setCustomFrom(event.target.value)}
                />
                <Input
                  containerClassName="w-40"
                  type="date"
                  label={t('pages.reports.to')}
                  value={customTo}
                  onChange={(event) => setCustomTo(event.target.value)}
                />
              </>
            )}
            <Select
              containerClassName="w-64"
              label={t('pages.reports.site')}
              value={siteId}
              options={[
                { value: '', label: t('pages.reports.allSites') },
                ...(sites ?? []).map((site) => ({
                  value: site.id,
                  label: site.name || site.domain,
                })),
              ]}
              onChange={(event) => setSiteId(event.target.value)}
            />
            <Button
              className="ml-auto"
              variant="primary"
              icon={<DownloadSimple weight="bold" className="h-4 w-4" />}
              loading={generate.isPending}
              disabled={customIncomplete}
              onClick={() => generate.mutate()}
            >
              {t('pages.reports.generate')}
            </Button>
          </div>
          <p className="mt-3 text-[11px] text-fg-subtle">
            {t('pages.reports.generateHint')}
          </p>
        </CardBody>
      </Card>

      {summaryQuery.isError && !data ? (
        <ErrorState
          error={summaryQuery.error}
          onRetry={() => summaryQuery.refetch()}
          retrying={summaryQuery.isFetching}
        />
      ) : summaryQuery.isPending ? (
        <SkeletonCard className="h-40" />
      ) : data ? (
        <Card>
          <CardHeader
            title={t('pages.reports.summaryTitle')}
            description={t('pages.reports.summaryHint')}
          />
          <CardBody>
            <StatGrid items={items} columns={5} />
            {topLine ? (
              <p className="mt-4 text-[13px] text-fg-subtle">{topLine}</p>
            ) : (
              <p className="mt-4 text-[13px] text-fg-subtle">
                {t('pages.reports.empty')}
              </p>
            )}
          </CardBody>
        </Card>
      ) : null}
    </div>
  )
}

export default ReportsPage
