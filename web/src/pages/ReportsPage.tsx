import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { DownloadSimple, Eye, FileText } from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Callout } from '@/components/ui/Callout'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Select } from '@/components/ui/Select'
import { Input } from '@/components/ui/Input'
import { StatGrid } from '@/components/ui/StatGrid'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import {
  reportsApi,
  reportKeys,
  fetchInterceptionReport,
  downloadInterceptionReport,
  type ReportActionFilter,
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

const ACTION_FILTERS: ReportActionFilter[] = ['all', 'blocked', 'monitor']

/**
 * Interception reports: a light summary in the console, an online preview
 * and the full report generated and downloaded on demand - the dashboard
 * never loads the full data, which keeps the control plane light.
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
  const queryClient = useQueryClient()
  const { data: sites } = useSitesList()

  const [preset, setPreset] = useState<ReportPreset>('30d')
  const [customFrom, setCustomFrom] = useState('')
  const [customTo, setCustomTo] = useState('')
  const [siteId, setSiteId] = useState('')
  const [action, setAction] = useState<ReportActionFilter>('all')
  const [search, setSearch] = useState('')
  const [titleDraft, setTitleDraft] = useState<string | null>(null)
  const [noteDraft, setNoteDraft] = useState<string | null>(null)
  const [preview, setPreview] = useState<{
    html: string
    filename: string
  } | null>(null)

  const params: ReportQuery = useMemo(() => {
    const range = rangeForPreset(preset)
    return {
      ...(range ?? {
        from: customFrom || undefined,
        to: customTo || undefined,
      }),
      site_id: siteId || undefined,
      action,
      q: search.trim() || undefined,
    }
  }, [preset, customFrom, customTo, siteId, action, search])

  const summaryQuery = useQuery({
    queryKey: reportKeys.summary(params),
    queryFn: () => reportsApi.summary(params),
  })

  const settingsQuery = useQuery({
    queryKey: reportKeys.settings(),
    queryFn: () => reportsApi.getSettings(),
  })
  const settings = settingsQuery.data
  const titleValue = titleDraft ?? settings?.title ?? 'Interception report'
  const noteValue = noteDraft ?? settings?.footer_note ?? ''

  const saveSettings = useMutation({
    mutationFn: () =>
      reportsApi.saveSettings({
        title: titleValue.trim(),
        footer_note: noteValue.trim() || null,
      }),
    onSuccess: (saved) => {
      setTitleDraft(null)
      setNoteDraft(null)
      queryClient.setQueryData(reportKeys.settings(), saved)
      toast.success(t('pages.reports.settingsSaved'))
    },
    onError: (error) =>
      toast.error(t('pages.reports.settingsSaveFailed'), errorMessage(error)),
  })

  const previewReport = useMutation({
    mutationFn: () => fetchInterceptionReport(params),
    onSuccess: (report) => setPreview(report),
    onError: (error) =>
      toast.error(t('pages.reports.generateFailed'), errorMessage(error)),
  })

  const generate = useMutation({
    mutationFn: () => downloadInterceptionReport(params),
    onSuccess: () => toast.success(t('pages.reports.generated')),
    onError: (error) =>
      toast.error(t('pages.reports.generateFailed'), errorMessage(error)),
  })

  const data = summaryQuery.data
  const customIncomplete = preset === 'custom' && (!customFrom || !customTo)

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
              containerClassName="w-56"
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
            <Select
              containerClassName="w-40"
              label={t('pages.reports.action')}
              value={action}
              options={ACTION_FILTERS.map((value) => ({
                value,
                label: t(`pages.reports.action_${value}`),
              }))}
              onChange={(event) =>
                setAction(event.target.value as ReportActionFilter)
              }
            />
            <Input
              containerClassName="w-52"
              label={t('pages.reports.search')}
              placeholder={t('pages.reports.searchPlaceholder')}
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <div className="ml-auto flex items-center gap-2">
              <Button
                variant="secondary"
                icon={<Eye weight="bold" className="h-4 w-4" />}
                loading={previewReport.isPending}
                disabled={customIncomplete}
                onClick={() => previewReport.mutate()}
              >
                {t('pages.reports.preview')}
              </Button>
              <Button
                variant="primary"
                icon={<DownloadSimple weight="bold" className="h-4 w-4" />}
                loading={generate.isPending}
                disabled={customIncomplete}
                onClick={() => generate.mutate()}
              >
                {t('pages.reports.generate')}
              </Button>
            </div>
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
        <Card className="mb-4">
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

      <Card>
        <CardHeader
          title={t('pages.reports.settingsTitle')}
          description={t('pages.reports.settingsHint')}
          action={
            <Button
              size="sm"
              variant="primary"
              loading={saveSettings.isPending}
              disabled={!titleValue.trim()}
              onClick={() => saveSettings.mutate()}
            >
              {t('common.save')}
            </Button>
          }
        />
        <CardBody className="flex flex-col gap-4">
          <Input
            label={t('pages.reports.heading')}
            hint={t('pages.reports.headingHint')}
            value={titleValue}
            onChange={(event) => setTitleDraft(event.target.value)}
          />
          <Input
            label={t('pages.reports.footerNote')}
            hint={t('pages.reports.footerNoteHint')}
            value={noteValue}
            onChange={(event) => setNoteDraft(event.target.value)}
          />
        </CardBody>
      </Card>

      {preview && (
        <Dialog
          open
          onClose={() => setPreview(null)}
          title={preview.filename}
          className="max-w-4xl"
          footer={
            <>
              <Button variant="ghost" onClick={() => setPreview(null)}>
                {t('common.close')}
              </Button>
              <Button
                variant="primary"
                icon={<DownloadSimple weight="bold" className="h-4 w-4" />}
                loading={generate.isPending}
                onClick={() => generate.mutate()}
              >
                {t('pages.reports.downloadFile')}
              </Button>
            </>
          }
        >
          <iframe
            title={t('pages.reports.previewTitle')}
            srcDoc={preview.html}
            sandbox=""
            className="h-[65vh] w-full rounded-md border border-line bg-white"
          />
        </Dialog>
      )}
    </div>
  )
}

export default ReportsPage
