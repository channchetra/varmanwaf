import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  CheckCircle,
  CloudArrowDown,
  WarningCircle,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { SkeletonStat } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { errorMessage } from '@/api/errors'
import {
  ipDatasetsApi,
  ipDatasetsKeys,
  type IpDatasetSyncResponse,
} from '@/api/ipDatasets'
import { formatDateTime, formatNumber } from '@/lib/format'

/**
 * The ipverse datasets the geo policies enforce with: every referenced
 * country/ASN key, whether its ranges are synced, and the sync actions.
 * "Synced" pushes fresh bundles to the sites that list the key, so what is
 * downloaded and what the edge enforces never drift apart.
 */
export function IpDataCard() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: ipDatasetsKeys.list(),
    queryFn: () => ipDatasetsApi.list(),
  })

  const report = (result: IpDatasetSyncResponse) => {
    const failed = result.results.filter((entry) => !entry.synced)
    if (failed.length > 0) {
      toast.warning(
        t('pages.geoData.syncPartial', { count: failed.length }),
        failed
          .map((entry) => `${entry.key}: ${entry.error ?? ''}`)
          .join('; '),
      )
    } else if (result.results.length > 0) {
      toast.success(
        t('pages.geoData.synced', {
          count: result.results.length,
          sites: result.pushed_sites,
        }),
      )
    }
    void queryClient.invalidateQueries({ queryKey: ipDatasetsKeys.all })
  }

  const syncKey = useMutation({
    mutationFn: (payload: { kind: 'country' | 'asn'; key: string }) =>
      ipDatasetsApi.sync(payload.kind, [payload.key]),
    onSuccess: report,
    onError: (error) =>
      toast.error(t('pages.geoData.syncFailed'), errorMessage(error)),
  })

  const syncAll = useMutation({
    mutationFn: () => ipDatasetsApi.syncReferenced(),
    onSuccess: report,
    onError: (error) =>
      toast.error(t('pages.geoData.syncFailed'), errorMessage(error)),
  })

  const data = query.data
  const referenced = data?.referenced ?? []
  const datasetFor = (kind: string, key: string) =>
    data?.items.find((item) => item.kind === kind && item.key === key)

  return (
    <Card>
      <CardHeader
        title={t('pages.geoData.title')}
        description={t('pages.geoData.hint')}
        action={
          <Button
            size="sm"
            variant="secondary"
            icon={<CloudArrowDown weight="bold" className="h-4 w-4" />}
            loading={syncAll.isPending}
            disabled={referenced.length === 0}
            onClick={() => syncAll.mutate()}
          >
            {t('pages.geoData.syncAll')}
          </Button>
        }
      />
      <CardBody className="flex flex-col gap-3">
        {query.isPending ? (
          <SkeletonStat />
        ) : referenced.length === 0 ? (
          <p className="py-4 text-center text-sm text-fg-subtle">
            {t('pages.geoData.noKeys')}
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {referenced.map((entry) => {
              const dataset = datasetFor(entry.kind, entry.key)
              const pending =
                syncKey.isPending && syncKey.variables?.key === entry.key
              return (
                <li
                  key={`${entry.kind}:${entry.key}`}
                  className="flex items-center gap-2 rounded-md border border-line bg-recessed/40 px-2.5 py-2"
                >
                  <Badge
                    tone={entry.kind === 'country' ? 'brand' : 'neutral'}
                    size="sm"
                  >
                    {entry.kind === 'country'
                      ? t('pages.geoData.country')
                      : t('pages.geoData.asn')}
                  </Badge>
                  <span className="pw-mono text-[13px] font-medium text-fg-strong">
                    {entry.key}
                  </span>
                  <span className="flex-1 truncate text-[11px] text-fg-subtle">
                    {entry.synced && dataset
                      ? t('pages.geoData.syncedAt', {
                          at: formatDateTime(dataset.synced_at),
                          ranges: formatNumber(
                            dataset.ipv4_ranges + dataset.ipv6_ranges,
                          ),
                        })
                      : dataset?.last_error
                        ? t('pages.geoData.error')
                        : t('pages.geoData.notSynced')}
                  </span>
                  {entry.synced ? (
                    <CheckCircle
                      weight="duotone"
                      className="h-4 w-4 shrink-0 text-fg-success"
                    />
                  ) : (
                    <WarningCircle
                      weight="duotone"
                      className="h-4 w-4 shrink-0 text-fg-warning"
                    />
                  )}
                  <Button
                    size="sm"
                    variant="ghost"
                    icon={<ArrowClockwise weight="bold" className="h-3.5 w-3.5" />}
                    loading={pending}
                    disabled={syncKey.isPending}
                    onClick={() =>
                      syncKey.mutate({ kind: entry.kind, key: entry.key })
                    }
                  >
                    {t('common.sync')}
                  </Button>
                </li>
              )
            })}
          </ul>
        )}
        <p className="text-[11px] text-fg-subtle">{t('pages.geoData.note')}</p>
      </CardBody>
    </Card>
  )
}

export default IpDataCard
