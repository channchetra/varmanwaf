import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { ChartLine } from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Select } from '@/components/ui/Select'
import { ErrorState } from '@/components/ErrorState'
import { TrafficPanels } from '@/pages/sites/TrafficPage'
import { sitesApi, siteKeys } from '@/api/sites'

/**
 * Fleet-wide traffic.
 *
 * The same panels the per-site page renders, but the scope starts at "all
 * sites" and can be narrowed to a single site from the selector. Admins see
 * every site; other roles only their own, which mirrors the analytics API's
 * own visibility rules.
 */
export function GlobalTrafficPage() {
  const { t } = useTranslation()
  const [siteId, setSiteId] = useState('')

  const sitesQuery = useQuery({
    queryKey: siteKeys.list({}),
    queryFn: () => sitesApi.list(),
    select: (page) => page.items,
  })

  const sites = sitesQuery.data ?? []

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.traffic.globalTitle')}
        description={t('pages.traffic.globalDescription')}
        actions={
          <Select
            aria-label={t('pages.sites.title')}
            className="h-9 w-60"
            value={siteId}
            options={[
              { value: '', label: t('pages.traffic.allSites') },
              ...sites.map((s) => ({ value: s.id, label: s.domain })),
            ]}
            onChange={(e) => setSiteId(e.target.value)}
          />
        }
      />

      {sitesQuery.isError && !sitesQuery.data ? (
        <ErrorState
          error={sitesQuery.error}
          onRetry={() => sitesQuery.refetch()}
          retrying={sitesQuery.isFetching}
        />
      ) : (
        <>
          {siteId === '' && (
            <div className="mb-4 flex items-center gap-2 rounded-lg border border-line bg-elevated px-4 py-2.5">
              <ChartLine weight="duotone" className="h-4 w-4 shrink-0 text-fg-subtle" />
              <p className="text-xs text-fg-subtle">{t('pages.traffic.globalHint')}</p>
            </div>
          )}
          <TrafficPanels siteId={siteId || undefined} />
        </>
      )}
    </div>
  )
}

export default GlobalTrafficPage
