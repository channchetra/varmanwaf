import { useEffect } from 'react'
import { NavLink, Outlet, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Globe,
  Shield,
  Lightning,
  Lock,
  ChartLine,
  Sliders,
  Gauge,
  CaretLeft,
  Robot,
  IdentificationCard,
  Network,
  Warning,
  Gear,
  BracketsCurly,
  FlowArrow,
  SquaresFour,
  ArrowSquareOut,
  type Icon,
} from '@phosphor-icons/react'
import { Link } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ErrorState'
import { ProtectionMode } from '@/components/site/ProtectionMode'
import { useSiteDetail } from '@/hooks'
import { useSiteStore } from '@/stores/siteStore'
import { liveSiteUrl } from '@/lib/siteUrl'

export function SiteDetailPage() {
  const { t } = useTranslation()
  const { siteId } = useParams<{ siteId: string }>()
  const setCurrentSiteId = useSiteStore((s) => s.setCurrentSiteId)

  useEffect(() => {
    if (siteId) setCurrentSiteId(siteId)
  }, [siteId, setCurrentSiteId])

  const detail = useSiteDetail(siteId)
  const site = detail.data?.site

  const paused = site?.status === 'paused'

  const base = `/sites/${siteId}`
  // Grouped so the bar reads as scopes: delivery, security, traffic,
  // rules & settings. Separators render between the groups.
  const tabGroups: { to: string; label: string; icon: Icon }[][] = [
    [{ to: `${base}/overview`, label: t('nav.overview'), icon: SquaresFour }],
    [
      {
        to: `${base}/security/protection`,
        label: t('nav.securityProtection'),
        icon: Shield,
      },
      {
        to: `${base}/security/rate-limiting`,
        label: t('nav.securityRateLimiting'),
        icon: Gauge,
      },
      { to: `${base}/security/bot`, label: t('nav.securityBot'), icon: Robot },
      {
        to: `${base}/security/access`,
        label: t('nav.securityAccess'),
        icon: IdentificationCard,
      },
      {
        to: `${base}/security/api-assets`,
        label: t('nav.securityApiAssets'),
        icon: BracketsCurly,
      },
    ],
    [
      { to: `${base}/origin`, label: t('nav.origin'), icon: Network },
      { to: `${base}/caching`, label: t('nav.caching'), icon: Lightning },
      { to: `${base}/ssl`, label: t('nav.ssl'), icon: Lock },
      { to: `${base}/traffic`, label: t('nav.traffic'), icon: ChartLine },
      { to: `${base}/topology`, label: t('nav.topology'), icon: FlowArrow },
    ],
    [
      {
        to: `${base}/rules/rewrite`,
        label: t('pages.rewrite.title'),
        icon: Sliders,
      },
      { to: `${base}/settings`, label: t('nav.settings'), icon: Gear },
    ],
  ]

  // The server answers 404 for sites the caller may not see — surface that
  // instead of rendering an empty shell around a broken id.
  if (detail.isError && !detail.data) {
    return (
      <div className="animate-slide-up">
        <ErrorState
          error={detail.error}
          onRetry={() => detail.refetch()}
          retrying={detail.isFetching}
          action={
            <Link to="/sites">
              <span className="inline-flex items-center gap-1.5 text-[13px] font-medium text-link">
                <CaretLeft weight="bold" className="h-3.5 w-3.5" />
                {t('pages.sites.title')}
              </span>
            </Link>
          }
        />
      </div>
    )
  }

  return (
    <div className="animate-slide-up">
      {/* Site header */}
      <div className="mb-5 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-brand-soft text-brand-ink">
            <Globe weight="duotone" className="h-6 w-6" />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              {site ? (
                <a
                  href={liveSiteUrl(site.domain, detail.data?.ssl?.has_certificate)}
                  target="_blank"
                  rel="noreferrer"
                  title={t('pages.siteDetail.visitSite')}
                  className="group inline-flex min-w-0 items-center gap-1.5"
                >
                  <h1 className="pw-mono truncate text-lg font-semibold tracking-tight text-fg-strong group-hover:text-brand-ink">
                    {site.domain}
                  </h1>
                  <ArrowSquareOut
                    weight="bold"
                    className="h-3.5 w-3.5 shrink-0 text-fg-subtle group-hover:text-brand-ink"
                  />
                </a>
              ) : (
                <Skeleton className="h-6 w-56 rounded-md" />
              )}
            </div>
            <p className="truncate text-[13px] text-fg-subtle">
              {site ? (
                <>
                  {site.name}
                  <span className="mx-1.5 text-fg-subtle/50">·</span>
                  <span className="capitalize">{t(`plans.${site.plan}`, site.plan)}</span>
                </>
              ) : (
                t('pages.siteDetail.overview')
              )}
            </p>
            {site && (site.alternate_domains?.length ?? 0) > 0 && (
              <p
                className="pw-mono truncate text-xs text-fg-subtle"
                title={site.alternate_domains.join(', ')}
              >
                + {site.alternate_domains.join(', ')}
              </p>
            )}
          </div>
        </div>

        {siteId && (
          <div className="w-full shrink-0 sm:max-w-xs">
            <ProtectionMode siteId={siteId} />
          </div>
        )}
      </div>

      {/* The edge answers a paused site with a maintenance page, so say so. */}
      {paused && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-[13px] text-fg">
          <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg" />
          <p>{t('pages.siteDetail.pausedNote')}</p>
        </div>
      )}

      {/* Tab nav, grouped by scope */}
      <div className="mb-6 flex items-center gap-1 overflow-x-auto border-b border-line">
        {tabGroups.map((group, groupIndex) => (
          <div key={groupIndex} className="flex items-center gap-1">
            {groupIndex > 0 && (
              <span
                aria-hidden
                className="mx-1.5 h-5 w-px shrink-0 bg-line"
              />
            )}
            {group.map((tab) => {
              const Icon = tab.icon
              return (
                <NavLink
                  key={tab.to}
                  to={tab.to}
                  className={({ isActive }) =>
                    cn(
                      '-mb-px inline-flex shrink-0 items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2.5 text-sm font-medium transition-colors',
                      isActive
                        ? 'border-brand text-fg-strong'
                        : 'border-transparent text-fg-subtle hover:text-fg',
                    )
                  }
                >
                  <Icon weight="duotone" className="h-4 w-4" />
                  {tab.label}
                </NavLink>
              )
            })}
          </div>
        ))}
      </div>

      <Outlet />
    </div>
  )
}

