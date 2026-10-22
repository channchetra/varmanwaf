import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  ArrowSquareOut,
  ChartLine,
  Lock,
  Shield,
  Warning,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Badge, type BadgeTone } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { StatGrid } from '@/components/ui/StatGrid'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ErrorState'
import { sitesApi, siteKeys } from '@/api/sites'
import { analyticsApi } from '@/api/analytics'
import { sslApi } from '@/api/ssl'
import { logsApi } from '@/api/logs'
import { wafSettingsApi } from '@/api/wafSettings'
import {
  formatCompactNumber,
  formatDateTime,
  formatNumber,
} from '@/lib/format'

const MODE_TONE: Record<string, BadgeTone> = {
  block: 'success',
  monitor: 'info',
}

const ACTION_TONE: Record<string, BadgeTone> = {
  block: 'danger',
  challenge: 'warning',
  monitor: 'info',
  allow: 'neutral',
}

/**
 * One site's own overview: what it protects, how it is enforced, where it
 * proxies to, and the latest findings - without leaving the site workspace.
 */
export function SiteOverviewPage() {
  const { siteId = '' } = useParams<{ siteId: string }>()
  const { t } = useTranslation()

  const to = new Date()
  const from = new Date(to.getTime() - 24 * 60 * 60 * 1000)

  const detail = useQuery({
    queryKey: [...siteKeys.detail(siteId), 'overview'],
    queryFn: () => sitesApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const summary = useQuery({
    queryKey: ['site-overview', siteId, 'summary'],
    queryFn: () =>
      analyticsApi.summary({
        site_id: siteId,
        from: from.toISOString(),
        to: to.toISOString(),
      }),
    enabled: Boolean(siteId),
  })
  const waf = useQuery({
    queryKey: ['site-overview', siteId, 'waf'],
    queryFn: () => wafSettingsApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const certificates = useQuery({
    queryKey: ['site-overview', siteId, 'certificates'],
    queryFn: () => sslApi.list(siteId),
    enabled: Boolean(siteId),
  })
  const events = useQuery({
    queryKey: ['site-overview', siteId, 'events'],
    queryFn: () =>
      logsApi.securityEvents({ site_id: siteId, page_size: 6 }),
    enabled: Boolean(siteId),
  })

  if (detail.isError && !detail.data) {
    return (
      <ErrorState
        variant="inline"
        error={detail.error}
        onRetry={() => detail.refetch()}
        retrying={detail.isFetching}
      />
    )
  }
  if (!detail.data) {
    return <SkeletonCard />
  }

  const site = detail.data.site
  const certs = certificates.data?.items ?? []
  // Prefer the certificate actually serving the site: the active row in the
  // certificate list, otherwise the site's own configured certificate (the
  // self-signed default or an uploaded pair). A failed ACME row is shown only
  // when nothing is serving, so a stale failure never masquerades as the cert.
  const activeCert = certs.find((cert) => cert.status === 'active') ?? null
  const siteCert = detail.data.ssl?.has_certificate ? detail.data.ssl : null
  const servingCert = activeCert ?? siteCert
  const failedCert = servingCert
    ? null
    : (certs.find((cert) => cert.status === 'failed') ?? null)
  const posture = waf.data
  const stats = summary.data

  return (
    <div className="flex flex-col gap-4">
      <StatGrid
        items={[
          {
            label: t('pages.siteOverview.requests'),
            value: stats ? formatCompactNumber(stats.requests) : '…',
            hint: t('pages.siteOverview.last24h'),
          },
          {
            label: t('pages.siteOverview.blocked'),
            value: stats ? formatCompactNumber(stats.blocked_requests) : '…',
            hint: t('pages.siteOverview.last24h'),
          },
          {
            label: t('pages.siteOverview.events'),
            value: stats ? formatNumber(stats.security_events) : '…',
            hint: t('pages.siteOverview.last24h'),
          },
          {
            label: t('pages.siteOverview.uniqueIps'),
            value: stats ? formatNumber(stats.unique_ips ?? 0) : '…',
            hint: t('pages.siteOverview.last24h'),
          },
        ]}
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title={t('pages.siteOverview.protection')}
            description={t('pages.siteOverview.protectionHint')}
            action={
              <Link to={`/sites/${siteId}/security/protection`}>
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<Shield weight="duotone" className="h-4 w-4" />}
                >
                  {t('pages.siteOverview.openProtection')}
                </Button>
              </Link>
            }
          />
          <CardBody className="flex flex-col gap-4">
            {posture ? (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={MODE_TONE[posture.mode ?? ''] ?? 'neutral'} dot>
                    {t(`pages.siteOverview.mode_${posture.mode ?? 'monitor'}`, {
                      defaultValue: posture.mode ?? 'monitor',
                    })}
                  </Badge>
                  <Badge tone="neutral">
                    {t('pages.siteOverview.paranoia', {
                      level: posture.paranoia_level,
                    })}
                  </Badge>
                  <Badge tone={posture.advanced_mode ? 'success' : 'neutral'}>
                    {posture.advanced_mode
                      ? t('pages.siteOverview.advancedOn')
                      : t('pages.siteOverview.advancedOff')}
                  </Badge>
                  <Badge tone="neutral">
                    {t('pages.siteOverview.engine', {
                      engine: posture.engine_mode,
                    })}
                  </Badge>
                </div>
                {posture.mode !== 'block' && (
                  <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-[12px] text-fg">
                    <Warning
                      weight="duotone"
                      className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning"
                    />
                    {t('pages.siteOverview.monitorHint')}
                  </p>
                )}
              </>
            ) : (
              <p className="text-[13px] text-fg-subtle">
                {t('pages.siteOverview.loading')}
              </p>
            )}
            <div className="flex flex-wrap gap-4 border-t border-line pt-3 text-[12px] text-fg-subtle">
              <span>
                {t('pages.siteOverview.rules', {
                  count: detail.data.rule_count,
                })}
              </span>
              <span>
                {t('pages.siteOverview.rateLimits', {
                  count: detail.data.rate_limit_count,
                })}
              </span>
              <span>
                {t('pages.siteOverview.cacheRules', {
                  count: detail.data.cache_rule_count,
                })}
              </span>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title={t('pages.siteOverview.certificate')}
            action={
              <Link to={`/sites/${siteId}/ssl`}>
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<Lock weight="duotone" className="h-4 w-4" />}
                >
                  {t('pages.siteOverview.openSsl')}
                </Button>
              </Link>
            }
          />
          <CardBody className="flex flex-col gap-2 text-[13px]">
            {servingCert ? (
              <>
                <p className="pw-mono truncate text-fg-strong">
                  {servingCert.domain}
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="success" dot>
                    {t('pages.siteOverview.serving')}
                  </Badge>
                  {servingCert.expires_at && (
                    <span className="text-fg-subtle">
                      {t('pages.siteOverview.expires', {
                        date: formatDateTime(servingCert.expires_at),
                      })}
                    </span>
                  )}
                </div>
                {servingCert.issuer && (
                  <p className="truncate text-[12px] text-fg-subtle">
                    {servingCert.issuer}
                  </p>
                )}
              </>
            ) : failedCert ? (
              <>
                <p className="pw-mono truncate text-fg-strong">
                  {failedCert.domain}
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="danger" dot>
                    {t('pages.sslGlobal.status_failed')}
                  </Badge>
                </div>
                {failedCert.failure_reason && (
                  <p className="text-[12px] text-fg-danger">
                    {failedCert.failure_reason}
                  </p>
                )}
              </>
            ) : (
              <p className="text-fg-subtle">
                {t('pages.siteOverview.noCertificate')}
              </p>
            )}
          </CardBody>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader
            title={t('pages.siteOverview.origin')}
            action={
              <Link to={`/sites/${siteId}/origin`}>
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<ArrowSquareOut weight="duotone" className="h-4 w-4" />}
                >
                  {t('pages.siteOverview.openOrigin')}
                </Button>
              </Link>
            }
          />
          <CardBody className="flex flex-col gap-2 text-[13px]">
            {detail.data.upstreams.length === 0 ? (
              <p className="text-fg-subtle">
                {t('pages.siteOverview.noOrigin')}
              </p>
            ) : (
              detail.data.upstreams.map((upstream) => (
                <div
                  key={upstream.id}
                  className="flex items-center justify-between gap-3"
                >
                  <span className="pw-mono truncate text-fg-strong">
                    {upstream.address}
                  </span>
                  <Badge
                    tone={
                      upstream.health_status === 'healthy'
                        ? 'success'
                        : upstream.health_status === 'unhealthy'
                          ? 'danger'
                          : 'neutral'
                    }
                    dot
                  >
                    {t(
                      `pages.siteOverview.health_${upstream.health_status ?? 'unknown'}`,
                      upstream.health_status ?? 'unknown',
                    )}
                  </Badge>
                </div>
              ))
            )}
            <p className="text-[12px] text-fg-subtle">
              {t('pages.siteOverview.siteStatus', {
                status: t(`status.${site.status}`, site.status),
              })}
            </p>
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader
            title={t('pages.siteOverview.recent')}
            description={t('pages.siteOverview.recentHint')}
            action={
              <Link to={`/logs?site_id=${siteId}`}>
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<ChartLine weight="duotone" className="h-4 w-4" />}
                >
                  {t('pages.siteOverview.openLogs')}
                </Button>
              </Link>
            }
          />
          <CardBody className="p-0">
            {events.data && events.data.items.length > 0 ? (
              <ul className="divide-y divide-line">
                {events.data.items.map((event) => (
                  <li
                    key={event.id}
                    className="flex flex-wrap items-center gap-2 px-4 py-2 text-[12px]"
                  >
                    <Badge
                      tone={ACTION_TONE[event.action] ?? 'neutral'}
                      size="sm"
                    >
                      {event.action}
                    </Badge>
                    <span className="pw-mono truncate text-fg">
                      {event.rule_id ?? '—'}
                    </span>
                    <span className="pw-mono truncate text-fg-subtle">
                      {event.path ?? '/'}
                    </span>
                    <span className="ml-auto text-fg-subtle">
                      {formatDateTime(event.timestamp)}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="px-4 py-6 text-center text-[13px] text-fg-subtle">
                {t('pages.siteOverview.noEvents')}
              </p>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  )
}

export default SiteOverviewPage
