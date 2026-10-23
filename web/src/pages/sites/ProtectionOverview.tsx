import { useMemo } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowRight,
  Gauge,
  Globe,
  IdentificationCard,
  Lightning,
  Robot,
  Shield,
  ShieldCheck,
  Sliders,
  Stack,
  Pulse,
} from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ErrorState'
import { policiesApi, policyKeys } from '@/api/policies'
import { cn } from '@/lib/utils'

type ProtectionTab = 'rules' | 'cc' | 'tuning'

/**
 * The site's protection overview: what configuration is actually in force,
 * in which order the stages run, and where each module is edited.
 *
 * Everything shown is resolved server-side (the same resolution the bundle
 * builder uses); site-local counters live on their own pages and are linked
 * rather than re-derived here.
 */
export function ProtectionOverview({
  onSelectTab,
}: {
  onSelectTab: (tab: ProtectionTab) => void
}) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const assignment = useQuery({
    queryKey: policyKeys.sitePolicy(siteId),
    queryFn: () => policiesApi.getSitePolicy(siteId),
    enabled: Boolean(siteId),
  })
  const effective = useQuery({
    queryKey: policyKeys.siteEffective(siteId),
    queryFn: () => policiesApi.effectiveConfig(siteId),
    enabled: Boolean(siteId),
  })
  const apply = useQuery({
    queryKey: policyKeys.applyStatus(siteId),
    queryFn: () => policiesApi.applyStatus(siteId),
    enabled: Boolean(siteId),
  })

  const data = effective.data
  const policy = assignment.data?.policy ?? null
  const overrideKinds = assignment.data?.override_kinds ?? []

  const applyState = useMemo(() => {
    const agents = apply.data?.agents ?? []
    if (agents.length === 0) return 'unknown' as const
    const published = apply.data?.published.policy_revision ?? 0
    if (agents.every((row) => (row.applied_policy_revision ?? 0) >= published)) {
      return 'applied' as const
    }
    if (agents.some((row) => (row.applied_policy_revision ?? 0) >= published)) {
      return 'partial' as const
    }
    return 'pending' as const
  }, [apply.data])

  if (assignment.isLoading || effective.isLoading) {
    return (
      <div className="flex flex-col gap-4">
        <SkeletonCard />
        <SkeletonCard />
      </div>
    )
  }
  if (assignment.isError && !assignment.data) {
    return (
      <div className="animate-slide-up">
        <ErrorState
          error={assignment.error}
          onRetry={() => assignment.refetch()}
          retrying={assignment.isFetching}
        />
      </div>
    )
  }

  const layerChip = (kind: string, label: string) => {
    const siteOverride = overrideKinds.includes(kind)
    const fromPolicy = Boolean(data?.layers?.[kind]) || (data?.crs && kind === 'crs')
    if (siteOverride) {
      return (
        <Badge tone="warning">
          {t('pages.protectionOverview.overrideHere', { label })}
        </Badge>
      )
    }
    if (fromPolicy) {
      return (
        <Badge tone="brand">
          {t('pages.protectionOverview.fromPolicy', { label })}
        </Badge>
      )
    }
    return (
      <Badge tone="neutral">
        {t('pages.protectionOverview.siteSettings')}
      </Badge>
    )
  }

  const stats: Array<{ label: string; value: string }> = [
    {
      label: t('pages.policies.fields.engineSwitch'),
      value: data?.effective.waf_enabled
        ? t('common.enabled')
        : t('common.disabled'),
    },
    {
      label: t('pages.policies.fields.paranoia'),
      value: String(data?.effective.paranoia_level ?? '-'),
    },
    {
      label: t('pages.policies.fields.advanced'),
      value: data?.effective.advanced_mode
        ? t('common.enabled')
        : t('common.disabled'),
    },
    {
      label: t('pages.policies.fields.engineMode'),
      value: data?.effective.engine_mode ?? '—',
    },
    {
      label: t('pages.protectionOverview.ruleCount'),
      value: String(data?.rules.length ?? 0),
    },
  ]

  const layerRuleCount = (kind: string): number => {
    const layer = (data?.layers as Record<string, unknown> | undefined)?.[
      kind
    ] as { rules?: unknown[] } | undefined
    return Array.isArray(layer?.rules) ? layer.rules.length : 0
  }

  const stages = [
    {
      id: 'ip',
      icon: Globe,
      title: t('pages.protectionOverview.stages.ip'),
      detail: t('pages.protectionOverview.stages.ipDetail', {
        n: layerRuleCount('ip_access'),
      }),
      to: `/sites/${siteId}/security/access`,
    },
    {
      id: 'bot',
      icon: Robot,
      title: t('pages.protectionOverview.stages.bot'),
      detail: t('pages.protectionOverview.stages.botDetail'),
      to: `/sites/${siteId}/security/bot`,
    },
    {
      id: 'rate',
      icon: Gauge,
      title: t('pages.protectionOverview.stages.rate'),
      detail: t('pages.protectionOverview.stages.rateDetail', {
        n: layerRuleCount('rate_limit'),
      }),
      to: `/sites/${siteId}/security/rate-limiting`,
    },
    {
      id: 'rules',
      icon: Shield,
      title: t('pages.protectionOverview.stages.rules'),
      detail: t('pages.protectionOverview.stages.rulesDetail', {
        rules: data?.rules.length ?? 0,
        plan: data?.plan.length ?? 0,
      }),
      onClick: () => onSelectTab('rules'),
    },
    {
      id: 'challenge',
      icon: Lightning,
      title: t('pages.protectionOverview.stages.challenge'),
      detail: t('pages.protectionOverview.stages.challengeDetail'),
      onClick: () => onSelectTab('cc'),
    },
  ]

  const modules = [
    {
      id: 'bot',
      icon: Robot,
      title: t('pages.protectionOverview.modules.bot'),
      description: t('pages.protectionOverview.modules.botHint'),
      chip: layerChip('bot', 'Bot'),
      onOpen: () => navigate(`/sites/${siteId}/security/bot`),
    },
    {
      id: 'rules',
      icon: Stack,
      title: t('pages.protectionOverview.modules.rules'),
      description: t('pages.protectionOverview.modules.rulesHint'),
      chip: layerChip('custom_rules', 'Rules'),
      onOpen: () => onSelectTab('rules'),
    },
    {
      id: 'access',
      icon: IdentificationCard,
      title: t('pages.protectionOverview.modules.access'),
      description: t('pages.protectionOverview.modules.accessHint'),
      chip: layerChip('ip_access', 'IP'),
      onOpen: () => navigate(`/sites/${siteId}/security/access`),
    },
    {
      id: 'rate',
      icon: Gauge,
      title: t('pages.protectionOverview.modules.rate'),
      description: t('pages.protectionOverview.modules.rateHint'),
      chip: layerChip('rate_limit', 'Limits'),
      onOpen: () => navigate(`/sites/${siteId}/security/rate-limiting`),
    },
    {
      id: 'cc',
      icon: Lightning,
      title: t('pages.protectionOverview.modules.cc'),
      description: t('pages.protectionOverview.modules.ccHint'),
      chip: (
        <Badge tone="neutral">
          {t('pages.protectionOverview.siteSettings')}
        </Badge>
      ),
      onOpen: () => onSelectTab('cc'),
    },
    {
      id: 'settings',
      icon: Sliders,
      title: t('pages.protectionOverview.modules.settings'),
      description: t('pages.protectionOverview.modules.settingsHint'),
      chip: layerChip('engine', 'Engine'),
      onOpen: () => onSelectTab('tuning'),
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      {/* Shared policy */}
      <Card className="order-3 border-focus/30">
        <CardBody className="space-y-4">
          <div className="flex flex-wrap items-start gap-4">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-focus/10 text-link">
              <ShieldCheck weight="duotone" className="h-6 w-6" />
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">
                {t('pages.protectionOverview.effectivePolicy')}
              </p>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <p className="text-[15px] font-semibold text-fg-strong">
                  {policy
                    ? t('pages.protectionOverview.follows', {
                        name: policy.name,
                      })
                    : t('pages.protectionOverview.noPolicy')}
                </p>
                {policy && (
                  <Badge tone={overrideKinds.length > 0 ? 'warning' : 'success'}>
                    {overrideKinds.length > 0
                      ? t('pages.protectionOverview.overridden', {
                          n: overrideKinds.length,
                        })
                      : t('pages.protectionOverview.followsFully')}
                  </Badge>
                )}
                {policy && (
                  <Badge tone="brand">
                    {t('pages.policies.revision', { n: policy.revision })}
                  </Badge>
                )}
              </div>
              <p className="mt-1 text-[13px] text-fg-subtle">
                {policy
                  ? t('pages.protectionOverview.followsHint')
                  : t('pages.protectionOverview.noPolicyHint')}
              </p>
            </div>
            <div className="flex flex-col items-end gap-2">
              <Badge
                tone={
                  applyState === 'applied'
                    ? 'success'
                    : applyState === 'pending' || applyState === 'partial'
                      ? 'warning'
                      : 'neutral'
                }
                dot
              >
                {t(`pages.sitePolicy.apply.${applyState}`, applyState)}
              </Badge>
              <Button size="sm" onClick={() => onSelectTab('tuning')}>
                {t('pages.protectionOverview.openPolicy')}
              </Button>
            </div>
          </div>

          <dl className="grid grid-cols-2 gap-3 border-t border-line pt-3 sm:grid-cols-3 lg:grid-cols-6">
            {stats.map((stat) => (
              <div key={stat.label}>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">
                  {stat.label}
                </dt>
                <dd className="mt-0.5 truncate text-[13px] font-medium text-fg-strong">
                  {stat.value}
                </dd>
              </div>
            ))}
          </dl>
        </CardBody>
      </Card>

      {/* Execution path */}
      <Card className="order-2">
        <CardHeader
          title={t('pages.protectionOverview.pathTitle')}
          description={t('pages.protectionOverview.pathHint')}
          action={<Pulse weight="duotone" className="h-5 w-5 text-fg-subtle" />}
        />
        <CardBody className="space-y-3">
          <ol className="grid gap-2 md:grid-cols-5">
            {stages.map((stage, index) => {
              const Icon = stage.icon
              const content = (
                <span className="flex h-full flex-col gap-1 rounded-lg border border-line px-3 py-3 text-left transition-colors hover:border-focus/40">
                  <span className="flex items-center gap-2">
                    <span className="pw-mono text-[11px] text-fg-subtle">
                      {String(index + 1).padStart(2, '0')}
                    </span>
                    <Icon weight="duotone" className="h-4 w-4 text-link" />
                  </span>
                  <span className="text-[13px] font-medium text-fg-strong">
                    {stage.title}
                  </span>
                  <span className="text-[11px] leading-snug text-fg-subtle">
                    {stage.detail}
                  </span>
                </span>
              )
              return (
                <li key={stage.id}>
                  {stage.to ? (
                    <Link to={stage.to} className="block h-full">
                      {content}
                    </Link>
                  ) : (
                    <button
                      type="button"
                      onClick={stage.onClick}
                      className="block h-full w-full"
                    >
                      {content}
                    </button>
                  )}
                </li>
              )
            })}
          </ol>
          <p className="flex items-start gap-2 rounded-md border border-focus/30 bg-focus/5 px-3 py-2 text-[12px] text-fg-subtle">
            <Shield weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
            {t('pages.protectionOverview.orderNote')}
          </p>
        </CardBody>
      </Card>

      {/* Modules */}
      <div className="order-1">
        <h2 className="text-[15px] font-semibold text-fg-strong">
          {t('pages.protectionOverview.modulesTitle')}
        </h2>
        <p className="mt-0.5 text-[13px] text-fg-subtle">
          {t('pages.protectionOverview.modulesHint')}
        </p>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {modules.map((module) => {
            const Icon = module.icon
            return (
              <Card key={module.id} className="h-full">
                <CardBody className="flex h-full flex-col gap-2">
                  <div className="flex items-start justify-between gap-2">
                    <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-recessed text-link">
                      <Icon weight="duotone" className="h-5 w-5" />
                    </span>
                    {module.chip}
                  </div>
                  <p className="text-[14px] font-semibold text-fg-strong">
                    {module.title}
                  </p>
                  <p className="flex-1 text-[12px] leading-snug text-fg-subtle">
                    {module.description}
                  </p>
                  <button
                    type="button"
                    onClick={module.onOpen}
                    className={cn(
                      'flex items-center gap-1 text-[13px] font-medium text-link hover:underline',
                    )}
                  >
                    {t('pages.protectionOverview.viewAndEdit')}
                    <ArrowRight weight="bold" className="h-3.5 w-3.5" />
                  </button>
                </CardBody>
              </Card>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export default ProtectionOverview
