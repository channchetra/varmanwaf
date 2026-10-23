import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  BracketsCurly,
  ClockCounterClockwise,
  Flask,
  Package,
  ShieldCheck,
  Sliders,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { QuickNav } from '@/components/ui/QuickNav'
import { policiesApi, policyKeys } from '@/api/policies'
import { exclusionsApi, exclusionsKeys } from '@/api/exclusions'
import { PolicyPage } from './PolicyPage'
import { ExclusionPackagesPanel } from './ExclusionPackagesPanel'
import { ProtectionSettingsPanel } from './ProtectionSettingsPanel'

/**
 * Policy tuning: one surface for the site's protection posture, learned from
 * Tiyi's policy-tuning layout - a summary header with state chips, a left
 * navigation, and the sections the operator actually tunes (posture, rule
 * exceptions, exclusion packages, preview and history). The panels that
 * already existed keep their own homes; the sections anchor to them instead
 * of duplicating state.
 */
export function PolicyTuningPage() {
  const { t } = useTranslation()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const effective = useQuery({
    queryKey: policyKeys.siteEffective(siteId),
    queryFn: () => policiesApi.effectiveConfig(siteId),
    enabled: Boolean(siteId),
  })
  const bindings = useQuery({
    queryKey: exclusionsKeys.bindings(siteId),
    queryFn: () => exclusionsApi.bindings(siteId),
    enabled: Boolean(siteId),
  })

  const sections = [
    { id: 'tuning-summary', label: t('pages.tuning.summary') },
    { id: 'tuning-posture', label: t('pages.tuning.posture') },
    { id: 'policy-effective', label: t('pages.tuning.crs') },
    { id: 'policy-overrides', label: t('pages.tuning.exceptions') },
    { id: 'tuning-packages', label: t('pages.tuning.packages') },
    { id: 'policy-plan', label: t('pages.tuning.preview') },
    { id: 'tuning-history', label: t('pages.tuning.history') },
  ]

  return (
    <div className="flex items-start gap-8">
      <QuickNav ariaLabel={t('pages.tuning.quickNav')} items={sections} />
      <div className="min-w-0 flex-1 space-y-5">
        <section id="tuning-summary" className="scroll-mt-6">
          <TuningSummary
            siteId={siteId}
            effective={effective.data}
            bindings={bindings.data?.length ?? 0}
          />
        </section>

        {/* The site's own posture knobs (the former Settings tab): they
            apply until an assigned policy overrides them. */}
        <section id="tuning-posture" className="scroll-mt-6">
          <ProtectionSettingsPanel />
        </section>

        {/* Posture, rule exceptions, preview and apply keep their existing
            panels; the nav anchors into them. */}
        <PolicyPage />

        <section id="tuning-packages" className="scroll-mt-6">
          <ExclusionPackagesPanel />
        </section>

        <section id="tuning-history" className="scroll-mt-6">
          <Card>
            <CardHeader
              title={t('pages.tuning.history')}
              description={t('pages.tuning.historyHint')}
              action={
                <ClockCounterClockwise
                  weight="duotone"
                  className="h-5 w-5 text-fg-subtle"
                />
              }
            />
            <CardBody className="flex flex-wrap gap-2">
              <Link
                to="/config-history"
                className="inline-flex items-center gap-1.5 rounded-md border border-line bg-recessed/40 px-3 py-1.5 text-[13px] font-medium text-link hover:bg-elevated"
              >
                <ClockCounterClockwise weight="duotone" className="h-4 w-4" />
                {t('pages.tuning.historyLink')}
              </Link>
              <Link
                to="/policies"
                className="inline-flex items-center gap-1.5 rounded-md border border-line bg-recessed/40 px-3 py-1.5 text-[13px] font-medium text-link hover:bg-elevated"
              >
                <BracketsCurly weight="duotone" className="h-4 w-4" />
                {t('pages.tuning.policiesLink')}
              </Link>
            </CardBody>
          </Card>
        </section>
      </div>
    </div>
  )
}

/** The state chips Tiyi puts above the tuning sections. */
function TuningSummary({
  siteId,
  effective,
  bindings,
}: {
  siteId: string
  effective:
    | {
        source: 'policy' | 'site'
        policy: { name: string } | null
        overridden: boolean
        effective: {
          waf_enabled: boolean
          mode: string | null
          paranoia_level: number
          advanced_mode: boolean
          engine_mode: string
          disabled_rules: string[]
          rule_target_exclusions: Record<string, string[]>
        }
        plan: Array<{ effective: 'enforce' | 'monitor' | 'disabled' }>
      }
    | undefined
  bindings: number
}) {
  const { t } = useTranslation()

  const enforced = effective?.plan.filter((row) => row.effective === 'enforce').length ?? 0
  const monitored = effective?.plan.filter((row) => row.effective === 'monitor').length ?? 0
  const disabled = effective?.plan.filter((row) => row.effective === 'disabled').length ?? 0
  const exclusions = effective
    ? Object.values(effective.effective.rule_target_exclusions).length
    : 0

  return (
    <Card>
      <CardHeader
        title={t('pages.tuning.summary')}
        description={t('pages.tuning.summaryHint')}
        action={
          <ShieldCheck weight="duotone" className="h-5 w-5 text-fg-subtle" />
        }
      />
      <CardBody className="flex flex-wrap items-center gap-2">
        {effective ? (
          <>
            <Badge
              tone={effective.effective.waf_enabled ? 'success' : 'neutral'}
              dot
              size="sm"
            >
              {effective.effective.waf_enabled
                ? t('pages.tuning.engineOn')
                : t('pages.tuning.engineOff')}
            </Badge>
            <Badge tone="neutral" size="sm">
              {t('pages.tuning.paranoia', {
                level: effective.effective.paranoia_level,
              })}
            </Badge>
            <Badge
              tone={effective.effective.advanced_mode ? 'warning' : 'neutral'}
              size="sm"
            >
              {effective.effective.advanced_mode
                ? t('pages.tuning.strict')
                : t('pages.tuning.normal')}
            </Badge>
            <Badge tone="neutral" size="sm">
              {t('pages.tuning.plan', {
                enforced,
                monitored,
                disabled,
              })}
            </Badge>
            <Badge tone="neutral" size="sm">
              {t('pages.tuning.engineMode', {
                mode: effective.effective.engine_mode || 'inherit',
              })}
            </Badge>
            <Badge
              tone={effective.source === 'policy' ? 'brand' : 'neutral'}
              size="sm"
            >
              {effective.source === 'policy'
                ? t('pages.tuning.fromPolicy', {
                    name: effective.policy?.name ?? '',
                  })
                : t('pages.tuning.fromSite')}
            </Badge>
            {effective.overridden && (
              <Badge tone="warning" size="sm">
                {t('pages.tuning.overridden')}
              </Badge>
            )}
          </>
        ) : (
          <span className="text-[13px] text-fg-subtle">
            {t('common.loading')}
          </span>
        )}
        <span className="inline-flex items-center gap-1.5 text-[12px] text-fg-subtle">
          <Sliders weight="duotone" className="h-4 w-4" />
          {t('pages.tuning.exclusions', { count: exclusions })}
        </span>
        <Link
          to={`/sites/${siteId}/security/access`}
          className="inline-flex items-center gap-1.5 text-[12px] text-link hover:underline"
        >
          <Flask weight="duotone" className="h-4 w-4" />
          {t('pages.tuning.ipAccessLink')}
        </Link>
        <Link
          to={`/sites/${siteId}/security/rate-limiting`}
          className="inline-flex items-center gap-1.5 text-[12px] text-link hover:underline"
        >
          <GaugeIcon />
          {t('pages.tuning.rateLimitsLink')}
        </Link>
        <Link
          to={`/sites/${siteId}/security/api-assets`}
          className="inline-flex items-center gap-1.5 text-[12px] text-link hover:underline"
        >
          <Package weight="duotone" className="h-4 w-4" />
          {t('pages.tuning.apiAssetsLink')}
        </Link>
        {bindings > 0 && (
          <Badge tone="brand" size="sm">
            {t('pages.tuning.bindings', { count: bindings })}
          </Badge>
        )}
      </CardBody>
    </Card>
  )
}

/** Small inline gauge glyph (keeps the icon import list short). */
function GaugeIcon() {
  return <Sliders weight="duotone" className="h-4 w-4" />
}

export default PolicyTuningPage
