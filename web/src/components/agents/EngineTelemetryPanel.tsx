import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Gauge, Plug, ShieldCheck } from '@phosphor-icons/react'
import { agentsApi } from '@/api/agents'
import type { AgentMetricsResponse } from '@/api/types'
import { Skeleton } from '@/components/ui/Skeleton'

/**
 * Engine telemetry for one agent: shadow comparisons between the Varman
 * pipeline and the legacy engine, plus external-processor call outcomes.
 * Shipped through the generic edge-metrics pipeline (30s cadence), so the
 * numbers are the latest cumulative counters the control plane holds.
 */
export function EngineTelemetryPanel({ agentId }: { agentId: string }) {
  const { t } = useTranslation()

  const telemetry = useQuery({
    queryKey: ['agents', agentId, 'engine-telemetry'],
    queryFn: async () => {
      const [shadow, checked, processor] = await Promise.all([
        agentsApi.metrics(agentId, { name: 'varman_waf_shadow_total' }),
        agentsApi.metrics(agentId, {
          name: 'varman_waf_shadow_checked_total',
        }),
        agentsApi.metrics(agentId, {
          name: 'varman_waf_processor_calls_total',
        }),
      ])
      return { shadow, checked, processor }
    },
    enabled: Boolean(agentId),
  })

  if (telemetry.isPending) {
    return <Skeleton className="h-24 w-full" />
  }
  if (telemetry.isError || !telemetry.data) {
    return null
  }

  /** Latest cumulative value for one label set (counters are monotonic). */
  const latest = (
    response: AgentMetricsResponse,
    label?: [string, string],
  ): number | null => {
    const series = response.series.filter((entry) => {
      if (!label) {
        return true
      }
      return (entry.labels ?? {})[label[0]] === label[1]
    })
    const points = series.flatMap((entry) => entry.points)
    if (points.length === 0) {
      return null
    }
    return points.reduce((max, point) => Math.max(max, point.max), 0)
  }

  const shadow = telemetry.data.shadow
  const processor = telemetry.data.processor
  const stats: Array<{ key: string; label: string; value: number | null }> = [
    {
      key: 'checked',
      label: t('pages.agents.engine.shadowChecked'),
      value: latest(telemetry.data.checked),
    },
    {
      key: 'agree',
      label: t('pages.agents.engine.shadowAgree'),
      value: latest(shadow, ['agreement', 'agree']),
    },
    {
      key: 'stricter',
      label: t('pages.agents.engine.shadowStricter'),
      value: latest(shadow, ['agreement', 'stricter']),
    },
    {
      key: 'weaker',
      label: t('pages.agents.engine.shadowWeaker'),
      value: latest(shadow, ['agreement', 'weaker']),
    },
    {
      key: 'processor-ok',
      label: t('pages.agents.engine.processorOk'),
      value: latest(processor, ['outcome', 'ok']),
    },
    {
      key: 'processor-timeout',
      label: t('pages.agents.engine.processorTimeout'),
      value: latest(processor, ['outcome', 'timeout']),
    },
    {
      key: 'processor-failed',
      label: t('pages.agents.engine.processorFailed'),
      value: latest(processor, ['outcome', 'failed']),
    },
  ]

  const hasData = stats.some((stat) => stat.value !== null)

  return (
    <div className="border-t border-line pt-4">
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="flex items-center gap-1.5 text-[13px] font-semibold text-fg-strong">
          <Gauge weight="duotone" className="h-4 w-4" />
          {t('pages.agents.engine.title')}
        </h3>
        <span className="text-[11px] text-fg-subtle">
          {t('pages.agents.engine.cadence')}
        </span>
      </div>
      {!hasData ? (
        <p className="text-[13px] text-fg-subtle">
          {t('pages.agents.engine.noData')}
        </p>
      ) : (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {stats.map((stat) => (
            <div
              key={stat.key}
              className="rounded-md border border-line bg-recessed px-3 py-2"
            >
              <span className="block text-[11px] uppercase tracking-wide text-fg-subtle">
                {stat.label}
              </span>
              <span className="pw-mono mt-0.5 block text-sm text-fg-strong">
                {stat.value ?? '—'}
              </span>
            </div>
          ))}
        </div>
      )}
      <p className="mt-2 flex items-start gap-1.5 text-[11px] text-fg-subtle">
        <ShieldCheck weight="duotone" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        {t('pages.agents.engine.hint')}
      </p>
      <p className="mt-1 flex items-start gap-1.5 text-[11px] text-fg-subtle">
        <Plug weight="duotone" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        {t('pages.agents.engine.processorHint')}
      </p>
    </div>
  )
}
