import { useMemo, type ReactElement, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  Cpu,
  HardDrives,
  Pulse,
  Timer,
  UsersThree,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { agentKeys, agentsApi } from '@/api/agents'
import { cn } from '@/lib/utils'
import {
  formatCompactNumber,
  formatPercent,
  formatSize,
  formatTime,
} from '@/lib/format'
import type { HostSample } from '@/api/types'

/**
 * Probe points drawn per chart. The control plane persists one sample per
 * minute, so 200 points spans a little over three hours of history.
 */
const SAMPLE_LIMIT = 200

/** Matches the heartbeat cadence the samples ride on. */
const REFRESH_MS = 30_000

const tooltipStyle = {
  background: 'var(--color-bg-elevated)',
  border: '1px solid var(--color-border-line)',
  borderRadius: 8,
  fontSize: 12,
  color: 'var(--color-text-default)',
}

const axisTick = { fontSize: 11, fill: 'var(--color-text-subtle)' }

/** A probe sample with the derived series the charts need. */
interface ProbePoint {
  at: number
  time: string
  cpu: number | null
  load1: number | null
  load5: number | null
  load15: number | null
  memoryPercent: number | null
  rxRate: number | null
  txRate: number | null
}

/**
 * Host probe history for one node: CPU, memory, load and network throughput,
 * plus the current values of the things that only move slowly (disk, process
 * count, uptime).
 *
 * Samples arrive newest-first from the API and carry cumulative byte counters,
 * so the series are reversed and differenced here.
 */
export function AgentProbePanel({ agentId }: { agentId: string }) {
  const { t } = useTranslation()

  const samplesQuery = useQuery({
    queryKey: agentKeys.samples(agentId, { page_size: SAMPLE_LIMIT }),
    queryFn: () => agentsApi.samples(agentId, { page_size: SAMPLE_LIMIT }),
    refetchInterval: REFRESH_MS,
  })

  const samples = useMemo(
    () => samplesQuery.data?.items ?? [],
    [samplesQuery.data],
  )

  const points = useMemo<ProbePoint[]>(() => {
    const ascending = [...samples].sort(
      (a, b) => sampleTime(a) - sampleTime(b),
    )

    return ascending.map((sample, i) => {
      const previous = i > 0 ? ascending[i - 1] : undefined
      const previousAt = previous ? sampleTime(previous) : 0
      const at = sampleTime(sample)
      const elapsed = (at - previousAt) / 1000
      const rate = (current: number | null, before: number | null) => {
        if (current === null || before === null || elapsed <= 0) return null
        // Counters reset when the host reboots; clamp instead of drawing a spike.
        return Math.max(0, (current - before) / elapsed)
      }

      return {
        at,
        time: formatTime(sample.sampled_at),
        cpu: sample.cpu_usage_percent,
        load1: sample.load1,
        load5: sample.load5,
        load15: sample.load15,
        memoryPercent: percent(sample.memory_used_bytes, sample.memory_total_bytes),
        rxRate: rate(sample.net_rx_bytes, previous?.net_rx_bytes ?? null),
        txRate: rate(sample.net_tx_bytes, previous?.net_tx_bytes ?? null),
      }
    })
  }, [samples])

  const latest = useMemo(() => latestSample(samples), [samples])
  const memoryPercent = percent(latest?.memory_used_bytes, latest?.memory_total_bytes)
  const diskPercent = percent(latest?.disk_used_bytes, latest?.disk_total_bytes)

  if (samplesQuery.isPending) {
    return (
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        {[0, 1, 2, 3, 4, 5].map((key) => (
          <span key={key} className="pw-skeleton h-16 rounded-lg" />
        ))}
      </div>
    )
  }

  if (samples.length === 0) {
    return (
      <EmptyState
        className="border-0 py-10"
        icon={<Pulse weight="duotone" className="h-8 w-8" />}
        title={t('pages.agents.probe.empty')}
        description={t('pages.agents.probe.emptyDescription')}
      />
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <ProbeTile
          icon={<Cpu weight="duotone" className="h-4 w-4" />}
          label={t('pages.agents.probe.memory')}
          value={memoryPercent != null ? formatPercent(memoryPercent / 100) : '—'}
          hint={
            latest
              ? `${formatSize(latest.memory_used_bytes)} / ${formatSize(latest.memory_total_bytes)}`
              : undefined
          }
        />
        <ProbeTile
          icon={<HardDrives weight="duotone" className="h-4 w-4" />}
          label={t('pages.agents.probe.disk')}
          value={diskPercent != null ? formatPercent(diskPercent / 100) : '—'}
          hint={
            latest
              ? `${formatSize(latest.disk_used_bytes)} / ${formatSize(latest.disk_total_bytes)}`
              : undefined
          }
        />
        <ProbeTile
          icon={<UsersThree weight="duotone" className="h-4 w-4" />}
          label={t('pages.agents.probe.processes')}
          value={latest?.process_count != null ? formatCompactNumber(latest.process_count) : '—'}
          hint={t('pages.agents.probe.tcpConnections', {
            count: latest?.tcp_connections ?? 0,
          })}
        />
        <ProbeTile
          icon={<Timer weight="duotone" className="h-4 w-4" />}
          label={t('pages.agents.probe.uptime')}
          value={latest?.uptime_secs != null ? formatUptime(latest.uptime_secs) : '—'}
          hint={latest ? formatTime(latest.sampled_at) : undefined}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ProbeChart
          title={t('pages.agents.probe.cpu')}
          description={t('pages.agents.probe.cpuHint')}
        >
          <AreaChart data={points} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="probeCpu" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f6821f" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#f6821f" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border-line)" vertical={false} />
            <XAxis dataKey="time" tick={axisTick} tickLine={false} axisLine={{ stroke: 'var(--color-border-line)' }} minTickGap={28} />
            <YAxis tick={axisTick} tickLine={false} axisLine={false} domain={[0, 100]} tickFormatter={(v: number) => `${v}%`} />
            <Tooltip contentStyle={tooltipStyle} formatter={(v) => formatPercent(Number(v ?? 0) / 100)} />
            <Area type="monotone" dataKey="cpu" name={t('pages.agents.probe.cpu')} stroke="#f6821f" strokeWidth={2} fill="url(#probeCpu)" connectNulls />
          </AreaChart>
        </ProbeChart>

        <ProbeChart
          title={t('pages.agents.probe.memoryPercent')}
          description={t('pages.agents.probe.memoryHint')}
        >
          <AreaChart data={points} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="probeMem" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#0051c3" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#0051c3" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border-line)" vertical={false} />
            <XAxis dataKey="time" tick={axisTick} tickLine={false} axisLine={{ stroke: 'var(--color-border-line)' }} minTickGap={28} />
            <YAxis tick={axisTick} tickLine={false} axisLine={false} domain={[0, 100]} tickFormatter={(v: number) => `${v}%`} />
            <Tooltip contentStyle={tooltipStyle} formatter={(v) => formatPercent(Number(v ?? 0) / 100)} />
            <Area type="monotone" dataKey="memoryPercent" name={t('pages.agents.probe.memory')} stroke="#0051c3" strokeWidth={2} fill="url(#probeMem)" connectNulls />
          </AreaChart>
        </ProbeChart>

        <ProbeChart
          title={t('pages.agents.probe.load')}
          description={t('pages.agents.probe.loadHint')}
        >
          <LineChart data={points} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border-line)" vertical={false} />
            <XAxis dataKey="time" tick={axisTick} tickLine={false} axisLine={{ stroke: 'var(--color-border-line)' }} minTickGap={28} />
            <YAxis tick={axisTick} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} formatter={(v) => Number(v ?? 0).toFixed(2)} />
            <Legend wrapperStyle={{ fontSize: 12 }} iconType="circle" />
            <Line type="monotone" dataKey="load1" name="1m" stroke="#e54d2a" strokeWidth={2} dot={false} connectNulls />
            <Line type="monotone" dataKey="load5" name="5m" stroke="#ffb224" strokeWidth={2} dot={false} connectNulls />
            <Line type="monotone" dataKey="load15" name="15m" stroke="#18794e" strokeWidth={2} dot={false} connectNulls />
          </LineChart>
        </ProbeChart>

        <ProbeChart
          title={t('pages.agents.probe.network')}
          description={t('pages.agents.probe.networkHint')}
        >
          <AreaChart data={points} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="probeTx" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#18794e" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#18794e" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border-line)" vertical={false} />
            <XAxis dataKey="time" tick={axisTick} tickLine={false} axisLine={{ stroke: 'var(--color-border-line)' }} minTickGap={28} />
            <YAxis tick={axisTick} tickLine={false} axisLine={false} tickFormatter={(v: number) => `${formatSize(v)}/s`} />
            <Tooltip contentStyle={tooltipStyle} formatter={(v) => `${formatSize(Number(v ?? 0))}/s`} />
            <Legend wrapperStyle={{ fontSize: 12 }} iconType="circle" />
            <Area type="monotone" dataKey="rxRate" name={t('pages.agents.probe.rx')} stroke="#0051c3" strokeWidth={2} fill="transparent" connectNulls />
            <Area type="monotone" dataKey="txRate" name={t('pages.agents.probe.tx')} stroke="#18794e" strokeWidth={2} fill="url(#probeTx)" connectNulls />
          </AreaChart>
        </ProbeChart>
      </div>
    </div>
  )
}

/** Wraps one chart in a card with a fixed height so the grid rows line up. */
function ProbeChart({
  title,
  description,
  children,
}: {
  title: string
  description?: string
  children: ReactElement
}) {
  return (
    <Card>
      <CardHeader title={title} description={description} />
      <CardBody>
        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            {children}
          </ResponsiveContainer>
        </div>
      </CardBody>
    </Card>
  )
}

function ProbeTile({
  icon,
  label,
  value,
  hint,
}: {
  icon: ReactNode
  label: string
  value: string
  hint?: string
}) {
  return (
    <div className="rounded-lg border border-line bg-recessed px-3 py-2.5">
      <span className="flex items-center gap-1.5 text-[11px] text-fg-subtle">
        {icon}
        {label}
      </span>
      <p className={cn('mt-1 truncate text-sm font-medium text-fg-strong')}>{value}</p>
      {hint && <p className="mt-0.5 truncate text-[11px] text-fg-subtle">{hint}</p>}
    </div>
  )
}

/** Epoch millis of a sample, tolerating an unparsable timestamp. */
function sampleTime(sample: HostSample): number {
  const parsed = new Date(sample.sampled_at).getTime()
  return Number.isNaN(parsed) ? 0 : parsed
}

/** Newest sample by `sampled_at`, which is what the API returns first anyway. */
function latestSample(samples: HostSample[]): HostSample | undefined {
  return samples.reduce<HostSample | undefined>(
    (newest, sample) =>
      !newest || sampleTime(sample) > sampleTime(newest) ? sample : newest,
    undefined,
  )
}

function percent(used: number | null | undefined, total: number | null | undefined): number | null {
  if (used == null || total == null || total <= 0) return null
  return (used / total) * 100
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86_400)
  const hours = Math.floor((seconds % 86_400) / 3_600)
  const minutes = Math.floor((seconds % 3_600) / 60)
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

export default AgentProbePanel
