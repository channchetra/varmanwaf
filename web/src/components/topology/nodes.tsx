import { createElement } from 'react'
import { Handle, Position, type NodeProps, type Node } from '@xyflow/react'
import {
  Broadcast,
  CloudArrowUp,
  Cpu,
  Cube,
  Desktop,
  Gear,
  Globe,
  Lightning,
  Lock,
  Prohibit,
  Robot,
  Shield,
  Stack,
  Tag,
  UserCircle,
  Warning,
  type Icon,
} from '@phosphor-icons/react'
import { cn } from '@/lib/utils'
import type { ChipTone, LayerKind, TopologyNodeData } from './graph'

const TONE_CLASS: Record<ChipTone, string> = {
  success: 'bg-success/12 text-fg-success',
  warning: 'bg-warning/15 text-fg',
  danger: 'bg-danger/12 text-fg-danger',
  neutral: 'bg-recessed text-fg-subtle',
  brand: 'bg-brand/12 text-brand-ink',
  info: 'bg-focus/10 text-link',
}

const LAYER_ICON: Record<LayerKind, Icon> = {
  rules: Shield,
  ratelimit: Lightning,
  ip: Prohibit,
  geo: Globe,
  bot: Robot,
  schema: Cube,
  exclusions: Tag,
  caching: CloudArrowUp,
  ssl: Lock,
  basicauth: UserCircle,
}

function Chips({ chips }: { chips?: TopologyNodeData['chips'] }) {
  if (!chips || chips.length === 0) return null
  return (
    <div className="mt-1.5 flex flex-wrap gap-1">
      {chips.map((chip, index) => (
        <span
          key={`${chip.text}-${index}`}
          className={cn(
            'rounded px-1.5 py-0.5 text-[10px] font-medium leading-4',
            TONE_CLASS[chip.tone] ?? TONE_CLASS.neutral,
          )}
        >
          {chip.text}
        </span>
      ))}
    </div>
  )
}

/** Left/right connection points, by node kind. */
function Handles({ kind }: { kind: TopologyNodeData['kind'] }) {
  const dot = '!h-2.5 !w-2.5 !border-2 !border-elevated !bg-brand'
  const left =
    kind === 'site' ||
    kind === 'waf' ||
    kind === 'route' ||
    kind === 'upstream' ||
    kind === 'agent'
  const right =
    kind === 'client' ||
    kind === 'site' ||
    kind === 'waf' ||
    kind === 'route' ||
    kind === 'control' ||
    kind === 'agent'
  return (
    <>
      {left && <Handle type="target" position={Position.Left} className={dot} />}
      {right && <Handle type="source" position={Position.Right} className={dot} />}
    </>
  )
}

function nodeIcon(kind: TopologyNodeData['kind'], layerKind?: LayerKind): Icon {
  if (kind === 'control') return Cpu
  if (kind === 'agent') return Desktop
  if (kind === 'client') return Broadcast
  if (kind === 'site') return Globe
  if (kind === 'waf') return Shield
  if (kind === 'route') return Stack
  if (kind === 'upstream') return CloudArrowUp
  if (kind === 'layer' && layerKind) return LAYER_ICON[layerKind]
  return Gear
}

/**
 * One node component for every kind: the shape is shared, the accent colour,
 * icon and chips vary. Placeholder nodes render dashed and muted so an empty
 * section is visibly "not configured" rather than missing.
 */
export function TopologyNode({ data }: NodeProps<Node<TopologyNodeData>>) {
  const { kind, label, subtitle, chips, layerKind, placeholder, healthy } = data
  // createElement keeps the icon out of a capitalized render-time variable
  // (react-hooks/static-components).
  const icon = createElement(nodeIcon(kind, layerKind), {
    weight: 'duotone',
    className: 'h-3.5 w-3.5',
  })

  const accent =
    placeholder
      ? 'border-dashed border-line bg-recessed/60 text-fg-subtle'
      : kind === 'control'
        ? 'border-brand/40 bg-brand/12'
        : kind === 'agent'
          ? 'border-focus/40 bg-focus/10'
          : kind === 'client'
            ? 'border-focus/30 bg-focus/10'
            : kind === 'site'
              ? 'border-brand/30 bg-brand/12'
              : kind === 'waf'
                ? 'border-success/30 bg-success/12'
                : kind === 'route'
                  ? 'border-warning/40 bg-warning/15'
                  : kind === 'upstream'
                    ? healthy === false
                      ? 'border-danger/30 bg-danger/12'
                      : 'border-success/30 bg-success/12'
                    : 'border-line bg-elevated'

  const isLayer = kind === 'layer'

  // Layer rows are compact: one line - icon, label, state chip - so all ten
  // layers fit the canvas without shrinking the whole graph.
  if (isLayer) {
    const chip = chips?.[0]
    return (
      <div className="flex w-[230px] items-center gap-2 rounded-lg border-2 border-line bg-elevated px-2.5 py-1.5 shadow-sm transition-shadow hover:shadow-md">
        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-brand/12 text-brand-ink">
          {icon}
        </span>
        <span className="min-w-0 flex-1 truncate text-[12px] font-medium text-fg-strong">
          {label}
        </span>
        {chip && (
          <span
            className={cn(
              'shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium leading-4',
              TONE_CLASS[chip.tone] ?? TONE_CLASS.neutral,
            )}
          >
            {chip.text}
          </span>
        )}
      </div>
    )
  }

  return (
    <div
      className={cn(
        'rounded-xl border-2 px-3 py-2 shadow-sm transition-shadow hover:shadow-md',
        isLayer ? 'w-[230px]' : 'w-[230px]',
        accent,
      )}
    >
      <Handles kind={kind} />
      <div className="flex items-center gap-2">
        <span
          className={cn(
            'flex h-6 w-6 shrink-0 items-center justify-center rounded-md',
            placeholder ? 'bg-recessed text-fg-subtle' : 'bg-elevated text-brand-ink',
          )}
        >
          {icon}
        </span>
        <div className="min-w-0 flex-1">
          <p className="truncate text-[13px] font-semibold leading-5 text-fg-strong">
            {label}
          </p>
          {subtitle && (
            <p className="truncate text-[11px] leading-4 text-fg-subtle" title={subtitle}>
              {subtitle}
            </p>
          )}
        </div>
        {placeholder && kind !== 'placeholder' && (
          <Warning weight="duotone" className="h-3.5 w-3.5 shrink-0 text-fg-warning" />
        )}
      </div>
      <Chips chips={chips} />
    </div>
  )
}

/** Group frame: a titled box the child nodes live inside. */
export function TopologyGroupNode({ data }: NodeProps<Node<TopologyNodeData>>) {
  const { label, subtitle, chips, placeholder } = data
  return (
    <div
      className={cn(
        'h-full w-full rounded-2xl border-2',
        placeholder
          ? 'border-dashed border-line bg-recessed/40'
          : 'border-line bg-recessed/50',
      )}
    >
      <div className="flex items-start gap-2 px-3 py-2">
        <div className="min-w-0 flex-1">
          <p className="truncate text-[12px] font-semibold uppercase tracking-wide text-fg-subtle">
            {label}
          </p>
          {subtitle && (
            <p className="truncate text-[11px] text-fg-subtle/80">{subtitle}</p>
          )}
        </div>
        <Chips chips={chips} />
      </div>
    </div>
  )
}

export const topologyNodeTypes = {
  topology: TopologyNode,
  topologyGroup: TopologyGroupNode,
}
