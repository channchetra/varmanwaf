import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Background,
  BackgroundVariant,
  Controls,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Node,
  type NodeChange,
  type Edge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import {
  ArrowClockwise,
  ArrowSquareOut,
  ArrowsIn,
  CaretLeft,
  ArrowsOut,
  CloudArrowUp,
  Cpu,
  FlowArrow,
  Gauge,
  Lightning,
  Prohibit,
  Stack,
  X,
} from '@phosphor-icons/react'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { ErrorState } from '@/components/ErrorState'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useCanWrite, useSitesList } from '@/hooks'
import { useFullscreen } from '@/lib/useFullscreen'
import { sitesApi } from '@/api/sites'
import { agentsApi } from '@/api/agents'
import type { Agent } from '@/api/types'
import { systemApi } from '@/api/system'
import { wafSettingsApi } from '@/api/wafSettings'
import { rateLimitApi } from '@/api/rateLimiting'
import { ipRulesApi } from '@/api/ipRules'
import { cachingApi } from '@/api/caching'
import { siteBasicAuthApi } from '@/api/siteBasicAuth'
import { botApi } from '@/api/bot'
import { geoApi } from '@/api/geo'
import { sslApi } from '@/api/ssl'
import { rewriteApi } from '@/api/rewrite'
import { rulesApi } from '@/api/rules'
import { exclusionsApi } from '@/api/exclusions'
import {
  buildFleetGraph,
  buildTopologyGraph,
  type ChipTone,
  type TopologyGraph,
  type TopologyInput,
  type TopologyLayer,
  type TopologyNodeData,
} from '@/components/topology/graph'
import { topologyEdgeTypes } from '@/components/topology/edges'
import { topologyNodeTypes } from '@/components/topology/nodes'
import {
  TopologyPanel,
  type CreateKind,
  type TopologyPanelData,
  type TopologySelection,
} from '@/components/topology/TopologyPanel'

/** Rows or `{ items }` envelopes, whichever the endpoint returned. */
function asItems<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[]
  const items = (data as { items?: unknown } | null)?.items
  return Array.isArray(items) ? (items as T[]) : []
}

const PALETTE: Array<{ kind: CreateKind; labelKey: string; icon: typeof Stack }> = [
  { kind: 'upstream', labelKey: 'pages.topology.palette.upstream', icon: CloudArrowUp },
  { kind: 'pool', labelKey: 'pages.topology.palette.pool', icon: Cpu },
  { kind: 'route', labelKey: 'pages.topology.palette.route', icon: Stack },
  { kind: 'ratelimit', labelKey: 'pages.topology.palette.ratelimit', icon: Gauge },
  { kind: 'iprule', labelKey: 'pages.topology.palette.iprule', icon: Prohibit },
  { kind: 'cacherule', labelKey: 'pages.topology.palette.cacherule', icon: Lightning },
]

function layoutKey(siteId: string) {
  return `varman.topology.layout.${siteId}`
}

function loadLayout(siteId: string): Record<string, { x: number; y: number }> {
  try {
    const raw = localStorage.getItem(layoutKey(siteId))
    return raw ? (JSON.parse(raw) as Record<string, { x: number; y: number }>) : {}
  } catch {
    return {}
  }
}

export function TopologyPage() {
  return (
    <ReactFlowProvider>
      <TopologyRouter />
    </ReactFlowProvider>
  )
}

/** `/topology` is the fleet view; `/sites/:id/topology` is one site's flow. */
function TopologyRouter() {
  const { siteId } = useParams<{ siteId: string }>()
  return siteId ? <SiteTopology siteId={siteId} /> : <FleetTopology />
}

/* ------------------------------------------------------------------ */
/* Shared canvas chrome                                                */
/* ------------------------------------------------------------------ */

function ToolButton({
  label,
  icon,
  onClick,
}: {
  label: string
  icon: React.ReactNode
  onClick: () => void
}) {
  return (
    <Button
      size="icon"
      variant="ghost"
      aria-label={label}
      title={label}
      icon={icon}
      onClick={onClick}
    />
  )
}

function CanvasChrome({
  eyebrow,
  title,
  subtitle,
  meta,
  actions,
}: {
  eyebrow: string
  title: string
  subtitle: string
  meta?: React.ReactNode
  actions?: React.ReactNode
}) {
  return (
    <div className="pointer-events-none absolute inset-x-0 top-0 z-20 flex items-start justify-between gap-2 p-3 sm:p-4">
      <div className="pointer-events-auto min-w-0 max-w-[calc(100vw-8.5rem)] rounded-xl border border-line bg-elevated px-4 py-3 shadow-md">
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-fg-subtle">
          {eyebrow}
        </p>
        <h1 className="mt-1 truncate text-[20px] font-semibold tracking-tight text-fg-strong">
          {title}
        </h1>
        <p className="mt-0.5 truncate text-[12px] text-fg-subtle" title={subtitle}>
          {subtitle}
        </p>
        {meta && <div className="mt-2 flex flex-wrap items-center gap-1.5">{meta}</div>}
      </div>
      {actions && (
        <div className="pointer-events-auto flex shrink-0 items-center gap-1 rounded-lg border border-line bg-elevated p-1 shadow-md">
          {actions}
        </div>
      )}
    </div>
  )
}

function CanvasLegend({
  items,
}: {
  items: Array<{ label: string; className: string }>
}) {
  const { t } = useTranslation()
  return (
    <div className="pointer-events-none absolute bottom-3 right-20 z-20 hidden items-center gap-3 rounded-lg border border-line bg-elevated px-3 py-1.5 text-[10px] text-fg-subtle shadow-sm xl:flex">
      {items.map((item) => (
        <span key={item.label} className="flex items-center gap-1.5">
          <span className={`h-2 w-2 rounded-full ${item.className}`} />
          {item.label}
        </span>
      ))}
      <span className="flex items-center gap-1.5">
        <span className="h-px w-4 bg-fill" />
        {t('pages.topology.legend.animated')}
      </span>
    </div>
  )
}

function AddRail({ onPick }: { onPick: (kind: CreateKind) => void }) {
  const { t } = useTranslation()
  return (
    <div className="pointer-events-auto absolute left-3 top-1/2 z-20 flex -translate-y-1/2 flex-col items-center gap-0.5 rounded-xl border border-line bg-elevated p-1.5 shadow-md">
      <span className="px-1 pb-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-fg-subtle">
        {t('pages.topology.palette.shortTitle')}
      </span>
      {PALETTE.map((item) => {
        const Icon = item.icon
        const label = t(item.labelKey)
        return (
          <button
            key={item.kind}
            type="button"
            draggable
            aria-label={label}
            title={label}
            onDragStart={(event) => {
              event.dataTransfer.setData('application/varman-topology', item.kind)
              event.dataTransfer.effectAllowed = 'copy'
            }}
            onClick={() => onPick(item.kind)}
            className="flex h-9 w-9 cursor-grab items-center justify-center rounded-lg text-fg-subtle transition-colors hover:bg-recessed hover:text-fg-strong focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
          >
            <Icon weight="duotone" className="h-4 w-4" />
          </button>
        )
      })}
    </div>
  )
}


/* ------------------------------------------------------------------ */
/* Fleet view: control plane -> agents -> every site                   */
/* ------------------------------------------------------------------ */

function FleetTopology() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { fitView, getZoom } = useReactFlow()
  const [selection, setSelection] = useState<TopologyNodeData | null>(null)

  const { data: sites } = useSitesList()
  const agentsQuery = useQuery({
    queryKey: ['topology', 'fleet', 'agents'],
    queryFn: () => agentsApi.list(),
  })
  const versionQuery = useQuery({
    queryKey: ['topology', 'fleet', 'version'],
    queryFn: () => systemApi.version(),
  })

  const agents = useMemo(() => asItems<Agent>(agentsQuery.data), [agentsQuery.data])

  const graph: TopologyGraph = useMemo(
    () =>
      buildFleetGraph({
        controlPlane: {
          version: versionQuery.data?.version ?? '…',
          grpcTls: versionQuery.data?.grpc_tls ?? true,
          registrationOpen: versionQuery.data?.registration_open ?? false,
        },
        agents: agents.map((agent) => ({
          id: agent.id,
          hostname: agent.hostname,
          ip_address: agent.ip_address,
          status: agent.status,
          connected: agent.connected,
          site_id: agent.site_id ?? null,
          site_domain: agent.site_domain ?? null,
          served_site_ids: agent.served_site_ids ?? [],
          version: agent.version ?? null,
        })),
        sites: (sites ?? []).map((site) => ({
          id: site.id,
          name: site.name ?? '',
          domain: site.domain ?? '',
          status: site.status ?? 'active',
        })),
      }),
    [agents, sites, versionQuery.data],
  )

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const {
    attach: attachGraph,
    fullscreen: graphFullscreen,
    toggle: toggleGraphFullscreen,
  } = useFullscreen<HTMLDivElement>()
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [appliedGraph, setAppliedGraph] = useState<TopologyGraph | null>(null)
  if (appliedGraph !== graph) {
    setAppliedGraph(graph)
    setNodes(graph.nodes as Node[])
    setEdges(graph.edges)
  }

  const nodeCount = nodes.length
  useEffect(() => {
    if (nodeCount === 0) return
    const handle = window.setTimeout(() => {
      void fitView({ padding: 0.15, duration: 250 })
    }, 80)
    return () => window.clearTimeout(handle)
  }, [nodeCount, fitView])

  // Opening the inspector shrinks the canvas. Keep the clicked node centred
  // at the current zoom instead of letting the right-hand columns disappear
  // under the new panel.
  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      setSelection(node.data as TopologyNodeData)
      const zoom = getZoom()
      window.setTimeout(() => {
        void fitView({
          nodes: [node],
          padding: 0.4,
          duration: 260,
          minZoom: zoom,
          maxZoom: zoom,
        })
      }, 90)
    },
    [getZoom, fitView],
  )

  const fitAll = useCallback(() => {
    void fitView({ padding: 0.1, duration: 300 })
  }, [fitView])

  return (
    <div
      ref={attachGraph}
      className={`topology-stage -mx-4 -my-6 flex h-[calc(100dvh-var(--topbar-height))] min-h-[620px] flex-col overflow-hidden sm:-mx-6 lg:-mx-8 ${
        graphFullscreen ? 'bg-base' : 'bg-recessed'
      }`}
    >
      <div className="relative flex min-h-0 flex-1">
        <div className="relative min-w-0 flex-1">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={(changes: NodeChange<Node>[]) => onNodesChange(changes)}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            onNodeDoubleClick={(_event, node) => {
              void fitView({ nodes: [node], padding: 1.2, duration: 300 })
            }}
            onPaneClick={() => setSelection(null)}
            nodeTypes={topologyNodeTypes}
            edgeTypes={topologyEdgeTypes}
            fitView
            fitViewOptions={{ padding: 0.1 }}
            minZoom={0.2}
            maxZoom={2.5}
            nodesConnectable={false}
            proOptions={{ hideAttribution: true }}
            className="topology-canvas [&_.react-flow__node]:cursor-grab"
          >
            <Background
              variant={BackgroundVariant.Dots}
              gap={28}
              size={1.2}
              color="var(--color-border-fill)"
            />
            <Controls showInteractive={false} />
          </ReactFlow>

          <div className="topology-vignette pointer-events-none absolute inset-0 z-10" />

          <CanvasChrome
            eyebrow={t('pages.topology.fleet.eyebrow')}
            title={t('pages.topology.fleet.title')}
            subtitle={t('pages.topology.fleet.canvasHint')}
            meta={
              <>
                <Badge tone="neutral">
                  {t('pages.topology.fleet.agentCount', { n: agents.length })}
                </Badge>
                <Badge tone="neutral">
                  {t('pages.topology.fleet.siteCount', { n: (sites ?? []).length })}
                </Badge>
              </>
            }
            actions={
              <Link to="/agents">
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<ArrowSquareOut className="h-4 w-4" />}
                >
                  {t('pages.topology.fleet.openAgents')}
                </Button>
              </Link>
            }
          />

          <CanvasLegend
            items={[
              { label: t('pages.topology.fleet.legendControl'), className: 'bg-brand-ink' },
              {
                label: t('pages.topology.fleet.legendAgent'),
                className: 'bg-[var(--color-graph-control)]',
              },
              { label: t('pages.topology.fleet.legendSite'), className: 'bg-brand-ink' },
            ]}
          />

          <div className="pointer-events-none absolute inset-x-0 bottom-3 z-20 flex justify-center">
            <div className="pointer-events-auto flex items-center gap-0.5 rounded-lg border border-line bg-elevated p-1 shadow-md">
              <ToolButton
                label={t('pages.topology.fit')}
                icon={<ArrowsOut className="h-4 w-4" />}
                onClick={fitAll}
              />
              <ToolButton
                label={graphFullscreen ? t('common.exitFullscreen') : t('common.expand')}
                icon={
                  graphFullscreen ? (
                    <ArrowsIn className="h-4 w-4" />
                  ) : (
                    <ArrowsOut className="h-4 w-4" />
                  )
                }
                onClick={() => void toggleGraphFullscreen()}
              />
              <ToolButton
                label={t('common.refresh')}
                icon={<ArrowClockwise className="h-4 w-4" />}
                onClick={() => {
                  void queryClient.invalidateQueries({ queryKey: ['topology', 'fleet'] })
                }}
              />
            </div>
          </div>
        </div>

        {selection && (
          <div className="topology-inspector-wrap absolute inset-x-3 bottom-3 z-30 h-[min(70%,620px)] overflow-hidden rounded-xl border border-line bg-elevated shadow-xl xl:relative xl:inset-auto xl:z-auto xl:h-full xl:w-[380px] xl:shrink-0 xl:rounded-none xl:border-y-0 xl:border-r-0 xl:shadow-none">
            <FleetInfoPanel node={selection} onClose={() => setSelection(null)} />
          </div>
        )}
      </div>
    </div>
  )
}

function FleetInfoPanel({
  node,
  onClose,
}: {
  node: TopologyNodeData
  onClose: () => void
}) {
  const { t } = useTranslation()
  const kindLabel =
    node.kind === 'control'
      ? t('pages.topology.fleet.controlPlane')
      : node.kind === 'agent'
        ? t('pages.topology.fleet.agent')
        : t('pages.topology.kinds.site')

  return (
    <aside className="topology-inspector flex h-full w-full flex-col overflow-hidden bg-elevated">
      <header className="flex shrink-0 items-center justify-between gap-2 border-b border-line px-5 py-4">
        <div className="min-w-0">
          <p className="truncate text-[15px] font-semibold text-fg-strong">
            {node.label}
          </p>
          <p className="truncate text-[11px] text-fg-subtle">{kindLabel}</p>
        </div>
        <Button
          size="icon"
          variant="ghost"
          aria-label={t('common.close')}
          onClick={onClose}
          icon={<X className="h-4 w-4" />}
        />
      </header>
      <div className="topology-panel-scroll min-h-0 flex-1 overflow-y-auto px-5 py-4">
        {node.subtitle && (
          <p className="mb-2 text-[12px] text-fg">{node.subtitle}</p>
        )}
        <div className="mb-3 flex flex-wrap gap-1">
          {(node.chips ?? []).map((chip, index) => (
            <Badge key={`${chip.text}-${index}`} tone={chip.tone} size="sm">
              {chip.text}
            </Badge>
          ))}
        </div>
        {node.kind === 'site' && node.entityId && (
          <Link to={`/sites/${node.entityId}/topology`}>
            <Button size="sm" icon={<FlowArrow className="h-4 w-4" />}>
              {t('pages.topology.fleet.openSiteTopology')}
            </Button>
          </Link>
        )}
        {node.kind === 'agent' && (
          <Link to="/agents">
            <Button
              size="sm"
              variant="secondary"
              icon={<ArrowSquareOut className="h-4 w-4" />}
            >
              {t('pages.topology.fleet.openAgents')}
            </Button>
          </Link>
        )}
      </div>
    </aside>
  )
}

/* ------------------------------------------------------------------ */
/* Site view: the full request path for one site                       */
/* ------------------------------------------------------------------ */

function SiteTopology({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const queryClient = useQueryClient()
  const { fitView, getZoom } = useReactFlow()

  const siteQuery = useQuery({
    queryKey: ['topology', siteId, 'site'],
    queryFn: () => sitesApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const wafQuery = useQuery({
    queryKey: ['topology', siteId, 'waf'],
    queryFn: () => wafSettingsApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const routesQuery = useQuery({
    queryKey: ['topology', siteId, 'routes'],
    queryFn: () => sitesApi.listRoutes(siteId),
    enabled: Boolean(siteId),
  })
  const poolsQuery = useQuery({
    queryKey: ['topology', siteId, 'pools'],
    queryFn: () => sitesApi.listPools(siteId),
    enabled: Boolean(siteId),
  })
  const upstreamsQuery = useQuery({
    queryKey: ['topology', siteId, 'upstreams'],
    queryFn: () => sitesApi.listUpstreams(siteId),
    enabled: Boolean(siteId),
  })
  const rateLimitsQuery = useQuery({
    queryKey: ['topology', siteId, 'rate-limits'],
    queryFn: () => rateLimitApi.list(siteId),
    enabled: Boolean(siteId),
  })
  const ipRulesQuery = useQuery({
    queryKey: ['topology', siteId, 'ip-rules'],
    queryFn: () => ipRulesApi.list(siteId),
    enabled: Boolean(siteId),
  })
  const cacheQuery = useQuery({
    queryKey: ['topology', siteId, 'cache'],
    queryFn: () => cachingApi.listRules(siteId),
    enabled: Boolean(siteId),
  })
  const basicAuthQuery = useQuery({
    queryKey: ['topology', siteId, 'basic-auth'],
    queryFn: () => siteBasicAuthApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const botQuery = useQuery({
    queryKey: ['topology', siteId, 'bot'],
    queryFn: () => botApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const geoQuery = useQuery({
    queryKey: ['topology', siteId, 'geo'],
    queryFn: () => geoApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const sslQuery = useQuery({
    queryKey: ['topology', siteId, 'ssl'],
    queryFn: () => sslApi.list(siteId),
    enabled: Boolean(siteId),
  })
  const rewritesQuery = useQuery({
    queryKey: ['topology', siteId, 'rewrites'],
    queryFn: () => rewriteApi.list(siteId),
    enabled: Boolean(siteId),
  })
  const rulesQuery = useQuery({
    queryKey: ['topology', siteId, 'rules'],
    queryFn: () => rulesApi.list(siteId),
    enabled: Boolean(siteId),
  })
  const exclusionsQuery = useQuery({
    queryKey: ['topology', siteId, 'exclusions'],
    queryFn: () => exclusionsApi.bindings(siteId),
    enabled: Boolean(siteId),
  })

  const panelData: TopologyPanelData | null = useMemo(() => {
    if (!siteQuery.data || !wafQuery.data) return null
    const waf = wafQuery.data
    return {
      site: siteQuery.data.site,
      waf: {
        engine_mode: waf.engine_mode,
        mode: waf.mode ?? 'block',
        paranoia_level: waf.paranoia_level,
        waf_enabled: waf.waf_enabled,
        advanced_mode: waf.advanced_mode,
        openapi_spec: waf.openapi_spec,
      },
      routes: routesQuery.data ?? [],
      pools: poolsQuery.data ?? [],
      upstreams: upstreamsQuery.data ?? [],
      rateLimits: asItems(rateLimitsQuery.data),
      ipRules: asItems(ipRulesQuery.data),
      cacheRules: asItems(cacheQuery.data),
      basicAuth: basicAuthQuery.data ?? null,
      bot: botQuery.data ?? null,
      geo: geoQuery.data ?? null,
      ruleCount: asItems(rulesQuery.data).length,
      exclusionCount: asItems(exclusionsQuery.data).length,
      sslCount: asItems(sslQuery.data).length,
      rewriteCount: asItems(rewritesQuery.data).length,
    }
  }, [
    siteQuery.data,
    wafQuery.data,
    routesQuery.data,
    poolsQuery.data,
    upstreamsQuery.data,
    rateLimitsQuery.data,
    ipRulesQuery.data,
    cacheQuery.data,
    basicAuthQuery.data,
    botQuery.data,
    geoQuery.data,
    rulesQuery.data,
    exclusionsQuery.data,
    sslQuery.data,
    rewritesQuery.data,
  ])

  const graph: TopologyGraph | null = useMemo(() => {
    if (!panelData) return null
    const p = panelData
    const tone = (on: boolean, warn = false): ChipTone =>
      on ? (warn ? 'warning' : 'success') : 'neutral'
    const layers: TopologyLayer[] = [
      {
        kind: 'rules',
        label: t('pages.topology.layers.rules'),
        summary: t('pages.topology.layerCounts.rules', { n: p.ruleCount }),
        tone: tone(p.ruleCount > 0),
      },
      {
        kind: 'ratelimit',
        label: t('pages.topology.layers.ratelimit'),
        summary: t('pages.topology.layerCounts.ratelimit', {
          n: p.rateLimits.length,
        }),
        tone: tone(p.rateLimits.length > 0),
      },
      {
        kind: 'ip',
        label: t('pages.topology.layers.ip'),
        summary: t('pages.topology.layerCounts.ip', { n: p.ipRules.length }),
        tone: tone(p.ipRules.length > 0),
      },
      {
        kind: 'geo',
        label: t('pages.topology.layers.geo'),
        summary: p.geo?.enabled
          ? t('pages.topology.layerCounts.geoOn', {
              action: p.geo.action,
              n: (p.geo.countries ?? []).length,
            })
          : t('pages.topology.off'),
        tone: tone(Boolean(p.geo?.enabled)),
      },
      {
        kind: 'bot',
        label: t('pages.topology.layers.bot'),
        summary: p.bot?.enabled
          ? t('pages.topology.layerCounts.botOn', { action: p.bot.action })
          : t('pages.topology.off'),
        tone: tone(Boolean(p.bot?.enabled)),
      },
      {
        kind: 'schema',
        label: t('pages.topology.layers.schema'),
        summary: p.waf.openapi_spec
          ? t('pages.topology.layerCounts.schemaOn')
          : t('pages.topology.layerCounts.schemaOff'),
        tone: tone(Boolean(p.waf.openapi_spec)),
      },
      {
        kind: 'exclusions',
        label: t('pages.topology.layers.exclusions'),
        summary: t('pages.topology.layerCounts.exclusions', {
          n: p.exclusionCount,
        }),
        tone: tone(p.exclusionCount > 0),
      },
      {
        kind: 'caching',
        label: t('pages.topology.layers.caching'),
        summary: t('pages.topology.layerCounts.caching', {
          n: p.cacheRules.length,
        }),
        tone: tone(p.cacheRules.length > 0),
      },
      {
        kind: 'ssl',
        label: t('pages.topology.layers.ssl'),
        summary: t('pages.topology.layerCounts.ssl', { n: p.sslCount }),
        tone: tone(p.sslCount > 0, p.sslCount === 0),
      },
      {
        kind: 'basicauth',
        label: t('pages.topology.layers.basicauth'),
        summary: p.basicAuth?.enabled
          ? t('pages.topology.layerCounts.basicauthOn', {
              n: (p.basicAuth.credentials ?? []).length,
            })
          : t('pages.topology.off'),
        tone: tone(Boolean(p.basicAuth?.enabled)),
      },
    ]

    const input: TopologyInput = {
      site: {
        id: p.site.id,
        name: p.site.name ?? '',
        domain: p.site.domain ?? '',
        alternate_domains: p.site.alternate_domains ?? [],
        status: p.site.status ?? 'active',
      },
      waf: {
        engine_mode: p.waf.engine_mode || 'inherit',
        mode: p.waf.mode,
        paranoia_level: p.waf.paranoia_level,
        waf_enabled: p.waf.waf_enabled,
        advanced_mode: p.waf.advanced_mode,
      },
      layers,
      routes: p.routes.map((route) => ({
        id: route.id,
        name: route.name ?? '',
        path: route.path ?? '/',
        match_type: route.match_type ?? 'prefix',
        enabled: route.enabled,
        pool_id: route.pool_id,
        ip_group_id: route.ip_group_id ?? null,
      })),
      pools: p.pools.map((pool) => ({
        id: pool.id,
        name: pool.name,
        lb_algorithm: pool.lb_algorithm,
        is_default: pool.is_default,
      })),
      upstreams: p.upstreams.map((up) => ({
        id: up.id,
        name: up.name,
        address: up.address,
        weight: up.weight,
        tls: up.tls,
        health_status: up.health_status,
        pool_id: up.pool_id,
      })),
      rewriteCount: p.rewriteCount,
    }
    return buildTopologyGraph(input)
  }, [panelData, t])

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const {
    attach: attachGraph,
    fullscreen: graphFullscreen,
    toggle: toggleGraphFullscreen,
  } = useFullscreen<HTMLDivElement>()
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [selection, setSelection] = useState<TopologySelection | null>(null)

  const applied = useMemo(() => {
    if (!graph) return null
    const saved = loadLayout(siteId)
    return {
      nodes: graph.nodes.map((node) =>
        saved[node.id] ? { ...node, position: saved[node.id] } : node,
      ) as Node[],
      edges: graph.edges,
    }
  }, [graph, siteId])
  const [appliedGraph, setAppliedGraph] = useState(applied)
  if (appliedGraph !== applied) {
    setAppliedGraph(applied)
    setNodes(applied?.nodes ?? [])
    setEdges(applied?.edges ?? [])
  }

  const nodeCount = nodes.length
  useEffect(() => {
    if (nodeCount === 0) return
    const handle = window.setTimeout(() => {
      void fitView({ padding: 0.15, duration: 250 })
    }, 80)
    return () => window.clearTimeout(handle)
  }, [nodeCount, fitView])

  const persistLayout = useCallback(() => {
    const layout: Record<string, { x: number; y: number }> = {}
    for (const node of nodes) {
      layout[node.id] = { x: node.position.x, y: node.position.y }
    }
    try {
      localStorage.setItem(layoutKey(siteId), JSON.stringify(layout))
    } catch {
      /* storage full or blocked - arrangement stays in memory */
    }
  }, [nodes, siteId])

  const autoLayout = useCallback(() => {
    try {
      localStorage.removeItem(layoutKey(siteId))
    } catch {
      /* ignore */
    }
    if (graph) {
      setNodes(graph.nodes as Node[])
      setEdges(graph.edges)
    }
    window.setTimeout(() => void fitView({ padding: 0.15, duration: 300 }), 50)
  }, [graph, siteId, setNodes, setEdges, fitView])

  // Docking the inspector narrows the canvas; centre the clicked node so the
  // editor never opens on a node that just slid behind the panel.
  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      setSelection({
        type: 'node',
        nodeId: node.id,
        data: node.data as TopologyNodeData,
      })
      const zoom = getZoom()
      window.setTimeout(() => {
        void fitView({
          nodes: [node],
          padding: 0.4,
          duration: 260,
          minZoom: zoom,
          maxZoom: zoom,
        })
      }, 90)
    },
    [getZoom, fitView],
  )

  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = 'copy'
  }, [])

  const onDrop = useCallback((event: React.DragEvent) => {
    event.preventDefault()
    const kind = event.dataTransfer.getData(
      'application/varman-topology',
    ) as CreateKind
    if (!kind) return
    // The drop opens the create form; nothing is written until it is saved.
    setSelection({ type: 'create', kind })
  }, [])

  const invalidate = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ['topology', siteId] })
    void queryClient.invalidateQueries({ queryKey: ['sites'] })
  }, [queryClient, siteId])

  const openCreate = useCallback((kind: CreateKind) => {
    setSelection({ type: 'create', kind })
  }, [])

  const fitAll = useCallback(() => {
    void fitView({ padding: 0.08, duration: 300 })
  }, [fitView])

  if (siteQuery.isError && !siteQuery.data) {
    return (
      <div className="animate-slide-up">
        <ErrorState
          error={siteQuery.error}
          onRetry={() => siteQuery.refetch()}
          retrying={siteQuery.isFetching}
        />
      </div>
    )
  }

  const site = siteQuery.data?.site

  return (
    <div
      ref={attachGraph}
      className={`topology-stage -mx-4 -my-6 flex h-[calc(100dvh-var(--topbar-height))] min-h-[620px] flex-col overflow-hidden sm:-mx-6 lg:-mx-8 ${
        graphFullscreen ? 'bg-base' : 'bg-recessed'
      }`}
    >
      <div className="relative flex min-h-0 flex-1">
        <div className="relative min-w-0 flex-1">
          {graph === null ? (
            <div className="flex h-full items-center justify-center p-6">
              <SkeletonCard />
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={(changes: NodeChange<Node>[]) => {
                onNodesChange(changes)
              }}
              onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              onNodeDoubleClick={(_event, node) => {
                void fitView({ nodes: [node], padding: 1.2, duration: 300 })
              }}
              onPaneClick={() => setSelection(null)}
              onNodeDragStop={persistLayout}
              onDragOver={onDragOver}
              onDrop={onDrop}
              nodeTypes={topologyNodeTypes}
              edgeTypes={topologyEdgeTypes}
              fitView
              fitViewOptions={{ padding: 0.08 }}
              minZoom={0.2}
              maxZoom={2.5}
              nodesConnectable={false}
              proOptions={{ hideAttribution: true }}
              className="topology-canvas [&_.react-flow__node]:cursor-grab"
            >
              <Background
                variant={BackgroundVariant.Dots}
                gap={28}
                size={1.2}
                color="var(--color-border-fill)"
              />
              <Controls showInteractive={false} />
            </ReactFlow>
          )}

          <div className="topology-vignette pointer-events-none absolute inset-0 z-10" />

          <CanvasChrome
            eyebrow={t('pages.topology.title')}
            title={site ? site.name || site.domain : t('pages.topology.title')}
            subtitle={
              site
                ? `${site.domain} · ${t('pages.topology.canvasHint')}`
                : t('pages.topology.canvasHint')
            }
            meta={
              <>
                {site && <Badge tone="brand">{site.domain}</Badge>}
                <Badge tone="neutral">
                  {t('pages.topology.nodeCount', { n: nodes.length })}
                </Badge>
                <Badge tone="neutral">
                  {t('pages.topology.edgeCount', { n: edges.length })}
                </Badge>
              </>
            }
            actions={
              <>
                <Link to={`/sites/${siteId}/overview`}>
                  <Button
                    size="sm"
                    variant="ghost"
                    icon={<CaretLeft className="h-4 w-4" />}
                  >
                    {t('pages.topology.backToSite')}
                  </Button>
                </Link>
                <Link to="/topology">
                  <Button
                    size="sm"
                    variant="ghost"
                    icon={<FlowArrow className="h-4 w-4" />}
                  >
                    {t('pages.topology.fleet.openFleet')}
                  </Button>
                </Link>
              </>
            }
          />

          {canWrite && <AddRail onPick={openCreate} />}

          <CanvasLegend
            items={[
              { label: t('pages.topology.legend.site'), className: 'bg-brand-ink' },
              { label: t('pages.topology.legend.waf'), className: 'bg-success' },
              { label: t('pages.topology.legend.route'), className: 'bg-warning' },
              { label: t('pages.topology.legend.upstream'), className: 'bg-success' },
            ]}
          />

          <div className="pointer-events-none absolute inset-x-0 bottom-3 z-20 flex justify-center">
            <div className="pointer-events-auto flex items-center gap-0.5 rounded-lg border border-line bg-elevated p-1 shadow-md">
              <ToolButton
                label={t('pages.topology.fit')}
                icon={<ArrowsOut className="h-4 w-4" />}
                onClick={fitAll}
              />
              <ToolButton
                label={t('pages.topology.autoLayout')}
                icon={<FlowArrow className="h-4 w-4" />}
                onClick={autoLayout}
              />
              <ToolButton
                label={graphFullscreen ? t('common.exitFullscreen') : t('common.expand')}
                icon={
                  graphFullscreen ? (
                    <ArrowsIn className="h-4 w-4" />
                  ) : (
                    <ArrowsOut className="h-4 w-4" />
                  )
                }
                onClick={() => void toggleGraphFullscreen()}
              />
              <ToolButton
                label={t('common.refresh')}
                icon={<ArrowClockwise className="h-4 w-4" />}
                onClick={() => {
                  void queryClient.invalidateQueries({
                    queryKey: ['topology', siteId],
                  })
                }}
              />
            </div>
          </div>
        </div>

        {selection && (
          <div className="topology-inspector-wrap absolute inset-x-3 bottom-3 z-30 h-[min(70%,620px)] overflow-hidden rounded-xl border border-line bg-elevated shadow-xl xl:relative xl:inset-auto xl:z-auto xl:h-full xl:w-[420px] xl:shrink-0 xl:rounded-none xl:border-y-0 xl:border-r-0 xl:shadow-none">
            <TopologyPanel
              siteId={siteId}
              selection={selection}
              data={panelData ?? EMPTY_PANEL_DATA}
              onClose={() => setSelection(null)}
              onChanged={invalidate}
              className="h-full"
            />
          </div>
        )}
      </div>
    </div>
  )
}

const EMPTY_PANEL_DATA: TopologyPanelData = {
  site: {
    id: '',
    name: '',
    domain: '',
    alternate_domains: [],
    status: 'active',
    protection_mode: 'block',
    plan: 'free',
    cache_quota_mb: 0,
    user_id: '',
    created_at: '',
    updated_at: '',
  },
  waf: {
    engine_mode: 'inherit',
    mode: 'block',
    paranoia_level: 1,
    waf_enabled: true,
    advanced_mode: false,
    openapi_spec: '',
  },
  routes: [],
  pools: [],
  upstreams: [],
  rateLimits: [],
  ipRules: [],
  cacheRules: [],
  basicAuth: null,
  bot: null,
  geo: null,
  ruleCount: 0,
  exclusionCount: 0,
  sslCount: 0,
  rewriteCount: 0,
}

export default TopologyPage
