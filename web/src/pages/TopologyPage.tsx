import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
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
  ArrowsOut,
  CloudArrowUp,
  Cpu,
  FlowArrow,
  Gauge,
  Lightning,
  Plus,
  Prohibit,
  Stack,
  Tag,
  X,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Callout } from '@/components/ui/Callout'
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
/* Fleet view: control plane -> agents -> every site                   */
/* ------------------------------------------------------------------ */

function FleetTopology() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { fitView } = useReactFlow()
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

  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      setSelection(node.data as TopologyNodeData)
    },
    [],
  )

  const refreshing = agentsQuery.isFetching || versionQuery.isFetching

  return (
    <div className="animate-slide-up flex h-[calc(100vh-140px)] min-h-[560px] flex-col">
      <PageHeader
        title={t('pages.topology.fleet.title')}
        description={t('pages.topology.fleet.description')}
      />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Badge tone="neutral">
          {t('pages.topology.fleet.agentCount', { n: agents.length })}
        </Badge>
        <Badge tone="neutral">
          {t('pages.topology.fleet.siteCount', { n: (sites ?? []).length })}
        </Badge>
        <div className="ml-auto flex items-center gap-2">
          <Link to="/agents">
            <Button size="sm" variant="ghost" icon={<ArrowSquareOut className="h-4 w-4" />}>
              {t('pages.topology.fleet.openAgents')}
            </Button>
          </Link>
          <Button
            size="sm"
            variant="ghost"
            title={graphFullscreen ? t('common.exitFullscreen') : t('common.expand')}
            icon={
              graphFullscreen ? (
                <ArrowsIn className="h-4 w-4" />
              ) : (
                <ArrowsOut className="h-4 w-4" />
              )
            }
            onClick={() => void toggleGraphFullscreen()}
          >
            {graphFullscreen ? t('common.exitFullscreen') : t('common.expand')}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={<ArrowClockwise className="h-4 w-4" />}
            loading={refreshing}
            onClick={() => {
              void queryClient.invalidateQueries({ queryKey: ['topology', 'fleet'] })
            }}
          >
            {t('common.refresh')}
          </Button>
        </div>
      </div>

      <Callout
        dismissKey="topology.fleet"
        tone="brand"
        className="mb-3"
        icon={<FlowArrow weight="duotone" className="h-5 w-5" />}
        title={t('pages.topology.fleet.overviewTitle')}
      >
        {t('pages.topology.fleet.overview')}
      </Callout>

      <div
        ref={attachGraph}
        className={`relative min-h-0 flex-1 overflow-hidden rounded-xl border border-line ${
          graphFullscreen ? 'rounded-none border-0 bg-bg' : 'bg-recessed/30'
        }`}
      >
        {graphFullscreen && (
          <div className="absolute right-3 top-3 z-10">
            <Button
              size="sm"
              variant="secondary"
              icon={<ArrowsIn className="h-4 w-4" />}
              onClick={() => void toggleGraphFullscreen()}
            >
              {t('common.exitFullscreen')}
            </Button>
          </div>
        )}
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={(changes: NodeChange<Node>[]) => onNodesChange(changes)}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          nodeTypes={topologyNodeTypes}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          minZoom={0.2}
          maxZoom={2.5}
          nodesConnectable={false}
          proOptions={{ hideAttribution: true }}
          className="[&_.react-flow__node]:cursor-grab"
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1} />
          <Controls showInteractive={false} />
          <MiniMap
            pannable
            zoomable
            nodeColor={(node) => {
              const kind = (node.data as { kind?: string })?.kind
              switch (kind) {
                case 'control':
                  return 'var(--color-text-brand)'
                case 'agent':
                  return 'var(--color-graph-control)'
                case 'site':
                  return 'var(--color-text-brand)'
                default:
                  return 'var(--color-border-fill)'
              }
            }}
          />
        </ReactFlow>

        {selection && (
          <FleetInfoPanel
            node={selection}
            onClose={() => setSelection(null)}
          />
        )}

        <div className="pointer-events-none absolute bottom-3 left-3 flex items-center gap-3 rounded-lg border border-line bg-elevated/95 px-3 py-1.5 text-[10px] text-fg-subtle">
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-brand-ink" />
            {t('pages.topology.fleet.legendControl')}
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-[var(--color-graph-control)]" />
            {t('pages.topology.fleet.legendAgent')}
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-brand-ink" />
            {t('pages.topology.fleet.legendSite')}
          </span>
          <span className="flex items-center gap-1">
            <Tag className="h-3 w-3" />
            {t('pages.topology.legend.animated')}
          </span>
        </div>
      </div>

      <p className="mt-2 text-[11px] text-fg-subtle">
        {t('pages.topology.fleet.hint')}
      </p>
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
    <aside className="absolute right-3 top-3 z-50 flex max-h-[calc(100%-24px)] w-[340px] flex-col overflow-hidden rounded-xl border border-line bg-elevated shadow-xl">
      <header className="flex items-center justify-between gap-2 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <p className="truncate text-[14px] font-semibold text-fg-strong">
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
      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
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
  const { fitView } = useReactFlow()

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

  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      setSelection({
        type: 'node',
        nodeId: node.id,
        data: node.data as TopologyNodeData,
      })
    },
    [],
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

  const refreshing =
    siteQuery.isFetching ||
    wafQuery.isFetching ||
    routesQuery.isFetching ||
    poolsQuery.isFetching

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

  return (
    <div className="animate-slide-up flex h-[calc(100vh-140px)] min-h-[560px] flex-col">
      <PageHeader
        title={t('pages.topology.title')}
        description={t('pages.topology.description')}
      />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        {siteQuery.data && (
          <Badge tone="brand">
            {siteQuery.data.site.name || siteQuery.data.site.domain}
          </Badge>
        )}
        <Badge tone="neutral">
          {t('pages.topology.nodeCount', { n: nodes.length })}
        </Badge>
        <Badge tone="neutral">
          {t('pages.topology.edgeCount', { n: edges.length })}
        </Badge>
        <div className="ml-auto flex items-center gap-2">
          <Link to="/topology">
            <Button size="sm" variant="ghost" icon={<FlowArrow className="h-4 w-4" />}>
              {t('pages.topology.fleet.openFleet')}
            </Button>
          </Link>
          <Button
            size="sm"
            variant="ghost"
            icon={<FlowArrow className="h-4 w-4" />}
            onClick={autoLayout}
          >
            {t('pages.topology.autoLayout')}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            title={graphFullscreen ? t('common.exitFullscreen') : t('common.expand')}
            icon={
              graphFullscreen ? (
                <ArrowsIn className="h-4 w-4" />
              ) : (
                <ArrowsOut className="h-4 w-4" />
              )
            }
            onClick={() => void toggleGraphFullscreen()}
          >
            {graphFullscreen ? t('common.exitFullscreen') : t('common.expand')}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={<ArrowClockwise className="h-4 w-4" />}
            loading={refreshing}
            onClick={() => {
              void queryClient.invalidateQueries({
                queryKey: ['topology', siteId],
              })
            }}
          >
            {t('common.refresh')}
          </Button>
        </div>
      </div>

      <Callout
        dismissKey="topology.site"
        tone="brand"
        className="mb-3"
        icon={<FlowArrow weight="duotone" className="h-5 w-5" />}
        title={t('pages.topology.overviewTitle')}
      >
        {t('pages.topology.overview')}
      </Callout>

      <div className="relative flex min-h-0 flex-1 gap-3">
        {canWrite && (
          <aside className="w-[188px] shrink-0 rounded-xl border border-line bg-elevated p-2.5">
            <p className="mb-1 px-1 text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">
              {t('pages.topology.palette.title')}
            </p>
            <p className="mb-2 px-1 text-[11px] leading-4 text-fg-subtle">
              {t('pages.topology.palette.hint')}
            </p>
            <div className="flex flex-col gap-1.5">
              {PALETTE.map((item) => {
                const Icon = item.icon
                return (
                  <div
                    key={item.kind}
                    draggable
                    onDragStart={(event) => {
                      event.dataTransfer.setData(
                        'application/varman-topology',
                        item.kind,
                      )
                      event.dataTransfer.effectAllowed = 'copy'
                    }}
                    className="flex cursor-grab items-center gap-2 rounded-lg border border-dashed border-line bg-recessed/40 px-2.5 py-2 text-[12px] text-fg hover:border-brand/40 hover:bg-brand/5"
                  >
                    <Icon weight="duotone" className="h-4 w-4 text-brand-ink" />
                    <span className="truncate">{t(item.labelKey)}</span>
                  </div>
                )
              })}
            </div>
            <p className="mt-2 flex items-center gap-1 px-1 text-[10px] text-fg-subtle">
              <Plus weight="bold" className="h-3 w-3" />
              {t('pages.topology.palette.dropHint')}
            </p>
          </aside>
        )}

        <div
          ref={attachGraph}
          className={`relative min-h-0 flex-1 overflow-hidden rounded-xl border border-line ${
            graphFullscreen ? 'rounded-none border-0 bg-bg' : 'bg-recessed/30'
          }`}
        >
          {graphFullscreen && (
            <div className="absolute right-3 top-3 z-10">
              <Button
                size="sm"
                variant="secondary"
                icon={<ArrowsIn className="h-4 w-4" />}
                onClick={() => void toggleGraphFullscreen()}
              >
                {t('common.exitFullscreen')}
              </Button>
            </div>
          )}
          {graph === null ? (
            <SkeletonCard />
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={(changes: NodeChange<Node>[]) => {
                onNodesChange(changes)
              }}
              onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              onNodeDragStop={persistLayout}
              onDragOver={onDragOver}
              onDrop={onDrop}
              nodeTypes={topologyNodeTypes}
              fitView
              fitViewOptions={{ padding: 0.15 }}
              minZoom={0.2}
              maxZoom={2.5}
              nodesConnectable={false}
              proOptions={{ hideAttribution: true }}
              className="[&_.react-flow__node]:cursor-grab"
            >
              <Background variant={BackgroundVariant.Dots} gap={22} size={1} />
              <Controls showInteractive={false} />
              <MiniMap
                pannable
                zoomable
                nodeColor={(node) => {
                  const kind = (node.data as { kind?: string })?.kind
                  switch (kind) {
                    case 'client':
                      return 'var(--color-graph-control)'
                    case 'site':
                      return 'var(--color-text-brand)'
                    case 'waf':
                      return 'var(--color-text-success)'
                    case 'route':
                      return 'var(--color-text-warning)'
                    case 'upstream':
                      return 'var(--color-text-success)'
                    case 'layer':
                      return 'var(--color-text-subtle)'
                    default:
                      return 'var(--color-border-fill)'
                  }
                }}
              />
            </ReactFlow>
          )}

          <TopologyPanel
            siteId={siteId}
            selection={selection}
            data={panelData ?? EMPTY_PANEL_DATA}
            onClose={() => setSelection(null)}
            onChanged={invalidate}
          />

          <div className="pointer-events-none absolute bottom-3 left-3 flex items-center gap-3 rounded-lg border border-line bg-elevated/95 px-3 py-1.5 text-[10px] text-fg-subtle">
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-brand-ink" />
              {t('pages.topology.legend.site')}
            </span>
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-success" />
              {t('pages.topology.legend.waf')}
            </span>
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-warning" />
              {t('pages.topology.legend.route')}
            </span>
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-success" />
              {t('pages.topology.legend.upstream')}
            </span>
            <span className="flex items-center gap-1">
              <Tag className="h-3 w-3" />
              {t('pages.topology.legend.animated')}
            </span>
          </div>
        </div>
      </div>

      <p className="mt-2 text-[11px] text-fg-subtle">
        {t('pages.topology.hint')}{' '}
        <Link to={`/sites/${siteId}/origin`} className="font-medium text-link">
          {t('pages.topology.openOrigin')}
        </Link>
      </p>
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
