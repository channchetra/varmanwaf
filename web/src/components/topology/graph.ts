import type { Edge, Node } from '@xyflow/react'
import { MarkerType } from '@xyflow/react'

/**
 * Topology graph model.
 *
 * The builder is pure: it turns the site's configuration (site, WAF posture,
 * security layers, routes, origin pools and their targets) into ReactFlow
 * nodes and edges with a layered left-to-right layout. Positions computed
 * here are defaults; the page overrides them with the operator's saved
 * arrangement.
 *
 * The flow is always complete: when a section is empty it carries a
 * placeholder node ("no origin pool yet"), so a site with nothing configured
 * still renders the full path instead of a single lonely node.
 */

export type LayerKind =
  | 'rules'
  | 'ratelimit'
  | 'ip'
  | 'geo'
  | 'bot'
  | 'schema'
  | 'exclusions'
  | 'caching'
  | 'ssl'
  | 'basicauth'

export type ChipTone =
  | 'success'
  | 'warning'
  | 'danger'
  | 'neutral'
  | 'brand'
  | 'info'

export interface NodeChip {
  text: string
  tone: ChipTone
}

export interface TopologyNodeData extends Record<string, unknown> {
  kind:
    | 'client'
    | 'site'
    | 'waf'
    | 'layer'
    | 'route'
    | 'pool'
    | 'upstream'
    | 'placeholder'
    | 'control'
    | 'agent'
  label: string
  subtitle?: string
  chips?: NodeChip[]
  /** Layer kind for `layer` nodes; drives the panel editor. */
  layerKind?: LayerKind
  /** Entity id (site, route, pool, upstream, ...) for the panel editor. */
  entityId?: string
  /** Layout order, used only for the one-time reveal stagger. */
  order?: number
  placeholder?: boolean
  healthy?: boolean
}

export interface TopologySite {
  id: string
  name: string
  domain: string
  alternate_domains: string[]
  status: string
}

export interface TopologyWaf {
  engine_mode: string
  mode: string
  paranoia_level: number
  waf_enabled: boolean
  advanced_mode: boolean
}

export interface TopologyLayer {
  kind: LayerKind
  label: string
  summary: string
  tone: ChipTone
}

export interface TopologyRoute {
  id: string
  name: string
  path: string
  match_type: string
  enabled: boolean
  pool_id: string
  ip_group_id: string | null
}

export interface TopologyPool {
  id: string
  name: string
  lb_algorithm: string
  is_default: boolean
}

export interface TopologyUpstream {
  id: string
  name: string
  address: string
  weight: number
  tls: boolean
  health_status: string
  pool_id: string
}

export interface TopologyInput {
  site: TopologySite
  waf: TopologyWaf
  layers: TopologyLayer[]
  routes: TopologyRoute[]
  pools: TopologyPool[]
  upstreams: TopologyUpstream[]
  /** Rewrite-rule count; shown as a chip on the routing group. */
  rewriteCount: number
}

export interface TopologyGraph {
  nodes: Node<TopologyNodeData>[]
  edges: Edge[]
}

/** Column origins (x) of the layered layout. */
export const COLUMN = {
  client: 0,
  site: 280,
  waf: 590,
  layers: 910,
  routes: 1260,
  pools: 1590,
} as const

export const LAYER_GROUP_ID = 'group-layers'
export const ROUTE_GROUP_ID = 'group-routes'
export const DEFAULT_ROUTE_ID = 'route-default'
export const PLACEHOLDER_POOL_ID = 'pool-placeholder'

export const GROUP_WIDTH = 300
/** Compact rows: ten layers must fit one screen without shrinking the graph. */
export const LAYER_NODE_HEIGHT = 48
export const ROUTE_NODE_HEIGHT = 100
export const UPSTREAM_NODE_HEIGHT = 64
export const POOL_WIDTH = 320

function link(
  id: string,
  source: string,
  target: string,
  options: { label?: string; tls?: boolean; live?: boolean } = {},
): Edge {
  const tls = options.tls ?? false
  return {
    id,
    source,
    target,
    type: 'signal',
    animated: false,
    label: options.label,
    data: { live: options.live ?? false, tls },
    labelStyle: { fill: tls ? 'var(--color-text-warning)' : 'var(--color-text-subtle)', fontSize: 10 },
    labelBgStyle: { fill: 'var(--color-bg-elevated)', fillOpacity: 0.85 },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: tls ? 'var(--color-text-warning)' : 'var(--color-text-subtle)',
      width: 12,
      height: 12,
    },
  }
}

/**
 * Build the full topology graph. Empty sections get placeholder nodes so the
 * rendered flow is always the complete path.
 */
export function buildTopologyGraph(input: TopologyInput): TopologyGraph {
  const { site, waf, layers, routes, pools, upstreams, rewriteCount } = input
  const nodes: Node<TopologyNodeData>[] = []
  const edges: Edge[] = []

  // --- Fixed chain --------------------------------------------------------
  nodes.push({
    id: 'client',
    type: 'topology',
    position: { x: COLUMN.client, y: 40 },
    data: {
      kind: 'client',
      label: 'Internet',
      subtitle: 'Visitors and attackers',
      chips: [
        { text: 'HTTP :80', tone: 'neutral' },
        { text: 'HTTPS :443', tone: 'warning' },
      ],
    },
    draggable: true,
  })

  nodes.push({
    id: 'site',
    type: 'topology',
    position: { x: COLUMN.site, y: 20 },
    data: {
      kind: 'site',
      entityId: site.id,
      label: site.name || site.domain,
      subtitle: [site.domain, ...(site.alternate_domains ?? [])]
        .filter(Boolean)
        .join(', '),
      chips: [
        {
          text: site.status === 'active' ? 'active' : site.status,
          tone: site.status === 'active' ? 'success' : 'warning',
        },
      ],
    },
  })

  nodes.push({
    id: 'waf',
    type: 'topology',
    position: { x: COLUMN.waf, y: 20 },
    data: {
      kind: 'waf',
      entityId: site.id,
      label: 'Web Protection',
      subtitle: `Engine: ${waf.engine_mode}`,
      chips: [
        {
          text: waf.waf_enabled ? `mode: ${waf.mode}` : 'disabled',
          tone: !waf.waf_enabled
            ? 'danger'
            : waf.mode === 'block'
              ? 'success'
              : 'warning',
        },
        { text: `PL ${waf.paranoia_level}`, tone: 'neutral' },
        ...(waf.advanced_mode
          ? [{ text: 'advanced', tone: 'brand' as ChipTone }]
          : []),
      ],
    },
  })

  edges.push(
    link('client-site', 'client', 'site', {
      label: 'TLS',
      tls: true,
      live: site.status === 'active',
    }),
  )
  edges.push(link('site-waf', 'site', 'waf', { live: waf.waf_enabled }))

  // --- Security layers group ---------------------------------------------
  const layerNodes = layers.map((layer, index) => ({
    id: `layer-${layer.kind}`,
    type: 'topology' as const,
    parentId: LAYER_GROUP_ID,
    extent: 'parent' as const,
    position: { x: 14, y: 52 + index * LAYER_NODE_HEIGHT },
    data: {
      kind: 'layer' as const,
      layerKind: layer.kind,
      label: layer.label,
      subtitle: layer.summary,
      chips: [{ text: layer.summary, tone: layer.tone }],
    },
  }))

  nodes.push({
    id: LAYER_GROUP_ID,
    type: 'topologyGroup',
    position: { x: COLUMN.layers, y: 0 },
    data: {
      kind: 'placeholder',
      label: 'Security layers',
      subtitle: `${layers.length} layer${layers.length === 1 ? '' : 's'} evaluated per request`,
    },
    style: {
      width: GROUP_WIDTH,
      height: 52 + Math.max(layers.length, 1) * LAYER_NODE_HEIGHT + 12,
    },
    selectable: false,
  })
  nodes.push(...layerNodes)

  edges.push(link('waf-layers', 'waf', LAYER_GROUP_ID, { live: waf.waf_enabled }))

  // --- Routing group ------------------------------------------------------
  const routeNodes = (
    routes.length > 0
      ? routes.map((route) => ({
          id: `route-${route.id}`,
          data: {
            kind: 'route' as const,
            entityId: route.id,
            label: route.path || '/',
            subtitle:
              `${route.match_type}${route.name ? ` · ${route.name}` : ''}`,
            chips: [
              {
                text: route.enabled ? 'enabled' : 'disabled',
                tone: (route.enabled ? 'success' : 'neutral') as ChipTone,
              },
              ...(route.ip_group_id
                ? [{ text: 'IP group', tone: 'info' as ChipTone }]
                : []),
            ],
          },
        }))
      : [
          {
            id: DEFAULT_ROUTE_ID,
            data: {
              kind: 'route' as const,
              label: 'All paths',
              subtitle: 'default route to the origin pool',
              chips: [{ text: 'default', tone: 'brand' as ChipTone }],
            },
          },
        ]
  ).map((route, index) => ({
    ...route,
    type: 'topology' as const,
    parentId: ROUTE_GROUP_ID,
    extent: 'parent' as const,
    position: { x: 14, y: 52 + index * ROUTE_NODE_HEIGHT },
  }))

  nodes.push({
    id: ROUTE_GROUP_ID,
    type: 'topologyGroup',
    position: { x: COLUMN.routes, y: 0 },
    data: {
      kind: 'placeholder',
      label: 'Routing',
      subtitle:
        routes.length > 0
          ? `${routes.length} route${routes.length === 1 ? '' : 's'}`
          : 'no explicit routes',
      chips:
        rewriteCount > 0
          ? [{ text: `${rewriteCount} rewrite${rewriteCount === 1 ? '' : 's'}`, tone: 'info' }]
          : undefined,
    },
    style: {
      width: GROUP_WIDTH,
      height: 52 + Math.max(routeNodes.length, 1) * ROUTE_NODE_HEIGHT + 12,
    },
    selectable: false,
  })
  nodes.push(...routeNodes)

  edges.push(link('layers-routes', LAYER_GROUP_ID, ROUTE_GROUP_ID, { live: true }))

  // --- Origin pools, each grouping its targets ----------------------------
  const poolsToRender: TopologyPool[] =
    pools.length > 0
      ? pools
      : [
          {
            id: PLACEHOLDER_POOL_ID,
            name: 'No origin pool yet',
            lb_algorithm: 'round_robin',
            is_default: true,
          },
        ]

  let poolY = 0
  for (const pool of poolsToRender) {
    const targets = upstreams.filter((up) => up.pool_id === pool.id)
    const isPlaceholder = pool.id === PLACEHOLDER_POOL_ID
    const poolId = `pool-${pool.id}`
    const height = 64 + Math.max(targets.length, 1) * UPSTREAM_NODE_HEIGHT + 10

    nodes.push({
      id: poolId,
      type: 'topologyGroup',
      position: { x: COLUMN.pools, y: poolY },
      data: {
        kind: 'placeholder',
        entityId: pool.id,
        label: pool.name,
        subtitle: pool.lb_algorithm,
        placeholder: isPlaceholder,
        chips: [
          ...(pool.is_default
            ? [{ text: 'default', tone: 'brand' as ChipTone }]
            : []),
          {
            text: `${targets.length} target${targets.length === 1 ? '' : 's'}`,
            tone: targets.length > 0 ? 'neutral' : 'warning',
          },
        ],
      },
      style: { width: POOL_WIDTH, height },
      selectable: !isPlaceholder,
    })

    if (targets.length === 0) {
      nodes.push({
        id: `${poolId}-empty`,
        type: 'topology',
        parentId: poolId,
        extent: 'parent',
        position: { x: 16, y: 56 },
        data: {
          kind: 'placeholder',
          label: 'No targets',
          subtitle: 'drag an upstream here or open the pool editor',
          placeholder: true,
        },
        draggable: false,
        selectable: false,
      })
    }

    targets.forEach((up, index) => {
      const healthy = up.health_status === 'healthy'
      nodes.push({
        id: `upstream-${up.id}`,
        type: 'topology',
        parentId: poolId,
        extent: 'parent',
        position: { x: 16, y: 56 + index * UPSTREAM_NODE_HEIGHT },
        data: {
          kind: 'upstream',
          entityId: up.id,
          label: up.address,
          subtitle: up.name || undefined,
          healthy,
          chips: [
            {
              text: up.health_status || 'unknown',
              tone: healthy
                ? 'success'
                : up.health_status === 'unhealthy'
                  ? 'danger'
                  : 'neutral',
            },
            ...(up.weight !== 1
              ? [{ text: `weight ${up.weight}`, tone: 'info' as ChipTone }]
              : []),
            ...(up.tls ? [{ text: 'TLS', tone: 'warning' as ChipTone }] : []),
          ],
        },
      })
      // Targets live inside the pool frame: containment is the pool→target
      // relationship. A separate edge would leave the group's right-hand
      // handle and loop backwards to a child inside the same frame.
    })

    // Route → pool edges (each route knows its pool; a route naming a pool
    // that no longer exists falls back to the default pool, and the default
    // route lands on whatever pool exists).
    const poolIds = new Set(pools.map((p) => p.id))
    const defaultPool = pools.find((p) => p.is_default) ?? pools[0]
    for (const route of routeNodes) {
      const routeEntity = routes.find((r) => `route-${r.id}` === route.id)
      let targetPool = routeEntity?.pool_id
      if (!targetPool || !poolIds.has(targetPool)) {
        targetPool = defaultPool?.id
      }
      const isTarget = isPlaceholder
        ? targetPool == null
        : targetPool === pool.id
      if (isTarget) {
        edges.push(
          link(`route-pool-${route.id}-${pool.id}`, route.id, poolId, {
            live: routeEntity?.enabled ?? false,
          }),
        )
      }
    }

    poolY += height + 28
  }

  nodes.forEach((node, index) => {
    node.data = { ...node.data, order: index }
  })
  return { nodes, edges }
}

/* ------------------------------------------------------------------ */
/* Fleet view: control plane -> agents (edge nodes) -> every site      */
/* ------------------------------------------------------------------ */

export interface FleetAgent {
  id: string
  hostname: string
  ip_address: string
  status: string
  connected: boolean
  site_id: string | null
  site_domain: string | null
  /** Every site this agent serves; unbound agents serve every site owned by
   *  the API key's user. */
  served_site_ids: string[]
  version: string | null
}

export interface FleetSite {
  id: string
  name: string
  domain: string
  status: string
}

export interface FleetInput {
  controlPlane: {
    version: string
    grpcTls: boolean
    registrationOpen: boolean
  }
  agents: FleetAgent[]
  sites: FleetSite[]
}

export const FLEET_COLUMN = {
  control: 0,
  agents: 440,
  sites: 960,
} as const

export const FLEET_ROW_HEIGHT = 104

/**
 * The fleet graph: the control plane, every registered agent (edge node) and
 * every site in one view - instead of one site at a time.
 *
 * Edges are control plane → agent → site. A bound agent links to its one site;
 * an unbound agent (all-in-one, or a node enrolled with an administrator key)
 * serves every site owned by its API key's user, so it links to all of them.
 * There is deliberately no control-plane → site edge: the control plane pushes
 * config to agents, never to a site directly.
 */
export function buildFleetGraph(input: FleetInput): TopologyGraph {
  const { controlPlane, agents, sites } = input
  const nodes: Node<TopologyNodeData>[] = []
  const edges: Edge[] = []

  nodes.push({
    id: 'control',
    type: 'topology',
    position: { x: FLEET_COLUMN.control, y: 30 },
    data: {
      kind: 'control',
      label: 'Control plane',
      subtitle: `v${controlPlane.version}`,
      chips: [
        {
          text: controlPlane.registrationOpen
            ? 'registration open'
            : 'registration closed',
          tone: controlPlane.registrationOpen ? 'warning' : 'success',
        },
        {
          text: controlPlane.grpcTls ? 'gRPC TLS' : 'gRPC plain',
          tone: controlPlane.grpcTls ? 'success' : 'warning',
        },
      ],
    },
  })

  // Sites keyed for the agent links.
  const siteById = new Map(sites.map((site) => [site.id, site]))

  if (agents.length === 0) {
    nodes.push({
      id: 'agents-empty',
      type: 'topology',
      position: { x: FLEET_COLUMN.agents, y: 30 },
      data: {
        kind: 'placeholder',
        label: 'No agents registered',
        subtitle: 'install an agent or run all-in-one',
        placeholder: true,
      },
    })
  } else {
    agents.forEach((agent, index) => {
      const statusTone: ChipTone =
        agent.status === 'online'
          ? 'success'
          : agent.status === 'degraded'
            ? 'warning'
            : 'danger'
      nodes.push({
        id: `agent-${agent.id}`,
        type: 'topology',
        position: {
          x: FLEET_COLUMN.agents,
          y: 30 + index * FLEET_ROW_HEIGHT,
        },
        data: {
          kind: 'agent',
          entityId: agent.id,
          label: agent.hostname || agent.id.slice(0, 8),
          subtitle: agent.ip_address,
          chips: [
            { text: agent.status, tone: statusTone },
            ...(agent.connected
              ? []
              : [{ text: 'disconnected', tone: 'warning' as ChipTone }]),
            ...(agent.site_id
              ? []
              : agent.served_site_ids.length > 0
                ? [{
                    text: `all sites (${agent.served_site_ids.length})`,
                    tone: 'info' as ChipTone,
                  }]
                : [{ text: 'unassigned', tone: 'warning' as ChipTone }]),
            ...(agent.version
              ? [{ text: `v${agent.version}`, tone: 'neutral' as ChipTone }]
              : []),
          ],
        },
      })
      edges.push(
        link(`control-${agent.id}`, 'control', `agent-${agent.id}`, {
          live: agent.connected,
        }),
      )

      const servedSiteIds = agent.site_id
        ? [agent.site_id]
        : agent.served_site_ids
      for (const siteId of servedSiteIds) {
        const servedSite = siteById.get(siteId)
        if (!servedSite) continue
        edges.push(
          link(
            `agent-${agent.id}-site-${servedSite.id}`,
            `agent-${agent.id}`,
            `site-${servedSite.id}`,
            { live: agent.connected && servedSite.status === 'active' },
          ),
        )
      }
    })
  }

  if (sites.length === 0) {
    nodes.push({
      id: 'sites-empty',
      type: 'topology',
      position: { x: FLEET_COLUMN.sites, y: 30 },
      data: {
        kind: 'placeholder',
        label: 'No sites yet',
        subtitle: 'create a site to start protecting traffic',
        placeholder: true,
      },
    })
  } else {
    sites.forEach((site, index) => {
      const servingAgents = agents.filter(
        (agent) =>
          agent.site_id === site.id ||
          (!agent.site_id && agent.served_site_ids.includes(site.id)),
      )
      const boundAgent = servingAgents.some(
        (agent) => agent.site_id === site.id,
      )
      nodes.push({
        id: `site-${site.id}`,
        type: 'topology',
        position: {
          x: FLEET_COLUMN.sites,
          y: 30 + index * FLEET_ROW_HEIGHT,
        },
        data: {
          kind: 'site',
          entityId: site.id,
          label: site.name || site.domain,
          subtitle: site.domain,
          chips: [
            {
              text: site.status,
              tone: site.status === 'active' ? 'success' : 'warning',
            },
            boundAgent
              ? { text: 'agent bound', tone: 'success' as ChipTone }
              : servingAgents.length > 0
                ? {
                    text: `served by ${servingAgents.length}`,
                    tone: 'success' as ChipTone,
                  }
                : { text: 'no agent', tone: 'warning' as ChipTone },
          ],
        },
      })
    })
  }

  nodes.forEach((node, index) => {
    node.data = { ...node.data, order: index }
  })
  return { nodes, edges }
}
