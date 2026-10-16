import { describe, expect, it } from 'vitest'
import {
  DEFAULT_ROUTE_ID,
  LAYER_GROUP_ID,
  PLACEHOLDER_POOL_ID,
  ROUTE_GROUP_ID,
  buildFleetGraph,
  buildTopologyGraph,
  type TopologyInput,
} from './graph'

function baseInput(overrides: Partial<TopologyInput> = {}): TopologyInput {
  return {
    site: {
      id: 'site-1',
      name: 'Example',
      domain: 'example.com',
      alternate_domains: ['www.example.com'],
      status: 'active',
    },
    waf: {
      engine_mode: 'varman',
      mode: 'block',
      paranoia_level: 2,
      waf_enabled: true,
      advanced_mode: true,
    },
    layers: [
      { kind: 'rules', label: 'Custom rules', summary: '3 rule(s)', tone: 'success' },
      { kind: 'geo', label: 'Geo / ASN', summary: 'off', tone: 'neutral' },
    ],
    routes: [],
    pools: [],
    upstreams: [],
    rewriteCount: 0,
    ...overrides,
  }
}

describe('buildTopologyGraph', () => {
  it('renders the complete chain even when nothing is configured', () => {
    const graph = buildTopologyGraph(baseInput())
    const ids = graph.nodes.map((node) => node.id)

    // The fixed chain is always present: visitors -> site -> WAF -> layers
    // -> routing -> pools. A site with no routes or targets must not collapse
    // into a single lonely node.
    expect(ids).toContain('client')
    expect(ids).toContain('site')
    expect(ids).toContain('waf')
    expect(ids).toContain(LAYER_GROUP_ID)
    expect(ids).toContain(ROUTE_GROUP_ID)
    expect(ids).toContain(DEFAULT_ROUTE_ID)
    expect(ids).toContain(`pool-${PLACEHOLDER_POOL_ID}`)

    // Layer nodes are children of the layers group.
    const ruleLayer = graph.nodes.find((node) => node.id === 'layer-rules')
    expect(ruleLayer?.parentId).toBe(LAYER_GROUP_ID)

    // Every link is animated.
    expect(graph.edges.length).toBeGreaterThan(0)
    expect(graph.edges.every((edge) => edge.animated === true)).toBe(true)

    // The default route still reaches the placeholder pool.
    expect(
      graph.edges.some(
        (edge) =>
          edge.source === DEFAULT_ROUTE_ID &&
          edge.target === `pool-${PLACEHOLDER_POOL_ID}`,
      ),
    ).toBe(true)
  })

  it('groups targets under their pool and routes to the right pool', () => {
    const graph = buildTopologyGraph(
      baseInput({
        routes: [
          {
            id: 'r1',
            name: 'API',
            path: '/api',
            match_type: 'prefix',
            enabled: true,
            pool_id: 'p1',
            ip_group_id: null,
          },
        ],
        pools: [
          { id: 'p1', name: 'origin', lb_algorithm: 'round_robin', is_default: true },
          { id: 'p2', name: 'backup', lb_algorithm: 'random', is_default: false },
        ],
        upstreams: [
          {
            id: 'u1',
            name: 'origin-a',
            address: '10.0.0.5:8080',
            weight: 1,
            tls: false,
            health_status: 'healthy',
            pool_id: 'p1',
          },
          {
            id: 'u2',
            name: 'origin-b',
            address: '10.0.0.6:8080',
            weight: 2,
            tls: true,
            health_status: 'unknown',
            pool_id: 'p1',
          },
        ],
      }),
    )

    const ids = graph.nodes.map((node) => node.id)
    expect(ids).toContain('route-r1')
    expect(ids).not.toContain(DEFAULT_ROUTE_ID)
    expect(ids).toContain('pool-p1')
    expect(ids).toContain('upstream-u1')
    expect(ids).toContain('upstream-u2')

    // Targets are grouped inside their pool.
    expect(graph.nodes.find((n) => n.id === 'upstream-u1')?.parentId).toBe('pool-p1')

    // The route links to its pool; the pool links to each target.
    expect(
      graph.edges.some((e) => e.source === 'route-r1' && e.target === 'pool-p1'),
    ).toBe(true)
    expect(
      graph.edges.some((e) => e.source === 'pool-p1' && e.target === 'upstream-u1'),
    ).toBe(true)
    expect(
      graph.edges.some((e) => e.source === 'pool-p1' && e.target === 'upstream-u2'),
    ).toBe(true)

    // Unhealthy targets are marked, healthy ones are not.
    const u2 = graph.nodes.find((n) => n.id === 'upstream-u2')
    expect(u2?.data.healthy).toBe(false)

    // A pool with no targets renders an explicit placeholder, not silence.
    expect(ids).toContain('pool-p2-empty')
  })

  it('marks a pool without targets and a route without an explicit pool', () => {
    const graph = buildTopologyGraph(
      baseInput({
        routes: [
          {
            id: 'r9',
            name: '',
            path: '/',
            match_type: 'prefix',
            enabled: false,
            pool_id: 'missing',
            ip_group_id: null,
          },
        ],
        pools: [
          { id: 'p1', name: 'origin', lb_algorithm: 'round_robin', is_default: true },
        ],
      }),
    )

    // The route names a pool that does not exist: it falls back to the
    // default pool rather than dangling with no link.
    expect(
      graph.edges.some((e) => e.source === 'route-r9' && e.target === 'pool-p1'),
    ).toBe(true)
    expect(graph.nodes.map((n) => n.id)).toContain('pool-p1-empty')
  })
})

describe('buildFleetGraph', () => {
  it('shows the control plane, every agent and every site in one view', () => {
    const graph = buildFleetGraph({
      controlPlane: { version: '1.1.1', grpcTls: true, registrationOpen: false },
      agents: [
        {
          id: 'a1',
          hostname: 'edge-1',
          ip_address: '10.0.0.10',
          status: 'online',
          connected: true,
          site_id: 's1',
          site_domain: 'example.com',
          version: '1.1.1',
        },
        {
          id: 'a2',
          hostname: 'edge-2',
          ip_address: '10.0.0.11',
          status: 'offline',
          connected: false,
          site_id: null,
          site_domain: null,
          version: '1.1.0',
        },
      ],
      sites: [
        { id: 's1', name: 'Example', domain: 'example.com', status: 'active' },
        { id: 's2', name: 'Other', domain: 'other.test', status: 'paused' },
      ],
    })

    const ids = graph.nodes.map((n) => n.id)
    expect(ids).toContain('control')
    expect(ids).toContain('agent-a1')
    expect(ids).toContain('agent-a2')
    expect(ids).toContain('site-s1')
    expect(ids).toContain('site-s2')

    // Every agent links from the control plane; the bound agent links to its
    // site, the unbound one does not. Every site links from the control plane
    // (it pushes their bundles to the edge fleet).
    expect(graph.edges.some((e) => e.source === 'control' && e.target === 'agent-a1')).toBe(true)
    expect(graph.edges.some((e) => e.source === 'agent-a1' && e.target === 'site-s1')).toBe(true)
    expect(graph.edges.some((e) => e.source === 'agent-a2')).toBe(false)
    expect(graph.edges.some((e) => e.source === 'control' && e.target === 'site-s1')).toBe(true)
    expect(graph.edges.some((e) => e.source === 'control' && e.target === 'site-s2')).toBe(true)

    // All links animated; statuses honest.
    expect(graph.edges.every((e) => e.animated === true)).toBe(true)
    const a2 = graph.nodes.find((n) => n.id === 'agent-a2')
    expect(a2?.data.chips?.[0]?.tone).toBe('danger')
    const s2 = graph.nodes.find((n) => n.id === 'site-s2')
    expect(s2?.data.chips?.some((c) => c.text === 'agent bound')).toBe(false)
  })

  it('renders explicit placeholders when the fleet is empty', () => {
    const graph = buildFleetGraph({
      controlPlane: { version: '1.1.1', grpcTls: true, registrationOpen: false },
      agents: [],
      sites: [],
    })
    const ids = graph.nodes.map((n) => n.id)
    expect(ids).toContain('control')
    expect(ids).toContain('agents-empty')
    expect(ids).toContain('sites-empty')
    expect(graph.edges.length).toBe(0)
  })
})
