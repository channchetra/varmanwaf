import { describe, expect, it } from 'vitest'
import {
  DEFAULT_ROUTE_ID,
  LAYER_GROUP_ID,
  PLACEHOLDER_POOL_ID,
  ROUTE_GROUP_ID,
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
