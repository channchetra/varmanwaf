import { BaseEdge, getBezierPath, type EdgeProps } from '@xyflow/react'

export interface SignalEdgeData extends Record<string, unknown> {
  /** The edge is part of a live path (online agent / active site). */
  live?: boolean
  /** TLS hop; the base line uses the warning tone. */
  tls?: boolean
}

/**
 * Curved signal line between two topology nodes.
 *
 * The base line draws in once when the graph appears. A live edge also carries
 * a slow dotted pulse; both animations are disabled under reduced motion. The
 * path is deliberately a single smooth curve: no bundled edges, no labels
 * competing with the node copy.
 */
export function SignalEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
  style,
  data,
  selected,
}: EdgeProps) {
  const [path] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    curvature: 0.38,
  })
  const signal = (data ?? {}) as SignalEdgeData

  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={style}
        className={[
          'topology-edge-line',
          signal.tls ? 'topology-edge-line--tls' : '',
          selected ? 'topology-edge-line--selected' : '',
        ]
          .filter(Boolean)
          .join(' ')}
      />
      {signal.live && (
        <path
          d={path}
          fill="none"
          className="topology-edge-flow"
          aria-hidden
        />
      )}
    </>
  )
}

export const topologyEdgeTypes = { signal: SignalEdge }
