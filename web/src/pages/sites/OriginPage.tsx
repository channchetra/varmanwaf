import { useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Signpost,
  Globe,
  Lock,
  Network,
  Plus,
  PencilSimple,
  Trash,
  ArrowClockwise,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { sitesApi, siteKeys } from '@/api/sites'
import { ipGroupsApi, ipGroupKeys } from '@/api/ipGroups'
import { errorMessage } from '@/api/errors'
import { useCanWrite } from '@/hooks'
import { formatDateTime } from '@/lib/format'
import type {
  CreatePoolRequest,
  CreateRouteRequest,
  CreateUpstreamRequest,
  IpGroupResponse,
  Route,
  Upstream,
  UpstreamPool,
  UpdatePoolRequest,
  UpdateRouteRequest,
  UpdateUpstreamRequest,
} from '@/api/types'

/* ── Load-balancing algorithm helpers ─────────────────────────────── */

/** Select values for the LB dropdown; keyed by `hash:<type>` for hash kinds. */
const HASH_KEY_TYPES = ['hash:header', 'hash:cookie', 'hash:query']

function isHashKeyType(value: string) {
  return HASH_KEY_TYPES.includes(value)
}

/** Parses `round_robin | least_connections | random | hash:ip | hash:header:key` into form fields. */
function splitLbAlgorithm(algo: string): { lbType: string; hashKey: string } {
  if (!algo || algo === 'round_robin') return { lbType: 'round_robin', hashKey: '' }
  if (algo === 'least_connections' || algo === 'random') {
    return { lbType: algo, hashKey: '' }
  }
  const parts = algo.split(':')
  if (parts[0] !== 'hash' || parts.length < 2) {
    return { lbType: 'round_robin', hashKey: '' }
  }
  return { lbType: `hash:${parts[1]}`, hashKey: parts.slice(2).join(':') }
}

/* ── Form state ───────────────────────────────────────────────────── */

interface PoolFormState {
  name: string
  lbType: string
  hashKey: string
  httpsOrigin: boolean
  sni: string
  verifyCert: boolean
}

const emptyPoolForm = (): PoolFormState => ({
  name: '',
  lbType: 'round_robin',
  hashKey: '',
  httpsOrigin: false,
  sni: '',
  verifyCert: true,
})

function poolFormFromPool(pool: UpstreamPool): PoolFormState {
  const { lbType, hashKey } = splitLbAlgorithm(pool.lb_algorithm)
  return {
    name: pool.name,
    lbType,
    hashKey,
    httpsOrigin: Boolean(pool.sni),
    sni: pool.sni ?? '',
    verifyCert: pool.verify_cert ?? true,
  }
}

interface NodeFormState {
  name: string
  address: string
  weight: string
  poolId: string
}

const emptyNodeForm = (poolId: string): NodeFormState => ({
  name: '',
  address: '',
  weight: '1',
  poolId,
})

/**
 * Mirrors the server's origin-address normalization (`host[:port]`) so a
 * pasted URL fails inline instead of as a generic 400.
 *
 * Returns the i18n key of the error, or the canonical address.
 */
function parseOriginAddress(raw: string): { error: string } | { address: string } {
  let address = raw.trim()
  for (const scheme of ['http://', 'https://']) {
    if (address.toLowerCase().startsWith(scheme)) {
      address = address.slice(scheme.length)
      break
    }
  }
  address = address.replace(/\/+$/, '')
  if (!address || address.length > 255) return { error: 'errors.addressRequired' }
  if (/[?#]/.test(address) || address.includes('/')) return { error: 'errors.addressPath' }

  let host = address
  let port = ''
  if (address.startsWith('[')) {
    const end = address.indexOf(']')
    if (end < 2) return { error: 'errors.addressInvalid' }
    host = address.slice(1, end)
    const tail = address.slice(end + 1)
    if (tail && !tail.startsWith(':')) return { error: 'errors.addressInvalid' }
    port = tail.slice(1)
    if (!/^[0-9A-Fa-f:.]+$/.test(host)) return { error: 'errors.addressInvalid' }
  } else {
    const parts = address.split(':')
    // A bare IPv6 literal has to be bracketed, otherwise the port is ambiguous.
    if (parts.length > 2) return { error: 'errors.addressInvalid' }
    if (parts.length === 2) {
      host = parts[0]
      port = parts[1]
    }
    if (!/^[A-Za-z0-9._-]+$/.test(host)) return { error: 'errors.addressInvalid' }
  }
  if (port && (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)) {
    return { error: 'errors.addressPort' }
  }
  return { address }
}

interface RouteFormState {
  name: string
  matchType: string
  path: string
  priority: string
  poolId: string
  /** Empty string gates the route to no group (every client matches). */
  ipGroupId: string
  enabled: boolean
}

const emptyRouteForm = (poolId: string): RouteFormState => ({
  name: '',
  matchType: 'prefix',
  path: '',
  priority: '',
  poolId,
  ipGroupId: '',
  enabled: true,
})

/* ── Page ─────────────────────────────────────────────────────────── */

export function OriginPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const poolsQuery = useQuery({
    queryKey: siteKeys.pools(siteId),
    queryFn: () => sitesApi.listPools(siteId),
    enabled: Boolean(siteId),
  })
  const upstreamsQuery = useQuery({
    queryKey: siteKeys.upstreams(siteId),
    queryFn: () => sitesApi.listUpstreams(siteId),
    enabled: Boolean(siteId),
  })
  const routesQuery = useQuery({
    queryKey: siteKeys.routes(siteId),
    queryFn: () => sitesApi.listRoutes(siteId),
    enabled: Boolean(siteId),
  })
  const ipGroupsQuery = useQuery({
    queryKey: ipGroupKeys.list({ page_size: 100 }),
    queryFn: () => ipGroupsApi.list({ page_size: 100 }),
  })

  const ipGroups: IpGroupResponse[] = useMemo(
    () => ipGroupsQuery.data?.items ?? [],
    [ipGroupsQuery.data],
  )
  const ipGroupById = useMemo(
    () => new Map(ipGroups.map((g) => [g.id, g])),
    [ipGroups],
  )
  /** Groups the server accepts as a route gate: enabled with ranges. */
  const gateableGroups = useMemo(
    () => ipGroups.filter((g) => g.enabled && g.ip_ranges.length > 0),
    [ipGroups],
  )

  const pools = useMemo(
    () =>
      [...(poolsQuery.data ?? [])].sort((a, b) => {
        if (a.is_default !== b.is_default) return a.is_default ? -1 : 1
        return a.created_at.localeCompare(b.created_at)
      }),
    [poolsQuery.data],
  )
  const poolById = useMemo(
    () => new Map(pools.map((p) => [p.id, p])),
    [pools],
  )
  const defaultPool = pools.find((p) => p.is_default)

  const nodesByPool = useMemo(() => {
    const map = new Map<string, Upstream[]>()
    for (const node of upstreamsQuery.data ?? []) {
      const list = map.get(node.pool_id) ?? []
      list.push(node)
      map.set(node.pool_id, list)
    }
    return map
  }, [upstreamsQuery.data])

  const routes = useMemo(
    () =>
      [...(routesQuery.data ?? [])].sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      ),
    [routesQuery.data],
  )

  const lbOptions = [
    { value: 'round_robin', label: t('pages.origin.lb.roundRobin') },
    { value: 'least_connections', label: t('pages.origin.lb.leastConnections') },
    { value: 'random', label: t('pages.origin.lb.random') },
    { value: 'hash:ip', label: t('pages.origin.lb.hashIp') },
    { value: 'hash:url', label: t('pages.origin.lb.hashUrl') },
    { value: 'hash:path', label: t('pages.origin.lb.hashPath') },
    { value: 'hash:header', label: t('pages.origin.lb.hashHeader') },
    { value: 'hash:cookie', label: t('pages.origin.lb.hashCookie') },
    { value: 'hash:query', label: t('pages.origin.lb.hashQuery') },
  ]

  const lbLabel = (algo: string) => {
    const { lbType, hashKey } = splitLbAlgorithm(algo)
    const base = lbOptions.find((o) => o.value === lbType)?.label ?? algo
    return hashKey ? `${base} · ${hashKey}` : base
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: siteKeys.all })
  }

  /* ── Pool mutations ────────────────────────────────────────────── */

  const [poolDialogOpen, setPoolDialogOpen] = useState(false)
  const [editingPool, setEditingPool] = useState<UpstreamPool | null>(null)
  const [poolForm, setPoolForm] = useState<PoolFormState>(emptyPoolForm())
  const [poolError, setPoolError] = useState<string | null>(null)
  const [pendingDeletePool, setPendingDeletePool] = useState<UpstreamPool | null>(null)

  const savePool = useMutation({
    mutationFn: (data: {
      id?: string
      create?: CreatePoolRequest
      update?: UpdatePoolRequest
    }) =>
      data.id
        ? sitesApi.updatePool(siteId, data.id, data.update ?? {})
        : sitesApi.createPool(siteId, data.create!),
    onSuccess: (pool, vars) => {
      toast.success(
        vars.id ? t('pages.origin.poolUpdated') : t('pages.origin.poolCreated'),
        pool.name,
      )
      setPoolDialogOpen(false)
      invalidate()
    },
    onError: (e) => setPoolError(errorMessage(e)),
  })

  const deletePool = useMutation({
    mutationFn: (id: string) => sitesApi.deletePool(siteId, id),
    onSuccess: (_d, id) => {
      toast.success(t('pages.origin.poolDeleted'), poolById.get(id)?.name)
      setPendingDeletePool(null)
      invalidate()
    },
    onError: (e) => {
      toast.error(t('pages.origin.poolDeleteFailed'), errorMessage(e))
    },
  })

  const openCreatePool = () => {
    setEditingPool(null)
    setPoolForm(emptyPoolForm())
    setPoolError(null)
    setPoolDialogOpen(true)
  }

  const openEditPool = (pool: UpstreamPool) => {
    setEditingPool(pool)
    setPoolForm(poolFormFromPool(pool))
    setPoolError(null)
    setPoolDialogOpen(true)
  }

  const submitPool = () => {
    setPoolError(null)
    const name = poolForm.name.trim()
    if (!name || name.length > 100) {
      setPoolError(t('pages.origin.errors.nameRequired'))
      return
    }

    const lbType = poolForm.lbType
    const hashKey = poolForm.hashKey.trim()
    let lbAlgorithm = lbType
    if (isHashKeyType(lbType)) {
      if (!hashKey) {
        setPoolError(t('pages.origin.errors.lbKeyRequired'))
        return
      }
      lbAlgorithm = `${lbType}:${hashKey}`
    }
    if (lbAlgorithm.length > 64) {
      setPoolError(t('pages.origin.errors.lbKeyRequired'))
      return
    }

    let sni: string | null = null
    if (poolForm.httpsOrigin) {
      sni = poolForm.sni.trim().toLowerCase()
      if (!sni) {
        setPoolError(t('pages.origin.errors.sniRequired'))
        return
      }
      if (sni.length > 255) {
        setPoolError(t('pages.origin.errors.sniTooLong'))
        return
      }
      if (sni === '$host' || sni.includes('://') || sni.includes(':')) {
        setPoolError(t('pages.origin.errors.sniInvalid'))
        return
      }
    }

    if (editingPool) {
      // Empty SNI clears the field server-side, disabling HTTPS origin.
      savePool.mutate({
        id: editingPool.id,
        update: {
          name,
          lb_algorithm: lbAlgorithm,
          sni: sni ?? '',
          verify_cert: sni ? poolForm.verifyCert : null,
        },
      })
      return
    }

    savePool.mutate({
      create: {
        name,
        lb_algorithm: lbAlgorithm,
        sni,
        verify_cert: sni ? poolForm.verifyCert : null,
      },
    })
  }

  /* ── Node mutations ────────────────────────────────────────────── */

  const [nodeDialogOpen, setNodeDialogOpen] = useState(false)
  const [editingNode, setEditingNode] = useState<Upstream | null>(null)
  const [nodeForm, setNodeForm] = useState<NodeFormState>(emptyNodeForm(''))
  const [nodeError, setNodeError] = useState<string | null>(null)
  const [pendingDeleteNode, setPendingDeleteNode] = useState<Upstream | null>(null)

  const saveNode = useMutation({
    mutationFn: (data: { id?: string; payload: CreateUpstreamRequest | UpdateUpstreamRequest }) =>
      data.id
        ? sitesApi.updateUpstream(siteId, data.id, data.payload as UpdateUpstreamRequest)
        : sitesApi.createUpstream(siteId, data.payload as CreateUpstreamRequest),
    onSuccess: (node, vars) => {
      toast.success(
        vars.id ? t('pages.origin.nodeUpdated') : t('pages.origin.nodeCreated'),
        node.address,
      )
      setNodeDialogOpen(false)
      invalidate()
    },
    onError: (e) => setNodeError(errorMessage(e)),
  })

  const deleteNode = useMutation({
    mutationFn: (id: string) => sitesApi.deleteUpstream(siteId, id),
    onSuccess: () => {
      toast.success(t('pages.origin.nodeDeleted'))
      setPendingDeleteNode(null)
      invalidate()
    },
    onError: (e) => toast.error(t('pages.origin.nodeDeleteFailed'), errorMessage(e)),
  })

  const openCreateNode = (pool: UpstreamPool) => {
    setEditingNode(null)
    setNodeForm(emptyNodeForm(pool.id))
    setNodeError(null)
    setNodeDialogOpen(true)
  }

  const openEditNode = (node: Upstream) => {
    setEditingNode(node)
    setNodeForm({
      name: node.name,
      address: node.address,
      weight: String(node.weight),
      poolId: node.pool_id,
    })
    setNodeError(null)
    setNodeDialogOpen(true)
  }

  const submitNode = () => {
    setNodeError(null)
    const name = nodeForm.name.trim()
    if (!name || name.length > 100) {
      setNodeError(t('pages.origin.errors.nameRequired'))
      return
    }
    const parsed = parseOriginAddress(nodeForm.address)
    if ('error' in parsed) {
      setNodeError(t(`pages.origin.${parsed.error}`))
      return
    }
    const address = parsed.address
    const weight = Number(nodeForm.weight)
    if (!Number.isInteger(weight) || weight < 1 || weight > 10_000) {
      setNodeError(t('pages.origin.errors.weightInvalid'))
      return
    }
    if (!nodeForm.poolId || !poolById.has(nodeForm.poolId)) {
      setNodeError(t('pages.origin.errors.poolRequired'))
      return
    }

    if (editingNode) {
      saveNode.mutate({
        id: editingNode.id,
        payload: { name, address, weight, pool_id: nodeForm.poolId },
      })
      return
    }
    saveNode.mutate({ payload: { name, address, weight, pool_id: nodeForm.poolId } })
  }

  /* ── Route mutations ───────────────────────────────────────────── */

  const [routeDialogOpen, setRouteDialogOpen] = useState(false)
  const [editingRoute, setEditingRoute] = useState<Route | null>(null)
  const [routeForm, setRouteForm] = useState<RouteFormState>(emptyRouteForm(''))
  const [routeError, setRouteError] = useState<string | null>(null)
  const [pendingDeleteRoute, setPendingDeleteRoute] = useState<Route | null>(null)

  const saveRoute = useMutation({
    mutationFn: (data: {
      id?: string
      create?: CreateRouteRequest
      update?: UpdateRouteRequest
    }) =>
      data.id
        ? sitesApi.updateRoute(siteId, data.id, data.update ?? {})
        : sitesApi.createRoute(siteId, data.create!),
    onSuccess: (route, vars) => {
      toast.success(
        vars.id ? t('pages.origin.routeUpdated') : t('pages.origin.routeCreated'),
        route.name,
      )
      setRouteDialogOpen(false)
      invalidate()
    },
    onError: (e) => setRouteError(errorMessage(e)),
  })

  const deleteRoute = useMutation({
    mutationFn: (id: string) => sitesApi.deleteRoute(siteId, id),
    onSuccess: (_d, id) => {
      toast.success(t('pages.origin.routeDeleted'), routes.find((r) => r.id === id)?.name)
      setPendingDeleteRoute(null)
      invalidate()
    },
    onError: (e) => toast.error(t('pages.origin.routeDeleteFailed'), errorMessage(e)),
  })

  const toggleRoute = useMutation({
    mutationFn: ({ route, enabled }: { route: Route; enabled: boolean }) =>
      sitesApi.updateRoute(siteId, route.id, { enabled }),
    onSuccess: () => invalidate(),
    onError: (e) => toast.error(t('pages.origin.routeToggleFailed'), errorMessage(e)),
  })

  const openCreateRoute = () => {
    setEditingRoute(null)
    setRouteForm(emptyRouteForm(defaultPool?.id ?? pools[0]?.id ?? ''))
    setRouteError(null)
    setRouteDialogOpen(true)
  }

  const openEditRoute = (route: Route) => {
    setEditingRoute(route)
    setRouteForm({
      name: route.name,
      matchType: route.match_type,
      path: route.path,
      priority: route.priority === null ? '' : String(route.priority),
      poolId: route.pool_id,
      ipGroupId: route.ip_group_id ?? '',
      enabled: route.enabled,
    })
    setRouteError(null)
    setRouteDialogOpen(true)
  }

  const submitRoute = () => {
    setRouteError(null)
    const name = routeForm.name.trim()
    if (!name || name.length > 100) {
      setRouteError(t('pages.origin.errors.nameRequired'))
      return
    }
    const matchType = routeForm.matchType
    const path = routeForm.path.trim()
    if (!path || path.length > 512) {
      setRouteError(t('pages.origin.errors.pathRequired'))
      return
    }
    if (matchType === 'regex') {
      try {
        new RegExp(path)
      } catch {
        setRouteError(t('pages.origin.errors.regexInvalid'))
        return
      }
    } else {
      if (!path.startsWith('/')) {
        setRouteError(t('pages.origin.errors.pathStartSlash'))
        return
      }
      if (path.startsWith('=') || path.startsWith('~')) {
        setRouteError(t('pages.origin.errors.pathSpecial'))
        return
      }
      if (matchType === 'prefix' && path === '/') {
        setRouteError(t('pages.origin.errors.pathRootPrefix'))
        return
      }
    }

    let priority: number | null = null
    if (routeForm.priority.trim() !== '') {
      const parsed = Number(routeForm.priority)
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 60_000) {
        setRouteError(t('pages.origin.errors.priorityInvalid'))
        return
      }
      priority = parsed
    }

    if (!routeForm.poolId || !poolById.has(routeForm.poolId)) {
      setRouteError(t('pages.origin.errors.poolRequired'))
      return
    }

    if (editingRoute) {
      saveRoute.mutate({
        id: editingRoute.id,
        update: {
          name,
          match_type: matchType,
          path,
          // `0` clears the priority back to the auto weight server-side.
          priority: priority ?? 0,
          enabled: routeForm.enabled,
          pool_id: routeForm.poolId,
          ip_group_id: routeForm.ipGroupId === '' ? null : routeForm.ipGroupId,
        },
      })
      return
    }

    saveRoute.mutate({
      create: {
        name,
        match_type: matchType,
        path,
        priority,
        enabled: routeForm.enabled,
        pool_id: routeForm.poolId,
        ip_group_id: routeForm.ipGroupId === '' ? null : routeForm.ipGroupId,
      },
    })
  }

  /* ── Route table ───────────────────────────────────────────────── */

  const MATCH_TONE: Record<string, 'neutral' | 'info' | 'warning'> = {
    prefix: 'neutral',
    exact: 'info',
    regex: 'warning',
  }

  const routeColumns: Column<Route>[] = [
    {
      key: 'name',
      header: t('common.name'),
      accessor: (r) => r.name,
      sortable: true,
      cell: (r) => (
        <div className="min-w-0">
          <p className="truncate text-[13px] font-medium text-fg-strong">{r.name}</p>
          <p className="truncate text-xs text-fg-subtle">
            {poolById.get(r.pool_id)?.name ?? t('pages.origin.missingPool')}
          </p>
        </div>
      ),
    },
    {
      key: 'match_type',
      header: t('pages.origin.matchType'),
      accessor: (r) => r.match_type,
      width: '1%',
      cell: (r) => (
        <Badge tone={MATCH_TONE[r.match_type] ?? 'neutral'}>
          {t(`pages.origin.match.${r.match_type}`, r.match_type)}
        </Badge>
      ),
    },
    {
      key: 'path',
      header: t('pages.origin.routePath'),
      accessor: (r) => r.path,
      cell: (r) => <span className="pw-mono text-[13px] text-fg">{r.path}</span>,
    },
    {
      key: 'priority',
      header: t('pages.origin.priority'),
      align: 'right',
      sortable: true,
      accessor: (r) => r.priority ?? 0,
      cell: (r) => (
        <span className="tabular-nums text-[13px] text-fg-subtle">
          {r.priority ?? t('pages.origin.auto')}
        </span>
      ),
    },
    {
      key: 'ip_group',
      header: t('pages.origin.ipGroup'),
      accessor: (r) => (r.ip_group_id ? ipGroupById.get(r.ip_group_id)?.name ?? '' : ''),
      cell: (r) => {
        if (!r.ip_group_id) {
          return <span className="text-xs text-fg-subtle">—</span>
        }
        const group = ipGroupById.get(r.ip_group_id)
        if (!group) {
          return <Badge tone="warning">{t('pages.origin.ipGroupMissing')}</Badge>
        }
        return <Badge tone="brand">{group.name}</Badge>
      },
    },
    {
      key: 'pool',
      header: t('pages.origin.targetPool'),
      accessor: (r) => poolById.get(r.pool_id)?.name ?? '',
      cell: (r) => {
        const pool = poolById.get(r.pool_id)
        return pool ? (
          <span className="text-[13px]">
            {pool.name}
            {pool.is_default && (
              <Badge tone="brand" size="sm" className="ml-1.5">
                {t('pages.origin.defaultBadge')}
              </Badge>
            )}
          </span>
        ) : (
          <span className="text-[13px] text-fg-danger">{t('pages.origin.missingPool')}</span>
        )
      },
    },
    {
      key: 'enabled',
      header: t('common.enabled'),
      accessor: (r) => (r.enabled ? 1 : 0),
      width: '1%',
      cell: (r) => (
        <Switch
          size="sm"
          checked={r.enabled}
          disabled={!canWrite || toggleRoute.isPending}
          aria-label={`${t('common.enabled')}: ${r.name}`}
          onCheckedChange={(enabled) => toggleRoute.mutate({ route: r, enabled })}
        />
      ),
    },
    {
      key: 'row-actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (r) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('common.edit')}
            disabled={!canWrite}
            onClick={() => openEditRoute(r)}
            icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            onClick={() => setPendingDeleteRoute(r)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  /* ── Node table (per pool) ─────────────────────────────────────── */

  const nodeColumns: Column<Upstream>[] = [
    {
      key: 'address',
      header: t('pages.origin.nodeAddress'),
      accessor: (n) => n.address,
      sortable: true,
      cell: (n) => (
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded bg-brand-soft text-brand">
            <Globe weight="duotone" className="h-3.5 w-3.5" />
          </span>
          <span className="pw-mono text-[13px] font-medium text-fg-strong">{n.address}</span>
        </div>
      ),
    },
    {
      key: 'name',
      header: t('common.name'),
      accessor: (n) => n.name,
      cell: (n) => <span className="text-[13px] text-fg-subtle">{n.name}</span>,
    },
    {
      key: 'weight',
      header: t('pages.origin.nodeWeight'),
      align: 'right',
      sortable: true,
      accessor: (n) => n.weight,
      cell: (n) => <span className="tabular-nums text-[13px] text-fg-subtle">{n.weight}</span>,
    },
    {
      key: 'created_at',
      header: t('pages.origin.added'),
      accessor: (n) => n.created_at,
      sortable: true,
      cell: (n) => (
        <span className="text-[13px] text-fg-subtle">{formatDateTime(n.created_at)}</span>
      ),
    },
    {
      key: 'row-actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (n) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('common.edit')}
            disabled={!canWrite}
            onClick={() => openEditNode(n)}
            icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            onClick={() => setPendingDeleteNode(n)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  /* ── Render ────────────────────────────────────────────────────── */

  const loading = poolsQuery.isPending || upstreamsQuery.isPending
  const refresh = () => {
    void poolsQuery.refetch()
    void upstreamsQuery.refetch()
    void routesQuery.refetch()
  }

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.origin.title')}
        description={t('pages.origin.description')}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              loading={poolsQuery.isFetching || routesQuery.isFetching}
              onClick={refresh}
              icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
            >
              {t('common.refresh')}
            </Button>
            {canWrite && (
              <Button
                variant="secondary"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={openCreatePool}
              >
                {t('pages.origin.addPool')}
              </Button>
            )}
            {canWrite && (
              <Button
                variant="primary"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={openCreateRoute}
              >
                {t('pages.origin.addRoute')}
              </Button>
            )}
          </div>
        }
      />

      {/* ── Origin pools ── */}
      {poolsQuery.isError && !poolsQuery.data ? (
        <ErrorState
          error={poolsQuery.error}
          onRetry={() => poolsQuery.refetch()}
          retrying={poolsQuery.isFetching}
        />
      ) : loading ? (
        <Card>
          <CardBody className="p-0">
            <SkeletonRows rows={5} columns={4} />
          </CardBody>
        </Card>
      ) : pools.length === 0 ? (
        <Card>
          <CardBody className="p-0">
            <EmptyState
              className="border-0 py-12"
              icon={<Network weight="duotone" className="h-8 w-8" />}
              title={t('pages.origin.poolsEmptyTitle')}
              description={t('pages.origin.poolsEmptyDescription')}
              action={
                canWrite ? (
                  <Button
                    variant="primary"
                    icon={<Plus weight="bold" className="h-4 w-4" />}
                    onClick={openCreatePool}
                  >
                    {t('pages.origin.addPool')}
                  </Button>
                ) : undefined
              }
            />
          </CardBody>
        </Card>
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {pools.map((pool) => {
            const nodes = nodesByPool.get(pool.id) ?? []
            return (
              <Card key={pool.id}>
                <CardHeader
                  title={
                    <span className="flex items-center gap-2">
                      <span className="truncate">{pool.name}</span>
                      {pool.is_default && (
                        <Badge tone="brand" size="sm">
                          {t('pages.origin.defaultBadge')}
                        </Badge>
                      )}
                    </span>
                  }
                  description={
                    <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
                      <span className="flex items-center gap-1">
                        <Network weight="duotone" className="h-3.5 w-3.5" />
                        {lbLabel(pool.lb_algorithm)}
                      </span>
                      {pool.sni ? (
                        <span className="flex items-center gap-1">
                          <Lock weight="duotone" className="h-3.5 w-3.5" />
                          <span className="pw-mono">{pool.sni}</span>
                          <span className="text-fg-subtle/70">
                            {pool.verify_cert === false
                              ? t('pages.origin.certNotVerified')
                              : t('pages.origin.certVerified')}
                          </span>
                        </span>
                      ) : (
                        <span className="flex items-center gap-1">
                          <Globe weight="duotone" className="h-3.5 w-3.5" />
                          {t('pages.origin.httpOrigin')}
                        </span>
                      )}
                    </span>
                  }
                  action={
                    <div className="flex items-center gap-1">
                      {canWrite && (
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label={t('common.edit')}
                          onClick={() => openEditPool(pool)}
                          icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
                        />
                      )}
                      {canWrite && !pool.is_default && (
                        <Button
                          size="icon"
                          variant="ghost"
                          className="hover:text-fg-danger"
                          aria-label={t('common.delete')}
                          onClick={() => setPendingDeletePool(pool)}
                          icon={<Trash weight="duotone" className="h-4 w-4" />}
                        />
                      )}
                    </div>
                  }
                />
                <CardBody className="p-0">
                  {nodes.length === 0 ? (
                    <EmptyState
                      className="border-0 py-8"
                      icon={<Globe weight="duotone" className="h-6 w-6" />}
                      title={t('pages.origin.nodesEmpty')}
                      description={t('pages.origin.nodesEmptyDescription')}
                      action={
                        canWrite ? (
                          <Button
                            size="sm"
                            variant="secondary"
                            icon={<Plus weight="bold" className="h-3.5 w-3.5" />}
                            onClick={() => openCreateNode(pool)}
                          >
                            {t('pages.origin.addNode')}
                          </Button>
                        ) : undefined
                      }
                    />
                  ) : (
                    <>
                      <Table
                        columns={nodeColumns}
                        data={nodes}
                        rowKey={(n) => n.id}
                        dense
                        onRowClick={
                          canWrite
                            ? (n) => openEditNode(n)
                            : undefined
                        }
                      />
                      {canWrite && (
                        <div className="border-t border-line px-5 py-2">
                          <Button
                            size="sm"
                            variant="ghost"
                            icon={<Plus weight="bold" className="h-3.5 w-3.5" />}
                            onClick={() => openCreateNode(pool)}
                          >
                            {t('pages.origin.addNode')}
                          </Button>
                        </div>
                      )}
                    </>
                  )}
                </CardBody>
              </Card>
            )
          })}
        </div>
      )}

      {/* ── Routes ── */}
      <div className="mt-6">
        {routesQuery.isError && !routesQuery.data ? (
          <ErrorState
            error={routesQuery.error}
            onRetry={() => routesQuery.refetch()}
            retrying={routesQuery.isFetching}
          />
        ) : (
          <Card>
            <CardHeader
              title={t('pages.origin.routesTitle')}
              description={t('pages.origin.routesDescription')}
            />
            <CardBody className="p-0">
              {routesQuery.isPending ? (
                <SkeletonRows rows={4} columns={6} />
              ) : routes.length === 0 ? (
                <EmptyState
                  className="border-0 py-10"
                  icon={<Signpost weight="duotone" className="h-8 w-8" />}
                  title={t('pages.origin.routesEmpty')}
                  description={t('pages.origin.routesEmptyDescription')}
                  action={
                    canWrite ? (
                      <Button
                        variant="primary"
                        icon={<Plus weight="bold" className="h-4 w-4" />}
                        onClick={openCreateRoute}
                      >
                        {t('pages.origin.addRoute')}
                      </Button>
                    ) : undefined
                  }
                />
              ) : (
                <Table
                  columns={routeColumns}
                  data={routes}
                  rowKey={(r) => r.id}
                  dense
                  onRowClick={canWrite ? (r) => openEditRoute(r) : undefined}
                />
              )}
            </CardBody>
          </Card>
        )}
      </div>

      {/* ── Pool dialog ── */}
      <Dialog
        open={poolDialogOpen}
        onClose={savePool.isPending ? () => undefined : () => setPoolDialogOpen(false)}
        title={editingPool ? t('pages.origin.editPool') : t('pages.origin.addPool')}
        description={
          editingPool
            ? t('pages.origin.poolEditDescription')
            : t('pages.origin.poolCreateDescription')
        }
        footer={
          <>
            <Button
              variant="ghost"
              onClick={() => setPoolDialogOpen(false)}
              disabled={savePool.isPending}
            >
              {t('common.cancel')}
            </Button>
            <Button variant="primary" onClick={submitPool} loading={savePool.isPending}>
              {editingPool ? t('common.save') : t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Input
            label={t('pages.origin.poolName')}
            value={poolForm.name}
            placeholder={t('pages.origin.poolNamePlaceholder')}
            onChange={(e) => setPoolForm((f) => ({ ...f, name: e.target.value }))}
            autoFocus
            required
          />
          <Select
            label={t('pages.origin.lbAlgorithm')}
            value={poolForm.lbType}
            hint={t('pages.origin.lbHint')}
            options={lbOptions}
            onChange={(e) => setPoolForm((f) => ({ ...f, lbType: e.target.value }))}
          />
          {isHashKeyType(poolForm.lbType) && (
            <Input
              label={t('pages.origin.lbKey')}
              value={poolForm.hashKey}
              placeholder="x-user-id"
              hint={t('pages.origin.lbKeyHint')}
              onChange={(e) => setPoolForm((f) => ({ ...f, hashKey: e.target.value }))}
              required
            />
          )}
          <Switch
            checked={poolForm.httpsOrigin}
            onCheckedChange={(httpsOrigin) => setPoolForm((f) => ({ ...f, httpsOrigin }))}
            label={t('pages.origin.httpsOrigin')}
            description={t('pages.origin.httpsOriginHint')}
          />
          {poolForm.httpsOrigin && (
            <>
              <Input
                label={t('pages.origin.sni')}
                value={poolForm.sni}
                placeholder="origin.example.com"
                hint={t('pages.origin.sniHint')}
                prefixIcon={<Lock weight="duotone" />}
                onChange={(e) => setPoolForm((f) => ({ ...f, sni: e.target.value }))}
                required
              />
              <Switch
                checked={poolForm.verifyCert}
                onCheckedChange={(verifyCert) => setPoolForm((f) => ({ ...f, verifyCert }))}
                label={t('pages.origin.verifyCert')}
                description={t('pages.origin.verifyCertHint')}
              />
            </>
          )}
          {poolError && (
            <p
              role="alert"
              className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
            >
              {poolError}
            </p>
          )}
        </div>
      </Dialog>

      {/* ── Node dialog ── */}
      <Dialog
        open={nodeDialogOpen}
        onClose={saveNode.isPending ? () => undefined : () => setNodeDialogOpen(false)}
        title={editingNode ? t('pages.origin.editNode') : t('pages.origin.addNode')}
        description={t('pages.origin.nodeDialogDescription')}
        footer={
          <>
            <Button
              variant="ghost"
              onClick={() => setNodeDialogOpen(false)}
              disabled={saveNode.isPending}
            >
              {t('common.cancel')}
            </Button>
            <Button variant="primary" onClick={submitNode} loading={saveNode.isPending}>
              {editingNode ? t('common.save') : t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Input
            label={t('pages.origin.nodeAddress')}
            value={nodeForm.address}
            placeholder="http://10.0.0.1:8080"
            hint={t('pages.origin.nodeAddressHint')}
            prefixIcon={<Globe weight="duotone" />}
            className="pw-mono"
            onChange={(e) => setNodeForm((f) => ({ ...f, address: e.target.value }))}
            autoFocus
            required
          />
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Input
              label={t('pages.origin.nodeName')}
              value={nodeForm.name}
              placeholder={t('pages.origin.nodeNamePlaceholder')}
              onChange={(e) => setNodeForm((f) => ({ ...f, name: e.target.value }))}
              required
            />
            <Input
              label={t('pages.origin.nodeWeight')}
              type="number"
              min={1}
              max={10000}
              value={nodeForm.weight}
              hint={t('pages.origin.nodeWeightHint')}
              onChange={(e) => setNodeForm((f) => ({ ...f, weight: e.target.value }))}
              required
            />
          </div>
          <Select
            label={t('pages.origin.nodePool')}
            value={nodeForm.poolId}
            options={pools.map((p) => ({
              value: p.id,
              label: p.is_default ? `${p.name} (${t('pages.origin.defaultBadge')})` : p.name,
            }))}
            onChange={(e) => setNodeForm((f) => ({ ...f, poolId: e.target.value }))}
          />
          {nodeError && (
            <p
              role="alert"
              className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
            >
              {nodeError}
            </p>
          )}
        </div>
      </Dialog>

      {/* ── Route dialog ── */}
      <Dialog
        open={routeDialogOpen}
        onClose={saveRoute.isPending ? () => undefined : () => setRouteDialogOpen(false)}
        title={editingRoute ? t('pages.origin.editRoute') : t('pages.origin.addRoute')}
        description={t('pages.origin.routeDialogDescription')}
        footer={
          <>
            <Button
              variant="ghost"
              onClick={() => setRouteDialogOpen(false)}
              disabled={saveRoute.isPending}
            >
              {t('common.cancel')}
            </Button>
            <Button variant="primary" onClick={submitRoute} loading={saveRoute.isPending}>
              {editingRoute ? t('common.save') : t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Input
            label={t('pages.origin.routeName')}
            value={routeForm.name}
            placeholder={t('pages.origin.routeNamePlaceholder')}
            onChange={(e) => setRouteForm((f) => ({ ...f, name: e.target.value }))}
            autoFocus
            required
          />
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Select
              label={t('pages.origin.matchType')}
              value={routeForm.matchType}
              options={[
                { value: 'prefix', label: t('pages.origin.match.prefix') },
                { value: 'exact', label: t('pages.origin.match.exact') },
                { value: 'regex', label: t('pages.origin.match.regex') },
              ]}
              onChange={(e) => setRouteForm((f) => ({ ...f, matchType: e.target.value }))}
            />
            <Input
              label={t('pages.origin.routePath')}
              value={routeForm.path}
              placeholder={routeForm.matchType === 'regex' ? '^/static/.*' : '/api'}
              hint={
                routeForm.matchType === 'regex'
                  ? t('pages.origin.pathRegexHint')
                  : t('pages.origin.routePathHint')
              }
              className="pw-mono"
              onChange={(e) => setRouteForm((f) => ({ ...f, path: e.target.value }))}
              required
            />
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Input
              label={t('pages.origin.priority')}
              type="number"
              min={1}
              max={60000}
              value={routeForm.priority}
              placeholder={t('pages.origin.auto')}
              hint={t('pages.origin.priorityHint')}
              onChange={(e) => setRouteForm((f) => ({ ...f, priority: e.target.value }))}
            />
            <Select
              label={t('pages.origin.targetPool')}
              value={routeForm.poolId}
              options={pools.map((p) => ({
                value: p.id,
                label: p.is_default ? `${p.name} (${t('pages.origin.defaultBadge')})` : p.name,
              }))}
              onChange={(e) => setRouteForm((f) => ({ ...f, poolId: e.target.value }))}
            />
          </div>
          <Select
            label={t('pages.origin.ipGroup')}
            value={routeForm.ipGroupId}
            options={[
              { value: '', label: t('pages.origin.ipGroupNone') },
              ...gateableGroups.map((g) => ({ value: g.id, label: g.name })),
              ...(editingRoute?.ip_group_id &&
              !gateableGroups.some((g) => g.id === editingRoute.ip_group_id)
                ? [
                    {
                      value: editingRoute.ip_group_id,
                      label: `${ipGroupById.get(editingRoute.ip_group_id)?.name ?? editingRoute.ip_group_id} (${t('pages.origin.ipGroupUnusable')})`,
                    },
                  ]
                : []),
            ]}
            hint={t('pages.origin.ipGroupHint')}
            onChange={(e) => setRouteForm((f) => ({ ...f, ipGroupId: e.target.value }))}
          />
          <Switch
            checked={routeForm.enabled}
            onCheckedChange={(enabled) => setRouteForm((f) => ({ ...f, enabled }))}
            label={t('common.enabled')}
          />
          {routeError && (
            <p
              role="alert"
              className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
            >
              {routeError}
            </p>
          )}
        </div>
      </Dialog>

      {/* ── Delete confirmations ── */}
      <ConfirmDialog
        open={pendingDeletePool !== null}
        onClose={() => setPendingDeletePool(null)}
        onConfirm={() => pendingDeletePool && deletePool.mutate(pendingDeletePool.id)}
        title={t('pages.origin.deletePoolTitle')}
        description={t('pages.origin.deletePoolDescription')}
        confirmLabel={t('common.delete')}
        loading={deletePool.isPending}
      >
        {pendingDeletePool && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDeletePool.name}</p>
            <p className="mt-0.5 text-xs text-fg-subtle">
              {(nodesByPool.get(pendingDeletePool.id) ?? []).length}{' '}
              {t('pages.origin.nodesCount')}
            </p>
          </div>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={pendingDeleteNode !== null}
        onClose={() => setPendingDeleteNode(null)}
        onConfirm={() => pendingDeleteNode && deleteNode.mutate(pendingDeleteNode.id)}
        title={t('pages.origin.deleteNodeTitle')}
        description={t('pages.origin.deleteNodeDescription')}
        confirmLabel={t('common.delete')}
        loading={deleteNode.isPending}
      >
        {pendingDeleteNode && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono text-[13px] font-medium text-fg-strong">
              {pendingDeleteNode.address}
            </p>
            <p className="mt-0.5 text-xs text-fg-subtle">{pendingDeleteNode.name}</p>
          </div>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={pendingDeleteRoute !== null}
        onClose={() => setPendingDeleteRoute(null)}
        onConfirm={() => pendingDeleteRoute && deleteRoute.mutate(pendingDeleteRoute.id)}
        title={t('pages.origin.deleteRouteTitle')}
        description={t('pages.origin.deleteRouteDescription')}
        confirmLabel={t('common.delete')}
        loading={deleteRoute.isPending}
      >
        {pendingDeleteRoute && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDeleteRoute.name}</p>
            <p className="pw-mono mt-0.5 text-xs text-fg-subtle">{pendingDeleteRoute.path}</p>
          </div>
        )}
      </ConfirmDialog>
    </div>
  )
}

export default OriginPage
