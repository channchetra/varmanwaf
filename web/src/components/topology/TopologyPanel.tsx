import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation } from '@tanstack/react-query'
import {
  ArrowSquareOut,
  FloppyDisk,
  Plus,
  Trash,
  X,
} from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { useToast } from '@/components/ui/Toast'
import { errorMessage } from '@/api/errors'
import { sitesApi } from '@/api/sites'
import { wafSettingsApi } from '@/api/wafSettings'
import { rateLimitApi } from '@/api/rateLimiting'
import { ipRulesApi } from '@/api/ipRules'
import { cachingApi } from '@/api/caching'
import { siteBasicAuthApi } from '@/api/siteBasicAuth'
import { botApi } from '@/api/bot'
import { geoApi } from '@/api/geo'
import type {
  BotConfig,
  CacheRule,
  GeoConfig,
  IpRule,
  RateLimitRule,
  Route,
  Site,
  SiteBasicAuth,
  Upstream,
  UpstreamPool,
} from '@/api/types'
import type { LayerKind, TopologyNodeData } from './graph'

export interface TopologyPanelData {
  site: Site
  waf: {
    engine_mode: string
    mode: string
    paranoia_level: number
    waf_enabled: boolean
    advanced_mode: boolean
    openapi_spec: string
  }
  routes: Route[]
  pools: UpstreamPool[]
  upstreams: Upstream[]
  rateLimits: RateLimitRule[]
  ipRules: IpRule[]
  cacheRules: CacheRule[]
  basicAuth: SiteBasicAuth | null
  bot: BotConfig | null
  geo: GeoConfig | null
  ruleCount: number
  exclusionCount: number
  sslCount: number
  rewriteCount: number
}

export type CreateKind =
  | 'upstream'
  | 'route'
  | 'pool'
  | 'ratelimit'
  | 'iprule'
  | 'cacherule'

export type TopologySelection =
  | { type: 'node'; nodeId: string; data: TopologyNodeData }
  | { type: 'create'; kind: CreateKind; poolId?: string }

interface PanelProps {
  siteId: string
  selection: TopologySelection | null
  data: TopologyPanelData
  onClose: () => void
  onChanged: () => void
}

function Section({
  title,
  children,
  action,
}: {
  title: string
  children: React.ReactNode
  action?: React.ReactNode
}) {
  return (
    <div className="border-t border-line px-4 py-3 first:border-t-0">
      <div className="mb-2 flex items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">
          {title}
        </p>
        {action}
      </div>
      {children}
    </div>
  )
}

function Field({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <label className="mb-2 block">
      <span className="mb-1 block text-[12px] font-medium text-fg-subtle">
        {label}
      </span>
      {children}
    </label>
  )
}

function ItemRow({
  children,
  onDelete,
  disabled,
}: {
  children: React.ReactNode
  onDelete?: () => void
  disabled?: boolean
}) {
  return (
    <div className="mb-1.5 flex items-center gap-2 rounded-md border border-line bg-recessed/40 px-2.5 py-1.5">
      <div className="min-w-0 flex-1 text-[12px] text-fg">{children}</div>
      {onDelete && (
        <Button
          size="icon"
          variant="ghost"
          aria-label="delete"
          disabled={disabled}
          onClick={onDelete}
          icon={<Trash className="h-3.5 w-3.5 text-fg-danger" />}
        />
      )}
    </div>
  )
}

/** The right-hand editor: one node (or one create form) at a time. */
export function TopologyPanel({
  siteId,
  selection,
  data,
  onClose,
  onChanged,
}: PanelProps) {
  const { t } = useTranslation()
  const toast = useToast()

  const done = (message: string) => {
    toast.success(message)
    onChanged()
    onClose()
  }
  const failed = (error: unknown) =>
    toast.error(t('pages.topology.saveFailed'), errorMessage(error))

  if (!selection) return null

  const title =
    selection.type === 'create'
      ? t(`pages.topology.create.${selection.kind}`)
      : selection.data.kind === 'layer'
        ? selection.data.label
        : t(`pages.topology.kinds.${selection.data.kind}`)

  return (
    <aside className="absolute right-3 top-3 z-50 flex max-h-[calc(100%-24px)] w-[360px] flex-col overflow-hidden rounded-xl border border-line bg-elevated shadow-xl">
      <header className="flex items-center justify-between gap-2 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <p className="truncate text-[14px] font-semibold text-fg-strong">
            {title}
          </p>
          {selection.type === 'node' && selection.data.subtitle && (
            <p className="truncate text-[11px] text-fg-subtle">
              {selection.data.subtitle}
            </p>
          )}
        </div>
        <Button
          size="icon"
          variant="ghost"
          aria-label={t('common.close')}
          onClick={onClose}
          icon={<X className="h-4 w-4" />}
        />
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {selection.type === 'create' ? (
          <CreateEditor
            siteId={siteId}
            kind={selection.kind}
            poolId={selection.poolId}
            data={data}
            onDone={done}
            onFailed={failed}
            onCancel={onClose}
          />
        ) : (
          <NodeEditor
            siteId={siteId}
            nodeId={selection.nodeId}
            data={selection.data}
            panel={data}
            onDone={done}
            onFailed={failed}
            onClose={onClose}
          />
        )}
      </div>
    </aside>
  )
}

/* ------------------------------------------------------------------ */
/* Node editors                                                        */
/* ------------------------------------------------------------------ */

function NodeEditor({
  siteId,
  data: node,
  panel,
  onDone,
  onFailed,
  onClose,
}: {
  siteId: string
  nodeId: string
  data: TopologyNodeData
  panel: TopologyPanelData
  onDone: (message: string) => void
  onFailed: (error: unknown) => void
  onClose: () => void
}) {
  const { t } = useTranslation()

  switch (node.kind) {
    case 'site':
      return (
        <SiteEditor
          siteId={siteId}
          site={panel.site}
          onDone={onDone}
          onFailed={onFailed}
        />
      )
    case 'waf':
      return (
        <WafEditor
          siteId={siteId}
          waf={panel.waf}
          onDone={onDone}
          onFailed={onFailed}
        />
      )
    case 'layer':
      return (
        <LayerEditor
          siteId={siteId}
          layerKind={node.layerKind ?? 'rules'}
          panel={panel}
          onDone={onDone}
          onFailed={onFailed}
        />
      )
    case 'route':
      return (
        <RouteEditor
          siteId={siteId}
          route={panel.routes.find((r) => r.id === node.entityId) ?? null}
          panel={panel}
          onDone={onDone}
          onFailed={onFailed}
          onClose={onClose}
        />
      )
    case 'pool':
      return (
        <PoolEditor
          siteId={siteId}
          pool={panel.pools.find((p) => p.id === node.entityId) ?? null}
          panel={panel}
          onDone={onDone}
          onFailed={onFailed}
          onClose={onClose}
        />
      )
    case 'upstream':
      return (
        <UpstreamEditor
          siteId={siteId}
          upstream={panel.upstreams.find((u) => u.id === node.entityId) ?? null}
          panel={panel}
          onDone={onDone}
          onFailed={onFailed}
          onClose={onClose}
        />
      )
    default:
      return (
        <Section title={t('pages.topology.panel.readOnly')}>
          <p className="text-[12px] text-fg-subtle">
            {t('pages.topology.panel.readOnlyHint')}
          </p>
        </Section>
      )
  }
}

function SiteEditor({
  siteId,
  site,
  onDone,
  onFailed,
}: {
  siteId: string
  site: Site
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
}) {
  const { t } = useTranslation()
  const [name, setName] = useState(site.name ?? '')
  const [domain, setDomain] = useState(site.domain ?? '')
  const [alternates, setAlternates] = useState(
    (site.alternate_domains ?? []).join(', '),
  )

  const save = useMutation({
    mutationFn: () =>
      sitesApi.update(siteId, {
        name,
        domain,
        alternate_domains: alternates
          .split(',')
          .map((d: string) => d.trim())
          .filter(Boolean),
      }),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  return (
    <>
      <Section title={t('pages.topology.panel.site')}>
        <Field label={t('pages.topology.panel.name')}>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label={t('pages.topology.panel.domain')}>
          <Input value={domain} onChange={(e) => setDomain(e.target.value)} />
        </Field>
        <Field label={t('pages.topology.panel.alternateDomains')}>
          <Input
            value={alternates}
            placeholder="www.example.com, api.example.com"
            onChange={(e) => setAlternates(e.target.value)}
          />
        </Field>
      </Section>
      <Section title={t('pages.topology.panel.actions')}>
        <div className="flex gap-2">
          <Button
            size="sm"
            icon={<FloppyDisk className="h-4 w-4" />}
            loading={save.isPending}
            onClick={() => save.mutate()}
          >
            {t('common.save')}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={<ArrowSquareOut className="h-4 w-4" />}
            onClick={() => window.open(`/sites/${siteId}/settings`, '_self')}
          >
            {t('pages.topology.panel.openPage')}
          </Button>
        </div>
      </Section>
    </>
  )
}

function WafEditor({
  siteId,
  waf,
  onDone,
  onFailed,
}: {
  siteId: string
  waf: TopologyPanelData['waf']
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
}) {
  const { t } = useTranslation()
  const [enabled, setEnabled] = useState(waf.waf_enabled)
  const [mode, setMode] = useState(waf.mode)
  const [engine, setEngine] = useState(waf.engine_mode)
  const [paranoia, setParanoia] = useState(String(waf.paranoia_level))

  const save = useMutation({
    mutationFn: () =>
      wafSettingsApi.update(siteId, {
        waf_enabled: enabled,
        mode,
        engine_mode: engine,
        paranoia_level: Number(paranoia),
      }),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  return (
    <>
      <Section title={t('pages.topology.panel.posture')}>
        <div className="mb-3 flex items-center justify-between gap-3">
          <span className="text-[12px] text-fg">{t('pages.topology.panel.wafEnabled')}</span>
          <Switch checked={enabled} onCheckedChange={setEnabled} />
        </div>
        <Field label={t('pages.topology.panel.enforcementMode')}>
          <Select
            value={mode}
            onChange={(e) => setMode(e.target.value)}
            options={[
              { value: 'block', label: t('pages.topology.panel.modeBlock') },
              { value: 'monitor', label: t('pages.topology.panel.modeMonitor') },
            ]}
          />
        </Field>
        <Field label={t('pages.topology.panel.engine')}>
          <Select
            value={engine}
            onChange={(e) => setEngine(e.target.value)}
            options={[
              { value: 'varman', label: 'Varman (native, enforcing)' },
              { value: 'legacy', label: 'Legacy signature engine' },
              { value: 'shadow', label: 'Shadow (compare only)' },
            ]}
          />
        </Field>
        <Field label={t('pages.topology.panel.paranoia')}>
          <Select
            value={paranoia}
            onChange={(e) => setParanoia(e.target.value)}
            options={['1', '2', '3', '4'].map((n) => ({
              value: n,
              label: `PL ${n}`,
            }))}
          />
        </Field>
      </Section>
      <Section title={t('pages.topology.panel.actions')}>
        <div className="flex gap-2">
          <Button
            size="sm"
            icon={<FloppyDisk className="h-4 w-4" />}
            loading={save.isPending}
            onClick={() => save.mutate()}
          >
            {t('common.save')}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={<ArrowSquareOut className="h-4 w-4" />}
            onClick={() =>
              window.open(
                `/sites/${siteId}/security/protection?tab=tuning`,
                '_self',
              )
            }
          >
            {t('pages.topology.panel.openPage')}
          </Button>
        </div>
      </Section>
    </>
  )
}

function LayerEditor({
  siteId,
  layerKind,
  panel,
  onDone,
  onFailed,
}: {
  siteId: string
  layerKind: LayerKind
  panel: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
}) {
  const { t } = useTranslation()

  if (layerKind === 'ratelimit') {
    return (
      <RateLimitSection
        siteId={siteId}
        panel={panel}
        onDone={onDone}
        onFailed={onFailed}
      />
    )
  }
  if (layerKind === 'ip') {
    return (
      <IpRuleSection
        siteId={siteId}
        panel={panel}
        onDone={onDone}
        onFailed={onFailed}
      />
    )
  }
  if (layerKind === 'caching') {
    return (
      <CacheSection
        siteId={siteId}
        panel={panel}
        onDone={onDone}
        onFailed={onFailed}
      />
    )
  }
  if (layerKind === 'basicauth') {
    return (
      <BasicAuthSection
        siteId={siteId}
        panel={panel}
        onDone={onDone}
        onFailed={onFailed}
      />
    )
  }
  if (layerKind === 'bot') {
    return (
      <BotSection
        siteId={siteId}
        panel={panel}
        onDone={onDone}
        onFailed={onFailed}
      />
    )
  }
  if (layerKind === 'geo') {
    return (
      <GeoSection
        siteId={siteId}
        panel={panel}
        onDone={onDone}
        onFailed={onFailed}
      />
    )
  }

  // Rules, API schema, exclusions, SSL: state + deep link (their editors are
  // pages of their own; the flow view points at them).
  const links: Record<string, { href: string; label: string; text: string }> = {
    rules: {
      href: `/sites/${siteId}/security/protection?tab=rules`,
      label: t('pages.topology.panel.openPage'),
      text: t('pages.topology.panel.rulesHint', { n: panel.ruleCount }),
    },
    schema: {
      href: `/sites/${siteId}/security/api-assets`,
      label: t('pages.topology.panel.openPage'),
      text: t('pages.topology.panel.schemaHint', {
        n: panel.waf.openapi_spec ? 1 : 0,
      }),
    },
    exclusions: {
      href: `/sites/${siteId}/security/protection?tab=tuning`,
      label: t('pages.topology.panel.openPage'),
      text: t('pages.topology.panel.exclusionsHint', {
        n: panel.exclusionCount,
      }),
    },
    ssl: {
      href: `/sites/${siteId}/ssl`,
      label: t('pages.topology.panel.openPage'),
      text: t('pages.topology.panel.sslHint', { n: panel.sslCount }),
    },
  }
  const link = links[layerKind] ?? links.rules
  return (
    <Section title={t(`pages.topology.layers.${layerKind}`)}>
      <p className="mb-3 text-[12px] text-fg-subtle">{link.text}</p>
      <Button
        size="sm"
        variant="secondary"
        icon={<ArrowSquareOut className="h-4 w-4" />}
        onClick={() => window.open(link.href, '_self')}
      >
        {link.label}
      </Button>
    </Section>
  )
}

/* ------------------------------------------------------------------ */
/* Layer sub-editors                                                   */
/* ------------------------------------------------------------------ */

function RateLimitSection({
  siteId,
  panel,
  onDone,
  onFailed,
}: {
  siteId: string
  panel: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
}) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [threshold, setThreshold] = useState('100')
  const [period, setPeriod] = useState('60')

  const create = useMutation({
    mutationFn: () =>
      rateLimitApi.create(siteId, {
        name: name || t('pages.topology.newRateLimit'),
        characteristics: ['ip'],
        threshold: Number(threshold),
        period_seconds: Number(period),
        action: 'block',
        enabled: true,
      }),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })
  const remove = useMutation({
    mutationFn: (id: string) => rateLimitApi.delete(siteId, id),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  return (
    <>
      <Section title={t('pages.topology.panel.existing')}>
        {panel.rateLimits.length === 0 && (
          <p className="text-[12px] text-fg-subtle">
            {t('pages.topology.panel.none')}
          </p>
        )}
        {panel.rateLimits.map((rule) => (
          <ItemRow
            key={rule.id}
            disabled={remove.isPending}
            onDelete={() => remove.mutate(rule.id)}
          >
            <span className="font-medium">{rule.name}</span>{' '}
            <span className="text-fg-subtle">
              {rule.threshold}/{rule.period_seconds}s ·{' '}
              {(rule.characteristics ?? []).join('+') || 'ip'} · {rule.action}
            </span>
          </ItemRow>
        ))}
      </Section>
      <Section title={t('pages.topology.panel.add')}>
        <Field label={t('pages.topology.panel.name')}>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label={t('pages.topology.panel.threshold')}>
            <Input
              type="number"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
            />
          </Field>
          <Field label={t('pages.topology.panel.windowSeconds')}>
            <Input
              type="number"
              value={period}
              onChange={(e) => setPeriod(e.target.value)}
            />
          </Field>
        </div>
        <Button
          size="sm"
          icon={<Plus className="h-4 w-4" />}
          loading={create.isPending}
          onClick={() => create.mutate()}
        >
          {t('common.add')}
        </Button>
      </Section>
    </>
  )
}

function IpRuleSection({
  siteId,
  panel,
  onDone,
  onFailed,
}: {
  siteId: string
  panel: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
}) {
  const { t } = useTranslation()
  const [cidr, setCidr] = useState('')
  const [action, setAction] = useState('block')

  const create = useMutation({
    mutationFn: () =>
      ipRulesApi.create(siteId, {
        name: cidr || t('pages.topology.newIpRule'),
        ip_ranges: cidr
          .split(',')
          .map((c) => c.trim())
          .filter(Boolean),
        action,
        enabled: true,
      }),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })
  const remove = useMutation({
    mutationFn: (id: string) => ipRulesApi.delete(siteId, id),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  return (
    <>
      <Section title={t('pages.topology.panel.existing')}>
        {panel.ipRules.length === 0 && (
          <p className="text-[12px] text-fg-subtle">
            {t('pages.topology.panel.none')}
          </p>
        )}
        {panel.ipRules.map((rule) => (
          <ItemRow
            key={rule.id}
            disabled={remove.isPending}
            onDelete={() => remove.mutate(rule.id)}
          >
            <span className="font-medium">{rule.name}</span>{' '}
            <span className="text-fg-subtle">
              {rule.action} ·{' '}
              {rule.group_name ?? (rule.ip_ranges ?? []).join(', ')}
            </span>
          </ItemRow>
        ))}
      </Section>
      <Section title={t('pages.topology.panel.add')}>
        <Field label={t('pages.topology.panel.cidr')}>
          <Input
            value={cidr}
            placeholder="203.0.113.0/24"
            onChange={(e) => setCidr(e.target.value)}
          />
        </Field>
        <Field label={t('pages.topology.panel.action')}>
          <Select
            value={action}
            onChange={(e) => setAction(e.target.value)}
            options={[
              { value: 'block', label: 'Block' },
              { value: 'allow', label: 'Allow' },
              { value: 'challenge', label: 'Challenge' },
            ]}
          />
        </Field>
        <Button
          size="sm"
          icon={<Plus className="h-4 w-4" />}
          loading={create.isPending}
          disabled={!cidr.trim()}
          onClick={() => create.mutate()}
        >
          {t('common.add')}
        </Button>
      </Section>
    </>
  )
}

function CacheSection({
  siteId,
  panel,
  onDone,
  onFailed,
}: {
  siteId: string
  panel: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
}) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [match, setMatch] = useState('')
  const [ttl, setTtl] = useState('3600')

  const create = useMutation({
    mutationFn: () =>
      cachingApi.createRule(siteId, {
        name: name || t('pages.topology.newCacheRule'),
        match_expression: match,
        edge_ttl_seconds: Number(ttl),
        cache_eligible: true,
        enabled: true,
      }),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })
  const remove = useMutation({
    mutationFn: (id: string) => cachingApi.deleteRule(siteId, id),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  return (
    <>
      <Section title={t('pages.topology.panel.existing')}>
        {panel.cacheRules.length === 0 && (
          <p className="text-[12px] text-fg-subtle">
            {t('pages.topology.panel.none')}
          </p>
        )}
        {panel.cacheRules.map((rule) => (
          <ItemRow
            key={rule.id}
            disabled={remove.isPending}
            onDelete={() => remove.mutate(rule.id)}
          >
            <span className="font-medium">{rule.name}</span>{' '}
            <span className="text-fg-subtle">
              {rule.match_expression || 'always'} · edge {rule.edge_ttl_seconds}s
            </span>
          </ItemRow>
        ))}
      </Section>
      <Section title={t('pages.topology.panel.add')}>
        <Field label={t('pages.topology.panel.name')}>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label={t('pages.topology.panel.matchExpression')}>
          <Input
            value={match}
            placeholder={'http.request.uri.path starts_with "/assets"'}
            onChange={(e) => setMatch(e.target.value)}
          />
        </Field>
        <Field label={t('pages.topology.panel.edgeTtl')}>
          <Input
            type="number"
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
          />
        </Field>
        <Button
          size="sm"
          icon={<Plus className="h-4 w-4" />}
          loading={create.isPending}
          onClick={() => create.mutate()}
        >
          {t('common.add')}
        </Button>
      </Section>
    </>
  )
}

function BasicAuthSection({
  siteId,
  panel,
  onDone,
  onFailed,
}: {
  siteId: string
  panel: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
}) {
  const { t } = useTranslation()
  const current = panel.basicAuth
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const save = useMutation({
    mutationFn: (body: {
      enabled?: boolean
      realm?: string
      credentials?: { username: string; password: string }[]
    }) => siteBasicAuthApi.update(siteId, body),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  const credentials = current?.credentials ?? []

  return (
    <>
      <Section title={t('pages.topology.panel.basicAuthState')}>
        <div className="mb-3 flex items-center justify-between gap-3">
          <span className="text-[12px] text-fg">
            {t('pages.topology.panel.enabled')}
          </span>
          <Switch
            checked={Boolean(current?.enabled)}
            onCheckedChange={(checked) =>
              save.mutate({ enabled: checked })
            }
          />
        </div>
        <Field label={t('pages.topology.panel.realm')}>
          <Input
            defaultValue={current?.realm ?? 'Restricted'}
            onBlur={(e) => save.mutate({ realm: e.target.value })}
          />
        </Field>
      </Section>
      <Section title={t('pages.topology.panel.credentials')}>
        {credentials.length === 0 && (
          <p className="text-[12px] text-fg-subtle">
            {t('pages.topology.panel.none')}
          </p>
        )}
        {credentials.map((credential) => (
          <ItemRow
            key={credential.username}
            disabled={save.isPending}
            onDelete={() =>
              save.mutate({
                credentials: credentials.filter(
                  (c) => c.username !== credential.username,
                ),
              })
            }
          >
            <span className="font-medium">{credential.username}</span>
          </ItemRow>
        ))}
        <div className="mt-2 grid grid-cols-2 gap-2">
          <Input
            placeholder={t('pages.topology.panel.username')}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <Input
            placeholder={t('pages.topology.panel.password')}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div className="mt-2">
          <Button
            size="sm"
            icon={<Plus className="h-4 w-4" />}
            loading={save.isPending}
            disabled={!username || !password}
            onClick={() =>
              save.mutate({
                credentials: [...credentials, { username, password }],
              })
            }
          >
            {t('common.add')}
          </Button>
        </div>
      </Section>
    </>
  )
}

function BotSection({
  siteId,
  panel,
  onDone,
  onFailed,
}: {
  siteId: string
  panel: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
}) {
  const { t } = useTranslation()
  const current = panel.bot
  const [enabled, setEnabled] = useState(Boolean(current?.enabled))
  const [action, setAction] = useState(current?.action ?? 'challenge')

  // Re-sync from the server value when it changes (adjusting during render,
  // not in an effect).
  const snapshot = `${current?.enabled}:${current?.action}`
  const [lastSnapshot, setLastSnapshot] = useState(snapshot)
  if (lastSnapshot !== snapshot) {
    setLastSnapshot(snapshot)
    setEnabled(Boolean(current?.enabled))
    setAction(current?.action ?? 'challenge')
  }

  const save = useMutation({
    mutationFn: () => botApi.update(siteId, { enabled, action }),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  return (
    <Section title={t('pages.topology.panel.botPosture')}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <span className="text-[12px] text-fg">
          {t('pages.topology.panel.enabled')}
        </span>
        <Switch checked={enabled} onCheckedChange={setEnabled} />
      </div>
      <Field label={t('pages.topology.panel.action')}>
        <Select
          value={action}
          onChange={(e) => setAction(e.target.value)}
          options={[
            { value: 'monitor', label: 'Monitor' },
            { value: 'challenge', label: 'Challenge' },
            { value: 'block', label: 'Block' },
          ]}
        />
      </Field>
      <Button
        size="sm"
        icon={<FloppyDisk className="h-4 w-4" />}
        loading={save.isPending}
        onClick={() => save.mutate()}
      >
        {t('common.save')}
      </Button>
    </Section>
  )
}

function GeoSection({
  siteId,
  panel,
  onDone,
  onFailed,
}: {
  siteId: string
  panel: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
}) {
  const { t } = useTranslation()
  const current = panel.geo
  const [enabled, setEnabled] = useState(Boolean(current?.enabled))
  const [action, setAction] = useState(current?.action ?? 'block')
  const [mode, setMode] = useState(current?.mode ?? 'block_list')

  // Re-sync from the server value when it changes (adjusting during render,
  // not in an effect).
  const snapshot = `${current?.enabled}:${current?.action}:${current?.mode}`
  const [lastSnapshot, setLastSnapshot] = useState(snapshot)
  if (lastSnapshot !== snapshot) {
    setLastSnapshot(snapshot)
    setEnabled(Boolean(current?.enabled))
    setAction(current?.action ?? 'block')
    setMode(current?.mode ?? 'block_list')
  }

  const save = useMutation({
    mutationFn: () => geoApi.update(siteId, { enabled, action, mode }),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  return (
    <>
      <Section title={t('pages.topology.panel.geoPolicy')}>
        <div className="mb-3 flex items-center justify-between gap-3">
          <span className="text-[12px] text-fg">
            {t('pages.topology.panel.enabled')}
          </span>
          <Switch checked={enabled} onCheckedChange={setEnabled} />
        </div>
        <Field label={t('pages.topology.panel.geoMode')}>
          <Select
            value={mode}
            onChange={(e) => setMode(e.target.value)}
            options={[
              { value: 'block_list', label: 'Deny listed countries' },
              { value: 'allow_list', label: 'Allow only listed countries' },
            ]}
          />
        </Field>
        <Field label={t('pages.topology.panel.action')}>
          <Select
            value={action}
            onChange={(e) => setAction(e.target.value)}
            options={[
              { value: 'monitor', label: 'Monitor' },
              { value: 'block', label: 'Block' },
            ]}
          />
        </Field>
        <p className="mb-3 text-[11px] text-fg-subtle">
          {t('pages.topology.panel.geoCountries', {
            n: (current?.countries ?? []).length,
            asns: (current?.blocked_asns ?? []).length,
          })}
        </p>
        <div className="flex gap-2">
          <Button
            size="sm"
            icon={<FloppyDisk className="h-4 w-4" />}
            loading={save.isPending}
            onClick={() => save.mutate()}
          >
            {t('common.save')}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={<ArrowSquareOut className="h-4 w-4" />}
            onClick={() =>
              window.open(`/sites/${siteId}/security/access?tab=geo`, '_self')
            }
          >
            {t('pages.topology.panel.openPage')}
          </Button>
        </div>
      </Section>
    </>
  )
}

/* ------------------------------------------------------------------ */
/* Routing editors                                                     */
/* ------------------------------------------------------------------ */

function RouteEditor({
  siteId,
  route,
  panel,
  onDone,
  onFailed,
  onClose,
}: {
  siteId: string
  route: Route | null
  panel: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
  onClose: () => void
}) {
  const { t } = useTranslation()
  const [name, setName] = useState(route?.name ?? '')
  const [path, setPath] = useState(route?.path ?? '/')
  const [matchType, setMatchType] = useState(route?.match_type ?? 'prefix')
  const [enabled, setEnabled] = useState(route?.enabled ?? true)
  const [poolId, setPoolId] = useState(
    route?.pool_id ?? panel.pools.find((p) => p.is_default)?.id ?? panel.pools[0]?.id ?? '',
  )

  const save = useMutation({
    mutationFn: () =>
      route
        ? sitesApi.updateRoute(siteId, route.id, {
            name,
            path,
            match_type: matchType,
            enabled,
            pool_id: poolId,
          })
        : sitesApi.createRoute(siteId, {
            name: name || path,
            path,
            match_type: matchType,
            enabled,
            pool_id: poolId,
          }),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })
  const remove = useMutation({
    mutationFn: () => sitesApi.deleteRoute(siteId, route?.id ?? ''),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  if (!route && panel.pools.length === 0) {
    return (
      <Section title={t('pages.topology.panel.route')}>
        <p className="text-[12px] text-fg-subtle">
          {t('pages.topology.panel.routeNeedsPool')}
        </p>
      </Section>
    )
  }

  return (
    <>
      <Section title={t('pages.topology.panel.route')}>
        <Field label={t('pages.topology.panel.name')}>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label={t('pages.topology.panel.path')}>
          <Input
            value={path}
            placeholder="/api"
            onChange={(e) => setPath(e.target.value)}
          />
        </Field>
        <Field label={t('pages.topology.panel.matchType')}>
          <Select
            value={matchType}
            onChange={(e) => setMatchType(e.target.value)}
            options={[
              { value: 'prefix', label: 'Prefix' },
              { value: 'exact', label: 'Exact' },
              { value: 'regex', label: 'Regex' },
            ]}
          />
        </Field>
        <Field label={t('pages.topology.panel.pool')}>
          <Select
            value={poolId}
            onChange={(e) => setPoolId(e.target.value)}
            options={panel.pools.map((pool) => ({
              value: pool.id,
              label: pool.name,
            }))}
          />
        </Field>
        <div className="mb-2 flex items-center justify-between gap-3">
          <span className="text-[12px] text-fg">
            {t('pages.topology.panel.enabled')}
          </span>
          <Switch checked={enabled} onCheckedChange={setEnabled} />
        </div>
      </Section>
      <Section title={t('pages.topology.panel.actions')}>
        <div className="flex gap-2">
          <Button
            size="sm"
            icon={<FloppyDisk className="h-4 w-4" />}
            loading={save.isPending}
            onClick={() => save.mutate()}
          >
            {t('common.save')}
          </Button>
          {route && (
            <Button
              size="sm"
              variant="ghost"
              icon={<Trash className="h-4 w-4 text-fg-danger" />}
              loading={remove.isPending}
              onClick={() => remove.mutate()}
            >
              {t('common.delete')}
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
        </div>
      </Section>
    </>
  )
}

function PoolEditor({
  siteId,
  pool,
  panel,
  onDone,
  onFailed,
  onClose,
}: {
  siteId: string
  pool: UpstreamPool | null
  panel: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
  onClose: () => void
}) {
  const { t } = useTranslation()
  const [name, setName] = useState(pool?.name ?? '')
  const [lb, setLb] = useState(pool?.lb_algorithm ?? 'round_robin')

  const save = useMutation({
    mutationFn: () =>
      pool
        ? sitesApi.updatePool(siteId, pool.id, { name, lb_algorithm: lb })
        : sitesApi.createPool(siteId, { name: name || 'origin', lb_algorithm: lb }),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })
  const remove = useMutation({
    mutationFn: () => sitesApi.deletePool(siteId, pool?.id ?? ''),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  const targets = panel.upstreams.filter((u) => u.pool_id === pool?.id)

  return (
    <>
      <Section title={t('pages.topology.panel.pool')}>
        <Field label={t('pages.topology.panel.name')}>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label={t('pages.topology.panel.lbAlgorithm')}>
          <Select
            value={lb}
            onChange={(e) => setLb(e.target.value)}
            options={[
              { value: 'round_robin', label: 'Round robin' },
              { value: 'random', label: 'Random' },
              { value: 'hash:ip', label: 'Hash: client IP' },
              { value: 'hash:uri', label: 'Hash: URI' },
            ]}
          />
        </Field>
        <p className="text-[11px] text-fg-subtle">
          {t('pages.topology.panel.targets', { n: targets.length })}
        </p>
      </Section>
      <Section title={t('pages.topology.panel.actions')}>
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            icon={<FloppyDisk className="h-4 w-4" />}
            loading={save.isPending}
            onClick={() => save.mutate()}
          >
            {t('common.save')}
          </Button>
          {pool && !pool.is_default && (
            <Button
              size="sm"
              variant="ghost"
              icon={<Trash className="h-4 w-4 text-fg-danger" />}
              loading={remove.isPending}
              onClick={() => remove.mutate()}
            >
              {t('common.delete')}
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
        </div>
      </Section>
    </>
  )
}

function UpstreamEditor({
  siteId,
  upstream,
  defaultPoolId,
  panel,
  onDone,
  onFailed,
  onClose,
}: {
  siteId: string
  upstream: Upstream | null
  defaultPoolId?: string
  panel: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
  onClose: () => void
}) {
  const { t } = useTranslation()
  const [name, setName] = useState(upstream?.name ?? 'origin')
  const [address, setAddress] = useState(upstream?.address ?? '')
  const [weight, setWeight] = useState(String(upstream?.weight ?? 1))
  const [tls, setTls] = useState(upstream?.tls ?? false)
  const [poolId, setPoolId] = useState(
    upstream?.pool_id ??
      defaultPoolId ??
      panel.pools.find((p) => p.is_default)?.id ??
      panel.pools[0]?.id ??
      '',
  )

  const save = useMutation({
    mutationFn: () =>
      upstream
        ? sitesApi.updateUpstream(siteId, upstream.id, {
            name,
            address,
            weight: Number(weight),
            tls,
            pool_id: poolId,
          })
        : sitesApi.createUpstream(siteId, {
            name,
            address,
            weight: Number(weight),
            tls,
            pool_id: poolId,
          }),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })
  const remove = useMutation({
    mutationFn: () => sitesApi.deleteUpstream(siteId, upstream?.id ?? ''),
    onSuccess: () => onDone(t('pages.topology.saved')),
    onError: onFailed,
  })

  return (
    <>
      <Section title={t('pages.topology.panel.upstream')}>
        <Field label={t('pages.topology.panel.name')}>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label={t('pages.topology.panel.address')}>
          <Input
            value={address}
            placeholder="10.0.0.5:8080"
            onChange={(e) => setAddress(e.target.value)}
          />
        </Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label={t('pages.topology.panel.weight')}>
            <Input
              type="number"
              value={weight}
              onChange={(e) => setWeight(e.target.value)}
            />
          </Field>
          <Field label={t('pages.topology.panel.pool')}>
            <Select
              value={poolId}
              onChange={(e) => setPoolId(e.target.value)}
              options={panel.pools.map((pool) => ({
                value: pool.id,
                label: pool.name,
              }))}
            />
          </Field>
        </div>
        <div className="mb-2 flex items-center justify-between gap-3">
          <span className="text-[12px] text-fg">
            {t('pages.topology.panel.tlsToOrigin')}
          </span>
          <Switch checked={tls} onCheckedChange={setTls} />
        </div>
      </Section>
      <Section title={t('pages.topology.panel.actions')}>
        <div className="flex gap-2">
          <Button
            size="sm"
            icon={<FloppyDisk className="h-4 w-4" />}
            loading={save.isPending}
            disabled={!address.trim()}
            onClick={() => save.mutate()}
          >
            {t('common.save')}
          </Button>
          {upstream && (
            <Button
              size="sm"
              variant="ghost"
              icon={<Trash className="h-4 w-4 text-fg-danger" />}
              loading={remove.isPending}
              onClick={() => remove.mutate()}
            >
              {t('common.delete')}
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
        </div>
      </Section>
    </>
  )
}

/* ------------------------------------------------------------------ */
/* Create forms (palette drops / add buttons)                          */
/* ------------------------------------------------------------------ */

function CreateEditor({
  siteId,
  kind,
  poolId,
  data,
  onDone,
  onFailed,
  onCancel,
}: {
  siteId: string
  kind: CreateKind
  poolId?: string
  data: TopologyPanelData
  onDone: (m: string) => void
  onFailed: (e: unknown) => void
  onCancel: () => void
}) {
  const { t } = useTranslation()

  if (kind === 'upstream') {
    return (
      <UpstreamEditor
        siteId={siteId}
        upstream={null}
        defaultPoolId={poolId}
        panel={data}
        onDone={onDone}
        onFailed={onFailed}
        onClose={onCancel}
      />
    )
  }
  if (kind === 'route') {
    return (
      <RouteEditor
        siteId={siteId}
        route={null}
        panel={data}
        onDone={onDone}
        onFailed={onFailed}
        onClose={onCancel}
      />
    )
  }
  if (kind === 'pool') {
    return (
      <PoolEditor
        siteId={siteId}
        pool={null}
        panel={data}
        onDone={onDone}
        onFailed={onFailed}
        onClose={onCancel}
      />
    )
  }
  if (kind === 'ratelimit' || kind === 'iprule' || kind === 'cacherule') {
    const layerKind: LayerKind =
      kind === 'ratelimit' ? 'ratelimit' : kind === 'iprule' ? 'ip' : 'caching'
    return (
      <LayerEditor
        siteId={siteId}
        layerKind={layerKind}
        panel={data}
        onDone={onDone}
        onFailed={onFailed}
      />
    )
  }
  return (
    <Section title={t('pages.topology.panel.add')}>
      <Badge tone="neutral">{kind}</Badge>
    </Section>
  )
}
