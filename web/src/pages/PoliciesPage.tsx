import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  CaretRight,
  Play,
  Plus,
  Stack,
  Trash,
} from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardFooter, CardHeader } from '@/components/ui/Card'
import { Callout } from '@/components/ui/Callout'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Dialog } from '@/components/ui/Dialog'
import { Input } from '@/components/ui/Input'
import { PillMultiSelect, TagInput } from '@/components/ui/MultiSelect'
import { Select } from '@/components/ui/Select'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { Switch } from '@/components/ui/Switch'
import { Tabs } from '@/components/ui/Tabs'
import { Textarea } from '@/components/ui/Textarea'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { PolicyTesterDialog } from '@/components/PolicyTesterDialog'
import { useCanWrite } from '@/hooks'
import { cn } from '@/lib/utils'
import { crsApi, crsKeys } from '@/api/crs'
import {
  EXCLUSION_TARGETS,
  MANAGED_RULE_IDS,
  managedRuleKeys,
  managedRulesApi,
  policiesApi,
  policyKeys,
  type ApiSchemaLayerConfig,
  type BotLayerConfig,
  type CrsImportLayerConfig,
  type CrsLayerConfig,
  type CustomRulesLayerConfig,
  type EngineLayerConfig,
  type IpAccessLayerConfig,
  type IpAccessLayerRule,
  type PolicyDetail,
  type PolicyLayerKind,
  type PolicyPreview,
  type PolicyRule,
  type PolicySummary,
  type PolicyVersion,
  type PolicyVersionDiff,
  type RateLimitLayerConfig,
  type RateLimitLayerRule,
  type RuleOverrideEntry,
  type RuleOverridesLayerConfig,
  type RulePlanEntry,
  type VirtualPatchesLayerConfig,
} from '@/api/policies'
import { WAF_CATEGORIES, WAF_ENGINE_MODES, WAF_STACKS } from '@/api/types'

/** Layer tabs of the editor, in display order. */
export const LAYER_TABS: PolicyLayerKind[] = [
  'engine',
  'crs',
  'custom_rules',
  'rule_overrides',
  'virtual_patches',
  'api_schema',
  'rate_limit',
  'ip_access',
  'bot',
  'crs_import',
]

/**
 * Global WAF policies: shared, revisioned configuration documents sites can
 * follow. Unassigned sites keep their own settings, so creating a policy has
 * no effect until it is assigned on a site's Policy tab.
 */
export function PoliciesPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const canWrite = useCanWrite()
  const toast = useToast()
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<PolicySummary | null>(null)

  const list = useQuery({
    queryKey: policyKeys.list(),
    queryFn: () => policiesApi.list(),
  })

  const remove = useMutation({
    mutationFn: (id: string) => policiesApi.remove(id),
    onSuccess: () => {
      toast.success(t('pages.policies.deleted'))
      setDeleteTarget(null)
      void queryClient.invalidateQueries({ queryKey: policyKeys.all })
    },
  })

  if (list.isError && !list.data) {
    return (
      <div className="animate-slide-up">
        <ErrorState
          error={list.error}
          onRetry={() => list.refetch()}
          retrying={list.isFetching}
        />
      </div>
    )
  }

  const policies = list.data ?? []

  return (
    <div className="animate-slide-up space-y-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold text-fg-strong">
            {t('pages.policies.title')}
          </h1>
          <p className="mt-1 text-[13px] text-fg-subtle">
            {t('pages.policies.description')}
          </p>
        </div>
        {canWrite && (
          <Button
            variant="primary"
            icon={<Plus weight="bold" className="h-4 w-4" />}
            onClick={() => setCreateOpen(true)}
          >
            {t('pages.policies.new')}
          </Button>
        )}
      </div>

      <Tabs
        items={[
          { value: 'policies', label: t('pages.policies.title') },
          { value: 'crs', label: t('pages.crs.title') },
        ]}
        value="policies"
        onChange={(value) => {
          if (value === 'crs') navigate('/crs')
        }}
      />

      <Callout
        tone="brand"
        icon={<Stack weight="duotone" className="h-5 w-5" />}
        title={t('pages.policies.overviewTitle')}
      >
        {t('pages.policies.overview')}
      </Callout>

      {list.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : policies.length === 0 ? (
        <Card>
          <CardBody className="flex flex-col items-center gap-3 py-10 text-center">
            <Stack weight="duotone" className="h-8 w-8 text-fg-subtle" />
            <div>
              <p className="text-sm font-medium text-fg-strong">
                {t('pages.policies.emptyTitle')}
              </p>
              <p className="mt-1 text-[13px] text-fg-subtle">
                {t('pages.policies.emptyBody')}
              </p>
            </div>
          </CardBody>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {policies.map((policy) => (
            <Card key={policy.id} className="flex flex-col">
              <CardHeader
                title={policy.name}
                description={
                  policy.description || t('pages.policies.noDescription')
                }
                action={
                  <Badge tone={policy.enabled ? 'success' : 'neutral'} dot>
                    {policy.enabled
                      ? t('pages.policies.stateEnabled')
                      : t('pages.policies.stateDisabled')}
                  </Badge>
                }
              />
              <CardBody className="flex-1 space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="neutral">
                    {t('pages.policies.revision', { n: policy.revision })}
                  </Badge>
                  <Badge tone="neutral">
                    {t('pages.policies.siteCount', { n: policy.site_count })}
                  </Badge>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {policy.layer_kinds.length === 0 ? (
                    <span className="text-xs text-fg-subtle">
                      {t('pages.policies.noLayers')}
                    </span>
                  ) : (
                    policy.layer_kinds.map((kind) => (
                      <Badge key={kind} tone="info">
                        {t(`pages.policies.layers.${kind}`)}
                      </Badge>
                    ))
                  )}
                </div>
              </CardBody>
              <CardFooter className="justify-between">
                <Link to={`/policies/${policy.id}`}>
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-line bg-elevated px-3 py-1.5 text-[13px] font-medium text-fg-strong transition-colors hover:border-fill">
                    {canWrite
                      ? t('pages.policies.open')
                      : t('pages.policies.view')}
                    <CaretRight weight="bold" className="h-3.5 w-3.5" />
                  </span>
                </Link>
                {canWrite && (
                  <Button
                    size="sm"
                    variant="ghost"
                    icon={<Trash className="h-4 w-4" />}
                    onClick={() => setDeleteTarget(policy)}
                  >
                    {t('common.delete')}
                  </Button>
                )}
              </CardFooter>
            </Card>
          ))}
        </div>
      )}

      <CreatePolicyDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(id) => {
          setCreateOpen(false)
          void queryClient.invalidateQueries({ queryKey: policyKeys.all })
          navigate(`/policies/${id}`)
        }}
      />

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && remove.mutate(deleteTarget.id)}
        loading={remove.isPending}
        title={t('pages.policies.deleteTitle')}
        description={t('pages.policies.deleteBody', {
          name: deleteTarget?.name ?? '',
          n: deleteTarget?.site_count ?? 0,
        })}
        confirmLabel={t('common.delete')}
      />
    </div>
  )
}

/* ── Create ───────────────────────────────────────────────────────────── */

function CreatePolicyDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean
  onClose: () => void
  onCreated: (id: string) => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [templateId, setTemplateId] = useState('')

  const templates = useQuery({
    queryKey: policyKeys.templates(),
    queryFn: () => policiesApi.templates(),
    enabled: open,
  })
  const selected = (templates.data ?? []).find(
    (template) => template.id === templateId,
  )

  const create = useMutation({
    mutationFn: () =>
      templateId
        ? policiesApi.fromTemplate({
            template_id: templateId,
            name,
            description,
          })
        : policiesApi.create({ name, description }),
    onSuccess: (policy) => {
      toast.success(t('pages.policies.created'), policy.name)
      setName('')
      setDescription('')
      setTemplateId('')
      onCreated(policy.id)
    },
    onError: (error) => {
      toast.error(t('pages.policies.createFailed'), String(error))
    },
  })

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t('pages.policies.new')}
      description={t('pages.policies.newHint')}
    >
      <div className="space-y-4 px-5 py-4">
        <Select
          label={t('pages.policies.template')}
          hint={selected?.description ?? t('pages.policies.templateHint')}
          value={templateId}
          onChange={(e) => setTemplateId(e.target.value)}
          options={[
            { value: '', label: t('pages.policies.blank') },
            ...(templates.data ?? []).map((template) => ({
              value: template.id,
              label: template.name,
            })),
          ]}
        />
        <Input
          label={t('pages.policies.name')}
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          maxLength={120}
        />
        <Input
          label={t('pages.policies.descriptionLabel')}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={create.isPending}
            disabled={name.trim().length === 0}
            onClick={() => create.mutate()}
          >
            {t('common.create')}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}

/* ── Editor ───────────────────────────────────────────────────────────── */

/** Version history: list, diff against the previous version, rollback. */
export function PolicyHistoryDialog({
  policyId,
  canWrite,
  onClose,
}: {
  policyId: string
  canWrite: boolean
  onClose: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<number | null>(null)

  const versions = useQuery({
    queryKey: policyKeys.versions(policyId),
    queryFn: () => policiesApi.versions(policyId),
  })
  const list: PolicyVersion[] = versions.data ?? []
  const currentId = selected ?? list[0]?.id ?? null
  const currentIndex = list.findIndex((version) => version.id === currentId)
  const previous = currentIndex >= 0 ? list[currentIndex + 1] : undefined

  const diff = useQuery({
    queryKey: policyKeys.versionDiff(
      policyId,
      previous?.id ?? 0,
      currentId ?? 0,
    ),
    queryFn: () =>
      policiesApi.versionDiff(policyId, previous!.id, currentId!),
    enabled: Boolean(previous && currentId),
  })

  const rollback = useMutation({
    mutationFn: (versionId: number) =>
      policiesApi.rollback(policyId, versionId),
    onSuccess: () => {
      toast.success(t('pages.policies.rollbackDone'))
      void queryClient.invalidateQueries({
        queryKey: policyKeys.versions(policyId),
      })
      void queryClient.invalidateQueries({
        queryKey: policyKeys.detail(policyId),
      })
      void queryClient.invalidateQueries({ queryKey: policyKeys.list() })
    },
    onError: (error) =>
      toast.error(t('pages.policies.rollbackFailed'), String(error)),
  })

  const currentVersion = list.find((version) => version.id === currentId)
  const diffData: PolicyVersionDiff | undefined = diff.data

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={t('pages.policies.history')}
      description={t('pages.policies.historyHint')}
    >
      <div className="max-h-[65vh] space-y-3 overflow-y-auto px-5 py-4">
        {versions.isLoading ? (
          <SkeletonCard />
        ) : list.length === 0 ? (
          <p className="text-[13px] text-fg-subtle">
            {t('pages.policies.noVersions')}
          </p>
        ) : (
          <ul className="divide-y divide-line rounded-lg border border-line">
            {list.map((version) => (
              <li
                key={version.id}
                className={cn(
                  'flex flex-wrap items-center gap-2 px-3 py-2 text-[13px]',
                  version.id === currentId && 'bg-recessed',
                )}
              >
                <button
                  type="button"
                  className="min-w-0 flex-1 text-left"
                  onClick={() => setSelected(version.id)}
                >
                  <span className="font-medium text-fg-strong">
                    {t('pages.policies.revision', { n: version.revision })}
                  </span>
                  <span className="ml-2 text-[11px] text-fg-subtle">
                    {version.source}
                    {version.actor ? ` · ${version.actor}` : ''} ·{' '}
                    {new Date(version.created_at).toLocaleString()}
                  </span>
                </button>
                {canWrite && version.id !== list[0]?.id && (
                  <Button
                    size="sm"
                    variant="ghost"
                    loading={rollback.isPending}
                    onClick={() => rollback.mutate(version.id)}
                  >
                    {t('pages.policies.rollback')}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}

        {previous && currentVersion && (
          <div className="rounded-lg border border-line p-3 text-[13px]">
            <p className="mb-2 font-medium text-fg-strong">
              {t('pages.policies.diffTitle', {
                from: previous.revision,
                to: currentVersion.revision,
              })}
            </p>
            {diffData ? (
              <div className="space-y-2">
                {diffData.fields.length > 0 && (
                  <p>
                    <span className="text-fg-subtle">
                      {t('pages.policies.diffFields')}:{' '}
                    </span>
                    {diffData.fields.join(', ')}
                  </p>
                )}
                {diffData.layers.map((layer) => (
                  <div key={layer.kind}>
                    <p className="text-[11px] tracking-wide text-fg-subtle uppercase">
                      {t(`pages.policies.layers.${layer.kind}`)}
                    </p>
                    <p className="text-[12px] break-all">
                      {layer.added.length > 0 && (
                        <span className="mr-2 text-fg-success">
                          +{layer.added.join(', ')}
                        </span>
                      )}
                      {layer.removed.length > 0 && (
                        <span className="mr-2 text-fg-danger">
                          −{layer.removed.join(', ')}
                        </span>
                      )}
                      {layer.changed.length > 0 && (
                        <span className="text-fg-subtle">
                          ~{layer.changed.join(', ')}
                        </span>
                      )}
                    </p>
                  </div>
                ))}
                {diffData.layers.length === 0 &&
                  diffData.fields.length === 0 && (
                    <p className="text-fg-subtle">
                      {t('pages.policies.diffNone')}
                    </p>
                  )}
              </div>
            ) : (
              <p className="text-fg-subtle">…</p>
            )}
          </div>
        )}
      </div>
    </Dialog>
  )
}

/** Shared save/remove wiring for the three layer forms. */
function useLayerMutation(
  policyId: string,
  kind: PolicyLayerKind,
  onStored: () => void,
) {
  const { t } = useTranslation()
  const toast = useToast()
  return useMutation({
    mutationFn: (config: unknown) =>
      policiesApi.putLayer(policyId, kind, config),
    onSuccess: () => {
      toast.success(t('pages.policies.layerSaved'))
      onStored()
    },
    onError: (error) => {
      toast.error(t('pages.policies.layerSaveFailed'), String(error))
    },
  })
}

export function LayerEditor({
  policy,
  tab,
  canWrite,
  onStored,
}: {
  policy: PolicyDetail
  tab: PolicyLayerKind
  canWrite: boolean
  onStored: () => void
}) {
  const stored = policy.layers.find((layer) => layer.kind === tab)
  if (tab === 'engine') {
    return (
      <EngineLayerForm
        policyId={policy.id}
        stored={stored?.config as EngineLayerConfig | undefined}
        hasStored={Boolean(stored)}
        canWrite={canWrite}
        onStored={onStored}
      />
    )
  }
  if (tab === 'crs') {
    return (
      <CrsLayerForm
        policyId={policy.id}
        stored={stored?.config as CrsLayerConfig | undefined}
        hasStored={Boolean(stored)}
        canWrite={canWrite}
        onStored={onStored}
      />
    )
  }
  if (tab === 'rule_overrides') {
    return (
      <RuleOverridesForm
        policyId={policy.id}
        stored={stored?.config as RuleOverridesLayerConfig | undefined}
        hasStored={Boolean(stored)}
        canWrite={canWrite}
        onStored={onStored}
      />
    )
  }
  if (tab === 'custom_rules') {
    return (
      <CustomRulesForm
        policyId={policy.id}
        stored={stored?.config as CustomRulesLayerConfig | undefined}
        hasStored={Boolean(stored)}
        canWrite={canWrite}
        onStored={onStored}
      />
    )
  }
  if (tab === 'virtual_patches') {
    return (
      <VirtualPatchesForm
        policyId={policy.id}
        stored={stored?.config as VirtualPatchesLayerConfig | undefined}
        hasStored={Boolean(stored)}
        canWrite={canWrite}
        onStored={onStored}
      />
    )
  }  if (tab === 'api_schema') {
    return (
      <ApiSchemaForm
        policyId={policy.id}
        stored={stored?.config as ApiSchemaLayerConfig | undefined}
        hasStored={Boolean(stored)}
        canWrite={canWrite}
        onStored={onStored}
      />
    )
  }
  if (tab === 'rate_limit') {
    return (
      <RateLimitForm
        policyId={policy.id}
        stored={stored?.config as RateLimitLayerConfig | undefined}
        hasStored={Boolean(stored)}
        canWrite={canWrite}
        onStored={onStored}
      />
    )
  }
  if (tab === 'ip_access') {
    return (
      <IpAccessForm
        policyId={policy.id}
        stored={stored?.config as IpAccessLayerConfig | undefined}
        hasStored={Boolean(stored)}
        canWrite={canWrite}
        onStored={onStored}
      />
    )
  }
  if (tab === 'bot') {
    return (
      <BotLayerForm
        policyId={policy.id}
        stored={stored?.config as BotLayerConfig | undefined}
        hasStored={Boolean(stored)}
        canWrite={canWrite}
        onStored={onStored}
      />
    )
  }
  return (
    <CrsImportForm
      policyId={policy.id}
      stored={stored?.config as CrsImportLayerConfig | undefined}
      hasStored={Boolean(stored)}
      canWrite={canWrite}
      onStored={onStored}
    />
  )
}

function LayerFooter({
  canWrite,
  hasStored,
  saving,
  onSave,
  onRemove,
}: {
  canWrite: boolean
  hasStored: boolean
  saving: boolean
  onSave: () => void
  onRemove: () => void
}) {
  const { t } = useTranslation()
  if (!canWrite) return null
  return (
    <div className="flex items-center justify-between border-t border-line bg-elevated/95 px-5 py-4 backdrop-blur">
      <Button
        variant="ghost"
        disabled={!hasStored}
        onClick={onRemove}
      >
        {t('pages.policies.removeLayer')}
      </Button>
      <div className="flex items-center gap-3">
        <span className="hidden text-[12px] text-fg-subtle sm:block">
          {t('pages.policies.saveHint')}
        </span>
        <Button variant="primary" size="lg" loading={saving} onClick={onSave}>
          {t('common.save')}
        </Button>
      </div>
    </div>
  )
}

/** Tri-state select: `''` = keep inheriting, otherwise the picked value. */
function TriSelect({
  label,
  hint,
  value,
  onChange,
  options,
}: {
  label: string
  hint?: string
  value: string
  onChange: (next: string) => void
  options: { value: string; label: string }[]
}) {
  const { t } = useTranslation()
  return (
    <Select
      label={label}
      hint={hint}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      options={[
        { value: '', label: t('pages.policies.keepInheriting') },
        ...options,
      ]}
    />
  )
}

function EngineLayerForm({
  policyId,
  stored,
  hasStored,
  canWrite,
  onStored,
}: {
  policyId: string
  stored?: EngineLayerConfig
  hasStored: boolean
  canWrite: boolean
  onStored: () => void
}) {
  const { t } = useTranslation()
  const save = useLayerMutation(policyId, 'engine', onStored)
  const remove = useMutation({
    mutationFn: () => policiesApi.deleteLayer(policyId, 'engine'),
    onSuccess: onStored,
  })

  const [wafEnabled, setWafEnabled] = useState(
    stored?.waf_enabled === undefined ? '' : String(stored.waf_enabled),
  )
  const [mode, setMode] = useState(stored?.mode ?? '')
  const [paranoia, setParanoia] = useState(
    stored?.paranoia_level === undefined ? '' : String(stored.paranoia_level),
  )
  const [advanced, setAdvanced] = useState(
    stored?.advanced_mode === undefined ? '' : String(stored.advanced_mode),
  )
  const [engineMode, setEngineMode] = useState(stored?.engine_mode ?? '')
  const [categories, setCategories] = useState<string[]>(
    stored?.monitor_categories ?? [],
  )
  const [stacks, setStacks] = useState<string[]>(
    stored?.monitor_stacks ?? [],
  )

  const config: EngineLayerConfig = {}
  if (wafEnabled !== '') config.waf_enabled = wafEnabled === 'true'
  if (mode) config.mode = mode
  if (paranoia) config.paranoia_level = Number(paranoia)
  if (advanced !== '') config.advanced_mode = advanced === 'true'
  if (engineMode) config.engine_mode = engineMode
  if (categories.length > 0) config.monitor_categories = categories
  if (stacks.length > 0) config.monitor_stacks = stacks

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="grid flex-1 gap-4 overflow-y-auto px-5 py-4 md:grid-cols-2">
        <TriSelect
          label={t('pages.policies.fields.wafEnabled')}
          value={wafEnabled}
          onChange={setWafEnabled}
          options={[
            { value: 'true', label: t('common.enabled') },
            { value: 'false', label: t('common.disabled') },
          ]}
        />
        <TriSelect
          label={t('pages.policies.fields.mode')}
          hint={t('pages.policies.fields.modeHint')}
          value={mode}
          onChange={setMode}
          options={[
            { value: 'off', label: 'off' },
            { value: 'monitor', label: 'monitor' },
            { value: 'block', label: 'block' },
          ]}
        />
        <TriSelect
          label={t('pages.policies.fields.paranoia')}
          value={paranoia}
          onChange={setParanoia}
          options={['1', '2', '3', '4'].map((level) => ({
            value: level,
            label: t('pages.policies.fields.paranoiaLevel', { n: level }),
          }))}
        />
        <TriSelect
          label={t('pages.policies.fields.advanced')}
          hint={t('pages.policies.fields.advancedHint')}
          value={advanced}
          onChange={setAdvanced}
          options={[
            { value: 'true', label: t('common.enabled') },
            { value: 'false', label: t('common.disabled') },
          ]}
        />
        <TriSelect
          label={t('pages.policies.fields.engineMode')}
          hint={t('pages.policies.fields.engineModeHint')}
          value={engineMode}
          onChange={setEngineMode}
          options={WAF_ENGINE_MODES.map((engine) => ({
            value: engine,
            label: engine,
          }))}
        />
        <div className="md:col-span-2">
          <PillMultiSelect
            label={t('pages.policies.fields.monitorCategories')}
            hint={t('pages.policies.fields.monitorHint')}
            options={WAF_CATEGORIES.map((category) => ({
              value: category,
              label: category,
            }))}
            value={categories}
            onChange={setCategories}
          />
          <p className="mt-1.5 text-[11px] text-fg-subtle">
            {t('pages.policies.fields.monitorCategoriesLinkage')}
          </p>
        </div>
        <div className="md:col-span-2">
          <PillMultiSelect
            label={t('pages.policies.fields.monitorStacks')}
            options={WAF_STACKS.map((stack) => ({
              value: stack,
              label: stack,
            }))}
            value={stacks}
            onChange={setStacks}
          />
        </div>
      </div>
      <LayerFooter
        canWrite={canWrite}
        hasStored={hasStored}
        saving={save.isPending || remove.isPending}
        onSave={() => save.mutate(config)}
        onRemove={() => remove.mutate()}
      />
    </div>
  )
}

function CrsLayerForm({
  policyId,
  stored,
  hasStored,
  canWrite,
  onStored,
}: {
  policyId: string
  stored?: CrsLayerConfig
  hasStored: boolean
  canWrite: boolean
  onStored: () => void
}) {
  const { t } = useTranslation()
  const save = useLayerMutation(policyId, 'crs', onStored)
  const remove = useMutation({
    mutationFn: () => policiesApi.deleteLayer(policyId, 'crs'),
    onSuccess: onStored,
  })
  const [rules, setRules] = useState<string[]>(
    stored?.monitor_managed_rules ?? [],
  )

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1 overflow-y-auto px-5 py-4">
        <PillMultiSelect
          label={t('pages.policies.fields.monitorManagedRules')}
          hint={t('pages.policies.fields.monitorManagedRulesHint')}
          options={MANAGED_RULE_IDS.map((id) => ({ value: id, label: id }))}
          value={rules}
          onChange={setRules}
        />
      </div>
      <LayerFooter
        canWrite={canWrite}
        hasStored={hasStored}
        saving={save.isPending || remove.isPending}
        onSave={() => save.mutate({ monitor_managed_rules: rules })}
        onRemove={() => remove.mutate()}
      />
    </div>
  )
}

const OVERRIDE_ACTIONS = [
  'default',
  'monitor',
  'disable',
  'score_override',
] as const

/** Managed-rule tuning: disable, log-only, score override and exclusions. */
function RuleOverridesForm({
  policyId,
  stored,
  hasStored,
  canWrite,
  onStored,
}: {
  policyId: string
  stored?: RuleOverridesLayerConfig
  hasStored: boolean
  canWrite: boolean
  onStored: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const save = useLayerMutation(policyId, 'rule_overrides', onStored)
  const remove = useMutation({
    mutationFn: () => policiesApi.deleteLayer(policyId, 'rule_overrides'),
    onSuccess: onStored,
  })
  const catalogue = useQuery({
    queryKey: managedRuleKeys.all,
    queryFn: () => managedRulesApi.list(),
  })

  type Draft = { action: string; score: string; exclusions: string[] }
  // Draft keyed by rule id; a missing key means "default" (no override).
  const [draft, setDraft] = useState<Record<string, Draft>>(() => {
    const initial: Record<string, Draft> = {}
    for (const entry of stored?.overrides ?? []) {
      if (!entry.rule_id) continue
      initial[entry.rule_id] = {
        action: entry.action,
        score: entry.score !== undefined ? String(entry.score) : '',
        exclusions: entry.exclude_targets ?? [],
      }
    }
    return initial
  })
  // Selector entries (tags / severity) are authored through the API; show
  // them read-only so the tuning is visible.
  const selectors = (stored?.overrides ?? []).filter(
    (entry) => !entry.rule_id,
  )

  const patch = (ruleId: string, next: Partial<Draft>) => {
    setDraft((current) => {
      const base = current[ruleId] ?? {
        action: 'default',
        score: '',
        exclusions: [],
      }
      return { ...current, [ruleId]: { ...base, ...next } }
    })
  }

  const setAction = (ruleId: string, action: string) => {
    setDraft((current) => {
      const next = { ...current }
      if (action === 'default') {
        const existing = current[ruleId]
        if (existing && existing.exclusions.length > 0) {
          next[ruleId] = { ...existing, action }
        } else {
          delete next[ruleId]
        }
      } else {
        const existing = current[ruleId]
        next[ruleId] = {
          action,
          score: existing?.score ?? '',
          exclusions: existing?.exclusions ?? [],
        }
      }
      return next
    })
  }

  const payload = () => ({
    overrides: Object.entries(draft)
      .filter(([, value]) => value.action !== 'default')
      .map(([rule_id, value]) => {
        const entry: RuleOverrideEntry = {
          rule_id,
          action: value.action as RuleOverrideEntry['action'],
        }
        if (value.action === 'score_override') {
          entry.score = Math.min(255, Math.max(1, Number(value.score) || 1))
        }
        if (value.exclusions.length > 0) {
          entry.exclude_targets = value.exclusions
        }
        return entry
      }),
  })

  const tuned = Object.entries(draft).filter(
    ([, value]) => value.action !== 'default',
  ).length

  // Draft preview: compiles the layer as if it were saved.
  const [preview, setPreview] = useState<PolicyPreview | null>(null)
  const [testDraftOpen, setTestDraftOpen] = useState(false)
  const runPreview = useMutation({
    mutationFn: () =>
      policiesApi.preview({
        policy_id: policyId,
        layers: { rule_overrides: payload() },
      }),
    onSuccess: (result) => setPreview(result),
    onError: (error) =>
      toast.error(t('pages.policies.previewFailed'), String(error)),
  })

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1 space-y-3 overflow-y-auto px-5 py-4">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-[13px] text-fg-subtle">
            {t('pages.policies.fields.ruleTuningHint')}
          </p>
          <Badge tone={tuned > 0 ? 'warning' : 'neutral'}>
            {t('pages.policies.fields.tunedCount', { n: tuned })}
          </Badge>
          <Button
            size="sm"
            loading={runPreview.isPending}
            onClick={() => runPreview.mutate()}
          >
            {t('pages.policies.preview')}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={<Play weight="fill" className="h-3.5 w-3.5" />}
            onClick={() => setTestDraftOpen(true)}
          >
            {t('pages.policies.testDraft')}
          </Button>
        </div>
        {selectors.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {selectors.map((entry, index) => (
              <Badge key={index} tone="info">
                {entry.tags && entry.tags.length > 0
                  ? t('pages.policies.fields.selectorTags', {
                      tags: entry.tags.join(', '),
                    })
                  : t('pages.policies.fields.selectorSeverity', {
                      n: entry.severity_min ?? 0,
                    })}{' '}
                → {t(`pages.policies.fields.override.${entry.action}`)}
              </Badge>
            ))}
          </div>
        )}
        {catalogue.isLoading ? (
          <SkeletonCard />
        ) : (
          <ul className="divide-y divide-line rounded-lg border border-line">
            {(catalogue.data ?? []).map((rule) => {
              const state = draft[rule.id]
              const action = state?.action ?? 'default'
              return (
                <li key={rule.id} className="space-y-2 px-3 py-2.5">
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <code className="text-xs text-fg-subtle">
                          {rule.id}
                        </code>
                        <span className="truncate text-[13px] font-medium text-fg-strong">
                          {rule.name}
                        </span>
                      </div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-fg-subtle">
                        {rule.tags.map((tag) => (
                          <span key={tag}>#{tag}</span>
                        ))}
                        <span>
                          {t('pages.policies.fields.ruleSeverity')}{' '}
                          {rule.severity}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Select
                        value={action}
                        disabled={!canWrite}
                        onChange={(e) => setAction(rule.id, e.target.value)}
                        options={OVERRIDE_ACTIONS.map((value) => ({
                          value,
                          label: t(`pages.policies.fields.override.${value}`),
                        }))}
                      />
                      {action === 'score_override' && (
                        <div className="w-20">
                          <Input
                            type="number"
                            min={1}
                            max={255}
                            value={state?.score ?? ''}
                            disabled={!canWrite}
                            onChange={(e) =>
                              patch(rule.id, { score: e.target.value })
                            }
                          />
                        </div>
                      )}
                    </div>
                  </div>
                  {action !== 'default' && (
                    <PillMultiSelect
                      label={t('pages.policies.fields.excludeTargets')}
                      hint={t('pages.policies.fields.excludeTargetsHint')}
                      options={EXCLUSION_TARGETS.map((target) => ({
                        value: target,
                        label: target,
                      }))}
                      value={state?.exclusions ?? []}
                      onChange={(exclusions) =>
                        patch(rule.id, { exclusions })
                      }
                    />
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </div>
      <LayerFooter
        canWrite={canWrite}
        hasStored={hasStored}
        saving={save.isPending || remove.isPending}
        onSave={() => save.mutate(payload())}
        onRemove={() => remove.mutate()}
      />
      {preview && (
        <RulePlanDialog
          plan={preview.plan}
          onClose={() => setPreview(null)}
        />
      )}
      {testDraftOpen && (
        <PolicyTesterDialog
          policyId={policyId}
          layers={{ rule_overrides: payload() }}
          onClose={() => setTestDraftOpen(false)}
        />
      )}
    </div>
  )
}

/** Read-only table of a compiled rule plan. */
export function RulePlanDialog({
  plan,
  onClose,
}: {
  plan: RulePlanEntry[]
  onClose: () => void
}) {
  const { t } = useTranslation()
  const tone: Record<string, 'success' | 'warning' | 'neutral'> = {
    enforce: 'success',
    monitor: 'warning',
    disabled: 'neutral',
  }
  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={t('pages.policies.planTitle')}
      description={t('pages.policies.planHint')}
    >
      <div className="max-h-[60vh] overflow-y-auto px-5 py-4">
        <ul className="divide-y divide-line rounded-lg border border-line">
          {plan.map((row) => (
            <li
              key={row.id}
              className="flex flex-wrap items-center gap-2 px-3 py-2 text-[13px]"
            >
              <code className="text-xs text-fg-subtle">{row.id}</code>
              <span className="min-w-0 flex-1 truncate font-medium text-fg-strong">
                {row.name}
              </span>
              {row.exclusions.length > 0 && (
                <span className="text-[11px] text-fg-subtle">
                  {t('pages.policies.planExclusions', {
                    targets: row.exclusions.join(', '),
                  })}
                </span>
              )}
              <Badge tone="neutral">
                {t('pages.policies.planScore', { n: row.score })}
              </Badge>
              <Badge tone={tone[row.effective] ?? 'neutral'}>
                {t(`pages.policies.plan.${row.effective}`)}
              </Badge>
            </li>
          ))}
        </ul>
      </div>
    </Dialog>
  )
}

/* ── P6 layers: patches, schema, rate limits, IP access, bot ───────────── */

function VirtualPatchesForm({
  policyId,
  stored,
  hasStored,
  canWrite,
  onStored,
}: {
  policyId: string
  stored?: VirtualPatchesLayerConfig
  hasStored: boolean
  canWrite: boolean
  onStored: () => void
}) {
  const { t } = useTranslation()
  const save = useLayerMutation(policyId, 'virtual_patches', onStored)
  const remove = useMutation({
    mutationFn: () => policiesApi.deleteLayer(policyId, 'virtual_patches'),
    onSuccess: onStored,
  })
  const [source, setSource] = useState(stored?.source ?? '')

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1 overflow-y-auto px-5 py-4">
        <Textarea
          label={t('pages.policies.fields.virtualPatchSource')}
          hint={t('pages.policies.fields.virtualPatchHint')}
          mono
          rows={12}
          value={source}
          disabled={!canWrite}
          onChange={(e) => setSource(e.target.value)}
        />
      </div>
      <LayerFooter
        canWrite={canWrite}
        hasStored={hasStored}
        saving={save.isPending || remove.isPending}
        onSave={() => save.mutate({ source })}
        onRemove={() => remove.mutate()}
      />
    </div>
  )
}

function ApiSchemaForm({
  policyId,
  stored,
  hasStored,
  canWrite,
  onStored,
}: {
  policyId: string
  stored?: ApiSchemaLayerConfig
  hasStored: boolean
  canWrite: boolean
  onStored: () => void
}) {
  const { t } = useTranslation()
  const save = useLayerMutation(policyId, 'api_schema', onStored)
  const remove = useMutation({
    mutationFn: () => policiesApi.deleteLayer(policyId, 'api_schema'),
    onSuccess: onStored,
  })
  const [spec, setSpec] = useState(stored?.openapi_spec ?? '')

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1 overflow-y-auto px-5 py-4">
        <Textarea
          label={t('pages.policies.fields.apiSchemaSpec')}
          hint={t('pages.policies.fields.apiSchemaHint')}
          mono
          rows={12}
          value={spec}
          error={
            spec.trim() !== '' && !spec.trimStart().startsWith('{')
              ? t('pages.policies.fields.apiSchemaShape')
              : undefined
          }
          disabled={!canWrite}
          onChange={(e) => setSpec(e.target.value)}
        />
      </div>
      <LayerFooter
        canWrite={canWrite}
        hasStored={hasStored}
        saving={save.isPending || remove.isPending}
        onSave={() => save.mutate({ openapi_spec: spec })}
        onRemove={() => remove.mutate()}
      />
    </div>
  )
}

const BOT_ACTIONS = ['block', 'challenge', 'js_challenge', 'log', 'allow']

function BotLayerForm({
  policyId,
  stored,
  hasStored,
  canWrite,
  onStored,
}: {
  policyId: string
  stored?: BotLayerConfig
  hasStored: boolean
  canWrite: boolean
  onStored: () => void
}) {
  const { t } = useTranslation()
  const save = useLayerMutation(policyId, 'bot', onStored)
  const remove = useMutation({
    mutationFn: () => policiesApi.deleteLayer(policyId, 'bot'),
    onSuccess: onStored,
  })
  const tri = (value: boolean | undefined) =>
    value === undefined ? '' : String(value)
  const [enabled, setEnabled] = useState(tri(stored?.enabled))
  const [action, setAction] = useState(stored?.action ?? '')
  const [whitelist, setWhitelist] = useState<string[]>(
    stored?.known_bots_whitelist ?? [],
  )
  const [js, setJs] = useState(tri(stored?.js_detection))
  const [tls, setTls] = useState(tri(stored?.tls_fingerprint))
  const [behavioral, setBehavioral] = useState(
    tri(stored?.behavioral_analysis),
  )
  const [ipVerify, setIpVerify] = useState(
    tri(stored?.ip_verification_enabled),
  )
  const [dnsVerify, setDnsVerify] = useState(
    tri(stored?.dns_verification_enabled),
  )

  const config = (): BotLayerConfig => {
    const out: BotLayerConfig = {}
    if (enabled !== '') out.enabled = enabled === 'true'
    if (action) out.action = action
    if (whitelist.length > 0) out.known_bots_whitelist = whitelist
    if (js !== '') out.js_detection = js === 'true'
    if (tls !== '') out.tls_fingerprint = tls === 'true'
    if (behavioral !== '') out.behavioral_analysis = behavioral === 'true'
    if (ipVerify !== '') out.ip_verification_enabled = ipVerify === 'true'
    if (dnsVerify !== '') out.dns_verification_enabled = dnsVerify === 'true'
    return out
  }

  const booleanOptions = [
    { value: 'true', label: t('common.enabled') },
    { value: 'false', label: t('common.disabled') },
  ]

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="grid flex-1 gap-4 overflow-y-auto px-5 py-4 md:grid-cols-2">
        <TriSelect
          label={t('pages.policies.fields.botEnabled')}
          value={enabled}
          onChange={setEnabled}
          options={booleanOptions}
        />
        <TriSelect
          label={t('pages.policies.fields.botAction')}
          value={action}
          onChange={setAction}
          options={BOT_ACTIONS.map((value) => ({ value, label: value }))}
        />
        <div className="md:col-span-2">
          <TagInput
            label={t('pages.policies.fields.botWhitelist')}
            hint={t('pages.policies.fields.botWhitelistHint')}
            value={whitelist}
            onChange={setWhitelist}
            disabled={!canWrite}
          />
        </div>
        <TriSelect
          label={t('pages.policies.fields.botJs')}
          value={js}
          onChange={setJs}
          options={booleanOptions}
        />
        <TriSelect
          label={t('pages.policies.fields.botTls')}
          value={tls}
          onChange={setTls}
          options={booleanOptions}
        />
        <TriSelect
          label={t('pages.policies.fields.botBehavioral')}
          value={behavioral}
          onChange={setBehavioral}
          options={booleanOptions}
        />
        <TriSelect
          label={t('pages.policies.fields.botIpVerify')}
          value={ipVerify}
          onChange={setIpVerify}
          options={booleanOptions}
        />
        <TriSelect
          label={t('pages.policies.fields.botDnsVerify')}
          value={dnsVerify}
          onChange={setDnsVerify}
          options={booleanOptions}
        />
      </div>
      <LayerFooter
        canWrite={canWrite}
        hasStored={hasStored}
        saving={save.isPending || remove.isPending}
        onSave={() => save.mutate(config())}
        onRemove={() => remove.mutate()}
      />
    </div>
  )
}

type RateRow = {
  name: string
  expression: string
  characteristics: string[]
  period: string
  threshold: string
  action: string
  enabled: boolean
}

const RATE_LIMIT_ACTIONS = ['block', 'challenge', 'js_challenge', 'log']

function RateLimitForm({
  policyId,
  stored,
  hasStored,
  canWrite,
  onStored,
}: {
  policyId: string
  stored?: RateLimitLayerConfig
  hasStored: boolean
  canWrite: boolean
  onStored: () => void
}) {
  const { t } = useTranslation()
  const save = useLayerMutation(policyId, 'rate_limit', onStored)
  const remove = useMutation({
    mutationFn: () => policiesApi.deleteLayer(policyId, 'rate_limit'),
    onSuccess: onStored,
  })
  const [rules, setRules] = useState<RateRow[]>(() =>
    (stored?.rules ?? []).map((rule: RateLimitLayerRule) => ({
      name: rule.name,
      expression: rule.expression ?? '',
      characteristics: rule.characteristics ?? ['ip'],
      period: String(rule.period_seconds ?? 60),
      threshold: String(rule.threshold ?? 100),
      action: rule.action ?? 'block',
      enabled: rule.enabled !== false,
    })),
  )

  const patch = (index: number, next: Partial<RateRow>) => {
    setRules((current) =>
      current.map((row, i) => (i === index ? { ...row, ...next } : row)),
    )
  }

  const payload = () =>
    rules.map((row) => ({
      name: row.name,
      expression: row.expression,
      characteristics: row.characteristics,
      period_seconds: Math.max(1, Number(row.period) || 60),
      threshold: Math.max(1, Number(row.threshold) || 100),
      action: row.action,
      enabled: row.enabled,
    }))

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1 space-y-3 overflow-y-auto px-5 py-4">
        {rules.length === 0 && (
          <p className="text-[13px] text-fg-subtle">
            {t('pages.policies.fields.rlEmpty')}
          </p>
        )}
        {rules.map((row, index) => (
          <div
            key={index}
            className="space-y-3 rounded-lg border border-line p-3"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-[13px] font-medium text-fg-strong">
                {row.name.trim() || t('pages.policies.fields.untitledRule')}
              </span>
              <div className="flex items-center gap-2">
                <Switch
                  checked={row.enabled}
                  onCheckedChange={(checked) =>
                    patch(index, { enabled: checked })
                  }
                />
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={!canWrite}
                  icon={<Trash className="h-4 w-4" />}
                  onClick={() =>
                    setRules((current) =>
                      current.filter((_, i) => i !== index),
                    )
                  }
                />
              </div>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <Input
                label={t('pages.policies.fields.rlName')}
                value={row.name}
                maxLength={200}
                onChange={(e) => patch(index, { name: e.target.value })}
              />
              <Input
                label={t('pages.policies.fields.ruleExpression')}
                hint={t('pages.policies.fields.ruleExpressionHint')}
                value={row.expression}
                onChange={(e) => patch(index, { expression: e.target.value })}
              />
            </div>
            <TagInput
              label={t('pages.policies.fields.rlCharacteristics')}
              hint={t('pages.policies.fields.rlCharacteristicsHint')}
              value={row.characteristics}
              onChange={(characteristics) =>
                patch(index, { characteristics })
              }
              disabled={!canWrite}
            />
            <div className="grid gap-3 md:grid-cols-3">
              <Input
                label={t('pages.policies.fields.rlThreshold')}
                type="number"
                min={1}
                value={row.threshold}
                onChange={(e) => patch(index, { threshold: e.target.value })}
              />
              <Input
                label={t('pages.policies.fields.rlPeriod')}
                type="number"
                min={1}
                value={row.period}
                onChange={(e) => patch(index, { period: e.target.value })}
              />
              <Select
                label={t('pages.policies.fields.ruleAction')}
                value={row.action}
                onChange={(e) => patch(index, { action: e.target.value })}
                options={RATE_LIMIT_ACTIONS.map((value) => ({
                  value,
                  label: value,
                }))}
              />
            </div>
          </div>
        ))}
        {canWrite && (
          <Button
            size="sm"
            icon={<Plus weight="bold" className="h-4 w-4" />}
            onClick={() =>
              setRules((current) => [
                ...current,
                {
                  name: '',
                  expression: '',
                  characteristics: ['ip'],
                  period: '60',
                  threshold: '100',
                  action: 'block',
                  enabled: true,
                },
              ])
            }
          >
            {t('pages.policies.fields.addRule')}
          </Button>
        )}
      </div>
      <LayerFooter
        canWrite={canWrite}
        hasStored={hasStored}
        saving={save.isPending || remove.isPending}
        onSave={() => save.mutate({ rules: payload() })}
        onRemove={() => remove.mutate()}
      />
    </div>
  )
}

type IpRow = {
  name: string
  ranges: string[]
  action: string
  enabled: boolean
}

const IP_ACCESS_ACTIONS = [
  'block',
  'challenge',
  'js_challenge',
  'allow',
  'basic_auth',
]

function IpAccessForm({
  policyId,
  stored,
  hasStored,
  canWrite,
  onStored,
}: {
  policyId: string
  stored?: IpAccessLayerConfig
  hasStored: boolean
  canWrite: boolean
  onStored: () => void
}) {
  const { t } = useTranslation()
  const save = useLayerMutation(policyId, 'ip_access', onStored)
  const remove = useMutation({
    mutationFn: () => policiesApi.deleteLayer(policyId, 'ip_access'),
    onSuccess: onStored,
  })
  const [rules, setRules] = useState<IpRow[]>(() =>
    (stored?.rules ?? []).map((rule: IpAccessLayerRule) => ({
      name: rule.name,
      ranges: rule.ip_ranges ?? [],
      action: rule.action ?? 'block',
      enabled: rule.enabled !== false,
    })),
  )

  const patch = (index: number, next: Partial<IpRow>) => {
    setRules((current) =>
      current.map((row, i) => (i === index ? { ...row, ...next } : row)),
    )
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1 space-y-3 overflow-y-auto px-5 py-4">
        {rules.length === 0 && (
          <p className="text-[13px] text-fg-subtle">
            {t('pages.policies.fields.ipEmpty')}
          </p>
        )}
        {rules.map((row, index) => (
          <div
            key={index}
            className="space-y-3 rounded-lg border border-line p-3"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-[13px] font-medium text-fg-strong">
                {row.name.trim() || t('pages.policies.fields.untitledRule')}
              </span>
              <div className="flex items-center gap-2">
                <Switch
                  checked={row.enabled}
                  onCheckedChange={(checked) =>
                    patch(index, { enabled: checked })
                  }
                />
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={!canWrite}
                  icon={<Trash className="h-4 w-4" />}
                  onClick={() =>
                    setRules((current) =>
                      current.filter((_, i) => i !== index),
                    )
                  }
                />
              </div>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <Input
                label={t('pages.policies.fields.ipName')}
                value={row.name}
                maxLength={200}
                onChange={(e) => patch(index, { name: e.target.value })}
              />
              <Select
                label={t('pages.policies.fields.ipAction')}
                value={row.action}
                onChange={(e) => patch(index, { action: e.target.value })}
                options={IP_ACCESS_ACTIONS.map((value) => ({
                  value,
                  label: value,
                }))}
              />
            </div>
            <TagInput
              label={t('pages.policies.fields.ipRanges')}
              hint={t('pages.policies.fields.ipRangesHint')}
              value={row.ranges}
              onChange={(ranges) => patch(index, { ranges })}
              disabled={!canWrite}
            />
          </div>
        ))}
        {canWrite && (
          <Button
            size="sm"
            icon={<Plus weight="bold" className="h-4 w-4" />}
            onClick={() =>
              setRules((current) => [
                ...current,
                { name: '', ranges: [], action: 'block', enabled: true },
              ])
            }
          >
            {t('pages.policies.fields.addRule')}
          </Button>
        )}
      </div>
      <LayerFooter
        canWrite={canWrite}
        hasStored={hasStored}
        saving={save.isPending || remove.isPending}
        onSave={() =>
          save.mutate({
            rules: rules.map((row) => ({
              name: row.name,
              ip_ranges: row.ranges,
              action: row.action,
              enabled: row.enabled,
            })),
          })
        }
        onRemove={() => remove.mutate()}
      />
    </div>
  )
}

const RULE_ACTIONS = ['block', 'log', 'challenge', 'js_challenge', 'allow']
const RULE_MODES = ['block', 'monitor', 'off']

function emptyRule(): PolicyRule {
  return {
    name: '',
    description: '',
    expression: '',
    action: 'block',
    severity: 3,
    tags: [],
    enabled: true,
    mode: 'block',
    priority: 0,
  }
}

function CustomRulesForm({
  policyId,
  stored,
  hasStored,
  canWrite,
  onStored,
}: {
  policyId: string
  stored?: CustomRulesLayerConfig
  hasStored: boolean
  canWrite: boolean
  onStored: () => void
}) {
  const { t } = useTranslation()
  const save = useLayerMutation(policyId, 'custom_rules', onStored)
  const remove = useMutation({
    mutationFn: () => policiesApi.deleteLayer(policyId, 'custom_rules'),
    onSuccess: onStored,
  })
  const [rules, setRules] = useState<PolicyRule[]>(stored?.rules ?? [])
  const [recipeOpen, setRecipeOpen] = useState(false)

  const patch = (index: number, next: Partial<PolicyRule>) => {
    setRules((current) =>
      current.map((rule, i) => (i === index ? { ...rule, ...next } : rule)),
    )
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1 space-y-3 overflow-y-auto px-5 py-4">
        {rules.length === 0 && (
          <p className="text-[13px] text-fg-subtle">
            {t('pages.policies.fields.noRules')}
          </p>
        )}
        {rules.map((rule, index) => (
          <div
            key={index}
            className="space-y-3 rounded-lg border border-line p-3"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-[13px] font-medium text-fg-strong">
                {rule.name.trim() || t('pages.policies.fields.untitledRule')}
              </span>
              <div className="flex items-center gap-2">
                <Switch
                  checked={rule.enabled !== false}
                  onCheckedChange={(checked) =>
                    patch(index, { enabled: checked })
                  }
                />
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={!canWrite}
                  icon={<Trash className="h-4 w-4" />}
                  onClick={() =>
                    setRules((current) =>
                      current.filter((_, i) => i !== index),
                    )
                  }
                />
              </div>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <Input
                label={t('pages.policies.fields.ruleName')}
                value={rule.name}
                maxLength={120}
                onChange={(e) => patch(index, { name: e.target.value })}
              />
              <Input
                label={t('pages.policies.fields.rulePriority')}
                type="number"
                value={String(rule.priority ?? 0)}
                onChange={(e) =>
                  patch(index, { priority: Number(e.target.value) || 0 })
                }
              />
            </div>
            <Input
              label={t('pages.policies.fields.ruleExpression')}
              hint={t('pages.policies.fields.ruleExpressionHint')}
              value={rule.expression}
              onChange={(e) => patch(index, { expression: e.target.value })}
            />
            <div className="grid gap-3 md:grid-cols-3">
              <Select
                label={t('pages.policies.fields.ruleAction')}
                value={rule.action}
                onChange={(e) => patch(index, { action: e.target.value })}
                options={RULE_ACTIONS.map((action) => ({
                  value: action,
                  label: action,
                }))}
              />
              <Select
                label={t('pages.policies.fields.ruleMode')}
                value={rule.mode ?? 'block'}
                onChange={(e) => patch(index, { mode: e.target.value })}
                options={RULE_MODES.map((mode) => ({
                  value: mode,
                  label: mode,
                }))}
              />
              <Select
                label={t('pages.policies.fields.ruleSeverity')}
                value={String(rule.severity ?? 3)}
                onChange={(e) =>
                  patch(index, { severity: Number(e.target.value) })
                }
                options={['1', '2', '3', '4', '5'].map((severity) => ({
                  value: severity,
                  label: severity,
                }))}
              />
            </div>
            <TagInput
              label={t('pages.policies.fields.ruleTags')}
              value={rule.tags ?? []}
              onChange={(tags) => patch(index, { tags })}
              disabled={!canWrite}
            />
          </div>
        ))}
        {canWrite && (
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              icon={<Plus weight="bold" className="h-4 w-4" />}
              onClick={() => setRules((current) => [...current, emptyRule()])}
            >
              {t('pages.policies.fields.addRule')}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setRecipeOpen(true)}>
              {t('pages.policies.fromRecipe')}
            </Button>
          </div>
        )}
      </div>
      <LayerFooter
        canWrite={canWrite}
        hasStored={hasStored}
        saving={save.isPending || remove.isPending}
        onSave={() => save.mutate({ rules })}
        onRemove={() => remove.mutate()}
      />
      {recipeOpen && (
        <RecipeDialog
          policyId={policyId}
          onClose={() => setRecipeOpen(false)}
          onApplied={(rule) => {
            // The server already stored the layer; merge into the local
            // draft so the editor reflects it immediately.
            setRules((current) => [
              ...current.filter((existing) => existing.name !== rule.name),
              rule,
            ])
            setRecipeOpen(false)
          }}
        />
      )}
    </div>
  )
}

/** Recipe gallery: pick a recipe, fill its parameters, apply it. */
export function RecipeDialog({
  policyId,
  onClose,
  onApplied,
}: {
  policyId: string
  onClose: () => void
  onApplied: (rule: PolicyRule) => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const recipes = useQuery({
    queryKey: policyKeys.recipes(),
    queryFn: () => policiesApi.recipes(),
  })
  const [recipeId, setRecipeId] = useState('')
  const [params, setParams] = useState<Record<string, string>>({})
  const recipe = (recipes.data ?? []).find((entry) => entry.id === recipeId)

  const apply = useMutation({
    mutationFn: () =>
      policiesApi.applyRecipe(policyId, { recipe_id: recipeId, params }),
    onSuccess: (result) => {
      toast.success(t('pages.policies.recipeApplied'), result.rule.name)
      onApplied(result.rule)
    },
    onError: (error) =>
      toast.error(t('pages.policies.recipeFailed'), String(error)),
  })

  return (
    <Dialog
      open
      onClose={onClose}
      size="md"
      title={t('pages.policies.fromRecipe')}
      description={t('pages.policies.recipeHint')}
    >
      <div className="space-y-3 px-5 py-4">
        <Select
          label={t('pages.policies.recipe')}
          value={recipeId}
          onChange={(e) => {
            setRecipeId(e.target.value)
            setParams({})
          }}
          options={[
            { value: '', label: t('pages.policies.recipePick') },
            ...(recipes.data ?? []).map((entry) => ({
              value: entry.id,
              label: entry.name,
            })),
          ]}
        />
        {recipe && (
          <p className="text-[13px] text-fg-subtle">{recipe.description}</p>
        )}
        {recipe?.params.map((param) => (
          <Input
            key={param.name}
            label={param.label}
            placeholder={param.placeholder}
            value={params[param.name] ?? ''}
            onChange={(e) =>
              setParams((current) => ({
                ...current,
                [param.name]: e.target.value,
              }))
            }
          />
        ))}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={apply.isPending}
            disabled={!recipeId}
            onClick={() => apply.mutate()}
          >
            {t('pages.policies.recipeApply')}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}

function CrsImportForm({
  policyId,
  stored,
  hasStored,
  canWrite,
  onStored,
}: {
  policyId: string
  stored?: CrsImportLayerConfig
  hasStored: boolean
  canWrite: boolean
  onStored: () => void
}) {
  const { t } = useTranslation()
  const save = useLayerMutation(policyId, 'crs_import', onStored)
  const remove = useMutation({
    mutationFn: () => policiesApi.deleteLayer(policyId, 'crs_import'),
    onSuccess: onStored,
  })
  const rulesets = useQuery({
    queryKey: crsKeys.list(),
    queryFn: () => crsApi.rulesets(),
  })
  const [rulesetId, setRulesetId] = useState(stored?.ruleset_id ?? '')
  const [paranoia, setParanoia] = useState(
    stored?.paranoia_level_max ? String(stored.paranoia_level_max) : '',
  )
  const [categories, setCategories] = useState<string[]>(
    stored?.categories ?? [],
  )
  const selected = (rulesets.data ?? []).find(
    (ruleset) => ruleset.id === rulesetId,
  )

  const config = (): CrsImportLayerConfig => {
    const out: CrsImportLayerConfig = { ruleset_id: rulesetId }
    if (paranoia) out.paranoia_level_max = Number(paranoia)
    if (categories.length > 0) out.categories = categories
    return out
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="grid flex-1 gap-4 overflow-y-auto px-5 py-4 md:grid-cols-2">
        <div className="space-y-2 md:col-span-2">
          <Select
            label={t('pages.policies.fields.crsImportRuleset')}
            hint={t('pages.policies.fields.crsImportRulesetHint')}
            value={rulesetId}
            disabled={!canWrite}
            onChange={(e) => setRulesetId(e.target.value)}
            options={[
              { value: '', label: t('pages.crs.pickRuleset') },
              ...(rulesets.data ?? []).map((ruleset) => ({
                value: ruleset.id,
                label: `${ruleset.name}${
                  ruleset.version ? ` ${ruleset.version}` : ''
                } (${ruleset.supported_count})`,
              })),
            ]}
          />
          {rulesets.data && rulesets.data.length === 0 && (
            <p className="text-[13px] text-fg-subtle">
              {t('pages.policies.fields.crsImportEmpty')}
            </p>
          )}
          {selected && (
            <p className="text-[12px] text-fg-subtle">
              {t('pages.policies.fields.crsImportCounts', {
                supported: selected.supported_count,
                unsupported: selected.unsupported_count,
                directives: selected.directive_count,
              })}
            </p>
          )}
        </div>
        <TriSelect
          label={t('pages.policies.fields.crsImportParanoia')}
          hint={t('pages.policies.fields.crsImportParanoiaHint')}
          value={paranoia}
          onChange={setParanoia}
          options={['1', '2', '3', '4'].map((value) => ({
            value,
            label: t('pages.policies.fields.paranoiaLevel', { n: value }),
          }))}
        />
        <div className="md:col-span-2">
          <TagInput
            label={t('pages.policies.fields.crsImportCategories')}
            hint={t('pages.policies.fields.crsImportCategoriesHint')}
            value={categories}
            onChange={setCategories}
            disabled={!canWrite}
          />
        </div>
      </div>
      <LayerFooter
        canWrite={canWrite}
        hasStored={hasStored}
        saving={save.isPending}
        onSave={() => {
          if (rulesetId) save.mutate(config())
        }}
        onRemove={() => remove.mutate()}
      />
    </div>
  )
}

export default PoliciesPage
