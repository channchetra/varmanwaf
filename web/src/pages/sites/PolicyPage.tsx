import { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FloppyDisk, Stack, Trash } from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Select } from '@/components/ui/Select'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { Textarea } from '@/components/ui/Textarea'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { useCanWrite } from '@/hooks'
import {
  policiesApi,
  policyKeys,
  type EffectiveConfig,
  type SitePolicyView,
} from '@/api/policies'

/** Starter overlays for the quick-add buttons in the overlay editor. */
const OVERRIDE_SNIPPETS: Array<{
  kind: string
  snippet: Record<string, unknown>
}> = [
  { kind: 'engine', snippet: { mode: 'monitor' } },
  { kind: 'crs', snippet: { monitor_managed_rules: [] } },
  { kind: 'custom_rules', snippet: { rules: [] } },
  { kind: 'rule_overrides', snippet: { overrides: [] } },
  { kind: 'virtual_patches', snippet: { source: '' } },
  { kind: 'api_schema', snippet: { openapi_spec: '' } },
  { kind: 'rate_limit', snippet: { rules: [] } },
  { kind: 'ip_access', snippet: { rules: [] } },
  { kind: 'bot', snippet: { action: 'challenge' } },
]

/**
 * The site's policy tab: which shared policy the site follows, the sparse
 * per-site overlay on top of it, and the effective configuration the next
 * bundle will carry (resolved exactly like the control plane resolves it).
 */
export function PolicyPage() {  const { t } = useTranslation()
  const { siteId = '' } = useParams<{ siteId: string }>()
  const canWrite = useCanWrite()
  const toast = useToast()
  const queryClient = useQueryClient()

  const assignment = useQuery({
    queryKey: policyKeys.sitePolicy(siteId),
    queryFn: () => policiesApi.getSitePolicy(siteId),
    enabled: Boolean(siteId),
  })
  const policies = useQuery({
    queryKey: policyKeys.list(),
    queryFn: () => policiesApi.list(),
  })
  const effective = useQuery({
    queryKey: policyKeys.siteEffective(siteId),
    queryFn: () => policiesApi.effectiveConfig(siteId),
    enabled: Boolean(siteId),
  })
  const override = useQuery({
    queryKey: policyKeys.siteOverride(siteId),
    queryFn: () => policiesApi.getSiteOverride(siteId),
    enabled: Boolean(siteId),
  })
  const apply = useQuery({
    queryKey: policyKeys.applyStatus(siteId),
    queryFn: () => policiesApi.applyStatus(siteId),
    enabled: Boolean(siteId),
  })

  const assign = useMutation({
    mutationFn: (policyId: string | null) =>
      policiesApi.setSitePolicy(siteId, policyId),
    onSuccess: (_view: SitePolicyView, policyId) => {
      toast.success(
        policyId ? t('pages.sitePolicy.assigned') : t('pages.sitePolicy.cleared'),
      )
      invalidatePolicyQueries()
    },
    onError: (error) => toast.error(t('pages.sitePolicy.assignFailed'), String(error)),
  })

  const saveOverride = useMutation({
    mutationFn: (config: Record<string, unknown>) =>
      policiesApi.putSiteOverride(siteId, config),
    onSuccess: () => {
      toast.success(t('pages.sitePolicy.overrideSaved'))
      invalidatePolicyQueries()
    },
    onError: (error) =>
      toast.error(t('pages.sitePolicy.overrideFailed'), String(error)),
  })

  const clearOverride = useMutation({
    mutationFn: () => policiesApi.deleteSiteOverride(siteId),
    onSuccess: () => {
      toast.success(t('pages.sitePolicy.overrideCleared'))
      invalidatePolicyQueries()
    },
  })

  function invalidatePolicyQueries() {
    void queryClient.invalidateQueries({ queryKey: policyKeys.sitePolicy(siteId) })
    void queryClient.invalidateQueries({ queryKey: policyKeys.siteOverride(siteId) })
    void queryClient.invalidateQueries({ queryKey: policyKeys.siteEffective(siteId) })
  }

  // Raw JSON draft of the overlay; `null` means "show the saved value".
  const [draft, setDraft] = useState<string | null>(null)
  const savedJson = useMemo(
    () => JSON.stringify(override.data?.config ?? {}, null, 2),
    [override.data],
  )
  useEffect(() => setDraft(null), [savedJson])
  const shownJson = draft ?? savedJson
  const draftError = useMemo(() => {
    if (draft === null) return null
    try {
      const parsed = JSON.parse(draft)
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return t('pages.sitePolicy.overrideShape')
      }
      return null
    } catch {
      return t('pages.sitePolicy.overrideJson')
    }
  }, [draft, t])

  // Quick-add buttons: merge a starter snippet for one layer kind into the
  // draft so operators do not have to memorise the shape.
  const insertSnippet = (kind: string, snippet: Record<string, unknown>) => {
    let base: Record<string, unknown> = {}
    try {
      const parsed = JSON.parse(shownJson)
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        base = parsed as Record<string, unknown>
      }
    } catch {
      base = {}
    }
    base[kind] = snippet
    setDraft(JSON.stringify(base, null, 2))
  }

  if (assignment.isError && !assignment.data) {
    return (
      <div className="animate-slide-up">
        <ErrorState
          error={assignment.error}
          onRetry={() => assignment.refetch()}
          retrying={assignment.isFetching}
        />
      </div>
    )
  }

  if (assignment.isLoading) {
    return (
      <div className="animate-slide-up space-y-4">
        <SkeletonCard />
        <SkeletonCard />
      </div>
    )
  }

  const current = assignment.data
  const effectiveData: EffectiveConfig | undefined = effective.data

  return (
    <div className="animate-slide-up space-y-4">
      {/* Assignment */}
      <Card>
        <CardHeader
          title={t('pages.sitePolicy.assignmentTitle')}
          description={t('pages.sitePolicy.assignmentHint')}
          action={<Stack weight="duotone" className="h-5 w-5 text-fg-subtle" />}
        />
        <CardBody className="space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="min-w-0 flex-1">
              <Select
                label={t('pages.sitePolicy.policy')}
                value={current?.policy?.id ?? ''}
                disabled={!canWrite || assign.isPending}
                onChange={(e) => assign.mutate(e.target.value || null)}
                options={[
                  { value: '', label: t('pages.sitePolicy.none') },
                  ...(policies.data ?? [])
                    .filter((policy) => policy.enabled || policy.id === current?.policy?.id)
                    .map((policy) => ({
                      value: policy.id,
                      label: policy.enabled
                        ? policy.name
                        : `${policy.name} (${t('pages.policies.stateDisabled')})`,
                      disabled: !policy.enabled,
                    })),
                ]}
              />
            </div>
            {current?.policy && (
              <div className="flex items-center gap-2 pb-1">
                <Badge tone="brand">
                  {t('pages.policies.revision', { n: current.policy.revision })}
                </Badge>
                {current.overridden && (
                  <Badge tone="warning">
                    {t('pages.sitePolicy.overridden')}
                  </Badge>
                )}
              </div>
            )}
          </div>
          {current?.policy === null && (
            <p className="text-[13px] text-fg-subtle">
              {t('pages.sitePolicy.noneHint')}
            </p>
          )}
        </CardBody>
      </Card>

      {/* Overlay */}
      {current?.policy && (
        <Card>
          <CardHeader
            title={t('pages.sitePolicy.overrideTitle')}
            description={t('pages.sitePolicy.overrideHint')}
            action={
              current.overridden && (
                <Badge tone="warning">
                  {t('pages.sitePolicy.overridden')}
                </Badge>
              )
            }
          />
          <CardBody className="space-y-3">
            {canWrite && (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-xs text-fg-subtle">
                  {t('pages.sitePolicy.overrideAdd')}
                </span>
                {OVERRIDE_SNIPPETS.map(({ kind, snippet }) => (
                  <Button
                    key={kind}
                    size="sm"
                    variant="ghost"
                    onClick={() => insertSnippet(kind, snippet)}
                  >
                    {t(`pages.policies.layers.${kind}`)}
                  </Button>
                ))}
              </div>
            )}
            <Textarea
              label={t('pages.sitePolicy.overrideLabel')}
              hint={t('pages.sitePolicy.overrideFormat')}
              mono
              rows={8}
              value={shownJson}
              error={draftError ?? undefined}
              disabled={!canWrite}
              onChange={(e) => setDraft(e.target.value)}
            />
            {canWrite && (
              <div className="flex justify-end gap-2">
                <Button
                  variant="ghost"
                  icon={<Trash className="h-4 w-4" />}
                  disabled={!current.overridden || clearOverride.isPending}
                  onClick={() => clearOverride.mutate()}
                >
                  {t('pages.sitePolicy.clearOverride')}
                </Button>
                <Button
                  variant="primary"
                  icon={<FloppyDisk className="h-4 w-4" />}
                  loading={saveOverride.isPending}
                  disabled={draft === null || draftError !== null}
                  onClick={() =>
                    draftError === null &&
                    saveOverride.mutate(JSON.parse(shownJson))
                  }
                >
                  {t('common.save')}
                </Button>
              </div>
            )}
          </CardBody>
        </Card>
      )}

      {/* Effective configuration */}
      <Card>
        <CardHeader
          title={t('pages.sitePolicy.effectiveTitle')}
          description={t('pages.sitePolicy.effectiveHint')}
          action={
            effectiveData && (
              <Badge tone={effectiveData.source === 'policy' ? 'brand' : 'neutral'}>
                {effectiveData.source === 'policy'
                  ? t('pages.sitePolicy.sourcePolicy', {
                      name: effectiveData.policy?.name ?? '',
                    })
                  : t('pages.sitePolicy.sourceSite')}
              </Badge>
            )
          }
        />
        <CardBody className="space-y-4">
          {effective.isLoading ? (
            <SkeletonCard />
          ) : effectiveData ? (
            <>
              <dl className="grid gap-3 text-[13px] sm:grid-cols-2 lg:grid-cols-3">
                <EffectiveRow
                  label={t('pages.policies.fields.wafEnabled')}
                  value={
                    effectiveData.effective.waf_enabled
                      ? t('common.enabled')
                      : t('common.disabled')
                  }
                />
                <EffectiveRow
                  label={t('pages.policies.fields.mode')}
                  value={
                    effectiveData.effective.mode ??
                    t('pages.sitePolicy.modeDerived')
                  }
                />
                <EffectiveRow
                  label={t('pages.policies.fields.paranoia')}
                  value={String(effectiveData.effective.paranoia_level)}
                />
                <EffectiveRow
                  label={t('pages.policies.fields.advanced')}
                  value={
                    effectiveData.effective.advanced_mode
                      ? t('common.enabled')
                      : t('common.disabled')
                  }
                />
                <EffectiveRow
                  label={t('pages.policies.fields.engineMode')}
                  value={effectiveData.effective.engine_mode}
                />
                <EffectiveRow
                  label={t('pages.policies.fields.monitorCategories')}
                  value={
                    effectiveData.effective.monitor_categories.join(', ') || '—'
                  }
                />
                <EffectiveRow
                  label={t('pages.policies.fields.monitorStacks')}
                  value={effectiveData.effective.monitor_stacks.join(', ') || '—'}
                />
                <EffectiveRow
                  label={t('pages.policies.fields.monitorManagedRules')}
                  value={
                    effectiveData.effective.monitor_managed_rules.join(', ') ||
                    '—'
                  }
                />
                <EffectiveRow
                  label={t('pages.sitePolicy.disabledRules')}
                  value={
                    effectiveData.effective.disabled_rules.join(', ') || '—'
                  }
                />
                <EffectiveRow
                  label={t('pages.sitePolicy.ruleScores')}
                  value={
                    Object.entries(effectiveData.effective.rule_scores)
                      .map(([id, score]) => `${id}=${score}`)
                      .join(', ') || '—'
                  }
                />
              </dl>

              <div>
                <p className="mb-2 text-[13px] font-medium text-fg-strong">
                  {t('pages.sitePolicy.rulesTitle', {
                    n: effectiveData.rules.length,
                  })}
                </p>
                {effectiveData.rules.length === 0 ? (
                  <p className="text-[13px] text-fg-subtle">
                    {t('pages.sitePolicy.noRules')}
                  </p>
                ) : (
                  <ul className="space-y-1.5">
                    {effectiveData.rules.map((rule, index) => (
                      <li
                        key={`${rule.name}-${index}`}
                        className="flex flex-wrap items-center gap-2 rounded-md border border-line px-3 py-2 text-[13px]"
                      >
                        <span className="font-medium text-fg-strong">
                          {rule.name}
                        </span>
                        <Badge tone="neutral">{rule.action}</Badge>
                        <Badge tone="neutral">{rule.mode ?? 'block'}</Badge>
                        {rule.enabled === false && (
                          <Badge tone="warning">
                            {t('common.disabled')}
                          </Badge>
                        )}
                        <code className="ml-auto max-w-full truncate text-xs text-fg-subtle">
                          {rule.expression}
                        </code>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {Object.entries(effectiveData.layers ?? {}).length > 0 && (
                <div>
                  <p className="mb-2 text-[13px] font-medium text-fg-strong">
                    {t('pages.sitePolicy.layersTitle')}
                  </p>
                  <ul className="space-y-1.5">
                    {Object.entries(effectiveData.layers).map(
                      ([kind, config]) => (
                        <li
                          key={kind}
                          className="flex flex-wrap items-center gap-2 rounded-md border border-line px-3 py-2 text-[13px]"
                        >
                          <Badge tone="info">
                            {t(`pages.policies.layers.${kind}`)}
                          </Badge>
                          <code className="ml-auto max-w-full truncate text-xs text-fg-subtle">
                            {JSON.stringify(config).slice(0, 120)}
                          </code>
                        </li>
                      ),
                    )}
                  </ul>
                </div>
              )}
            </>
          ) : (
            <p className="text-[13px] text-fg-subtle">
              {t('pages.sitePolicy.effectiveUnavailable')}
            </p>
          )}
        </CardBody>
      </Card>

      {/* Compiled rule plan */}
      {effectiveData && (
        <Card>
          <CardHeader
            title={t('pages.sitePolicy.planTitle')}
            description={t('pages.sitePolicy.planHint')}
          />
          <CardBody>
            <ul className="divide-y divide-line rounded-lg border border-line">
              {effectiveData.plan.map((row) => (
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
                  <Badge tone={PLAN_TONE[row.effective] ?? 'neutral'}>
                    {t(`pages.policies.plan.${row.effective}`)}
                  </Badge>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      )}

      {/* Apply status: published vs applied, per node. */}
      <Card>
        <CardHeader
          title={t('pages.sitePolicy.applyTitle')}
          description={t('pages.sitePolicy.applyHint')}
        />
        <CardBody className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-[13px]">
            <Badge tone="neutral">
              {t('pages.sitePolicy.publishedRevision', {
                n: apply.data?.published.policy_revision ?? 0,
              })}
            </Badge>
            <code className="text-xs text-fg-subtle">
              {apply.data?.published.config_hash.slice(0, 12) || '—'}
            </code>
            {apply.data?.published.version_id != null && (
              <Badge tone="info">v{apply.data.published.version_id}</Badge>
            )}
          </div>
          <ul className="divide-y divide-line rounded-lg border border-line">
            {(apply.data?.agents ?? []).map((row) => (
              <li
                key={row.id}
                className="flex flex-wrap items-center gap-2 px-3 py-2 text-[13px]"
              >
                <span className="min-w-0 flex-1 truncate font-medium text-fg-strong">
                  {row.hostname}
                </span>
                <span className="text-[11px] text-fg-subtle">
                  {t('pages.sitePolicy.appliedRevision', {
                    n: row.applied_policy_revision ?? 0,
                  })}
                </span>
                <Badge tone={APPLY_TONE[row.state] ?? 'neutral'}>
                  {t(`pages.sitePolicy.apply.${row.state}`)}
                </Badge>
              </li>
            ))}
          </ul>
        </CardBody>
      </Card>
    </div>
  )
}

const APPLY_TONE: Record<string, 'success' | 'warning' | 'neutral'> = {
  applied: 'success',
  pending: 'warning',
  unknown: 'neutral',
}

const PLAN_TONE: Record<string, 'success' | 'warning' | 'neutral'> = {
  enforce: 'success',
  monitor: 'warning',
  disabled: 'neutral',
}

function EffectiveRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-line bg-recessed px-3 py-2">
      <dt className="text-xs text-fg-subtle">{label}</dt>
      <dd className="mt-0.5 truncate font-medium text-fg-strong">{value}</dd>
    </div>
  )
}

export default PolicyPage
