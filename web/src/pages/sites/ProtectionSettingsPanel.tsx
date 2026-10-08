import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Gauge, Lightning, ShieldWarning, Wrench } from '@phosphor-icons/react'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Textarea } from '@/components/ui/Textarea'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { wafSettingsApi, wafSettingsKeys } from '@/api/wafSettings'
import { useCanWrite } from '@/hooks'
import { cn } from '@/lib/utils'
import {
  WAF_CATEGORIES,
  WAF_ENGINE_MODES,
  WAF_STACKS,
  type UpdateWafSettingsRequest,
  type WafSettings,
} from '@/api/types'

/**
 * The site-level WAF grading knobs: the one-switch advanced mode (strict rule
 * set + request-body inspection) and the per-category / per-stack monitor
 * downgrades, applied instantly on toggle.
 */
export function ProtectionSettingsPanel() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  // Custom-layer drafts: `null` means "show the saved value" (unedited).
  const [patchesDraft, setPatchesDraft] = useState<string | null>(null)
  const [openapiDraft, setOpenapiDraft] = useState<string | null>(null)

  const settingsQuery = useQuery({
    queryKey: wafSettingsKeys.settings(siteId),
    queryFn: () => wafSettingsApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const settings = settingsQuery.data

  const update = useMutation({
    mutationFn: (payload: UpdateWafSettingsRequest) =>
      wafSettingsApi.update(siteId, payload),
    onMutate: async (payload) => {
      await queryClient.cancelQueries({
        queryKey: wafSettingsKeys.settings(siteId),
      })
      const previous = queryClient.getQueryData<WafSettings>(
        wafSettingsKeys.settings(siteId),
      )
      queryClient.setQueryData<WafSettings>(
        wafSettingsKeys.settings(siteId),
        (prev) =>
          prev
            ? {
                ...prev,
                ...(payload.advanced_mode !== undefined && {
                  advanced_mode: payload.advanced_mode,
                }),
                ...(payload.engine_mode !== undefined && {
                  engine_mode: payload.engine_mode,
                }),
                ...(payload.virtual_patches !== undefined && {
                  virtual_patches: payload.virtual_patches,
                }),
                ...(payload.openapi_spec !== undefined && {
                  openapi_spec: payload.openapi_spec,
                }),
                ...(payload.monitor_categories !== undefined && {
                  monitor_categories: payload.monitor_categories,
                }),
                ...(payload.monitor_stacks !== undefined && {
                  monitor_stacks: payload.monitor_stacks,
                }),
              }
            : prev,
      )
      return { previous }
    },
    onError: (error, _payload, context) => {
      if (context?.previous) {
        queryClient.setQueryData(
          wafSettingsKeys.settings(siteId),
          context.previous,
        )
      }
      toast.error(
        t('pages.protection.updateFailed'),
        error instanceof Error ? error.message : undefined,
      )
    },
    onSuccess: (saved) => {
      queryClient.setQueryData(wafSettingsKeys.settings(siteId), saved)
      toast.success(t('pages.protection.saved'))
    },
    onSettled: () => {
      void queryClient.invalidateQueries({
        queryKey: wafSettingsKeys.all(siteId),
      })
    },
  })

  if (settingsQuery.isPending) {
    return <SkeletonCard className="h-64" />
  }
  if (settingsQuery.isError && !settings) {
    return (
      <ErrorState
        error={settingsQuery.error}
        onRetry={() => settingsQuery.refetch()}
        retrying={settingsQuery.isFetching}
      />
    )
  }
  if (!settings) return null

  const busy = update.isPending
  const categoriesOn = (settings.monitor_categories ?? []) as string[]
  const stacksOn = (settings.monitor_stacks ?? []) as string[]
  const patchesValue = patchesDraft ?? settings.virtual_patches ?? ''
  const openapiValue = openapiDraft ?? settings.openapi_spec ?? ''

  const toggleCategory = (category: string, on: boolean) => {
    update.mutate({
      monitor_categories: on
        ? [...categoriesOn, category]
        : categoriesOn.filter((c) => c !== category),
    })
  }
  const toggleStack = (stack: string, on: boolean) => {
    update.mutate({
      monitor_stacks: on
        ? [...stacksOn, stack]
        : stacksOn.filter((s) => s !== stack),
    })
  }

  return (
    <div className="flex flex-col gap-4">
      {/* ── Advanced mode ─────────────────────────────────────────────── */}
      <Card
        className={cn(
          settings.advanced_mode && 'border-danger/35',
        )}
      >
        <CardBody className="flex items-start justify-between gap-4">
          <span className="flex min-w-0 gap-3">
            <span
              className={cn(
                'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
                settings.advanced_mode
                  ? 'bg-danger/15 text-fg-danger'
                  : 'bg-recessed text-fg-subtle',
              )}
            >
              <Lightning weight="duotone" className="h-5 w-5" />
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-semibold text-fg-strong">
                {t('pages.protection.advancedMode')}
              </span>
              <span className="mt-0.5 block text-[13px] text-fg-subtle">
                {t('pages.protection.advancedModeHint')}
              </span>
              <span className="mt-1.5 flex items-center gap-1.5 text-xs text-fg-warning">
                <Gauge weight="duotone" className="h-3.5 w-3.5 shrink-0" />
                {t('pages.protection.performanceHint')}
              </span>
            </span>
          </span>
          <Switch
            size="md"
            checked={settings.advanced_mode}
            disabled={!canWrite || busy}
            aria-label={t('pages.protection.advancedMode')}
            onCheckedChange={(advanced_mode) =>
              update.mutate({ advanced_mode })
            }
          />
        </CardBody>
      </Card>

      {/* ── Detection engine ──────────────────────────────────────────── */}
      <Card>
        <CardHeader
          title={t('pages.protection.engineTitle')}
          description={t('pages.protection.engineHint')}
        />
        <CardBody>
          <Select
            className="max-w-md"
            value={(settings.engine_mode ?? 'inherit') as string}
            disabled={!canWrite || busy}
            aria-label={t('pages.protection.engineTitle')}
            options={WAF_ENGINE_MODES.map((mode) => ({
              value: mode,
              label: t(`pages.protection.engine_${mode}`),
            }))}
            onChange={(event) =>
              update.mutate({ engine_mode: event.target.value })
            }
          />
        </CardBody>
      </Card>

      {/* ── Custom layers: SecLang virtual patches + OpenAPI ─────────── */}
      <Card>
        <CardHeader
          title={t('pages.protection.customLayersTitle')}
          description={t('pages.protection.customLayersHint')}
        />
        <CardBody className="flex flex-col gap-6">
          <section className="flex flex-col gap-2">
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
              <Wrench weight="duotone" className="h-3.5 w-3.5" />
              {t('pages.protection.virtualPatches')}
            </h3>
            <Textarea
              mono
              rows={5}
              value={patchesValue}
              disabled={!canWrite || busy}
              placeholder={t('pages.protection.virtualPatchesPlaceholder')}
              onChange={(event) => setPatchesDraft(event.target.value)}
              aria-label={t('pages.protection.virtualPatches')}
            />
            <div className="flex items-start justify-between gap-3">
              <span className="text-[11px] text-fg-subtle">
                {t('pages.protection.virtualPatchesHint')}
              </span>
              <Button
                size="sm"
                variant="primary"
                disabled={!canWrite || busy || patchesDraft === null}
                onClick={() =>
                  update.mutate(
                    { virtual_patches: patchesValue },
                    { onSuccess: () => setPatchesDraft(null) },
                  )
                }
              >
                {t('common.save')}
              </Button>
            </div>
          </section>

          <section className="flex flex-col gap-2">
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
              <Wrench weight="duotone" className="h-3.5 w-3.5" />
              {t('pages.protection.openapiSpec')}
            </h3>
            <Textarea
              mono
              rows={5}
              value={openapiValue}
              disabled={!canWrite || busy}
              placeholder={t('pages.protection.openapiSpecPlaceholder')}
              onChange={(event) => setOpenapiDraft(event.target.value)}
              aria-label={t('pages.protection.openapiSpec')}
            />
            <div className="flex items-start justify-between gap-3">
              <span className="text-[11px] text-fg-subtle">
                {t('pages.protection.openapiSpecHint')}
              </span>
              <Button
                size="sm"
                variant="primary"
                disabled={!canWrite || busy || openapiDraft === null}
                onClick={() =>
                  update.mutate(
                    { openapi_spec: openapiValue },
                    { onSuccess: () => setOpenapiDraft(null) },
                  )
                }
              >
                {t('common.save')}
              </Button>
            </div>
          </section>
        </CardBody>
      </Card>

      {/* ── Monitor downgrades ────────────────────────────────────────── */}
      <Card>
        <CardHeader
          title={t('pages.protection.monitorTitle')}
          description={t('pages.protection.monitorHint')}
        />
        <CardBody className="flex flex-col gap-5">
          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
              {t('pages.protection.monitorCategories')}
            </h3>
            <div className="grid grid-cols-1 gap-x-8 gap-y-1 sm:grid-cols-2 lg:grid-cols-3">
              {WAF_CATEGORIES.map((category) => {
                const on = categoriesOn.includes(category)
                return (
                  <div
                    key={category}
                    className="flex items-center justify-between gap-3 rounded-md px-1 py-1.5"
                  >
                    <span className="min-w-0">
                      <span
                        className={cn(
                          'block truncate text-sm',
                          on ? 'text-fg' : 'text-fg-subtle',
                        )}
                      >
                        {t(`pages.waf.${category}`)}
                      </span>
                    </span>
                    <Switch
                      size="sm"
                      checked={on}
                      disabled={!canWrite || busy}
                      aria-label={t(`pages.waf.${category}`)}
                      onCheckedChange={(enabled) =>
                        toggleCategory(category, enabled)
                      }
                    />
                  </div>
                )
              })}
            </div>
          </section>

          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
              {t('pages.protection.monitorStacks')}
            </h3>
            <div className="grid grid-cols-1 gap-x-8 gap-y-1 sm:grid-cols-2 lg:grid-cols-4">
              {WAF_STACKS.map((stack) => {
                const on = stacksOn.includes(stack)
                return (
                  <div
                    key={stack}
                    className="flex items-center justify-between gap-3 rounded-md px-1 py-1.5"
                  >
                    <span className="min-w-0">
                      <span
                        className={cn(
                          'block truncate text-sm',
                          on ? 'text-fg' : 'text-fg-subtle',
                        )}
                      >
                        {t(`pages.waf.stack_${stack}`)}
                      </span>
                    </span>
                    <Switch
                      size="sm"
                      checked={on}
                      disabled={!canWrite || busy}
                      aria-label={t(`pages.waf.stack_${stack}`)}
                      onCheckedChange={(enabled) => toggleStack(stack, enabled)}
                    />
                  </div>
                )
              })}
            </div>
          </section>

          <p className="flex items-start gap-2 border-t border-line pt-3 text-xs leading-relaxed text-fg-subtle">
            <ShieldWarning
              weight="duotone"
              className="mt-0.5 h-3.5 w-3.5 shrink-0"
            />
            {t('pages.protection.monitorExplainer')}
          </p>
        </CardBody>
      </Card>
    </div>
  )
}

export default ProtectionSettingsPanel
