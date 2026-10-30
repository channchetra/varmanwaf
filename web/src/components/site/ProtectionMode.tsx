import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  CaretDown,
  Eye,
  PauseCircle,
  ShieldCheck,
  ShieldWarning,
  type Icon,
} from '@phosphor-icons/react'
import { Badge, type BadgeTone } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Callout } from '@/components/ui/Callout'
import { Dialog } from '@/components/ui/Dialog'
import { Skeleton } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { policiesApi, policyKeys } from '@/api/policies'
import { sitesApi, siteKeys } from '@/api/sites'
import { wafSettingsApi, wafSettingsKeys } from '@/api/wafSettings'
import { useCanWrite, useSiteDetail } from '@/hooks'
import { cn } from '@/lib/utils'

type ProtectionState = 'block' | 'monitor' | 'paused' | 'off'

interface ModeMeta {
  icon: Icon
  labelKey: string
  subtitleKey: string
  hintKey: string
  tone: BadgeTone
}

const MODES: Record<Exclude<ProtectionState, 'off'>, ModeMeta> = {
  block: {
    icon: ShieldCheck,
    labelKey: 'pages.protectionMode.block',
    subtitleKey: 'pages.protectionMode.blockSubtitle',
    hintKey: 'pages.protectionMode.blockHint',
    tone: 'success',
  },
  monitor: {
    icon: Eye,
    labelKey: 'pages.protectionMode.monitor',
    subtitleKey: 'pages.protectionMode.monitorSubtitle',
    hintKey: 'pages.protectionMode.monitorHint',
    tone: 'info',
  },
  paused: {
    icon: PauseCircle,
    labelKey: 'pages.protectionMode.paused',
    subtitleKey: 'pages.protectionMode.pausedSubtitle',
    hintKey: 'pages.protectionMode.pausedHint',
    tone: 'neutral',
  },
}

const OFF_META: ModeMeta = {
  icon: ShieldWarning,
  labelKey: 'pages.protectionMode.off',
  subtitleKey: 'pages.protectionMode.offSubtitle',
  hintKey: 'pages.protectionMode.offHint',
  tone: 'warning',
}

const CHOICES: Array<Exclude<ProtectionState, 'off'>> = ['block', 'monitor', 'paused']

/** Maps the server-reported effective mode onto this control's states. */
function reportedProtectionState(
  value: string | undefined,
): ProtectionState | null {
  switch (value) {
    case 'block':
    case 'monitor':
    case 'off':
      return value
    case 'paused':
    case 'pending':
      // A pending site is not serving either; Paused is the closest control
      // state and saving Block or Monitor activates it.
      return 'paused'
    default:
      return null
  }
}

/**
 * The one enforcement control for a site: Block, Monitor or Paused.
 *
 * This is the gate the engine actually reads (`waf_settings.mode` plus the
 * site status), not the per-rule mode. It is used in the site header and on
 * the Protection overview so the same decision is always one click away.
 */
export function ProtectionMode({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const toast = useToast()
  const canWrite = useCanWrite()
  const queryClient = useQueryClient()
  const detail = useSiteDetail(siteId)
  const effective = useQuery({
    queryKey: policyKeys.siteEffective(siteId),
    queryFn: () => policiesApi.effectiveConfig(siteId),
    enabled: Boolean(siteId),
  })

  const [open, setOpen] = useState(false)
  const [selected, setSelected] = useState<Exclude<ProtectionState, 'off'> | null>(null)

  const paused = detail.data?.site.status === 'paused'
  const ready = Boolean(detail.data) && !effective.isPending && !effective.isError
  const source = effective.data?.source ?? 'site'
  const policy = effective.data?.policy ?? null
  const policyManaged = source === 'policy' && Boolean(policy)
  // The backend resolves the same builder the edge consumes, so this matches
  // the sites list and includes the rule-derived fallback in one place. The
  // older effective-config derivation stays as a fallback for cached rows.
  const reported = reportedProtectionState(
    detail.data?.site.protection_mode,
  )
  const current: ProtectionState | null = !ready
    ? null
    : (reported ??
      (detail.data?.site.status !== 'active'
        ? 'paused'
        : effective.data && !effective.data.effective.waf_enabled
          ? 'off'
          : effective.data?.effective.mode === 'monitor'
            ? 'monitor'
            : 'block'))

  const meta = current ? (current === 'off' ? OFF_META : MODES[current]) : null
  const Icon = meta?.icon ?? ShieldWarning

  const save = useMutation({
    mutationFn: async (next: Exclude<ProtectionState, 'off'>) => {
      if (next === 'paused') {
        await sitesApi.update(siteId, { status: 'paused' })
        return
      }
      await Promise.all([
        wafSettingsApi.update(siteId, {
          waf_enabled: true,
          mode: next === 'monitor' ? 'monitor' : 'block',
        }),
        paused ? sitesApi.update(siteId, { status: 'active' }) : Promise.resolve(),
      ])
    },
    onSuccess: (_saved, next) => {
      toast.success(
        t('pages.protectionMode.saved', {
          mode: t(MODES[next].labelKey),
        }),
      )
      setOpen(false)
      setSelected(null)
      void queryClient.invalidateQueries({ queryKey: siteKeys.all })
      void queryClient.invalidateQueries({
        queryKey: wafSettingsKeys.settings(siteId),
      })
      void queryClient.invalidateQueries({
        queryKey: policyKeys.siteEffective(siteId),
      })
      void queryClient.invalidateQueries({
        queryKey: policyKeys.applyStatus(siteId),
      })
    },
    onError: (error) => {
      toast.error(
        t('pages.protectionMode.saveFailed'),
        error instanceof Error ? error.message : undefined,
      )
    },
  })

  const openDialog = () => {
    if (!current) return
    setSelected(current === 'off' ? null : current)
    setOpen(true)
  }

  const policyBlocksChoice =
    policyManaged && selected !== null && selected !== 'paused'
  const canSave =
    canWrite && selected !== null && !policyBlocksChoice && !save.isPending

  const trigger = (
    <button
      type="button"
      onClick={openDialog}
      disabled={!current}
      aria-haspopup="dialog"
      aria-label={t('pages.protectionMode.title')}
      className="group flex w-full items-center gap-3 rounded-lg border border-line bg-elevated px-3 py-2 text-left transition-colors hover:border-brand/45 hover:bg-recessed/40 disabled:cursor-wait"
    >
      <span
        className={cn(
          'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg',
          current === 'block' && 'bg-success/12 text-fg-success',
          current === 'monitor' && 'bg-focus/10 text-link',
          current === 'paused' && 'bg-recessed text-fg-subtle',
          current === 'off' && 'bg-warning/12 text-fg-warning',
          !current && 'bg-recessed text-fg-subtle',
        )}
      >
        <Icon weight="duotone" className="h-5 w-5" />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-[10px] font-semibold uppercase tracking-[0.12em] text-fg-subtle">
          {t('pages.protectionMode.title')}
        </span>
        <span className="flex flex-wrap items-center gap-2">
          {!current || !meta ? (
            <Skeleton className="h-4 w-20" />
          ) : (
            <span className="text-sm font-semibold text-fg-strong">
              {t(meta.labelKey)}
            </span>
          )}
          {current === 'off' && (
            <Badge tone="warning" size="sm">
              {t('pages.protectionMode.offBadge')}
            </Badge>
          )}
          {policyManaged && (
            <Badge tone="brand" size="sm">
              {t('pages.protectionMode.policyBadge')}
            </Badge>
          )}
        </span>
        <span className="mt-0.5 block truncate text-[11px] text-fg-subtle">
          {meta ? t(meta.subtitleKey) : t('pages.protectionMode.checking')}
        </span>
      </span>
      <CaretDown
        weight="bold"
        className="h-3.5 w-3.5 shrink-0 text-fg-subtle transition-transform group-hover:text-fg"
      />
    </button>
  )

  return (
    <>
      {trigger}

      <Dialog
        open={open}
        onClose={() => {
          if (!save.isPending) setOpen(false)
        }}
        title={t('pages.protectionMode.dialogTitle')}
        description={t('pages.protectionMode.dialogHint')}
        size="lg"
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button
              variant="ghost"
              onClick={() => setOpen(false)}
              disabled={save.isPending}
            >
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              onClick={() => selected && save.mutate(selected)}
              disabled={!canSave}
              loading={save.isPending}
            >
              {t('pages.protectionMode.save')}
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          {policyManaged && (
            <Callout
              tone="info"
              icon={<ShieldWarning weight="duotone" className="h-5 w-5" />}
              title={t('pages.protectionMode.policyTitle', {
                name: policy?.name ?? '',
              })}
              actions={
                <Link
                  to={`/sites/${siteId}/security/protection?tab=tuning`}
                  onClick={() => setOpen(false)}
                  className="inline-flex items-center rounded-md border border-line px-3 py-1.5 text-[12px] font-medium text-link hover:border-brand/40"
                >
                  {t('pages.protectionMode.openAdvanced')}
                </Link>
              }
            >
              {t('pages.protectionMode.policyHint')}
            </Callout>
          )}

          {current === 'off' && (
            <Callout
              tone="warning"
              icon={<ShieldWarning weight="duotone" className="h-5 w-5" />}
            >
              {t('pages.protectionMode.offNotice')}
            </Callout>
          )}

          <div
            className="grid gap-3 sm:grid-cols-3"
            role="group"
            aria-label={t('pages.protectionMode.title')}
          >
            {CHOICES.map((choice) => {
              const choiceMeta = MODES[choice]
              const ChoiceIcon = choiceMeta.icon
              const active = selected === choice
              const blocked = policyManaged && choice !== 'paused'
              return (
                <button
                  key={choice}
                  type="button"
                  aria-pressed={active}
                  disabled={blocked}
                  onClick={() => setSelected(choice)}
                  className={cn(
                    'flex min-h-32 flex-col items-start gap-2 rounded-xl border p-4 text-left transition-colors',
                    active
                      ? 'border-brand bg-brand-soft'
                      : 'border-line bg-recessed/30 hover:border-fill',
                    blocked && 'cursor-not-allowed opacity-55',
                  )}
                >
                  <span className="flex w-full items-center justify-between">
                    <ChoiceIcon
                      weight="duotone"
                      className={cn(
                        'h-6 w-6',
                        active ? 'text-brand-ink' : 'text-fg-subtle',
                      )}
                    />
                    {active && (
                      <ShieldCheck weight="fill" className="h-4 w-4 text-brand-ink" />
                    )}
                  </span>
                  <span
                    className={cn(
                      'text-sm font-semibold',
                      active ? 'text-brand-ink' : 'text-fg-strong',
                    )}
                  >
                    {t(choiceMeta.labelKey)}
                  </span>
                  <span className="text-[12px] leading-snug text-fg-subtle">
                    {t(choiceMeta.hintKey)}
                  </span>
                </button>
              )
            })}
          </div>

          {!canWrite && (
            <p className="text-[12px] text-fg-subtle">
              {t('pages.protectionMode.readonly')}
            </p>
          )}
        </div>
      </Dialog>
    </>
  )
}
