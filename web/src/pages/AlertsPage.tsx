import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  BellRinging,
  Eye,
  PencilSimple,
  Plus,
  Trash,
  PaperPlaneTilt,
} from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Callout } from '@/components/ui/Callout'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { Input } from '@/components/ui/Input'
import { PillMultiSelect } from '@/components/ui/MultiSelect'
import { Select } from '@/components/ui/Select'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { Switch } from '@/components/ui/Switch'
import { Table, type Column } from '@/components/ui/Table'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { useCanWrite, useSitesList } from '@/hooks'
import { cn } from '@/lib/utils'
import { QuickNav } from '@/components/ui/QuickNav'
import { NotificationSettingsCard, LoginSecurityCard, AlertHistoryCard } from '@/components/alerts/DeliveryPanels'
import {
  alertsApi,
  alertKeys,
  type AlertPreview,
  type AlertRule,
  type AlertRuleRequest,
  type AlertSilence,
} from '@/api/alerts'
import {
  notificationsApi,
  notificationsKeys,
  type NotificationChannel,
} from '@/api/notifications'

/**
 * Security alerts: threshold rules over stored security events, maintenance
 * silences, and the notification channels they deliver to. Ratios require a
 * minimum sample count, so a single blocked probe cannot page anyone; the
 * per-rule preview reports exactly what the next evaluation would see.
 */
export function AlertsPage() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const toast = useToast()
  const queryClient = useQueryClient()
  const sites = useSitesList()

  const [ruleDialog, setRuleDialog] = useState<{
    open: boolean
    rule?: AlertRule
  }>({ open: false })
  const [channelDialog, setChannelDialog] = useState<{
    open: boolean
    channel?: NotificationChannel
  }>({ open: false })
  const [silenceOpen, setSilenceOpen] = useState(false)
  const [deleteRule, setDeleteRule] = useState<AlertRule | null>(null)
  const [deleteChannel, setDeleteChannel] =
    useState<NotificationChannel | null>(null)
  const [deleteSilence, setDeleteSilence] = useState<AlertSilence | null>(null)
  const [preview, setPreview] = useState<{
    rule: AlertRule
    data: AlertPreview
  } | null>(null)

  const rules = useQuery({
    queryKey: alertKeys.rules(),
    queryFn: () => alertsApi.rules(),
  })
  const silences = useQuery({
    queryKey: alertKeys.silences(),
    queryFn: () => alertsApi.silences(),
  })
  const channels = useQuery({
    queryKey: notificationsKeys.channels(),
    queryFn: () => notificationsApi.channels(),
  })

  const previewRule = useMutation({
    mutationFn: (rule: AlertRule) =>
      alertsApi.previewRule(rule.id).then((data) => ({ rule, data })),
    onSuccess: (result) => setPreview(result),
    onError: (error) => toast.error(t('pages.alerts.previewFailed'), String(error)),
  })

  const removeRule = useMutation({
    mutationFn: (id: string) => alertsApi.removeRule(id),
    onSuccess: () => {
      toast.success(t('pages.alerts.ruleDeleted'))
      setDeleteRule(null)
      void queryClient.invalidateQueries({ queryKey: alertKeys.all })
    },
    onError: (error) => toast.error(t('pages.alerts.ruleDeleteFailed'), String(error)),
  })

  const removeChannel = useMutation({
    mutationFn: (id: string) => notificationsApi.removeChannel(id),
    onSuccess: () => {
      toast.success(t('pages.alerts.channelDeleted'))
      setDeleteChannel(null)
      void queryClient.invalidateQueries({ queryKey: notificationsKeys.all })
    },
    onError: (error) => toast.error(t('pages.alerts.channelDeleteFailed'), String(error)),
  })

  const removeSilence = useMutation({
    mutationFn: (id: string) => alertsApi.removeSilence(id),
    onSuccess: () => {
      toast.success(t('pages.alerts.silenceDeleted'))
      setDeleteSilence(null)
      void queryClient.invalidateQueries({ queryKey: alertKeys.all })
    },
    onError: (error) => toast.error(t('pages.alerts.silenceDeleteFailed'), String(error)),
  })

  const testChannel = useMutation({
    mutationFn: (id: string) => notificationsApi.testChannel(id),
    onSuccess: (result) => {
      if (result.ok) {
        toast.success(t('pages.alerts.channelTestOk'))
      } else {
        toast.error(t('pages.alerts.channelTestFailed'), result.error ?? '')
      }
    },
    onError: (error) => toast.error(t('pages.alerts.channelTestFailed'), String(error)),
  })

  const siteName = (siteId: string | null | undefined) =>
    siteId
      ? (sites.data ?? []).find((site) => site.id === siteId)?.name ?? siteId
      : t('pages.alerts.allSites')

  const channelName = (id: string) =>
    (channels.data ?? []).find((channel) => channel.id === id)?.name ?? id

  const ruleColumns: Column<AlertRule>[] = [
    {
      key: 'name',
      header: t('pages.alerts.name'),
      accessor: (r) => r.name,
      cell: (r) => (
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="truncate font-medium text-fg-strong">
              {r.name}
            </span>
            {!r.enabled && (
              <Badge tone="neutral">{t('common.disabled')}</Badge>
            )}
            <Badge tone={SEVERITY_TONE[r.severity] ?? 'neutral'}>
              {r.severity}
            </Badge>
          </div>
          <p className="pw-mono truncate text-[11px] text-fg-subtle">
            {r.metric === 'blocked_ratio'
              ? t('pages.alerts.conditionRatio', {
                  threshold: r.threshold,
                  window: r.window_seconds,
                  samples: r.min_samples,
                })
              : t('pages.alerts.conditionCount', {
                  threshold: r.threshold,
                  window: r.window_seconds,
                })}
            {r.site_id ? ` · ${siteName(r.site_id)}` : ''}
            {r.event_type ? ` · ${r.event_type}` : ''}
            {r.rule_id_contains ? ` · ~${r.rule_id_contains}` : ''}
          </p>
        </div>
      ),
    },
    {
      key: 'channels',
      header: t('pages.alerts.channels'),
      accessor: (r) => r.channels.length,
      width: '1%',
      cell: (r) => (
        <span className="text-[13px] text-fg-subtle">
          {r.channels.length === 0
            ? t('pages.alerts.allSubscribed')
            : r.channels.map(channelName).join(', ')}
        </span>
      ),
    },
    {
      key: 'last',
      header: t('pages.alerts.lastObservation'),
      width: '1%',
      cell: (r) => (
        <div className="whitespace-nowrap text-[12px] text-fg-subtle">
          {r.last_value != null ? (
            <p className="pw-mono">
              {r.metric === 'blocked_ratio'
                ? `${r.last_value.toFixed(1)}% (${r.last_samples ?? 0})`
                : String(r.last_value)}
            </p>
          ) : (
            <p>—</p>
          )}
          {r.last_fired_at && (
            <p className="text-[11px] text-fg-subtle">
              {t('pages.alerts.firedAt', {
                time: new Date(r.last_fired_at).toLocaleString(),
              })}
            </p>
          )}
        </div>
      ),
    },
    {
      key: 'actions',
      header: '',
      width: '1%',
      cell: (r) => (
        <div className="flex items-center gap-1">
          <Button
            size="sm"
            variant="ghost"
            icon={<Eye className="h-4 w-4" />}
            loading={previewRule.isPending && previewRule.variables?.id === r.id}
            onClick={() => previewRule.mutate(r)}
          >
            {t('pages.alerts.preview')}
          </Button>
          {canWrite && (
            <>
              <Button
                size="sm"
                variant="ghost"
                icon={<PencilSimple className="h-4 w-4" />}
                onClick={() => setRuleDialog({ open: true, rule: r })}
              />
              <Button
                size="sm"
                variant="ghost"
                icon={<Trash className="h-4 w-4" />}
                onClick={() => setDeleteRule(r)}
              />
            </>
          )}
        </div>
      ),
    },
  ]

  const silenceColumns: Column<AlertSilence>[] = [
    {
      key: 'scope',
      header: t('pages.alerts.scope'),
      accessor: (r) => r.site_id ?? '',
      width: '1%',
      cell: (r) => <span className="text-[13px]">{siteName(r.site_id)}</span>,
    },
    {
      key: 'reason',
      header: t('pages.alerts.reason'),
      accessor: (r) => r.reason,
      cell: (r) => (
        <span className="text-[13px]">
          {r.reason || <span className="text-fg-subtle">—</span>}
        </span>
      ),
    },
    {
      key: 'window',
      header: t('pages.alerts.window'),
      width: '1%',
      cell: (r) => (
        <span className="pw-mono whitespace-nowrap text-[12px] text-fg-subtle">
          {new Date(r.starts_at).toLocaleString()} →{' '}
          {r.ends_at
            ? new Date(r.ends_at).toLocaleString()
            : t('pages.alerts.untilDeleted')}
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      width: '1%',
      cell: (r) =>
        canWrite && (
          <Button
            size="sm"
            variant="ghost"
            icon={<Trash className="h-4 w-4" />}
            onClick={() => setDeleteSilence(r)}
          />
        ),
    },
  ]

  const channelColumns: Column<NotificationChannel>[] = [
    {
      key: 'name',
      header: t('pages.alerts.name'),
      accessor: (r) => r.name,
      cell: (r) => (
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="truncate font-medium text-fg-strong">
              {r.name}
            </span>
            <Badge tone="neutral">{r.kind}</Badge>
            {!r.enabled && (
              <Badge tone="neutral">{t('common.disabled')}</Badge>
            )}
          </div>
          <p className="truncate text-[11px] text-fg-subtle">
            {r.events.length === 0
              ? t('pages.alerts.allEvents')
              : r.events.join(', ')}
          </p>
        </div>
      ),
    },
    {
      key: 'actions',
      header: '',
      width: '1%',
      cell: (r) =>
        canWrite && (
          <div className="flex items-center gap-1">
            <Button
              size="sm"
              variant="ghost"
              icon={<PaperPlaneTilt className="h-4 w-4" />}
              loading={
                testChannel.isPending && testChannel.variables === r.id
              }
              onClick={() => testChannel.mutate(r.id)}
            >
              {t('pages.alerts.test')}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              icon={<PencilSimple className="h-4 w-4" />}
              onClick={() => setChannelDialog({ open: true, channel: r })}
            />
            <Button
              size="sm"
              variant="ghost"
              icon={<Trash className="h-4 w-4" />}
              onClick={() => setDeleteChannel(r)}
            />
          </div>
        ),
    },
  ]

  const sections = useMemo(
    () => [
      { id: 'rules', label: t('pages.alerts.rulesTitle') },
      { id: 'silences', label: t('pages.alerts.silencesTitle') },
      { id: 'channels', label: t('pages.alerts.channelsTitle') },
      ...(canWrite
        ? [
            { id: 'delivery', label: t('pages.alerts.deliverySection') },
            { id: 'security', label: t('pages.alerts.securitySection') },
            { id: 'history', label: t('pages.alerts.historySection') },
          ]
        : []),
    ],
    [t, canWrite],
  )

  if (rules.isError && !rules.data) {
    return (
      <div className="animate-slide-up">
        <ErrorState
          error={rules.error}
          onRetry={() => rules.refetch()}
          retrying={rules.isFetching}
        />
      </div>
    )
  }

  return (
    <div className="animate-slide-up space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-fg-strong">
          {t('pages.alerts.title')}
        </h1>
        <p className="mt-1 text-[13px] text-fg-subtle">
          {t('pages.alerts.description')}
        </p>
      </div>

      <Callout
        dismissKey="alerts"
        tone="brand"
        icon={<BellRinging weight="duotone" className="h-5 w-5" />}
        title={t('pages.alerts.overviewTitle')}
      >
        {t('pages.alerts.overview')}
      </Callout>

      <div className="flex items-start gap-8">
        <QuickNav
          ariaLabel={t('pages.alerts.sectionsNav')}
          items={sections}
        />
        <div className="min-w-0 flex-1 space-y-5">
          <div className="xl:hidden">
            <SectionNav items={sections} />
          </div>
      {/* Rules */}
      <Card id="rules" className="scroll-mt-24">
        <CardHeader
          title={t('pages.alerts.rulesTitle')}
          description={t('pages.alerts.rulesHint')}
          action={
            canWrite && (
              <Button
                variant="primary"
                size="sm"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={() => setRuleDialog({ open: true })}
              >
                {t('pages.alerts.newRule')}
              </Button>
            )
          }
        />
        <CardBody>
          {rules.isLoading ? (
            <SkeletonCard />
          ) : (rules.data ?? []).length === 0 ? (
            <EmptyState
              icon={<BellRinging weight="duotone" className="h-6 w-6" />}
              title={t('pages.alerts.noRules')}
              description={t('pages.alerts.noRulesHint')}
            />
          ) : (
            <Table
              columns={ruleColumns}
              data={rules.data ?? []}
              rowKey={(r) => r.id}
              dense
            />
          )}
        </CardBody>
      </Card>

      {/* Silences */}
      <Card id="silences" className="scroll-mt-24">
        <CardHeader
          title={t('pages.alerts.silencesTitle')}
          description={t('pages.alerts.silencesHint')}
          action={
            canWrite && (
              <Button
                size="sm"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={() => setSilenceOpen(true)}
              >
                {t('pages.alerts.newSilence')}
              </Button>
            )
          }
        />
        <CardBody>
          {silences.isLoading ? (
            <SkeletonCard />
          ) : (silences.data ?? []).length === 0 ? (
            <p className="text-[13px] text-fg-subtle">
              {t('pages.alerts.noSilences')}
            </p>
          ) : (
            <Table
              columns={silenceColumns}
              data={silences.data ?? []}
              rowKey={(r) => r.id}
              dense
            />
          )}
        </CardBody>
      </Card>

      {/* Channels */}
      <Card id="channels" className="scroll-mt-24">
        <CardHeader
          title={t('pages.alerts.channelsTitle')}
          description={t('pages.alerts.channelsHint')}
          action={
            canWrite && (
              <Button
                size="sm"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={() => setChannelDialog({ open: true })}
              >
                {t('pages.alerts.newChannel')}
              </Button>
            )
          }
        />
        <CardBody>
          {channels.isLoading ? (
            <SkeletonCard />
          ) : (channels.data ?? []).length === 0 ? (
            <p className="text-[13px] text-fg-subtle">
              {t('pages.alerts.noChannels')}
            </p>
          ) : (
            <Table
              columns={channelColumns}
              data={channels.data ?? []}
              rowKey={(r) => r.id}
              dense
            />
          )}
        </CardBody>
      </Card>

      {/* Delivery: thresholds, per-event toggles and the master switch */}
      {canWrite && (
        <section id="delivery" className="scroll-mt-24">
          <NotificationSettingsCard
            canWrite={canWrite}
            onSaved={() =>
              void queryClient.invalidateQueries({
                queryKey: ['notifications'],
              })
            }
          />
        </section>
      )}

      {/* Login security: the anomaly baseline and the login audit */}
      {canWrite && (
        <section id="security" className="scroll-mt-24">
          <LoginSecurityCard canWrite={canWrite} />
        </section>
      )}

      {/* History: the paged, filterable alert history */}
      {canWrite && (
        <section id="history" className="scroll-mt-24">
          <AlertHistoryCard canWrite={canWrite} />
        </section>
      )}
        </div>
      </div>

      {ruleDialog.open && (
        <RuleDialog
          rule={ruleDialog.rule}
          onClose={() => setRuleDialog({ open: false })}
          onSaved={() => {
            setRuleDialog({ open: false })
            void queryClient.invalidateQueries({ queryKey: alertKeys.all })
          }}
        />
      )}

      {channelDialog.open && (
        <ChannelDialog
          channel={channelDialog.channel}
          onClose={() => setChannelDialog({ open: false })}
          onSaved={() => {
            setChannelDialog({ open: false })
            void queryClient.invalidateQueries({
              queryKey: notificationsKeys.all,
            })
          }}
        />
      )}

      {silenceOpen && (
        <SilenceDialog
          onClose={() => setSilenceOpen(false)}
          onSaved={() => {
            setSilenceOpen(false)
            void queryClient.invalidateQueries({ queryKey: alertKeys.all })
          }}
        />
      )}

      {preview && (
        <Dialog
          open
          onClose={() => setPreview(null)}
          size="md"
          title={t('pages.alerts.previewTitle', { name: preview.rule.name })}
          description={t('pages.alerts.previewHint')}
        >
          <div className="space-y-3 px-5 py-4 text-[13px]">
            <dl className="grid grid-cols-2 gap-3">
              <PreviewRow
                label={t('pages.alerts.previewValue')}
                value={
                  preview.data.metric === 'blocked_ratio'
                    ? `${preview.data.value.toFixed(1)}%`
                    : String(preview.data.value)
                }
              />
              <PreviewRow
                label={t('pages.alerts.previewThreshold')}
                value={
                  preview.data.metric === 'blocked_ratio'
                    ? `${preview.data.threshold}%`
                    : String(preview.data.threshold)
                }
              />
              <PreviewRow
                label={t('pages.alerts.previewHits')}
                value={String(preview.data.hits)}
              />
              <PreviewRow
                label={t('pages.alerts.previewSamples')}
                value={String(preview.data.samples)}
              />
            </dl>
            <p className="text-fg-subtle">{preview.data.samples_basis}</p>
            <div className="flex flex-wrap items-center gap-2">
              <Badge
                tone={preview.data.threshold_met ? 'warning' : 'neutral'}
              >
                {preview.data.threshold_met
                  ? t('pages.alerts.wouldFire')
                  : t('pages.alerts.wouldNotFire')}
              </Badge>
              {preview.data.silenced && (
                <Badge tone="neutral">
                  {t('pages.alerts.previewSilenced', {
                    reason: preview.data.silence_reason ?? '',
                  })}
                </Badge>
              )}
            </div>
            <p className="text-[12px] text-fg-subtle">
              {t('pages.alerts.previewNote', {
                window: preview.data.window_seconds,
                samples: preview.data.min_samples,
              })}
            </p>
          </div>
        </Dialog>
      )}

      <ConfirmDialog
        open={deleteRule !== null}
        onClose={() => setDeleteRule(null)}
        onConfirm={() => deleteRule && removeRule.mutate(deleteRule.id)}
        loading={removeRule.isPending}
        tone="danger"
        title={t('pages.alerts.ruleDeleteTitle')}
        description={t('pages.alerts.ruleDeleteBody', {
          name: deleteRule?.name ?? '',
        })}
        confirmLabel={t('common.delete')}
      />
      <ConfirmDialog
        open={deleteChannel !== null}
        onClose={() => setDeleteChannel(null)}
        onConfirm={() =>
          deleteChannel && removeChannel.mutate(deleteChannel.id)
        }
        loading={removeChannel.isPending}
        tone="danger"
        title={t('pages.alerts.channelDeleteTitle')}
        description={t('pages.alerts.channelDeleteBody', {
          name: deleteChannel?.name ?? '',
        })}
        confirmLabel={t('common.delete')}
      />
      <ConfirmDialog
        open={deleteSilence !== null}
        onClose={() => setDeleteSilence(null)}
        onConfirm={() =>
          deleteSilence && removeSilence.mutate(deleteSilence.id)
        }
        loading={removeSilence.isPending}
        tone="danger"
        title={t('pages.alerts.silenceDeleteTitle')}
        confirmLabel={t('common.delete')}
      />
    </div>
  )
}

const SEVERITY_TONE: Record<string, 'success' | 'warning' | 'danger' | 'neutral'> = {
  info: 'neutral',
  warning: 'warning',
  critical: 'danger',
}

function PreviewRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-line bg-recessed px-3 py-2">
      <dt className="text-xs text-fg-subtle">{label}</dt>
      <dd className="mt-0.5 font-medium text-fg-strong">{value}</dd>
    </div>
  )
}

const WINDOW_CHOICES = [60, 300, 900, 3600, 21600, 86400]
const COOLDOWN_CHOICES = [60, 300, 900, 3600, 86400]
const ALERT_EVENT_TYPES = ['waf', 'managed', 'ip_geo', 'bot', 'rate_limit', 'challenge']

function RuleDialog({
  rule,
  onClose,
  onSaved,
}: {
  rule?: AlertRule
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const sites = useSitesList()
  const channels = useQuery({
    queryKey: notificationsKeys.channels(),
    queryFn: () => notificationsApi.channels(),
  })

  const [name, setName] = useState(rule?.name ?? '')
  const [enabled, setEnabled] = useState(rule?.enabled ?? true)
  const [metric, setMetric] = useState(rule?.metric ?? 'event_count')
  const [threshold, setThreshold] = useState(
    rule ? String(rule.threshold) : '10',
  )
  const [window, setWindow] = useState(
    rule ? String(rule.window_seconds) : '300',
  )
  const [minSamples, setMinSamples] = useState(
    rule ? String(rule.min_samples) : '100',
  )
  const [siteId, setSiteId] = useState(rule?.site_id ?? '')
  const [eventType, setEventType] = useState(rule?.event_type ?? '')
  const [ruleIdContains, setRuleIdContains] = useState(
    rule?.rule_id_contains ?? '',
  )
  const [severity, setSeverity] = useState(rule?.severity ?? 'warning')
  const [selected, setSelected] = useState<string[]>(rule?.channels ?? [])
  const [cooldown, setCooldown] = useState(
    rule ? String(rule.cooldown_seconds) : '900',
  )

  const save = useMutation({
    mutationFn: () => {
      const payload: AlertRuleRequest = {
        name: name.trim(),
        enabled,
        metric,
        threshold: Number(threshold),
        window_seconds: Number(window),
        min_samples: metric === 'blocked_ratio' ? Number(minSamples) : 0,
        site_id: siteId || null,
        event_type: eventType,
        rule_id_contains: ruleIdContains.trim(),
        severity,
        channels: selected,
        cooldown_seconds: Number(cooldown),
      }
      return rule
        ? alertsApi.updateRule(rule.id, payload)
        : alertsApi.createRule(payload)
    },
    onSuccess: () => {
      toast.success(rule ? t('pages.alerts.ruleUpdated') : t('pages.alerts.ruleCreated'))
      onSaved()
    },
    onError: (error) => toast.error(t('pages.alerts.ruleSaveFailed'), String(error)),
  })

  const thresholdValid =
    Number(threshold) > 0 &&
    (metric !== 'blocked_ratio' || Number(threshold) <= 100)

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={rule ? t('pages.alerts.editRule') : t('pages.alerts.newRule')}
      description={t('pages.alerts.ruleDialogHint')}
    >
      <div className="max-h-[70vh] space-y-3 overflow-y-auto px-5 py-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <Input
            label={t('pages.alerts.name')}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <Select
            label={t('pages.alerts.metric')}
            value={metric}
            onChange={(e) => setMetric(e.target.value as AlertRule['metric'])}
            options={[
              { value: 'event_count', label: t('pages.alerts.metricCount') },
              { value: 'blocked_ratio', label: t('pages.alerts.metricRatio') },
            ]}
          />
          <Input
            label={
              metric === 'blocked_ratio'
                ? t('pages.alerts.thresholdPercent')
                : t('pages.alerts.thresholdCount')
            }
            type="number"
            value={threshold}
            error={thresholdValid ? undefined : t('pages.alerts.thresholdInvalid')}
            onChange={(e) => setThreshold(e.target.value)}
          />
          <Select
            label={t('pages.alerts.windowLabel')}
            value={window}
            onChange={(e) => setWindow(e.target.value)}
            options={WINDOW_CHOICES.map((value) => ({
              value: String(value),
              label: formatSeconds(t, value),
            }))}
          />
          {metric === 'blocked_ratio' && (
            <Input
              label={t('pages.alerts.minSamples')}
              hint={t('pages.alerts.minSamplesHint')}
              type="number"
              value={minSamples}
              onChange={(e) => setMinSamples(e.target.value)}
            />
          )}
          <Select
            label={t('pages.alerts.cooldown')}
            hint={t('pages.alerts.cooldownHint')}
            value={cooldown}
            onChange={(e) => setCooldown(e.target.value)}
            options={COOLDOWN_CHOICES.map((value) => ({
              value: String(value),
              label: formatSeconds(t, value),
            }))}
          />
          <Select
            label={t('pages.alerts.scope')}
            value={siteId}
            onChange={(e) => setSiteId(e.target.value)}
            options={[
              { value: '', label: t('pages.alerts.allSites') },
              ...(sites.data ?? []).map((site) => ({
                value: site.id,
                label: site.name,
              })),
            ]}
          />
          <Select
            label={t('pages.alerts.severity')}
            value={severity}
            onChange={(e) =>
              setSeverity(e.target.value as AlertRule['severity'])
            }
            options={['info', 'warning', 'critical'].map((value) => ({
              value,
              label: value,
            }))}
          />
          <Select
            label={t('pages.alerts.eventType')}
            hint={t('pages.alerts.eventTypeHint')}
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
            options={[
              { value: '', label: t('pages.alerts.anyEventType') },
              ...ALERT_EVENT_TYPES.map((value) => ({ value, label: value })),
            ]}
          />
          <Input
            label={t('pages.alerts.ruleIdContains')}
            hint={t('pages.alerts.ruleIdContainsHint')}
            placeholder={t('pages.alerts.ruleIdContainsPlaceholder')}
            value={ruleIdContains}
            onChange={(e) => setRuleIdContains(e.target.value)}
          />
        </div>
        <PillMultiSelect
          label={t('pages.alerts.channels')}
          hint={t('pages.alerts.channelsHint')}
          options={(channels.data ?? []).map((channel) => ({
            value: channel.id,
            label: channel.name,
            hint: channel.kind,
          }))}
          value={selected}
          onChange={setSelected}
        />
        <Switch
          checked={enabled}
          onCheckedChange={setEnabled}
          label={t('common.enabled')}
        />
        <div className="flex justify-end gap-2 border-t border-line pt-3">
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={save.isPending}
            disabled={!name.trim() || !thresholdValid}
            onClick={() => save.mutate()}
          >
            {t('common.save')}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}

const SILENCE_CHOICES = [
  { value: '3600', label: '1h' },
  { value: '14400', label: '4h' },
  { value: '86400', label: '24h' },
  { value: '604800', label: '7d' },
  { value: '', label: '' },
]

function SilenceDialog({
  onClose,
  onSaved,
}: {
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const sites = useSitesList()
  const [siteId, setSiteId] = useState('')
  const [reason, setReason] = useState('')
  const [duration, setDuration] = useState('3600')

  const save = useMutation({
    mutationFn: () =>
      alertsApi.createSilence({
        site_id: siteId || null,
        reason: reason.trim(),
        ends_at:
          duration === ''
            ? null
            : new Date(Date.now() + Number(duration) * 1000).toISOString(),
      }),
    onSuccess: () => {
      toast.success(t('pages.alerts.silenceCreated'))
      onSaved()
    },
    onError: (error) => toast.error(t('pages.alerts.silenceSaveFailed'), String(error)),
  })

  return (
    <Dialog
      open
      onClose={onClose}
      size="md"
      title={t('pages.alerts.newSilence')}
      description={t('pages.alerts.silenceDialogHint')}
    >
      <div className="space-y-3 px-5 py-4">
        <Select
          label={t('pages.alerts.scope')}
          value={siteId}
          onChange={(e) => setSiteId(e.target.value)}
          options={[
            { value: '', label: t('pages.alerts.allSites') },
            ...(sites.data ?? []).map((site) => ({
              value: site.id,
              label: site.name,
            })),
          ]}
        />
        <Input
          label={t('pages.alerts.reason')}
          placeholder={t('pages.alerts.reasonPlaceholder')}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <Select
          label={t('pages.alerts.windowLabel')}
          value={duration}
          onChange={(e) => setDuration(e.target.value)}
          options={SILENCE_CHOICES.map((choice) => ({
            value: choice.value,
            label:
              choice.value === ''
                ? t('pages.alerts.untilDeleted')
                : choice.label,
          }))}
        />
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={save.isPending}
            onClick={() => save.mutate()}
          >
            {t('pages.alerts.silence')}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}

function ChannelDialog({
  channel,
  onClose,
  onSaved,
}: {
  channel?: NotificationChannel
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const eventTypes = useQuery({
    queryKey: notificationsKeys.eventTypes(),
    queryFn: () => notificationsApi.eventTypes(),
  })

  const config = channel?.config ?? {}
  const [name, setName] = useState(channel?.name ?? '')
  const [kind, setKind] = useState(channel?.kind ?? 'webhook')
  const [url, setUrl] = useState(String(config.url ?? ''))
  const [enabled, setEnabled] = useState(channel?.enabled ?? true)
  const [selected, setSelected] = useState<string[]>(channel?.events ?? [])
  // Email config fields.
  const [smtpHost, setSmtpHost] = useState(String(config.smtp_host ?? ''))
  const [smtpPort, setSmtpPort] = useState(String(config.smtp_port ?? '587'))
  const [smtpUser, setSmtpUser] = useState(String(config.smtp_user ?? ''))
  const [smtpPass, setSmtpPass] = useState(
    typeof config.smtp_pass === 'string' ? config.smtp_pass : '',
  )
  const [smtpTls, setSmtpTls] = useState(String(config.tls ?? 'starttls'))
  const [from, setFrom] = useState(String(config.from ?? ''))
  const [to, setTo] = useState(
    Array.isArray(config.to) ? (config.to as string[]).join(', ') : '',
  )
  // Telegram config fields.
  const [botToken, setBotToken] = useState(
    typeof config.bot_token === 'string' ? config.bot_token : '',
  )
  const [chatId, setChatId] = useState(String(config.chat_id ?? ''))

  const save = useMutation({
    mutationFn: () => {
      const body = {
        name: name.trim(),
        kind,
        config:
          kind === 'email'
            ? {
                smtp_host: smtpHost.trim(),
                smtp_port: Number(smtpPort),
                smtp_user: smtpUser.trim(),
                smtp_pass: smtpPass,
                tls: smtpTls,
                from: from.trim(),
                to: to
                  .split(',')
                  .map((entry) => entry.trim())
                  .filter(Boolean),
              }
            : kind === 'telegram'
              ? { bot_token: botToken.trim(), chat_id: chatId.trim() }
              : { url: url.trim() },
        events: selected,
        enabled,
      }
      return channel
        ? notificationsApi.updateChannel(channel.id, body)
        : notificationsApi.createChannel(body)
    },
    onSuccess: () => {
      toast.success(
        channel ? t('pages.alerts.channelUpdated') : t('pages.alerts.channelCreated'),
      )
      onSaved()
    },
    onError: (error) => toast.error(t('pages.alerts.channelSaveFailed'), String(error)),
  })

  const configFilled =
    kind === 'email'
      ? smtpHost.trim() !== ''
      : kind === 'telegram'
        ? botToken.trim() !== '' && chatId.trim() !== ''
        : url.trim() !== ''

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={channel ? t('pages.alerts.editChannel') : t('pages.alerts.newChannel')}
      description={t('pages.alerts.channelDialogHint')}
    >
      <div className="max-h-[70vh] space-y-3 overflow-y-auto px-5 py-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <Input
            label={t('pages.alerts.name')}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <Select
            label={t('pages.alerts.kind')}
            value={kind}
            onChange={(e) => setKind(e.target.value as NotificationChannel['kind'])}
            options={['email', 'wecom', 'dingtalk', 'webhook', 'telegram'].map(
              (value) => ({
                value,
                label: value,
              }),
            )}
          />
        </div>
        {kind === 'email' ? (
          <div className="grid gap-3 sm:grid-cols-2">
            <Input
              label={t('pages.alerts.smtpHost')}
              value={smtpHost}
              onChange={(e) => setSmtpHost(e.target.value)}
            />
            <Input
              label={t('pages.alerts.smtpPort')}
              type="number"
              value={smtpPort}
              onChange={(e) => setSmtpPort(e.target.value)}
            />
            <Input
              label={t('pages.alerts.smtpUser')}
              value={smtpUser}
              onChange={(e) => setSmtpUser(e.target.value)}
            />
            <Input
              label={t('pages.alerts.smtpPass')}
              type="password"
              value={smtpPass}
              onChange={(e) => setSmtpPass(e.target.value)}
            />
            <Select
              label={t('pages.alerts.smtpTls')}
              value={smtpTls}
              onChange={(e) => setSmtpTls(e.target.value)}
              options={['ssl', 'starttls', 'none'].map((value) => ({
                value,
                label: value,
              }))}
            />
            <Input
              label={t('pages.alerts.from')}
              value={from}
              onChange={(e) => setFrom(e.target.value)}
            />
            <div className="sm:col-span-2">
              <Input
                label={t('pages.alerts.to')}
                hint={t('pages.alerts.toHint')}
                value={to}
                onChange={(e) => setTo(e.target.value)}
              />
            </div>
          </div>
        ) : kind === 'telegram' ? (
          <div className="grid gap-3 sm:grid-cols-2">
            <Input
              label={t('pages.alerts.telegramToken')}
              hint={t('pages.alerts.telegramTokenHint')}
              value={botToken}
              onChange={(e) => setBotToken(e.target.value)}
            />
            <Input
              label={t('pages.alerts.telegramChatId')}
              hint={t('pages.alerts.telegramChatIdHint')}
              placeholder="-1001234567890"
              value={chatId}
              onChange={(e) => setChatId(e.target.value)}
            />
          </div>
        ) : (
          <Input
            label={t('pages.alerts.url')}
            hint={t('pages.alerts.urlHint')}
            placeholder="https://…"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        )}
        <PillMultiSelect
          label={t('pages.alerts.events')}
          hint={t('pages.alerts.eventsHint')}
          options={(eventTypes.data ?? []).map((value) => ({
            value,
            label: value,
          }))}
          value={selected}
          onChange={setSelected}
        />
        <Switch
          checked={enabled}
          onCheckedChange={setEnabled}
          label={t('common.enabled')}
        />
        <div className="flex justify-end gap-2 border-t border-line pt-3">
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={save.isPending}
            disabled={!name.trim() || !configFilled}
            onClick={() => save.mutate()}
          >
            {t('common.save')}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}

/** Section pills: deep-linkable anchors (`/alerts#delivery`) with scroll-spy. */
function SectionNav({ items }: { items: { id: string; label: string }[] }) {
  const [active, setActive] = useState(items[0]?.id ?? '')
  const ids = items.map((item) => item.id).join('|')

  // Deep link: /alerts#delivery scrolls to the section once it has painted.
  useEffect(() => {
    const hash = window.location.hash.replace('#', '')
    if (!hash || !items.some((item) => item.id === hash)) return
    const timer = window.setTimeout(() => {
      document
        .getElementById(hash)
        ?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, 80)
    return () => window.clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ids])

  // Scroll-spy: the pill of the section in view lights up.
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) setActive(entry.target.id)
        }
      },
      { rootMargin: '-25% 0px -65% 0px' },
    )
    for (const id of ids.split('|')) {
      const element = document.getElementById(id)
      if (element) observer.observe(element)
    }
    return () => observer.disconnect()
  }, [ids])

  const goTo = (id: string) => {
    setActive(id)
    // Keep the URL shareable without a router round-trip.
    window.history.replaceState(null, '', `#${id}`)
    document
      .getElementById(id)
      ?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="sticky top-16 z-20 flex flex-wrap items-center gap-1.5 rounded-lg border border-line bg-elevated/90 px-2 py-1.5 backdrop-blur">
      {items.map((item) => (
        <button
          key={item.id}
          type="button"
          onClick={() => goTo(item.id)}
          className={cn(
            'rounded-full border px-3 py-1 text-[12px] font-medium transition-colors',
            active === item.id
              ? 'border-brand/40 bg-brand/12 text-brand'
              : 'border-line text-fg-subtle hover:border-brand/40 hover:text-brand',
          )}
        >
          {item.label}
        </button>
      ))}
    </div>
  )
}

function formatSeconds(
  t: (key: string, options?: Record<string, unknown>) => string,
  seconds: number,
): string {
  if (seconds < 3600) return t('pages.alerts.seconds', { n: seconds })
  if (seconds < 86400) return t('pages.alerts.minutes', { n: seconds / 60 })
  return t('pages.alerts.hours', { n: seconds / 3600 })
}

export default AlertsPage
