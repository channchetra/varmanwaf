import { useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowClockwise, Bell, UploadSimple } from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Callout } from '@/components/ui/Callout'
import { Card, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import {
  notificationsApi,
  notificationKeys,
  NOTIFICATION_EVENT_TYPES,
  type NotificationSettings,
} from '@/api/notifications'
import {
  loginSecurityApi,
  type LoginSecuritySettings,
  type LoginSecurityInput,
} from '@/api/loginSecurity'
import { useCanWrite } from '@/hooks'
import { formatDateTime, formatRelative } from '@/lib/format'

const SEVERITY_TONE: Record<string, 'info' | 'warning' | 'danger'> = {
  info: 'info',
  warning: 'warning',
  critical: 'danger',
}

export function NotificationsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const [eventTypeFilter, setEventTypeFilter] = useState('')
  const [eventsOffset, setEventsOffset] = useState(0)

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: notificationKeys.all })
  }

  // Settings and history are administrator-only server-side, so viewers get
  // the overview instead of a wall of 403s. Channel CRUD lives on the Alerts
  // page - one owner for delivery targets.
  const settingsQuery = useQuery({
    queryKey: notificationKeys.settings(),
    queryFn: () => notificationsApi.getSettings(),
    enabled: canWrite,
    retry: false,
  })

  const eventsQuery = useQuery({
    queryKey: notificationKeys.events(eventsOffset),
    queryFn: () =>
      notificationsApi.listEvents(
        50,
        eventsOffset,
        eventTypeFilter || undefined,
      ),
    enabled: canWrite,
    retry: false,
  })

  const events = useMemo(() => eventsQuery.data ?? [], [eventsQuery.data])

  return (
    <>
      <PageHeader
        title={t('pages.notifications.title')}
        description={t('pages.notifications.description')}
      />

      <Callout
        className="mb-4"
        tone="brand"
        icon={<Bell weight="duotone" className="h-5 w-5" />}
        title={t('pages.notifications.overviewTitle')}
      >
        {t('pages.notifications.overview')}
      </Callout>

      {!canWrite ? (
        <Callout
          tone="neutral"
          title={t('pages.notifications.adminOnlyTitle')}
        >
          {t('pages.notifications.adminOnly')}
        </Callout>
      ) : (
        <div className="space-y-4">

        {/* Threshold settings */}
        {settingsQuery.data && (
          <SettingsCard
            settings={settingsQuery.data}
            canWrite={canWrite}
            onSaved={invalidate}
          />
        )}

        {/* Login security */}
        <LoginSecurityCard canWrite={canWrite} />

        {/* Alert history */}
        <Card>
          <CardBody>
            <div className="mb-4 flex flex-wrap items-center gap-3">
              <h3 className="text-base font-semibold text-fg">
                {t('pages.notifications.historyTitle')}
              </h3>
              <Select
                className="w-56"
                value={eventTypeFilter}
                onChange={(e) => {
                  setEventTypeFilter(e.target.value)
                  setEventsOffset(0)
                }}
                options={[
                  { value: '', label: t('pages.notifications.allEvents') },
                  ...NOTIFICATION_EVENT_TYPES.map((type) => ({
                    value: type,
                    label: t(`pages.notifications.event_${type.replace('.', '_')}`),
                  })),
                ]}
              />
              <Button
                size="sm"
                variant="ghost"
                className="ml-auto"
                onClick={() => eventsQuery.refetch()}
              >
                <ArrowClockwise className="h-4 w-4" />
              </Button>
            </div>

            {eventsQuery.isLoading ? (
              <SkeletonRows columns={4} rows={5} />
            ) : eventsQuery.isError ? (
              <ErrorState error={eventsQuery.error} onRetry={() => eventsQuery.refetch()} />
            ) : events.length === 0 ? (
              <EmptyState
                title={t('pages.notifications.noEvents')}
                description={t('pages.notifications.noEventsHint')}
              />
            ) : (
              <>
                <div className="divide-y divide-line">
                  {events.map((event) => (
                    <div key={event.id} className="flex items-start gap-3 py-2.5">
                      <Badge tone={SEVERITY_TONE[event.severity] ?? 'neutral'}>
                        {t(`pages.notifications.severity_${event.severity}`)}
                      </Badge>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-fg" title={event.title}>
                          {event.title}
                        </p>
                        <p className="truncate text-xs text-fg-subtle" title={event.message}>
                          {event.message}
                        </p>
                      </div>
                      <span className="shrink-0 text-xs text-fg-subtle" title={formatDateTime(event.created_at)}>
                        {formatRelative(event.created_at)}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="mt-3 flex justify-end gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={eventsOffset === 0}
                    onClick={() => setEventsOffset((o) => Math.max(0, o - 50))}
                  >
                    {t('pagination.previous')}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={events.length < 50}
                    onClick={() => setEventsOffset((o) => o + 50)}
                  >
                    {t('pagination.next')}
                  </Button>
                </div>
              </>
            )}
          </CardBody>
        </Card>
        </div>
      )}
    </>
  )
}

/* ── Threshold settings ─────────────────────────────────────────── */

/** Event type → the settings key that gates its delivery. */
const EVENT_TOGGLE_KEY: Record<string, keyof NotificationSettings> = {
  'agent.offline': 'notify_agent_offline',
  'agent.online': 'notify_agent_online',
  'agent.resource': 'notify_agent_resource',
  'control_plane.resource': 'notify_control_plane_resource',
  'cert.expiring': 'notify_cert_expiry',
  'cert.expired': 'notify_cert_expiry',
  'cert.renewal_failed': 'notify_cert_renewal_failed',
  'config.sync_failed': 'notify_config_sync_failed',
  'site.failover_changed': 'notify_site_failover_changed',
  'auth.login_anomaly': 'notify_auth_login_anomaly',
}

function SettingsCard({
  settings,
  canWrite,
  onSaved,
}: {
  settings: NotificationSettings
  canWrite: boolean
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()

  const [enabled, setEnabled] = useState(settings.enabled)
  const [cpu, setCpu] = useState(String(settings.cpu_percent))
  const [memory, setMemory] = useState(String(settings.memory_percent))
  const [disk, setDisk] = useState(String(settings.disk_percent))
  const [dedup, setDedup] = useState(String(settings.dedup_window_secs))
  const [certDays, setCertDays] = useState(String(settings.cert_expiry_warn_days))
  const [toggles, setToggles] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {}
    for (const key of new Set(Object.values(EVENT_TOGGLE_KEY))) {
      initial[key] = Boolean(settings[key])
    }
    return initial
  })

  const toggleEventDelivery = (type: string) => {
    const key = EVENT_TOGGLE_KEY[type]
    setToggles((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  const saveMutation = useMutation({
    mutationFn: () =>
      notificationsApi.saveSettings({
        enabled,
        cpu_percent: Number(cpu),
        memory_percent: Number(memory),
        disk_percent: Number(disk),
        dedup_window_secs: Number(dedup),
        cert_expiry_warn_days: Number(certDays),
        ...toggles,
      } as NotificationSettings),
    onSuccess: () => {
      toast.success(t('pages.notifications.settingsSaved'))
      onSaved()
    },
    onError: () => toast.error(t('pages.notifications.settingsSaveFailed')),
  })

  const eventToggleRows = useMemo(() => {
    const seen = new Set<string>()
    return NOTIFICATION_EVENT_TYPES.filter((type) => {
      const key = EVENT_TOGGLE_KEY[type]
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
  }, [])

  return (
    <Card>
      <CardBody>
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-base font-semibold text-fg">
            {t('pages.notifications.settingsTitle')}
          </h3>
          <label className="flex items-center gap-2 text-sm" title={t('pages.notifications.masterEnabledHint')}>
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              disabled={!canWrite}
              className="rounded border-border"
            />
            {t('pages.notifications.masterEnabled')}
          </label>
        </div>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
          <Input
            type="number"
            label={t('pages.notifications.cpuThreshold')}
            value={cpu}
            onChange={(e) => setCpu(e.target.value)}
          />
          <Input
            type="number"
            label={t('pages.notifications.memoryThreshold')}
            value={memory}
            onChange={(e) => setMemory(e.target.value)}
          />
          <Input
            type="number"
            label={t('pages.notifications.diskThreshold')}
            value={disk}
            onChange={(e) => setDisk(e.target.value)}
          />
          <Input
            type="number"
            label={t('pages.notifications.dedupWindow')}
            value={dedup}
            onChange={(e) => setDedup(e.target.value)}
          />
          <Input
            type="number"
            label={t('pages.notifications.certExpiryWarnDays')}
            value={certDays}
            onChange={(e) => setCertDays(e.target.value)}
          />
        </div>
        <p className="mt-2 text-xs text-fg-subtle">
          {t('pages.notifications.settingsHint')}
        </p>

        <div className="mt-4">
          <p className="mb-2 text-sm font-medium text-fg">
            {t('pages.notifications.eventToggles')}
          </p>
          <p className="mb-2 text-xs text-fg-subtle">
            {t('pages.notifications.eventTogglesHint')}
          </p>
          <div className="grid grid-cols-1 gap-1 rounded-md border border-border p-2 md:grid-cols-2">
            {eventToggleRows.map((type) => {
              const key = EVENT_TOGGLE_KEY[type]
              return (
                <label key={type} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={Boolean(toggles[key])}
                    onChange={() => toggleEventDelivery(type)}
                    disabled={!canWrite}
                    className="rounded border-border"
                  />
                  {t(`pages.notifications.event_${type.replace('.', '_')}`)}
                </label>
              )
            })}
          </div>
        </div>

        {canWrite && (
          <div className="mt-4 flex justify-end">
            <Button
              variant="primary"
              disabled={saveMutation.isPending}
              onClick={() => saveMutation.mutate()}
            >
              {t('common.save')}
            </Button>
          </div>
        )}
      </CardBody>
    </Card>
  )
}

/* ── Login security ─────────────────────────────────────────────── */

function LoginSecurityCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const settingsQuery = useQuery({
    queryKey: ['login-security'],
    queryFn: () => loginSecurityApi.getSettings(),
  })

  const historyQuery = useQuery({
    queryKey: ['login-history'],
    queryFn: () => loginSecurityApi.listHistory(10, 0),
  })

  const [anomalyEnabled, setAnomalyEnabled] = useState<boolean | null>(null)
  const [baseline, setBaseline] = useState<string>('')
  const [trustedHeader, setTrustedHeader] = useState<string>('')
  const [trustLastHop, setTrustLastHop] = useState<boolean>(false)
  const [geoUrl, setGeoUrl] = useState<string>('')

  const stored = settingsQuery.data
  const current: LoginSecuritySettings | null = useMemo(() => {
    if (!stored) return null
    return {
      ...stored,
      anomaly_enabled: anomalyEnabled ?? stored.anomaly_enabled,
      baseline_count: baseline === '' ? stored.baseline_count : Number(baseline),
      trusted_header: trustedHeader === '' ? stored.trusted_header : trustedHeader.trim().toLowerCase(),
      trust_last_hop: trustLastHop || stored.trust_last_hop,
      online_geo_url: geoUrl === '' ? stored.online_geo_url : geoUrl.trim(),
    }
  }, [stored, anomalyEnabled, baseline, trustedHeader, trustLastHop, geoUrl])

  const saveMutation = useMutation({
    mutationFn: (payload: LoginSecurityInput) =>
      loginSecurityApi.saveSettings(payload),
    onSuccess: () => {
      toast.success(t('pages.notifications.settingsSaved'))
      queryClient.invalidateQueries({ queryKey: ['login-security'] })
      setAnomalyEnabled(null)
      setBaseline('')
      setTrustedHeader('')
      setTrustLastHop(false)
      setGeoUrl('')
    },
    onError: (error) =>
      toast.error(error.message || t('pages.notifications.settingsSaveFailed')),
  })

  const uploadMutation = useMutation({
    mutationFn: (file: File) => loginSecurityApi.uploadGeoip(file),
    onSuccess: (result) => {
      toast.success(t('pages.notifications.geoipUploaded', { bytes: result.bytes }))
      queryClient.invalidateQueries({ queryKey: ['login-security'] })
    },
    onError: (error) =>
      toast.error(error.message || t('pages.notifications.geoipUploadFailed')),
  })

  const history = useMemo(() => historyQuery.data ?? [], [historyQuery.data])

  return (
    <Card>
      <CardBody>
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-fg">
              {t('pages.notifications.loginSecurityTitle')}
            </h3>
            <p className="text-xs text-fg-subtle">
              {t('pages.notifications.loginSecurityHint')}
            </p>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={current?.anomaly_enabled ?? false}
              onChange={(e) => setAnomalyEnabled(e.target.checked)}
              disabled={!canWrite}
              className="rounded border-border"
            />
            {t('pages.notifications.anomalyEnabled')}
          </label>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
          <Input
            type="number"
            label={t('pages.notifications.anomalyBaseline')}
            value={baseline === '' ? String(current?.baseline_count ?? '') : baseline}
            onChange={(e) => setBaseline(e.target.value)}
          />
          <Input
            label={t('pages.notifications.trustedHeader')}
            value={trustedHeader === '' ? current?.trusted_header ?? '' : trustedHeader}
            onChange={(e) => setTrustedHeader(e.target.value)}
            placeholder="x-forwarded-for"
          />
          <Input
            className="md:col-span-2"
            label={t('pages.notifications.geoUrl')}
            value={geoUrl === '' ? current?.online_geo_url ?? '' : geoUrl}
            onChange={(e) => setGeoUrl(e.target.value)}
            placeholder="http://ip-api.com/json/{ip}?…"
          />
        </div>
        <label className="mt-2 flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={current?.trust_last_hop ?? false}
            onChange={(e) => setTrustLastHop(e.target.checked)}
            disabled={!canWrite}
            className="rounded border-border"
          />
          {t('pages.notifications.trustLastHop')}
        </label>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <input
            ref={fileInputRef}
            type="file"
            accept=".mmdb"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0]
              if (file) uploadMutation.mutate(file)
              e.target.value = ''
            }}
          />
          {canWrite && (
            <Button
              size="sm"
              variant="ghost"
              disabled={uploadMutation.isPending}
              onClick={() => fileInputRef.current?.click()}
            >
              <UploadSimple className="h-4 w-4" />
              {t('pages.notifications.uploadGeoip')}
            </Button>
          )}
          <Badge tone={current?.geoip_local_enabled ? 'success' : 'neutral'}>
            {current?.geoip_local_enabled
              ? t('pages.notifications.geoipLocalOn')
              : t('pages.notifications.geoipLocalOff')}
          </Badge>
          {canWrite && (
            <Button
              size="sm"
              variant="ghost"
              className="ml-auto"
              disabled={saveMutation.isPending || !current}
              onClick={() => current && saveMutation.mutate(current)}
            >
              {t('common.save')}
            </Button>
          )}
        </div>

        {history.length > 0 && (
          <div className="mt-4">
            <p className="mb-2 text-sm font-medium text-fg">
              {t('pages.notifications.loginHistoryTitle')}
            </p>
            <div className="divide-y divide-line rounded-md border border-border">
              {history.slice(0, 8).map((entry) => (
                <div key={entry.id} className="flex items-center gap-3 px-3 py-1.5 text-sm">
                  <span className="w-56 truncate text-fg" title={entry.email}>{entry.email}</span>
                  <span className="text-fg-subtle">{entry.ip}</span>
                  <Badge tone="info">{entry.country_code ?? '—'}</Badge>
                  <span className="truncate text-xs text-fg-subtle" title={entry.city ?? ''}>
                    {[entry.region, entry.city].filter(Boolean).join(' / ')}
                  </span>
                  <span className="ml-auto shrink-0 text-xs text-fg-subtle">
                    {formatRelative(entry.created_at)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardBody>
    </Card>
  )
}
