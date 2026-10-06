import { useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Gauge,
  Plus,
  PencilSimple,
  Trash,
  ArrowClockwise,
  Lightning,
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
import { PillMultiSelect } from '@/components/ui/MultiSelect'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { rateLimitApi, rateLimitKeys } from '@/api/rateLimiting'
import { siteKeys } from '@/api/sites'
import { useCanWrite } from '@/hooks'
import { formatNumber } from '@/lib/format'
import {
  RATE_LIMIT_CHARACTERISTICS,
  RATE_LIMIT_CHARACTERISTICS_PENDING,
  RULE_ACTIONS,
  isValidRateLimitCharacteristic,
  type CreateRateLimitRequest,
  type RateLimitRule,
} from '@/api/types'

const ACTION_TONE: Record<string, 'danger' | 'warning' | 'info' | 'success' | 'neutral'> = {
  block: 'danger',
  challenge: 'warning',
  js_challenge: 'warning',
  log: 'info',
  allow: 'success',
}

/** Windows the backend accepts (1..86400 seconds), presented as friendly presets. */
const PERIODS = [10, 30, 60, 300, 600, 3600, 86400]

interface FormState {
  name: string
  expression: string
  characteristics: string[]
  period_seconds: number
  threshold: number
  action: string
  mitigation_timeout_seconds: number
  priority: number
  enabled: boolean
}

const emptyForm = (): FormState => ({
  name: '',
  expression: '',
  characteristics: ['ip'],
  period_seconds: 60,
  threshold: 100,
  action: 'challenge',
  mitigation_timeout_seconds: 300,
  priority: 100,
  enabled: true,
})

function formFromRule(rule: RateLimitRule): FormState {
  return {
    name: rule.name,
    expression: rule.expression,
    characteristics: [...(rule.characteristics ?? [])],
    period_seconds: rule.period_seconds,
    threshold: rule.threshold,
    action: rule.action,
    mitigation_timeout_seconds: rule.mitigation_timeout_seconds,
    priority: rule.priority,
    enabled: rule.enabled,
  }
}

export function RateLimitingPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<RateLimitRule | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm())
  const [charDraft, setCharDraft] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<RateLimitRule | null>(null)

  const rulesQuery = useQuery({
    queryKey: rateLimitKeys.list(siteId),
    queryFn: () => rateLimitApi.list(siteId),
    enabled: Boolean(siteId),
  })

  const rules = useMemo(
    () =>
      [...(rulesQuery.data?.items ?? [])].sort(
        (a, b) => a.priority - b.priority || a.name.localeCompare(b.name),
      ),
    [rulesQuery.data],
  )

  // Re-seed the dialog form every time it opens (render-phase reset), so the
  // first paint already shows the right rule instead of the previous one.
  const seedKey = dialogOpen ? (editing?.id ?? 'new') : ''
  const [lastSeedKey, setLastSeedKey] = useState<string | null>(null)
  if (seedKey !== lastSeedKey) {
    setLastSeedKey(seedKey)
    if (dialogOpen) {
      setError(null)
      setCharDraft('')
      setForm(editing ? formFromRule(editing) : emptyForm())
    }
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: rateLimitKeys.all(siteId) })
    void queryClient.invalidateQueries({ queryKey: siteKeys.detail(siteId) })
  }

  const save = useMutation({
    mutationFn: (payload: CreateRateLimitRequest) =>
      editing
        ? rateLimitApi.update(siteId, editing.id, payload)
        : rateLimitApi.create(siteId, payload),
    onSuccess: (saved) => {
      toast.success(
        editing ? t('pages.rateLimiting.ruleUpdated') : t('pages.rateLimiting.ruleCreated'),
        saved.name,
      )
      closeDialog()
      invalidate()
    },
  })

  const toggle = useMutation({
    mutationFn: ({ rule, enabled }: { rule: RateLimitRule; enabled: boolean }) =>
      rateLimitApi.toggleEnabled(siteId, rule.id, enabled),
    onSuccess: () => invalidate(),
  })

  const remove = useMutation({
    mutationFn: (id: string) => rateLimitApi.delete(siteId, id),
    onSuccess: (_data, id) => {
      toast.success(t('pages.rateLimiting.ruleDeleted'), rules.find((r) => r.id === id)?.name)
      setPendingDelete(null)
      invalidate()
    },
  })

  const closeDialog = () => {
    setDialogOpen(false)
    setEditing(null)
    setForm(emptyForm())
    setCharDraft('')
    setError(null)
  }

  const addCharacteristic = () => {
    const value = charDraft.trim()
    if (!value) return
    if (!isValidRateLimitCharacteristic(value)) {
      setError(t('pages.rateLimiting.characteristicFormatInvalid'))
      return
    }
    setError(null)
    setForm((f) =>
      f.characteristics.includes(value)
        ? f
        : { ...f, characteristics: [...f.characteristics, value] },
    )
    setCharDraft('')
  }

  const submit = () => {
    setError(null)
    const name = form.name.trim()
    if (!name) {
      setError(t('pages.rateLimiting.nameRequired'))
      return
    }
    if (form.characteristics.length === 0) {
      setError(t('pages.rateLimiting.characteristicsRequired'))
      return
    }
    if (!form.characteristics.every(isValidRateLimitCharacteristic)) {
      setError(t('pages.rateLimiting.characteristicFormatInvalid'))
      return
    }
    if (!Number.isFinite(form.threshold) || form.threshold < 1 || form.threshold > 10_000_000) {
      setError(t('pages.rateLimiting.thresholdInvalid'))
      return
    }
    if (!Number.isFinite(form.period_seconds) || form.period_seconds < 1 || form.period_seconds > 86_400) {
      setError(t('pages.rateLimiting.periodInvalid'))
      return
    }
    if (
      !Number.isFinite(form.mitigation_timeout_seconds) ||
      form.mitigation_timeout_seconds < 0 ||
      form.mitigation_timeout_seconds > 86_400
    ) {
      setError(t('pages.rateLimiting.mitigationInvalid'))
      return
    }
    save.mutate({
      name,
      expression: form.expression.trim(),
      characteristics: form.characteristics,
      period_seconds: form.period_seconds,
      threshold: form.threshold,
      action: form.action,
      mitigation_timeout_seconds: form.mitigation_timeout_seconds,
      priority: Number.isFinite(form.priority) ? form.priority : 0,
      enabled: form.enabled,
    })
  }

  const columns: Column<RateLimitRule>[] = [
    {
      key: 'name',
      header: t('common.name'),
      accessor: (r) => r.name,
      sortable: true,
      cell: (r) => (
        <div className="min-w-0">
          <p className="truncate text-[13px] font-medium text-fg-strong">{r.name}</p>
          <p className="pw-mono truncate text-xs text-fg-subtle">
            {r.expression || t('pages.rateLimiting.allRequests')}
          </p>
        </div>
      ),
    },
    {
      key: 'characteristics',
      header: t('pages.rateLimiting.characteristics'),
      width: '1%',
      cell: (r) => (
        <div className="flex max-w-[220px] flex-wrap gap-1">
          {(r.characteristics ?? []).map((c) => (
            <span
              key={c}
              className="pw-mono rounded border border-line bg-recessed px-1.5 py-px text-[10px] text-fg-subtle"
            >
              {c}
            </span>
          ))}
        </div>
      ),
    },
    {
      key: 'limit',
      header: t('pages.rateLimiting.limit'),
      align: 'right',
      width: '1%',
      cell: (r) => (
        <div className="text-right">
          <p className="tabular-nums text-[13px] font-medium text-fg-strong">
            {formatNumber(r.threshold)}
          </p>
          <p className="text-[11px] text-fg-subtle">
            {t('pages.rateLimiting.perSeconds', { seconds: r.period_seconds })}
          </p>
        </div>
      ),
    },
    {
      key: 'action',
      header: t('pages.waf.action'),
      accessor: (r) => r.action,
      width: '1%',
      cell: (r) => (
        <Badge tone={ACTION_TONE[r.action] ?? 'neutral'}>
          {t(`actions.${r.action}`, r.action)}
        </Badge>
      ),
    },
    {
      key: 'mitigation',
      header: t('pages.rateLimiting.mitigation'),
      accessor: (r) => r.mitigation_timeout_seconds,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span className="tabular-nums text-[13px] text-fg-subtle">
          {r.mitigation_timeout_seconds > 0
            ? t('pages.rateLimiting.seconds', { seconds: r.mitigation_timeout_seconds })
            : t('pages.rateLimiting.untilReset')}
        </span>
      ),
    },
    {
      key: 'priority',
      header: t('common.priority'),
      accessor: (r) => r.priority,
      sortable: true,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span className="pw-mono tabular-nums text-xs text-fg-subtle">{r.priority}</span>
      ),
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
          disabled={!canWrite || toggle.isPending}
          aria-label={`${t('common.enabled')}: ${r.name}`}
          onCheckedChange={(enabled) => toggle.mutate({ rule: r, enabled })}
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
            onClick={() => {
              setEditing(r)
              setDialogOpen(true)
            }}
            icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            onClick={() => setPendingDelete(r)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  const activeCount = rules.filter((r) => r.enabled).length

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.rateLimiting.title')}
        description={t('pages.rateLimiting.description')}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              loading={rulesQuery.isFetching}
              onClick={() => rulesQuery.refetch()}
              icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
            >
              {t('common.refresh')}
            </Button>
            {canWrite && (
              <Button
                variant="primary"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={() => {
                  setEditing(null)
                  setDialogOpen(true)
                }}
              >
                {t('pages.rateLimiting.addRule')}
              </Button>
            )}
          </div>
        }
      />

      {rules.length > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-4 rounded-lg border border-line bg-elevated px-4 py-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-soft text-brand">
            <Lightning weight="duotone" className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-fg-strong">
              {t('pages.rateLimiting.summary', { active: activeCount, total: rules.length })}
            </p>
            <p className="text-xs text-fg-subtle">{t('pages.rateLimiting.summaryHint')}</p>
          </div>
        </div>
      )}

      {rulesQuery.isError && !rulesQuery.data ? (
        <ErrorState
          error={rulesQuery.error}
          onRetry={() => rulesQuery.refetch()}
          retrying={rulesQuery.isFetching}
        />
      ) : (
        <Card>
          <CardHeader
            title={t('pages.rateLimiting.rulesTitle')}
            description={t('pages.rateLimiting.rulesHint')}
          />
          <CardBody className="p-0">
            {rulesQuery.isPending ? (
              <SkeletonRows rows={5} columns={7} />
            ) : rules.length === 0 ? (
              <EmptyState
                className="py-12"
                icon={<Gauge weight="duotone" className="h-8 w-8" />}
                title={t('pages.rateLimiting.empty')}
                description={t('pages.rateLimiting.emptyDescription')}
                action={
                  canWrite ? (
                    <Button
                      variant="primary"
                      icon={<Plus weight="bold" className="h-4 w-4" />}
                      onClick={() => {
                        setEditing(null)
                        setDialogOpen(true)
                      }}
                    >
                      {t('pages.rateLimiting.addRule')}
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <Table
                columns={columns}
                data={rules}
                rowKey={(r) => r.id}
                dense
                onRowClick={
                  canWrite
                    ? (r) => {
                        setEditing(r)
                        setDialogOpen(true)
                      }
                    : undefined
                }
              />
            )}
          </CardBody>
        </Card>
      )}

      {/* Create / edit */}
      <Dialog
        open={dialogOpen}
        onClose={save.isPending ? () => undefined : closeDialog}
        size="lg"
        title={editing ? t('pages.rateLimiting.editRule') : t('pages.rateLimiting.addRule')}
        description={t('pages.rateLimiting.dialogDescription')}
        footer={
          <>
            <Button variant="ghost" onClick={closeDialog} disabled={save.isPending}>
              {t('common.cancel')}
            </Button>
            <Button variant="primary" onClick={submit} loading={save.isPending}>
              {editing ? t('common.save') : t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Input
            label={t('common.name')}
            value={form.name}
            autoFocus
            placeholder={t('pages.rateLimiting.namePlaceholder')}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            required
          />

          <Input
            label={t('pages.waf.expression')}
            value={form.expression}
            className="pw-mono text-[13px]"
            placeholder='http.request.uri.path starts_with "/api"'
            hint={t('pages.rateLimiting.expressionHint')}
            onChange={(e) => setForm((f) => ({ ...f, expression: e.target.value }))}
          />

          <PillMultiSelect
            label={t('pages.rateLimiting.characteristics')}
            hint={t('pages.rateLimiting.characteristicsHint')}
            min={1}
            value={form.characteristics}
            onChange={(characteristics) => setForm((f) => ({ ...f, characteristics }))}
            options={[
              ...RATE_LIMIT_CHARACTERISTICS.map((c) => {
                const pending = RATE_LIMIT_CHARACTERISTICS_PENDING.includes(c)
                return {
                  value: c,
                  label: pending
                    ? `${t(`characteristics.${c}`, c)} (${t('common.comingSoon')})`
                    : t(`characteristics.${c}`, c),
                  disabled: pending,
                }
              }),
              // Parameterized (and legacy) values arrive from the API rather
              // than the fixed pill list.
              ...form.characteristics
                .filter((c) => !(RATE_LIMIT_CHARACTERISTICS as string[]).includes(c))
                .map((c) => ({ value: c, label: c })),
            ]}
          />

          <div className="flex items-end gap-2">
            <Input
              className="pw-mono flex-1 text-[13px]"
              aria-label={t('pages.rateLimiting.characteristicsCustomLabel')}
              placeholder="header:X-Api-Key"
              value={charDraft}
              hint={t('pages.rateLimiting.characteristicsCustomHint')}
              onChange={(e) => setCharDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  addCharacteristic()
                }
              }}
            />
            <Button variant="ghost" onClick={addCharacteristic} disabled={!charDraft.trim()}>
              {t('common.add')}
            </Button>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Input
              type="number"
              label={t('pages.rateLimiting.threshold')}
              value={form.threshold}
              min={1}
              max={10000000}
              hint={t('pages.rateLimiting.thresholdHint')}
              onChange={(e) => setForm((f) => ({ ...f, threshold: Number(e.target.value) }))}
            />
            <div>
              <Select
                label={t('pages.rateLimiting.period')}
                value={String(form.period_seconds)}
                options={PERIODS.map((p) => ({
                  value: String(p),
                  label:
                    p >= 3600
                      ? t('pages.rateLimiting.hours', { hours: p / 3600 })
                      : t('pages.rateLimiting.seconds', { seconds: p }),
                }))}
                onChange={(e) =>
                  setForm((f) => ({ ...f, period_seconds: Number(e.target.value) }))
                }
              />
              <Input
                type="number"
                className="mt-2 h-8 text-xs"
                aria-label={t('pages.rateLimiting.periodSeconds')}
                value={form.period_seconds}
                min={1}
                max={86400}
                hint={t('pages.rateLimiting.periodSecondsHint')}
                onChange={(e) =>
                  setForm((f) => ({ ...f, period_seconds: Number(e.target.value) }))
                }
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Select
              label={t('pages.waf.action')}
              value={form.action}
              options={RULE_ACTIONS.map((a) => ({ value: a, label: t(`actions.${a}`, a) }))}
              onChange={(e) => setForm((f) => ({ ...f, action: e.target.value }))}
            />
            <Input
              type="number"
              label={t('pages.rateLimiting.mitigationTimeout')}
              value={form.mitigation_timeout_seconds}
              min={0}
              max={86400}
              hint={t('pages.rateLimiting.mitigationHint')}
              onChange={(e) =>
                setForm((f) => ({
                  ...f,
                  mitigation_timeout_seconds: Number(e.target.value),
                }))
              }
            />
            <Input
              type="number"
              label={t('common.priority')}
              value={form.priority}
              min={0}
              onChange={(e) => setForm((f) => ({ ...f, priority: Number(e.target.value) }))}
            />
          </div>

          <Switch
            checked={form.enabled}
            onCheckedChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
            label={t('common.enabled')}
            description={t('pages.rateLimiting.enabledHint')}
          />

          {error && (
            <p
              role="alert"
              className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
            >
              {error}
            </p>
          )}
        </div>
      </Dialog>

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete.id)}
        title={t('pages.rateLimiting.deleteTitle')}
        description={t('pages.rateLimiting.deleteDescription')}
        confirmLabel={t('common.delete')}
        loading={remove.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDelete.name}</p>
            <p className="mt-0.5 text-xs text-fg-subtle">
              {t('pages.rateLimiting.deleteMeta', {
                threshold: formatNumber(pendingDelete.threshold),
                seconds: pendingDelete.period_seconds,
              })}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </div>
  )
}

export default RateLimitingPage
