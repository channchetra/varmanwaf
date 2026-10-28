import { useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  PencilSimple,
  Plus,
  Plugs,
  Trash,
  WarningCircle,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { Textarea } from '@/components/ui/Textarea'
import { ErrorState } from '@/components/ErrorState'
import { sitesApi, siteKeys } from '@/api/sites'
import { errorMessage } from '@/api/errors'
import { useCanWrite } from '@/hooks'
import { formatDateTime } from '@/lib/format'
import type {
  CreatePortForwardRequest,
  PortForward,
  UpdatePortForwardRequest,
} from '@/api/types'

const PORT_MIN = 10_000
const PORT_MAX = 10_099

interface FormState {
  name: string
  listenPort: string
  targetHost: string
  targetPort: string
  allowed: string
  enabled: boolean
}

const emptyForm = (): FormState => ({
  name: '',
  listenPort: String(PORT_MIN),
  targetHost: '',
  targetPort: '22',
  allowed: '',
  enabled: true,
})

function formFromForward(forward: PortForward): FormState {
  return {
    name: forward.name,
    listenPort: String(forward.listen_port),
    targetHost: forward.target_host,
    targetPort: String(forward.target_port),
    allowed: forward.allowed_cidrs.join('\n'),
    enabled: forward.enabled,
  }
}

function parseAllowed(raw: string): string[] {
  const values = raw
    .split(/[\n,]+/)
    .map((value) => value.trim())
    .filter(Boolean)
  return [...new Set(values)]
}

/**
 * Per-site TCP port forwards: listen on a published edge port and copy bytes
 * to a private host:port. The agent enforces the source allowlist.
 */
export function PortForwardingPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<PortForward | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm())
  const [formError, setFormError] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<PortForward | null>(null)

  const forwardsQuery = useQuery({
    queryKey: siteKeys.portForwards(siteId),
    queryFn: () => sitesApi.listPortForwards(siteId),
    enabled: Boolean(siteId),
  })
  const forwards = useMemo(
    () => forwardsQuery.data ?? [],
    [forwardsQuery.data],
  )

  const save = useMutation({
    mutationFn: (data: {
      id?: string
      create?: CreatePortForwardRequest
      update?: UpdatePortForwardRequest
    }) =>
      data.id
        ? sitesApi.updatePortForward(siteId, data.id, data.update ?? {})
        : sitesApi.createPortForward(siteId, data.create!),
    onSuccess: (forward, vars) => {
      toast.success(
        vars.id
          ? t('pages.portForwards.updated')
          : t('pages.portForwards.created'),
        forward.name,
      )
      setDialogOpen(false)
      setEditing(null)
      setForm(emptyForm())
      void queryClient.invalidateQueries({
        queryKey: siteKeys.portForwards(siteId),
      })
    },
    onError: (e) => setFormError(errorMessage(e)),
  })

  const remove = useMutation({
    mutationFn: (id: string) => sitesApi.deletePortForward(siteId, id),
    onSuccess: () => {
      toast.success(t('pages.portForwards.deleted'), pendingDelete?.name)
      setPendingDelete(null)
      void queryClient.invalidateQueries({
        queryKey: siteKeys.portForwards(siteId),
      })
    },
    onError: (e) =>
      toast.error(t('pages.portForwards.deleteFailed'), errorMessage(e)),
  })

  const openCreate = () => {
    setEditing(null)
    setForm(emptyForm())
    setFormError(null)
    setDialogOpen(true)
  }

  const openEdit = (forward: PortForward) => {
    setEditing(forward)
    setForm(formFromForward(forward))
    setFormError(null)
    setDialogOpen(true)
  }

  const submit = () => {
    const name = form.name.trim()
    if (!name) {
      setFormError(t('pages.portForwards.errors.name'))
      return
    }
    const listenPort = Number.parseInt(form.listenPort, 10)
    if (
      Number.isNaN(listenPort) ||
      listenPort < PORT_MIN ||
      listenPort > PORT_MAX
    ) {
      setFormError(
        t('pages.portForwards.errors.listenPort', {
          min: PORT_MIN,
          max: PORT_MAX,
        }),
      )
      return
    }
    const targetHost = form.targetHost.trim()
    if (!targetHost) {
      setFormError(t('pages.portForwards.errors.targetHost'))
      return
    }
    const targetPort = Number.parseInt(form.targetPort, 10)
    if (Number.isNaN(targetPort) || targetPort < 1 || targetPort > 65_535) {
      setFormError(t('pages.portForwards.errors.targetPort'))
      return
    }
    const allowed = parseAllowed(form.allowed)
    if (allowed.length === 0) {
      setFormError(t('pages.portForwards.errors.allowed'))
      return
    }
    const payload = {
      name,
      listen_port: listenPort,
      target_host: targetHost,
      target_port: targetPort,
      allowed_cidrs: allowed,
      enabled: form.enabled,
    }
    if (editing) {
      save.mutate({ id: editing.id, update: payload })
    } else {
      save.mutate({ create: payload })
    }
  }

  const columns: Column<PortForward>[] = [
    {
      key: 'name',
      header: t('common.name'),
      accessor: (row) => row.name,
      sortable: true,
      cell: (row) => (
        <div className="flex items-center gap-2">
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded bg-brand-soft text-brand-ink">
            <Plugs weight="duotone" className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <p className="truncate text-[13px] font-medium text-fg-strong">
              {row.name}
            </p>
            <Badge
              tone={row.enabled ? 'success' : 'neutral'}
              size="sm"
              dot
            >
              {row.enabled
                ? t('pages.portForwards.enabled')
                : t('pages.portForwards.disabled')}
            </Badge>
          </div>
        </div>
      ),
    },
    {
      key: 'listen_port',
      header: t('pages.portForwards.listenPort'),
      accessor: (row) => row.listen_port,
      sortable: true,
      width: '120px',
      cell: (row) => (
        <span className="pw-mono text-[13px] text-fg">
          {row.listen_port}
        </span>
      ),
    },
    {
      key: 'target',
      header: t('pages.portForwards.target'),
      accessor: (row) => `${row.target_host}:${row.target_port}`,
      cell: (row) => (
        <span className="pw-mono text-[13px] text-fg">
          {row.target_host}:{row.target_port}
        </span>
      ),
    },
    {
      key: 'allowed',
      header: t('pages.portForwards.allowed'),
      accessor: (row) => row.allowed_cidrs.join(', '),
      cell: (row) => (
        <div className="flex flex-wrap gap-1">
          {row.allowed_cidrs.slice(0, 2).map((cidr) => (
            <Badge key={cidr} tone="neutral" size="sm">
              {cidr}
            </Badge>
          ))}
          {row.allowed_cidrs.length > 2 && (
            <Badge tone="neutral" size="sm">
              +{row.allowed_cidrs.length - 2}
            </Badge>
          )}
        </div>
      ),
    },
    {
      key: 'updated_at',
      header: t('pages.portForwards.updatedToast'),
      accessor: (row) => row.updated_at,
      sortable: true,
      width: '170px',
      cell: (row) => (
        <span className="text-[13px] text-fg-subtle">
          {formatDateTime(row.updated_at)}
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (row) => (
        <div
          className="flex items-center justify-end gap-1"
          onClick={(event) => event.stopPropagation()}
        >
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('common.edit')}
            disabled={!canWrite}
            onClick={() => openEdit(row)}
            icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            onClick={() => setPendingDelete(row)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('pages.portForwards.title')}
        description={t('pages.portForwards.description')}
        actions={
          canWrite ? (
            <Button
              variant="primary"
              icon={<Plus weight="bold" className="h-4 w-4" />}
              onClick={openCreate}
            >
              {t('pages.portForwards.add')}
            </Button>
          ) : undefined
        }
      />

      <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/8 px-3 py-2.5 text-[13px] text-fg">
        <WarningCircle
          weight="duotone"
          className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning"
        />
        <p>{t('pages.portForwards.warning')}</p>
      </div>

      {forwardsQuery.isError && !forwardsQuery.data ? (
        <ErrorState
          error={forwardsQuery.error}
          onRetry={() => forwardsQuery.refetch()}
          retrying={forwardsQuery.isFetching}
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            {forwardsQuery.isPending ? (
              <SkeletonRows rows={4} columns={5} />
            ) : forwards.length === 0 ? (
              <EmptyState
                className="border-0 py-12"
                icon={<Plugs weight="duotone" className="h-8 w-8" />}
                title={t('pages.portForwards.empty')}
                description={t('pages.portForwards.emptyDescription')}
                action={
                  canWrite ? (
                    <Button
                      variant="primary"
                      icon={<Plus weight="bold" className="h-4 w-4" />}
                      onClick={openCreate}
                    >
                      {t('pages.portForwards.add')}
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <Table
                columns={columns}
                data={forwards}
                rowKey={(row) => row.id}
                dense
                onRowClick={canWrite ? (row) => openEdit(row) : undefined}
              />
            )}
          </CardBody>
        </Card>
      )}

      <Dialog
        open={dialogOpen}
        onClose={
          save.isPending ? () => undefined : () => setDialogOpen(false)
        }
        title={
          editing
            ? t('pages.portForwards.edit')
            : t('pages.portForwards.add')
        }
        description={t('pages.portForwards.dialogDescription')}
        size="lg"
        footer={
          <>
            <Button
              variant="ghost"
              disabled={save.isPending}
              onClick={() => setDialogOpen(false)}
            >
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              loading={save.isPending}
              onClick={submit}
            >
              {editing ? t('common.save') : t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Input
            label={t('pages.portForwards.name')}
            value={form.name}
            placeholder="SSH to lab server"
            onChange={(e) =>
              setForm((current) => ({ ...current, name: e.target.value }))
            }
            required
          />
          <div className="grid gap-4 sm:grid-cols-3">
            <Input
              label={t('pages.portForwards.listenPort')}
              type="number"
              min={PORT_MIN}
              max={PORT_MAX}
              value={form.listenPort}
              hint={t('pages.portForwards.listenPortHint', {
                min: PORT_MIN,
                max: PORT_MAX,
              })}
              containerClassName="pw-mono"
              onChange={(e) =>
                setForm((current) => ({
                  ...current,
                  listenPort: e.target.value,
                }))
              }
            />
            <Input
              label={t('pages.portForwards.targetHost')}
              value={form.targetHost}
              placeholder="10.1.18.200"
              containerClassName="pw-mono"
              onChange={(e) =>
                setForm((current) => ({
                  ...current,
                  targetHost: e.target.value,
                }))
              }
            />
            <Input
              label={t('pages.portForwards.targetPort')}
              type="number"
              min={1}
              max={65_535}
              value={form.targetPort}
              placeholder="22"
              containerClassName="pw-mono"
              onChange={(e) =>
                setForm((current) => ({
                  ...current,
                  targetPort: e.target.value,
                }))
              }
            />
          </div>
          <Textarea
            label={t('pages.portForwards.allowed')}
            hint={t('pages.portForwards.allowedHint')}
            mono
            rows={3}
            placeholder={'203.0.113.7\n10.0.0.0/8'}
            value={form.allowed}
            onChange={(e) =>
              setForm((current) => ({
                ...current,
                allowed: e.target.value,
              }))
            }
          />
          <div className="rounded-lg border border-line bg-recessed/40 px-3 py-2.5">
            <Switch
              checked={form.enabled}
              onCheckedChange={(enabled) =>
                setForm((current) => ({ ...current, enabled }))
              }
              label={t('pages.portForwards.enabled')}
              description={t('pages.portForwards.enabledHint')}
            />
          </div>
          <p className="text-xs text-fg-subtle">
            {t('pages.portForwards.encryptionHint')}
          </p>
          {formError && (
            <p
              role="alert"
              className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
            >
              {formError}
            </p>
          )}
        </div>
      </Dialog>

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete.id)}
        title={t('pages.portForwards.deleteTitle')}
        description={t('pages.portForwards.deleteDescription')}
        loading={remove.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono text-[13px] font-medium text-fg-strong">
              {pendingDelete.name} · {pendingDelete.listen_port} →{' '}
              {pendingDelete.target_host}:{pendingDelete.target_port}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </div>
  )
}

export default PortForwardingPage
