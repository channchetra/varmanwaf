import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Prohibit, ShieldWarning } from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { Table, type Column } from '@/components/ui/Table'
import { ErrorState } from '@/components/ErrorState'
import { blockedIpsApi, blockedIpKeys } from '@/api/blockedIps'
import type { BlockedIp } from '@/api/types'
import { useCanWrite } from '@/hooks'
import { formatDateTime, formatNumber, formatRelative } from '@/lib/format'

/**
 * Lists the IPs the edge currently refuses for this site — WAF/rate-limit
 * auto-blocks and server-issued block commands — with per-IP attack history
 * and a one-click unblock. Blocks appear and expire without user action, so
 * the list polls on a short interval.
 */
export function AutoBlockedIpsCard({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const [pendingUnblock, setPendingUnblock] = useState<BlockedIp | null>(null)

  const query = useQuery({
    queryKey: blockedIpKeys.list(siteId),
    queryFn: () => blockedIpsApi.list(siteId),
    enabled: Boolean(siteId),
    refetchInterval: 30_000,
  })

  const unblock = useMutation({
    mutationFn: (ip: string) => blockedIpsApi.unblock(siteId, ip),
    onSuccess: (result) => {
      toast.success(t('pages.ipRules.autoBlocked.unblocked'), result.ip)
      setPendingUnblock(null)
      void queryClient.invalidateQueries({
        queryKey: blockedIpKeys.all(siteId),
      })
    },
    onError: (e) =>
      toast.error(
        e instanceof Error ? e.message : String(e),
      ),
  })

  const items = query.data ?? []

  const columns: Column<BlockedIp>[] = [
    {
      key: 'ip',
      header: t('pages.ipRules.autoBlocked.ip'),
      accessor: (r) => r.ip,
      cell: (r) => (
        <div className="min-w-0">
          <p className="pw-mono truncate text-[13px] font-medium text-fg-strong">
            {r.ip}
          </p>
          {r.reason && (
            <p className="line-clamp-1 text-xs text-fg-subtle">{r.reason}</p>
          )}
        </div>
      ),
    },
    {
      key: 'attack_count',
      header: t('pages.ipRules.autoBlocked.attacks'),
      accessor: (r) => r.attack_count,
      sortable: true,
      width: '1%',
      cell: (r) => (
        <Badge tone="danger">{formatNumber(r.attack_count)}</Badge>
      ),
    },
    {
      key: 'last_attack_at',
      header: t('pages.ipRules.autoBlocked.lastAttack'),
      accessor: (r) => r.last_attack_at ?? '',
      sortable: true,
      width: '1%',
      cell: (r) =>
        r.last_attack_at ? (
          <span
            className="text-[13px] text-fg-subtle"
            title={formatDateTime(r.last_attack_at)}
          >
            {formatRelative(r.last_attack_at)}
          </span>
        ) : (
          <span className="text-[13px] text-fg-subtle">—</span>
        ),
    },
    {
      key: 'expires_at',
      header: t('pages.ipRules.autoBlocked.expiresAt'),
      accessor: (r) => r.expires_at ?? '',
      width: '1%',
      cell: (r) =>
        r.expires_at ? (
          <div className="text-right sm:text-left">
            <p
              className="text-[13px] text-fg-strong"
              title={formatDateTime(r.expires_at)}
            >
              {formatRelative(r.expires_at)}
            </p>
            <p className="text-xs text-fg-subtle">
              {formatDateTime(r.expires_at)}
            </p>
          </div>
        ) : (
          <Badge tone="neutral">
            {t('pages.ipRules.autoBlocked.permanent')}
          </Badge>
        ),
    },
    {
      key: 'row-actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (r) => (
        <Button
          size="sm"
          variant="secondary"
          disabled={!canWrite}
          onClick={(e) => {
            e.stopPropagation()
            setPendingUnblock(r)
          }}
        >
          {t('pages.ipRules.autoBlocked.unblock')}
        </Button>
      ),
    },
  ]

  return (
    <Card>
      <CardHeader
        title={t('pages.ipRules.autoBlocked.title')}
        description={t('pages.ipRules.autoBlocked.description')}
      />
      <CardBody className="p-0">
        {query.isError && !query.data ? (
          <ErrorState
            error={query.error}
            onRetry={() => query.refetch()}
            retrying={query.isFetching}
          />
        ) : query.isPending ? (
          <SkeletonRows rows={3} columns={5} />
        ) : items.length === 0 ? (
          <EmptyState
            className="border-0 py-10"
            icon={<ShieldWarning weight="duotone" className="h-8 w-8" />}
            title={t('pages.ipRules.autoBlocked.empty')}
            description={t('pages.ipRules.autoBlocked.emptyDescription')}
          />
        ) : (
          <Table
            columns={columns}
            data={items}
            rowKey={(r) => r.ip}
            dense
          />
        )}
      </CardBody>

      <ConfirmDialog
        open={pendingUnblock !== null}
        onClose={() => setPendingUnblock(null)}
        onConfirm={() => pendingUnblock && unblock.mutate(pendingUnblock.ip)}
        title={t('pages.ipRules.autoBlocked.unblockTitle')}
        description={t('pages.ipRules.autoBlocked.unblockDescription')}
        confirmLabel={t('pages.ipRules.autoBlocked.unblock')}
        loading={unblock.isPending}
      >
        {pendingUnblock && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono flex items-center gap-2 text-[13px] font-medium text-fg-strong">
              <Prohibit weight="duotone" className="h-4 w-4 text-fg-danger" />
              {pendingUnblock.ip}
            </p>
            {pendingUnblock.reason && (
              <p className="mt-0.5 text-xs text-fg-subtle">
                {pendingUnblock.reason}
              </p>
            )}
          </div>
        )}
      </ConfirmDialog>
    </Card>
  )
}

export default AutoBlockedIpsCard
