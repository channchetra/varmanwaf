import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Select } from '@/components/ui/Select'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { errorMessage } from '@/api/errors'
import { useCanWrite } from '@/hooks'
import { failoverApi, failoverKeys } from '@/api/failover'
import type { FailoverPolicy } from '@/api/types'

/** Select options, ordered from "least specific" to "most explicit". */
const POLICY_OPTIONS: { value: FailoverPolicy; labelKey: string }[] = [
  { value: 'inherit', labelKey: 'pages.sites.failover.policy.inherit' },
  { value: 'open', labelKey: 'pages.sites.failover.policy.open' },
  { value: 'closed', labelKey: 'pages.sites.failover.policy.closed' },
]

/**
 * Disconnected behaviour for one site: what the edge serves while the
 * control plane is unreachable and the host has no synced rule bundle.
 *
 * `inherit` follows the control-plane-wide default (whose current value the
 * hint spells out); `open` / `closed` override it for this site only. The
 * value is pushed to the agents with the next configuration sync, so it is
 * available even when that sync never happens again.
 */
export function FailoverPanel() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const query = useQuery({
    queryKey: failoverKeys.all(siteId),
    queryFn: () => failoverApi.get(siteId),
    enabled: Boolean(siteId),
  })
  // Local override for optimistic UI; falls back to the server value so the
  // form stays editable without mirroring query state into an effect.
  const [override, setOverride] = useState<FailoverPolicy | null>(null)
  const policy = override ?? query.data?.failover_policy ?? null

  const save = useMutation({
    mutationFn: (next: FailoverPolicy) => failoverApi.update(siteId, next),
    onSuccess: (updated) => {
      toast.success(t('pages.sites.failover.saved'))
      setOverride(updated.failover_policy)
      void queryClient.invalidateQueries({
        queryKey: failoverKeys.all(siteId),
      })
    },
    onError: (e) => toast.error(errorMessage(e)),
  })

  if (query.isPending) return <SkeletonCard />
  if (query.isError || !query.data || policy === null) return null

  const defaultHint = query.data.default_fail_open
    ? t('pages.sites.failover.defaultOpen')
    : t('pages.sites.failover.defaultClosed')

  return (
    <Card>
      <CardHeader
        title={t('pages.sites.failover.title')}
        description={t('pages.sites.failover.description')}
      />
      <CardBody>
        <Select
          label={t('pages.sites.failover.policyLabel')}
          hint={
            policy === 'inherit'
              ? defaultHint
              : t('pages.sites.failover.inheritHint', { default: defaultHint })
          }
          value={policy}
          options={POLICY_OPTIONS.map((o) => ({
            value: o.value,
            label: t(o.labelKey),
          }))}
          disabled={!canWrite || save.isPending}
          onChange={(e) => {
            const next = e.target.value as FailoverPolicy
            setOverride(next)
            if (next !== query.data.failover_policy) save.mutate(next)
          }}
        />
      </CardBody>
    </Card>
  )
}

export default FailoverPanel
