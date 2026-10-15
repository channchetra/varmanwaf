import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Package,
  Plus,
  Trash,
  WarningCircle,
  ArrowClockwise,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { Switch } from '@/components/ui/Switch'
import { SkeletonStat } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ErrorState'
import { useToast } from '@/components/ui/Toast'
import { errorMessage } from '@/api/errors'
import {
  exclusionsApi,
  exclusionsKeys,
  type ExclusionBinding,
  type ExclusionPackage,
} from '@/api/exclusions'
import { useCanWrite } from '@/hooks'
import { formatDateTime } from '@/lib/format'

/**
 * Exclusion packages: the curated catalogue (WordPress, Next.js static
 * assets, Nextcloud WebDAV, rich-text editors) and the site's bindings.
 * Attaching a package scopes its exclusions to a path prefix; nothing is
 * applied until it is attached, and every entry states what it excludes.
 */
export function ExclusionPackagesPanel() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const packagesQuery = useQuery({
    queryKey: exclusionsKeys.packages(),
    queryFn: () => exclusionsApi.packages(),
  })
  const bindingsQuery = useQuery({
    queryKey: exclusionsKeys.bindings(siteId),
    queryFn: () => exclusionsApi.bindings(siteId),
    enabled: Boolean(siteId),
  })

  const [prefixes, setPrefixes] = useState<Record<string, string>>({})

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: exclusionsKeys.all })
  }

  const attach = useMutation({
    mutationFn: (payload: { key: string; prefix: string }) =>
      exclusionsApi.attach(siteId, payload.key, payload.prefix),
    onSuccess: (binding) => {
      toast.success(
        t('pages.exclusions.attached', {
          name: binding.package_name,
          prefix: binding.path_prefix,
        }),
      )
      setPrefixes((current) => ({ ...current, [binding.package_key]: '' }))
      invalidate()
    },
    onError: (error) =>
      toast.error(t('pages.exclusions.attachFailed'), errorMessage(error)),
  })

  const update = useMutation({
    mutationFn: (payload: {
      id: string
      enabled?: boolean
      reinstall?: boolean
    }) =>
      exclusionsApi.updateBinding(siteId, payload.id, {
        enabled: payload.enabled,
        reinstall: payload.reinstall,
      }),
    onSuccess: () => invalidate(),
    onError: (error) =>
      toast.error(t('pages.exclusions.updateFailed'), errorMessage(error)),
  })

  const remove = useMutation({
    mutationFn: (id: string) => exclusionsApi.removeBinding(siteId, id),
    onSuccess: () => {
      toast.success(t('pages.exclusions.removed'))
      invalidate()
    },
    onError: (error) =>
      toast.error(t('pages.exclusions.removeFailed'), errorMessage(error)),
  })

  if (packagesQuery.isError && !packagesQuery.data) {
    return (
      <ErrorState
        error={packagesQuery.error}
        onRetry={() => packagesQuery.refetch()}
        retrying={packagesQuery.isFetching}
      />
    )
  }
  if (!packagesQuery.data || !bindingsQuery.data) {
    return <SkeletonStat />
  }

  const bindings = bindingsQuery.data

  return (
    <div className="flex flex-col gap-4">
      {/* Attached bindings */}
      <Card>
        <CardHeader
          title={t('pages.exclusions.attachedTitle')}
          description={t('pages.exclusions.attachedHint')}
          action={
            <Badge tone={bindings.length ? 'brand' : 'neutral'} size="sm">
              {bindings.length}
            </Badge>
          }
        />
        <CardBody>
          {bindings.length === 0 ? (
            <p className="py-6 text-center text-sm text-fg-subtle">
              {t('pages.exclusions.noneAttached')}
            </p>
          ) : (
            <ul className="flex flex-col gap-2">
              {bindings.map((binding) => (
                <BindingRow
                  key={binding.id}
                  binding={binding}
                  canWrite={canWrite}
                  pending={update.isPending || remove.isPending}
                  onToggle={(enabled) =>
                    update.mutate({ id: binding.id, enabled })
                  }
                  onReinstall={() =>
                    update.mutate({ id: binding.id, reinstall: true })
                  }
                  onRemove={() => remove.mutate(binding.id)}
                />
              ))}
            </ul>
          )}
        </CardBody>
      </Card>

      {/* Catalogue */}
      <Card>
        <CardHeader
          title={t('pages.exclusions.catalogue')}
          description={t('pages.exclusions.catalogueHint')}
        />
        <CardBody className="flex flex-col gap-4">
          {packagesQuery.data.map((pkg) => (
            <CatalogueRow
              key={pkg.id}
              pkg={pkg}
              canWrite={canWrite}
              prefix={prefixes[pkg.key] ?? ''}
              onPrefixChange={(value) =>
                setPrefixes((current) => ({ ...current, [pkg.key]: value }))
              }
              attaching={
                attach.isPending && attach.variables?.key === pkg.key
              }
              onAttach={() =>
                attach.mutate({
                  key: pkg.key,
                  prefix: prefixes[pkg.key] ?? '',
                })
              }
            />
          ))}
          <p className="text-[11px] text-fg-subtle">
            {t('pages.exclusions.targetsHint')}
          </p>
        </CardBody>
      </Card>
    </div>
  )
}

function BindingRow({
  binding,
  canWrite,
  pending,
  onToggle,
  onReinstall,
  onRemove,
}: {
  binding: ExclusionBinding
  canWrite: boolean
  pending: boolean
  onToggle: (enabled: boolean) => void
  onReinstall: () => void
  onRemove: () => void
}) {
  const { t } = useTranslation()
  return (
    <li className="flex flex-wrap items-center gap-3 rounded-md border border-line bg-recessed/40 px-3 py-2">
      <Switch
        checked={binding.enabled}
        disabled={!canWrite}
        onCheckedChange={onToggle}
        label={binding.package_name}
      />
      <span className="pw-mono text-[13px] text-fg-strong">
        {binding.path_prefix}
      </span>
      <Badge tone="neutral" size="sm">
        v{binding.package_version}
      </Badge>
      {binding.stale && (
        <Badge tone="warning" size="sm">
          {t('pages.exclusions.stale')}
        </Badge>
      )}
      <span className="flex-1 text-[11px] text-fg-subtle">
        {formatDateTime(binding.created_at)}
      </span>
      {binding.stale && canWrite && (
        <Button
          size="sm"
          variant="secondary"
          icon={<ArrowClockwise weight="bold" className="h-3.5 w-3.5" />}
          disabled={pending}
          onClick={onReinstall}
        >
          {t('pages.exclusions.reinstall')}
        </Button>
      )}
      {canWrite && (
        <Button
          size="sm"
          variant="ghost"
          icon={<Trash weight="bold" className="h-3.5 w-3.5" />}
          disabled={pending}
          onClick={onRemove}
        >
          {t('common.delete')}
        </Button>
      )}
    </li>
  )
}

function CatalogueRow({
  pkg,
  canWrite,
  prefix,
  onPrefixChange,
  attaching,
  onAttach,
}: {
  pkg: ExclusionPackage
  canWrite: boolean
  prefix: string
  onPrefixChange: (value: string) => void
  attaching: boolean
  onAttach: () => void
}) {
  const { t } = useTranslation()
  return (
    <div className="rounded-md border border-line px-3 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Package weight="duotone" className="h-4 w-4 text-fg-subtle" />
        <span className="text-[13px] font-semibold text-fg-strong">
          {pkg.name}
        </span>
        <Badge tone={pkg.builtin ? 'brand' : 'neutral'} size="sm">
          {pkg.builtin ? t('pages.exclusions.builtin') : t('pages.exclusions.custom')}
        </Badge>
        <Badge tone="neutral" size="sm">
          v{pkg.version}
        </Badge>
      </div>
      <p className="mt-1 text-[12px] text-fg-subtle">{pkg.description}</p>
      <ul className="mt-2 flex flex-col gap-1">
        {pkg.entries.map((entry, index) => (
          <li key={index} className="text-[12px] text-fg">
            <span className="pw-mono font-medium">
              {entry.rule_id
                ? entry.rule_id
                : `${t('pages.exclusions.selector')}: ${[
                    ...(entry.tags ?? []),
                    ...(entry.severity_min !== undefined
                      ? [`severity>=${entry.severity_min}`]
                      : []),
                  ].join(', ')}`}
            </span>
            <span className="text-fg-subtle">
              {' '}
              — {t('pages.exclusions.excludes')}:{' '}
              <span className="pw-mono">{entry.targets.join(', ')}</span>
            </span>
            {entry.note && (
              <span className="block text-[11px] text-fg-subtle">
                {entry.note}
              </span>
            )}
          </li>
        ))}
      </ul>
      {canWrite && (
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <Input
            containerClassName="w-64"
            className="pw-mono"
            label={t('pages.exclusions.pathPrefix')}
            hint={t('pages.exclusions.pathPrefixHint')}
            placeholder="/wp-admin"
            value={prefix}
            onChange={(event) => onPrefixChange(event.target.value)}
          />
          <Button
            variant="secondary"
            icon={<Plus weight="bold" className="h-4 w-4" />}
            loading={attaching}
            disabled={!prefix.trim().startsWith('/')}
            onClick={onAttach}
          >
            {t('pages.exclusions.attach')}
          </Button>
        </div>
      )}
      {pkg.entries.some((entry) => entry.note === undefined) && (
        <p className="mt-2 flex items-center gap-1.5 text-[11px] text-fg-subtle">
          <WarningCircle weight="duotone" className="h-3.5 w-3.5" />
          {t('pages.exclusions.review')}
        </p>
      )}
    </div>
  )
}

export default ExclusionPackagesPanel
