import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { DownloadSimple, Info, Warning, X } from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ApiError } from '@/api/client'
import { errorMessage } from '@/api/errors'
import { ipGroupsApi, ipGroupKeys } from '@/api/ipGroups'
import {
  ipListsApi,
  ipListKeys,
  type IpListCatalogEntry,
  type IpListImportRequest,
} from '@/api/ipLists'
import { cn } from '@/lib/utils'

const CATEGORIES = ['all', 'country', 'bot', 'vpn', 'asn', 'custom'] as const
type Category = (typeof CATEGORIES)[number]

/**
 * The outcome of the last import, shown inline above the list so an
 * import that failed its first fetch (or hit an existing subscription)
 * stays visible with its fix at hand instead of vanishing as a toast.
 */
type ImportNotice =
  | { kind: 'unsynced'; name: string; groupId: string; error: string }
  | { kind: 'duplicate'; message: string }

/**
 * Browse and import curated IP lists (country blocks, crawler / monitoring
 * ranges, VPN networks, ASN prefixes, custom URLs). Each import creates an
 * IP group subscription; the console shows exactly what the first fetch
 * returned, including the error when a source is unreachable.
 */
export function IpListCatalogDialog({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const [category, setCategory] = useState<Category>('all')
  const [query, setQuery] = useState('')
  const [variant, setVariant] = useState<'compact' | 'detailed'>('compact')
  const [actions, setActions] = useState<Record<string, string>>({})
  // Custom URL panel.
  const [customName, setCustomName] = useState('')
  const [customUrl, setCustomUrl] = useState('')
  const [customSelector, setCustomSelector] = useState('')
  // ASN panel.
  const [asn, setAsn] = useState('')
  // Last import outcome (inline banner above the list).
  const [notice, setNotice] = useState<ImportNotice | null>(null)

  const catalog = useQuery({
    queryKey: ipListKeys.catalog({
      q: query.trim() || undefined,
      category: category === 'all' || category === 'asn' || category === 'custom'
        ? undefined
        : category,
    }),
    queryFn: () =>
      ipListsApi.catalog({
        q: query.trim() || undefined,
        category:
          category === 'all' || category === 'asn' || category === 'custom'
            ? undefined
            : category,
      }),
  })

  const entries = useMemo(
    () =>
      (catalog.data?.entries ?? []).filter((entry) => {
        if (category === 'asn') return entry.category === 'asn'
        if (category === 'custom') return false
        return true
      }),
    [catalog.data, category],
  )

  const runImport = useMutation({
    mutationFn: (payload: IpListImportRequest) => ipListsApi.import(payload),
    onSuccess: (result) => {
      if (result.synced) {
        setNotice(null)
        toast.success(
          t('pages.ipLists.imported'),
          t('pages.ipLists.importedDetail', {
            name: result.group.name,
            ranges: result.group.ip_ranges.length,
          }),
        )
      } else {
        // The group exists, but its first fetch failed. Keep the failure
        // and its remedy on screen instead of a transient toast.
        setNotice({
          kind: 'unsynced',
          name: result.group.name,
          groupId: result.group.id,
          error: result.error ?? result.group.last_sync_error ?? '',
        })
      }
      void queryClient.invalidateQueries({ queryKey: ipGroupKeys.all })
      void queryClient.invalidateQueries({ queryKey: ipListKeys.all })
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 409) {
        setNotice({ kind: 'duplicate', message: errorMessage(error) })
        return
      }
      toast.error(t('pages.ipLists.importFailed'), errorMessage(error))
    },
  })

  const retrySync = useMutation({
    mutationFn: (groupId: string) => ipGroupsApi.sync(groupId),
    onSuccess: (result) => {
      toast.success(
        t('pages.ipLists.retrySucceeded'),
        t('pages.ipLists.importedDetail', {
          name: notice?.kind === 'unsynced' ? notice.name : result.id,
          ranges: result.ip_count,
        }),
      )
      setNotice(null)
      void queryClient.invalidateQueries({ queryKey: ipGroupKeys.all })
      void queryClient.invalidateQueries({ queryKey: ipListKeys.all })
    },
    onError: (error) =>
      setNotice((current) =>
        current && current.kind === 'unsynced'
          ? { ...current, error: errorMessage(error) }
          : current,
      ),
  })

  const actionFor = (entry: IpListCatalogEntry) =>
    actions[entry.id] ?? entry.suggested_action

  const importEntry = (entry: IpListCatalogEntry) =>
    runImport.mutate({
      catalog_id: entry.id,
      variant: entry.category === 'country' ? variant : undefined,
      action: actionFor(entry) as 'block' | 'allow',
    })

  return (
    <Dialog
      open
      onClose={onClose}
      size="xl"
      title={t('pages.ipLists.title')}
      description={t('pages.ipLists.description')}
    >
      <div className="flex min-h-0 flex-1 flex-col">
        {/* Category pills + search */}
        <div className="shrink-0 space-y-3 border-b border-line px-5 py-3">
          <div className="flex flex-wrap items-center gap-1.5">
            {CATEGORIES.map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => setCategory(value)}
                className={cn(
                  'rounded-full border px-3 py-1.5 text-[12px] font-medium transition-colors',
                  category === value
                    ? 'border-brand/40 bg-brand/12 text-brand-ink'
                    : 'border-line text-fg-subtle hover:text-fg',
                )}
              >
                {t(`pages.ipLists.categories.${value}`)}
              </button>
            ))}
            <div className="ml-auto flex items-center gap-2">
              {category === 'all' || category === 'country' ? (
                <Select
                  containerClassName="w-44"
                  value={variant}
                  onChange={(event) =>
                    setVariant(event.target.value as 'compact' | 'detailed')
                  }
                  options={[
                    { value: 'compact', label: t('pages.ipLists.variantCompact') },
                    { value: 'detailed', label: t('pages.ipLists.variantDetailed') },
                  ]}
                />
              ) : null}
              {category !== 'custom' && category !== 'asn' && (
                <Input
                  containerClassName="w-56"
                  placeholder={t('pages.ipLists.searchPlaceholder')}
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                />
              )}
            </div>
          </div>
          {category === 'country' && (
            <p className="text-[12px] text-fg-subtle">
              {t('pages.ipLists.variantHint')}
            </p>
          )}
          {(catalog.data?.notes ?? []).map((note) => (
            <p
              key={note}
              className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-[12px] text-fg"
            >
              <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
              {note}
            </p>
          ))}
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-3">
          {notice && (
            <div
              className={cn(
                'mb-3 rounded-md border px-3 py-2 text-[12px]',
                notice.kind === 'unsynced'
                  ? 'border-warning/40 bg-warning/10'
                  : 'border-focus/30 bg-focus/5',
              )}
            >
              <div className="flex items-start gap-2">
                {notice.kind === 'unsynced' ? (
                  <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
                ) : (
                  <Info weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
                )}
                <div className="min-w-0 flex-1">
                  <p className="font-medium text-fg">
                    {notice.kind === 'unsynced'
                      ? t('pages.ipLists.importedUnsynced')
                      : t('pages.ipLists.duplicateTitle')}
                  </p>
                  <p className="mt-0.5 break-words text-fg-subtle">
                    {notice.kind === 'unsynced'
                      ? `${notice.name}: ${notice.error}`
                      : notice.message}
                  </p>
                  {notice.kind === 'duplicate' && (
                    <p className="mt-0.5 text-fg-subtle">
                      {t('pages.ipLists.duplicateHint')}
                    </p>
                  )}
                </div>
                {notice.kind === 'unsynced' && (
                  <Button
                    size="sm"
                    variant="secondary"
                    loading={retrySync.isPending}
                    onClick={() => retrySync.mutate(notice.groupId)}
                  >
                    {t('pages.ipLists.retrySync')}
                  </Button>
                )}
                <button
                  type="button"
                  onClick={() => setNotice(null)}
                  title={t('common.close')}
                  aria-label={t('common.close')}
                  className="shrink-0 rounded p-0.5 text-fg-subtle transition-colors hover:text-fg"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}

          {category === 'asn' ? (
            <div className="space-y-3">
              <p className="text-[13px] text-fg-subtle">
                {t('pages.ipLists.asnHint')}
              </p>
              <div className="flex items-end gap-2">
                <Input
                  label={t('pages.ipLists.asnLabel')}
                  placeholder="15169"
                  value={asn}
                  onChange={(event) => setAsn(event.target.value)}
                />
                <Button
                  variant="primary"
                  icon={<DownloadSimple className="h-4 w-4" />}
                  loading={runImport.isPending}
                  disabled={!/^\d+$/.test(asn.trim())}
                  onClick={() =>
                    runImport.mutate({
                      catalog_id: `asn:${asn.trim()}`,
                      action: 'block',
                    })
                  }
                >
                  {t('pages.ipLists.import')}
                </Button>
              </div>
              <p className="flex items-start gap-2 rounded-md border border-focus/30 bg-focus/5 px-3 py-2 text-[12px] text-fg-subtle">
                <Info weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
                {t('pages.ipLists.asnAttribution')}
              </p>
            </div>
          ) : category === 'custom' ? (
            <div className="space-y-3">
              <Input
                label={t('pages.ipLists.customName')}
                value={customName}
                onChange={(event) => setCustomName(event.target.value)}
              />
              <Input
                label={t('pages.ipLists.customUrl')}
                hint={t('pages.ipLists.customUrlHint')}
                placeholder="https://example.com/blocklist.txt"
                value={customUrl}
                onChange={(event) => setCustomUrl(event.target.value)}
              />
              <Input
                label={t('pages.ipLists.customSelector')}
                hint={t('pages.ipLists.customSelectorHint')}
                placeholder="prefixes.ipv4,prefixes.ipv6"
                value={customSelector}
                onChange={(event) => setCustomSelector(event.target.value)}
              />
              <div className="flex justify-end">
                <Button
                  variant="primary"
                  icon={<DownloadSimple className="h-4 w-4" />}
                  loading={runImport.isPending}
                  disabled={!customName.trim() || !customUrl.trim()}
                  onClick={() =>
                    runImport.mutate({
                      name: customName.trim(),
                      url: customUrl.trim(),
                      selector: customSelector.trim() || undefined,
                      action: 'block',
                    })
                  }
                >
                  {t('pages.ipLists.import')}
                </Button>
              </div>
            </div>
          ) : catalog.isLoading ? (
            <SkeletonRows rows={6} />
          ) : entries.length === 0 ? (
            <p className="py-8 text-center text-[13px] text-fg-subtle">
              {t('pages.ipLists.noResults')}
            </p>
          ) : (
            <ul className="divide-y divide-line rounded-lg border border-line">
              {entries.map((entry) => (
                <li
                  key={entry.id}
                  className="flex flex-wrap items-start gap-3 px-3 py-3"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[13px] font-medium text-fg-strong">
                        {entry.name}
                      </span>
                      {entry.prefix_count != null && (
                        <Badge tone="neutral">
                          {t('pages.ipLists.prefixes', {
                            n: entry.prefix_count,
                          })}
                        </Badge>
                      )}
                      {entry.authoritative === false && (
                        <Badge tone="warning">
                          {t('pages.ipLists.prefilter')}
                        </Badge>
                      )}
                    </div>
                    <p className="mt-0.5 text-[12px] text-fg-subtle">
                      {entry.description}
                    </p>
                    <p className="mt-0.5 text-[11px] text-fg-subtle/80">
                      {entry.attribution}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Select
                      containerClassName="w-28"
                      value={actionFor(entry)}
                      onChange={(event) =>
                        setActions((current) => ({
                          ...current,
                          [entry.id]: event.target.value,
                        }))
                      }
                      options={[
                        { value: 'block', label: t('pages.ipLists.block') },
                        { value: 'allow', label: t('pages.ipLists.allow') },
                      ]}
                    />
                    <Button
                      size="sm"
                      variant="primary"
                      icon={<DownloadSimple className="h-4 w-4" />}
                      loading={runImport.isPending}
                      onClick={() => importEntry(entry)}
                    >
                      {t('pages.ipLists.import')}
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="shrink-0 border-t border-line px-5 py-2 text-[11px] text-fg-subtle">
          {t('pages.ipLists.footer')}
        </div>
      </div>
    </Dialog>
  )
}

export default IpListCatalogDialog
