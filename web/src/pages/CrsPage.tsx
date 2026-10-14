import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { DownloadSimple, SealCheck, Trash } from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Callout } from '@/components/ui/Callout'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Dialog } from '@/components/ui/Dialog'
import { Input } from '@/components/ui/Input'
import { Pagination } from '@/components/ui/Pagination'
import { Select } from '@/components/ui/Select'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { useCanWrite } from '@/hooks'
import {
  crsApi,
  crsKeys,
  type CrsRule,
  type CrsRuleset,
} from '@/api/crs'

/**
 * CRS rulesets: import an archive (GitHub release or URL), then browse the
 * parsed rule catalogue with file/line provenance. Rules this engine cannot
 * compile stay visible with their error instead of being dropped.
 */
export function CrsPage() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const toast = useToast()
  const queryClient = useQueryClient()
  const [importOpen, setImportOpen] = useState(false)
  const [selected, setSelected] = useState<CrsRuleset | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<CrsRuleset | null>(null)

  const list = useQuery({
    queryKey: crsKeys.list(),
    queryFn: () => crsApi.rulesets(),
  })

  const remove = useMutation({
    mutationFn: (id: string) => crsApi.remove(id),
    onSuccess: () => {
      toast.success(t('pages.crs.deleted'))
      setDeleteTarget(null)
      if (selected) setSelected(null)
      void queryClient.invalidateQueries({ queryKey: crsKeys.all })
    },
    onError: (error) => toast.error(t('pages.crs.deleteFailed'), String(error)),
  })

  if (list.isError && !list.data) {
    return (
      <div className="animate-slide-up">
        <ErrorState
          error={list.error}
          onRetry={() => list.refetch()}
          retrying={list.isFetching}
        />
      </div>
    )
  }

  const rulesets = list.data ?? []

  return (
    <div className="animate-slide-up space-y-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold text-fg-strong">
            {t('pages.crs.title')}
          </h1>
          <p className="mt-1 text-[13px] text-fg-subtle">
            {t('pages.crs.description')}
          </p>
        </div>
        {canWrite && (
          <Button
            variant="primary"
            icon={<DownloadSimple weight="bold" className="h-4 w-4" />}
            onClick={() => setImportOpen(true)}
          >
            {t('pages.crs.import')}
          </Button>
        )}
      </div>

      <Callout
        tone="brand"
        icon={<SealCheck weight="duotone" className="h-5 w-5" />}
        title={t('pages.crs.overviewTitle')}
      >
        {t('pages.crs.overview')}
      </Callout>

      {list.isLoading ? (
        <SkeletonCard />
      ) : rulesets.length === 0 ? (
        <Card>
          <CardBody className="flex flex-col items-center gap-3 py-10 text-center">
            <DownloadSimple weight="duotone" className="h-8 w-8 text-fg-subtle" />
            <div>
              <p className="text-sm font-medium text-fg-strong">
                {t('pages.crs.emptyTitle')}
              </p>
              <p className="mt-1 text-[13px] text-fg-subtle">
                {t('pages.crs.emptyBody')}
              </p>
            </div>
          </CardBody>
        </Card>
      ) : (
        <div className="space-y-3">
          {rulesets.map((ruleset) => (
            <Card key={ruleset.id}>
              <CardHeader
                title={`${ruleset.name}${
                  ruleset.version ? ` ${ruleset.version}` : ''
                }`}
                description={ruleset.source}
                action={
                  <div className="flex items-center gap-2">
                    {ruleset.used_by_policies > 0 && (
                      <Badge tone="brand">
                        {t('pages.crs.usedBy', {
                          n: ruleset.used_by_policies,
                        })}
                      </Badge>
                    )}
                    <Button
                      size="sm"
                      onClick={() => setSelected(ruleset)}
                    >
                      {t('pages.crs.browse')}
                    </Button>
                    {canWrite && (
                      <Button
                        size="sm"
                        variant="ghost"
                        icon={<Trash className="h-4 w-4" />}
                        onClick={() => setDeleteTarget(ruleset)}
                      />
                    )}
                  </div>
                }
              />
              <CardBody className="flex flex-wrap items-center gap-2 text-[13px]">
                <Badge tone="success">
                  {t('pages.crs.supported', { n: ruleset.supported_count })}
                </Badge>
                {ruleset.unsupported_count > 0 && (
                  <Badge tone="warning">
                    {t('pages.crs.unsupported', {
                      n: ruleset.unsupported_count,
                    })}
                  </Badge>
                )}
                {ruleset.directive_count > 0 && (
                  <Badge tone="neutral">
                    {t('pages.crs.directives', {
                      n: ruleset.directive_count,
                    })}
                  </Badge>
                )}
                <code className="ml-auto text-xs text-fg-subtle">
                  {ruleset.fingerprint.slice(0, 12)}
                </code>
              </CardBody>
            </Card>
          ))}
        </div>
      )}

      <ImportDialog
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={(ruleset) => {
          setImportOpen(false)
          void queryClient.invalidateQueries({ queryKey: crsKeys.all })
          if (ruleset.deduplicated) {
            toast.info(t('pages.crs.deduplicated'), ruleset.name)
          } else {
            toast.success(t('pages.crs.imported'), ruleset.name)
          }
        }}
      />

      {selected && (
        <RulesetDialog
          ruleset={selected}
          onClose={() => setSelected(null)}
        />
      )}

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && remove.mutate(deleteTarget.id)}
        loading={remove.isPending}
        title={t('pages.crs.deleteTitle')}
        description={t('pages.crs.deleteBody', {
          name: deleteTarget?.name ?? '',
          n: deleteTarget?.used_by_policies ?? 0,
        })}
        confirmLabel={t('common.delete')}
      />
    </div>
  )
}

function ImportDialog({
  open,
  onClose,
  onImported,
}: {
  open: boolean
  onClose: () => void
  onImported: (ruleset: CrsRuleset) => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const [name, setName] = useState('')
  const [tag, setTag] = useState('')
  const [url, setUrl] = useState('')

  const releases = useQuery({
    queryKey: crsKeys.releases(),
    queryFn: () => crsApi.releases(),
    enabled: open,
    retry: false,
  })

  const importRuleset = useMutation({
    mutationFn: () => {
      const payload = { name: name || undefined }
      if (tag.trim() !== '') return crsApi.import({ ...payload, github_tag: tag.trim() })
      return crsApi.import({ ...payload, url: url.trim() })
    },
    onSuccess: onImported,
    onError: (error) =>
      toast.error(t('pages.crs.importFailed'), String(error)),
  })

  const sourceMissing = tag.trim() === '' && url.trim() === ''

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="md"
      title={t('pages.crs.import')}
      description={t('pages.crs.importHint')}
    >
      <div className="space-y-3 px-5 py-4">
        {releases.isError ? (
          <Input
            label={t('pages.crs.release')}
            hint={t('pages.crs.releasesUnavailable')}
            placeholder="v4.30.0"
            value={tag}
            onChange={(e) => setTag(e.target.value)}
          />
        ) : (
          <Select
            label={t('pages.crs.release')}
            hint={t('pages.crs.releaseHint')}
            value={tag}
            onChange={(e) => setTag(e.target.value)}
            options={[
              { value: '', label: t('pages.crs.pickRelease') },
              ...(releases.data ?? []).map((release) => ({
                value: release.tag,
                label: `${release.tag}${
                  release.prerelease ? ` (${t('pages.crs.prerelease')})` : ''
                }`,
              })),
            ]}
          />
        )}
        <Input
          label={t('pages.crs.url')}
          placeholder="https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.30.0.tar.gz"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <Input
          label={t('pages.crs.name')}
          placeholder="OWASP CRS"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={importRuleset.isPending}
            disabled={sourceMissing}
            onClick={() => importRuleset.mutate()}
          >
            {t('pages.crs.import')}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}

const RULE_PAGE_SIZE = 50

function RulesetDialog({
  ruleset,
  onClose,
}: {
  ruleset: CrsRuleset
  onClose: () => void
}) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const [keyword, setKeyword] = useState('')
  const [paranoia, setParanoia] = useState('')
  const [phase, setPhase] = useState('')
  const [supported, setSupported] = useState('')

  const query = {
    q: keyword.trim() || undefined,
    paranoia: paranoia || undefined,
    phase: phase || undefined,
    supported: supported || undefined,
    page,
    page_size: RULE_PAGE_SIZE,
  }
  const detail = useQuery({
    queryKey: crsKeys.detail(ruleset.id, query),
    queryFn: () => crsApi.ruleset(ruleset.id, query),
  })
  const rules = detail.data?.rules

  return (
    <Dialog
      open
      onClose={onClose}
      size="xl"
      title={`${ruleset.name}${ruleset.version ? ` ${ruleset.version}` : ''}`}
      description={t('pages.crs.catalogHint')}
    >
      <div className="max-h-[70vh] space-y-3 overflow-y-auto px-5 py-4">
        <div className="grid gap-3 sm:grid-cols-4">
          <div className="sm:col-span-2">
            <Input
              label={t('pages.crs.keyword')}
              placeholder={t('pages.crs.keywordPlaceholder')}
              value={keyword}
              onChange={(e) => {
                setKeyword(e.target.value)
                setPage(1)
              }}
            />
          </div>
          <Select
            label={t('pages.crs.paranoia')}
            value={paranoia}
            onChange={(e) => {
              setParanoia(e.target.value)
              setPage(1)
            }}
            options={[
              { value: '', label: t('common.noData') },
              ...['1', '2', '3', '4'].map((value) => ({
                value,
                label: t('pages.policies.fields.paranoiaLevel', { n: value }),
              })),
            ]}
          />
          <Select
            label={t('pages.crs.phase')}
            value={phase}
            onChange={(e) => {
              setPhase(e.target.value)
              setPage(1)
            }}
            options={[
              { value: '', label: t('common.noData') },
              ...['1', '2', '3', '4', '5'].map((value) => ({
                value,
                label: value,
              })),
            ]}
          />
        </div>
        <div className="grid gap-3 sm:grid-cols-4">
          <Select
            label={t('pages.crs.status')}
            value={supported}
            onChange={(e) => {
              setSupported(e.target.value)
              setPage(1)
            }}
            options={[
              { value: '', label: t('common.noData') },
              { value: 'true', label: t('pages.crs.statusSupported') },
              { value: 'false', label: t('pages.crs.statusUnsupported') },
            ]}
          />
        </div>

        {detail.isLoading ? (
          <SkeletonCard />
        ) : (
          <>
            <ul className="divide-y divide-line rounded-lg border border-line">
              {(rules?.items ?? []).map((rule: CrsRule) => (
                <li key={rule.id} className="space-y-1 px-3 py-2 text-[13px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <code className="text-xs text-fg-subtle">
                      {rule.rule_id || '—'}
                    </code>
                    <span className="min-w-0 flex-1 truncate font-medium text-fg-strong">
                      {rule.message || rule.source.slice(0, 60)}
                    </span>
                    {rule.paranoia_level != null && (
                      <Badge tone="neutral">PL{rule.paranoia_level}</Badge>
                    )}
                    {rule.severity && (
                      <Badge tone="neutral">{rule.severity}</Badge>
                    )}
                    <Badge tone={rule.supported ? 'success' : 'warning'}>
                      {rule.supported
                        ? t('pages.crs.statusSupported')
                        : rule.kind === 'directive'
                          ? t('pages.crs.statusDirective')
                          : t('pages.crs.statusUnsupported')}
                    </Badge>
                  </div>
                  <p className="truncate text-xs text-fg-subtle">
                    {rule.file}:{rule.line}
                    {rule.category ? ` · ${rule.category}` : ''}
                    {rule.error ? ` · ${rule.error}` : ''}
                  </p>
                </li>
              ))}
            </ul>
            {rules && rules.total > RULE_PAGE_SIZE && (
              <Pagination
                page={rules.page}
                pageSize={rules.page_size}
                total={rules.total}
                onChange={setPage}
              />
            )}
          </>
        )}
      </div>
    </Dialog>
  )
}

export default CrsPage
