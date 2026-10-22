import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  CaretLeft,
  ClockCounterClockwise,
  Play,
  Stack,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Callout } from '@/components/ui/Callout'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { QuickNav } from '@/components/ui/QuickNav'
import { ErrorState } from '@/components/ErrorState'
import { PolicyTesterDialog } from '@/components/PolicyTesterDialog'
import { useCanWrite } from '@/hooks'
import { policiesApi, policyKeys } from '@/api/policies'
import {
  LAYER_TABS,
  LayerEditor,
  PolicyHistoryDialog,
} from './PoliciesPage'

/**
 * One policy as a tuning surface: the same shape as the site's Policy
 * tuning page - a summary header, a left navigation and one section per
 * layer the policy carries. The editor lives here now; the list page links
 * into it instead of opening a modal.
 */
export function PolicyDetailPage() {
  const { t } = useTranslation()
  const { policyId = '' } = useParams<{ policyId: string }>()
  const canWrite = useCanWrite()
  const queryClient = useQueryClient()
  const [historyOpen, setHistoryOpen] = useState(false)
  const [testOpen, setTestOpen] = useState(false)

  const detail = useQuery({
    queryKey: policyKeys.detail(policyId),
    queryFn: () => policiesApi.get(policyId),
    enabled: Boolean(policyId),
  })
  const policy = detail.data

  const invalidate = () => {
    void queryClient.invalidateQueries({
      queryKey: policyKeys.detail(policyId),
    })
    void queryClient.invalidateQueries({ queryKey: policyKeys.list() })
  }

  if (detail.isError && !policy) {
    return (
      <div className="animate-slide-up">
        <ErrorState
          error={detail.error}
          onRetry={() => detail.refetch()}
          retrying={detail.isFetching}
        />
      </div>
    )
  }
  if (!policy) {
    return (
      <div className="animate-slide-up">
        <SkeletonCard />
      </div>
    )
  }

  const present = LAYER_TABS.filter((kind) =>
    policy.layer_kinds.includes(kind),
  )
  const sections = [
    { id: 'policy-overview', label: t('pages.policies.sections.overview') },
    ...LAYER_TABS.map((kind) => ({
      id: `policy-layer-${kind}`,
      label: t(`pages.policies.layers.${kind}`),
    })),
    { id: 'policy-history', label: t('pages.policies.sections.history') },
    { id: 'policy-test', label: t('pages.policies.sections.test') },
  ]

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={policy.name}
        description={
          policy.description || t('pages.policies.noDescription')
        }
      />

      <div className="mb-3">
        <Link
          to="/policies"
          className="inline-flex items-center gap-1.5 text-[13px] font-medium text-link"
        >
          <CaretLeft weight="bold" className="h-3.5 w-3.5" />
          {t('pages.policies.backToList')}
        </Link>
      </div>

      <Callout
        dismissKey="policydetail"
        tone="brand"
        className="mb-5"
        icon={<Stack weight="duotone" className="h-5 w-5" />}
        title={t('pages.policies.detailOverviewTitle')}
      >
        {t('pages.policies.detailOverview')}
      </Callout>

      <div className="flex items-start gap-8">
        <QuickNav
          ariaLabel={t('pages.policies.quickNav')}
          items={sections}
        />
        <div className="min-w-0 flex-1 space-y-5">
          {/* Overview: state chips + the actions that used to live in the
              modal's header. */}
          <section id="policy-overview" className="scroll-mt-6">
            <Card>
              <CardHeader
                title={t('pages.policies.sections.overview')}
                description={t('pages.policies.detailOverviewHint')}
                action={
                  <Badge tone={policy.enabled ? 'success' : 'neutral'} dot>
                    {policy.enabled
                      ? t('pages.policies.stateEnabled')
                      : t('pages.policies.stateDisabled')}
                  </Badge>
                }
              />
              <CardBody className="flex flex-col gap-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="brand">
                    {t('pages.policies.revision', { n: policy.revision })}
                  </Badge>
                  <Badge tone="neutral">
                    {t('pages.policies.siteCount', { n: policy.site_count })}
                  </Badge>
                  <Badge tone="neutral">
                    {t('pages.policies.layerCount', {
                      n: policy.layer_kinds.length,
                    })}
                  </Badge>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    icon={
                      <ClockCounterClockwise className="h-4 w-4" />
                    }
                    onClick={() => setHistoryOpen(true)}
                  >
                    {t('pages.policies.history')}
                  </Button>
                  <Button
                    size="sm"
                    icon={<Play weight="fill" className="h-3.5 w-3.5" />}
                    onClick={() => setTestOpen(true)}
                  >
                    {t('pages.policies.test')}
                  </Button>
                </div>
                <p className="text-[12px] text-fg-subtle">
                  {t('pages.policies.editorBanner')}
                </p>
              </CardBody>
            </Card>
          </section>

          {/* One section per layer kind, always all of them: configured
              layers open with their values, unconfigured ones show the same
              editor empty - saving creates the layer, so nothing is hidden
              behind an add-one-by-one flow. */}
          {LAYER_TABS.map((kind) => {
            const isPresent = present.includes(kind)
            return (
              <section
                key={kind}
                id={`policy-layer-${kind}`}
                className="scroll-mt-6"
              >
                <Card>
                  <CardHeader
                    title={t(`pages.policies.layers.${kind}`)}
                    description={t(
                      `pages.policies.layerHints.${kind}`,
                      '',
                    )}
                    action={
                      isPresent ? (
                        <Badge tone="success" dot>
                          {t('pages.policies.layerConfigured')}
                        </Badge>
                      ) : (
                        <Badge tone="neutral">
                          {t('pages.policies.layerNotConfigured')}
                        </Badge>
                      )
                    }
                  />
                  <CardBody>
                    {!isPresent && (
                      <p className="mb-3 text-[12px] text-fg-subtle">
                        {t('pages.policies.layerNotConfiguredHint')}
                      </p>
                    )}
                    <LayerEditor
                      policy={policy}
                      tab={kind}
                      canWrite={canWrite}
                      onStored={invalidate}
                    />
                  </CardBody>
                </Card>
              </section>
            )
          })}

          {/* History and preview as their own sections. */}
          <section id="policy-history" className="scroll-mt-6">
            <Card>
              <CardHeader
                title={t('pages.policies.sections.history')}
                description={t('pages.policies.historyHint')}
                action={
                  <Button
                    size="sm"
                    icon={<ClockCounterClockwise className="h-4 w-4" />}
                    onClick={() => setHistoryOpen(true)}
                  >
                    {t('pages.policies.history')}
                  </Button>
                }
              />
            </Card>
          </section>

          <section id="policy-test" className="scroll-mt-6">
            <Card>
              <CardHeader
                title={t('pages.policies.sections.test')}
                description={t('pages.policies.testHint')}
                action={
                  <Button
                    size="sm"
                    icon={<Play weight="fill" className="h-3.5 w-3.5" />}
                    onClick={() => setTestOpen(true)}
                  >
                    {t('pages.policies.test')}
                  </Button>
                }
              />
            </Card>
          </section>
        </div>
      </div>

      {historyOpen && (
        <PolicyHistoryDialog
          policyId={policyId}
          canWrite={canWrite}
          onClose={() => setHistoryOpen(false)}
        />
      )}
      {testOpen && (
        <PolicyTesterDialog
          policyId={policyId}
          onClose={() => setTestOpen(false)}
        />
      )}
    </div>
  )
}

export default PolicyDetailPage
