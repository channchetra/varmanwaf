import { useState } from 'react'
import { Navigate, useLocation, useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Cloud, Gauge, ShieldCheck, Warning } from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Tabs } from '@/components/ui/Tabs'
import { Switch } from '@/components/ui/Switch'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { useToast } from '@/components/ui/Toast'
import { challengeApi, challengeKeys } from '@/api/challenge'
import { useCanWrite } from '@/hooks'
import { ProtectionSettingsPanel } from './ProtectionSettingsPanel'
import { WafRulesPanel } from './WafRulesPanel'
import { CcPanel } from './CcPanel'

type ProtectionTab = 'settings' | 'rules' | 'cc'

const PROTECTION_TABS: ProtectionTab[] = ['settings', 'rules', 'cc']

function parseTab(value: string | null): ProtectionTab {
  return PROTECTION_TABS.includes(value as ProtectionTab)
    ? (value as ProtectionTab)
    : 'settings'
}

/**
 * Web protection for one site: WAF posture and rules, the grading knobs and
 * CC protection under one roof, fronted by the under-attack banner.
 */
export function ProtectionPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = parseTab(searchParams.get('tab'))

  const setTab = (next: string) => {
    const params = new URLSearchParams(searchParams)
    params.set('tab', next)
    setSearchParams(params, { replace: true })
  }

  const challengeQuery = useQuery({
    queryKey: challengeKeys.config(siteId),
    queryFn: () => challengeApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const underAttack = challengeQuery.data?.under_attack_mode ?? false

  const setUnderAttack = useMutation({
    mutationFn: (enabled: boolean) =>
      challengeApi.update(siteId, {
        // The challenge gate must be on for the banner to mean anything; the
        // server forces the same pairing.
        under_attack_mode: enabled,
        ...(enabled ? { enabled: true } : {}),
      }),
    onSuccess: (saved) => {
      queryClient.setQueryData(challengeKeys.config(siteId), saved)
      toast.success(
        saved.under_attack_mode
          ? t('pages.protection.underAttackOn')
          : t('pages.protection.underAttackOff'),
      )
      void queryClient.invalidateQueries({ queryKey: challengeKeys.all(siteId) })
    },
    onError: (error) => {
      toast.error(
        t('pages.protection.updateFailed'),
        error instanceof Error ? error.message : undefined,
      )
    },
  })

  const [confirmUnderAttack, setConfirmUnderAttack] = useState(false)

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.protection.title')}
        description={t('pages.protection.description')}
      />

      {/* ── Under Attack banner ─────────────────────────────────────────── */}
      {challengeQuery.isPending ? (
        <SkeletonCard className="mb-5 h-16" />
      ) : (
        <div
          className={`mb-5 flex flex-wrap items-center justify-between gap-4 rounded-lg border px-4 py-3 ${
            underAttack
              ? 'border-danger/45 bg-danger/10'
              : 'border-line bg-elevated'
          }`}
        >
          <span className="flex min-w-0 items-center gap-3">
            <span
              className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${
                underAttack
                  ? 'bg-danger/15 text-fg-danger'
                  : 'bg-recessed text-fg-subtle'
              }`}
            >
              {underAttack ? (
                <Warning weight="fill" className="h-5 w-5" />
              ) : (
                <ShieldCheck weight="duotone" className="h-5 w-5" />
              )}
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-semibold text-fg-strong">
                {underAttack
                  ? t('pages.protection.underAttackActive')
                  : t('pages.protection.underAttackTitle')}
              </span>
              <span className="mt-0.5 block text-[13px] text-fg-subtle">
                {underAttack
                  ? t('pages.protection.underAttackActiveHint')
                  : t('pages.protection.underAttackHint')}
              </span>
            </span>
          </span>
          {canWrite && (
            <Switch
              size="md"
              checked={underAttack}
              disabled={!canWrite || setUnderAttack.isPending}
              aria-label={t('pages.protection.underAttackTitle')}
              onCheckedChange={(enabled) => {
                if (enabled) {
                  setConfirmUnderAttack(true)
                } else {
                  setUnderAttack.mutate(false)
                }
              }}
            />
          )}
        </div>
      )}

      <Tabs
        variant="pill"
        className="mb-5"
        value={tab}
        onChange={setTab}
        items={[
          {
            value: 'settings',
            label: t('pages.protection.tabSettings'),
            icon: <Gauge weight="duotone" className="h-4 w-4" />,
          },
          {
            value: 'rules',
            label: t('pages.protection.tabRules'),
            icon: <ShieldCheck weight="duotone" className="h-4 w-4" />,
          },
          {
            value: 'cc',
            label: t('pages.protection.tabCc'),
            icon: <Cloud weight="duotone" className="h-4 w-4" />,
          },
        ]}
      />

      {tab === 'settings' && <ProtectionSettingsPanel />}
      {tab === 'rules' && <WafRulesPanel />}
      {tab === 'cc' && <CcPanel />}

      <ConfirmDialog
        open={confirmUnderAttack}
        onClose={() => setConfirmUnderAttack(false)}
        onConfirm={() => {
          setConfirmUnderAttack(false)
          setUnderAttack.mutate(true)
        }}
        tone="danger"
        title={t('pages.protection.underAttackConfirmTitle')}
        description={t('pages.protection.underAttackConfirmDescription')}
        confirmLabel={t('pages.protection.underAttackCta')}
        loading={setUnderAttack.isPending}
      />
    </div>
  )
}

/** Forwards a pre-merge route (`/security/waf`, `/security/cc`) here, query intact. */
export function LegacyProtectionRedirect({ tab }: { tab: ProtectionTab }) {
  const { siteId = '' } = useParams<{ siteId: string }>()
  const location = useLocation()
  const params = new URLSearchParams(location.search)
  params.set('tab', tab)
  return (
    <Navigate to={`/sites/${siteId}/security/protection?${params.toString()}`} replace />
  )
}

export default ProtectionPage
