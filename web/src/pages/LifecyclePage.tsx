import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ArrowRight, BookOpen } from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { QuickNav } from '@/components/ui/QuickNav'

/**
 * Global pages some features link to. Site-scoped features fall back to the
 * sites list — without a selected site there is nothing to link to directly.
 */
const GLOBAL_TO: Record<string, string> = {
  errorPages: '/settings',
  logs: '/logs',
}

const resolve = (feature: string) => GLOBAL_TO[feature] ?? '/sites'

const DOC_URL = (lang: string) =>
  `https://github.com/shuaiZend/PingWAF/blob/main/docs/${
    lang.startsWith('zh') ? 'zh/' : ''
  }http-lifecycle.md`

interface Stage {
  /** i18n suffix under pages.lifecycle.stages. */
  key: string
  /** Pingora hook shown next to the title, when the stage maps to one. */
  hook?: string
  /** Feature ids rendered as links to their configuration pages. */
  features: string[]
}

const STAGES: Stage[] = [
  { key: 'tls', features: ['ssl'] },
  {
    key: 'earlyRequest',
    hook: 'early_request_filter',
    features: ['waf', 'access', 'bot', 'rateLimit', 'cc'],
  },
  { key: 'request', hook: 'request_filter', features: ['rewrite', 'caching'] },
  { key: 'cacheLookup', hook: 'proxy_cache', features: ['caching'] },
  { key: 'upstream', hook: 'upstream_peer', features: ['origin'] },
  {
    key: 'upstreamResponse',
    hook: 'upstream_response_filter',
    features: ['errorPages', 'caching'],
  },
  { key: 'response', hook: 'response_filter', features: ['errorPages', 'ssl', 'rewrite'] },
  { key: 'responseBody', hook: 'response_body_filter', features: ['rewrite'] },
  { key: 'failure', hook: 'fail_to_proxy', features: [] },
  { key: 'logging', hook: 'logging', features: ['logs'] },
]

interface WafCheck {
  key: string
  /** Feature id whose label the configure link reuses. */
  feature?: string
}

/** The WAF plugin's internal checks, in enforcement order. */
const WAF_CHECKS: WafCheck[] = [
  { key: 'paused' },
  { key: 'mtls', feature: 'ssl' },
  { key: 'access', feature: 'access' },
  { key: 'basicAuth', feature: 'access' },
  { key: 'bot', feature: 'bot' },
  { key: 'rateLimit', feature: 'rateLimit' },
  { key: 'engine', feature: 'waf' },
]

const TIPS = [
  'observation',
  'firstMatch',
  'cache',
  'customPages',
  'responseCache',
] as const

/**
 * Request lifecycle reference.
 *
 * A static map of the data-plane pipeline: which stage of the Pingora proxy
 * each feature acts in, and which page configures it. Mirrors
 * `docs/http-lifecycle.md`.
 */
export function LifecyclePage() {
  const { t, i18n } = useTranslation()

  const navItems = useMemo(
    () =>
      STAGES.map((stage, index) => ({
        id: `stage-${stage.key}`,
        label: `${index + 1}. ${t(`pages.lifecycle.stages.${stage.key}.title`)}`,
      })),
    [t],
  )

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.lifecycle.title')}
        description={t('pages.lifecycle.description')}
        actions={
          <a
            href={DOC_URL(i18n.language ?? 'en')}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex h-9 items-center gap-1.5 rounded-md border border-line bg-elevated px-3 text-[13px] font-medium text-fg shadow-sm transition-colors hover:bg-recessed"
          >
            <BookOpen weight="duotone" className="h-4 w-4" />
            {t('pages.lifecycle.docLink')}
          </a>
        }
      />

      <div className="flex max-w-6xl items-start gap-8">
        <QuickNav ariaLabel={t('pages.lifecycle.quickNav')} items={navItems} />

        <div className="flex min-w-0 flex-1 flex-col gap-4">
          <div className="space-y-3">
            {STAGES.map((stage, index) => (
              <Card
                key={stage.key}
                id={`stage-${stage.key}`}
                className="scroll-mt-6"
              >
                <CardBody className="flex gap-4">
                  <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-brand-soft font-mono text-[13px] font-semibold text-brand">
                    {String(index + 1).padStart(2, '0')}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="text-[15px] font-semibold text-fg-strong">
                        {t(`pages.lifecycle.stages.${stage.key}.title`)}
                      </h2>
                      {stage.hook && (
                        <code className="rounded border border-line bg-recessed px-1.5 py-0.5 font-mono text-[11px] text-fg-subtle">
                          {stage.hook}
                        </code>
                      )}
                    </div>
                    <p className="mt-1 text-sm leading-relaxed text-fg-subtle">
                      {t(`pages.lifecycle.stages.${stage.key}.desc`)}
                    </p>
                    {stage.features.length > 0 && (
                      <div className="mt-3 flex flex-wrap gap-1.5">
                        {stage.features.map((feature) => (
                          <Link
                            key={feature}
                            to={resolve(feature)}
                            className="inline-flex items-center gap-1 rounded-full border border-line bg-recessed px-2.5 py-0.5 text-xs text-fg-subtle transition-colors hover:border-fill hover:text-fg"
                          >
                            {t(`pages.lifecycle.features.${feature}`)}
                            <ArrowRight weight="bold" className="h-3 w-3" />
                          </Link>
                        ))}
                      </div>
                    )}
                  </div>
                </CardBody>
              </Card>
            ))}
          </div>

          <Card>
            <CardHeader
              title={t('pages.lifecycle.wafTitle')}
              description={t('pages.lifecycle.wafDescription')}
            />
            <CardBody>
              <ol className="space-y-4">
                {WAF_CHECKS.map((check, index) => (
                  <li key={check.key} className="flex gap-3">
                    <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-line bg-recessed font-mono text-[11px] text-fg-subtle">
                      {index + 1}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        <h3 className="text-sm font-medium text-fg-strong">
                          {t(`pages.lifecycle.checks.${check.key}.title`)}
                        </h3>
                        {check.feature && (
                          <Link
                            to={resolve(check.feature)}
                            className="inline-flex items-center gap-1 text-xs text-link hover:underline"
                          >
                            {t(`pages.lifecycle.features.${check.feature}`)}
                            <ArrowRight weight="bold" className="h-3 w-3" />
                          </Link>
                        )}
                      </div>
                      <p className="mt-0.5 text-[13px] leading-relaxed text-fg-subtle">
                        {t(`pages.lifecycle.checks.${check.key}.desc`)}
                      </p>
                    </div>
                  </li>
                ))}
              </ol>
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={t('pages.lifecycle.tipsTitle')}
              description={t('pages.lifecycle.tipsDescription')}
            />
            <CardBody>
              <div className="grid gap-4 sm:grid-cols-2">
                {TIPS.map((tip) => (
                  <div
                    key={tip}
                    className="rounded-lg border border-line bg-recessed p-4"
                  >
                    <h3 className="text-sm font-medium text-fg-strong">
                      {t(`pages.lifecycle.tips.${tip}.title`)}
                    </h3>
                    <p className="mt-1 text-[13px] leading-relaxed text-fg-subtle">
                      {t(`pages.lifecycle.tips.${tip}.desc`)}
                    </p>
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>
        </div>
      </div>
    </div>
  )
}

export default LifecyclePage
