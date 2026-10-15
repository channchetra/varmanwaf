import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation } from '@tanstack/react-query'
import { MagnifyingGlass, WarningCircle } from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { countryFlag } from '@/api/geo'
import { ipAnalysisApi, type IpAnalysis } from '@/api/ipAnalysis'
import { errorMessage } from '@/api/errors'

const VERDICT_TONES: Record<
  string,
  'neutral' | 'success' | 'warning' | 'danger' | 'brand'
> = {
  pass: 'neutral',
  allow: 'success',
  block: 'danger',
  challenge: 'warning',
  js_challenge: 'warning',
  basic_auth: 'warning',
  monitor: 'brand',
}

/**
 * Client IP analysis: enter an address, see what the site's stored config -
 * IP rules, IP groups and the geo policy - decides for it, computed from the
 * same loaders the edge bundle is compiled from.
 */
export function IpAnalysisCard() {
  const { t } = useTranslation()
  const { siteId = '' } = useParams<{ siteId: string }>()
  const [ip, setIp] = useState('')

  const analyze = useMutation({
    mutationFn: (value: string) => ipAnalysisApi.analyze(siteId, value),
  })

  const submit = () => {
    const value = ip.trim()
    if (value) analyze.mutate(value)
  }

  return (
    <Card>
      <CardHeader
        title={t('pages.ipAnalysis.title')}
        description={t('pages.ipAnalysis.hint')}
      />
      <CardBody className="flex flex-col gap-4">
        <div className="flex items-end gap-2">
          <Input
            className="pw-mono"
            containerClassName="flex-1"
            value={ip}
            placeholder={t('pages.ipAnalysis.placeholder')}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault()
                submit()
              }
            }}
            onChange={(event) => setIp(event.target.value)}
          />
          <Button
            variant="secondary"
            icon={<MagnifyingGlass weight="bold" className="h-4 w-4" />}
            loading={analyze.isPending}
            disabled={!ip.trim()}
            onClick={submit}
          >
            {t('pages.ipAnalysis.analyze')}
          </Button>
        </div>

        {analyze.isError && (
          <p className="text-sm text-fg-danger">{errorMessage(analyze.error)}</p>
        )}

        {analyze.data && <AnalysisResult result={analyze.data} />}
      </CardBody>
    </Card>
  )
}

function AnalysisResult({ result }: { result: IpAnalysis }) {
  const { t } = useTranslation()
  const verdict = result.verdict
  const matchedGroups = result.groups.filter((group) => group.matched)

  return (
    <div className="flex flex-col gap-3 rounded-md border border-line bg-recessed/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="pw-mono text-sm font-medium text-fg-strong">{result.ip}</span>
        <Badge tone={VERDICT_TONES[verdict.action] ?? 'neutral'} dot size="sm">
          {t(`ipVerdicts.${verdict.action}`, verdict.action)}
        </Badge>
        {verdict.observed && (
          <Badge tone="warning" size="sm">
            {t('pages.ipAnalysis.observed')}
          </Badge>
        )}
      </div>

      {!result.geo.synced && result.geo.missing_keys.length > 0 && (
        <p className="flex items-start gap-1.5 text-[12px] text-fg-warning">
          <WarningCircle
            weight="duotone"
            className="mt-0.5 h-4 w-4 shrink-0"
          />
          {t('pages.ipAnalysis.missingKeys', {
            keys: result.geo.missing_keys.join(', '),
          })}
        </p>
      )}

      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[13px]">
        <dt className="text-fg-subtle">{t('pages.ipAnalysis.country')}</dt>
        <dd>
          {result.country
            ? `${countryFlag(result.country)} ${result.country}`
            : t('pages.ipAnalysis.unknown')}
        </dd>
        <dt className="text-fg-subtle">{t('pages.ipAnalysis.asn')}</dt>
        <dd className="pw-mono">
          {result.asn_matches.length > 0
            ? result.asn_matches.join(', ')
            : t('pages.ipAnalysis.unknown')}
        </dd>
        <dt className="text-fg-subtle">{t('pages.ipAnalysis.geo')}</dt>
        <dd>
          {result.geo.enabled
            ? result.geo.reason
            : t('pages.ipAnalysis.geoDisabled')}
        </dd>
        <dt className="text-fg-subtle">{t('pages.ipAnalysis.matchedRule')}</dt>
        <dd>
          {result.ip_rule
            ? `${result.ip_rule.name} (${t(`actions.${result.ip_rule.action}`, result.ip_rule.action)})`
            : t('pages.ipAnalysis.noRule')}
        </dd>
        <dt className="text-fg-subtle">{t('pages.ipAnalysis.groups')}</dt>
        <dd>
          {matchedGroups.length > 0
            ? matchedGroups.map((group) => group.name).join(', ')
            : t('pages.ipAnalysis.noGroup')}
        </dd>
      </dl>

      <div>
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">
          {t('pages.ipAnalysis.limitations')}
        </p>
        <ul className="list-disc space-y-0.5 pl-4 text-[12px] text-fg-subtle">
          {result.limitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}

export default IpAnalysisCard
