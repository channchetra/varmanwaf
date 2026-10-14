import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation } from '@tanstack/react-query'
import { Play } from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Textarea } from '@/components/ui/Textarea'
import { useToast } from '@/components/ui/Toast'
import {
  policiesApi,
  type PolicyTestView,
  type TestRequestInput,
} from '@/api/policies'

/** Parse `Name: value` lines into a header map (blank lines are skipped). */
function parseHeaders(raw: string): Record<string, string> {
  const headers: Record<string, string> = {}
  for (const line of raw.split('\n')) {
    const index = line.indexOf(':')
    if (index <= 0) continue
    headers[line.slice(0, index).trim()] = line.slice(index + 1).trim()
  }
  return headers
}

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

const VERDICT_TONE: Record<
  string,
  'success' | 'warning' | 'danger' | 'neutral'
> = {
  pass: 'success',
  monitor: 'warning',
  block: 'danger',
  challenge: 'warning',
}

/**
 * Rule tester: evaluates one sample request against a candidate policy with
 * the same native engine the edge runs (managed rules, custom rules,
 * tuning, virtual patches). Edge decisions that need request history —
 * rate limits, IP/geo access, bot checks — are reported as skipped.
 */
export function PolicyTesterDialog({
  policyId,
  siteId,
  layers,
  onClose,
}: {
  policyId?: string
  siteId?: string
  /** Draft layers to compile into the test, like the preview. */
  layers?: Partial<Record<string, unknown>>
  onClose: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const [method, setMethod] = useState('GET')
  const [path, setPath] = useState('/')
  const [query, setQuery] = useState('')
  const [host, setHost] = useState('')
  const [clientIp, setClientIp] = useState('203.0.113.10')
  const [headerText, setHeaderText] = useState('')
  const [body, setBody] = useState('')
  const [result, setResult] = useState<PolicyTestView | null>(null)

  const run = useMutation({
    mutationFn: () => {
      const request: TestRequestInput = {
        method,
        path,
        query,
        host,
        client_ip: clientIp,
        headers: parseHeaders(headerText),
      }
      if (body.trim() !== '') request.body = body
      return policiesApi.test({
        policy_id: policyId,
        site_id: siteId,
        layers: layers as never,
        request,
      })
    },
    onSuccess: (view) => setResult(view),
    onError: (error) =>
      toast.error(t('pages.policies.testFailed'), String(error)),
  })

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={t('pages.policies.test')}
      description={t('pages.policies.testHint')}
    >
      <div className="max-h-[70vh] space-y-3 overflow-y-auto px-5 py-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <Select
            label={t('pages.policies.testMethod')}
            value={method}
            onChange={(e) => setMethod(e.target.value)}
            options={METHODS.map((value) => ({ value, label: value }))}
          />
          <div className="sm:col-span-2">
            <Input
              label={t('pages.policies.testPath')}
              value={path}
              onChange={(e) => setPath(e.target.value)}
            />
          </div>
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          <Input
            label={t('pages.policies.testQuery')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <Input
            label={t('pages.policies.testHost')}
            value={host}
            placeholder="shop.example.com"
            onChange={(e) => setHost(e.target.value)}
          />
          <Input
            label={t('pages.policies.testClientIp')}
            value={clientIp}
            onChange={(e) => setClientIp(e.target.value)}
          />
        </div>
        <Textarea
          label={t('pages.policies.testHeaders')}
          hint={t('pages.policies.testHeadersHint')}
          mono
          rows={3}
          value={headerText}
          onChange={(e) => setHeaderText(e.target.value)}
        />
        <Textarea
          label={t('pages.policies.testBody')}
          mono
          rows={3}
          value={body}
          onChange={(e) => setBody(e.target.value)}
        />
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            {t('common.close')}
          </Button>
          <Button
            variant="primary"
            loading={run.isPending}
            icon={<Play weight="fill" className="h-4 w-4" />}
            onClick={() => run.mutate()}
          >
            {t('pages.policies.testRun')}
          </Button>
        </div>

        {result && (
          <div className="space-y-3 rounded-lg border border-line p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={VERDICT_TONE[result.result.action] ?? 'neutral'} dot>
                {t(`pages.policies.verdict.${result.result.action}`)}
              </Badge>
              <Badge tone="neutral">
                {t('pages.policies.planScore', { n: result.result.score })}
              </Badge>
            </div>
            <p className="text-[13px] break-words text-fg-subtle">
              {result.result.details || '—'}
            </p>
            {result.result.matched_rules.length > 0 && (
              <ul className="space-y-1">
                {result.result.matched_rules.map((hit, index) => (
                  <li
                    key={`${hit.id}-${index}`}
                    className="flex flex-wrap items-center gap-2 text-[13px]"
                  >
                    <code className="text-xs text-fg-subtle">
                      {hit.id || '—'}
                    </code>
                    <span className="font-medium text-fg-strong">
                      {hit.name}
                    </span>
                    <Badge tone="info">{hit.source}</Badge>
                    {hit.tuned && (
                      <Badge tone="warning">{t('pages.policies.tuned')}</Badge>
                    )}
                  </li>
                ))}
              </ul>
            )}
            {result.result.notes.length > 0 && (
              <ul className="list-inside list-disc text-[12px] text-fg-subtle">
                {result.result.notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            )}
            <p className="text-[12px] text-fg-subtle">
              {t('pages.policies.testSkipped')}:{' '}
              {result.result.skipped.join('; ')}
            </p>
          </div>
        )}
      </div>
    </Dialog>
  )
}

export default PolicyTesterDialog
