import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowRight,
  BracketsCurly,
  CaretUpDown,
  Flask,
  Plus,
  Trash,
} from '@phosphor-icons/react'
import { Dialog } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Textarea } from '@/components/ui/Textarea'
import { TagInput } from '@/components/ui/MultiSelect'
import { useToast } from '@/components/ui/Toast'
import { cn } from '@/lib/utils'
import { rulesApi, ruleKeys } from '@/api/rules'
import { siteKeys } from '@/api/sites'
import { policiesApi, type PolicyRule } from '@/api/policies'
import {
  buildExpression,
  EXPRESSION_FIELDS,
  EXPRESSION_OPERATORS,
  parseExpression,
  DEFAULT_FIELD,
  type ExpressionCombinator,
  type ExpressionCondition,
} from '@/lib/expression'
import { RULE_ACTIONS, RULE_MODES, type CreateRuleRequest, type Rule, type RuleGroup } from '@/api/types'

/** Tag suggestions surfaced by the tag editor, grouped by what agents detect. */
const TAG_SUGGESTIONS = [
  'sqli',
  'xss',
  'rce',
  'lfi',
  'ssrf',
  'bot',
  'recon',
  'owasp:a03',
  'rate-limit',
]

const SEVERITIES = [1, 2, 3, 4, 5]

const emptyCondition = (): ExpressionCondition => ({
  field: DEFAULT_FIELD,
  operator: 'contains',
  value: '',
})

interface RuleFormState {
  name: string
  description: string
  groupId: string
  action: string
  severity: number
  mode: string
  priority: number
  tags: string[]
  enabled: boolean
}

const emptyForm = (): RuleFormState => ({
  name: '',
  description: '',
  groupId: '',
  action: 'block',
  severity: 3,
  mode: 'block',
  priority: 100,
  tags: [],
  enabled: true,
})

function formFromRule(rule: Rule): RuleFormState {
  return {
    name: rule.name,
    description: rule.description ?? '',
    groupId: rule.group_id ?? '',
    action: rule.action,
    severity: rule.severity,
    mode: rule.mode,
    priority: rule.priority,
    tags: [...(rule.tags ?? [])],
    enabled: rule.enabled,
  }
}

/**
 * What happens when the rule's condition matches, stated from the engine's
 * own semantics (the runtime mode caps the action; `off` short-circuits).
 */
function outcomeFor(
  t: (key: string, options?: Record<string, unknown>) => string,
  action: string,
  mode: string,
): { chip: string; text: string; tone: 'danger' | 'warning' | 'neutral' | 'success' } {
  if (mode === 'off') {
    return {
      chip: t('pages.waf.outcomes.offChip'),
      text: t('pages.waf.outcomes.offText'),
      tone: 'neutral',
    }
  }
  const monitored = mode === 'monitor'
  switch (action) {
    case 'allow':
      return {
        chip: t('pages.waf.outcomes.allowChip'),
        text: monitorPrefix(t, monitored) + t('pages.waf.outcomes.allowText'),
        tone: 'success',
      }
    case 'log':
      return {
        chip: t('pages.waf.outcomes.logChip'),
        text: t('pages.waf.outcomes.logText'),
        tone: 'neutral',
      }
    case 'challenge':
    case 'js_challenge':
      return {
        chip: t('pages.waf.outcomes.challengeChip'),
        text:
          monitorPrefix(t, monitored) + t('pages.waf.outcomes.challengeText'),
        tone: monitored ? 'warning' : 'danger',
      }
    default:
      return {
        chip: t('pages.waf.outcomes.blockChip'),
        text: monitorPrefix(t, monitored) + t('pages.waf.outcomes.blockText'),
        tone: monitored ? 'warning' : 'danger',
      }
  }
}

function monitorPrefix(
  t: (key: string, options?: Record<string, unknown>) => string,
  monitored: boolean,
): string {
  return monitored ? `${t('pages.waf.outcomes.monitorPrefix')} ` : ''
}

export interface RuleDialogProps {
  open: boolean
  onClose: () => void
  siteId: string
  groups: RuleGroup[]
  /** The rule being edited; `null` opens the dialog in create mode. */
  rule: Rule | null
  /** Tags pre-applied when the dialog is opened from a detection toggle. */
  presetTags?: string[]
  /** Expression pre-filled when the dialog is opened from a template. */
  presetExpression?: string
}

export function RuleDialog({
  open,
  onClose,
  siteId,
  groups,
  rule,
  presetTags,
  presetExpression,
}: RuleDialogProps) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [form, setForm] = useState<RuleFormState>(emptyForm())
  const [editor, setEditor] = useState<'builder' | 'raw'>('builder')
  const [conditions, setConditions] = useState<ExpressionCondition[]>([emptyCondition()])
  const [combinator, setCombinator] = useState<ExpressionCombinator>('and')
  const [raw, setRaw] = useState('')
  const [error, setError] = useState<string | null>(null)
  // Draft tester.
  const [testOpen, setTestOpen] = useState(false)
  const [testMethod, setTestMethod] = useState('GET')
  const [testPath, setTestPath] = useState('/admin')
  const [testQuery, setTestQuery] = useState('')
  const [testBody, setTestBody] = useState('')
  const [testIp, setTestIp] = useState('203.0.113.10')

  // Re-seed the form every time the dialog opens so stale state never leaks
  // between "create", "edit rule A" and "edit rule B". This runs during render
  // (the supported "adjust state when props change" pattern) so the first paint
  // already shows the right values.
  const seedKey = open
    ? JSON.stringify([rule?.id ?? 'new', presetExpression ?? '', presetTags ?? []])
    : ''
  const [lastSeedKey, setLastSeedKey] = useState<string | null>(null)
  if (seedKey !== lastSeedKey) {
    setLastSeedKey(seedKey)
    if (open) {
      setError(null)
      setTestOpen(false)
      if (rule) {
        setForm(formFromRule(rule))
        const parsed = parseExpression(rule.expression)
        if (parsed) {
          setEditor('builder')
          setConditions(parsed.conditions)
          setCombinator(parsed.combinator)
          setRaw(rule.expression)
        } else {
          setEditor('raw')
          setConditions([emptyCondition()])
          setCombinator('and')
          setRaw(rule.expression)
        }
      } else {
        setForm({
          ...emptyForm(),
          tags: presetTags ? [...presetTags] : [],
        })
        setConditions([emptyCondition()])
        setCombinator('and')
        setEditor('builder')
        setRaw(presetExpression ?? '')
      }
    }
  }

  const builtExpression = useMemo(
    () => buildExpression(conditions, combinator),
    [conditions, combinator],
  )
  const expression = editor === 'builder' ? builtExpression : raw.trim()

  const groupOptions = useMemo(
    () => [
      { value: '', label: t('pages.waf.noGroup') },
      ...groups.map((g) => ({ value: g.id, label: g.name })),
    ],
    [groups, t],
  )

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ruleKeys.all(siteId) })
    void queryClient.invalidateQueries({ queryKey: siteKeys.detail(siteId) })
  }

  const save = useMutation({
    mutationFn: (payload: CreateRuleRequest) =>
      rule ? rulesApi.update(siteId, rule.id, payload) : rulesApi.create(siteId, payload),
    onSuccess: (saved) => {
      toast.success(
        rule ? t('pages.waf.ruleUpdated') : t('pages.waf.ruleCreated'),
        saved.name,
      )
      invalidate()
      onClose()
    },
  })

  const test = useMutation({
    mutationFn: () => {
      const draft: PolicyRule = {
        name: form.name.trim() || t('pages.waf.untitledDraft'),
        description: form.description.trim(),
        expression,
        action: form.action,
        severity: form.severity,
        tags: form.tags,
        enabled: true,
        mode: form.mode,
        priority: form.priority,
      }
      return policiesApi.test({
        site_id: siteId,
        draft_rules: [draft],
        request: {
          method: testMethod,
          path: testPath.startsWith('/') ? testPath : `/${testPath}`,
          query: testQuery,
          body: testBody,
          client_ip: testIp,
        },
      })
    },
  })

  const submit = () => {
    setError(null)
    const name = form.name.trim()
    if (!name) {
      setError(t('pages.waf.nameRequired'))
      return
    }
    if (!expression) {
      setError(t('pages.waf.expressionRequired'))
      return
    }
    if (editor === 'builder' && conditions.length === 0) {
      setError(t('pages.waf.expressionRequired'))
      return
    }
    save.mutate({
      name,
      group_id: form.groupId || null,
      description: form.description.trim() || null,
      expression,
      action: form.action,
      severity: form.severity,
      tags: form.tags,
      enabled: form.enabled,
      mode: form.mode,
      priority: Number.isFinite(form.priority) ? form.priority : 0,
    })
  }

  const updateCondition = (index: number, patch: Partial<ExpressionCondition>) => {
    setConditions((prev) => prev.map((c, i) => (i === index ? { ...c, ...patch } : c)))
  }

  const outcome = outcomeFor(t, form.action, form.mode)
  const testResult = test.data?.result
  const draftIds = new Set(
    (testResult?.matched_rules ?? [])
      .filter((hit) => hit.source === 'draft')
      .map((hit) => hit.id),
  )

  return (
    <Dialog
      open={open}
      onClose={save.isPending ? () => undefined : onClose}
      size="xl"
      title={rule ? t('pages.waf.editRule') : t('pages.waf.addRule')}
      description={t('pages.waf.ruleDialogDescription')}
      footer={
        <>
          <Button
            variant="ghost"
            icon={<Flask weight="duotone" className="h-4 w-4" />}
            disabled={!expression}
            onClick={() => {
              setTestOpen(true)
              test.mutate()
            }}
          >
            {t('pages.waf.testRule')}
          </Button>
          <Button variant="ghost" onClick={onClose} disabled={save.isPending}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={submit} loading={save.isPending}>
            {rule ? t('common.save') : t('common.create')}
          </Button>
        </>
      }
    >
      <div className="flex max-h-[72vh] flex-col gap-5 overflow-y-auto pr-1">
        {/* Identity */}
        <section className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Input
            label={t('common.name')}
            value={form.name}
            placeholder={t('pages.waf.ruleNamePlaceholder')}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            autoFocus
            required
          />
          <Select
            label={t('pages.waf.group')}
            value={form.groupId}
            options={groupOptions}
            hint={t('pages.waf.groupHint')}
            onChange={(e) => setForm((f) => ({ ...f, groupId: e.target.value }))}
          />
          <div className="sm:col-span-2">
            <Input
              label={t('common.description')}
              value={form.description}
              placeholder={t('pages.waf.descriptionPlaceholder')}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </div>
        </section>

        {/* When */}
        <section className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h3 className="text-[13px] font-semibold text-fg-strong">
              {t('pages.waf.whenTitle')}
            </h3>
            <div className="flex items-center gap-1 rounded-md border border-line bg-recessed p-0.5">
              {(['builder', 'raw'] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => {
                    if (mode === 'raw' && editor === 'builder') setRaw(builtExpression)
                    setEditor(mode)
                  }}
                  className={cn(
                    'inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition-colors',
                    editor === mode
                      ? 'bg-elevated text-fg-strong shadow-sm'
                      : 'text-fg-subtle hover:text-fg',
                  )}
                >
                  {mode === 'builder' ? (
                    <CaretUpDown weight="bold" className="h-3.5 w-3.5" />
                  ) : (
                    <BracketsCurly weight="bold" className="h-3.5 w-3.5" />
                  )}
                  {mode === 'builder' ? t('pages.waf.builder') : t('pages.waf.advanced')}
                </button>
              ))}
            </div>
          </div>

          {editor === 'builder' ? (
            <div className="flex flex-col gap-2 rounded-lg border border-line bg-recessed/60 p-3">
              {conditions.map((condition, index) => {
                const field = EXPRESSION_FIELDS.find((f) => f.value === condition.field)
                return (
                  <div key={index} className="flex flex-col gap-2">
                    <div className="grid grid-cols-1 items-start gap-2 sm:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)_minmax(0,1.4fr)_auto]">
                      <Select
                        aria-label={t('pages.waf.field')}
                        className="h-9"
                        value={condition.field}
                        onChange={(e) => updateCondition(index, { field: e.target.value })}
                        options={EXPRESSION_FIELDS.map((f) => ({
                          value: f.value,
                          label: `${t(`pages.waf.fields.${f.labelKey}`)}  ·  ${f.value}`,
                        }))}
                      />
                      <Select
                        aria-label={t('pages.waf.operator')}
                        className="h-9"
                        value={condition.operator}
                        onChange={(e) =>
                          updateCondition(index, {
                            operator: e.target.value as ExpressionCondition['operator'],
                          })
                        }
                        options={EXPRESSION_OPERATORS.map((op) => ({
                          value: op,
                          label: t(`pages.waf.operators.${op}`),
                        }))}
                      />
                      {condition.operator === 'in' ? (
                        <Textarea
                          aria-label={t('pages.waf.value')}
                          className="min-h-9 py-1.5 text-[13px]"
                          mono
                          rows={1}
                          value={condition.value}
                          placeholder={t('pages.waf.setPlaceholder')}
                          hint={t('pages.waf.setHint')}
                          onChange={(e) => updateCondition(index, { value: e.target.value })}
                        />
                      ) : field?.choices ? (
                        <Select
                          aria-label={t('pages.waf.value')}
                          className="h-9"
                          value={condition.value}
                          onChange={(e) => updateCondition(index, { value: e.target.value })}
                          options={field.choices.map((c) => ({ value: c, label: c }))}
                        />
                      ) : (
                        <Input
                          aria-label={t('pages.waf.value')}
                          className="h-9"
                          value={condition.value}
                          placeholder={field?.placeholder ?? ''}
                          onChange={(e) => updateCondition(index, { value: e.target.value })}
                        />
                      )}
                      <Button
                        size="icon"
                        variant="ghost"
                        className="mt-0.5 hover:text-fg-danger sm:mt-0"
                        aria-label={t('pages.waf.removeCondition')}
                        disabled={conditions.length === 1}
                        onClick={() =>
                          setConditions((prev) => prev.filter((_, i) => i !== index))
                        }
                        icon={<Trash weight="duotone" className="h-4 w-4" />}
                      />
                    </div>
                    {index < conditions.length - 1 && (
                      <div className="flex items-center gap-2 pl-1">
                        <Select
                          aria-label={t('pages.waf.combinator')}
                          className="h-8 w-28 text-xs"
                          value={combinator}
                          onChange={(e) =>
                            setCombinator(e.target.value as ExpressionCombinator)
                          }
                          options={[
                            { value: 'and', label: t('pages.waf.combinatorAnd') },
                            { value: 'or', label: t('pages.waf.combinatorOr') },
                          ]}
                        />
                        <span className="h-px flex-1 bg-line" />
                      </div>
                    )}
                  </div>
                )
              })}
              <Button
                size="sm"
                variant="secondary"
                className="self-start"
                icon={<Plus weight="bold" className="h-3.5 w-3.5" />}
                onClick={() => setConditions((prev) => [...prev, emptyCondition()])}
              >
                {t('pages.waf.addCondition')}
              </Button>
            </div>
          ) : (
            <Textarea
              mono
              rows={4}
              value={raw}
              placeholder='http.request.uri.path starts_with "/admin" and ip.src in { "203.0.113.44" }'
              hint={t('pages.waf.advancedHint')}
              onChange={(e) => setRaw(e.target.value)}
            />
          )}

          {expression && (
            <p className="pw-mono break-all rounded-md border border-line bg-recessed px-3 py-2 text-xs text-fg-subtle">
              {expression}
            </p>
          )}
        </section>

        {/* Then */}
        <section className="space-y-2">
          <h3 className="text-[13px] font-semibold text-fg-strong">
            {t('pages.waf.thenTitle')}
          </h3>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {RULE_ACTIONS.map((action) => {
              const active = form.action === action
              const card = outcomeFor(t, action, form.mode)
              return (
                <button
                  key={action}
                  type="button"
                  onClick={() => setForm((f) => ({ ...f, action }))}
                  className={cn(
                    'flex h-full flex-col gap-1 rounded-lg border px-3 py-2.5 text-left transition-colors',
                    active
                      ? 'border-brand bg-brand-soft/60'
                      : 'border-line hover:border-fill',
                  )}
                >
                  <span className="flex items-center gap-2">
                    <span className="text-[13px] font-medium text-fg-strong">
                      {t(`pages.waf.actionCards.${action}.title`)}
                    </span>
                    <Badge tone={active ? 'brand' : 'neutral'} size="sm">
                      {t(`pages.waf.actionCards.${action}.chip`)}
                    </Badge>
                  </span>
                  <span className="text-[12px] leading-snug text-fg-subtle">
                    {t(`pages.waf.actionCards.${action}.description`)}
                  </span>
                  {active && (
                    <span className="mt-1 text-[11px] text-fg-subtle">
                      {card.text}
                    </span>
                  )}
                </button>
              )
            })}
          </div>
        </section>

        {/* Actual request path */}
        <section className="space-y-2 rounded-lg border border-line bg-recessed/40 px-4 py-3">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">
            {t('pages.waf.pathTitle')}
          </p>
          <div className="flex flex-wrap items-center gap-2 text-[12px]">
            <span className="rounded-md border border-line bg-elevated px-2.5 py-1.5">
              <span className="block text-[11px] text-fg-subtle">
                {t('pages.waf.pathCondition')}
              </span>
              <span className="font-medium text-fg-strong">
                {t('pages.waf.pathConditionValue')}
              </span>
            </span>
            <ArrowRight weight="bold" className="h-3.5 w-3.5 text-fg-subtle" />
            <span className="rounded-md border border-line bg-elevated px-2.5 py-1.5">
              <span className="block text-[11px] text-fg-subtle">
                {t('pages.waf.pathAction', {
                  action: t(`pages.waf.actionCards.${form.action}.title`),
                })}
              </span>
              <span className="font-medium text-fg-strong">
                {outcome.chip}
              </span>
            </span>
            <ArrowRight weight="bold" className="h-3.5 w-3.5 text-fg-subtle" />
            <span
              className={cn(
                'rounded-md border px-2.5 py-1.5',
                outcome.tone === 'danger'
                  ? 'border-danger/40 bg-danger/8 text-fg-danger'
                  : outcome.tone === 'warning'
                    ? 'border-warning/40 bg-warning/10 text-fg'
                    : outcome.tone === 'success'
                      ? 'border-success/40 bg-success/10 text-fg-success'
                      : 'border-line bg-elevated text-fg-subtle',
              )}
            >
              <span className="block text-[11px] opacity-80">
                {t('pages.waf.pathResult')}
              </span>
              <span className="font-medium">{outcome.text}</span>
            </span>
          </div>
        </section>

        {/* Runtime */}
        <section className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Select
            label={t('pages.waf.mode')}
            value={form.mode}
            hint={t('pages.waf.ruleModeHint')}
            options={RULE_MODES.map((m) => ({
              value: m,
              label: t(`pages.waf.mode_${m}`),
            }))}
            onChange={(e) => setForm((f) => ({ ...f, mode: e.target.value }))}
          />
          <Input
            type="number"
            label={t('common.priority')}
            value={form.priority}
            min={0}
            hint={t('pages.waf.priorityHint')}
            onChange={(e) => setForm((f) => ({ ...f, priority: Number(e.target.value) }))}
          />
          <div>
            <p className="mb-2 text-[13px] font-medium text-fg">
              {t('pages.waf.severity')}
            </p>
            <div className="flex items-center gap-1.5">
              {SEVERITIES.map((level) => (
                <button
                  key={level}
                  type="button"
                  onClick={() => setForm((f) => ({ ...f, severity: level }))}
                  aria-label={`${t('pages.waf.severity')} ${level}`}
                  aria-pressed={form.severity === level}
                  className={cn(
                    'h-8 flex-1 rounded-md border text-xs font-medium transition-colors',
                    form.severity === level
                      ? level >= 4
                        ? 'border-danger bg-danger/12 text-fg-danger'
                        : 'border-brand bg-brand-soft text-brand-ink'
                      : 'border-line text-fg-subtle hover:border-fill hover:text-fg',
                  )}
                >
                  {level}
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-xs text-fg-subtle">{t('pages.waf.severityHint')}</p>
          </div>
          <div className="sm:col-span-2">
            <TagInput
              label={t('pages.waf.tags')}
              hint={t('pages.waf.tagsHint')}
              value={form.tags}
              suggestions={TAG_SUGGESTIONS}
              placeholder={t('pages.waf.tagPlaceholder')}
              onChange={(tags) => setForm((f) => ({ ...f, tags }))}
            />
          </div>
          <div className="flex items-end">
            <Switch
              checked={form.enabled}
              onCheckedChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
              label={t('common.enabled')}
              description={t('pages.waf.enabledHint')}
            />
          </div>
        </section>

        {/* Draft tester */}
        {testOpen && (
          <section className="space-y-3 rounded-lg border border-focus/30 bg-focus/5 px-4 py-3">
            <div className="flex items-center gap-2">
              <Flask weight="duotone" className="h-4 w-4 text-link" />
              <h3 className="text-[13px] font-semibold text-fg-strong">
                {t('pages.waf.testTitle')}
              </h3>
              {testResult && (
                <Badge
                  tone={
                    testResult.action === 'block'
                      ? 'danger'
                      : testResult.action === 'challenge'
                        ? 'warning'
                        : testResult.action === 'monitor'
                          ? 'warning'
                          : 'success'
                  }
                >
                  {testResult.action}
                </Badge>
              )}
              <Button
                size="sm"
                variant="ghost"
                className="ml-auto"
                loading={test.isPending}
                onClick={() => test.mutate()}
              >
                {t('pages.waf.testRun')}
              </Button>
            </div>
            <p className="text-[12px] text-fg-subtle">{t('pages.waf.testHint')}</p>
            <div className="grid gap-2 sm:grid-cols-5">
              <Select
                label={t('pages.logs.method')}
                value={testMethod}
                onChange={(e) => setTestMethod(e.target.value)}
                options={['GET', 'POST', 'PUT', 'DELETE', 'HEAD'].map((m) => ({
                  value: m,
                  label: m,
                }))}
              />
              <Input
                containerClassName="sm:col-span-2"
                label={t('pages.logs.path')}
                value={testPath}
                onChange={(e) => setTestPath(e.target.value)}
              />
              <Input
                label={t('pages.waf.testQuery')}
                value={testQuery}
                onChange={(e) => setTestQuery(e.target.value)}
              />
              <Input
                label={t('pages.waf.testClientIp')}
                value={testIp}
                onChange={(e) => setTestIp(e.target.value)}
              />
              <Textarea
                containerClassName="sm:col-span-5"
                label={t('pages.waf.testBody')}
                mono
                rows={2}
                value={testBody}
                onChange={(e) => setTestBody(e.target.value)}
              />
            </div>

            {test.isError && (
              <p role="alert" className="text-[12px] text-fg-danger">
                {t('pages.waf.testFailed')}: {String(test.error)}
              </p>
            )}

            {testResult && (
              <div className="space-y-2 rounded-md border border-line bg-elevated px-3 py-2.5 text-[12px]">
                <p className="text-fg">
                  {t('pages.waf.testScore')}: <strong>{testResult.score}</strong>
                  {testResult.details ? ` · ${testResult.details}` : ''}
                </p>
                {testResult.matched_rules.length > 0 && (
                  <ul className="space-y-1">
                    {testResult.matched_rules.map((hit) => (
                      <li key={hit.id} className="flex flex-wrap items-center gap-2">
                        <Badge tone={hit.source === 'draft' ? 'brand' : 'neutral'} size="sm">
                          {hit.source === 'draft'
                            ? t('pages.waf.testDraftBadge')
                            : hit.source}
                        </Badge>
                        <span className="text-fg-strong">{hit.name}</span>
                        <span className="pw-mono text-[11px] text-fg-subtle">
                          {hit.id}
                        </span>
                        {hit.tuned && (
                          <Badge tone="warning" size="sm">
                            {t('pages.waf.testTuned')}
                          </Badge>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
                {draftIds.size === 0 && (
                  <p className="text-fg-subtle">{t('pages.waf.testNoMatch')}</p>
                )}
                {testResult.notes.length > 0 && (
                  <ul className="list-disc space-y-0.5 pl-4 text-fg-subtle">
                    {testResult.notes.map((note, index) => (
                      <li key={index}>{note}</li>
                    ))}
                  </ul>
                )}
                <p className="text-[11px] text-fg-subtle">
                  {t('pages.waf.testSimulated')}: {testResult.simulated.join(', ')}
                  {testResult.skipped.length > 0
                    ? ` · ${t('pages.waf.testSkipped')}: ${testResult.skipped.join(', ')}`
                    : ''}
                </p>
              </div>
            )}
          </section>
        )}

        {error && (
          <p role="alert" className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger">
            {error}
          </p>
        )}
      </div>
    </Dialog>
  )
}

export default RuleDialog
