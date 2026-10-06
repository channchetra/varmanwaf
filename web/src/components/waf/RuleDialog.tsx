import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash, CaretUpDown, BracketsCurly } from '@phosphor-icons/react'
import { Dialog } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Textarea } from '@/components/ui/Textarea'
import { TagInput } from '@/components/ui/MultiSelect'
import { useToast } from '@/components/ui/Toast'
import { cn } from '@/lib/utils'
import { rulesApi, ruleKeys } from '@/api/rules'
import { siteKeys } from '@/api/sites'
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

  return (
    <Dialog
      open={open}
      onClose={save.isPending ? () => undefined : onClose}
      size="lg"
      title={rule ? t('pages.waf.editRule') : t('pages.waf.addRule')}
      description={t('pages.waf.ruleDialogDescription')}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={save.isPending}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={submit} loading={save.isPending}>
            {rule ? t('common.save') : t('common.create')}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
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
        </div>

        <Input
          label={t('common.description')}
          value={form.description}
          placeholder={t('pages.waf.descriptionPlaceholder')}
          onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
        />

        {/* ── Expression ─────────────────────────────────────────────── */}
        <div>
          <div className="mb-2 flex items-center justify-between gap-3">
            <span className="text-[13px] font-medium text-fg">
              {t('pages.waf.expression')}
            </span>
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
            <p className="pw-mono mt-2 break-all rounded-md border border-line bg-recessed px-3 py-2 text-xs text-fg-subtle">
              {expression}
            </p>
          )}
        </div>

        {/* ── Enforcement ────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Select
            label={t('pages.waf.action')}
            value={form.action}
            options={RULE_ACTIONS.map((a) => ({ value: a, label: t(`actions.${a}`, a) }))}
            onChange={(e) => setForm((f) => ({ ...f, action: e.target.value }))}
          />
          <Select
            label={t('pages.waf.mode')}
            value={form.mode}
            hint={t('pages.waf.ruleModeHint')}
            options={RULE_MODES.map((m) => ({ value: m, label: t(`pages.waf.mode_${m}`) }))}
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
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
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
                        : 'border-brand bg-brand-soft text-brand'
                      : 'border-line text-fg-subtle hover:border-fill hover:text-fg',
                  )}
                >
                  {level}
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-xs text-fg-subtle">{t('pages.waf.severityHint')}</p>
          </div>

          <TagInput
            label={t('pages.waf.tags')}
            hint={t('pages.waf.tagsHint')}
            value={form.tags}
            suggestions={TAG_SUGGESTIONS}
            placeholder={t('pages.waf.tagPlaceholder')}
            onChange={(tags) => setForm((f) => ({ ...f, tags }))}
          />
        </div>

        <Switch
          checked={form.enabled}
          onCheckedChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
          label={t('common.enabled')}
          description={t('pages.waf.enabledHint')}
        />

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
