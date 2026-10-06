/**
 * A tiny, round-trippable rule-expression language for the WAF console.
 *
 * The control plane stores `rules.expression` as an opaque string and ships it
 * verbatim to the agents, so the console owns the canonical syntax. It is
 * deliberately wirefilter-flavoured and flat:
 *
 *     http.request.uri.path starts_with "/admin" and ip.src in { "10.0.0.1" "10.0.0.2" }
 *
 * `buildExpression` renders the builder form, `parseExpression` reads a stored
 * expression back into that form so editing never loses information — anything
 * that does not parse is shown in the raw editor instead.
 */

export type ExpressionOperator =
  | 'eq'
  | 'ne'
  | 'contains'
  | 'not_contains'
  | 'starts_with'
  | 'ends_with'
  | 'matches'
  | 'in'

export type ExpressionCombinator = 'and' | 'or'

export interface ExpressionCondition {
  field: string
  operator: ExpressionOperator
  value: string
}

export interface ParsedExpression {
  conditions: ExpressionCondition[]
  combinator: ExpressionCombinator
}

export const EXPRESSION_OPERATORS: ExpressionOperator[] = [
  'eq',
  'ne',
  'contains',
  'not_contains',
  'starts_with',
  'ends_with',
  'matches',
  'in',
]

/** Fields the builder offers. `headerName` marks the ones needing a header key. */
export interface ExpressionField {
  value: string
  /** i18n key suffix under `pages.waf.fields.*`. */
  labelKey: string
  placeholder: string
  /** Values for this field are a fixed vocabulary — rendered as a select. */
  choices?: string[]
}

export const EXPRESSION_FIELDS: ExpressionField[] = [
  {
    value: 'http.request.uri.path',
    labelKey: 'path',
    placeholder: '/admin',
  },
  {
    value: 'http.request.uri.query',
    labelKey: 'query',
    placeholder: 'id=1 UNION SELECT',
  },
  {
    value: 'http.request.uri',
    labelKey: 'uri',
    placeholder: '/api/v1/users?id=1',
  },
  {
    value: 'http.host',
    labelKey: 'host',
    placeholder: 'example.com',
  },
  {
    value: 'http.request.method',
    labelKey: 'method',
    placeholder: 'GET',
    choices: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
  },
  {
    value: 'http.user_agent',
    labelKey: 'userAgent',
    placeholder: 'sqlmap/1.8',
  },
  {
    value: 'http.referer',
    labelKey: 'referer',
    placeholder: 'https://evil.example',
  },
  {
    value: 'http.cookie',
    labelKey: 'cookie',
    placeholder: 'session=',
  },
  {
    value: 'http.request.headers',
    labelKey: 'headers',
    placeholder: 'x-forwarded-for',
  },
  {
    value: 'ip.src',
    labelKey: 'clientIp',
    placeholder: '203.0.113.44',
  },
  {
    value: 'ip.src.country',
    labelKey: 'country',
    placeholder: 'CN',
  },
  {
    value: 'http.request.uri.args',
    labelKey: 'args',
    placeholder: 'redirect',
  },
]

export const DEFAULT_FIELD = 'http.request.uri.path'

/** Escapes a value for the quoted-string form. */
export function quoteValue(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

function unquoteValue(raw: string): string {
  const trimmed = raw.trim()
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed
      .slice(1, -1)
      .replace(/\\"/g, '"')
      .replace(/\\\\/g, '\\')
  }
  return trimmed
}

/** `{ "a" "b" }` ⇄ newline-separated list, used by the `in` operator. */
export function parseSetValue(raw: string): string[] {
  const trimmed = raw.trim()
  const inner = trimmed.startsWith('{') && trimmed.endsWith('}')
    ? trimmed.slice(1, -1)
    : trimmed
  const out: string[] = []
  const re = /"((?:[^"\\]|\\.)*)"|(\S+)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(inner)) !== null) {
    out.push(m[1] !== undefined ? unquoteValue(`"${m[1]}"`) : m[2])
  }
  return out
}

export function buildSetValue(values: string[]): string {
  const clean = values.map((v) => v.trim()).filter(Boolean)
  if (clean.length === 0) return '{}'
  return `{ ${clean.map(quoteValue).join(' ')} }`
}

export function renderConditionValue(condition: ExpressionCondition): string {
  if (condition.operator === 'in') {
    return buildSetValue(condition.value.split('\n'))
  }
  return quoteValue(condition.value)
}

export function buildExpression(
  conditions: ExpressionCondition[],
  combinator: ExpressionCombinator,
): string {
  const usable = conditions.filter((c) => c.field && c.value.trim().length > 0)
  return usable
    .map((c) => `${c.field} ${c.operator} ${renderConditionValue(c)}`)
    .join(` ${combinator} `)
}

/**
 * Splits on a top-level combinator. Quoted strings and `{…}` sets are skipped so
 * a value containing the word "and" does not break the parse.
 */
function splitTopLevel(input: string, combinator: ExpressionCombinator): string[] {
  const parts: string[] = []
  let depth = 0
  let inString = false
  let escaped = false
  let current = ''
  const needle = ` ${combinator} `

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i]
    if (escaped) {
      current += ch
      escaped = false
      continue
    }
    if (ch === '\\') {
      current += ch
      escaped = true
      continue
    }
    if (ch === '"') {
      inString = !inString
      current += ch
      continue
    }
    if (!inString) {
      if (ch === '{') depth += 1
      else if (ch === '}') depth = Math.max(0, depth - 1)
      else if (depth === 0 && input.startsWith(needle, i)) {
        parts.push(current)
        current = ''
        i += needle.length - 1
        continue
      }
    }
    current += ch
  }
  parts.push(current)
  return parts.map((p) => p.trim()).filter(Boolean)
}

const CONDITION_RE = /^(\S+)\s+(eq|ne|contains|not_contains|starts_with|ends_with|matches|in)\s+(.+)$/

function parseCondition(part: string): ExpressionCondition | null {
  const m = CONDITION_RE.exec(part.trim())
  if (!m) return null
  const [, field, operator, rawValue] = m
  const value =
    operator === 'in' ? parseSetValue(rawValue).join('\n') : unquoteValue(rawValue)
  return { field, operator: operator as ExpressionOperator, value }
}

/**
 * Returns `null` when the expression is not expressible in the builder (free
 * text, parentheses, functions) — the caller then falls back to the raw editor.
 */
export function parseExpression(expression: string): ParsedExpression | null {
  const source = expression.trim()
  if (!source) return null

  const orParts = splitTopLevel(source, 'or')
  if (orParts.length > 1) {
    const conditions = orParts.map(parseCondition)
    if (conditions.every((c): c is ExpressionCondition => c !== null)) {
      return { conditions, combinator: 'or' }
    }
    return null
  }

  const andParts = splitTopLevel(source, 'and')
  const conditions = andParts.map(parseCondition)
  if (conditions.every((c): c is ExpressionCondition => c !== null)) {
    return { conditions, combinator: 'and' }
  }
  return null
}

/** Human-readable one-liner for tables and confirmations. */
export function describeExpression(expression: string): string {
  return expression.trim() || '—'
}
