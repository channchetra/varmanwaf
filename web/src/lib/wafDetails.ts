/**
 * Read the rule that actually decided an event from the agent's
 * `waf_details` string.
 *
 * The event row stores the first match in `rule_id`. A weak signature can
 * match first (e.g. `SSRF-006` in a User-Agent) while a managed rule later in
 * the same string forced the block (`VARMAN-1020`). The list uses this helper
 * so the rule column names the deciding rule, not the first match. The
 * server-side why-chain remains the authoritative resolver.
 */
export interface DecidingRule {
  id: string
  name: string
  action: 'block' | 'challenge' | 'js_challenge'
}

const REASON_PREFIX =
  /^(?:clean|likely-clean|likely-attack|attack|stage1-critical):\s*/

export function decidingRule(
  details: string | null | undefined,
): DecidingRule | null {
  if (!details) return null
  const cleaned = details.replace(REASON_PREFIX, '')
  for (const segment of cleaned.split('; ')) {
    const match = segment.match(
      /^([^\s[]+)\s+\[([^\]]*)\]\s+action=(block|challenge|js_challenge)\b/i,
    )
    if (!match) continue
    const [, id, name, action] = match
    return {
      id,
      name: name.trim(),
      action: action.toLowerCase() as DecidingRule['action'],
    }
  }
  return null
}
