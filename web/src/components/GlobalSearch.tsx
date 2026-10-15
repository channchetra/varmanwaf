import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { MagnifyingGlass } from '@phosphor-icons/react'
import { Dialog } from '@/components/ui/Dialog'
import { Badge } from '@/components/ui/Badge'
import { sitesApi, siteKeys } from '@/api/sites'
import { policiesApi, policyKeys } from '@/api/policies'
import { crsApi, crsKeys } from '@/api/crs'
import { alertsApi, alertKeys } from '@/api/alerts'
import { ipGroupsApi, ipGroupKeys } from '@/api/ipGroups'
import { cn } from '@/lib/utils'

interface SearchItem {
  key: string
  group: string
  title: string
  subtitle?: string
  detail?: string
  to: string
}

/** Pages offered as direct jumps when the query matches them. */
const NAV_ITEMS: Array<{ labelKey: string; to: string }> = [
  { labelKey: 'nav.dashboard', to: '/dashboard' },
  { labelKey: 'nav.sites', to: '/sites' },
  { labelKey: 'nav.policies', to: '/policies' },
  { labelKey: 'nav.crs', to: '/crs' },
  { labelKey: 'nav.alerts', to: '/alerts' },
  { labelKey: 'pages.logs.title', to: '/logs' },
  { labelKey: 'nav.agents', to: '/agents' },
  { labelKey: 'pages.ipGroups.title', to: '/ip-groups' },
  { labelKey: 'pages.settings.title', to: '/settings' },
]

const GROUP_ORDER = [
  'navigate',
  'sites',
  'policies',
  'ipLists',
  'crs',
  'alerts',
]

/**
 * Global search (⌘/Ctrl+K): one palette over the things an operator jumps
 * between - pages, sites, policies, IP lists, CRS rulesets and alert rules.
 *
 * It searches the lists the API already exposes (no hidden full-text index),
 * so an entry you can see here is one the backend really has.
 */
export function GlobalSearch({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const listRef = useRef<HTMLUListElement>(null)

  const sites = useQuery({
    queryKey: siteKeys.list({}),
    queryFn: () => sitesApi.list(),
    staleTime: 60_000,
  })
  const policies = useQuery({
    queryKey: policyKeys.list(),
    queryFn: () => policiesApi.list(),
    staleTime: 60_000,
  })
  const groups = useQuery({
    queryKey: ipGroupKeys.list(),
    queryFn: () => ipGroupsApi.list(),
    staleTime: 60_000,
  })
  const rulesets = useQuery({
    queryKey: crsKeys.list(),
    queryFn: () => crsApi.rulesets(),
    staleTime: 60_000,
  })
  const alertRules = useQuery({
    queryKey: alertKeys.rules(),
    queryFn: () => alertsApi.rules(),
    staleTime: 60_000,
  })

  const items = useMemo<SearchItem[]>(() => {
    const out: SearchItem[] = []
    for (const { labelKey, to } of NAV_ITEMS) {
      out.push({ key: `nav:${to}`, group: 'navigate', title: t(labelKey), to })
    }
    for (const site of sites.data?.items ?? []) {
      out.push({
        key: `site:${site.id}`,
        group: 'sites',
        title: site.domain,
        subtitle: site.name,
        to: `/sites/${site.id}`,
      })
    }
    for (const policy of policies.data ?? []) {
      out.push({
        key: `policy:${policy.id}`,
        group: 'policies',
        title: policy.name,
        detail: t('search.policyMeta', {
          revision: policy.revision,
          sites: policy.site_count,
        }),
        to: '/policies',
      })
    }
    for (const group of groups.data?.items ?? []) {
      out.push({
        key: `ipgroup:${group.id}`,
        group: 'ipLists',
        title: group.name,
        detail: t('search.ipListMeta', {
          ranges: group.ip_ranges.length,
          action: group.action,
        }),
        to: '/ip-groups',
      })
    }
    for (const ruleset of rulesets.data ?? []) {
      out.push({
        key: `crs:${ruleset.id}`,
        group: 'crs',
        title: `${ruleset.name}${
          ruleset.version ? ` ${ruleset.version}` : ''
        }`,
        detail: t('search.crsMeta', {
          compiled: ruleset.supported_count,
          total: ruleset.rule_count,
        }),
        to: '/crs',
      })
    }
    for (const rule of alertRules.data ?? []) {
      out.push({
        key: `alert:${rule.id}`,
        group: 'alerts',
        title: rule.name,
        detail: `${rule.metric} ${
          rule.metric === 'blocked_ratio' ? `${rule.threshold}%` : rule.threshold
        } / ${rule.window_seconds}s`,
        to: '/alerts',
      })
    }
    return out
  }, [t, sites.data, policies.data, groups.data, rulesets.data, alertRules.data])

  const needle = query.trim().toLowerCase()
  const filtered = useMemo(() => {
    if (needle === '') return items
    return items.filter((item) =>
      `${item.title} ${item.subtitle ?? ''} ${item.detail ?? ''}`
        .toLowerCase()
        .includes(needle),
    )
  }, [items, needle])

  const visible = useMemo(() => {
    // Without a query keep the palette readable: all navigation entries plus
    // a handful of each data group.
    if (needle !== '') return filtered.slice(0, 40)
    const counts: Record<string, number> = {}
    return filtered.filter((item) => {
      const seen = counts[item.group] ?? 0
      counts[item.group] = seen + 1
      return item.group === 'navigate' || seen < 4
    })
  }, [filtered, needle])

  // Reset the highlighted row when the query changes. Adjusting the state
  // during render (instead of in an effect) avoids a cascading render - the
  // pattern React documents for "adjusting state when a prop changes".
  const [activeQuery, setActiveQuery] = useState(query)
  if (activeQuery !== query) {
    setActiveQuery(query)
    setActive(0)
  }

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setActive((value) => Math.min(value + 1, visible.length - 1))
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setActive((value) => Math.max(value - 1, 0))
    } else if (event.key === 'Enter') {
      event.preventDefault()
      const item = visible[active]
      if (item) {
        navigate(item.to)
        onClose()
      }
    }
  }

  // Keep the active row in view while arrowing through a long list.
  useEffect(() => {
    const node = listRef.current?.querySelector<HTMLElement>(
      `[data-index="${active}"]`,
    )
    node?.scrollIntoView({ block: 'nearest' })
  }, [active])

  const sections = useMemo(
    () =>
      GROUP_ORDER.map((group) => ({
        group,
        items: visible
          .map((item, index) => ({ item, index }))
          .filter((entry) => entry.item.group === group),
      })).filter((section) => section.items.length > 0),
    [visible],
  )

  return (
    <Dialog open onClose={onClose} size="lg" title={t('search.title')}>
      <div className="flex min-h-0 flex-col">
        <div className="relative shrink-0 border-b border-line px-5 py-3">
          <MagnifyingGlass
            weight="duotone"
            className="pointer-events-none absolute left-7 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle"
          />
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={onKeyDown}
            placeholder={t('search.placeholder')}
            className="h-10 w-full rounded-md border border-line bg-recessed pl-9 pr-3 text-sm text-fg placeholder:text-fg-subtle/70 focus:border-focus focus:outline-none"
          />
        </div>

        <ul ref={listRef} className="max-h-[55vh] min-h-0 flex-1 overflow-y-auto py-2">
          {visible.length === 0 ? (
            <li className="px-5 py-8 text-center text-[13px] text-fg-subtle">
              {t('search.noResults')}
            </li>
          ) : (
            sections.map((section) => (
              <li key={section.group}>
                <p className="px-5 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">
                  {t(`search.groups.${section.group}`)}
                </p>
                <ul>
                  {section.items.map(({ item, index }) => (
                    <li key={item.key}>
                      <button
                        type="button"
                        data-index={index}
                        onClick={() => {
                          navigate(item.to)
                          onClose()
                        }}
                        onMouseEnter={() => setActive(index)}
                        className={cn(
                          'flex w-full items-center gap-3 px-5 py-2 text-left transition-colors',
                          index === active ? 'bg-recessed' : undefined,
                        )}
                      >
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-[13px] font-medium text-fg-strong">
                            {item.title}
                          </span>
                          {(item.subtitle || item.detail) && (
                            <span className="block truncate text-[12px] text-fg-subtle">
                              {item.subtitle ?? item.detail}
                            </span>
                          )}
                        </span>
                        {item.subtitle && item.detail && (
                          <Badge tone="neutral">{item.detail}</Badge>
                        )}
                      </button>
                    </li>
                  ))}
                </ul>
              </li>
            ))
          )}
        </ul>

        <div className="shrink-0 border-t border-line px-5 py-2 text-[11px] text-fg-subtle">
          {t('search.hint')}
        </div>
      </div>
    </Dialog>
  )
}

export default GlobalSearch
