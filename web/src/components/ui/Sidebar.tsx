import { useState } from 'react'
import { NavLink, useMatch } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  House,
  Globe,
  Shield,
  Lightning,
  Lock,
  ChartLine,
  List,
  Desktop,
  Gear,
  Gauge,
  Robot,
  IdentificationCard,
  FunnelSimple,
  CaretDown,
  Network,
  FlowArrow,
  Sparkle,
  type Icon,
} from '@phosphor-icons/react'
import { cn } from '@/lib/utils'

interface NavLeaf {
  to: string
  labelKey: string
  icon: Icon
  end?: boolean
  requiresSite?: boolean
}

interface NavSub {
  to: string
  labelKey: string
  icon: Icon
  requiresSite?: boolean
}

interface NavGroup {
  labelKey: string
  icon: Icon
  children: NavSub[]
}

type NavEntry =
  | ({ kind: 'leaf' } & NavLeaf)
  | ({ kind: 'group' } & NavGroup)

export interface SidebarProps {
  collapsed: boolean
  onNavigate?: () => void
}

export function Sidebar({ collapsed, onNavigate }: SidebarProps) {
  const { t } = useTranslation()
  // Resolve the active site so site-scoped links point at the current site.
  const siteMatch = useMatch('/sites/:siteId/*')
  const siteId = siteMatch?.params.siteId
  const site = (path: string) => (siteId ? `/sites/${siteId}/${path}` : '/sites')
  // Per-site nav items should be disabled when no site is selected.
  const hasSiteContext = Boolean(siteId)

  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({
    security: true,
  })

  const toggleGroup = (key: string) =>
    setOpenGroups((g) => ({ ...g, [key]: !g[key] }))

  const nav: NavEntry[] = [
    { kind: 'leaf', to: '/dashboard', labelKey: 'nav.dashboard', icon: House },
    { kind: 'leaf', to: '/sites', labelKey: 'nav.sites', icon: Globe },
    {
      kind: 'group',
      labelKey: 'nav.security',
      icon: Shield,
      children: [
        {
          to: site('security/protection'),
          labelKey: 'nav.securityProtection',
          icon: Shield,
          requiresSite: true,
        },
        {
          to: site('security/rate-limiting'),
          labelKey: 'nav.securityRateLimiting',
          icon: Gauge,
          requiresSite: true,
        },
        { to: site('security/bot'), labelKey: 'nav.securityBot', icon: Robot, requiresSite: true },
        {
          to: site('security/access'),
          labelKey: 'nav.securityAccess',
          icon: IdentificationCard,
          requiresSite: true,
        },
      ],
    },
    { kind: 'leaf', to: site('origin'), labelKey: 'nav.origin', icon: Network, requiresSite: true },
    { kind: 'leaf', to: site('caching'), labelKey: 'nav.caching', icon: Lightning, requiresSite: true },
    { kind: 'leaf', to: '/ip-groups', labelKey: 'nav.ipGroups', icon: FunnelSimple },
    // SSL/TLS and traffic in the sidebar are the *global* surfaces; each site's
    // own certificates and traffic live in that site's tab bar.
    { kind: 'leaf', to: '/ssl', labelKey: 'nav.ssl', icon: Lock },
    { kind: 'leaf', to: '/traffic', labelKey: 'nav.traffic', icon: ChartLine },
    { kind: 'leaf', to: '/logs', labelKey: 'nav.logs', icon: List },
    { kind: 'leaf', to: '/assistant', labelKey: 'nav.assistant', icon: Sparkle },
    { kind: 'leaf', to: '/agents', labelKey: 'nav.agents', icon: Desktop },
    { kind: 'leaf', to: '/lifecycle', labelKey: 'nav.lifecycle', icon: FlowArrow },
    { kind: 'leaf', to: '/settings', labelKey: 'nav.settings', icon: Gear },
  ]

  const linkBase =
    'group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors duration-150'
  const linkIdle = 'text-fg-subtle hover:bg-recessed hover:text-fg'
  const linkActive = 'bg-brand-soft text-brand'

  return (
    <nav className="flex h-full flex-col gap-0.5 overflow-y-auto px-2 py-3">
      {nav.map((entry) => {
        if (entry.kind === 'leaf') {
          const IconCmp = entry.icon
          const disabled = entry.requiresSite && !hasSiteContext
          return (
            <NavLink
              key={entry.labelKey}
              to={entry.to}
              end={entry.end}
              onClick={(e) => {
                if (disabled) {
                  e.preventDefault()
                  return
                }
                onNavigate?.()
              }}
              title={collapsed ? (disabled ? t('nav.selectSiteFirst') : t(entry.labelKey)) : undefined}
              className={({ isActive }) =>
                cn(
                  linkBase,
                  disabled
                    ? 'cursor-not-allowed opacity-50'
                    : isActive
                      ? linkActive
                      : linkIdle,
                  collapsed && 'justify-center px-0',
                )
              }
              aria-disabled={disabled}
            >
              <IconCmp weight="duotone" className="h-5 w-5 shrink-0" />
              {!collapsed && <span className="truncate">{t(entry.labelKey)}</span>}
            </NavLink>
          )
        }

        // group
        const IconCmp = entry.icon
        const groupKey = entry.labelKey
        const isOpen = openGroups[groupKey] ?? false
        // Only consider children active if they have a valid site context.
        const childActive = hasSiteContext && entry.children.some((c) =>
          window.location.pathname.startsWith(c.to),
        )

        if (collapsed) {
          const groupDisabled = !hasSiteContext && entry.children.some((c) => c.requiresSite)
          return (
            <NavLink
              key={groupKey}
              to={entry.children[0].to}
              onClick={(e) => {
                if (groupDisabled) {
                  e.preventDefault()
                  return
                }
                onNavigate?.()
              }}
              title={groupDisabled ? t('nav.selectSiteFirst') : t(groupKey)}
              className={({ isActive }) =>
                cn(
                  linkBase,
                  'justify-center px-0',
                  groupDisabled
                    ? 'cursor-not-allowed opacity-50'
                    : isActive || childActive
                      ? linkActive
                      : linkIdle,
                )
              }
              aria-disabled={groupDisabled}
            >
              <IconCmp weight="duotone" className="h-5 w-5 shrink-0" />
            </NavLink>
          )
        }

        return (
          <div key={groupKey}>
            <button
              type="button"
              onClick={() => toggleGroup(groupKey)}
              className={cn(
                linkBase,
                'w-full',
                childActive ? 'text-brand' : 'text-fg-subtle hover:bg-recessed hover:text-fg',
              )}
              aria-expanded={isOpen}
            >
              <IconCmp weight="duotone" className="h-5 w-5 shrink-0" />
              <span className="flex-1 truncate text-left">{t(groupKey)}</span>
              <CaretDown
                weight="bold"
                className={cn(
                  'h-3.5 w-3.5 shrink-0 transition-transform duration-200',
                  isOpen && 'rotate-180',
                )}
              />
            </button>
            <div
              className={cn(
                'grid transition-[grid-template-rows] duration-200 ease-out',
                isOpen ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]',
              )}
            >
              <div className="overflow-hidden">
                <div className="ml-4 mt-0.5 flex flex-col gap-0.5 border-l border-line pl-2">
                  {entry.children.map((child) => {
                    const ChildIcon = child.icon
                    const childDisabled = child.requiresSite && !hasSiteContext
                    return (
                      <NavLink
                        key={child.to + child.labelKey}
                        to={child.to}
                        onClick={(e) => {
                          if (childDisabled) {
                            e.preventDefault()
                            return
                          }
                          onNavigate?.()
                        }}
                        className={({ isActive }) =>
                          cn(
                            'flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] transition-colors duration-150',
                            childDisabled
                              ? 'cursor-not-allowed opacity-50'
                              : isActive
                                ? 'bg-brand-soft font-medium text-brand'
                                : 'text-fg-subtle hover:bg-recessed hover:text-fg',
                          )
                        }
                        aria-disabled={childDisabled}
                        title={childDisabled ? t('nav.selectSiteFirst') : undefined}
                      >
                        <ChildIcon className="h-4 w-4 shrink-0" />
                        <span className="truncate">{t(child.labelKey)}</span>
                      </NavLink>
                    )
                  })}
                </div>
              </div>
            </div>
          </div>
        )
      })}
    </nav>
  )
}
