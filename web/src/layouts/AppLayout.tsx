import { Suspense, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import {
  List,
  MagnifyingGlass,
  MoonStars,
  Sun,
  CaretDown,
  UserCircle,
  Gear,
  SignOut,
  Translate,
  ShieldCheck,
  Sparkle,
} from '@phosphor-icons/react'
import { cn } from '@/lib/utils'
import { Sidebar } from '@/components/ui/Sidebar'
import { Breadcrumb, type BreadcrumbItem } from '@/components/ui/Breadcrumb'
import { Button } from '@/components/ui/Button'
import { GlobalSearch } from '@/components/GlobalSearch'
import { ForceChangePasswordDialog } from '@/components/ForceChangePasswordDialog'
import { AssistantWidget } from '@/components/assistant/AssistantWidget'
import { useThemeStore } from '@/stores/themeStore'
import { useAuthStore } from '@/stores/authStore'
import { useAssistantWidgetStore } from '@/stores/assistantWidgetStore'
import { displayApi, displayKeys } from '@/api/display'
import { setDisplayTimeZone } from '@/lib/format'
import { supportedLanguages } from '@/i18n'

const langLabels: Record<string, string> = {
  en: 'English',
}

// Map the first path segment(s) to a translation key for breadcrumbs.
const crumbKeys: Record<string, string> = {
  dashboard: 'pages.dashboard.title',
  sites: 'pages.sites.title',
  security: 'nav.security',
  waf: 'pages.waf.title',
  'rate-limiting': 'pages.rateLimiting.title',
  bot: 'pages.bot.title',
  cc: 'pages.cc.title',
  'ip-rules': 'pages.ipRules.title',
  caching: 'pages.caching.title',
  ssl: 'pages.ssl.title',
  traffic: 'pages.traffic.title',
  rules: 'nav.security',
  rewrite: 'pages.rewrite.title',
  'error-pages': 'pages.errorPages.title',
  settings: 'pages.settings.title',
  logs: 'pages.logs.title',
  assistant: 'pages.assistant.title',
  agents: 'pages.agents.title',
  'blocked-ips': 'pages.blockedIps.title',
  notifications: 'pages.notifications.title',
  'config-history': 'pages.configHistory.title',
  reports: 'pages.reports.title',
  lifecycle: 'pages.lifecycle.title',
}

export function AppLayout() {
  const { t, i18n } = useTranslation()
  const location = useLocation()
  const isTopologyCanvas =
    location.pathname === '/topology' ||
    /^\/sites\/[^/]+\/topology\/?$/.test(location.pathname)
  const navigate = useNavigate()
  const { resolved, toggle } = useThemeStore()
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)
  const toggleAssistant = useAssistantWidgetStore((s) => s.toggle)
  // The instance timezone renders every absolute timestamp in the console;
  // applied here once, and again from the Settings card after a change.
  const display = useQuery({
    queryKey: displayKeys.settings(),
    queryFn: () => displayApi.get(),
  })
  useEffect(() => {
    if (display.data) setDisplayTimeZone(display.data.timezone)
  }, [display.data])
  // The assistant stays administrator-only (fork divergence): the provider
  // key is shared fleet-wide and its write tools can reach every site.
  const isAdmin = user?.role === 'admin'

  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [searchOpen, setSearchOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [langMenuOpen, setLangMenuOpen] = useState(false)
  const userMenuRef = useRef<HTMLDivElement>(null)
  const langMenuRef = useRef<HTMLDivElement>(null)

  // Close the mobile drawer on navigation (render-phase reset on prop change,
  // so the drawer never flashes open for the new page).
  const [lastPathname, setLastPathname] = useState(location.pathname)
  if (location.pathname !== lastPathname) {
    setLastPathname(location.pathname)
    setMobileOpen(false)
  }

  // Close dropdowns on outside click.
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setUserMenuOpen(false)
      }
      if (langMenuRef.current && !langMenuRef.current.contains(e.target as Node)) {
        setLangMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  // Cmd/Ctrl+K opens the global search palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setSearchOpen(true)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  const crumbs = useMemo<BreadcrumbItem[]>(() => {
    const segments = location.pathname.split('/').filter(Boolean)
    const items: BreadcrumbItem[] = [{ label: t('app.name'), to: '/dashboard' }]
    let path = ''
    for (const seg of segments) {
      path += `/${seg}`
      // Skip the raw site id segment; label it as the site name context.
      const key = crumbKeys[seg]
      if (key) {
        items.push({ label: t(key), to: path })
      } else if (/^[a-zA-Z0-9_-]{8,}$/.test(seg)) {
        items.push({ label: seg.slice(0, 8), to: path })
      }
    }
    return items
  }, [location.pathname, t])

  const handleLogout = () => {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex h-full w-full overflow-hidden bg-base">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      {/* Desktop sidebar */}
      <aside
        className={cn(
          'relative z-20 hidden shrink-0 border-r border-line bg-elevated transition-[width] duration-200 ease-out md:block',
          collapsed ? 'w-16' : 'w-60',
        )}
      >
        <div className="flex h-full flex-col">
          <SidebarHeader collapsed={collapsed} />
          <Sidebar collapsed={collapsed} />
          <SidebarFooter
            collapsed={collapsed}
            onToggle={() => setCollapsed((c) => !c)}
          />
        </div>
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div
            className="absolute inset-0 animate-fade-in bg-overlay"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="absolute left-0 top-0 flex h-full w-60 flex-col border-r border-line bg-elevated shadow-lg">
            <SidebarHeader collapsed={false} />
            <Sidebar collapsed={false} onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-elevated/85 px-4 backdrop-blur">
          <Button
            size="icon"
            variant="ghost"
            className="md:hidden"
            aria-label="Open navigation"
            onClick={() => setMobileOpen(true)}
            icon={<List weight="bold" className="h-5 w-5" />}
          />

          <Breadcrumb items={crumbs} className="hidden min-w-0 sm:block" />

          <div className="ml-auto flex items-center gap-2">
            {/* Search opens the palette (⌘/Ctrl+K) */}
            <button
              type="button"
              onClick={() => setSearchOpen(true)}
              className="relative hidden h-9 w-64 items-center rounded-md border border-line bg-recessed pl-9 pr-12 text-left text-sm text-fg-subtle transition-colors hover:border-focus lg:flex"
            >
              <MagnifyingGlass
                weight="duotone"
                className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle"
              />
              <span className="truncate">{t('search.placeholder')}</span>
              <kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 rounded border border-line bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-fg-subtle">
                ⌘K
              </kbd>
            </button>

            {searchOpen && <GlobalSearch onClose={() => setSearchOpen(false)} />}

            {/* First-sign-in accounts replace their password before anything
                else; the dialog hides itself once the flag clears. */}
            <ForceChangePasswordDialog />

            {/* Language */}
            <div className="relative" ref={langMenuRef}>
              <Button
                size="icon"
                variant="ghost"
                aria-label={t('user.language')}
                onClick={() => setLangMenuOpen((o) => !o)}
                icon={<Translate weight="duotone" className="h-5 w-5" />}
              />
              {langMenuOpen && (
                <DropdownMenu className="right-0 w-40">
                  {supportedLanguages.map((lng) => (
                    <DropdownItem
                      key={lng}
                      active={i18n.language?.startsWith(lng)}
                      onClick={() => {
                        void i18n.changeLanguage(lng)
                        setLangMenuOpen(false)
                      }}
                    >
                      {langLabels[lng]}
                    </DropdownItem>
                  ))}
                </DropdownMenu>
              )}
            </div>

            {/* Theme toggle */}
            <Button
              size="icon"
              variant="ghost"
              aria-label={t('theme.toggle')}
              title={t('theme.toggle')}
              onClick={toggle}
              icon={
                resolved === 'dark' ? (
                  <Sun weight="duotone" className="h-5 w-5" />
                ) : (
                  <MoonStars weight="duotone" className="h-5 w-5" />
                )
              }
            />

            {/* AI assistant panel (administrators only, like the page) */}
            {isAdmin && (
              <Button
                size="icon"
                variant="ghost"
                aria-label={t('pages.assistant.open')}
                title={t('pages.assistant.open')}
                onClick={toggleAssistant}
                icon={<Sparkle weight="duotone" className="h-5 w-5" />}
              />
            )}

            {/* User menu */}
            <div className="relative" ref={userMenuRef}>
              <button
                onClick={() => setUserMenuOpen((o) => !o)}
                aria-label={user?.name ?? user?.email ?? t('user.account')}
                aria-haspopup="menu"
                aria-expanded={userMenuOpen}
                className="flex items-center gap-1.5 rounded-md px-1.5 py-1 transition-colors hover:bg-recessed max-sm:min-h-11"
              >
                <UserCircle weight="duotone" className="h-7 w-7 text-brand-ink" />
                <CaretDown weight="bold" className="h-3 w-3 text-fg-subtle" />
              </button>
              {userMenuOpen && (
                <DropdownMenu className="right-0 w-56">
                  <div className="border-b border-line px-3 py-2">
                    <p className="truncate text-sm font-medium text-fg-strong">
                      {user?.name ?? user?.email ?? t('user.anonymous')}
                    </p>
                    <p className="truncate text-xs text-fg-subtle">
                      {user?.email}
                      {user?.role ? ` · ${t(`user.role.${user.role}`, user.role)}` : ''}
                    </p>
                  </div>
                  <DropdownItem
                    icon={<Gear className="h-4 w-4" />}
                    onClick={() => {
                      setUserMenuOpen(false)
                      navigate('/settings')
                    }}
                  >
                    {t('user.account')}
                  </DropdownItem>
                  <DropdownItem
                    icon={<SignOut className="h-4 w-4" />}
                    onClick={handleLogout}
                  >
                    {t('user.signOut')}
                  </DropdownItem>
                </DropdownMenu>
              )}
            </div>
          </div>
        </header>

        <main id="main" tabIndex={-1} className="flex-1 overflow-y-auto outline-none">
          {/* The topology canvas owns the whole main column; every other
              surface keeps the 1400px reading measure. */}
          <div
            className={cn(
              'w-full px-4 py-6 sm:px-6 lg:px-8',
              !isTopologyCanvas && 'mx-auto max-w-[1400px]',
            )}
          >
            <Suspense
              fallback={
                <div
                  role="status"
                  aria-live="polite"
                  className="flex min-h-60 items-center justify-center gap-2 text-sm text-fg-subtle"
                >
                  <span className="h-2 w-2 animate-pulse rounded-full bg-brand-ink" />
                  Loading…
                </div>
              }
            >
              <Outlet />
            </Suspense>
          </div>
        </main>
      </div>

      {/* Floating AI assistant (ball + sliding panel, mounted for the whole
          admin session; streaming state survives open/close cycles). */}
      {isAdmin && <AssistantWidget />}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Sub-components                                                      */
/* ------------------------------------------------------------------ */

function SidebarHeader({ collapsed }: { collapsed: boolean }) {
  return (
    <Link
      to="/dashboard"
      className={cn(
        'flex h-14 shrink-0 items-center gap-2.5 border-b border-line px-4',
        collapsed && 'justify-center px-0',
      )}
    >
      <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand text-on-brand">
        <ShieldCheck weight="fill" className="h-5 w-5" />
      </span>
      {!collapsed && (
        <span className="text-[15px] font-semibold tracking-tight text-fg-strong">
          VarmanWAF
        </span>
      )}
    </Link>
  )
}

function SidebarFooter({
  collapsed,
  onToggle,
}: {
  collapsed: boolean
  onToggle: () => void
}) {
  const { t } = useTranslation()
  return (
    <div className="shrink-0 border-t border-line p-2">
      <button
        onClick={onToggle}
        className={cn(
          'flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-fg-subtle transition-colors hover:bg-recessed hover:text-fg',
          collapsed && 'justify-center px-0',
        )}
        title={collapsed ? t('sidebar.expand') : t('sidebar.collapse')}
      >
        <CaretDown
          weight="bold"
          className={cn(
            'h-4 w-4 shrink-0 transition-transform duration-200',
            collapsed ? '-rotate-90' : 'rotate-90',
          )}
        />
        {!collapsed && <span>{t('sidebar.collapse')}</span>}
      </button>
    </div>
  )
}

function DropdownMenu({
  className,
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return (
    <div
      className={cn(
        'absolute z-50 mt-2 animate-scale-in overflow-hidden rounded-lg border border-line bg-elevated py-1 shadow-lg',
        className,
      )}
    >
      {children}
    </div>
  )
}

function DropdownItem({
  children,
  icon,
  onClick,
  active,
}: {
  children: ReactNode
  icon?: ReactNode
  onClick?: () => void
  active?: boolean
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm transition-colors',
        active ? 'bg-brand-soft text-brand-ink' : 'text-fg hover:bg-recessed',
      )}
    >
      {icon}
      <span className="truncate">{children}</span>
    </button>
  )
}
