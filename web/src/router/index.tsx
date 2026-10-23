/* eslint-disable react-refresh/only-export-components -- router config, not a component module */
import { lazy, type ReactElement } from 'react'
import {
  createBrowserRouter,
  Navigate,
  useLocation,
  useParams,
} from 'react-router-dom'
import { AppLayout } from '@/layouts/AppLayout'
import { useAuthStore } from '@/stores/authStore'
import { EmptyState } from '@/components/ui/EmptyState'
import { Button } from '@/components/ui/Button'

// Keep the login screen and app shell eager; load route surfaces on demand.
import { LoginPage } from '@/pages/LoginPage'

const DashboardPage = lazy(() =>
  import('@/pages/DashboardPage').then((m) => ({ default: m.DashboardPage })),
)
const SitesListPage = lazy(() =>
  import('@/pages/SitesListPage').then((m) => ({ default: m.SitesListPage })),
)
const SiteDetailPage = lazy(() =>
  import('@/pages/SiteDetailPage').then((m) => ({ default: m.SiteDetailPage })),
)
const RateLimitingPage = lazy(() =>
  import('@/pages/RateLimitingPage').then((m) => ({ default: m.RateLimitingPage })),
)
const LogsPage = lazy(() =>
  import('@/pages/LogsPage').then((m) => ({ default: m.LogsPage })),
)
const AgentsPage = lazy(() =>
  import('@/pages/AgentsPage').then((m) => ({ default: m.AgentsPage })),
)
const AssistantPage = lazy(() =>
  import('@/pages/AssistantPage').then((m) => ({ default: m.AssistantPage })),
)
const SettingsPage = lazy(() =>
  import('@/pages/SettingsPage').then((m) => ({ default: m.SettingsPage })),
)
const BotProtectionPage = lazy(() =>
  import('@/pages/sites/BotPage').then((m) => ({ default: m.BotPage })),
)
const ProtectionPage = lazy(() =>
  import('@/pages/sites/ProtectionPage').then((m) => ({ default: m.ProtectionPage })),
)
const AccessControlPage = lazy(() =>
  import('@/pages/sites/AccessControlPage').then((m) => ({ default: m.AccessControlPage })),
)
const ApiAssetsPage = lazy(() =>
  import('@/pages/sites/ApiAssetsPage').then((m) => ({ default: m.ApiAssetsPage })),
)
const CachingPage = lazy(() =>
  import('@/pages/sites/CachingPage').then((m) => ({ default: m.CachingPage })),
)
const SslPage = lazy(() =>
  import('@/pages/sites/SslPage').then((m) => ({ default: m.SslPage })),
)
const TrafficPage = lazy(() =>
  import('@/pages/sites/TrafficPage').then((m) => ({ default: m.TrafficPage })),
)
const GlobalSslPage = lazy(() =>
  import('@/pages/GlobalSslPage').then((m) => ({ default: m.GlobalSslPage })),
)
const GlobalTrafficPage = lazy(() =>
  import('@/pages/GlobalTrafficPage').then((m) => ({ default: m.GlobalTrafficPage })),
)
const IpGroupsPage = lazy(() =>
  import('@/pages/IpGroupsPage').then((m) => ({ default: m.IpGroupsPage })),
)
const RewritePage = lazy(() =>
  import('@/pages/sites/RewritePage').then((m) => ({ default: m.RewritePage })),
)
const OriginPage = lazy(() =>
  import('@/pages/sites/OriginPage').then((m) => ({ default: m.OriginPage })),
)
const SiteOverviewPage = lazy(() =>
  import('@/pages/sites/SiteOverviewPage').then((m) => ({ default: m.SiteOverviewPage })),
)
const LifecyclePage = lazy(() =>
  import('@/pages/LifecyclePage').then((m) => ({ default: m.LifecyclePage })),
)
const PoliciesPage = lazy(() =>
  import('@/pages/PoliciesPage').then((m) => ({ default: m.PoliciesPage })),
)
const PolicyDetailPage = lazy(() =>
  import('@/pages/PolicyDetailPage').then((m) => ({ default: m.PolicyDetailPage })),
)
const CrsPage = lazy(() =>
  import('@/pages/CrsPage').then((m) => ({ default: m.CrsPage })),
)
const AlertsPage = lazy(() =>
  import('@/pages/AlertsPage').then((m) => ({ default: m.AlertsPage })),
)
const BlockedIpsPage = lazy(() =>
  import('@/pages/BlockedIpsPage').then((m) => ({ default: m.BlockedIpsPage })),
)
const ConfigHistoryPage = lazy(() =>
  import('@/pages/ConfigHistoryPage').then((m) => ({ default: m.ConfigHistoryPage })),
)
const ReportsPage = lazy(() =>
  import('@/pages/ReportsPage').then((m) => ({ default: m.ReportsPage })),
)
const SiteSettingsPage = lazy(() =>
  import('@/pages/sites/SiteSettingsPage').then((m) => ({ default: m.SiteSettingsPage })),
)
const TopologyPage = lazy(() =>
  import('@/pages/TopologyPage').then((m) => ({ default: m.TopologyPage })),
)

/** Redirects unauthenticated users to the login page. */
function RequireAuth({ children }: { children: ReactElement }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const location = useLocation()
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }
  return children
}

function NotFoundPage() {
  return (
    <EmptyState
      title="Page not found"
      description="The page you are looking for doesn't exist or has been moved."
      action={
        <Button variant="primary" onClick={() => (window.location.href = '/dashboard')}>
          Back to dashboard
        </Button>
      }
    />
  )
}

/** Legacy deep links: keep their query string while moving to the merged tab. */
function LegacyProtectionRedirect({ tab }: { tab: 'rules' | 'cc' }) {
  const { siteId = '' } = useParams<{ siteId: string }>()
  const location = useLocation()
  const params = new URLSearchParams(location.search)
  params.set('tab', tab)
  return (
    <Navigate to={`/sites/${siteId}/security/protection?${params.toString()}`} replace />
  )
}

function LegacySecurityRedirect({ tab }: { tab: 'ip' | 'geo' }) {
  const { siteId = '' } = useParams<{ siteId: string }>()
  const location = useLocation()
  const params = new URLSearchParams(location.search)
  params.set('tab', tab)
  return (
    <Navigate to={`/sites/${siteId}/security/access?${params.toString()}`} replace />
  )
}

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/',
    element: (
      <RequireAuth>
        <AppLayout />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <Navigate to="/dashboard" replace /> },
      { path: 'dashboard', element: <DashboardPage /> },
      { path: 'sites', element: <SitesListPage /> },
      {
        path: 'sites/:siteId',
        element: <SiteDetailPage />,
        children: [
          { index: true, element: <Navigate to="overview" replace /> },
          { path: 'overview', element: <SiteOverviewPage /> },
          { path: 'origin', element: <OriginPage /> },
          { path: 'security/protection', element: <ProtectionPage /> },
          { path: 'security/rate-limiting', element: <RateLimitingPage /> },
          { path: 'security/bot', element: <BotProtectionPage /> },
          { path: 'security/access', element: <AccessControlPage /> },
          { path: 'security/api-assets', element: <ApiAssetsPage /> },
          // The policy surface lives inside Web Protection now; old links
          // keep working.
          {
            path: 'security/policy',
            element: <Navigate to="../protection?tab=policy" replace />,
          },
          // WAF and CC were separate tabs before they were merged; keep old
          // links (including the `?rule=` deep link) working.
          {
            path: 'security/waf',
            element: <LegacyProtectionRedirect tab="rules" />,
          },
          {
            path: 'security/cc',
            element: <LegacyProtectionRedirect tab="cc" />,
          },
          // IP rules and geo were separate tabs before they were merged; keep
          // old links (including `?block=…` deep links) working.
          {
            path: 'security/ip-rules',
            element: <LegacySecurityRedirect tab="ip" />,
          },
          {
            path: 'security/geo',
            element: <LegacySecurityRedirect tab="geo" />,
          },
          { path: 'caching', element: <CachingPage /> },
          { path: 'ssl', element: <SslPage /> },
          { path: 'traffic', element: <TrafficPage /> },
          { path: 'rules/rewrite', element: <RewritePage /> },
          { path: 'settings', element: <SiteSettingsPage /> },
          { path: 'topology', element: <TopologyPage /> },
        ],
      },
      { path: 'logs', element: <LogsPage /> },
      { path: 'assistant', element: <AssistantPage /> },
      { path: 'agents', element: <AgentsPage /> },
      { path: 'ip-groups', element: <IpGroupsPage /> },
      { path: 'blocked-ips', element: <BlockedIpsPage /> },
      { path: 'policies', element: <PoliciesPage /> },
      { path: 'policies/:policyId', element: <PolicyDetailPage /> },
      { path: 'topology', element: <TopologyPage /> },
      { path: 'crs', element: <CrsPage /> },
      { path: 'alerts', element: <AlertsPage /> },
      { path: 'notifications', element: <Navigate to="/alerts" replace /> },
      { path: 'config-history', element: <ConfigHistoryPage /> },
      { path: 'reports', element: <ReportsPage /> },
      { path: 'lifecycle', element: <LifecyclePage /> },
      // Global surfaces. The per-site counterparts live under `/sites/:siteId`.
      { path: 'ssl', element: <GlobalSslPage /> },
      { path: 'traffic', element: <GlobalTrafficPage /> },
      { path: 'settings', element: <SettingsPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
])

export default router
