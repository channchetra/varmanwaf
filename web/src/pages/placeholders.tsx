import { useTranslation } from 'react-i18next'
import {
  Robot,
  IdentificationCard,
  Lightning,
  Lock,
  ChartLine,
  Sliders,
  FileHtml,
  Gear,
} from '@phosphor-icons/react'
import { PlaceholderPage } from '@/components/PlaceholderPage'

/** Site-scoped security & rule pages that share the standard shell. */

export function BotProtectionPage() {
  const { t } = useTranslation()
  return (
    <PlaceholderPage
      title={t('pages.bot.title')}
      description={t('pages.bot.description')}
      icon={<Robot weight="duotone" />}
      emptyTitle={t('pages.bot.empty')}
    />
  )
}

export function IpRulesPage() {
  const { t } = useTranslation()
  return (
    <PlaceholderPage
      title={t('pages.ipRules.title')}
      description={t('pages.ipRules.description')}
      icon={<IdentificationCard weight="duotone" />}
      emptyTitle={t('pages.ipRules.empty')}
      actionLabel={t('pages.ipRules.addRule')}
    />
  )
}

export function CachingPage() {
  const { t } = useTranslation()
  return (
    <PlaceholderPage
      title={t('pages.caching.title')}
      description={t('pages.caching.description')}
      icon={<Lightning weight="duotone" />}
      emptyTitle={t('pages.caching.empty')}
      actionLabel={t('pages.caching.purgeAll')}
    />
  )
}

export function SslPage() {
  const { t } = useTranslation()
  return (
    <PlaceholderPage
      title={t('pages.ssl.title')}
      description={t('pages.ssl.description')}
      icon={<Lock weight="duotone" />}
      emptyTitle={t('pages.ssl.certificate')}
    />
  )
}

export function TrafficPage() {
  const { t } = useTranslation()
  return (
    <PlaceholderPage
      title={t('pages.traffic.title')}
      description={t('pages.traffic.description')}
      icon={<ChartLine weight="duotone" />}
      emptyTitle={t('pages.traffic.requests')}
    />
  )
}

export function RewritePage() {
  const { t } = useTranslation()
  return (
    <PlaceholderPage
      title={t('pages.rewrite.title')}
      description={t('pages.rewrite.description')}
      icon={<Sliders weight="duotone" />}
      emptyTitle={t('pages.rewrite.empty')}
    />
  )
}

export function ErrorPagesPage() {
  const { t } = useTranslation()
  return (
    <PlaceholderPage
      title={t('pages.errorPages.title')}
      description={t('pages.errorPages.description')}
      icon={<FileHtml weight="duotone" />}
      emptyTitle={t('pages.errorPages.empty')}
    />
  )
}

export function SiteSettingsPage() {
  const { t } = useTranslation()
  return (
    <PlaceholderPage
      title={t('pages.siteSettings.title')}
      description={t('pages.siteSettings.description')}
      icon={<Gear weight="duotone" />}
      emptyTitle={t('pages.siteSettings.title')}
    />
  )
}
