import { useTranslation } from 'react-i18next'
import { Gear } from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Callout } from '@/components/ui/Callout'
import { FailoverPanel } from '@/pages/sites/FailoverPanel'

/**
 * Site settings: behaviour that is neither traffic policy nor a security
 * layer. Today that is the disconnected-edge failover policy; more
 * site-wide knobs land here as they appear.
 */
export function SiteSettingsPage() {
  const { t } = useTranslation()
  return (
    <>
      <PageHeader
        title={t('pages.siteSettings.title')}
        description={t('pages.siteSettings.description')}
      />

      <Callout
        className="mb-4"
        tone="brand"
        icon={<Gear weight="duotone" className="h-5 w-5" />}
        title={t('pages.siteSettings.overviewTitle')}
      >
        {t('pages.siteSettings.overview')}
      </Callout>

      <FailoverPanel />
    </>
  )
}

export default SiteSettingsPage
