import type { Site, SiteProtectionMode } from '@/api/types'

/**
 * The sites list and overview use the progressive labels (“Blocking”,
 * “Monitoring”), while the Protection mode picker keeps the short action
 * names (“Block”, “Monitor”). Keep that distinction in one place.
 */
const LABEL_KEY: Record<SiteProtectionMode, string> = {
  block: 'status.blocking',
  monitor: 'status.monitoring',
  paused: 'status.paused',
  off: 'status.off',
  pending: 'status.pending',
}

export function protectionModeLabelKey(mode: SiteProtectionMode): string {
  return LABEL_KEY[mode]
}

/**
 * The effective mode, with a lifecycle-only fallback for servers that
 * predate `protection_mode`.
 */
export function protectionModeOf(
  site: Pick<Site, 'protection_mode' | 'status'>,
): SiteProtectionMode {
  const mode = site.protection_mode as SiteProtectionMode | undefined
  if (
    mode === 'block' ||
    mode === 'monitor' ||
    mode === 'paused' ||
    mode === 'off' ||
    mode === 'pending'
  ) {
    return mode
  }
  if (site.status === 'paused') return 'paused'
  if (site.status === 'pending') return 'pending'
  return 'block'
}
