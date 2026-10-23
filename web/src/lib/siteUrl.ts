/**
 * The public URL a site is served on. The list payload carries no TLS flag,
 * so HTTPS is the default; development hosts that only speak HTTP (the local
 * e2e site is `*.varman.local`) fall back to HTTP. The site detail passes the
 * resolved SSL setting explicitly.
 */
export function liveSiteUrl(domain: string, https?: boolean): string {
  const development =
    /^(localhost|127(?:\.\d{1,3}){3}|\[::1\])$/i.test(domain) ||
    /\.(local|localhost|test|invalid)$/i.test(domain)
  const secure = https ?? !development
  return `${secure ? 'https' : 'http'}://${domain}`
}
