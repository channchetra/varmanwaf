import type { AccessLog } from '@/api/types'

/**
 * Headers curl manages itself or that belong to the captured connection
 * rather than the request; replaying them verbatim breaks the copy.
 */
const SKIPPED_HEADERS = new Set([
  'connection',
  'content-length',
  'host',
  'keep-alive',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/** Single-quotes a shell word, escaping embedded quotes. */
function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`
}

/**
 * Renders an access log entry as a runnable `curl` command. Cookies and
 * authorization headers are copied verbatim so the request can be replayed
 * during incident response.
 */
export function buildCurlCommand(log: AccessLog): string {
  const scheme = log.scheme ?? (log.tls_version ? 'https' : 'http')
  const host = log.host ?? 'localhost'
  const query = log.query_string ? `?${log.query_string}` : ''
  const url = `${scheme}://${host}${log.path ?? '/'}${query}`

  const lines = [`curl -X ${log.method} ${shellQuote(url)}`]
  for (const [name, value] of Object.entries(log.request_headers ?? {})) {
    if (SKIPPED_HEADERS.has(name.toLowerCase())) continue
    lines.push(`  -H ${shellQuote(`${name}: ${value}`)}`)
  }

  const body = log.request_body ?? ''
  const hasBody = body !== '' && log.method !== 'GET' && log.method !== 'HEAD'
  if (hasBody) {
    lines.push(`  --data-raw ${shellQuote(body)}`)
  }

  let command = lines.join(' \\\n')
  if (hasBody && log.request_body_truncated) {
    command +=
      '\n# Note: the captured request body was truncated — restore the missing bytes before running.'
  }
  return command
}
