/**
 * VarmanWAF website generator.
 *
 * Renders every document under docs/ into the public documentation site.
 * The docs shell is a dedicated surface: grouped sidebar, docs search, a
 * right-hand table of contents, numbered steps, callouts and screenshots.
 * The landing page, Khmer guide and release archive stay part of the same
 * build so the public site and the repository docs never drift.
 *
 * Usage: node build.mjs
 */
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { marked } from 'marked'

const here = path.dirname(fileURLToPath(import.meta.url))
const repo = path.resolve(here, '..')
const docsDir = path.join(repo, 'docs')
const dist = path.join(here, 'dist')
const src = path.join(here, 'src')
const GITHUB = 'https://github.com/channchetra/varmanwaf'

/* ------------------------------------------------------------------ */
/* Navigation                                                          */
/* ------------------------------------------------------------------ */

const NAV = [
  {
    id: 'start',
    title: 'Start here',
    items: [
      { slug: '', label: 'Documentation home', href: '/docs/' },
      { slug: 'quick-start', label: 'Quick start' },
      { slug: 'deployment-paths', label: 'Choose your deployment' },
    ],
  },
  {
    id: 'roles',
    title: 'By role',
    items: [
      { slug: 'roles/site-user', label: 'Site owners' },
      { slug: 'roles/administrator', label: 'Administrators' },
      { slug: 'roles/developer', label: 'Developers' },
      { slug: 'roles/system-administrator', label: 'System administrators' },
    ],
  },
  {
    id: 'console',
    title: 'Console guide',
    items: [
      { slug: 'user-guide', label: 'Console walkthrough' },
      { slug: 'features', label: 'Feature inventory' },
      { slug: 'usage', label: 'Using the console' },
      { slug: 'navigation-ia', label: 'Navigation & IA' },
      { slug: 'ui-language', label: 'Design language' },
    ],
  },
  {
    id: 'deploy',
    title: 'Deploy & operate',
    items: [
      { slug: 'deployment', label: 'Deployment guide' },
      { slug: 'ha', label: 'High availability' },
      { slug: 'sizing', label: 'Sizing & capacity' },
      { slug: 'http-lifecycle', label: 'Request lifecycle' },
      { slug: 'acme_chart', label: 'ACME certificate flow' },
      { slug: 'profiling', label: 'Profiling' },
    ],
  },
  {
    id: 'security',
    title: 'Security engine',
    items: [
      { slug: 'security-engine', label: 'Engine overview' },
      { slug: 'virtual-patches', label: 'Virtual patches' },
      { slug: 'compatibility', label: 'SecLang & CRS' },
      { slug: 'performance', label: 'Performance' },
      { slug: 'shadow-report', label: 'Shadow report' },
      { slug: 'benchmarks/v1.0.0', label: 'Benchmark 1.0.0' },
    ],
  },
  {
    id: 'developers',
    title: 'Developers',
    items: [
      { slug: 'developer-guide', label: 'Developer guide' },
      { slug: 'architecture', label: 'Architecture' },
      { slug: 'modules', label: 'Workspace modules' },
      { slug: 'api', label: 'REST API' },
    ],
  },
  {
    id: 'reference',
    title: 'Reference',
    items: [
      { slug: 'releases', label: 'Release notes', href: '/releases/' },
      { slug: 'references', label: 'References' },
      { slug: 'roadmap', label: 'Roadmap' },
      { slug: 'upstream-pingwaf-map', label: 'Upstream baseline' },
      { slug: 'upstream-update-plan', label: 'Upstream sync plan' },
      { slug: 'waf-engine-review', label: 'Early engine review' },
      { slug: 'waf-benchmark-report', label: 'Early benchmark' },
    ],
  },
  {
    id: 'khmer',
    title: 'ភាសាខ្មែរ',
    items: [{ slug: 'khmer', label: 'ណែនាំអ្នកប្រើប្រាស់', href: '/khmer/index.html' }],
  },
]

const NAV_ITEMS = []
for (const group of NAV) {
  for (const item of group.items) {
    if (item.slug === 'khmer' || item.slug === 'releases') continue
    NAV_ITEMS.push({ ...item, group: group.id, groupTitle: group.title })
  }
}

const LEADS = {
  'quick-start':
    'From a clean Linux host to one protected site: prerequisites, Docker or source, first login and a real request through the edge.',
  'deployment-paths':
    'All-in-one, split control plane and edge agents, or an HA fleet. Pick the shape that survives the failure you actually care about.',
  'roles/site-user':
    'The site owner’s path: sign in, read the dashboard, change the protection mode, fix the origin and explain a block.',
  'roles/administrator':
    'Users, policies, CRS, IP intelligence, alerts, reports and the audit trail for the whole instance.',
  'roles/developer':
    'Build, test and ship VarmanWAF itself — the repository map, the local gate, the API and the release contract.',
  'roles/system-administrator':
    'Hosts, PostgreSQL, edge fleets, certificates, HA, backups and upgrades. The control plane is never in the request path.',
  features:
    'The complete operator-facing feature set: every console surface, what it does, how it works and the honest limits.',
  'user-guide':
    'A practical walkthrough of the console: sites, origins, protection, access, caching, TLS, logs and the fleet.',
  ha: 'Run VarmanWAF so no single node stops traffic: edge fleets, a control-plane standby, PostgreSQL HA and the failure semantics you can rely on.',
  architecture:
    'The real system shape: control plane, edge agents, the request path, hard invariants and what happens when a dependency fails.',
  'security-engine':
    'The detection pipeline from normalization to signatures, expressions and anomaly scoring — and the limits of each layer.',
  developer:
    'Build, test, release and document the platform. The console bundle is embedded, so the order of builds matters.',
  api: 'Every REST endpoint, its permissions, request shapes and the status codes the control plane actually returns.',
  deployment:
    'Docker Compose, binary + systemd, environment variables, ports, TLS, backup and the upgrade procedure.',
  sizing:
    'How much server VarmanWAF needs, what consumes memory and CPU, and how to measure your own capacity instead of guessing.',
  'http-lifecycle':
    'Where every feature acts in the request pipeline: WAF checks, cache, rewrites, error pages and the order that matters.',
  compatibility:
    'What SecLang and CRS constructs are supported, what is deliberately different, and how to validate a ruleset before enforcing it.',
  'virtual-patches':
    'Fast, narrow rules for a new CVE: template, bind, observe, enforce and retire the patch when the upstream fix lands.',
  modules:
    'The workspace map: the Varman crates, the pingap proxy foundation and where each responsibility lives.',
  acme_chart:
    'The ACME certificate flow: order, HTTP-01/DNS-01 challenge, validation, renewal and the state the SSL page exposes.',
  usage:
    'Core operator flows with screenshots: create a site, configure the origin, enable the WAF and verify a request.',
  'ui-language':
    'The console’s box system: type, spacing, radii and state colour that keep dense operator screens honest.',
  'navigation-ia':
    'Why the console is grouped the way it is, where each surface lives, and the merges that removed duplicate pages.',
  references:
    'The upstream projects, standards and prior art that shaped VarmanWAF — and the boundary of what was reused.',
  roadmap:
    'Honest status tracking for the platform phases, shipped surfaces and the next work that is not pretending to exist.',
  'shadow-report':
    'Engine rollout evidence from running the legacy and Varman decisions side by side on the same traffic.',
  'benchmarks/v1.0.0':
    'The 1.0.0 benchmark: throughput, latency and the exact test setup behind the published numbers.',
  'waf-engine-review':
    'Historical record of the first engine review (2026-10-04), kept for provenance rather than current guidance.',
  'waf-benchmark-report':
    'Historical record of the first data-plane benchmark (2026-10-04); the 1.0.0 report is the current reference.',
  releases: 'Every VarmanWAF release with its image digest and verification evidence.',
}

/* ------------------------------------------------------------------ */
/* Markdown                                                             */
/* ------------------------------------------------------------------ */

marked.setOptions({ gfm: true, breaks: false })

function stripTags(html) {
  return html
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim()
}

function rewriteLinks(html, relative) {
  const baseDir = path.posix.dirname(relative)
  const resolve = (target) => path.posix.normalize(path.posix.join(baseDir, target))
  return html
    .replace(/href="([^"]+)"/g, (full, href) => {
      if (/^(https?:|mailto:|#|\/)/.test(href)) return full
      if (href.startsWith('./user-guide-km/')) return 'href="/khmer/index.html"'
      const [target, anchor = ''] = href.split('#')
      if (target.startsWith('images/')) return `href="/images/${target.slice(7)}${anchor ? `#${anchor}` : ''}"`
      if (target.endsWith('.md')) {
        const resolved = resolve(target)
        if (resolved.startsWith('..')) {
          return `href="${GITHUB}/blob/main/${resolved.replace(/^\.\.\//, '')}${anchor ? `#${anchor}` : ''}"`
        }
        if (resolved.startsWith('releases/')) {
          return `href="/releases/${path.basename(resolved, '.md')}.html${anchor ? `#${anchor}` : ''}"`
        }
        if (resolved.startsWith('benchmarks/')) {
          return `href="/docs/benchmarks-v1.0.0.html${anchor ? `#${anchor}` : ''}"`
        }
        return `href="/docs/${slugFor(resolved)}.html${anchor ? `#${anchor}` : ''}"`
      }
      if (target.startsWith('../')) {
        return `href="${GITHUB}/blob/main/${target.replace(/^\.\.\//, '')}"`
      }
      if (target.startsWith('./')) return `href="/docs/${slugFor(resolve(target))}.html"`
      return full
    })
    .replace(/src="([^"]+)"/g, (full, source) => {
      if (/^(https?:|data:|\/)/.test(source)) return full
      if (source.startsWith('./images/')) return `src="/images/${source.slice(9)}"`
      if (source.startsWith('images/')) return `src="/images/${source.slice(7)}"`
      return full
    })
}

function slugify(text) {
  // GitHub-compatible heading anchors: keep letters, numbers, spaces and
  // hyphens; remove punctuation; spaces become hyphens without collapsing.
  return (
    text
      .toLowerCase()
      .trim()
      .replace(/[^\p{L}\p{N}\s-]/gu, '')
      .replace(/\s/g, '-')
      .replace(/^-+|-+$/g, '') || 'section'
  )
}

function withHeadingIds(html) {
  const toc = []
  const seen = new Map()
  const out = html.replace(/<h([1-4])>(.*?)<\/h\1>/gs, (_full, level, inner) => {
    const text = stripTags(inner)
    let id = slugify(text)
    const count = seen.get(id) ?? 0
    seen.set(id, count + 1)
    if (count > 0) id = `${id}-${count}`
    if (Number(level) >= 2 && Number(level) <= 3) toc.push({ level: Number(level), text, id })
    return `<h${level} id="${id}">${inner}</h${level}>`
  })
  return { html: out, toc }
}

function transformCallouts(html) {
  return html.replace(/<blockquote>([\s\S]*?)<\/blockquote>/g, (full, inner) => {
    const lead = stripTags(inner).toLowerCase()
    let tone = 'note'
    if (/warning|caution|danger|never|do not/.test(lead.slice(0, 80))) tone = 'warning'
    else if (/tip|shortcut|prefer|recommended/.test(lead.slice(0, 80))) tone = 'tip'
    return `<blockquote class="callout callout-${tone}">${inner}</blockquote>`
  })
}

function transformFigures(html) {
  return html.replace(/<p>\s*<img([^>]*?)>\s*<\/p>/g, (full, attrs) => {
    const srcMatch = attrs.match(/src="([^"]+)"/)
    const altMatch = attrs.match(/alt="([^"]*)"/)
    if (!srcMatch) return full
    const source = srcMatch[1]
    const caption = (altMatch?.[1] || '').trim()
    const clean = attrs.replace(/\s*(src|alt)="[^"]*"/g, '').trim()
    return `<figure class="doc-figure">
  <a href="${source}" target="_blank" rel="noreferrer"><img ${clean} src="${source}" alt="${caption}" loading="lazy" decoding="async"></a>
  <figcaption>${caption ? `<span>${caption}</span>` : '<span></span>'}<span class="fig-hint">Open full size ↗</span></figcaption>
</figure>`
  })
}

function transformSteps(html) {
  return html.replace(
    /<h([23])([^>]*)>Step\s+(\d+)\s*[—–:-]\s*([\s\S]*?)<\/h\1>/g,
    (_full, level, attrs, number, rest) =>
      `<h${level}${attrs} class="doc-step" data-step="${number}">${rest}</h${level}>`,
  )
}

function transformTables(html) {
  return html.replace(/<table>([\s\S]*?)<\/table>/g, '<div class="table-wrap"><table>$1</table></div>')
}


function extractLead(html, relative, keepFirst = false) {
  const firstHeading = html.search(/<h2[\s>]/)
  const prefix = firstHeading >= 0 ? html.slice(0, firstHeading) : html
  const blockquoteStart = prefix.indexOf('<blockquote')
  const blockquoteEnd = prefix.indexOf('</blockquote>')
  let match = null
  for (const candidate of prefix.matchAll(/<p>([\s\S]*?)<\/p>/g)) {
    const start = candidate.index ?? 0
    const inQuote = blockquoteStart >= 0 && start > blockquoteStart && (blockquoteEnd < 0 || start < blockquoteEnd)
    if (!inQuote) {
      match = candidate
      break
    }
  }
  const key = relative.replace(/\.md$/, '')
  const override = LEADS[key] || LEADS[slugFor(relative)]
  if (!match) {
    return { lead: override || '', html }
  }
  const paragraph = match[0]
  const paragraphText = stripTags(match[1])
  const lead = override || paragraphText
  const short = (value) => value.toLowerCase().replace(/\s+/g, ' ').slice(0, 48)
  const duplicate =
    !override ||
    short(paragraphText) === short(lead) ||
    short(paragraphText).startsWith(short(lead)) ||
    short(lead).startsWith(short(paragraphText))
  if (duplicate && !keepFirst && match.index !== undefined) {
    html = html.slice(0, match.index) + html.slice(match.index + paragraph.length)
  }
  return { lead: lead.length > 230 ? `${lead.slice(0, 227).replace(/\s+\S*$/, '')}…` : lead, html }
}

function renderDocWithToc(relative, options = {}) {
  const raw = fs.readFileSync(path.join(docsDir, relative), 'utf8')
  const prepared = raw.replace(
    /```mermaid\r?\n([\s\S]*?)```/g,
    (_m, body) => `\n<div class="mermaid">\n${body.trim()}\n</div>\n`,
  )
  let html = marked.parse(prepared)
  html = rewriteLinks(html, relative)
  const titleMatch = html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/)
  const title = titleMatch ? stripTags(titleMatch[1]) : path.basename(relative, '.md')
  if (titleMatch) html = html.replace(titleMatch[0], '')
  const withIds = withHeadingIds(html)
  html = withIds.html
  html = transformCallouts(html)
  html = transformFigures(html)
  html = transformSteps(html)
  html = transformTables(html)
  const extracted = extractLead(html, relative, Boolean(options.keepFirst))
  html = extracted.html
  const text = stripTags(html)
  const words = text.split(/\s+/).filter(Boolean).length
  return {
    title,
    lead: extracted.lead,
    html,
    toc: withIds.toc,
    text,
    words,
  }
}

function slugFor(relative) {
  return relative
    .replace(/\.md$/i, '')
    .replace(/[\\/]/g, '-')
    .toLowerCase()
}

/* ------------------------------------------------------------------ */
/* Release metadata                                                     */
/* ------------------------------------------------------------------ */

const releaseFiles = fs
  .readdirSync(path.join(docsDir, 'releases'))
  .filter((name) => /^v\d+\.\d+\.\d+\.md$/.test(name))
  .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))

const LATEST_RELEASE = releaseFiles[0]?.replace(/\.md$/, '') ?? 'dev'
const LATEST_DATE = (() => {
  const raw = fs.readFileSync(path.join(docsDir, 'releases', releaseFiles[0]), 'utf8')
  return raw.match(/\*\*Release date:\*\*\s*([^\n]+)/)?.[1]?.trim() ?? ''
})()

/* ------------------------------------------------------------------ */
/* Shell                                                               */
/* ------------------------------------------------------------------ */

const ICONS = {
  search:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>',
  chevron:
    '<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>',
  arrow:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
  arrowLeft:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 12H5M11 18l-6-6 6-6"/></svg>',
  external:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 7h10v10"/><path d="M7 17 17 7"/></svg>',
  sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>',
  menu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg>',
  collapse:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/></svg>',
  github:
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.55.1.76-.24.76-.54v-2.08c-3.09.67-3.74-1.31-3.74-1.31-.5-1.29-1.23-1.63-1.23-1.63-1.01-.7.08-.68.08-.68 1.11.08 1.69 1.14 1.69 1.14.99 1.7 2.6 1.21 3.23.93.1-.72.39-1.21.71-1.49-2.47-.28-5.07-1.24-5.07-5.49 0-1.21.43-2.2 1.14-2.98-.11-.28-.5-1.41.11-2.94 0 0 .93-.3 3.05 1.14a10.6 10.6 0 0 1 5.55 0c2.12-1.44 3.05-1.14 3.05-1.14.61 1.53.22 2.66.11 2.94.71.78 1.14 1.77 1.14 2.98 0 4.26-2.6 5.21-5.08 5.48.4.35.75 1.02.75 2.06v3.07c0 .3.2.65.76.54A11.1 11.1 0 0 0 12 .9Z"/></svg>',
  list: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>',
  user: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>',
  shield:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 21 6v6c0 5-3.8 8.7-9 10-5.2-1.3-9-5-9-10V6Z"/><path d="m8.5 12 2.4 2.4 4.6-5"/></svg>',
  wrench:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L4 17v3h3l5.3-5.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.1-2.1Z"/></svg>',
  server:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg>',
  code: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m8 8-4 4 4 4M16 8l4 4-4 4M14 4l-4 16"/></svg>',
  layers:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5"/><path d="m3 18 9 5 9-5"/></svg>',
  book: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v16H6.5A2.5 2.5 0 0 0 4 21.5Z"/><path d="M4 5.5v16"/></svg>',
  terminal:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 7 5 5-5 5M13 17h6"/></svg>',
  cloud:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 18a4 4 0 0 1-.4-8A6 6 0 0 1 18 9.5a4 4 0 0 1 .5 8Z"/></svg>',
}

function itemHref(item) {
  return item.href || `/docs/${slugFor(item.slug)}.html`
}

function activeGroupFor(activeSlug) {
  if (activeSlug.startsWith('releases')) return 'reference'
  return NAV.find((group) => group.items.some((item) => item.slug === activeSlug))?.id ?? ''
}

function docsSidebar(activeSlug) {
  const activeGroup = activeGroupFor(activeSlug)
  const groups = NAV.map((group) => {
    const links = group.items
      .map((item) => {
        const href = itemHref(item)
        const active =
          item.slug === activeSlug || (item.slug === 'releases' && activeSlug.startsWith('releases'))
        return `<li><a class="docs-nav-link${active ? ' is-active' : ''}" href="${href}"${
          active ? ' aria-current="page"' : ''
        }>${item.label}</a></li>`
      })
      .join('')
    return `<details class="docs-nav-group" data-nav-group="${group.id}"${
      group.id === activeGroup || group.id === 'start' ? ' open' : ''
    }>
  <summary><span>${group.title}</span>${ICONS.chevron}</summary>
  <ul>${links}</ul>
</details>`
  }).join('\n')
  return `<aside class="docs-sidebar" id="docs-sidebar">
  <div class="docs-sidebar-inner">
    <div class="docs-sidebar-head">
      <span class="docs-sidebar-label">VarmanWAF documentation</span>
      <span class="docs-version">${LATEST_RELEASE}</span>
    </div>
    <nav class="docs-nav" aria-label="Documentation">${groups}</nav>
    <div class="docs-sidebar-foot">
      <span>Apache-2.0</span>
      <a href="${GITHUB}" target="_blank" rel="noreferrer">GitHub ${ICONS.external}</a>
    </div>
  </div>
</aside>`
}

function docsTopbar() {
  return `<header class="docs-topbar">
  <div class="docs-topbar-inner">
    <button type="button" class="docs-icon-button docs-menu-toggle" data-docs-menu aria-label="Open documentation navigation" aria-expanded="false" aria-controls="docs-sidebar">${ICONS.menu}</button>
    <a class="docs-brand" href="/docs/" aria-label="VarmanWAF documentation home">
      <span class="docs-brand-mark" aria-hidden="true">${ICONS.shield}</span>
      <span class="docs-brand-word">VarmanWAF</span>
      <span class="docs-brand-pill">Docs</span>
    </a>
    <button type="button" class="docs-search-trigger" data-docs-search aria-label="Search documentation">
      ${ICONS.search}<span>Search documentation</span><kbd>Ctrl K</kbd>
    </button>
    <nav class="docs-topnav" aria-label="Site">
      <a href="/">Website</a>
      <a href="/releases/">Releases</a>
      <a class="docs-github" href="${GITHUB}" target="_blank" rel="noreferrer" aria-label="VarmanWAF on GitHub">${ICONS.github}</a>
      <button type="button" class="docs-icon-button docs-theme" data-docs-theme aria-label="Switch to light theme">${ICONS.sun}${ICONS.moon}</button>
      <button type="button" class="docs-icon-button docs-collapse" data-docs-collapse aria-label="Collapse documentation sidebar" aria-pressed="false">${ICONS.collapse}</button>
    </nav>
  </div>
</header>`
}

function searchDialog() {
  return `<dialog class="docs-search-dialog" id="docs-search">
  <div class="docs-search-box">
    <div class="docs-search-field">
      ${ICONS.search}
      <input type="search" placeholder="Search the documentation…" aria-label="Search the documentation" autocomplete="off" spellcheck="false">
      <kbd>Esc</kbd>
    </div>
    <div class="docs-search-results" data-search-results>
      <p class="docs-search-hint">Type to search guides, console surfaces, deployment paths and releases.</p>
    </div>
    <div class="docs-search-foot"><span data-search-count>—</span><span>Use ↑ ↓ to move · Enter to open</span></div>
  </div>
</dialog>`
}

function docsShell({
  title,
  description,
  group,
  body,
  toc = [],
  slug = '',
  file = '',
  wide = false,
  isHome = false,
}) {
  const tocHtml =
    !wide && toc.length > 0
      ? `<aside class="docs-toc" aria-label="On this page">
  <div class="docs-toc-inner">
    <p class="docs-toc-title">${ICONS.list}<span>On this page</span></p>
    <ul>${toc
      .map(
        (entry) =>
          `<li class="lvl-${entry.level}"><a href="#${entry.id}">${entry.text}</a></li>`,
      )
      .join('')}</ul>
    <a class="docs-back-top" href="#main">Back to top</a>
  </div>
</aside>`
      : ''
  const edit = file
    ? `<a class="docs-edit" href="${GITHUB}/blob/main/docs/${file}" target="_blank" rel="noreferrer">Edit this page ${ICONS.external}</a>`
    : ''
  const index = NAV_ITEMS.findIndex((item) => item.slug === slug)
  const prev = index > 0 ? NAV_ITEMS[index - 1] : null
  const next = index >= 0 && index < NAV_ITEMS.length - 1 ? NAV_ITEMS[index + 1] : null
  const pager =
    !isHome && (prev || next)
      ? `<nav class="docs-pager" aria-label="Documentation pages">
  ${prev ? `<a class="docs-pager-link" href="${itemHref(prev)}"><span>Previous</span><strong>${prev.label}</strong></a>` : '<span></span>'}
  ${next ? `<a class="docs-pager-link docs-pager-next" href="${itemHref(next)}"><span>Next</span><strong>${next.label}</strong></a>` : '<span></span>'}
</nav>`
      : ''
  return `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · VarmanWAF Docs</title>
<meta name="description" content="${description}">
<meta name="theme-color" content="#0b1220" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f7f9fc" media="(prefers-color-scheme: light)">
<script>
  try {
    var pref = localStorage.getItem('varman-theme') || 'system';
    var dark = pref === 'dark' || (pref === 'system' && !window.matchMedia('(prefers-color-scheme: light)').matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    document.documentElement.dataset.themePreference = pref;
    if (localStorage.getItem('varman-docs-nav') === 'collapsed') document.documentElement.dataset.docsSidebar = 'collapsed';
  } catch (e) {}
</script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/docs.css?v=20261025">
</head>
<body class="docs-page">
<a class="skip-link" href="#main">Skip to content</a>
${docsTopbar()}
<div class="docs-shell"${isHome ? ' data-docs-home' : ''}>
  ${docsSidebar(slug)}
  <div class="docs-main" id="main" tabindex="-1">
    <div class="docs-article-wrap${wide ? ' is-wide' : ''}">
      <article class="docs-article">
        ${isHome ? '' : `<nav class="docs-breadcrumb" aria-label="Breadcrumb"><a href="/docs/">Docs</a><span>/</span>${group ? `<span>${group}</span><span>/</span>` : ''}<span aria-current="page">${title}</span></nav>`}
        ${body}
        ${isHome ? '' : `<div class="docs-article-foot">${edit}<span>${LATEST_RELEASE} · VarmanWAF documentation</span></div>`}
        ${pager}
      </article>
      ${tocHtml}
    </div>
    ${docsFooter()}
  </div>
</div>
<div class="docs-mobile-scrim" data-docs-scrim hidden></div>
${searchDialog()}
<script src="/assets/docs.js?v=20261025" defer></script>
</body>
</html>`
}

function docsFooter() {
  return `<footer class="docs-footer">
  <span>© 2026 VarmanWAF · Apache-2.0</span>
  <span class="docs-footer-links">
    <a href="/">Website</a>
    <a href="/releases/">Releases</a>
    <a href="${GITHUB}" target="_blank" rel="noreferrer">GitHub</a>
    <a href="/khmer/index.html">ភាសាខ្មែរ</a>
  </span>
</footer>`
}

/* ------------------------------------------------------------------ */
/* Article frame                                                       */
/* ------------------------------------------------------------------ */

function docArticle({ title, lead, html, group, words, role }) {
  return `<header class="docs-article-head">
  ${group ? `<p class="docs-eyebrow"><span></span>${group}</p>` : ''}
  <h1>${title}</h1>
  ${lead ? `<p class="docs-lead">${lead}</p>` : ''}
  <p class="docs-meta">${Math.max(2, Math.round(words / 220))} min read${role ? ` · ${role}` : ''}</p>
</header>
<div class="docs-body">${html}</div>`
}

function docsHome() {
  const roleCards = [
    {
      href: '/docs/roles-site-user.html',
      icon: 'user',
      title: 'Site owners',
      body: 'Run one site with confidence: protection mode, origin, cache, TLS and a request you can explain.',
      meta: 'Start with the site',
    },
    {
      href: '/docs/roles-administrator.html',
      icon: 'shield',
      title: 'Administrators',
      body: 'Users, policies, CRS, IP intelligence, alerts and the audit trail for the whole instance.',
      meta: 'Own the guardrails',
    },
    {
      href: '/docs/roles-developer.html',
      icon: 'code',
      title: 'Developers',
      body: 'Build the Rust engine and the React console, run the local gate and ship the bundle with the binary.',
      meta: 'Change the platform',
    },
    {
      href: '/docs/roles-system-administrator.html',
      icon: 'server',
      title: 'System administrators',
      body: 'Hosts, PostgreSQL, edge fleets, certificates, HA, backup and upgrades — without putting the control plane in the path.',
      meta: 'Run the fleet',
    },
  ]
  const deployCards = [
    {
      href: '/docs/deployment-paths.html#path-a--all-in-one',
      badge: 'Fastest',
      title: 'All-in-one',
      body: 'One process, one host. The smallest way to evaluate VarmanWAF or protect a single internal app.',
      detail: 'Control plane + edge + PostgreSQL',
    },
    {
      href: '/docs/deployment-paths.html#path-b--control-plane--edge-agents',
      badge: 'Standard',
      title: 'Control plane + edges',
      body: 'The production shape. Edge nodes keep serving from their last-good bundle when the control plane is away.',
      detail: '1 control plane · N edge nodes',
    },
    {
      href: '/docs/deployment-paths.html#path-c--ha-edge-fleet',
      badge: 'HA',
      title: 'Edge fleet + standby',
      body: 'Two failure domains: multiple edges behind DNS/LB and a control-plane standby over replicated PostgreSQL.',
      detail: '2+ edges · standby · DB HA',
    },
  ]
  const shots = [
    ['/docs/features.html#31-protection--the-single-security-surface', 'protection.webp', 'Protection', 'One mode, rules and decisions'],
    ['/docs/features.html#24-routing-topology-the-flow-views', 'topology-docked.webp', 'Topology', 'The real request path, editable'],
    ['/docs/features.html#312-logs', 'decision-chain.webp', 'Decision chain', 'Why a request was blocked'],
    ['/docs/features.html#13-fleet--agents', 'agents.webp', 'Agents', 'Heartbeat, version, scope'],
    ['/docs/features.html#41-policies', 'policies.webp', 'Policies', 'Reusable guardrails, versioned'],
    ['/docs/features.html#38-caching', 'caching.webp', 'Caching', 'Rules, hit ratio, purge'],
  ]
  const groups = NAV.filter((group) => !['khmer'].includes(group.id))
    .map(
      (group) => `<div class="docs-home-group">
  <h3>${group.title}</h3>
  <ul>${group.items
    .map((item) => `<li><a href="${itemHref(item)}">${item.label} ${ICONS.arrow}</a></li>`)
    .join('')}</ul>
</div>`,
    )
    .join('')
  const body = `<div class="docs-home">
  <section class="docs-hero">
    <div class="docs-hero-copy">
      <p class="docs-eyebrow"><span></span>VarmanWAF documentation</p>
      <h1>Run a WAF you can explain.</h1>
      <p class="docs-hero-lead">A distributed, self-hosted Web Application Firewall. Learn the request path, choose the deployment shape, and give every role the surface it actually needs.</p>
      <div class="docs-hero-actions">
        <button type="button" class="docs-hero-search" data-docs-search>${ICONS.search}<span>Search the documentation</span><kbd>Ctrl K</kbd></button>
        <a class="docs-hero-link" href="/docs/quick-start.html">Quick start ${ICONS.arrow}</a>
      </div>
      <p class="docs-hero-meta">${LATEST_RELEASE} · ${NAV_ITEMS.length - 1} guides · Apache-2.0 · No telemetry</p>
    </div>
    <div class="docs-hero-visual" aria-hidden="true">
      <div class="docs-path-card">
        <div class="docs-path-head"><span class="status-dot"></span><span>Live request path</span><em>200</em></div>
        <div class="docs-path-node"><span class="node-icon">${ICONS.cloud}</span><div><strong>Client</strong><small>HTTP / HTTPS</small></div></div>
        <div class="docs-path-link"><span></span><em>TLS</em></div>
        <div class="docs-path-node is-accent"><span class="node-icon">${ICONS.shield}</span><div><strong>Web Protection</strong><small>rules · score · action</small></div></div>
        <div class="docs-path-link"><span></span></div>
        <div class="docs-path-node"><span class="node-icon">${ICONS.layers}</span><div><strong>Security layers</strong><small>10 checks</small></div></div>
        <div class="docs-path-link"><span></span></div>
        <div class="docs-path-node"><span class="node-icon">${ICONS.server}</span><div><strong>Origin pool</strong><small>2 healthy targets</small></div></div>
      </div>
    </div>
  </section>
  <section class="docs-home-section">
    <div class="docs-section-head"><h2>Start with your role</h2><p>Four paths through the same product. Pick the one that matches your job.</p></div>
    <div class="docs-role-grid">${roleCards
      .map(
        (card) => `<a class="docs-role-card" href="${card.href}">
  <span class="docs-role-icon">${ICONS[card.icon]}</span>
  <span class="docs-role-copy"><strong>${card.title}</strong><span>${card.body}</span><em>${card.meta} ${ICONS.arrow}</em></span>
</a>`,
      )
      .join('')}</div>
  </section>
  <section class="docs-home-section">
    <div class="docs-section-head"><h2>Choose a deployment</h2><p>Start with the failure you need to survive. The control plane is never in the request path.</p></div>
    <div class="docs-deploy-grid">${deployCards
      .map(
        (card) => `<a class="docs-deploy-card" href="${card.href}">
  <span class="docs-deploy-badge">${card.badge}</span>
  <strong>${card.title}</strong>
  <span>${card.body}</span>
  <em>${card.detail} ${ICONS.arrow}</em>
</a>`,
      )
      .join('')}</div>
  </section>
  <section class="docs-home-section">
    <div class="docs-section-head"><h2>See the console before you install</h2><p>Real screens from the current release. Screenshots are the UI, not mockups.</p></div>
    <div class="docs-shot-grid">${shots
      .map(
        ([href, img, title, cap]) => `<a class="docs-shot-card" href="${href}">
  <span class="docs-shot-image"><img src="/images/console/${img}" alt="${title}" loading="lazy" decoding="async"></span>
  <span class="docs-shot-copy"><strong>${title}</strong><span>${cap}</span></span>
</a>`,
      )
      .join('')}</div>
  </section>
  <section class="docs-home-section">
    <div class="docs-section-head"><h2>Every document, in one place</h2><p>The repository markdown is the source of truth. This index is generated from it.</p></div>
    <div class="docs-home-groups">${groups}</div>
    <p class="docs-home-khmer">Also available in <a href="/khmer/index.html">ភាសាខ្មែរ — the full Khmer user guide</a>.</p>
  </section>
</div>`
  return docsShell({
    title: 'Documentation',
    description:
      'VarmanWAF documentation: quick start, role guides, the console, deployment and HA, the security engine and the REST API.',
    body,
    wide: true,
    isHome: true,
    slug: '',
  })
}

/* ------------------------------------------------------------------ */
/* Release pages                                                       */
/* ------------------------------------------------------------------ */

function releaseMeta(name) {
  const raw = fs.readFileSync(path.join(docsDir, 'releases', name), 'utf8')
  return {
    version: name.replace(/\.md$/, ''),
    date: raw.match(/\*\*Release date:\*\*\s*([^\n]+)/)?.[1]?.trim() ?? '',
    title: raw.match(/^#\s+(.+)$/m)?.[1]?.trim() ?? name,
    summary:
      raw
        .split('\n')
        .find((line) => line && !line.startsWith('#') && !line.startsWith('**') && !line.startsWith('>')) ??
      '',
  }
}

function releasePage(name) {
  const relative = `releases/${name}`
  const doc = renderDocWithToc(relative, { keepFirst: true })
  const meta = releaseMeta(name)
  return docsShell({
    title: meta.version,
    description: `${meta.version} release notes — ${meta.title}`,
    group: 'Reference',
    body: docArticle({
      title: meta.version,
      lead: meta.title,
      html: doc.html,
      group: 'Release notes',
      words: doc.words,
    }),
    toc: doc.toc,
    slug: `releases/${meta.version}`,
    file: relative,
  })
}

function releasesIndex() {
  const cards = releaseFiles
    .map((name) => releaseMeta(name))
    .map(
      (meta) => `<a class="release-card" href="/releases/${meta.version}.html">
  <span class="release-version">${meta.version}</span>
  <strong>${meta.title.replace(/^VarmanWAF\s+/, '')}</strong>
  <span class="release-date">${meta.date}</span>
  <span class="release-more">Read the release ${ICONS.arrow}</span>
</a>`,
    )
    .join('')
  const body = `<div class="docs-home">
  <section class="docs-hero docs-hero-compact">
    <div class="docs-hero-copy">
      <p class="docs-eyebrow"><span></span>Release archive</p>
      <h1>Every release, with its evidence.</h1>
      <p class="docs-hero-lead">Each round ships whole: build, tests, the E2E sweep on a live deployment, and a published image with its digest recorded here.</p>
      <p class="docs-hero-meta">${releaseFiles.length} releases · newest ${LATEST_RELEASE}${LATEST_DATE ? ` · ${LATEST_DATE}` : ''}</p>
    </div>
  </section>
  <section class="docs-home-section">
    <div class="release-grid">${cards}</div>
  </section>
</div>`
  return docsShell({
    title: 'Release notes',
    description: 'Every VarmanWAF release with its image digest and verification evidence.',
    body,
    wide: true,
    isHome: true,
    slug: 'releases',
  })
}

/* ------------------------------------------------------------------ */
/* Landing page helpers (unchanged visual world)                       */
/* ------------------------------------------------------------------ */

function navbar(active = '') {
  const link = (href, label, id) =>
    `<a href="${href}"${active === id ? ' aria-current="page"' : ''}>${label}</a>`
  return `<header class="site-header" id="site-header">
  <div class="container nav-wrap">
    <a class="wordmark" href="/" aria-label="VarmanWAF home">
      <span class="brand-mark" aria-hidden="true"><svg width="14" height="16" viewBox="0 0 24 28" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 2 22 6v8c0 6-4.4 10.4-10 12-5.6-1.6-10-6-10-12V6Z"/><path d="m8 14 3 3 5-6"/></svg></span>
      <span class="brand-wordmark">VarmanWAF</span>
    </a>
    <nav class="desktop-nav" aria-label="Main navigation">
      ${link('/#features', 'Features')}
      ${link('/#how-it-works', 'How it works')}
      ${link('/#deploy', 'Deploy')}
      ${link('/docs/', 'Docs', 'docs')}
    </nav>
    <div class="nav-actions">
      <div class="theme-control">
        <button type="button" class="theme-trigger" id="theme-trigger" aria-expanded="false" aria-controls="appearance-panel" aria-label="Color theme: System">
          <svg class="theme-icon icon-theme-system" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
          <svg class="theme-icon icon-theme-light" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
          <svg class="theme-icon icon-theme-dark" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>
          <span id="theme-label">System</span>
          <svg class="theme-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
        </button>
        <div class="theme-panel" id="appearance-panel" role="dialog" aria-labelledby="appearance-title" aria-describedby="appearance-description" hidden>
          <h2 id="appearance-title">Appearance</h2>
          <p id="appearance-description">Your space, your style.</p>
          <div class="theme-options" role="radiogroup" aria-label="Color theme">
            <button type="button" role="radio" class="theme-option" data-theme-option="light" aria-checked="false" tabindex="-1"><span class="theme-preview theme-preview-light" aria-hidden="true"><span class="theme-preview-window"><i></i><i></i><i></i></span><span class="theme-preview-icon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2"/></svg></span></span><span>Light</span><span class="theme-selected" aria-hidden="true"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span></button>
            <button type="button" role="radio" class="theme-option" data-theme-option="dark" aria-checked="false" tabindex="-1"><span class="theme-preview theme-preview-dark" aria-hidden="true"><span class="theme-preview-window"><i></i><i></i><i></i></span><span class="theme-preview-icon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg></span></span><span>Dark</span><span class="theme-selected" aria-hidden="true"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span></button>
            <button type="button" role="radio" class="theme-option" data-theme-option="system" aria-checked="true" tabindex="0"><span class="theme-preview theme-preview-system" aria-hidden="true"><span class="theme-preview-window"><i></i><i></i><i></i></span><span class="theme-preview-icon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg></span></span><span>System</span><span class="theme-selected" aria-hidden="true"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span></button>
          </div>
          <div class="theme-hint"><span class="status-dot" aria-hidden="true"></span><span>System matches your device's appearance.</span></div>
        </div>
      </div>
      <span class="animation-control">
        <button type="button" class="animation-toggle" id="animation-toggle" aria-label="Disable mouse effects" aria-pressed="true">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="2" width="14" height="20" rx="7"/><path d="M12 6v4"/></svg>
        </button>
        <span class="animation-tooltip" id="animation-tooltip">Disable mouse effects</span>
      </span>
      <a class="github-nav" href="${GITHUB}" target="_blank" rel="noreferrer" aria-label="VarmanWAF on GitHub">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.55.1.76-.24.76-.54v-2.08c-3.09.67-3.74-1.31-3.74-1.31-.5-1.29-1.23-1.63-1.23-1.63-1.01-.7.08-.68.08-.68 1.11.08 1.69 1.14 1.69 1.14.99 1.7 2.6 1.21 3.23.93.1-.72.39-1.21.71-1.49-2.47-.28-5.07-1.24-5.07-5.49 0-1.21.43-2.2 1.14-2.98-.11-.28-.5-1.41.11-2.94 0 0 .93-.3 3.05 1.14a10.6 10.6 0 0 1 5.55 0c2.12-1.44 3.05-1.14 3.05-1.14.61 1.53.22 2.66.11 2.94.71.78 1.14 1.77 1.14 2.98 0 4.26-2.6 5.21-5.08 5.48.4.35.75 1.02.75 2.06v3.07c0 .3.2.65.76.54A11.1 11.1 0 0 0 12 .9Z"/></svg>
        <span>GitHub</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 7h10v10"/><path d="M7 17 17 7"/></svg>
      </a>
      <button type="button" class="icon-button menu-toggle" id="menu-toggle" aria-label="Open navigation" aria-expanded="false" aria-controls="mobile-nav">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
      </button>
    </div>
  </div>
  <nav class="mobile-nav" id="mobile-nav" aria-label="Mobile navigation" hidden>
    <a href="/#features">Features</a>
    <a href="/#how-it-works">How it works</a>
    <a href="/#deploy">Deploy</a>
    <a href="/docs/">Docs</a>
  </nav>
</header>`
}

function footer() {
  return `<footer class="site-footer container">
  <div class="footer-main">
    <div>
      <a class="wordmark" href="/" aria-label="VarmanWAF home"><span class="brand-mark" aria-hidden="true"><svg width="14" height="16" viewBox="0 0 24 28" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 2 22 6v8c0 6-4.4 10.4-10 12-5.6-1.6-10-6-10-12V6Z"/><path d="m8 14 3 3 5-6"/></svg></span><span class="brand-wordmark">VarmanWAF</span></a>
      <p>A distributed WAF you run yourself.</p>
    </div>
    <div class="footer-links">
      <a href="/docs/">Documentation</a>
      <a href="/releases/">Releases</a>
      <a href="/docs/features.html">Features</a>
      <a href="/khmer/index.html">ខ្មែរ</a>
      <a href="${GITHUB}" target="_blank" rel="noreferrer">GitHub</a>
    </div>
  </div>
  <div class="footer-bottom">
    <span>© 2026 VarmanWAF. Apache-2.0.</span>
    <span><svg class="tiny-shield" width="11" height="12" viewBox="0 0 24 28" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" aria-hidden="true"><path d="M12 2 22 6v8c0 6-4.4 10.4-10 12-5.6-1.6-10-6-10-12V6Z"/></svg> Built in the open.</span>
  </div>
  <a class="studio-signature" href="${GITHUB}" target="_blank" rel="noreferrer">
    <svg class="oxog-mark" viewBox="0 0 105 60" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 8v44l18-26Z"></path><path d="M98 8v44L80 26Z"></path><path d="M35 30h35"></path><path d="M52 16v28"></path></svg>
    <div class="studio-copy">
      <span class="studio-eyebrow">OPEN SOURCE, BUILT IN THE OPEN</span>
      <h2>Small team.<br><span>Sharp tools.</span></h2>
      <p>VarmanWAF ships with every release verified end to end.</p>
    </div>
    <span class="studio-link">Star on GitHub <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 7h10v10"/><path d="M7 17 17 7"/></svg></span>
  </a>
</footer>`
}

function landingPage() {
  const body = fs.readFileSync(path.join(src, 'index.html'), 'utf8')
  return body
    .replace('<!-- NAV -->', navbar(''))
    .replace('<!-- FOOTER -->', footer())
}

/* ------------------------------------------------------------------ */
/* Build                                                               */
/* ------------------------------------------------------------------ */

function rmrf(target) {
  fs.rmSync(target, { recursive: true, force: true })
}

function copyDir(from, to, filter = () => true) {
  fs.mkdirSync(to, { recursive: true })
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const source = path.join(from, entry.name)
    const target = path.join(to, entry.name)
    if (!filter(source, entry)) continue
    if (entry.isDirectory()) copyDir(source, target, filter)
    else fs.copyFileSync(source, target)
  }
}

const SEARCH = []

function addSearch(entry) {
  SEARCH.push(entry)
}

function main() {
  rmrf(dist)
  fs.mkdirSync(dist, { recursive: true })

  // Landing + shared assets
  fs.writeFileSync(path.join(dist, 'index.html'), landingPage())
  fs.copyFileSync(path.join(src, 'favicon.svg'), path.join(dist, 'favicon.svg'))
  copyDir(path.join(src, 'assets'), path.join(dist, 'assets'))
  if (fs.existsSync(path.join(here, 'node_modules', 'mermaid', 'dist', 'mermaid.min.js'))) {
    fs.copyFileSync(
      path.join(here, 'node_modules', 'mermaid', 'dist', 'mermaid.min.js'),
      path.join(dist, 'assets', 'mermaid.min.js'),
    )
  }
  copyDir(path.join(docsDir, 'images'), path.join(dist, 'images'))

  // Docs
  const docsOut = path.join(dist, 'docs')
  fs.mkdirSync(docsOut, { recursive: true })

  for (const group of NAV) {
    for (const item of group.items) {
      if (!item.slug || item.slug === 'releases' || item.href) continue
      const relative = `${item.slug}.md`
      const candidate = path.join(docsDir, relative)
      if (!fs.existsSync(candidate)) {
        console.warn(`  ! missing doc: ${relative}`)
        continue
      }
      const doc = renderDocWithToc(relative)
      const slug = slugFor(item.slug)
      const role =
        item.slug.startsWith('roles/') ? 'Role guide'
          : group.id === 'console' ? 'Console guide'
            : group.id === 'deploy' ? 'Deploy & operate'
              : group.id === 'developers' ? 'Developer reference'
                : group.id === 'security' ? 'Security engine'
                  : group.id === 'reference' ? 'Reference'
                    : 'Getting started'
      fs.writeFileSync(
        path.join(docsOut, `${slug}.html`),
        docsShell({
          title: doc.title,
          description: doc.lead || `${doc.title} — VarmanWAF documentation`,
          group: group.title,
          body: docArticle({
            title: doc.title,
            lead: doc.lead,
            html: doc.html,
            group: group.title,
            words: doc.words,
            role,
          }),
          toc: doc.toc,
          slug: item.slug,
          file: relative,
        }),
      )
      addSearch({
        title: doc.title,
        description: doc.lead,
        group: group.title,
        url: `/docs/${slug}.html`,
        headings: doc.toc.map((heading) => heading.text),
        text: doc.text.slice(0, 900),
      })
      for (const heading of doc.toc.slice(0, 12)) {
        addSearch({
          title: heading.text,
          description: `${doc.title} · ${group.title}`,
          group: group.title,
          url: `/docs/${slug}.html#${heading.id}`,
          headings: [],
          text: '',
          kind: 'section',
        })
      }
    }
  }

  // Docs home
  fs.writeFileSync(path.join(docsOut, 'index.html'), docsHome())
  addSearch({
    title: 'Documentation home',
    description: 'Start with your role, choose a deployment, see the console.',
    group: 'Start here',
    url: '/docs/',
    headings: [],
    text: 'VarmanWAF documentation start here roles deployment console feature inventory quick start',
  })

  // Releases
  const releasesDir = path.join(dist, 'releases')
  fs.mkdirSync(releasesDir, { recursive: true })
  for (const name of releaseFiles) {
    const version = name.replace(/\.md$/, '')
    fs.writeFileSync(path.join(releasesDir, `${version}.html`), releasePage(name))
    const meta = releaseMeta(name)
    addSearch({
      title: `Release ${version}`,
      description: meta.title,
      group: 'Release notes',
      url: `/releases/${version}.html`,
      headings: [],
      text: `${meta.version} ${meta.title} ${meta.summary}`,
    })
  }
  fs.writeFileSync(path.join(releasesDir, 'index.html'), releasesIndex())

  // Khmer
  copyDir(path.join(docsDir, 'user-guide-km'), path.join(dist, 'khmer'))

  // Search index
  fs.writeFileSync(
    path.join(docsOut, 'search-index.json'),
    JSON.stringify(
      SEARCH.sort(
        (a, b) =>
          (a.kind === 'section' ? 1 : 0) - (b.kind === 'section' ? 1 : 0) ||
          a.title.localeCompare(b.title),
      ),
    ),
  )

  // The static server sends assets with `immutable` for a year, so a content
  // change must produce a new URL. Hash the shared bundles once and rewrite
  // every version marker instead of relying on manually bumped dates.
  const assetVersion = crypto
    .createHash('sha256')
    .update(
      ['site.css', 'site.js', 'docs.css', 'docs.js']
        .map((name) => fs.readFileSync(path.join(dist, 'assets', name)))
        .join('\n'),
    )
    .digest('hex')
    .slice(0, 10)
  const rewriteVersions = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const target = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        rewriteVersions(target)
      } else if (entry.name.endsWith('.html')) {
        const html = fs.readFileSync(target, 'utf8')
        const rewritten = html.replace(/\?v=\d{8}/g, `?v=${assetVersion}`)
        if (rewritten !== html) fs.writeFileSync(target, rewritten)
      }
    }
  }
  rewriteVersions(dist)

  console.log(
    `site built: ${SEARCH.length} searchable pages · ${releaseFiles.length} releases · landing · docs shell · assets ${assetVersion}`,
  )
}

main()
