/**
 * VarmanWAF website generator.
 *
 * Renders every document under docs/ into the static site, so the website and
 * the repository documentation are the same single source. Output lands in
 * dist/ (landing page, docs pages, the Khmer guide, releases, images).
 *
 * Usage: node build.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { marked } from 'marked'

const here = path.dirname(fileURLToPath(import.meta.url))
const repo = path.resolve(here, '..')
const docsDir = path.join(repo, 'docs')
const dist = path.join(here, 'dist')
const src = path.join(here, 'src')

/* ------------------------------------------------------------------ */
/* Document catalogue: what the website publishes, grouped by audience */
/* ------------------------------------------------------------------ */

const GROUPS = [
  {
    id: 'start',
    title: 'Getting started',
    blurb: 'Install, deploy and protect the first site.',
    docs: [
      ['quick-start', 'Quick start'],
      ['deployment', 'Deployment guide'],
      ['usage', 'Using the console'],
      ['user-guide', 'User guide (English)'],
      ['features', 'Feature inventory'],
    ],
  },
  {
    id: 'security',
    title: 'Security engine',
    blurb: 'How the engine decides, and what ships with it.',
    docs: [
      ['security-engine', 'Security engine'],
      ['compatibility', 'SecLang & CRS compatibility'],
      ['performance', 'Performance (lane costs)'],
      ['benchmarks/v1.0.0', 'Benchmark report (1.0.0)'],
      ['shadow-report', 'Shadow comparison report'],
    ],
  },
  {
    id: 'operations',
    title: 'Operations',
    blurb: 'Run it in production: scale, fail over, keep it healthy.',
    docs: [
      ['ha', 'High availability & scaling'],
      ['sizing', 'Server sizing & capacity'],
      ['http-lifecycle', 'The HTTP request lifecycle'],
      ['acme_chart', 'ACME certificate flow'],
      ['navigation-ia', 'Console information architecture'],
    ],
  },
  {
    id: 'developer',
    title: 'Developer',
    blurb: 'Build, test, release, and where things live.',
    docs: [
      ['developer-guide', 'Developer guide'],
      ['architecture', 'Architecture'],
      ['modules', 'Workspace modules'],
      ['api', 'REST API reference'],
      ['ui-language', 'Console design language'],
    ],
  },
  {
    id: 'reference',
    title: 'Reference & history',
    blurb: 'Background, upstream lineage and the roadmap.',
    docs: [
      ['references', 'References and upstream inspiration'],
      ['roadmap', 'Roadmap'],
      ['upstream-pingwaf-map', 'Upstream baseline map'],
      ['upstream-update-plan', 'Upstream sync plan'],
      ['waf-engine-review', 'Early engine review (historical)'],
      ['waf-benchmark-report', 'Early benchmark (historical)'],
    ],
  },
]

/** Files under docs/ that become pages (flat file name -> slug). */
function slugFor(relative) {
  return relative
    .replace(/\.md$/i, '')
    .replace(/[\\/]/g, '-')
    .toLowerCase()
}

/* ------------------------------------------------------------------ */
/* Markdown rendering                                                  */
/* ------------------------------------------------------------------ */

marked.setOptions({ gfm: true, breaks: false })

/** Rewrite repo-relative links so the website resolves them. */
function rewriteLinks(html, currentSlug) {
  return html.replace(/href="([^"]+)"/g, (full, href) => {
    if (/^(https?:|mailto:|#)/.test(href)) return full
    // ../README.md -> the repository README is not published; point at the repo.
    if (href.startsWith('../')) {
      return `href="https://github.com/channchetra/varmanwaf/blob/main/${href.slice(3)}"`
    }
    if (href.startsWith('./user-guide-km/')) {
      return `href="/khmer/index.html"`
    }
    const match = href.match(/^\.\/(.+?)\.md(#.*)?$/)
    if (match) {
      const target = match[1]
      const anchor = match[2] ?? ''
      if (target.startsWith('releases/')) {
        return `href="/releases/${path.basename(target)}.html${anchor}"`
      }
      if (target.startsWith('benchmarks/')) {
        return `href="/docs/benchmarks-v1.0.0.html${anchor}"`
      }
      return `href="/docs/${slugFor(target)}.html${anchor}"`
    }
    if (href.startsWith('./')) return `href="/docs/${slugFor(href.slice(2))}.html"`
    if (href.startsWith('images/')) return `href="/images/${href.slice(7)}"`
    return full
  })
}

/** Heading ids + the per-page table of contents. */
function withHeadingIds(html) {
  const toc = []
  const seen = new Map()
  const out = html.replace(
    /<h([1-4])>(.*?)<\/h\1>/gs,
    (_full, level, inner) => {
      const text = inner.replace(/<[^>]+>/g, '')
      let id = text
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
      if (!id) id = 'section'
      const count = seen.get(id) ?? 0
      seen.set(id, count + 1)
      if (count > 0) id = `${id}-${count}`
      if (Number(level) <= 3) toc.push({ level: Number(level), text, id })
      return `<h${level} id="${id}">${inner}</h${level}>`
    },
  )
  return { html: out, toc }
}

function renderDoc(relative) {
  const raw = fs.readFileSync(path.join(docsDir, relative), 'utf8')
  // ```mermaid fences become mermaid divs; the client renders them.
  const prepared = raw.replace(
    /```mermaid\r?\n([\s\S]*?)```/g,
    (_m, body) => `\n<div class="mermaid">\n${body.trim()}\n</div>\n`,
  )
  const slug = slugFor(relative)
  let html = marked.parse(prepared)
  html = rewriteLinks(html, slug)
  return withHeadingIds(html)
}

function pageShell({ title, description, body, toc = [], active = '' }) {
  const tocHtml =
    toc.length > 0
      ? `<aside class="doc-toc">
        <p class="doc-toc-title">On this page</p>
        <ul>${toc
          .filter((entry) => entry.level <= 3)
          .map(
            (entry) =>
              `<li class="lvl-${entry.level}"><a href="#${entry.id}">${entry.text}</a></li>`,
          )
          .join('')}</ul>
      </aside>`
      : ''
  return `<!doctype html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · VarmanWAF</title>
<meta name="description" content="${description}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/site.css">
</head>
<body>
${navbar(active)}
<main class="doc-main">
  <div class="doc-wrap">
    <article class="doc-body">${body}</article>
    ${tocHtml}
  </div>
</main>
${footer()}
<script src="/assets/site.js" defer></script>
<script type="module">
  import mermaid from '/assets/mermaid.min.js'
  mermaid.initialize({ startOnLoad: true, theme: 'dark' })
</script>
</body>
</html>`
}

function navbar(active = '') {
  const link = (href, label, id) =>
    `<a href="${href}"${active === id ? ' class="active"' : ''}>${label}</a>`
  return `<header class="nav">
  <div class="nav-inner">
    <a class="brand" href="/">
      <span class="brand-mark">វ</span>
      <span class="brand-name">VarmanWAF</span>
    </a>
    <nav class="nav-links">
      ${link('/#features', 'Features')}
      ${link('/#architecture', 'Architecture')}
      ${link('/#performance', 'Performance')}
      ${link('/docs/', 'Docs', 'docs')}
      ${link('/khmer/index.html', 'ខ្មែរ')}
      ${link('/releases/', 'Releases')}
    </nav>
    <div class="nav-actions">
      <a class="btn btn-ghost" href="https://github.com/channchetra/varmanwaf" rel="noopener">GitHub</a>
      <a class="btn btn-primary" href="/#quick-start">Quick start</a>
    </div>
  </div>
</header>`
}

function footer() {
  return `<footer class="footer">
  <div class="footer-inner">
    <div class="footer-brand">
      <span class="brand-mark">វ</span>
      <div>
        <p class="footer-name">VarmanWAF</p>
        <p class="footer-note">Self-hosted, distributed Web Application Firewall. Apache-2.0.</p>
      </div>
    </div>
    <div class="footer-cols">
      <div>
        <p class="footer-col-title">Product</p>
        <a href="/#features">Features</a>
        <a href="/#architecture">Architecture</a>
        <a href="/#performance">Performance</a>
        <a href="/#quick-start">Quick start</a>
      </div>
      <div>
        <p class="footer-col-title">Documentation</p>
        <a href="/docs/">All documents</a>
        <a href="/docs/features.html">Feature inventory</a>
        <a href="/docs/security-engine.html">Security engine</a>
        <a href="/khmer/index.html">ណែនាំអ្នកប្រើប្រាស់ (ខ្មែរ)</a>
      </div>
      <div>
        <p class="footer-col-title">Operations</p>
        <a href="/docs/ha.html">High availability</a>
        <a href="/docs/sizing.html">Sizing &amp; capacity</a>
        <a href="/docs/benchmarks-v1.0.0.html">Benchmark report</a>
        <a href="/releases/">Release notes</a>
      </div>
      <div>
        <p class="footer-col-title">Project</p>
        <a href="https://github.com/channchetra/varmanwaf" rel="noopener">GitHub</a>
        <a href="https://hub.docker.com/r/sovichetra/varmanwaf" rel="noopener">Docker Hub</a>
        <a href="/docs/developer-guide.html">Developer guide</a>
        <a href="/docs/roadmap.html">Roadmap</a>
      </div>
    </div>
  </div>
  <p class="footer-legal">VarmanWAF is built on PingWAF / Pingap / Pingora. Geo and ASN data from ipverse.</p>
</footer>`
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

function main() {
  rmrf(dist)
  fs.mkdirSync(dist, { recursive: true })

  // --- landing + assets -------------------------------------------------
  fs.copyFileSync(path.join(src, 'index.html'), path.join(dist, 'index.html'))
  fs.copyFileSync(path.join(src, 'favicon.svg'), path.join(dist, 'favicon.svg'))
  copyDir(path.join(src, 'assets'), path.join(dist, 'assets'))
  fs.copyFileSync(
    path.join(here, 'node_modules', 'mermaid', 'dist', 'mermaid.min.js'),
    path.join(dist, 'assets', 'mermaid.min.js'),
  )
  copyDir(path.join(docsDir, 'images'), path.join(dist, 'images'))

  // --- docs pages -------------------------------------------------------
  const docsOut = path.join(dist, 'docs')
  fs.mkdirSync(docsOut, { recursive: true })

  let rendered = 0
  const indexGroups = []
  for (const group of GROUPS) {
    const entries = []
    for (const [file, label] of group.docs) {
      const relative = file.endsWith('.md') ? file : `${file}.md`
      const candidate = path.join(docsDir, relative)
      if (!fs.existsSync(candidate)) {
        console.warn(`  ! missing doc: ${relative}`)
        continue
      }
      const { html, toc } = renderDoc(relative)
      const slug = slugFor(relative)
      const title = label
      fs.writeFileSync(
        path.join(docsOut, `${slug}.html`),
        pageShell({
          title,
          description: `${title} - VarmanWAF documentation`,
          body: `<p class="doc-kicker"><a href="/docs/">Documentation</a> · ${group.title}</p>\n${html}`,
          toc,
          active: 'docs',
        }),
      )
      entries.push({ slug, label })
      rendered++
    }
    indexGroups.push({ ...group, entries })
  }

  // --- releases ---------------------------------------------------------
  const releasesDir = path.join(dist, 'releases')
  fs.mkdirSync(releasesDir, { recursive: true })
  const releaseFiles = fs
    .readdirSync(path.join(docsDir, 'releases'))
    .filter((name) => name.endsWith('.md'))
    .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
  const releaseLinks = []
  for (const name of releaseFiles) {
    const { html, toc } = renderDoc(`releases/${name}`)
    const slug = name.replace(/\.md$/, '')
    fs.writeFileSync(
      path.join(releasesDir, `${slug}.html`),
      pageShell({
        title: slug,
        description: `VarmanWAF ${slug} release notes`,
        body: `<p class="doc-kicker"><a href="/releases/">Releases</a> · ${slug}</p>\n${html}`,
        toc,
        active: 'docs',
      }),
    )
    releaseLinks.push(slug)
  }
  fs.writeFileSync(
    path.join(releasesDir, 'index.html'),
    pageShell({
      title: 'Release notes',
      description: 'Every VarmanWAF release with its verification evidence',
      body: `<h1>Release notes</h1>
<p>Every round ships whole: build, tests, the E2E sweep on a live deployment,
and a published image with its digest recorded here.</p>
<ul class="release-list">${releaseLinks
        .map((slug) => `<li><a href="/releases/${slug}.html">${slug}</a></li>`)
        .join('')}</ul>`,
      active: 'docs',
    }),
  )

  // --- documentation index ---------------------------------------------
  fs.writeFileSync(
    path.join(docsOut, 'index.html'),
    pageShell({
      title: 'Documentation',
      description: 'All VarmanWAF documentation, rendered from the repository',
      body: `<h1>Documentation</h1>
<p class="doc-lead">Everything in <code>docs/</code>, rendered from the same
markdown the repository ships - plus the Khmer user guide with screenshots of
every feature.</p>
${indexGroups
  .map(
    (group) => `<section class="doc-group">
  <h2>${group.title}</h2>
  <p class="doc-group-blurb">${group.blurb}</p>
  <div class="doc-cards">${group.entries
    .map(
      (entry) =>
        `<a class="doc-card" href="/docs/${entry.slug}.html">${entry.label}</a>`,
    )
    .join('')}</div>
</section>`,
  )
  .join('\n')}
<section class="doc-group">
  <h2>Other languages</h2>
  <div class="doc-cards">
    <a class="doc-card" href="/khmer/index.html">ណែនាំអ្នកប្រើប្រាស់ (ភាសាខ្មែរ) - full guide with screenshots</a>
  </div>
</section>`,
      active: 'docs',
    }),
  )

  // --- Khmer guide (already HTML) --------------------------------------
  copyDir(path.join(docsDir, 'user-guide-km'), path.join(dist, 'khmer'))

  console.log(`site built: ${rendered} docs + ${releaseLinks.length} releases + landing`)
}

main()
