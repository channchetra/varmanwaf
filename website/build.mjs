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
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · VarmanWAF</title>
<meta name="description" content="${description}">
<meta name="theme-color" content="#0b1220" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f5f8fd" media="(prefers-color-scheme: light)">
<script>
  try {
    var pref = localStorage.getItem('varman-theme') || 'system';
    var dark = pref === 'dark' || (pref === 'system' && !window.matchMedia('(prefers-color-scheme: light)').matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    document.documentElement.dataset.themePreference = pref;
    document.documentElement.dataset.animations = localStorage.getItem('varman-animations') === 'off' ? 'off' : 'on';
  } catch (e) {}
</script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/site.css?v=20261023">
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
${navbar(active)}
<main class="doc-main" id="main">
  <div class="doc-wrap">
    <article class="doc-body">${body}</article>
    ${tocHtml}
  </div>
</main>
${footer()}
<script src="/assets/site.js?v=20261023" defer></script>
<script type="module">
  import mermaid from '/assets/mermaid.min.js'
  mermaid.initialize({
    startOnLoad: true,
    theme: document.documentElement.dataset.theme === 'light' ? 'default' : 'dark',
  })
</script>
</body>
</html>`
}

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
            <button type="button" role="radio" class="theme-option" data-theme-option="light" aria-checked="false" tabindex="-1">
              <span class="theme-preview theme-preview-light" aria-hidden="true"><span class="theme-preview-window"><i></i><i></i><i></i></span><span class="theme-preview-icon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2"/></svg></span></span>
              <span>Light</span>
              <span class="theme-selected" aria-hidden="true"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span>
            </button>
            <button type="button" role="radio" class="theme-option" data-theme-option="dark" aria-checked="false" tabindex="-1">
              <span class="theme-preview theme-preview-dark" aria-hidden="true"><span class="theme-preview-window"><i></i><i></i><i></i></span><span class="theme-preview-icon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg></span></span>
              <span>Dark</span>
              <span class="theme-selected" aria-hidden="true"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span>
            </button>
            <button type="button" role="radio" class="theme-option" data-theme-option="system" aria-checked="true" tabindex="0">
              <span class="theme-preview theme-preview-system" aria-hidden="true"><span class="theme-preview-window"><i></i><i></i><i></i></span><span class="theme-preview-icon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg></span></span>
              <span>System</span>
              <span class="theme-selected" aria-hidden="true"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span>
            </button>
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
      <a class="github-nav" href="https://github.com/channchetra/varmanwaf" target="_blank" rel="noreferrer" aria-label="VarmanWAF on GitHub">
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
      <a href="https://github.com/channchetra/varmanwaf" target="_blank" rel="noreferrer">GitHub</a>
    </div>
  </div>
  <div class="footer-bottom">
    <span>© 2026 VarmanWAF. Apache-2.0.</span>
    <span><svg class="tiny-shield" width="11" height="12" viewBox="0 0 24 28" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" aria-hidden="true"><path d="M12 2 22 6v8c0 6-4.4 10.4-10 12-5.6-1.6-10-6-10-12V6Z"/></svg> Built in the open.</span>
  </div>
  <a class="studio-signature" href="https://github.com/channchetra/varmanwaf" target="_blank" rel="noreferrer">
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
