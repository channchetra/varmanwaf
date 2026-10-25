/* VarmanWAF documentation runtime. */
(() => {
  'use strict'

  const root = document.documentElement
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)')
  const systemLight = window.matchMedia('(prefers-color-scheme: light)')

  /* ------------------------------------------------------------ theme */

  const themeButton = document.querySelector('[data-docs-theme]')

  function storedPreference() {
    try {
      const value = localStorage.getItem('varman-theme')
      return value === 'light' || value === 'dark' || value === 'system' ? value : 'system'
    } catch (error) {
      return 'system'
    }
  }

  function resolved(preference) {
    if (preference === 'light' || preference === 'dark') return preference
    return systemLight.matches ? 'light' : 'dark'
  }

  function applyTheme(preference) {
    root.dataset.themePreference = preference
    root.dataset.theme = resolved(preference)
    if (themeButton) {
      const next = root.dataset.theme === 'dark' ? 'light' : 'dark'
      themeButton.setAttribute('aria-label', `Switch to ${next} theme`)
      themeButton.setAttribute('title', `Switch to ${next} theme`)
    }
  }

  if (themeButton) {
    themeButton.addEventListener('click', () => {
      const next = root.dataset.theme === 'dark' ? 'light' : 'dark'
      try {
        localStorage.setItem('varman-theme', next)
      } catch (error) {
        /* private mode */
      }
      applyTheme(next)
    })
    systemLight.addEventListener('change', () => {
      if ((root.dataset.themePreference || 'system') === 'system') applyTheme('system')
    })
    applyTheme(storedPreference())
  }

  /* ---------------------------------------------------- sidebar groups */

  const groups = Array.from(document.querySelectorAll('[data-nav-group]'))
  let savedGroups = {}
  try {
    savedGroups = JSON.parse(localStorage.getItem('varman-docs-groups') || '{}')
  } catch (error) {
    savedGroups = {}
  }

  for (const group of groups) {
    const id = group.dataset.navGroup
    if (Object.prototype.hasOwnProperty.call(savedGroups, id)) {
      group.open = Boolean(savedGroups[id])
    }
    if (group.querySelector('.docs-nav-link.is-active')) group.open = true
    group.addEventListener('toggle', () => {
      savedGroups[id] = group.open
      try {
        localStorage.setItem('varman-docs-groups', JSON.stringify(savedGroups))
      } catch (error) {
        /* private mode */
      }
    })
  }

  /* --------------------------------------------------------- sidebar UI */

  const sidebar = document.getElementById('docs-sidebar')
  const menuButton = document.querySelector('[data-docs-menu]')
  const collapseButton = document.querySelector('[data-docs-collapse]')
  const scrim = document.querySelector('[data-docs-scrim]')

  function setMobileMenu(open) {
    if (!sidebar || !menuButton) return
    sidebar.classList.toggle('is-open', open)
    menuButton.setAttribute('aria-expanded', open ? 'true' : 'false')
    if (scrim) scrim.hidden = !open
    document.body.style.overflow = open ? 'hidden' : ''
    if (open) {
      sidebar.tabIndex = -1
      sidebar.focus({ preventScroll: true })
    }
  }

  if (menuButton) menuButton.addEventListener('click', () => setMobileMenu(!sidebar.classList.contains('is-open')))
  if (scrim) scrim.addEventListener('click', () => setMobileMenu(false))
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') setMobileMenu(false)
  })
  if (sidebar) {
    sidebar.addEventListener('click', (event) => {
      const link = event.target.closest('a')
      if (link && window.matchMedia('(max-width: 1024px)').matches) setMobileMenu(false)
    })
  }

  function applySidebarCollapsed(collapsed) {
    if (collapsed) root.dataset.docsSidebar = 'collapsed'
    else delete root.dataset.docsSidebar
    if (collapseButton) {
      collapseButton.setAttribute('aria-pressed', collapsed ? 'true' : 'false')
      collapseButton.setAttribute(
        'aria-label',
        collapsed ? 'Expand documentation sidebar' : 'Collapse documentation sidebar',
      )
    }
  }

  if (collapseButton) {
    const collapsed = root.dataset.docsSidebar === 'collapsed'
    applySidebarCollapsed(collapsed)
    collapseButton.addEventListener('click', () => {
      const next = root.dataset.docsSidebar !== 'collapsed'
      applySidebarCollapsed(next)
      try {
        localStorage.setItem('varman-docs-nav', next ? 'collapsed' : 'expanded')
      } catch (error) {
        /* private mode */
      }
    })
  }

  /* ------------------------------------------------------------- search */

  const dialog = document.getElementById('docs-search')
  const resultsBox = dialog?.querySelector('[data-search-results]')
  const input = dialog?.querySelector('input[type="search"]')
  const countLabel = dialog?.querySelector('[data-search-count]')
  let searchIndex = null
  let searchPromise = null
  let selected = -1
  let currentResults = []

  function loadIndex() {
    if (searchPromise) return searchPromise
    searchPromise = fetch('/docs/search-index.json')
      .then((response) => {
        if (!response.ok) throw new Error('search index unavailable')
        return response.json()
      })
      .then((data) => {
        searchIndex = data
        return data
      })
      .catch(() => {
        searchIndex = []
        return searchIndex
      })
    return searchPromise
  }

  function escapeHtml(value) {
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
  }

  function highlight(value, query) {
    if (!query) return escapeHtml(value)
    const index = value.toLowerCase().indexOf(query.toLowerCase())
    if (index < 0) return escapeHtml(value)
    return `${escapeHtml(value.slice(0, index))}<mark>${escapeHtml(
      value.slice(index, index + query.length),
    )}</mark>${escapeHtml(value.slice(index + query.length))}`
  }

  function score(entry, query) {
    const title = entry.title.toLowerCase()
    const description = (entry.description || '').toLowerCase()
    const text = (entry.text || '').toLowerCase()
    const headings = (entry.headings || []).join(' ').toLowerCase()
    const section = entry.kind === 'section'
    const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const word = new RegExp(`\\b${escaped}\\b`, 'i').test(title)
    let value = 0
    if (title === query) value += section ? 150 : 160
    else if (title.startsWith(query)) value += section ? 125 : 135
    else if (word) value += section ? 95 : 105
    else if (title.includes(query)) value += section ? 50 : 60
    if (headings.includes(query)) value += 24
    if (description.includes(query)) value += 18
    if (text.includes(query)) value += 8
    return value
  }

  function renderResults(query) {
    if (!resultsBox) return
    const value = query.trim()
    if (!value) {
      resultsBox.innerHTML =
        '<p class="docs-search-hint">Type to search guides, console surfaces, deployment paths and releases.</p>'
      if (countLabel) countLabel.textContent = '—'
      selected = -1
      currentResults = []
      return
    }
    const results = (searchIndex || [])
      .map((entry) => ({ entry, score: score(entry, value.toLowerCase()) }))
      .filter((item) => item.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 18)
    currentResults = results.map((item) => item.entry)
    selected = results.length > 0 ? 0 : -1
    if (countLabel) countLabel.textContent = `${results.length} result${results.length === 1 ? '' : 's'}`
    if (results.length === 0) {
      resultsBox.innerHTML = `<p class="docs-search-hint">No results for “${escapeHtml(
        value,
      )}”. Try “protection”, “agents”, “HA” or “API”.</p>`
      return
    }
    let group = ''
    const html = []
    for (const item of results) {
      if (item.entry.group !== group) {
        group = item.entry.group
        html.push(`<p class="docs-search-group">${escapeHtml(group)}</p>`)
      }
      html.push(
        `<a class="docs-search-result${item === results[0] ? ' is-selected' : ''}" href="${item.entry.url}" data-search-result>`,
        `<strong>${highlight(item.entry.title, value)}</strong>`,
        item.entry.description
          ? `<span>${highlight(item.entry.description, value)}</span>`
          : '',
        '</a>',
      )
    }
    resultsBox.innerHTML = html.join('')
  }

  function moveSelection(delta) {
    const items = Array.from(resultsBox?.querySelectorAll('[data-search-result]') || [])
    if (items.length === 0) return
    items[selected]?.classList.remove('is-selected')
    selected = (selected + delta + items.length) % items.length
    items[selected]?.classList.add('is-selected')
    items[selected]?.scrollIntoView({ block: 'nearest' })
  }

  function openSearch() {
    if (!dialog) return
    loadIndex()
    if (typeof dialog.showModal === 'function') dialog.showModal()
    else dialog.setAttribute('open', '')
    input?.focus()
    input?.select()
    renderResults(input?.value || '')
  }

  function closeSearch() {
    if (!dialog) return
    if (typeof dialog.close === 'function') dialog.close()
    else dialog.removeAttribute('open')
  }

  for (const trigger of document.querySelectorAll('[data-docs-search]')) {
    trigger.addEventListener('click', (event) => {
      event.preventDefault()
      openSearch()
    })
  }

  input?.addEventListener('input', () => renderResults(input.value))
  input?.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      moveSelection(1)
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      moveSelection(-1)
    } else if (event.key === 'Enter' && selected >= 0) {
      event.preventDefault()
      const item = currentResults[selected]
      if (item) window.location.href = item.url
    }
  })

  dialog?.addEventListener('click', (event) => {
    if (event.target === dialog) closeSearch()
  })
  dialog?.addEventListener('close', () => {
    if (input) input.value = ''
    renderResults('')
  })

  document.addEventListener('keydown', (event) => {
    const typing =
      event.target instanceof HTMLElement &&
      (event.target.matches('input, textarea, select') || event.target.isContentEditable)
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault()
      openSearch()
    } else if (event.key === '/' && !typing && !event.metaKey && !event.ctrlKey) {
      event.preventDefault()
      openSearch()
    }
  })

  /* --------------------------------------------------------- scroll spy */

  const article = document.querySelector('.docs-article')
  const tocLinks = Array.from(document.querySelectorAll('.docs-toc a'))
  const headings = Array.from(article?.querySelectorAll('.docs-body h2[id], .docs-body h3[id]') || [])
  if (tocLinks.length && headings.length) {
    const linkById = new Map(tocLinks.map((link) => [link.getAttribute('href')?.slice(1), link]))
    const visible = new Map()
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) visible.set(entry.target.id, entry.isIntersecting)
        const active = headings.find((heading) => visible.get(heading.id)) || headings[0]
        for (const link of tocLinks) link.classList.remove('is-active')
        const link = linkById.get(active?.id)
        if (link) {
          link.classList.add('is-active')
          link.setAttribute('aria-current', 'location')
        }
      },
      { rootMargin: '-90px 0px -68% 0px', threshold: [0, 1] },
    )
    for (const heading of headings) observer.observe(heading)
    const initial = linkById.get(headings[0].id)
    if (initial && !tocLinks.some((link) => link.classList.contains('is-active'))) {
      initial.classList.add('is-active')
      initial.setAttribute('aria-current', 'location')
    }
  }

  /* ---------------------------------------------------------- copy code */

  for (const block of document.querySelectorAll('.docs-body pre')) {
    const code = block.querySelector('code')
    if (!code || !navigator.clipboard) continue
    const button = document.createElement('button')
    button.type = 'button'
    button.className = 'docs-copy'
    button.textContent = 'Copy'
    button.setAttribute('aria-label', 'Copy code to clipboard')
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(code.innerText)
        button.textContent = 'Copied'
        button.classList.add('is-copied')
        window.setTimeout(() => {
          button.textContent = 'Copy'
          button.classList.remove('is-copied')
        }, 1600)
      } catch (error) {
        button.textContent = 'Select'
      }
    })
    block.appendChild(button)
  }

  /* ------------------------------------------------------------ mermaid */

  if (document.querySelector('.mermaid')) {
    import('/assets/mermaid.min.js')
      .then((module) => {
        const mermaid = module.default
        mermaid.initialize({
          startOnLoad: false,
          securityLevel: 'strict',
          theme: root.dataset.theme === 'dark' ? 'dark' : 'neutral',
        })
        mermaid.run({ nodes: Array.from(document.querySelectorAll('.mermaid')) })
      })
      .catch(() => {
        /* diagrams stay as readable source if the runtime is unavailable */
      })
  }
})()
