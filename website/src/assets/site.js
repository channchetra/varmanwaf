/* Small, dependency-free enhancements: nav shadow, theme toggle, TOC
 * scrollspy, code copy buttons. */

const nav = document.getElementById('nav')
if (nav) {
  const onScroll = () => nav.classList.toggle('scrolled', window.scrollY > 8)
  onScroll()
  window.addEventListener('scroll', onScroll, { passive: true })
}

// Theme toggle: system preference by default, an explicit choice is remembered.
const themeToggle = document.getElementById('theme-toggle')
if (themeToggle) {
  const root = document.documentElement
  const media = window.matchMedia('(prefers-color-scheme: light)')
  const currentTheme = () =>
    root.dataset.theme === 'light' || root.dataset.theme === 'dark'
      ? root.dataset.theme
      : media.matches
        ? 'light'
        : 'dark'
  const sync = () => {
    themeToggle.setAttribute(
      'aria-label',
      currentTheme() === 'light' ? 'Switch to dark theme' : 'Switch to light theme',
    )
  }
  themeToggle.addEventListener('click', () => {
    const next = currentTheme() === 'light' ? 'dark' : 'light'
    root.dataset.theme = next
    try {
      localStorage.setItem('varman-theme', next)
    } catch (e) {}
    sync()
  })
  sync()
}

// Table-of-contents highlight for documentation pages.
const tocLinks = Array.from(document.querySelectorAll('.doc-toc a[href^="#"]'))
if (tocLinks.length > 0) {
  const targets = tocLinks
    .map((link) => {
      const id = decodeURIComponent(link.getAttribute('href').slice(1))
      const el = document.getElementById(id)
      return el ? { link, el } : null
    })
    .filter(Boolean)

  const update = () => {
    const fromTop = window.scrollY + 120
    let current = targets[0]
    for (const target of targets) {
      if (target.el.offsetTop <= fromTop) current = target
    }
    for (const target of targets) {
      target.link.classList.toggle('active', target === current)
    }
  }
  update()
  window.addEventListener('scroll', update, { passive: true })
}

// Copy button on code blocks (documentation pages).
for (const pre of document.querySelectorAll('.doc-body pre')) {
  const button = document.createElement('button')
  button.type = 'button'
  button.textContent = 'copy'
  button.className = 'code-copy'
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(pre.innerText)
      button.textContent = 'copied'
      setTimeout(() => (button.textContent = 'copy'), 1400)
    } catch {
      button.textContent = 'n/a'
    }
  })
  pre.style.position = 'relative'
  pre.appendChild(button)
}
