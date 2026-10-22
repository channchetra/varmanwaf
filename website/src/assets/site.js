/* VarmanWAF site runtime.
 *
 * Rebuilt from the guardianwaf.com runtime teardown: a three-state theme
 * panel, an animations/mouse-effects preference, a pointer-reactive SVG
 * overlay (trails, relays, lifts, pulses), the interactive request pipeline,
 * deployment tabs, copy buttons and the mobile navigation. Everything is
 * vanilla DOM state - no framework and no build step for the behavior.
 */
(() => {
  'use strict'

  const root = document.documentElement
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)')
  const finePointer = window.matchMedia('(pointer: fine)')

  /* ------------------------------------------------------------- theme */

  const themeTrigger = document.getElementById('theme-trigger')
  const themePanel = document.getElementById('appearance-panel')
  const themeLabel = document.getElementById('theme-label')
  const themeOptions = Array.from(document.querySelectorAll('[data-theme-option]'))
  const systemQuery = window.matchMedia('(prefers-color-scheme: light)')

  const themeNames = { light: 'Light', dark: 'Dark', system: 'System' }

  function storedTheme() {
    try {
      const value = localStorage.getItem('varman-theme')
      return value === 'light' || value === 'dark' || value === 'system' ? value : 'system'
    } catch (e) {
      return 'system'
    }
  }

  function resolvedTheme(pref) {
    if (pref === 'light' || pref === 'dark') return pref
    return systemQuery.matches ? 'light' : 'dark'
  }

  function applyTheme(pref) {
    root.dataset.themePreference = pref
    root.dataset.theme = resolvedTheme(pref)
    if (themeLabel) themeLabel.textContent = themeNames[pref]
    if (themeTrigger) themeTrigger.setAttribute('aria-label', `Color theme: ${themeNames[pref]}`)
    for (const option of themeOptions) {
      const checked = option.dataset.themeOption === pref
      option.setAttribute('aria-checked', checked ? 'true' : 'false')
      option.tabIndex = checked ? 0 : -1
    }
  }

  function setTheme(pref) {
    try {
      localStorage.setItem('varman-theme', pref)
    } catch (e) {}
    applyTheme(pref)
  }

  function closeThemePanel() {
    if (!themePanel || !themeTrigger) return
    themePanel.hidden = true
    themeTrigger.setAttribute('aria-expanded', 'false')
  }

  if (themeTrigger && themePanel) {
    themeTrigger.addEventListener('click', () => {
      const open = themePanel.hidden
      themePanel.hidden = !open
      themeTrigger.setAttribute('aria-expanded', open ? 'true' : 'false')
      if (open) {
        const selected = themeOptions.find((option) => option.getAttribute('aria-checked') === 'true')
        if (selected) selected.focus({ preventScroll: true })
      }
    })
    for (const option of themeOptions) {
      option.addEventListener('click', () => setTheme(option.dataset.themeOption))
      option.addEventListener('keydown', (event) => {
        if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
          event.preventDefault()
          const current = themeOptions.indexOf(option)
          const next = (current + (event.key === 'ArrowRight' ? 1 : -1) + themeOptions.length) % themeOptions.length
          themeOptions[next].focus()
          setTheme(themeOptions[next].dataset.themeOption)
        }
      })
    }
    document.addEventListener('click', (event) => {
      if (!themePanel.hidden && !themePanel.contains(event.target) && !themeTrigger.contains(event.target)) {
        closeThemePanel()
      }
    })
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeThemePanel()
    })
    systemQuery.addEventListener('change', () => {
      if ((root.dataset.themePreference || 'system') === 'system') applyTheme('system')
    })
    applyTheme(storedTheme())
  }

  /* ------------------------------------------- animation / mouse effects */

  const animationToggle = document.getElementById('animation-toggle')
  const animationTooltip = document.getElementById('animation-tooltip')

  function storedAnimations() {
    try {
      return localStorage.getItem('varman-animations') === 'off' ? 'off' : 'on'
    } catch (e) {
      return 'on'
    }
  }

  function applyAnimations(state) {
    root.dataset.animations = state
    if (animationToggle) {
      animationToggle.setAttribute('aria-pressed', state === 'on' ? 'true' : 'false')
      animationToggle.setAttribute('aria-label', state === 'on' ? 'Disable mouse effects' : 'Enable mouse effects')
    }
    if (animationTooltip) {
      animationTooltip.textContent = state === 'on' ? 'Disable mouse effects' : 'Enable mouse effects'
    }
    if (state === 'off') hideAmbient()
  }

  if (animationToggle) {
    animationToggle.addEventListener('click', () => {
      const next = storedAnimations() === 'on' ? 'off' : 'on'
      try {
        localStorage.setItem('varman-animations', next)
      } catch (e) {}
      applyAnimations(next)
    })
    applyAnimations(storedAnimations())
  }

  /* --------------------------------------------------- ambient overlay */

  const SVG_NS = 'http://www.w3.org/2000/svg'
  let ambient = null
  let ambientEnabled = false
  let ambientFrame = 0
  let ambientVisible = false
  let points = []
  let pointer = { x: 0, y: 0 }
  let lastMove = 0
  let cursorRing = null
  let cursorCore = null
  let trailPairs = []
  let lifts = []
  let relayLine = null
  let relayRing = null
  let pointerGlow = null
  let trailsGroup = null
  let pulseCount = 0

  function el(name, attrs = {}) {
    const node = document.createElementNS(SVG_NS, name)
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value))
    return node
  }

  function buildAmbient() {
    if (ambient) return ambient
    ambient = el('svg', { class: 'site-interactions', 'aria-hidden': 'true', focusable: 'false' })
    const defs = el('defs')
    const xGrad = el('linearGradient', { id: 'ambient-x-fade', x2: '100%', y2: '0%' })
    for (const [offset, color] of [['0%', 'black'], ['3%', 'white'], ['97%', 'white'], ['100%', 'black']]) {
      xGrad.appendChild(el('stop', { offset, 'stop-color': color }))
    }
    const yGrad = el('linearGradient', { id: 'ambient-y-fade', x2: '0%', y2: '100%' })
    for (const [offset, color] of [['0%', 'black'], ['3%', 'white'], ['97%', 'white'], ['100%', 'black']]) {
      yGrad.appendChild(el('stop', { offset, 'stop-color': color }))
    }
    const glow = el('radialGradient', { id: 'ambient-glow' })
    glow.appendChild(el('stop', { offset: '0', 'stop-color': 'currentColor', 'stop-opacity': '1' }))
    glow.appendChild(el('stop', { offset: '0.4', 'stop-color': 'currentColor', 'stop-opacity': '0.3' }))
    glow.appendChild(el('stop', { offset: '1', 'stop-color': 'currentColor', 'stop-opacity': '0' }))
    defs.append(xGrad, yGrad, glow)

    const maskX = el('mask', { id: 'ambient-mask-x', maskUnits: 'userSpaceOnUse', x: '0', y: '0', width: '100%', height: '100%' })
    maskX.appendChild(el('rect', { width: '100%', height: '100%', fill: 'url(#ambient-x-fade)' }))
    const maskY = el('mask', { id: 'ambient-mask-y', maskUnits: 'userSpaceOnUse', x: '0', y: '0', width: '100%', height: '100%' })
    maskY.appendChild(el('rect', { width: '100%', height: '100%', fill: 'url(#ambient-y-fade)' }))
    defs.append(maskX, maskY)
    ambient.appendChild(defs)

    const outer = el('g', { mask: 'url(#ambient-mask-x)' })
    const inner = el('g', { mask: 'url(#ambient-mask-y)' })
    outer.appendChild(inner)

    const liftsGroup = el('g', { class: 'ambient-lifts' })
    const glyphs = [
      'M-16 0H16M0-16V16M-9-9 9 9M9-9-9 9',
      'M0-16 14-8V8L0 16-14 8V-8ZM0-7V7M-6 0H6',
      'M-14 8V-8L0-16 14-8V8L0 16ZM-6 0H6M0-6V6',
      'M-16 8H-6V-8H4V8H14M-2-12V-2',
    ]
    const positions = [
      [18, 26, -18], [78, 18, 12], [10, 66, 8], [86, 60, -10],
      [36, 82, 15], [64, 78, -15], [50, 14, 6], [28, 48, -6],
    ]
    for (const [px, py, rotate] of positions) {
      const group = el('g', { class: 'ambient-lift', display: 'none', transform: `translate(0 0) rotate(${rotate})`, opacity: '0' })
      group.appendChild(el('path', { class: 'ambient-trace', d: 'M-100-22H-64L-42 0H-20M20 0H54L76 24H110' }))
      group.appendChild(el('path', { class: 'ambient-glyph', d: glyphs[Math.floor(Math.random() * glyphs.length)] }))
      group.appendChild(el('circle', { class: 'ambient-node', cx: '-90', cy: '-22', r: '1.8' }))
      group.appendChild(el('rect', { class: 'ambient-node', x: '108', y: '22', width: '3', height: '3' }))
      liftsGroup.appendChild(group)
      lifts.push({ node: group, x: px, y: py, rotate, opacity: 0 })
    }

    const effects = el('g', { class: 'ambient-effects' })
    const trails = el('g', { class: 'ambient-trails' })
    trailsGroup = trails
    for (let i = 0; i < 18; i++) {
      const soft = el('path', { class: 'ambient-trail-soft' })
      const core = el('path', { class: 'ambient-trail-core' })
      trails.append(soft, core)
      trailPairs.push({ soft, core })
    }
    pointerGlow = el('circle', { class: 'ambient-cursor-glow', r: '80', fill: 'url(#ambient-glow)', opacity: '0' })
    relayLine = el('line', { class: 'ambient-relay-link', opacity: '0' })
    relayRing = el('circle', { class: 'ambient-relay-ring', r: '26', fill: 'none', opacity: '0' })
    cursorRing = el('circle', { class: 'ambient-cursor-ring', r: '15', fill: 'none' })
    cursorCore = el('circle', { class: 'ambient-cursor-core', r: '2.5' })

    effects.append(trails, pointerGlow, relayLine, relayRing, cursorRing, cursorCore)
    inner.append(liftsGroup, effects)
    ambient.appendChild(outer)
    document.body.appendChild(ambient)
    resizeAmbient()
    return ambient
  }

  function resizeAmbient() {
    if (!ambient) return
    ambient.setAttribute('viewBox', `0 0 ${window.innerWidth} ${window.innerHeight}`)
  }

  function hideAmbient() {
    ambientVisible = false
    if (!ambient) return
    ambient.style.display = 'none'
  }

  function showAmbient() {
    if (!ambient) buildAmbient()
    ambient.style.display = 'block'
    ambientVisible = true
  }

  function ambientAllowed() {
    return root.dataset.animations !== 'off' && !reduceMotion.matches && finePointer.matches
  }

  function updateAmbient() {
    ambientFrame = 0
    if (!ambient || !ambientVisible) return
    const now = performance.now()
    const idle = now - lastMove
    const fade = Math.max(0, 1 - idle / 1200)

    if (idle > 1400) {
      points = []
      for (const pair of trailPairs) {
        pair.soft.setAttribute('opacity', '0')
        pair.core.setAttribute('opacity', '0')
      }
      cursorRing.setAttribute('opacity', '0')
      cursorCore.setAttribute('opacity', '0')
      pointerGlow.setAttribute('opacity', '0')
      relayLine.setAttribute('opacity', '0')
      relayRing.setAttribute('opacity', '0')
      for (const lift of lifts) lift.node.setAttribute('display', 'none')
      return
    }

    // Trail segments, oldest first, faded by age.
    for (let i = 0; i < trailPairs.length; i++) {
      const a = points[i]
      const b = points[i + 1]
      const pair = trailPairs[i]
      if (!a || !b) {
        pair.soft.setAttribute('opacity', '0')
        pair.core.setAttribute('opacity', '0')
        continue
      }
      const d = `M${a.x.toFixed(1)} ${a.y.toFixed(1)}L${b.x.toFixed(1)} ${b.y.toFixed(1)}`
      pair.soft.setAttribute('d', d)
      pair.core.setAttribute('d', d)
      const age = (i + 1) / trailPairs.length
      pair.soft.setAttribute('opacity', (age * 0.45 * fade).toFixed(3))
      pair.core.setAttribute('opacity', (age * 0.75 * fade).toFixed(3))
    }

    cursorRing.setAttribute('cx', pointer.x)
    cursorRing.setAttribute('cy', pointer.y)
    cursorRing.setAttribute('opacity', (0.6 * fade).toFixed(3))
    cursorCore.setAttribute('cx', pointer.x)
    cursorCore.setAttribute('cy', pointer.y)
    cursorCore.setAttribute('opacity', (0.9 * fade).toFixed(3))
    pointerGlow.setAttribute('cx', pointer.x)
    pointerGlow.setAttribute('cy', pointer.y)
    pointerGlow.setAttribute('opacity', (0.22 * fade).toFixed(3))
    if (trailsGroup) trailsGroup.setAttribute('opacity', fade.toFixed(3))

    let nearest = null
    let nearestDistance = Infinity
    const edge = 170
    for (const lift of lifts) {
      const x = (lift.x / 100) * window.innerWidth
      const y = (lift.y / 100) * window.innerHeight
      const distance = Math.hypot(pointer.x - x, pointer.y - y)
      const visible = distance < edge && fade > 0.05
      if (visible) {
        lift.node.setAttribute('display', 'inline')
        lift.node.setAttribute('transform', `translate(${x.toFixed(1)} ${y.toFixed(1)}) rotate(${lift.rotate})`)
        const opacity = Math.max(0.15, 1 - distance / edge) * 0.9 * fade
        lift.node.setAttribute('opacity', opacity.toFixed(3))
        if (distance < nearestDistance) {
          nearestDistance = distance
          nearest = { x, y }
        }
      } else if (lift.node.getAttribute('display') !== 'none') {
        lift.node.setAttribute('display', 'none')
      }
    }

    if (nearest) {
      relayLine.setAttribute('x1', pointer.x)
      relayLine.setAttribute('y1', pointer.y)
      relayLine.setAttribute('x2', nearest.x)
      relayLine.setAttribute('y2', nearest.y)
      relayLine.setAttribute('opacity', (0.35 * fade).toFixed(3))
      relayRing.setAttribute('cx', nearest.x)
      relayRing.setAttribute('cy', nearest.y)
      relayRing.setAttribute('opacity', (0.4 * fade).toFixed(3))
    } else {
      relayLine.setAttribute('opacity', '0')
      relayRing.setAttribute('opacity', '0')
    }

    ambientFrame = requestAnimationFrame(updateAmbient)
  }

  function spawnPulse(x, y) {
    if (!ambient) return
    pulseCount += 1
    ambient.setAttribute('data-pulse-count', String(pulseCount))
    const wave = el('circle', { class: 'ambient-pulse', cx: x, cy: y, r: '6', opacity: '0.75' })
    ambient.appendChild(wave)
    if (typeof wave.animate === 'function') {
      wave.animate(
        [
          { r: 6, opacity: 0.75 },
          { r: 64, opacity: 0 },
        ],
        { duration: 900, easing: 'cubic-bezier(.2,.7,.3,1)' },
      ).onfinish = () => wave.remove()
    } else {
      wave.remove()
    }
    const halo = el('circle', { class: 'ambient-wave-halo', cx: x, cy: y, r: '10', opacity: '0.5' })
    ambient.appendChild(halo)
    if (typeof halo.animate === 'function') {
      halo.animate(
        [
          { r: 10, opacity: 0.4 },
          { r: 140, opacity: 0 },
        ],
        { duration: 1200, easing: 'ease-out' },
      ).onfinish = () => halo.remove()
    } else {
      halo.remove()
    }
  }

  function onPointerMove(event) {
    if (!ambientAllowed()) {
      if (ambientVisible) hideAmbient()
      return
    }
    const now = performance.now()
    pointer = { x: event.clientX, y: event.clientY }
    lastMove = now
    points.push({ x: pointer.x, y: pointer.y, t: now })
    if (points.length > 18) points.shift()
    if (!ambientVisible) showAmbient()
    if (!ambientFrame) ambientFrame = requestAnimationFrame(updateAmbient)
  }

  function onPointerDown(event) {
    if (!ambientAllowed()) return
    pointer = { x: event.clientX, y: event.clientY }
    lastMove = performance.now()
    points.push({ x: pointer.x, y: pointer.y, t: lastMove })
    if (points.length > 18) points.shift()
    if (!ambientVisible) showAmbient()
    spawnPulse(event.clientX, event.clientY)
    if (!ambientFrame) ambientFrame = requestAnimationFrame(updateAmbient)
  }

  document.addEventListener('pointermove', onPointerMove, { passive: true })
  document.addEventListener('pointerdown', onPointerDown, { passive: true })
  window.addEventListener('resize', resizeAmbient)
  reduceMotion.addEventListener('change', () => {
    if (!ambientAllowed()) hideAmbient()
  })

  /* ------------------------------------------------------ pipeline demo */

  const requestData = {
    clean: {
      target: 'GET /api/products?category=books',
      stages: ['on', 'on', 'on', 'on', 'on', 'on'],
      tone: 'safe',
      verdict: 'Allowed',
      code: '200',
      text: 'No suspicious tokens. The request reaches your application.',
      score: 0,
      icon: 'check',
    },
    sqli: {
      target: "GET /api/users?id=1%20OR%201=1--",
      stages: ['on', 'on', 'on', 'attack', 'muted', 'muted'],
      tone: 'attack',
      verdict: 'Blocked',
      code: '403',
      text: 'SQL operators and a comment sequence trigger the detection stage.',
      score: 55,
      icon: 'x',
    },
    xss: {
      target: 'GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E',
      stages: ['on', 'on', 'on', 'attack', 'muted', 'muted'],
      tone: 'attack',
      verdict: 'Blocked',
      code: '403',
      text: 'Executable markup is identified by the XSS detector.',
      score: 65,
      icon: 'x',
    },
    bot: {
      target: 'GET /checkout · suspicious client fingerprint',
      stages: ['on', 'on', 'on', 'on', 'challenge', 'muted'],
      tone: 'challenge',
      verdict: 'Challenged',
      code: 'PoW',
      text: 'A suspicious client receives a JavaScript proof-of-work challenge.',
      score: 40,
      icon: 'shield',
    },
  }

  const icons = {
    check: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>',
    x: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>',
    shield: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1Z"/><path d="M12 8v4M12 16h.01"/></svg>',
  }

  const requestOptions = Array.from(document.querySelectorAll('[data-request]'))
  const requestTarget = document.getElementById('request-target')
  const pipelineTrack = document.getElementById('pipeline-track')
  const requestResult = document.getElementById('request-result')

  function renderRequest(key) {
    const data = requestData[key]
    if (!data) return
    for (const button of requestOptions) {
      const selected = button.dataset.request === key
      button.classList.toggle('selected', selected)
      button.setAttribute('aria-pressed', selected ? 'true' : 'false')
    }
    if (requestTarget) requestTarget.textContent = data.target
    if (requestResult) {
      requestResult.className = `request-result result-${data.tone}`
      requestResult.innerHTML = `<span class="result-verdict">${icons[data.icon]} ${data.verdict} <code>${data.code}</code></span><p>${data.text}</p><span class="result-score">Example score <b>${data.score}</b><span>/100</span></span>`
    }
    if (pipelineTrack) {
      const stages = Array.from(pipelineTrack.querySelectorAll('.pipeline-stage'))
      for (const stage of stages) stage.classList.remove('stage-on', 'stage-attack', 'stage-challenge', 'stage-muted')
      // Force a reflow so the checkpoint animation restarts on every selection.
      void pipelineTrack.offsetWidth
      stages.forEach((stage, index) => {
        const state = data.stages[index] || 'on'
        if (state !== 'muted') stage.classList.add('stage-on')
        if (state === 'attack') stage.classList.add('stage-attack')
        if (state === 'challenge') stage.classList.add('stage-challenge')
        if (state === 'muted') stage.classList.add('stage-muted')
      })
    }
  }

  for (const button of requestOptions) {
    button.addEventListener('click', () => renderRequest(button.dataset.request))
  }

  /* ------------------------------------------------------ deploy tabs */

  const deployData = {
    docker: {
      title: 'One container. Every backend.',
      description: 'Start the all-in-one image: console, control plane and edge in one process, with PostgreSQL alongside.',
      code: `docker compose up -d
# console   https://localhost:9080
# traffic   :80 / :443
# gRPC      :9090`,
      note: 'First boot generates a self-signed console certificate. Change the seeded admin password immediately.',
    },
    split: {
      title: 'Your fleet. Your topology.',
      description: 'Run the control plane once and one agent per edge. The control plane is never in the request path.',
      code: `# control plane
varman control-plane

# each edge
varman-agent --control https://waf.example.com:9090

# agents keep their last-good bundle on disk`,
      note: 'Registration is closed by default; mTLS pins each agent to the control plane certificate.',
    },
    binary: {
      title: 'Your infrastructure. One binary.',
      description: 'Install the static binary and run the all-in-one process under systemd, with your own PostgreSQL.',
      code: `curl -fsSL https://get.varman.dev | sh
varman init
systemctl enable --now varman

# console https://<host>:9080
# traffic :80 / :443`,
      note: 'Prebuilt binaries are published for amd64 and arm64 on GitHub Releases; the installer verifies the checksum.',
    },
  }

  const deployTabs = Array.from(document.querySelectorAll('[data-deploy]'))
  const deployTitle = document.getElementById('deploy-title')
  const deployDescription = document.getElementById('deploy-description')
  const deployCode = document.getElementById('deploy-code')
  const deployNote = document.getElementById('deploy-note')

  function selectDeploy(key) {
    const data = deployData[key]
    if (!data) return
    for (const tab of deployTabs) tab.setAttribute('aria-selected', tab.dataset.deploy === key ? 'true' : 'false')
    if (deployTitle) deployTitle.textContent = data.title
    if (deployDescription) deployDescription.textContent = data.description
    if (deployCode) deployCode.textContent = data.code
    if (deployNote) deployNote.textContent = data.note
  }

  for (const tab of deployTabs) tab.addEventListener('click', () => selectDeploy(tab.dataset.deploy))

  /* -------------------------------------------------------- copy buttons */

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch (e) {
      const area = document.createElement('textarea')
      area.value = text
      area.style.position = 'fixed'
      area.style.opacity = '0'
      document.body.appendChild(area)
      area.select()
      const ok = document.execCommand('copy')
      area.remove()
      return ok
    }
  }

  for (const button of document.querySelectorAll('[data-copy-target]')) {
    button.addEventListener('click', async () => {
      const target = document.getElementById(button.dataset.copyTarget)
      if (!target) return
      const ok = await copyText(target.textContent || '')
      const label = button.querySelector('span')
      if (!label) return
      const original = label.textContent
      label.textContent = ok ? 'Copied' : 'Failed'
      setTimeout(() => {
        label.textContent = original
      }, 1400)
    })
  }

  /* --------------------------------------------------------- mobile nav */

  const menuToggle = document.getElementById('menu-toggle')
  const mobileNav = document.getElementById('mobile-nav')

  if (menuToggle && mobileNav) {
    const closeMenu = () => {
      mobileNav.hidden = true
      menuToggle.setAttribute('aria-expanded', 'false')
      menuToggle.setAttribute('aria-label', 'Open navigation')
    }
    menuToggle.addEventListener('click', () => {
      const open = mobileNav.hidden
      mobileNav.hidden = !open
      menuToggle.setAttribute('aria-expanded', open ? 'true' : 'false')
      menuToggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation')
    })
    for (const link of mobileNav.querySelectorAll('a')) link.addEventListener('click', closeMenu)
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeMenu()
    })
  }

  /* ------------------------------------------------ docs TOC + copy code */

  const tocLinks = Array.from(document.querySelectorAll('.doc-toc a[href^="#"]'))
  if (tocLinks.length > 0) {
    const targets = tocLinks
      .map((link) => {
        const id = decodeURIComponent(link.getAttribute('href').slice(1))
        const node = document.getElementById(id)
        return node ? { link, node } : null
      })
      .filter(Boolean)
    const update = () => {
      const fromTop = window.scrollY + 140
      let current = targets[0]
      for (const target of targets) if (target.node.offsetTop <= fromTop) current = target
      for (const target of targets) target.link.classList.toggle('active', target === current)
    }
    update()
    window.addEventListener('scroll', update, { passive: true })
  }

  for (const pre of document.querySelectorAll('.doc-body pre')) {
    const button = document.createElement('button')
    button.type = 'button'
    button.textContent = 'copy'
    button.className = 'code-copy'
    button.addEventListener('click', async () => {
      const ok = await copyText(pre.innerText)
      button.textContent = ok ? 'copied' : 'n/a'
      setTimeout(() => {
        button.textContent = 'copy'
      }, 1400)
    })
    pre.style.position = 'relative'
    pre.appendChild(button)
  }
})()
