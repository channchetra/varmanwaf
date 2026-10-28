/* VarmanWAF site runtime.
 *
 * Rebuilt from the guardianwaf.com runtime teardown: a three-state theme
 * panel, an animations/mouse-effects preference, a pointer-reactive SVG
 * overlay (security constellation, links, pulses, trails), the interactive
 * request pipeline,
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
  let cursorOrbit = null
  let shownAt = 0
  let pointerPresent = false
  let pulseCount = 0
  let constellationLinks = []
  let linkPulses = []

  // Security glyphs are drawn on a 24x24 grid so they stay legible at node
  // size and can be picked at random without loading icon files.
  const securityGlyphs = [
    { name: 'shield', paths: ['M12 2 20 5.5V12c0 4.6-3.4 7.7-8 9.5-4.6-1.8-8-4.9-8-9.5V5.5Z', 'm9 11.6 2 2 4-4.2'] },
    { name: 'lock', paths: ['M6 10.5h12V21H6Z', 'M9 10.5V7.8a3 3 0 0 1 6 0v2.7', 'M12 14.5v2.4'] },
    { name: 'key', paths: ['M8 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z', 'M11.5 12H21', 'M17 12v2.6', 'M20 12v1.8'] },
    { name: 'bug', paths: ['M8.2 7.6a3.8 3.8 0 0 1 7.6 0', 'M7 11.5h10v3.8a5 5 0 0 1-10 0Z', 'M3.5 13h3.5M17 13h3.5', 'M5 8l2.2 2M19 8l-2.2 2', 'M6 18.5 8 16.6M18 18.5 16 16.6'] },
    { name: 'eye', paths: ['M2 12s4.2-7 10-7 10 7 10 7-4.2 7-10 7S2 12 2 12Z', 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z'] },
    { name: 'terminal', paths: ['M3 4.5h18v15H3Z', 'm7 9 3 3-3 3', 'M13 15h4'] },
    { name: 'fingerprint', paths: ['M8 19.5c-1.6-2.1-2.5-4.6-2.5-7.3a6.5 6.5 0 0 1 13 0c0 2.7-.9 5.2-2.5 7.3', 'M12 21c-1.2-2-1.9-4.3-1.9-6.7a1.9 1.9 0 0 1 3.8 0c0 1.4.2 2.7.6 4', 'M5.6 10.2A6.8 6.8 0 0 1 12 4.4'] },
    { name: 'network', paths: ['M12 4v4.5', 'M5.2 18.2 10 13.5', 'M18.8 18.2 14 13.5', 'M12 8.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5Z', 'M5.2 20a2.3 2.3 0 1 0 0-4.6 2.3 2.3 0 0 0 0 4.6Z', 'M18.8 20a2.3 2.3 0 1 0 0-4.6 2.3 2.3 0 0 0 0 4.6Z'] },
    { name: 'database', paths: ['M4 6c0 1.7 3.6 3 8 3s8-1.3 8-3-3.6-3-8-3-8 1.3-8 3Z', 'M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6', 'M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3'] },
    { name: 'code', paths: ['m8 8-4.2 4L8 16', 'm16 8 4.2 4L16 16', 'm13.5 5-3 14'] },
    { name: 'radar', paths: ['M12 3a9 9 0 1 0 9 9', 'M12 7a5 5 0 1 0 5 5', 'm12 12 6.5-6.5', 'M12 11.8h.4'] },
    { name: 'cloud', paths: ['M6.4 18h10.9a3.8 3.8 0 0 0 .6-7.6 5.8 5.8 0 0 0-11-1.9A3.2 3.2 0 0 0 6.4 18Z', 'M9 14.5h6'] },
  ]

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

    const constellation = el('g', { class: 'ambient-constellation' })
    for (let i = 0; i < 16; i++) {
      const link = el('line', { class: 'ambient-constellation-link', opacity: '0' })
      constellation.appendChild(link)
      constellationLinks.push(link)
    }

    const liftsGroup = el('g', { class: 'ambient-lifts' })
    const positions = [
      [12, 21], [34, 13], [62, 18], [86, 26],
      [18, 47], [43, 39], [70, 45], [90, 60],
      [10, 74], [32, 69], [57, 81], [82, 77],
    ]
    const start = Math.floor(Math.random() * securityGlyphs.length)
    for (const [index, [px, py]] of positions.entries()) {
      const glyph = securityGlyphs[(start + index) % securityGlyphs.length]
      const group = el('g', { class: 'ambient-lift', display: 'none', opacity: '0', 'data-icon': glyph.name })
      group.appendChild(el('circle', { class: 'ambient-icon-orbit', r: '30' }))
      group.appendChild(el('circle', { class: 'ambient-icon-disc', r: '22' }))
      const icon = el('svg', { class: 'ambient-icon', x: '-13', y: '-13', width: '26', height: '26', viewBox: '0 0 24 24' })
      for (const d of glyph.paths) icon.appendChild(el('path', { d }))
      group.appendChild(icon)
      liftsGroup.appendChild(group)
      lifts.push({ node: group, x: px, y: py, seed: Math.random() * 6.28, opacity: 0 })
    }

    const pulses = el('g', { class: 'ambient-link-pulses' })
    for (let i = 0; i < 8; i++) {
      const pulse = el('circle', { class: 'ambient-link-pulse', r: '1.8', opacity: '0' })
      pulses.appendChild(pulse)
      linkPulses.push(pulse)
    }

    const effects = el('g', { class: 'ambient-effects' })
    const trails = el('g', { class: 'ambient-trails' })
    trailsGroup = trails
    for (let i = 0; i < 22; i++) {
      const soft = el('path', { class: 'ambient-trail-soft' })
      const core = el('path', { class: 'ambient-trail-core' })
      trails.append(soft, core)
      trailPairs.push({ soft, core })
    }
    pointerGlow = el('circle', { class: 'ambient-cursor-glow', r: '80', fill: 'url(#ambient-glow)', opacity: '0' })
    relayLine = el('line', { class: 'ambient-relay-link', opacity: '0' })
    relayRing = el('circle', { class: 'ambient-relay-ring', r: '30', fill: 'none', opacity: '0' })
    cursorOrbit = el('circle', { class: 'ambient-cursor-orbit', r: '31', fill: 'none' })
    cursorRing = el('circle', { class: 'ambient-cursor-ring', r: '18', fill: 'none' })
    cursorCore = el('circle', { class: 'ambient-cursor-core', r: '3' })

    effects.append(trails, pointerGlow, relayLine, relayRing, cursorOrbit, cursorRing, cursorCore)
    inner.append(constellation, liftsGroup, pulses, effects)
    ambient.appendChild(outer)
    ambient.setAttribute('data-nodes', String(lifts.length))
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
    shownAt = performance.now()
  }

  function ambientAllowed() {
    return root.dataset.animations !== 'off' && !reduceMotion.matches && finePointer.matches
  }

  function updateAmbient() {
    ambientFrame = 0
    if (!ambient || !ambientVisible) return
    const now = performance.now()
    const idle = now - lastMove
    const fade = Math.max(0, 1 - idle / 2600)
    const reveal = Math.min(1, Math.max(0, (now - shownAt) / 500))

    if (idle > 3000) {
      points = []
      for (const pair of trailPairs) {
        pair.soft.setAttribute('opacity', '0')
        pair.core.setAttribute('opacity', '0')
      }
      cursorRing.setAttribute('opacity', '0')
      cursorCore.setAttribute('opacity', '0')
      cursorOrbit.setAttribute('opacity', '0')
      pointerGlow.setAttribute('opacity', '0')
      relayLine.setAttribute('opacity', '0')
      relayRing.setAttribute('opacity', '0')
      for (const lift of lifts) lift.node.setAttribute('display', 'none')
      for (const link of constellationLinks) link.setAttribute('opacity', '0')
      for (const pulse of linkPulses) pulse.setAttribute('opacity', '0')
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
      if (Math.hypot(b.x - a.x, b.y - a.y) > 110) {
        pair.soft.setAttribute('opacity', '0')
        pair.core.setAttribute('opacity', '0')
        continue
      }
      const d = `M${a.x.toFixed(1)} ${a.y.toFixed(1)}L${b.x.toFixed(1)} ${b.y.toFixed(1)}`
      pair.soft.setAttribute('d', d)
      pair.core.setAttribute('d', d)
      const age = (i + 1) / trailPairs.length
      pair.soft.setAttribute('opacity', (age * 0.55 * fade).toFixed(3))
      pair.core.setAttribute('opacity', (age * 0.9 * fade).toFixed(3))
    }

    cursorRing.setAttribute('cx', pointer.x)
    cursorRing.setAttribute('cy', pointer.y)
    cursorRing.setAttribute('opacity', (0.75 * fade * reveal).toFixed(3))
    cursorCore.setAttribute('cx', pointer.x)
    cursorCore.setAttribute('cy', pointer.y)
    cursorCore.setAttribute('opacity', (fade * reveal).toFixed(3))
    cursorOrbit.setAttribute('cx', pointer.x)
    cursorOrbit.setAttribute('cy', pointer.y)
    cursorOrbit.setAttribute('stroke-dashoffset', (-(now * 0.018) % 12).toFixed(2))
    cursorOrbit.setAttribute('opacity', (0.55 * fade * reveal).toFixed(3))
    pointerGlow.setAttribute('cx', pointer.x)
    pointerGlow.setAttribute('cy', pointer.y)
    pointerGlow.setAttribute('opacity', (0.28 * fade * reveal).toFixed(3))
    if (trailsGroup) trailsGroup.setAttribute('opacity', fade.toFixed(3))

    // Icons drift very slowly, then brighten near the pointer.
    const nodes = []
    for (const lift of lifts) {
      const x = (lift.x / 100) * window.innerWidth + Math.sin(now / 4200 + lift.seed) * 5
      const y = (lift.y / 100) * window.innerHeight + Math.cos(now / 5000 + lift.seed) * 4
      const distance = Math.hypot(pointer.x - x, pointer.y - y)
      const proximity = Math.max(0, 1 - distance / 360)
      const opacity = (0.24 + 0.7 * proximity) * fade * reveal
      lift.node.setAttribute('display', 'inline')
      lift.node.setAttribute('transform', `translate(${x.toFixed(1)} ${y.toFixed(1)})`)
      lift.node.setAttribute('opacity', opacity.toFixed(3))
      nodes.push({ x, y, distance, opacity })
    }

    const near = nodes
      .filter((node) => node.distance < 480)
      .sort((a, b) => a.distance - b.distance)
      .slice(0, 7)
    const active = []
    let linkIndex = 0
    const drawLink = (a, b, opacity) => {
      const link = constellationLinks[linkIndex++]
      if (!link) return
      link.setAttribute('x1', a.x.toFixed(1))
      link.setAttribute('y1', a.y.toFixed(1))
      link.setAttribute('x2', b.x.toFixed(1))
      link.setAttribute('y2', b.y.toFixed(1))
      link.setAttribute('stroke-dashoffset', (-(now * 0.012) % 9).toFixed(2))
      link.setAttribute('opacity', opacity.toFixed(3))
      active.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y, opacity })
    }

    for (const node of near) {
      drawLink(pointer, node, (0.32 + 0.4 * (1 - node.distance / 480)) * fade * reveal)
    }
    for (let i = 1; i < near.length; i++) {
      drawLink(near[i - 1], near[i], 0.28 * fade * reveal)
    }
    for (; linkIndex < constellationLinks.length; linkIndex++) {
      constellationLinks[linkIndex].setAttribute('opacity', '0')
    }

    for (let i = 0; i < linkPulses.length; i++) {
      const pulse = linkPulses[i]
      const link = active[i]
      if (!link) {
        pulse.setAttribute('opacity', '0')
        continue
      }
      const t = (now * 0.00055 + i * 0.17) % 1
      pulse.setAttribute('cx', (link.x1 + (link.x2 - link.x1) * t).toFixed(1))
      pulse.setAttribute('cy', (link.y1 + (link.y2 - link.y1) * t).toFixed(1))
      pulse.setAttribute('opacity', Math.min(0.95, link.opacity * 1.4).toFixed(3))
    }

    if (near[0]) {
      relayLine.setAttribute('x1', pointer.x)
      relayLine.setAttribute('y1', pointer.y)
      relayLine.setAttribute('x2', near[0].x)
      relayLine.setAttribute('y2', near[0].y)
      relayLine.setAttribute('opacity', (0.45 * fade * reveal).toFixed(3))
      relayRing.setAttribute('cx', near[0].x)
      relayRing.setAttribute('cy', near[0].y)
      relayRing.setAttribute('opacity', (0.5 * fade * reveal).toFixed(3))
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
    // Chromium emits a synthetic (0,0) move when a page settles. Ignore it so
    // the constellation only appears once the visitor actually moves.
    if (!pointerPresent) {
      pointerPresent = true
      if (event.clientX === 0 && event.clientY === 0) return
    }
    const now = performance.now()
    pointer = { x: event.clientX, y: event.clientY }
    lastMove = now
    points.push({ x: pointer.x, y: pointer.y, t: now })
    if (points.length > 22) points.shift()
    if (!ambientVisible) showAmbient()
    if (!ambientFrame) ambientFrame = requestAnimationFrame(updateAmbient)
  }

  function onPointerDown(event) {
    if (!ambientAllowed()) return
    pointerPresent = true
    pointer = { x: event.clientX, y: event.clientY }
    lastMove = performance.now()
    points.push({ x: pointer.x, y: pointer.y, t: lastMove })
    if (points.length > 22) points.shift()
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

  /* ------------------------------------------------- hero product tilt */

  const heroFrame = document.querySelector('.hero-product .product-frame')
  let heroTiltFrame = 0
  let heroTilt = { x: 0, y: 0 }

  function resetHeroTilt() {
    if (!heroFrame) return
    heroFrame.style.setProperty('--tilt-x', '0deg')
    heroFrame.style.setProperty('--tilt-y', '0deg')
    heroFrame.style.setProperty('--tilt-lift', '0px')
  }

  function applyHeroTilt() {
    heroTiltFrame = 0
    if (!heroFrame) return
    heroFrame.style.setProperty('--tilt-x', `${heroTilt.y.toFixed(2)}deg`)
    heroFrame.style.setProperty('--tilt-y', `${heroTilt.x.toFixed(2)}deg`)
    heroFrame.style.setProperty('--tilt-lift', `${(-Math.abs(heroTilt.x) * 0.18 - Math.abs(heroTilt.y) * 0.18).toFixed(2)}px`)
  }

  if (heroFrame) {
    document.addEventListener(
      'pointermove',
      (event) => {
        if (!ambientAllowed() || window.innerWidth < 960) {
          resetHeroTilt()
          return
        }
        heroTilt = {
          x: (event.clientX / window.innerWidth - 0.5) * 2.4,
          y: (event.clientY / window.innerHeight - 0.5) * 1.8,
        }
        if (!heroTiltFrame) heroTiltFrame = requestAnimationFrame(applyHeroTilt)
      },
      { passive: true },
    )
    document.addEventListener('pointerleave', resetHeroTilt)
    window.addEventListener('blur', resetHeroTilt)
    reduceMotion.addEventListener('change', () => {
      if (reduceMotion.matches) resetHeroTilt()
    })
    resetHeroTilt()
  }

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
      title: 'One container. One protected app.',
      description:
        'Start the all-in-one image: console, control plane and edge in one process, with PostgreSQL alongside. Good for a lab or a single internal app.',
      code: `docker compose up -d
# console   https://localhost:9080
# traffic   :80 / :443
# gRPC      :9090`,
      note: 'First boot generates a self-signed console certificate. Change the seeded admin password immediately.',
    },
    split: {
      title: 'One control plane. A fleet of edges.',
      description:
        'Run the control plane once and one agent per edge. The control plane is never in the request path; edges keep serving their last-good bundle.',
      code: `# control plane
varman server --db-url "postgres://…" \
  --admin-addr 0.0.0.0:9080 --grpc-addr 0.0.0.0:9090

# each edge
varman agent --server-url "http://control-plane:9090" \
  --api-key "…"`,
      note: 'Bind an agent to one site, or leave it unbound for every site owned by its API key. Issue the key in Settings → API keys.',
    },
    ha: {
      title: 'Two failure domains. No single edge.',
      description:
        'Put two or more edge nodes behind DNS, a load balancer or anycast. Add a control-plane standby and replicated PostgreSQL for configuration writes.',
      code: `# 1. two or more edge nodes
# 2. DNS / LB / anycast in front
# 3. a control-plane standby
# 4. PostgreSQL streaming replication

# agents reconnect and re-sync by config_hash
# while the remaining edges keep serving`,
      note: 'The control plane is a control dependency, not a traffic dependency. Losing it stops changes, not requests.',
    },
    binary: {
      title: 'Your host. Your service manager.',
      description:
        'Install the static binary and run the all-in-one process under systemd, with your own PostgreSQL and your own certificate.',
      code: `curl -fsSL https://raw.githubusercontent.com/channchetra/varmanwaf/main/install.sh | bash

# then, with your database
varman all-in-one --db-url "postgres://…" \
  --admin-addr 0.0.0.0:9080`,
      note: 'Prebuilt Linux binaries are published for amd64 and arm64 on GitHub Releases; the installer verifies the checksum.',
    },
  }

  const deployTabs = Array.from(document.querySelectorAll('[data-deploy]'))
  const deployTitle = document.getElementById('deploy-title')
  const deployDescription = document.getElementById('deploy-description')
  const deployCode = document.getElementById('deploy-code')
  const deployNote = document.getElementById('deploy-code-note')

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
      const label = button.querySelector('[data-copy-label]') || button.querySelector('span')
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

  /* ------------------------------------------------------ scroll reveals */

  function initReveals() {
    if (reduceMotion.matches) return

    const groups = [
      ['.name-grid', 0],
      ['.stats-grid .stat', 70],
      ['#features .section-intro', 0],
      ['#features .feature-card', 65],
      ['#features .capabilities', 80],
      ['#features .protection-strip', 60],
      ['#how-it-works .section-intro', 0],
      ['#how-it-works .pipeline-demo', 50],
      ['#how-it-works .pipeline-footnote', 90],
      ['#performance .performance-copy', 0],
      ['#performance .benchmark-card', 80],
      ['#deploy .section-intro', 0],
      ['#deploy .deployment-tabs', 30],
      ['#deploy .deployment-info > h3', 60],
      ['#deploy .deployment-info > p', 90],
      ['#deploy .deployment-info > .text-link', 120],
      ['#deploy .code-window', 80],
      ['.observability-copy', 0],
      ['.observability-product', 80],
      ['.faq-section > div:first-child', 0],
      ['.faq-list details', 55],
      ['.final-cta', 0],
      ['.site-footer .footer-main', 0],
      ['.site-footer .footer-bottom', 60],
    ]

    const seen = new Set()
    const targets = []
    for (const [selector, stagger] of groups) {
      const list = Array.from(document.querySelectorAll(selector))
      list.forEach((node, index) => {
        if (seen.has(node)) return
        seen.add(node)
        targets.push({ node, delay: Math.min(index * stagger, 260) })
      })
    }
    if (targets.length === 0) return

    const cleanup = (node) => {
      const delay = parseFloat(node.style.getPropertyValue('--reveal-delay')) || 0
      window.setTimeout(() => {
        node.classList.remove('reveal', 'is-revealed')
        node.style.removeProperty('--reveal-delay')
      }, 950 + delay)
    }

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue
          const node = entry.target
          observer.unobserve(node)
          node.classList.add('is-revealed')
          cleanup(node)
        }
      },
      { threshold: 0.02, rootMargin: '0px 0px -2% 0px' },
    )

    for (const { node, delay } of targets) {
      const rect = node.getBoundingClientRect()
      if (rect.top < window.innerHeight - 24) continue
      node.classList.add('reveal')
      node.style.setProperty('--reveal-delay', `${delay}ms`)
      observer.observe(node)
    }

    reduceMotion.addEventListener('change', () => {
      if (!reduceMotion.matches) return
      observer.disconnect()
      for (const { node } of targets) {
        node.classList.remove('reveal', 'is-revealed')
        node.style.removeProperty('--reveal-delay')
      }
    })
  }

  initReveals()

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
