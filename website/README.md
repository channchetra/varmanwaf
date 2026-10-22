# VarmanWAF website

The public website: a landing page plus **every document in `docs/`**, rendered
at build time from the same markdown the repository ships, so the site can
never drift from the source. The Khmer user guide (with its screenshots) and
the release notes are published as-is.

## Build and run

```bash
cd website
npm install          # marked + mermaid
npm run build        # renders docs/ into dist/ (landing, docs, releases, khmer)

# serve locally
node -e "require('http')" # (not needed) - use the container or any static server
python3 -m http.server -d dist 8080
```

### Container (small image, `scratch`)

```bash
cd website && npm install && npm run build     # dist/ must exist first
docker build -f website/Dockerfile -t varmanwaf-website website/
docker run --rm -p 8080:8080 varmanwaf-website
# open http://localhost:8080
```

The image is `scratch` plus a statically linked server written in the standard
library only (no crates, no shell, no libc). Expected size: a few megabytes,
dominated by the site files (screenshots + the mermaid runtime).

## What is published

| Path | Source |
| --- | --- |
| `/` | `src/index.html` (landing: features, architecture, engine, performance, quick start) |
| `/docs/` | index of all documents, grouped by audience |
| `/docs/<slug>.html` | rendered `docs/*.md` (links rewritten, headings anchored, TOC generated) |
| `/khmer/index.html` | `docs/user-guide-km/` copied verbatim (Khmer guide with screenshots) |
| `/releases/` | rendered `docs/releases/*.md` |
| `/images/` | `docs/images/` |

Markdown is rendered with `marked` (GFM tables included); ```` ```mermaid ````
fences become live diagrams via the bundled `mermaid` runtime. Relative links
between documents are rewritten to site URLs; links out of `docs/` (e.g. the
repository README) point at GitHub.

## Layout

```text
website/
├── build.mjs            # the generator (docs -> dist)
├── Dockerfile           # rust:alpine -> scratch
├── package.json
├── server/server.rs     # dependency-free static server (std only)
├── src/
│   ├── index.html       # landing page
│   ├── favicon.svg
│   └── assets/          # site.css, site.js
└── dist/                # generated (not committed)
```

## Design language

The public site follows the same visual language as GuardianWAF's site, with
VarmanWAF's own content: navy `#0b1220` and light `#f5f8fd` backgrounds, a
single blue accent (`#88c2ff` dark / `#2165c5` light), Space Grotesk for UI
text, JetBrains Mono for code and labels, a 1728px layout grid with
`clamp(20px, 3.5vw, 72px)` gutters, hairline borders and small radii.

## What the landing reproduces

The landing was rebuilt after a runtime teardown of guardianwaf.com (DOM
structure, computed styles, CSS keyframes, `document.getAnimations()` and the
interactive widgets). The structure is mirrored section for section, with our
own copy and artwork:

- sticky header with a three-state theme panel (Light / Dark / System, with
  previews), a mouse-effects toggle, GitHub and a mobile menu;
- hero with a staggered entrance, a coded shield SVG, SMIL traffic packets,
  a floating shield, a blinking orbit spark, labels and a scroll nudge;
- four-stat strip; six feature cards with the SQL token visual, fingerprint
  rings, routing graph, animated bar chart, integration tags and the wide
  open-source card;
- the interactive request inspector: four example requests, six pipeline
  stages (checkpoint animation with per-stage delays), attack/challenge states
  and a live verdict + score;
- deployment tabs (Docker Compose / control plane + edges / binary) with a
  code window, copy button and changing note;
- observability split with a dashboard mock: metric strip, SVG chart drawn
  with `stroke-dashoffset`, and a security-event list;
- native `<details>` FAQ with rotating plus signs, final CTA with an inline
  install command and corner marks, footer with a signature card.

### Motion and preferences

- 11 CSS keyframes: `theme-panel-enter`, `shield-float`, `nudge`, `spark`,
  `blink`, `scan`, `checkpoint`, `bar-grow`, `chart-draw`, `hero-entrance`
  (the studio logo draw was not carried over).
- A fixed, pointer-events-none SVG overlay (`site-interactions`) draws a
  cursor ring/core, a fading 18-point trail, proximity "lift" glyphs, relay
  links, click pulses and wave halos. It is built in `site.js` at runtime.
- Dark is the default; the theme is stored under `varman-theme`
  (`light` / `dark` / `system`) and resolved before paint. The mouse-effects
  preference is stored under `varman-animations` (`on` / `off`); off also
  disables CSS animation and transition globally.
- The overlay and page animations are disabled for
  `prefers-reduced-motion: reduce`, coarse pointers, and viewports below
  800px. `chart-draw` is pinned to its final state when motion is off.

The runtime is intentionally framework-free: state changes touch only the
affected DOM (pipeline classes and result, deploy tab content, theme/animations
attributes), so there is no client-side router or hydration step.

## Notes

- The docs are the single source: edit `docs/*.md`, rebuild, and the website
  follows. New documents are added to the catalogue in `build.mjs` (`GROUPS`).
- The server supports `GET`/`HEAD`, clean directory indexes (`index.html`),
  correct MIME types, path-traversal rejection, and long-lived caching for
  `/assets/`. It is intentionally not a general-purpose web server.
- No image is published to Docker Hub: the website image is built locally.
