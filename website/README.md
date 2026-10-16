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

## Notes

- The docs are the single source: edit `docs/*.md`, rebuild, and the website
  follows. New documents are added to the catalogue in `build.mjs` (`GROUPS`).
- The server supports `GET`/`HEAD`, clean directory indexes (`index.html`),
  correct MIME types, path-traversal rejection, and long-lived caching for
  `/assets/`. It is intentionally not a general-purpose web server.
- No image is published to Docker Hub: the website image is built locally.
