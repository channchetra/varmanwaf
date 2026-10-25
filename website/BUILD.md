# Building the documentation site

The VarmanWAF docs are generated from the repository markdown by
[`build.mjs`](./build.mjs). There is no separate docs source tree: the website
and `docs/` cannot drift.

## Requirements

- Node 22+
- npm
- Python 3 only for a quick local static server (optional)

## Build

```bash
cd website
npm ci
npm run build
```

`build.mjs` reads `docs/`, renders every page, and writes:

| Output | Source |
| --- | --- |
| `dist/index.html` | `src/index.html` (landing) |
| `dist/docs/*.html` | every document in `docs/` |
| `dist/docs/index.html` | the role/deployment/console hub |
| `dist/docs/search-index.json` | page + section search index |
| `dist/releases/*.html` | every release note, auto-discovered |
| `dist/khmer/` | `docs/user-guide-km/` copied verbatim |

## Docs shell

- `src/assets/docs.css` — tokens, sticky top bar, grouped sidebar, article
  typography, callouts, numbered steps, figures, TOC, search dialog, home hub,
  releases, light/dark and responsive rules.
- `src/assets/docs.js` — theme persistence, sidebar groups/collapse, mobile
  drawer, docs search (`Ctrl/⌘ K`), scroll-spy, copy buttons and Mermaid.
- `build.mjs` — the `NAV` array defines the sidebar and search metadata;
  `LEADS` holds the page summaries. Add a document to `NAV` to publish it.

Headings use GitHub-compatible anchors, so cross-document `#anchors` copied
from the repository keep working. Images live in `docs/images/console/` and
are referenced from markdown as `images/console/<name>.webp`; the build
rewrites them to `/images/console/<name>.webp` and wraps standalone images in
`<figure>` captions.

## Local preview

```bash
python3 -m http.server -d dist 8082
# http://127.0.0.1:8082/docs/
```

## Container

```bash
cd website
npm run build
docker build -f Dockerfile -t varmanwaf-website:local .
docker run --rm -p 8081:8080 varmanwaf-website:local
# http://localhost:8081/docs/
```

The runtime image is `scratch` + a static server from `server/server.rs`
(standard library only). The image is built locally and is not published to
Docker Hub.

## Docs QA

Before shipping a docs change:

- `node build.mjs` must report the expected page/release counts.
- Every internal `href`/`src` and every `#anchor` must resolve.
- Check the docs home, one role page, the deployment page and one release page
  in light and dark at 1440 px and 390 px.
- Open search (`Ctrl/⌘ K`), search for a feature, and follow a result.
