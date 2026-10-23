# VarmanWAF Handoff — 2026-10-23

This is the continuation memory for the console/site-management, public-website,
and Impeccable accessibility work. Read this first on a new machine, then open
`docs/releases/v1.1.9.md` for the user-facing release record.

> The handoff commit is after the `v1.1.9` release tag. Check out `main` (not
> the tag) to get this file; the tag remains the immutable release artifact.

## Status at handoff

| Item | State |
|---|---|
| Branch / tag | `main`; release-doc commit `41de69c`, annotated tag `v1.1.9` pushed to GitHub |
| Local console | **1.1.9**, healthy at `https://localhost:9080` (self-signed cert) |
| Local website | **v1.1.9** at `http://localhost:8081` |
| Production | **1.1.8**, not auto-upgraded |
| Production live site | `varman.unitywork.space` — unchanged by this round |
| Image | `sovichetra/varmanwaf:1.1.9` / `:latest` |
| Digest | `sha256:84f29c4bded9d3f6282c2355757ba45126a343d4523985bd311b2d64b5175967` |
| Release notes | `docs/releases/v1.1.9.md` |
| Design system | `web/DESIGN.md`, `web/.impeccable/design.json` |

No database migration and no API change in 1.1.9. Existing modes, rules,
policies and logs are preserved.

## Product model (settled earlier, do not re-litigate)

- **Protection mode** is the single enforcement gate per site: **Block**,
  **Monitor** or **Paused**, in the site header on every site tab. It writes the
  site status plus WAF mode. A policy-managed site shows “Managed by policy” and
  routes the change to **Protection → Advanced**.
- **Rules detect.** A rule’s own **Rule mode** is an explicit override for that
  rule only; it never overrides the site mode.
- **Advanced** (formerly “Policy tuning”) holds paranoia, advanced mode,
  monitor-only categories, exclusions, shared policy and history.
- **Policies** are optional reusable configuration across sites. They are not a
  second enforcement switch.
- Site tabs are **Overview · Rules · Flood protection · Advanced**.
- Site list **Visit site** and the site-detail domain open the live site; the
  row/domain in the list opens the workspace.

## What was shipped

### v1.1.8 — site-management clarity

- One Protection mode control; removed the competing bulk rule-mode card and
  separate pause/activate buttons.
- Rules page reads the **effective** mode; per-rule mode is labelled as an
  override.
- Tabs renamed; Overview reordered to modules → request path → optional policy.
- Site list Visit action and detail domain link to the live site.
- Responsive sites table hides lower-priority columns before clipping actions.
- Release record: `docs/releases/v1.1.8.md`.

### Public website

- Rebuilt from the GuardianWAF visual language (navy `#0b1220`, light
  `#f5f8fd`, accent `#88c2ff`, Space Grotesk + JetBrains Mono, 1728px grid),
  with VarmanWAF’s own copy and artwork.
- Landing page: hero shield, stats, six feature cards, interactive pipeline,
  deploy tabs, observability mock, FAQ, CTA, footer, pointer overlay, theme
  panel. Docs pages share header/footer/theme.
- Source in `website/`; build reads `docs/` and auto-discovers release notes.
- Local preview container `varmanwaf-website` on `http://localhost:8081`.

### Impeccable capture and audit

- Captured `web/PRODUCT.md`, `web/DESIGN.md`,
  `web/.impeccable/design.json`.
- Direction: **“The Operations Bridge”**, palette **“Signal Ember on
  Graphite”**, component feel **“Crisp, restrained, instrument-like”**.
- Initial audit 13/20; the fix round is 1.1.9.

### v1.1.9 — accessibility, theming and loading round

**Contrast**

- Ember is a fill, not UI text: primary buttons use dark ink on ember
  (`--color-text-on-brand`, 6.53:1; 5.46:1 on light hover).
- New `brand-ink` text token: `#a34700` light / `#ffb066` dark for ember
  labels/icons/active nav.
- Danger text `#b83c2c` light / `#ff6340` dark; warning text `#805b09` /
  `#ffc53d`; filled destructive buttons use Danger Strong
  (`#c2410c` / `#b83c2c`) with white text.
- Dedicated placeholder token `#767676` / `#9a9a9a`.
- Card metadata/topology subtitles use full muted text, not 70–80% opacity.
- Login brand panel is graphite (`bg-brand-panel`) with white text (16.9:1),
  not white on a full ember surface; assistant user bubble uses dark ink.
- Switch on-track uses `brand-ink` with an elevated thumb.

**Keyboard / assistive technology**

- Sortable `<th>` content is a real button; `aria-sort` is set on the cell.
- Dialogs focus the panel, trap Tab, make `#root` inert, restore focus to the
  trigger and close on Escape; title/description use `aria-labelledby` /
  `aria-describedby`.
- Skip link targets `main#main`.
- Account menu has an accessible name, `aria-haspopup` and `aria-expanded`.
- Closed AI assistant aside is `inert`; card headings are `h2` under the page
  `h1`; login has a single `h1` and a 24px password-reveal target.
- Mobile buttons/icon controls and sidebar items use 44px minimum targets.

**Motion, charts, loading**

- `prefers-reduced-motion` removes decorative animation/transform transitions
  but keeps 150ms color/border/opacity feedback.
- Charts use resolved-theme palette `web/src/lib/chartPalette.ts`; topology
  nodes/edges/minimap use tokens; React Flow controls/minimap chrome themed.
- Routes are `React.lazy` chunks behind the shell’s Suspense boundary. Entry
  chunk fell from ~1.25MB to ~86kB.
- Dashboard top-rule rows key by `rule_id + action`; the analytics API
  legitimately returns `VARMAN-1020` once as monitor and once as block.

**Docs / detector**

- Updated `web/DESIGN.md`, `web/.impeccable/design.json`, `docs/features.md`,
  `docs/navigation-ia.md`, `docs/ui-language.md`, `docs/user-guide.md`,
  `docs/roadmap.md`, `docs/README.md`.
- Impeccable detector reports **0 findings**. The two generated email error-page
  font sizes (22px / 96px) carry a narrow inline waiver because they are
  emailed artifacts, not console UI.

## Verification evidence

- `npx tsc -b` clean.
- `npm run lint` **0 errors** (7 pre-existing fast-refresh warnings).
- `npx vitest run` **34/34**.
- Impeccable detector **0 findings**.
- Lighthouse accessibility **1.0 on `/login` and `/dashboard`** (dev-server
  `robots.txt` is the only SEO warning).
- Browser checks in light/dark for buttons, active nav, placeholders, table
  keyboard sort + `aria-sort`, dialog focus/inert/Escape/restore, skip link,
  route loading, charts, topology minimap and duplicate-key fix.
- E2E: full 45-script sweep **44/45 first pass**. The only failure was
  `run-e2e-fine-tuning.ps1` cleanup expecting 200 from `/.git/config` while
  earlier tests had left the site in **Block** mode (got the site’s own 403).
  Setting the site baseline to **monitor** and rerunning passed all checks.
  Final smoke also passed: `run-e2e.ps1`, navigation, site-tabs, UI-fixes,
  topology.
- Binary: `varman 1.1.9 (7b296f9, tls=openssl)`.
- Image digest recorded above; local running container and both pushed tags
  match it.

## Repository facts

Recent commits:

```text
41de69c docs(release): add v1.1.9 notes and verification
7b296f9 fix(web): use a single h1 on the login screen
f640def fix(web): complete the keyboard and contrast pass
5181053 fix(web): keep login and assistant text readable on ember
404eb2f fix(web): key dashboard top rules by rule and action
fd81607 feat(web): accessibility and loading pass for 1.1.9
```

Version is bumped in two places in the root `Cargo.toml`: the workspace
`version` and every internal `pingap-*` path dependency. Do not bump unrelated
external crates that share the `1.1.8` string. `Cargo.lock` was regenerated by
the release build.

The working tree is clean except local graph state `.gitnexus/` (untracked;
do not commit).

## Environment / setup

Local workspace used here: `C:\Users\MPTC\Desktop\waf-dev\VarmanWAF`.
Docker Desktop must be running. Compose services: `varman`, `varman-postgres`,
`varman-processor`, `varman-origin`, `varman-dev`, `varmanwaf-website`.

Local console: `https://localhost:9080` with a self-signed certificate.
Local test site UUID (E2E scripts): `996841ea-f1c0-4ba2-be1e-34aca2e0439c`,
domain `e2e.varman.local`. Local dev credentials are the compose defaults
(`admin@varman.local` / `varman123`). **Do not store production credentials in
this repo.**

The Rust build container `varman-dev:1` is local-only and **not part of the
repo**. It is built from the parent workspace’s `Dockerfile.dev`
(`rust:1.98.1-bookworm` + protobuf/cmake/clang/openssl/nasm) and mounts:

- workspace root → `/waf`
- `varman-target` volume → `/target`
- `varman-cargo-git` volume → `/usr/local/cargo/git`
- `varman-cargo-registry` volume → `/usr/local/cargo/registry`

If the image is missing on another PC, either `docker save`/`load`
`varman-dev:1` or recreate an equivalent image from those requirements.

## Commands

### Web checks and build

```bash
cd VarmanWAF/web
npm ci
npx tsc -b
npm run lint
npm test
npm run build
```

### Rust release build (only via dev container; ~8 min)

Build `web/dist` first, then:

```bash
docker exec varman-dev bash -c \
  "cd /waf/VarmanWAF && touch varman-control/src/frontend.rs && \
   CARGO_TARGET_DIR=/target cargo build --release -p varman"
```

Touching `frontend.rs` is required so the rebuilt web bundle is embedded.
Verify:

```bash
docker exec varman-dev /target/release/varman --version
```

### Build runtime image and deploy locally

```bash
cd <workspace>
docker cp varman-dev:/target/release/varman build-artifacts/varman
cp VarmanWAF/varman.toml build-artifacts/varman.toml
docker build -f VarmanWAF/Dockerfile.runtime \
  -t sovichetra/varmanwaf:1.1.9 \
  -t sovichetra/varmanwaf:latest \
  build-artifacts
cd VarmanWAF
docker compose up -d --force-recreate varman
curl.exe -sk https://localhost:9080/healthz
curl.exe -sk https://localhost:9080/api/v1/version
```

`docker compose up` leaves PostgreSQL/processor untouched. No migration.

### E2E

```powershell
cd build-artifacts
pwsh -NoProfile -File .\run-e2e-all.ps1
```

The sweep paces login attempts at 25s per script (10/min limiter). Before
fine-tuning, make sure the test site is in **monitor** mode; otherwise its
cleanup probe expects 200 from `/.git/config` and gets the site’s own 403:

```http
PUT /api/v1/sites/996841ea-f1c0-4ba2-be1e-34aca2e0439c/waf/settings
{ "waf_enabled": true, "mode": "monitor" }
```

`run-e2e.ps1` recreates the site if needed, restarts `varman`, and leaves the
stack running.

### Website

```bash
cd VarmanWAF/website
npm run build
docker build -f Dockerfile -t varmanwaf-website:local .
docker rm -f varmanwaf-website
docker run -d --name varmanwaf-website -p 8081:8080 varmanwaf-website:local
```

`npm run build` renders the landing page plus every document in `docs/`;
release pages are discovered from `docs/releases/`.

### Publish image

```bash
docker push sovichetra/varmanwaf:1.1.9
docker push sovichetra/varmanwaf:latest
docker inspect sovichetra/varmanwaf:1.1.9 --format '{{json .RepoDigests}}'
```

Record the digest in `docs/releases/v1.1.9.md`, rebuild the website so its
release page shows it, then commit/tag/push.

### Production upgrade (only when the user asks)

```bash
cd ~/varmanwaf && docker compose pull
docker compose up -d --force-recreate varman
curl -sk https://localhost:9080/api/v1/version
```

Production was **1.1.8** at handoff. Do not auto-upgrade it.

## Gotchas learned this round

- Docker Desktop sometimes stops answering the CLI while containers still
  serve traffic. Restarting Docker Desktop and `wsl --terminate docker-desktop`
  recovered it; containers with `restart: unless-stopped` came back. Manually
  start `varman-dev`, `varman-origin` and `varmanwaf-website` afterward.
- The deployed console uses a self-signed cert, so the desktop browser rejects
  `https://localhost:9080`. Use `http://localhost:5173` Vite for UI inspection,
  or `curl -k` for deployed API/asset checks. Vite is stopped at handoff.
- `run-e2e-fine-tuning.ps1` assumes the site baseline is **monitor**. Set that
  before running it after another script has left the site in Block mode.
- The first E2E pass was 44/45 because of that precondition, not a product bug.
- The web app’s `dist/` is embedded into the Rust binary; rebuilding only the
  image without the Rust build keeps the old UI.
- The binary embeds the git short hash at build time. Commit code before the
  final Rust build, or the reported hash will point at the previous commit.
- `.gitnexus/` is local graph state and must not be committed.
- Generated error-page templates intentionally use 22px/96px outside the
  console type ramp; the Impeccable detector waiver is inline in
  `web/src/api/errorPages.ts`.

## Suggested next moves

1. On the new PC, clone `https://github.com/channchetra/varmanwaf.git`, check
   out `v1.1.9`, and read this file.
2. If the user wants production on 1.1.9, run the upgrade command and verify
   `/api/v1/version`, `/healthz`, the served bundle hash and the site mode.
3. Optional rigor: run the full 45-script sweep once more on the final image
   with the monitor baseline. The current evidence is 44/45 + a passing
   fine-tuning rerun + final smoke.
4. No known code blockers. The next feature round can start from `v1.1.9`.
