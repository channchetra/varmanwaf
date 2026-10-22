# UI language: the console's "box" system

The console follows one consistent visual language, modelled on the studied
product's settings panels and implemented with our own components and brand
colour (`#f6821f`).

## The rule

Every page or panel **explains itself before it asks for input**:

1. **Header** - title + one-line description (`PageHeader`).
2. **Overview box** - a `Callout` in the **brand** tone: an icon, a short
   title and two sentences on what the page answers, where things are
   configured, and what the honest limits are. No silent surfaces.
3. **Boxed sections** - every group of settings lives in a `Card` with a
   header (title + hint) and a body; nothing floats on the page background.
4. **Stat strips** - label/value tiles (`StatGrid`) for summaries (effective
   policy, fleet counts, posture) instead of prose.

## Tones (`Callout`)

| Tone | Use |
|---|---|
| `brand` | Page/panel overviews, primary guidance - the product accent |
| `info` | Operational notes, deep links to docs |
| `warning` | Cautions (destructive or security-relevant choices) |
| `danger` | Failures and refusals |
| `success` | Confirmed/healthy states |
| `neutral` | Secondary context |

Body copy stays in the readable foreground colours; the tone colours the
icon, border and background tint - brand orange is for emphasis, never for
long text.

## Where it is applied (this round)

Overviews: Dashboard, Sites, Policies, CRS rulesets, Alerts, IP lists, Logs,
Agents, Settings, Bot Protection, Rate limiting, Access control, WAF rules,
CC protection, Engine posture (Grading). Selection states use brand: pill
tabs' active item, card selections, primary buttons.

## Notes for future rounds

- New pages must add the overview box before shipping; complex panels get
  their own.
- Prefer extracting a `Callout`/`StatGrid` usage over ad-hoc coloured
  paragraphs; hard-coded blues/purples are not part of the palette.
- The overview text must be operational and honest (what the page does, what
  it does not, where the state lives) - not marketing copy.

## Dismissible overviews (v1.1.7)

An informational overview box can pass `dismissKey`. It then renders a close
button and remembers the choice in `localStorage` under
`varman.banner.<key>` for seven days, so a note that has been read does not
keep taking the top of the page. Only static guidance is dismissible: live
warnings (a paused TLS listener, an expiring certificate, an unsynced geo
key) deliberately have no key, because the operator needs them until the
state changes.

## Fullscreen canvases (v1.1.7)

The fleet and site topology graphs carry an **Expand / Exit fullscreen**
action that makes the canvas itself fullscreen; Escape or the browser's own
exit restores the console. State is derived from `fullscreenchange`, so an
OS-level exit is reflected in the button.

## Site overview (v1.1.7)

Opening a site lands on its own **Overview** tab (`/sites/:id/overview`): the
24-hour counters, the protection posture in force, the active certificate,
origin health and the latest security findings, each with a link into the
surface that owns it. This is the one place that combines what the site
serves with what is enforced on it.
