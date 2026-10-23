---
name: VarmanWAF Console
description: The operations bridge for a distributed, self-hosted web application firewall.
colors:
  signal-ember: "#f6821f"
  ember-hover-light: "#e5731a"
  ember-hover-dark: "#ff9a4d"
  on-ember: "#1d1d1d"
  on-danger: "#ffffff"
  brand-ink-light: "#a34700"
  brand-ink-dark: "#ffb066"
  brand-soft-light: "#fef0e4"
  brand-soft-dark: "#423529"
  canvas-light: "#ffffff"
  canvas-dark: "#1d1d1d"
  surface-light: "#ffffff"
  surface-dark: "#2a2a2a"
  recessed-light: "#f7f7f8"
  recessed-dark: "#161616"
  ink-light: "#1d1d1d"
  ink-dark: "#e8e8e8"
  muted-light: "#666666"
  muted-dark: "#a0a0a0"
  strong-light: "#000000"
  strong-dark: "#ffffff"
  line-light: "#e8e8e8"
  line-dark: "#3a3a3a"
  focus-light: "#0051c3"
  focus-dark: "#52a9ff"
  danger-light: "#e54d2a"
  danger-dark: "#ff6340"
  danger-strong-light: "#c2410c"
  danger-strong-dark: "#b83c2c"
  danger-text-light: "#b83c2c"
  danger-text-dark: "#ff6340"
  success-light: "#18794e"
  success-dark: "#30a46c"
  warning-light: "#ffb224"
  warning-dark: "#ffc53d"
  warning-text-light: "#805b09"
  warning-text-dark: "#ffc53d"
  placeholder-light: "#767676"
  placeholder-dark: "#9a9a9a"
  graph-control-light: "#6e56cf"
  graph-control-dark: "#b477e4"
typography:
  display:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "24px"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "20px"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.01em"
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "normal"
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.6
    letterSpacing: "normal"
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "11px"
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "0.08em"
  micro:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "10px"
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "0.08em"
  caption:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "normal"
  body-small:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  title-small:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "normal"
  headline-small:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "18px"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.01em"
  mono:
    fontFamily: "'SFMono-Regular', ui-monospace, 'JetBrains Mono', Menlo, Consolas, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
rounded:
  sm: "4px"
  md: "6px"
  lg: "8px"
  xl: "12px"
  full: "9999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "20px"
  2xl: "24px"
  3xl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.signal-ember}"
    textColor: "{colors.on-ember}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "36px"
  button-primary-hover:
    backgroundColor: "{colors.ember-hover-light}"
    textColor: "{colors.on-ember}"
    rounded: "{rounded.md}"
  button-secondary:
    backgroundColor: "{colors.surface-light}"
    textColor: "{colors.ink-light}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "36px"
  button-ghost:
    textColor: "{colors.muted-light}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "36px"
  button-danger:
    backgroundColor: "{colors.danger-strong-light}"
    textColor: "{colors.on-danger}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "36px"
  input:
    backgroundColor: "{colors.surface-light}"
    textColor: "{colors.ink-light}"
    placeholderColor: "{colors.placeholder-light}"
    rounded: "{rounded.md}"
    padding: "0 12px"
    height: "36px"
  card:
    backgroundColor: "{colors.surface-light}"
    textColor: "{colors.ink-light}"
    rounded: "{rounded.lg}"
    padding: "20px"
  badge-neutral:
    backgroundColor: "{colors.recessed-light}"
    textColor: "{colors.muted-light}"
    rounded: "{rounded.full}"
    padding: "2px 10px"
  nav-item-active:
    backgroundColor: "{colors.brand-soft-light}"
    textColor: "{colors.brand-ink-light}"
    rounded: "{rounded.md}"
    padding: "8px 12px"
---

# Design System: VarmanWAF Console

## Overview

**Creative North Star: "The Operations Bridge"**

The console is a command bridge between a control plane and a fleet of edges. It is dense because operators are making real decisions, but it is quiet: graphite surfaces, hairline structure and a single ember signal keep the eye on the request, the site and the verdict. Nothing decorative competes with a live incident.

The visual system is instrument-like rather than consumer-like. Small radii, compact controls, system type and monospaced readouts make the interface feel native to the work. Light and dark are both first-class; the same semantic tokens carry the same meaning in either theme. Color is a state language: ember for action and selection, red/green/amber for danger/success/warning, neutrals for everything else.

Motion is state, not choreography. Page and dialog entrances are short, hover states are 150 ms, and nothing loops unless it is genuinely live.

**Key Characteristics:**
- Signal over noise: one ember accent, used sparingly for action, selection and state.
- Instrument density: compact controls, tables and readouts built for repeated use.
- Tonal depth: 1 px hairlines and layered surfaces before shadows.
- One gate per decision: enforcement is a single explicit control, not a hidden default.
- System type for familiarity; mono only for data, code and measurement.
- Light/dark parity from the same semantic tokens.

## Colors

A warm signal ember on graphite neutrals, with a cool blue reserved for focus and links.

### Primary
- **Signal Ember** (`#f6821f`): primary buttons, active navigation, selected controls, the brand mark and the small state dot. In dark it stays the same; hover shifts to `#ff9a4d` (dark) or `#e5731a` (light). It is an indicator lamp, not a surface wash.
- **On Ember** (`#1d1d1d`): text and icons on a filled ember control. Dark ink measures 6.53:1 on ember and 5.46:1 on the light hover fill; white is not used on ember for UI text.
- **Brand Ink** (`#a34700` light / `#ffb066` dark): ember-tinted text and icons on canvas or `brand-soft` badges and active navigation. Measures 6.07:1 on light canvas and 5.44:1 on the soft tint; dark is 9.36:1 on canvas and 6.57:1 on the soft tint.

### Neutral
- **Canvas** (`#ffffff` light / `#1d1d1d` dark): the page background and the scrollbar track.
- **Surface** (`#ffffff` light / `#2a2a2a` dark): cards, the sidebar, the top bar and dialogs.
- **Recessed** (`#f7f7f8` light / `#161616` dark): table headers, inset panels, skeletons and the bottom of a two-tone control.
- **Ink** (`#1d1d1d` light / `#e8e8e8` dark): default body text.
- **Muted** (`#666666` light / `#a0a0a0` dark): secondary labels, descriptions and inactive navigation.
- **Strong** (`#000000` light / `#ffffff` dark): headings, key values and active labels.
- **Line** (`#e8e8e8` light / `#3a3a3a` dark): the 1 px structure around every surface. **Fill** (`#d9d9d9` / `#4a4a4a`) is the stronger border for hover and dividers.
- **Focus / Link** (`#0051c3` light / `#52a9ff` dark): focus rings, text links and informational emphasis.
- **Danger** (`#e54d2a` light / `#ff6340` dark), **Success** (`#18794e` light / `#30a46c` dark), **Warning** (`#ffb224` light / `#ffc53d` dark): semantic verdict fills, tints and chart series only. For text use **Danger Ink** (`#b83c2c` / `#ff6340`, 5.64:1 / 5.71:1) and **Warning Ink** (`#805b09` / `#ffc53d`, 6.14:1 / 10.68:1). Filled destructive buttons use **Danger Strong** (`#c2410c` / `#b83c2c`) with white text (5.18:1 / 5.64:1) and darken on hover.
- **Placeholder** (`#767676` light / `#9a9a9a` dark): input hints only (4.54:1 / 5.10:1). A placeholder never replaces a visible label.
- **Graph Control** (`#6e56cf` light / `#b477e4` dark): the control-plane node in topology views only; not a general-purpose accent.

### Contrast
- Body, labels, placeholder and semantic text in both themes meet 4.5:1; icons and chart strokes meet 3:1.
- Filled controls use dark ink on ember and white on Danger Strong; no white-on-ember UI text.
- Chart series are theme-switched in JavaScript (`chartPalette.ts`) rather than relying on browser CSS variables inside SVG presentation attributes.
- Disabled controls are exempt from contrast minima and sit at 60% opacity with no pointer.

### Named Rules
**The Signal Rule.** Ember covers at most ~10% of any screen. It marks a primary action, the current selection or a live state - never a large background, never body text, never decoration.

**The Semantic-Only Rule.** Red, green and amber never carry branding or emphasis. If a color is not reporting danger, success or a warning, it is a neutral.

**The Two-Canvas Rule.** Light and dark are peers. A new color is not complete until both themes have a role for it; never pick one theme as the "real" one.

## Typography

**Display Font:** system sans (`-apple-system`, `Segoe UI`, Roboto, Helvetica Neue, Arial)
**Body Font:** the same system sans
**Label/Mono Font:** `SFMono-Regular`, `ui-monospace`, `JetBrains Mono`, Menlo, Consolas

**Character:** familiar and compact. The system face disappears into the task; the mono face is reserved for addresses, expressions and measurements, so a monospaced row reads as data rather than decoration.

### Hierarchy
- **Display** (600, 24px, 1.25, -0.02em): page titles only; one per page.
- **Headline** (600, 20px, 1.3): dialog titles and prominent site headers.
- **Title** (600, 15px, 1.4): card headers, section labels and the name of a thing.
- **Body** (400, 14px, 1.6): descriptions and prose, max ~70ch; tables and dense panels can run denser.
- **Label** (500, 10-11px, uppercase, 0.08em): stat labels, table headers and small section eyebrows.
- **Micro** (500, 10px, uppercase, 0.08em): the smallest meta line; use sparingly inside dense panels.
- **Caption** (400-500, 12px, 1.4): table metadata, badge text, hints and dense secondary rows.
- **Body small** (400, 13px, 1.5): secondary body text and table cells.
- **Title small** (600, 16px, 1.4): subheads and compact card titles.
- **Headline small** (600, 18px, 1.3): site headers and larger section titles.
- **Mono** (400, 12-13px, 1.5): IPs, domains, expressions, rule ids, log rows and tabular numbers. Use `font-variant-numeric: tabular-nums` for counts.

Generated error-page templates use 22px and 96px outside the console ramp; they are emailed artifacts, not app UI.

### Named Rules
**The Readout Rule.** Mono is a measurement voice: code, addresses, expressions, timestamps and numeric tables. Do not set prose, labels or navigation in mono to make a surface feel technical.

**The One Step Rule.** The type scale is fixed, not fluid. Stay within 11-24 px; use weight and color for hierarchy before adding another size.

## Layout

The shell is a 240 px sidebar (64 px collapsed) beside a 56 px sticky top bar. Content sits in a `max-width: 1400px` column with 16 px / 24 px / 32 px horizontal padding and a 24 px top rhythm. Page headers reserve `margin-bottom: 24px`.

Cards use 20 px internal padding; grids use 16-20 px gaps; dense tables use 8-12 px cell padding. The density is deliberate: an operator scans many rows and labels per screen. Responsive behavior is structural - the sidebar becomes a drawer, page headers stack, tables hide low-priority columns before clipping actions, and dialogs cap at `calc(100dvh - 2rem)`.

Motion: 150 ms for hover/press, 160-200 ms for dialog/scale entrances, 240-280 ms for page slides and toasts, with `cubic-bezier(0.16, 1, 0.3, 1)` for entrances. Under `prefers-reduced-motion`, decorative animation and transform transitions are removed while 150 ms color, border and opacity feedback remains.

## Elevation & Depth

A tonal system with soft structural shadows, not a floating-card system. At rest, a card is a 1 px `line` border over the `elevated` surface with a barely-there `shadow-sm`. Interactive cards may lift by 2 px and move to `shadow-md`; dialogs, the mobile sidebar and toasts use `shadow-lg` to leave the page. Depth is communicated first by the base/elevated/recessed tonal steps, then by the hairline, then by shadow.

### Shadow Vocabulary
- **sm** (`0 1px 2px rgba(0, 0, 0, 0.05)`; dark: `0 1px 2px rgba(0, 0, 0, 0.3)`): cards, buttons and the top bar at rest.
- **md** (`0 4px 6px -1px rgba(0, 0, 0, 0.1)`; dark: `0 4px 6px -1px rgba(0, 0, 0, 0.4)`): interactive hover and popovers.
- **lg** (`0 10px 15px -3px rgba(0, 0, 0, 0.1)`; dark: `0 10px 15px -3px rgba(0, 0, 0, 0.5)`): dialogs, toasts and the mobile sidebar.

### Named Rules
**The Hairline Rule.** Structure comes from a 1 px border and a tonal surface. A border plus a wide shadow is a ghost card; pick structure, add shadow only when the element actually lifts.

**The No-Halo Rule.** No zero-offset colored glows. A shadow carries an offset and a soft blur; color never substitutes for depth.

## Shapes

The form language is instrument-like: 4 px for tiny marks, 6 px for controls, 8 px for cards and grouped surfaces, 12 px for dialogs and the largest containers. Badges and pills use a full radius; everything else stays under 12 px. Borders are 1 px at rest, 2 px for a focus ring offset by 2 px. Icons are Phosphor duotone at 16-24 px, one stroke family across the whole console.

### Named Rules
**The Instrument Rule.** Radii stay at or below 12 px (except pills). Large consumer radii, thick colored side-borders and decorative blobs are out of vocabulary.

## Components

### Buttons
- **Shape:** 6 px radius (`rounded-md`); 36 px default height, 32 px small, 44 px large, 36×36 icon. On viewports below `sm`, every button has a 44 px minimum height and icon buttons a 44 px width.
- **Primary:** ember background, dark ink text, 0 16 px padding, `shadow-sm`; hover `brand-hover`, active `translate-y-px`; disabled at 60% opacity.
- **Secondary:** elevated surface, 1 px line border, ink text, `shadow-sm`; hover recessed.
- **Danger:** Danger Strong fill, white text; hover darkens by 5%.
- **Ghost:** transparent, muted text; hover recessed + full ink.
- **Link:** transparent, link color, no horizontal padding, underline on hover.
- **Focus:** a 2 px focus ring at 2 px offset in the focus color, visible on every variant.

### Badges
- **Style:** pill, 11-12 px medium text, 2 px 10 px padding, 1 px tone border at 30-40% and a 12% tone fill; optional 6 px dot.
- **State:** neutral is recessed/muted; success/danger/warning/info/brand carry semantics only. Never use a badge as a button.

### Cards
- **Corner Style:** 8 px (`rounded-lg`).
- **Background:** elevated surface; recessed for insets.
- **Shadow Strategy:** `shadow-sm` at rest; `shadow-md` only when interactive and hovered.
- **Border:** 1 px `line`.
- **Internal Padding:** 20 px; header `20px 20px 16px`, body `20px`.

### Inputs / Fields
- **Style:** 36 px high, 6 px radius, elevated surface, 1 px line border, 14 px text, 12 px left padding (36 px with a leading icon).
- **Placeholder:** `placeholder` token at 4.5:1 or better; never the only label for a field.
- **Focus:** border switches to the focus color plus a 2 px `focus/25` ring.
- **Error / Disabled:** danger border and 25% danger ring; disabled at 60% opacity with no pointer.
- **Labels:** 13 px medium muted; hint/error 12 px.
- **Switch:** the on track uses `brand-ink` with an elevated thumb; the off track uses `fill`. Track-to-canvas and thumb-to-track both meet 3:1 in light and dark.

### Tabs
- **Underline:** 14 px medium, 12 px horizontal padding, 2 px bottom border in ember when active; muted text otherwise.
- **Pill:** recessed container with 4 px padding, 6 px item radius; active item is elevated with `shadow-sm` and ember text.

### Navigation
- **Sidebar:** 240 px (64 px collapsed), elevated surface, 1 px right border; items 14 px medium, 6 px radius, 12 px horizontal padding, 8 px vertical.
- **Active item:** `brand-soft` background with `brand-ink` text; hover recessed with full ink. Group labels use 11 px uppercase muted with wide tracking.
- **Top bar:** 56 px sticky, elevated/85% with `backdrop-blur`, 1 px bottom border; breadcrumbs are 13 px muted with the current segment strong.
- **Mobile:** the sidebar becomes a 240 px drawer with `shadow-lg`; page chrome collapses, tables hide low-priority columns before clipping actions, and nav/button targets grow to 44 px.
- **Keyboard:** a visible-on-focus skip link starts the shell; sortable table headers are real buttons with `aria-sort`; dialogs move focus to the panel, trap Tab, make the app root `inert`, and restore focus to the trigger on close.

### Protection mode (signature)
- **Shape:** a compact card in the site header; 8 px radius, 1 px line, elevated surface; a leading 36 px icon tile tinted by state.
- **States:** Block = success tint, Monitor = focus tint, Paused = recessed, WAF off = warning tint.
- **Dialog:** three equal radio-like cards (Block / Monitor / Paused) with a plain-language consequence; selected card uses the ember border and `brand-soft`; one Save. This is the only enforcement control; other surfaces may display the mode but never duplicate the switch.

## Do's and Don'ts

### Do:
- **Do** use ember for primary actions, active navigation and the current selection - and keep it under ~10% of the screen.
- **Do** build structure from a 1 px `line` border plus the base/elevated/recessed tonal steps; add `shadow-sm` for rest and `shadow-lg` only for overlays.
- **Do** keep radii in the 4/6/8/12 px set; pills are the only full-radius shape.
- **Do** use mono for IPs, domains, rule expressions, logs and tabular counts; use the system sans for prose and controls.
- **Do** show published vs applied, the effective mode and the why-chain instead of implying a state.
- **Do** keep one primary control per decision; if a value is editable in two places, one of them is wrong.
- **Do** verify both themes and keyboard focus before shipping a component.

### Don't:
- **Don't** add a second enforcement switch or a bulk "mode" that competes with Protection mode.
- **Don't** use ember as a large background, gradient text or body color; it is a signal, not a surface.
- **Don't** use red/green/amber for branding or emphasis outside danger/success/warning.
- **Don't** stack a 1 px border and a wide shadow on the same resting card; choose structure or lift.
- **Don't** use colored side-borders thicker than 1 px, large consumer radii, emoji or unicode glyphs as icons, or decorative glows.
- **Don't** turn a routine settings edit into a modal; use a modal only for a protected decision (enforcement, destructive actions).
- **Don't** simplify by deleting a feature; group it, rename it, or demote it to Advanced.
- **Don't** fabricate benchmarks, customers, certifications or "all clear" states; show the real limit.
