# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Scope

This record covers the VarmanWAF platform and its operator console. The public
website shares the same product truth but owns its own surface strategy. The
console is a React/Vite/TypeScript app; the control plane and engine are
written in Rust. The platform truth lives in the repository's `docs/` and
release notes.

## Users

**Primary: security and platform operators.** In-house SRE, platform and
security engineers running public websites, APIs and internal systems on
infrastructure they control. They deploy the control plane and edge agents,
protect sites, investigate individual requests, and keep a fleet in sync.

Administrators own global settings (identity, TLS for the management listener,
log retention, AI providers, API protection); operators work inside a site.
Read-only accounts may review configuration and evidence without changing it.

## Product Purpose

VarmanWAF is a self-hosted, distributed Web Application Firewall. A central
control plane compiles versioned configuration; lightweight Pingora edge
agents serve traffic from their local last-good bundle; a native Rust engine
inspects and decides. Success means every protected site serves traffic with
the intended enforcement, every change is traceable and reversible, and every
verdict can be explained from the console.

## Positioning

A distributed WAF whose **control plane is never in the request path** and
whose **native Rust engine runs managed rules and OWASP CRS 4.30.0 without
ModSecurity** - combined with **honest, verifiable operations**: published
versus applied state is visible, each security event resolves to its rule,
score, policy and exclusion, and releases are verified by a full live E2E
sweep rather than marketing claims.

## Operating Context

- Deployment is self-hosted: Docker Compose all-in-one, or a control plane plus
  one agent per edge, with PostgreSQL as the authoritative store. Agents are
  pinned with mTLS and keep their bundle, blocked IPs and config hash on disk.
- Daily work happens in the site workspace: origin, protection, rate limits,
  bot posture, access rules, API assets, caching, TLS, traffic, topology,
  logs, rewrites and settings.
- Operators read security events and the *why* resolver, export reports,
  review config history, and manage certificates and the agent fleet.
- Releases follow a fixed ritual: build, unit tests, a live E2E sweep, a
  published image digest, a tag, and release notes that record the evidence.
- Documentation is published in English and Khmer; the website is generated
  from the repository docs.

## Capabilities and Constraints

- Detection: 14 built-in managed rules, custom expression rules, native
  SecLang, OWASP CRS 4.30.0, API schema checks, CRS rule tuning and exclusions.
- Enforcement: one per-site **Protection mode** (Block / Monitor / Paused).
  Rules decide what is suspicious; the mode decides what the edge does. A
  rule's own mode is an explicit per-rule override, never a hidden substitute
  for the site mode. A site following a shared policy has its mode controlled
  by that policy.
- Access and abuse: IP rules and groups, ipverse geo/ASN, rate limiting, bot
  posture and challenges, under-attack mode.
- Fleet and delivery: agents, versioned bundles, config history with rollback,
  revisioned shared policies, editable routing topology.
- Observability: security/access logs with a why-chain, analytics, alerts,
  reports on demand or scheduled, auto-block ledger.
- Technical constraints: Apache-2.0, self-hosted, PostgreSQL, Linux edge
  agents, no vendor lock-in. The control plane serves the console and API on
  :9080; edges carry the traffic.
- Honest limits are product content: unsynced geo keys, uncompilable CRS
  rules, unapplied settings and monitor-only families are shown as such.
- Every feature must stay reachable when the interface is simplified; group,
  rename and demote, never silently delete an operator capability.

## Brand Commitments

- The name **VarmanWAF** and the Khmer identity (the `វ` mark) are fixed.
- Voice: direct, operational, honest about limits. Controls name the action;
  errors name the problem and the recovery.
- No invented customers, certifications, benchmarks or success stories.
  Measurements come from the published benchmark and release evidence.

## Evidence on Hand

- Full documentation set in `docs/` (quick start, user guide, features,
  security engine, architecture, HA, sizing, API, developer guide).
- Release notes for every version with sweep counts and image digests.
- Benchmark and sizing reports; the 45-script E2E sweep definition and logs.
- The Khmer user guide with screenshots under `docs/user-guide-km/`.
- No customer testimonials, case studies, third-party certifications or
  independent audits are on hand; future work must not fabricate them.

## Product Principles

1. **Enforcement is one explicit gate.** Detection never silently overrides
   the site's Protection mode; make the consequence of each mode plain.
2. **Show what is applied, not what is claimed.** Published, resolved and
   applied state stay distinguishable, and every verdict explains itself.
3. **The edge owns traffic; the control plane owns change.** Losing the
   control plane may stop changes, never traffic.
4. **Simplify by hierarchy, not by amputation.** Group, rename and demote;
   keep every feature reachable.
5. **Evidence over assertion.** Real measurements, real sweep results, honest
   limits - no invented credibility.

## Accessibility & Inclusion

The console targets keyboard operation, visible focus, semantic controls and
the WCAG 2.1 AA contrast baseline. A formal accessibility audit is not yet on
hand; that gap is recorded rather than claimed as complete. Documentation is
maintained in English and Khmer.
