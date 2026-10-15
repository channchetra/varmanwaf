# Navigation information architecture (v0.48.0)

Why this round exists: the sidebar grew to 20 flat items with global and
site-scoped entries interleaved, and two surfaces owned the same feature
(alerts delivery). This is the item-by-item study behind the consolidated
navigation.

## Inventory and decisions

| # | Item (before) | Scope | What it is | Finding | Decision |
|---|---|---|---|---|---|
| 1 | Dashboard | global | Overview stats + report summary | none | keep (leaf) |
| 2 | Sites | global | Site list; the site page owns a 13-tab bar | the sidebar's site entries duplicate that tab bar | keep (leaf) |
| 3 | Policies | global | Policy layers, versions, rollback | CRS rulesets are an input to policy layers | grouped under **Protection** |
| 4 | CRS rules | global | Imported CRS ruleset catalogue | belongs with Policies | grouped under **Protection** |
| 5 | Alerts | global | Alert rules, silences, channels, history | **duplicate**: channels/settings/history also lived on Notifications | **merged** into `/alerts` (Alerts & notifications) |
| 6 | Security (group) | site | Web Protection, Rate limiting, Bot, Access control | site-scoped; interleaved with global items | contextual **This site** group (only inside a site) |
| 7 | Origin | site | Upstreams and pools | site-scoped | contextual **This site** |
| 8 | Caching | site | Cache rules | site-scoped | contextual **This site** |
| 9 | IP Groups | global | Reusable IP lists (manual + subscriptions) | adjacent to Blocked IPs | **Protection**, renamed **IP lists** |
| 10 | IP Blacklist | global | Dynamic blocks (auto + manual) | adjacent to IP lists | **Protection**, renamed **Blocked IPs** |
| 11 | Notifications | global | Thresholds, login security, history | **duplicate** of Alerts | **merged**; `/notifications` redirects to `/alerts` |
| 12 | SSL/TLS | global | Fleet certificate overview | the site has its own SSL tab | **Fleet** |
| 13 | Traffic | global | Fleet traffic analytics | the site has its own traffic tab | **Traffic & logs** |
| 14 | Logs | global | Security events + access logs with the why-chain | none | **Traffic & logs** |
| 15 | AI Assistant | global | Assistant chat | a tool, not a surface | **Tools** |
| 16 | Agents | global | Fleet agents | fleet ops | **Fleet** |
| 17 | Request lifecycle | global | Pipeline documentation page | documentation, not operations | **Tools** |
| 18 | Config history | global | Configuration versions + rollback | fleet ops | **Fleet** |
| + | Reports | global | Report system | analytics | **Traffic & logs** |
| + | Settings | global | Console and instance settings | none | keep (leaf, bottom) |

## The merges, precisely

- **Alerts & notifications** (`/alerts`): one page, six sections with a
  sticky section nav that scrolls: **Rules**, **Silences**, **Channels**,
  **Delivery** (thresholds + per-event toggles), **Login security**,
  **History** (the paged, filterable history - it replaced the old
  "Recent notifications" list, which was the smaller duplicate).
  `/notifications` now redirects to `/alerts`, so old links keep working.
- **This site** (contextual): appears only inside a site and lists that
  site's tabs (Web protection, Rate limiting, Bot protection, Access
  control, Origin, Caching, SSL/TLS, Traffic). Outside a site the section
  is absent, so the sidebar no longer mixes scopes.

## Deliberately NOT merged (with reasons)

- **Policies vs Config history**: policy revisions/rollback are
  content-scoped (one policy), configuration versions are row-scoped
  snapshots (site or global). Different lifecycles; merging would blur
  what a rollback restores.
- **IP lists vs Blocked IPs**: static reusable lists vs dynamic
  auto/manual blocks reconciled from heartbeats. Different owners
  (operators vs the edge); only adjacency, not duplication.
- **Traffic vs Logs**: aggregates vs records - the drill-down path
  (Traffic -> Logs) is deliberate.
- **SSL/TLS global vs site tab**: fleet overview vs per-site certificate
  management.
- **Request lifecycle**: kept as the one documentation page; it moved
  under Tools rather than being deleted.

## Resulting structure

```
Dashboard
Sites
Protection        Policies · CRS rules · Alerts & notifications · IP lists · Blocked IPs
Traffic & logs    Traffic · Logs · Reports
Fleet             Agents · SSL/TLS · Config history
Tools             AI Assistant · Request lifecycle
This site*        Web protection · Rate limiting · Bot protection · Access control
                  Origin · Caching · SSL/TLS · Traffic
Settings
```
\* shown only while a site is open.

## Follow-ups (not this round)

- If Policies keeps growing, evaluate CRS-as-a-tab inside it.
- A site tab-bar audit (13 tabs is its own consolidation candidate).
- Deep-link anchors (`/alerts#delivery`) if operators ask for them.

## Site level (v0.49.0)

Studying the site page showed most of it was already consolidated in
earlier rounds: **Web Protection** is a tabbed hub (engine, rules, policy,
CC) and **Access control** covers IP rules + geo, with every legacy path
(`security/policy`, `security/waf`, `security/cc`, `security/ip-rules`,
`security/geo`) redirecting into them.

Two real findings were fixed:

- **The site Settings page (failover) was orphaned** - routed at
  `/sites/:id/settings` but linked from nowhere, so the disconnected-edge
  failover policy was invisible in the UI. It is now a tab in the site bar
  and an entry in the sidebar's "This site" group.
- **The tab bar and the sidebar's "This site" group disagreed** (rewrite
  missing from the sidebar; settings from both). They now list the same
  nine destinations.

The site tab bar is also grouped by scope with subtle separators -
`Origin | Protection · Rate limiting · Bot · Access | Caching · SSL/TLS ·
Traffic | Rewrite · Settings` - so the bar reads as sections rather than a
flat list.
