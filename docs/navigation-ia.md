# Navigation information architecture (v0.48.0)

Why this round exists: the sidebar grew to 20 flat items with global and
site-scoped entries interleaved, and two surfaces owned the same feature
(alerts delivery). This is the item-by-item study behind the consolidated
navigation.

## Inventory and decisions

| # | Item (before) | Scope | What it is | Finding | Decision |
|---|---|---|---|---|---|
| 1 | Dashboard | global | Overview stats + report summary | none | keep (leaf) |
| 2 | Sites | global | Site list; the site page owns a 14-tab bar | the sidebar's site entries duplicate that tab bar | keep (leaf) |
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
  site's tabs (Protection, Rate limiting, Bot protection, Access control,
  Origin, Caching, SSL/TLS, Traffic). Outside a site the section
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
This site*        Overview · Protection · Rate limiting · Bot protection · Access control
                  Origin · API assets · Caching · SSL/TLS · Traffic · Topology · Logs
                  Rewrite · Settings
Settings
```
\* shown only while a site is open.

## Site overview tab (v1.1.7)

Opening a site now lands on **Overview** (`/sites/:id/overview`), the site's
own dashboard: 24-hour requests / blocked / security events / unique IPs, the
protection posture in force (mode, paranoia, advanced mode, engine mode), the
active certificate, the origin health, and the latest security findings with a
link into Logs. The legacy default (`origin`) still resolves, so old links and
bookmarks keep working.

The site list opens the overview from the row and from the domain. Its action
button visits the live site in a new tab.

## One protection mode (v1.1.8)

The site-level enforcement mode now has exactly one control: the **Protection
mode** button in the site header, present on every site tab.

- **Block / Monitor / Paused** writes both the site status and the WAF mode.
  Paused replaces the old separate pause button; Block/Monitor resume a paused
  site. The old quick pause on the sites list was removed for the same reason.
- **The site domain is a link to the live site** (new tab), with an external
  icon. The site list's action button also visits the live site; the row and
  the domain in the list open the site workspace.
- **Protection tabs** are now **Overview · Rules · Flood protection ·
  Advanced**. "Policy tuning" is renamed Advanced; "CC Protection" is
  Flood protection.
- **Rules** no longer offers a bulk "apply mode to every rule" card. The site
  mode is the gate; a rule's **Rule mode** is an explicit override for that
  rule only.
- **Protection → Advanced** keeps paranoia, advanced mode, monitor-only
  categories, exclusions, shared policy and history. A site that follows a
  shared policy shows "Managed by policy" in the mode dialog and routes the
  change to Advanced instead of pretending a local write would apply.

The Protection page's Overview now starts with the operational modules, then
the request path, then the optional shared policy, so policies are no longer
the first thing an operator sees.

## Protection section (v0.50.0)

Applying the study's remaining conclusions:

- **CRS rulesets folded under Policies**: the two pages now share a
  **Policies | CRS rulesets** section tab strip (route-based, so both
  `/policies` and `/crs` keep working for deep links), and the CRS entry
  left the sidebar - one fewer menu item, the same reachability. The
  "rules umbrella" question resolved itself: the policy editor already
  carries a layer tab strip that includes the **crs**, **custom rules**
  and **rule overrides** layers, so the rule surfaces are already grouped
  where they are edited.
- **`/alerts` is deep-linkable**: the section pills update the URL hash
  (`/alerts#delivery`), an incoming hash scrolls to its section on load,
  and a scroll-spy lights the pill of the section in view.

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
