# For site owners

> **Who this is for:** the person who owns a website or API and needs to keep it
> online and protected without running the platform itself. You usually have a
> `viewer` account, or an administrator account scoped to your own sites.

You do not need shell access, a database, or a deep WAF background. The console
gives you one workspace per site: what it serves, what is enforced, what is
happening right now, and the few switches that change the outcome.

## What you can do

- Read the dashboard and your site's 24-hour story.
- Change the site's protection mode and explain a block.
- Add or reorder origin servers and routes.
- Turn on caching, review certificates, and inspect traffic and logs.
- Open the topology to see the real request path.
- Ask the assistant to explain an event or a setting.

Global users, policies, agents, backups, and TLS for the control plane belong
to the [administrator](./administrator.md) or
[system administrator](./system-administrator.md).

## Your first 30 minutes

### Step 1 — Sign in

Open the console over HTTPS. If this is the first boot, the seeded account is
`admin@varman.local` / `varman123`; change the password immediately if you own
the instance. A viewer account should be created by your administrator instead
of sharing the seeded one.

![Sign in to the console](images/console/login.webp)

### Step 2 — Read the dashboard before changing anything

The dashboard is the fleet's front page: request volume, blocked requests,
top rules, site health, and recent security events. Use it to answer "is this
normal?" before you touch a setting.

![Dashboard with traffic, security events and site health](images/console/dashboard.webp)

### Step 3 — Open your site

**Sites** lists every site you can see. The row shows the domain, status,
request count, blocked count, and when it was added. Open the site name to
enter its workspace; use the external-link action to visit the live site.

![Sites list with status and request counters](images/console/sites.webp)

### Step 4 — Understand the site at a glance

The **Overview** tab answers what the site serves and what is enforced:
requests and blocks for the last 24 hours, the protection mode and paranoia
level in force, the serving certificate, origin health, and the latest
findings. Every card links to the tab that owns the setting.

![Site overview with protection, origin and certificate cards](images/console/site-overview.webp)

### Step 5 — Check the protection mode

The site header carries one **Protection mode** control: **Block**, **Monitor**,
or **Paused**. This is the single enforcement gate. A rule's own mode is only an
override for that rule; it never overrides the site.

- **Block** — malicious requests are stopped.
- **Monitor** — everything is evaluated and logged, nothing is blocked.
- **Paused** — the site is effectively offline at the edge.

![Protection surface with mode, rules and recent decisions](images/console/protection.webp)

If a site is managed by a shared policy, the mode is owned by that policy and
the control routes you to the policy instead of editing it in place.

### Step 6 — Point the site at a real origin

**Origin** holds the pools and their nodes. Every site starts with a `default`
pool; add the first node there. Give the pool more than one node when you want
round-robin or weighted balancing, and use **Routes** for path or host
dispatch. Test the origin from the edge before you debug the WAF.

![Origin pools, nodes and route dispatch](images/console/origin.webp)

### Step 7 — Make it fast and give it a certificate

**Caching** is where you add cache rules and see hit ratios. Cache only content
that is safe to share; the rule builder exposes the methods, paths, query
handling, TTL, and purge controls.

![Cache rules and hit ratio](images/console/caching.webp)

**SSL/TLS** shows the certificate in force, its expiry, the ACME state, and the
events behind a failed issuance. Upload a certificate manually or let ACME
issue and renew one.

![Site certificate, expiry and ACME events](images/console/ssl.webp)

### Step 8 — Watch real traffic

**Traffic** plots requests, status codes, cache hit ratio, and top paths for the
selected window. Use it with **Logs** when a user reports a specific request:
the request ID is the join key between the two surfaces.

![Traffic analytics with requests, status and cache](images/console/traffic.webp)

![Security logs with request IDs and decisions](images/console/logs.webp)

### Step 9 — Open the topology when the path is unclear

The **Topology** canvas shows the real request path: Internet → Site →
Protection → Security layers → Routing → Origin pools. Click a node to open its
editor beside the graph. The fleet view shows control plane → agent → site.

![Site topology with the docked editor](images/console/topology-docked.webp)

### Step 10 — Ask the assistant when you are stuck

The AI assistant can explain a blocked request, summarize a rule, or walk you
to the setting that owns a behavior. It is administrator-only on self-hosted
instances, so ask your administrator if the assistant is not in your sidebar.
Never paste production secrets into a conversation.

![AI assistant explaining a request decision](images/console/assistant.webp)

## Common tasks

| I want to… | Go to |
|---|---|
| Prove a request was blocked and why | **Logs** → the event → *Why was this blocked?* |
| Let a new API path through | **Protection → Custom rules**, or **Routes** for dispatch |
| Stop a credential-stuffing burst | **Protection → Rate limiting** |
| Block a country or an ASN | **Protection → Access control** |
| Put the site in observation mode | Site header → **Protection mode → Monitor** |
| Add a second origin | **Origin → Add node**, same pool |
| Serve an uploaded certificate | **SSL/TLS → Upload certificate** |
| See what changed after an incident | **Config history** (administrator) |
| Hand a problem to the platform team | Copy the request ID and open **Logs** |

## When to escalate

- **Every request is blocked, including health checks** → check the site's
  protection mode and the edge agent status; escalate to the system
  administrator.
- **Certificate issuance fails** → open **SSL/TLS → Events**; ACME needs a
  public DNS name and reachable HTTP-01/DNS-01 path. If the CDN reports 525 or
  the certificate says **Unknown issuer**, use the
  [TLS troubleshooting guide](../tls-troubleshooting.md).
- **The origin is healthy but the edge returns 502** → check the origin address
  from the agent's network, not just from your laptop.
- **A rule fires but you cannot edit it** → it may be managed by a shared
  policy; an administrator owns the policy version.

## Related

- [Console walkthrough](../user-guide.md) — every surface, end to end.
- [Feature inventory](../features.md) — the complete list of capabilities.
- [For administrators](./administrator.md) — users, policies, alerts, reports.
- [For system administrators](./system-administrator.md) — deployment, agents, HA.
