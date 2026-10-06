# PingWAF User Guide

## Getting Started

### First Login

1. Open the dashboard at `https://your-server:9080` (self-signed certificate
   until you upload a real one under Settings → Control plane HTTPS)
2. Log in with the seeded credentials:
   - Email: `admin@pingwaf.local`
   - Password: `pingwaf123`
3. **Immediately change your password**: Profile → Change Password

### Dashboard Overview

The dashboard provides:
- **Analytics**: Request trends, per-site traffic over time, top rules triggered, status codes
- **Sites**: Manage protected websites
- **Agents**: Monitor connected data-plane agents
- **Logs**: Security events and access logs
- **Settings**: Elasticsearch, API keys, global preferences

## Adding a Website

### Step 1: Create a Site

Navigate to **Sites → Add Site**:
- **Name**: Human-readable label (e.g., "Production API")
- **Domain**: The hostname to protect (e.g., `api.example.com`)
- **Plan**: `free`, `pro`, or `enterprise` (affects feature limits)

### Step 2: Configure Upstreams

Each site needs at least one origin server:

```
Sites → [your site] → Origin → Add node
```

The **Origin** tab is a site's default view. Every site starts with a `default` origin pool, and the first node you add goes into it — see [Origin Pools & Routes](#origin-pools--routes) for pools, load balancing and path-based dispatch.

| Field | Description |
|-------|-------------|
| Node name | Label for this origin (e.g., "origin-1") |
| Origin address | Origin `host:port` (e.g., `10.0.0.1:8080`) |
| Weight | 1–10000; round robin splits traffic by weight (default: 1) |
| Pool | Origin pool the node belongs to |

### Step 3: DNS Setup

Point your domain's DNS to the PingWAF server:
- **A record**: `api.example.com → YOUR_PINGWAF_IP`
- **CNAME**: If behind a load balancer

### Step 4: SSL Certificate

See [SSL Certificate Management](#ssl-certificate-management) below.

## Origin Pools & Routes

Open **Sites → [your site] → Origin** to manage origin pools, load balancing and route dispatch.

### Origin Pools

An origin pool is a set of origin nodes sharing one load-balancing algorithm and origin protocol.

| Field | Description |
|-------|-------------|
| Pool name | Label for the pool (e.g., "primary") |
| Load balancing | `Round robin` or a hash algorithm (see below) |
| SNI hostname | Non-empty enables **HTTPS to origin**; must be a bare hostname covered by the origin certificate (`$host` is not supported) |
| Verify origin certificate | Turning this off skips certificate validation (not recommended) |

Load-balancing algorithms:

| Algorithm | Spec | Behavior |
|-----------|------|----------|
| Round robin | `round_robin` | Spreads requests by node weight |
| Least connections | `least_connections` | Picks the node with the fewest in-flight requests |
| Random | `random` | Picks a node at random (weight-aware) |
| IP hash | `hash:ip` | Pins the same client IP to one node |
| URL hash | `hash:url` | Pins by request URL |
| Path hash | `hash:path` | Pins by request path |
| Header hash | `hash:header:<name>` | Pins by a request header value |
| Cookie hash | `hash:cookie:<name>` | Pins by a cookie value |
| Query hash | `hash:query:<name>` | Pins by a query-string parameter |

The site's default pool (marked **Default**) cannot be deleted, and a pool can only be deleted once no origin nodes and no routes reference it.

### Routes

Routes dispatch requests to different pools by path; unmatched traffic goes to the default pool.

| Field | Description |
|-------|-------------|
| Rule name | Label for the route (e.g., "api-to-dedicated-pool") |
| Match | `Prefix`, `Exact`, or `Regex` |
| Path | Starts with `/` (e.g., `/api`), or a regular expression (e.g., `^/static/.*`) |
| Priority weight | 1–60000; empty uses the auto weight (exact 1024 / prefix 512 / regex 256) |
| Target pool | Pool that receives matching traffic |
| Enabled | Toggle a route without deleting it |

A prefix route on `/` is rejected: it would conflict with the default-pool fallback.

## WAF Configuration

### Security Modes

Each site operates in one of three modes:

| Mode | Behavior |
|------|----------|
| **Off** | Traffic passes through without inspection |
| **Detection** | Rules evaluated, matches logged, but not blocked |
| **Prevention** | Rules evaluated, matches blocked with configured action |

Set via: `Sites → [site] → Web Protection → WAF Rules`

### Rule Groups

Rules are organized into groups that execute in order:

| Phase | Description |
|-------|-------------|
| `request` | Evaluated on incoming requests |
| `response` | Evaluated on upstream responses |
| `custom` | User-defined rule groups |

### WAF Rules

Each rule defines a condition and an action:

**Conditions** (match any):
- Request URI path (regex or prefix)
- HTTP method
- Request headers
- Query parameters
- Request body content
- IP address / CIDR range
- User-Agent string
- Country (GeoIP)

**Actions**:
- `allow` — Skip remaining rules, permit request
- `block` — Return 403 Forbidden
- `challenge` — Show CAPTCHA/JS challenge
- `rate_limit` — Apply rate limiting
- `log` — Log only, do not block
- `redirect` — Redirect to a URL

### Managed Rulesets

PingWAF includes built-in protection against:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Remote Code Execution (RCE)
- Path Traversal
- Command Injection
- Protocol violations

Enable/disable individual rules within managed groups.

### Rule Grading

```
Sites → [site] → Web Protection → Grading
```

Besides per-rule toggles, the whole detection posture of a site can be graded:

| Control | Behavior |
|---------|----------|
| **Advanced mode** | Enables the strict managed rule set plus deep request-body inspection. Higher interception rate at a proportional performance cost. |
| **Attack categories** (9) | `sqli`, `xss`, `rce`, `lfi`, `ssrf`, `deser`, `crlf`, `xxe`, `ssti` — switch a family off to downgrade its matches to monitoring: detection and logging stay fully active, but nothing is blocked. |
| **Backend stacks** (4) | `java`, `php`, `python`, `node` — same downgrade semantics for stack-specific detections. Language-agnostic detections are never downgraded by a stack switch. |

A site without explicit grading settings behaves exactly like the default posture: every detection blocks.

### Under Attack Mode

```
Sites → [site] → Web Protection (top banner)
```

A site-wide emergency switch: every visitor is challenged with a JavaScript check, and CC protection is switched on automatically. Enable it only while the site is under an active flood attack and disable it once the attack subsides.

## Rate Limiting

Configure per-site rate limits:

```
Sites → [site] → Rate Limiting → Add Rule
```

| Field | Description |
|-------|-------------|
| Name | Rule label |
| Threshold | Max requests allowed in the period |
| Period (seconds) | Time window for counting (1–86400) |
| Action | `block`, `log`, `challenge`, `js_challenge`, or `allow` |
| Characteristics | How to group traffic: `ip`, `ip_nat`, `host`, `path`, `asn`, `country`, plus parameterized forms `header:<name>`, `cookie:<name>`, `query:<name>` |
| Filter expression | Optional match condition (empty = all requests) |
| Mitigation timeout | How long the action applies once triggered (0–86400 seconds) |

Example: Limit to 100 requests per 60 seconds per IP on `/api/*`.

Requests missing the header, cookie or query parameter bucket together, so they still count against the limit. Header names match case-insensitively; cookie and query names are case-sensitive. The `ja3` characteristic is reserved for future use and is not yet accepted by the API.

## CC Protection & Challenges

### Challenge Settings

```
Sites → [site] → Web Protection → CC Protection
```

| Setting | Options |
|---------|---------|
| Mode | `off`, `passive`, `active` |
| Type | `js_challenge`, `captcha`, `managed` |
| Expiry | How long a passed challenge remains valid |

- **Passive**: Challenge only when suspicious behavior is detected
- **Active**: Challenge all requests matching configured criteria

## Cache Configuration

### Cache Rules

```
Sites → [site] → Cache Rules
```

| Field | Description |
|-------|-------------|
| Name | Rule label |
| Path pattern | URI pattern to cache (e.g., `/static/*`) |
| Edge TTL | How long to cache at the edge (seconds) |
| Browser TTL | `Cache-Control: max-age` sent to clients |
| Status | `enabled` or `disabled` |

### Cache Purging

Purge cached content immediately:

```
Cache → Purge
```

Options:
- Purge all cache for a site
- Purge by URL pattern
- Purge by cache tag

### Disk Quotas

Monitor cache disk usage:

```
Cache → Status
```

Shows per-site cache size and hit rates.

## SSL Certificate Management

### Automatic (ACME / Let's Encrypt)

```
Sites → [site] → Certificates → Add → Let's Encrypt
```

**Challenge Types:**
- **HTTP-01**: Requires port 80 reachable. Best for most setups.
- **DNS-01**: Supports wildcard certificates. Providers:
  - Cloudflare
  - Route 53
  - DigitalOcean
  - Aliyun (Alibaba Cloud)
  - DNSPod (Tencent Cloud)
  - CloudXNS
  - Manual

Certificates auto-renew 30 days before expiry.

### Manual Upload

```
Sites → [site] → Certificates → Add → Upload
```

Provide:
- Certificate (PEM format, including chain)
- Private key (PEM format)
- Domain names covered

### SSL Settings

```
Sites → [site] → SSL Settings
```

- Minimum TLS version (1.2 or 1.3)
- Force HTTPS redirect
- HSTS configuration
- OCSP stapling

### Certificate Status and Events

Agents report each site's certificate status in every heartbeat, shown on the SSL/TLS page:

- **Valid**
- **Expiring soon** — the certificate lapses within 48 hours
- **Expired**

The SSL/TLS page also keeps an event log per certificate — created, renewal requested, renewed, failed, deleted, plus raw ACME output — so issuance attempts can be followed from the console.

## Request/Response Rewriting

### Rewrite Rules

```
Sites → [site] → Rewrite Rules → Add
```

| Field | Description |
|-------|-------------|
| Type | `request` or `response` |
| Match | URL pattern (regex) |
| Replace | Replacement string |
| Headers | Add/remove/modify headers |

Examples:
- Strip `/api/v1` prefix: match `^/api/v1/(.*)` → replace `/$1`
- Add security headers: `X-Frame-Options: DENY`
- Remove `Server` header from responses

## Custom Error Pages

```
Sites → [site] → Error Pages → Add
```

| Field | Description |
|-------|-------------|
| Status code | HTTP status to customize (e.g., 403, 429, 502) |
| Content type | `html`, `json`, or `text` |
| Body | Custom response content |

## Log Management

### Viewing Logs

**Security Events**: `Logs → Security`
- Filtered by site, rule, action, time range
- Shows matched rule, client IP, request details

**Access Logs**: `Logs → Access`
- All proxied requests with timing information
- Filter by status code, path, client IP
- Request headers and a body preview (first 1 KiB) are stored in PostgreSQL, so requests can be inspected from the dashboard without Elasticsearch

### Elasticsearch Integration

For high-volume deployments, ship logs to Elasticsearch:

```
Settings → Elasticsearch
```

| Setting | Description |
|---------|-------------|
| URLs | Comma-separated ES endpoints |
| Index prefix | Prefix for daily indices |
| Username/Password | Basic auth credentials |
| API Key | Alternative to basic auth |
| Max body size | Truncation limit for logged bodies |

Enable the Elasticsearch shipper via environment:
```bash
PINGWAF_ES_ENABLED=true
PINGWAF_ES_URLS=http://elasticsearch:9200
```

### Log Retention

Purge old logs:
```
Logs → Purge (select age threshold)
```

## Agent Management

### Adding Agents

1. Generate an API key: **Settings → API Keys → Create**
2. Install the agent on the edge server:
   ```bash
   pingwaf agent --server-url http://control-plane:9090 --api-key YOUR_KEY
   ```
3. The agent appears automatically in **Agents**

### Monitoring Agents

The Agents page shows:
- Connection status (online/offline/degraded)
- Last heartbeat time
- System info (hostname, OS, CPU, memory)
- Agent version
- Pending commands

### Agent Commands

Push commands to connected agents:
- **Reload Config**: Force immediate config sync
- **Block IP**: Temporarily block an IP address
- **Unblock IP**: Remove a temporary block
- **Purge Cache**: Clear local cache
- **Restart Agent**: Graceful agent restart

## Access Control

Per-site IP rules and geo restrictions live on one page:

```
Sites → [site] → Access control
```

Switch between the **IP rules** and **Geo restrictions** tabs with `?tab=ip` / `?tab=geo`; links to the former separate IP-rules and geo pages redirect here automatically.

### IP Rules

| Field | Description |
|-------|-------------|
| Rule name | Label for the rule (e.g., "Block scraper subnet") |
| Target | A manual **IP / CIDR** list, or an **IP group reference** whose ranges always follow the group's latest contents |
| IP/CIDR | Address or range (e.g., `192.168.1.0/24`) — manual mode only |
| Action | `block`, `allow`, `challenge`, or `js_challenge` |
| Note | Why this rule exists (audit) |
| Priority | Lower values are matched first |

IP rules are evaluated before the WAF. Bulk import accepts one IP or CIDR per line.

### Geo Restrictions

Block or allow traffic by country and ASN:

- **Mode**: `block_list` (block specific countries) or `allow_list` (allow only specific countries)
- **Countries**: ISO 3166-1 alpha-2 codes (e.g., US, CN, DE)
- **Blocked ASNs**: deny entire autonomous systems (e.g., `AS13335`)
- **Block unknown locations**: deny traffic whose location cannot be determined
- **Action**: how matched traffic is handled

A "Requests by country" chart (last 24 hours) sits next to the policy editor.

### Global IP Groups

**IP Groups** (in the sidebar) manages named collections of IP ranges, either **global** (applied to all sites) or **per-site** (assigned to selected sites). Each group has an action: `block` or `allow`.

Groups can subscribe to an external list instead of (or in addition to) manually entered ranges:

| Field | Description |
|-------|-------------|
| Subscription Source URL | URL of the list to fetch (e.g., `https://example.com/ip-list.txt`) |
| Refresh interval | Manual only, hourly, every 6 hours, daily, or weekly |

A background scheduler refreshes enabled subscriptions when their interval elapses; use **Sync now** to refresh immediately. A failed sync keeps the previous ranges and records the error, which is shown on the group's row as the last sync error.

One group, **Cloudflare**, is seeded on first boot: the official Cloudflare IP ranges from `https://api.cloudflare.com/client/v4/ips`, refreshed daily. It starts disabled — enable it once you know how it fits your traffic.

Site IP rules can reference a group instead of enumerating ranges; see [IP Rules](#ip-rules) above.

## Bot Protection

```
Sites → [site] → Bot Protection
```

| Setting | Description |
|---------|-------------|
| Enable bot protection | Turn classification on or off |
| User-Agent analysis | Inspect the User-Agent header to classify traffic |
| Bot action | `block`, `challenge`, or `log` — applied to traffic classified as a bot (non-browser user agents) |
| Known bots | Whitelist of good crawlers that always pass |

How a request is classified:

1. Verified bots whose User-Agent matches a **known bots** entry pass.
2. Real browsers (known browser user agents) pass.
3. Everything else receives the configured **bot action**.

Known-bot entries are case-insensitive substrings matched against the User-Agent header (e.g., `Googlebot`); the console offers quick-add suggestions for common crawlers.

JavaScript detection, TLS fingerprinting and behavioral analysis appear in the console as *Coming soon* — they are roadmap items, not implemented yet.

## AI Assistant

```
Settings → AI assistant · sidebar assistant icon
```

The console embeds an AI assistant that answers questions about your deployment by calling the same MCP tools external clients use (see below). Configure an OpenAI-compatible provider under **Settings → AI assistant**:

| Setting | Description |
|---------|-------------|
| Enable assistant | Master switch; the AI Assistant page prompts for setup while it is off |
| Base URL | OpenAI-compatible endpoint, e.g. `https://api.openai.com/v1` |
| Model | Model name, e.g. `gpt-4o-mini` |
| API key | Provider credential, stored server-side and shown masked afterwards |
| Temperature | 0–2; lower answers change less between runs |
| Max tool rounds | How many tool-call rounds one answer may take (1–10) |
| System prompt | Prefilled with the built-in default; clear and save to reuse it |
| Allow write tools | Off by default; enables the tools that change state (observation mode, site enable/disable) |

**Test draft** verifies the provider without saving. Once enabled, ask a question on the AI Assistant page and watch tool calls appear inline as the answer streams. Conversations are stored server-side, so history survives reloads, and the assistant is administrator-only.

## MCP Server

```
Settings → MCP server
```

Every deployment hosts an MCP (Model Context Protocol) endpoint at `/mcp` on the console origin, so external AI agents — Claude Code, IDE copilots, scripts — can inspect and operate the firewall. The Settings card shows the live endpoint, the tool inventory (write tools tagged), and copy-paste client snippets.

To connect a client you need an API key (**Settings → API keys**) with the `read` permission; add `write`, whose owner must be an administrator, for the two tools that change state. Then paste the card's JSON into the client, or for Claude Code run:

```bash
claude mcp add --transport http pingwaf https://waf.example.com:9080/mcp \
  --header "Authorization: Bearer pwk_YOUR_KEY"
```

Read-only credentials see only the read tools; administrators with a `write` key may also call `set_observation_mode` and `set_site_status`. The endpoint sits behind the same API protection as the console (access log, IP allowlist, WAF), so it obeys whatever **Settings → API protection** allows.

## Internationalization (i18n)

The dashboard supports multiple languages:
- English (default)
- 中文 (Chinese)
- 日本語 (Japanese)

Language is auto-detected from the browser. Override via the language selector in the dashboard header.
