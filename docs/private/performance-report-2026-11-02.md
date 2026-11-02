# Production performance report — 2026-11-02

> **Internal document.** Generated from the production analytics API at
> `2026-11-02T06:40Z` for the preceding 24 hours (19 sites, 1 embedded agent).
> The public website does not include `docs/private/`.

## Executive summary

- **37,399 requests** in 24h, **667 MB** egress, **2,904 unique IPs**.
- The dashboard's **899 ms average latency is not the normal request
  latency**. It is dominated by long-lived streaming and WebSocket
  connections that stay open for 30–47 seconds.
- **6,691 “errors” = 5,828 4xx + 863 5xx.** The dashboard adds both classes
  into one card. Most 4xx are expected WAF blocks (403), auth challenges
  (401) and scanner 404s; the 5xx count is the real health signal.
- **86% of all 5xx (747 of 863) came from `calendar.unity-workspace.com`.**
  Its origin `10.1.18.200:80` is returning 503; this is the single biggest
  availability problem.
- **10,833 security events**, **1,479 blocked**, **917 distinct attackers**,
  **34 rules triggered**. Bot protection is the dominant source (8,437
  monitor-only events) and is not blocking.
- Cache hit rate is **0%** because no site has active cache rules. For these
  dynamic apps that is expected, but it means every byte is origin work.

## Latency: where the 899 ms comes from

`avg_latency_ms` is `AVG(total_latency_ms)` over every access log row,
including WebSocket upgrades and streaming responses.

| Slow path | Requests | Avg latency |
| --- | ---: | ---: |
| `/user-service/api/v1/quotas/stream` | 169 | 47,504 ms |
| `/api/stream/events` | 80 | 46,459 ms |
| `/api/jmap/events` | 117 | 45,372 ms |
| `/api/storage/quota-stream` | 181 | 32,852 ms |
| `/api/documents` | 172 | 1,180 ms |
| `/graph/v1.0/me/drives` | 219 | 330 ms |
| `/api/stream/logs/16/1/1167` | 760 | 230 ms |
| `/api/auth/refresh` | 1,549 | 152 ms |
| `/api/fonts.json` | 1,581 | 46 ms |
| `/api/storage/quota` | 3,258 | 51 ms |
| `/realms/.../openid-connect/auth` | 1,660 | 95 ms |

The four long-stream paths alone account for about **23.0 million ms** of the
observed **33.6 million ms** total. Excluding only those four paths leaves an
approximate average of **~290 ms** over the remaining 36,852 requests. Ordinary
pages and APIs in the top-path list run at **4–230 ms**.

Per-site 24h averages (sorted high to low):

| Site | Requests | Avg ms | Max ms | 4xx | 5xx |
| --- | ---: | ---: | ---: | ---: | ---: |
| argocd | 559 | 5,241 | 49,961 | 24 | 1 |
| gateway | 2,211 | 3,952 | 49,983 | 236 | 2 |
| woodpecker | 2,285 | 2,118 | 49,990 | 167 | 25 |
| webmail | 7,188 | 1,621 | 50,019 | 86 | 3 |
| account | 212 | 576 | 47,972 | 14 | 7 |
| asset | 127 | 480 | 49,142 | 8 | 0 |
| uoffice | 274 | 353 | 47,899 | 223 | 0 |
| drive | 5,737 | 310 | 49,951 | 299 | 28 |
| mail-bridge | 1,962 | 296 | 47,247 | 1,430 | 2 |
| admin-mail | 2,376 | 132 | 47,510 | 889 | 40 |
| office | 5,514 | 121 | 30,006 | 149 | 4 |
| auth | 3,925 | 51 | 893 | 566 | 3 |
| varman | 15 | 22 | 64 | 0 | 0 |
| kafka-ui | 401 | 14 | 431 | 357 | 1 |
| mail | 1,735 | 12 | 140 | 570 | 0 |
| meet | 784 | 7 | 70 | 607 | 1 |
| calendar | 839 | 4 | 243 | 71 | 747 |

The very high per-site averages on `argocd`, `gateway`, `woodpecker` and
`webmail` line up with long-lived streaming/WebSocket traffic, not with slow
HTML pages.

## Errors: 6,691 is two different things

| Status class | Count | Meaning |
| --- | ---: | --- |
| 4xx | 5,828 | Client/request outcomes |
| 5xx | 863 | Server/origin failures |

4xx detail:

| Status | Count | Likely meaning |
| --- | ---: | --- |
| 403 | 3,420 | WAF blocks (top attacker `93.123.109.247`: 1,272 requests, all blocked) |
| 401 | 920 | Auth challenges / unauthenticated API calls |
| 404 | 831 | Missing paths, mostly scanners and stale links |
| 400 | 642 | Malformed requests |
| 429/431/405 | 15 | Rate limit, header size, method |

5xx detail:

| Site | 5xx | Share of all 5xx |
| --- | ---: | ---: |
| calendar | 747 | 86.6% |
| admin-mail | 40 | 4.6% |
| drive | 28 | 3.2% |
| woodpecker | 25 | 2.9% |
| account | 7 | 0.8% |
| office | 4 | 0.5% |
| auth / webmail | 3 each | 0.7% |
| gateway / mail-bridge | 2 each | 0.5% |
| meet / kafka-ui / monitoring-mail | 1 each | 0.3% |

`calendar` receives 839 requests and returns 747 5xx — about **89% of its
traffic**. The access log shows these are forwarded to
`10.1.18.200:80`, so this is an origin problem, not the WAF. Fixing it removes
most of the production 5xx.

The 7-day window contains 5,162 5xx and the 30-day window 5,234, while the
last 24h contains 863. Most of the month's 5xx happened earlier in the week;
after fixing calendar, review the 7-day trend for the earlier spike.

## Security activity

| Rule | Action | Hits | Unique IPs |
| --- | --- | ---: | ---: |
| Bot protection | monitor | 8,437 | 662 |
| `sem.cmd.command_context` | block | 1,379 | 118 |
| `VARMAN-1020` | monitor | 238 | 29 |
| `VARMAN-1001` | monitor | 169 | 53 |
| Dotfile reconnaissance | monitor | 130 + 130 + 14 | 16 |
| `SSRF-006` | monitor | 126 | 93 |
| `VARMAN-1020` | block | 64 | 63 |
| Backup file reconnaissance | monitor | 26 + 7 | 7 |
| `virtual-patch:930100` / `932370…` | block | 9 each | 9 each |

- The dominant event source is **Bot protection in monitor mode**. It records
  traffic but does not challenge or block. If bot traffic should be reduced,
  switch that posture to challenge or block after reviewing the 662 IPs.
- The top attacker (`93.123.109.247`, NL) sent 1,272 requests and every one
  was blocked. That is the expected behavior.
- 30-day totals: 21,753 events, 3,732 blocked, 2,573 distinct attackers,
  84 rules.

## Cache, agents and traffic

- **Cache hit rate: 0.0%** (`0` hits). No cache rules are active. These are
  mostly authenticated/dynamic applications (mail, drive, Keycloak, Argocd),
  so this is not automatically a defect. Static assets could still benefit
  from a cache rule if they are served through the WAF.
- **1/1 agents online**, no failover event in the window.
- **667 MB egress** over 37.4K requests ≈ 18.7 KB/request.
- Top client IPs include Cloudflare edge addresses (`172.70.x`, `162.158.x`,
  `104.22.x`) alongside real client IPs. The sites do trust
  `cf-connecting-ip` with Cloudflare ranges, but some rows still carry edge
  IPs. Check the forwarded-header configuration on the sites that show edge
  IPs; otherwise “unique IPs/attackers” is understated and rate limiting can
  bucket unrelated clients together.

## What the dashboard cards mean

| Card | Definition |
| --- | --- |
| Requests | `COUNT(*)` in `access_logs` for the window |
| Egress | `SUM(response_size)` |
| Blocked | Security events with a blocking/challenge action |
| Security events | Rows in `security_events` |
| Active agents | Online agents / total agents |
| Cache hit rate | Cache hits divided by cache-participating requests |
| Avg latency | `AVG(total_latency_ms)`, **including streaming/WSS lifetime** |
| Errors | `client_errors + server_errors` = **4xx + 5xx** |
| Unique IPs | `COUNT(DISTINCT client_ip)` |
| Attackers | Distinct client IPs in security events |

The dashboard values in the screenshot (36.6K / 874 ms / 6.6K) are an earlier
24h window than the API pull above (37,399 / 899 ms / 6,691); the definitions
match.

## Recommendations, in priority order

1. **Fix `calendar`'s origin** (`10.1.18.200:80`): it is 89% 5xx and accounts
   for 86.6% of all production 5xx.
2. **Split the dashboard error card into 4xx and 5xx.** A single “Errors”
   number makes normal WAF blocks and auth challenges look like outages.
3. **Exclude long-lived streams/WebSockets from the headline latency**, or
   show p50/p95 for non-streaming paths. The current average is dominated by
   connections that are supposed to stay open for tens of seconds.
4. **Review bot protection.** 8,437 monitor-only events from 662 IPs are the
   largest security signal; move to challenge/block if that traffic is
   unwanted.
5. **Investigate the remaining 5xx sites** (`admin-mail`, `drive`,
   `woodpecker`) after calendar is fixed.
6. **Enable caching for static assets** if applicable; 0% is expected for
   authenticated apps but leaves easy egress savings on the table.
7. **Verify Cloudflare client-IP logging** on the sites where the top-IP
   report shows edge addresses; it affects rate limiting, IP rules and
   attacker counts.
