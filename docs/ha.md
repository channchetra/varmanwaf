# High Availability & Scaling

How to run VarmanWAF so that no single failure stops traffic, how to add
nodes, how to point domains at the fleet, and what the platform does (and
does not) promise during a failure.

> **The core property**: the control plane is **never in the request path**.
> Every edge node serves traffic from its own persisted bundle, so control
> plane maintenance, database failover or network partitions do not stop the
> sites - they stop *changes* from propagating until the connection returns.

## 1. Topologies

### 1.1 Single all-in-one (no HA)

One container: control plane, edge, PostgreSQL. Fine for labs and small
internal deployments. Failure of the host stops traffic.

### 1.2 Control plane + N edge nodes (the standard production shape)

```text
                  DNS / LB / anycast
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
   Edge node A       Edge node B       Edge node C
   (agent+proxy)     (agent+proxy)     (agent+proxy)
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │ gRPC :9090 (heartbeat, config sync, logs)
                          ▼
                 Control plane (:9080/:9090) + PostgreSQL
```

- Traffic HA is provided by having **two or more edge nodes** behind DNS
  round-robin, a TCP/HTTP load balancer, or anycast.
- Each edge holds the full configuration for the sites it is bound to; losing
  one node removes its share of capacity but not correctness.
- The control plane is a *control* dependency only: agents keep serving with
  their last-good bundle and reconnect with backoff.

### 1.3 Control-plane standby

The control plane is a single writer against PostgreSQL. For a hot standby:

1. Run a second control-plane instance against a **replica** or a shared
   primary (it serves the console/API; the DB is the authority).
2. Keep the primary as the write target; promote the standby by pointing it at
   the promoted database.
3. Agents reconnect to whichever endpoint the DNS name resolves to; they
   re-sync from `config_hash` and keep serving meanwhile.

This is documented as an operational pattern, not an automatic cluster: the
platform intentionally keeps the control plane small and replaceable rather
than running a consensus protocol nobody asked for.

### 1.4 PostgreSQL HA

PostgreSQL is the only stateful component. Any standard approach works:

- Managed PostgreSQL (RDS/Cloud SQL/…): automatic failover + PITR.
- Self-managed streaming replication with a VIP or a proxy in front.
- The minimum: **automated backups + tested restore** (see
  [`deployment.md`](./deployment.md) §Backup & Recovery).

RPO/RTO guidance: with streaming replication, RPO ≈ seconds and RTO ≈
promotion time. Without it, RPO = your last backup. Edge nodes keep serving
regardless; only configuration changes are blocked.

## 2. Adding an edge node

1. Install the agent on the new host (Docker image or binary + systemd).
2. Point it at the control plane (`VARMAN_SERVER_URL` / config file) with its
   API key; if registration is closed, pre-register the node in **Agents**.
3. The node registers, receives the bundles for its bound sites, and starts
   serving. Verify: **Agents** shows it online with a fresh heartbeat and the
   site's config hash.
4. Add it to your DNS/LB pool. Drain it by removing it from the pool first
   when taking it out.

### Node synchronization (what actually syncs)

| Item | Mechanism | Latency |
| --- | --- | --- |
| Site bundles (rules, policies, posture, exclusions) | gRPC `SyncRules` / `GetSiteConfig`, keyed by `config_hash` | push, seconds |
| Blocked IPs & auto-blocks | agent ledger + control-plane push | seconds |
| Certificates | certificate events + SNI store sync | seconds |
| Heartbeats (health, metrics, cache/cert state) | bidi heartbeat stream | 10s interval |
| Logs / security events / metrics | batched shipping | 10-30s ingest lag |
| Commands (unblock, challenge config, purge) | heartbeat stream commands | seconds |

A node that misses a push catches up on reconnect: it compares its
`config_hash`, requests the diff, and applies it hot - no restart.

## 3. Pointing a domain at the fleet

1. **Create the site** (Sites → Add site) with the domain (and any
   `alternate_domains`). The edge resolves requests by the `Host` header, so
   the domains must be configured before traffic arrives.
2. **DNS**: point the domain's `A`/`AAAA` records at your edge node IPs (one
   record per node for round-robin, or at your load balancer/anycast
   address). Use a low TTL (60-300s) while migrating.
3. **TLS**: issue certificates per site (ACME HTTP-01/DNS-01 or manual
   upload). For DNS-01 with many domains, use a wildcard certificate; the
   HTTP-01 challenge needs port 80 reachable on the node that answers.
4. **Verify**: `curl -H "Host: your.domain" http://<edge-ip>/` answers from
   the origin, and the site's Logs show the request.
5. **Redirect HTTP→HTTPS** if you want it (Rewrite rules or a route).

Common patterns:

- **One domain, many nodes**: DNS round-robin with health-checked LB, or
  anycast for global traffic.
- **Wildcard sites**: add `*.example.com` as an alternate domain and use a
  wildcard certificate.
- **Migrating from an existing proxy**: lower the TTL, add the site and
  certificate first, then switch the records; keep the old proxy's
  configuration until the edge answers correctly for every domain.

## 4. Failure semantics (what HA does and does not promise)

| Failure | Traffic | Changes |
| --- | --- | --- |
| One edge node down | Removed from the pool; capacity drops | unaffected |
| Control plane down | Served from last-good bundles | queued (nothing is lost in the DB) |
| PostgreSQL down | Traffic unaffected | console/API reads fail; writes blocked |
| Config push fails | Node keeps last-good bundle | retried on reconnect |
| Certificate expiry | Node keeps serving; clients warn | renew via ACME or upload |
| Origin pool down | Failover policy (secondary pool / static response) | unaffected |
| Auto-block storm | Refusal lane absorbs it | unblock via API/console |

## 5. Runbook highlights

- **Rolling upgrade**: upgrade one edge node at a time (remove from pool →
  upgrade → verify → return). The control plane can be upgraded while edges
  serve; agents reconnect automatically.
- **Certificate rotation**: ACME renews automatically; verify with the
  global SSL page (expiry warnings).
- **Database failover**: promote the replica, repoint the control plane,
  restart it; edges never stop.
- **Restore**: restore the database, start the control plane, then let agents
  re-sync (`config_hash` catches them up).
- **Disaster drill**: stop the control plane for 30 minutes and confirm the
  sites keep serving; then stop one edge node and confirm the pool absorbs
  it. Both are expected to be non-events.

## 6. Capacity per node

See [`sizing.md`](./sizing.md) for measured throughput and sizing tables.
Rule of thumb: ~1,000-1,500 req/s per allocated vCPU for pass-through
traffic on a tuned host; blocked traffic is cheaper; memory is dominated by
peak concurrent connections.
