# For system administrators

> **Who this is for:** the person who owns the hosts, PostgreSQL, the edge
> fleet, the certificates, and the upgrade window. You decide the topology and
> you are on the hook when an agent goes dark.

VarmanWAF is designed around one property: **the control plane is never in the
request path**. Every edge agent serves from its own persisted bundle. A
control-plane restart, database failover, or network partition stops
*configuration changes*, not traffic.

## Step 1 — Choose the topology first

Do not start with a single container and hope to grow into HA. Pick the shape
now; the deployment guide and the HA document are the deep references.

| Shape | Use it when | What fails traffic |
|---|---|---|
| **All-in-one** | Lab, single internal app, one host | The host |
| **Control plane + N edges** | Standard production; multiple sites or regions | Only when every edge is gone |
| **Edges + control-plane standby** | Changes must survive a control-plane host failure | Database promotion window for writes |
| **Edges + PostgreSQL HA** | Critical platform | Database promotion / DNS propagation |

The full comparison, diagrams, and runbooks are in
[Deployment paths](../deployment-paths.md) and
[High availability](../ha.md).

## Step 2 — Prepare the host and the ports

- Linux (amd64/arm64), 2 GB RAM and 10 GB disk as a practical floor; size from
  [Sizing & capacity](../sizing.md), not from a blog post.
- PostgreSQL 14+ (16 recommended). This is the only stateful component.
- Ports: **80/443** for proxied sites, **9080** for the console/API, **9090**
  for gRPC between agents and the control plane. PostgreSQL stays internal.

Set real secrets before first boot:

```bash
export JWT_SECRET=$(openssl rand -hex 32)
export ADMIN_PASSWORD=$(openssl rand -hex 16)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)
docker compose up -d
```

Do not keep the seeded `varman123` password on a reachable host. If
`TLS_SANS` does not include the hostname you will use, the generated management
certificate will warn; set it or upload a real certificate in **Settings**.

## Step 3 — Bring up the first control plane / edge

For the standard all-in-one or split shapes, follow the exact commands in the
[Deployment guide](../deployment.md). The essentials:

```bash
# All-in-one
varman all-in-one --db-url "postgres://..." --admin-addr 0.0.0.0:9080

# Split: control plane
varman server --db-url "postgres://..." \
  --admin-addr 0.0.0.0:9080 --grpc-addr 0.0.0.0:9090

# Split: edge agent
varman agent --server-url "http://control-plane:9090" --api-key "..."
```

An agent needs an API key from **Settings → API keys** (or a pre-registration
in **Agents** when registration is closed). Bind it to a site, or let an
unbound agent serve every site owned by its key's owner.

## Step 4 — Verify the data plane, not just the health endpoint

```bash
curl -sk https://localhost:9080/healthz
curl -sk https://localhost:9080/api/v1/version
```

Then verify through the edge: send a request with the site's `Host` header and
confirm the response carries `server: varmanwaf` and an `x-request-id`. A
control plane that answers but an edge that does not is not a deployment.

![Dashboard showing traffic, blocks and site health](images/console/dashboard.webp)

## Step 5 — Harden the control plane

- **Settings → Control plane HTTPS**: install a trusted certificate; the
  self-signed default is for first boot only.
- **Settings → Users**: named administrator accounts; viewer accounts for site
  owners; no shared admin login.
- **Settings → API keys**: scoped keys, one per integration; rotate on staff
  change.
- **Settings → API protection**: keep the management API behind the allowlist
  you actually need.
- **Registration**: leave `ALLOW_REGISTRATION=false` unless you intentionally
  run an open instance.
- **Backups**: schedule the PostgreSQL dump before you need it; test a restore
  into a scratch database.

![Settings with identity, TLS, retention and providers](images/console/settings.webp)

## Step 6 — Run an edge fleet

The standard production shape is a control plane plus **two or more** edge
nodes behind DNS, a TCP/HTTP load balancer, or anycast. Each node holds the
bundles for its bound sites and keeps serving through a control-plane outage.

1. Install the agent on each host.
2. Point it at the control plane with its API key; verify it appears in
   **Agents** with a fresh heartbeat.
3. Bind it to sites (or leave it unbound for a key owner's whole portfolio).
4. Add it to the traffic pool; remove it from the pool before draining.
5. Upgrade one node at a time — never the whole fleet at once.

![Agents with heartbeat, version and served-site scope](images/console/agents.webp)

The fleet topology is the fastest way to see a binding mistake: the only edges
are **control plane → agent → site**. A site with no agent is not being served
by that agent, no matter what the site page says.

![Fleet topology: control plane, edge agent and site](images/console/fleet-topology.webp)

## Step 7 — Make the database boring

PostgreSQL is the only stateful service. Use managed PostgreSQL or streaming
replication with a VIP/proxy; the platform does not run a consensus protocol.
What matters:

- Automated backups **and** a tested restore.
- A promotion procedure that points the control plane at the new primary.
- Edge nodes keep serving during the promotion; only writes wait.
- After promotion, verify agents reconnect and config hashes converge.

```bash
pg_dump -U varman -d varman -Fc -f varman_$(date +%Y%m%d).dump
pg_restore -U varman -d varman_scratch --clean varman_20261025.dump
```

See [Backup & recovery](../deployment.md#backup--recovery) for the full
commands and a cron example.

## Step 8 — Certificates and ACME

Site certificates are per-site; the management listener has its own
certificate. ACME needs a public DNS name and a reachable HTTP-01 or DNS-01
path. If issuance fails, the SSL page shows the state and the events; the
application log holds the raw ACME transcript.

![Site certificate, expiry and ACME events](images/console/ssl.webp)

Do not debug ACME by restarting the control plane. Check DNS, port 80, and the
challenge path first.

## Step 9 — Upgrade safely

The order matters in a distributed deployment:

1. Back up the database.
2. Upgrade the control plane; migrations run on startup.
3. Verify `/healthz`, `/api/v1/version`, and the console bundle hash.
4. Upgrade agents **one at a time**; confirm each reconnects and serves.
5. Run the feature check, then the full E2E sweep.
6. Keep the previous image tag for rollback; the schema is forward-only, so a
   rollback needs the matching database state.

```bash
docker compose pull varman
docker compose up -d --force-recreate varman
curl -sk https://localhost:9080/api/v1/version
```

Release notes list the image digest and the verification evidence for each
round. See [Releases](../releases/index.html).

## Step 10 — Observe the right signals

| Signal | Where | What it means |
|---|---|---|
| Edge heartbeat | **Agents** | A stale heartbeat is an outage, not a warning |
| Config hash convergence | **Agents** / **Config history** | A node is serving an older bundle |
| Request volume and 5xx | **Traffic** / dashboard | Edge or origin problem, not necessarily WAF |
| Blocked rate | Dashboard / **Logs** | A rule change, an attack, or a false positive |
| Certificate expiry | **SSL/TLS** | Renewal failed or ACME is blocked |
| Database health | PostgreSQL / `/healthz` | Control-plane writes at risk |
| Disk and cache quota | Host / **Caching** | Cache fills can evict or fail writes |

![Configuration history with versions, diffs and rollback](images/console/config-history.webp)

## Incident runbook

| Symptom | First check | Then |
|---|---|---|
| Site returns 502 | Origin from the **edge** network | Pool health, route match, upstream port |
| Every request blocked | Site mode, then the decision chain | Rule, policy version, exclusion scope |
| Agent offline | Agents page, `:9090` reachability, key | Re-register or replace the node |
| Config not applying | Config history / applied hash | Control-plane → agent sync, then retry |
| ACME stuck | DNS, port 80, challenge path | SSL events, application log |
| High memory | Cache quota, process metrics | Profiling, cache eviction, restart plan |
| Upgrade regression | Previous image tag | Restore DB only if the schema changed |

## Related

- [Deployment paths](../deployment-paths.md) — choose all-in-one, split, or HA.
- [Deployment guide](../deployment.md) — commands, config, firewall, backup.
- [High availability](../ha.md) — topologies, node sync, failure semantics.
- [Sizing & capacity](../sizing.md) — measured limits.
- [For administrators](./administrator.md) — users, policies, evidence.
- [For developers](./developer.md) — build and release.
