# PingWAF Deployment Guide

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Linux (amd64/arm64), macOS | Ubuntu 22.04+, Debian 12+ |
| PostgreSQL | 14+ | 16 |
| RAM | 512 MB | 2 GB+ |
| Disk | 1 GB | 10 GB+ (logs, cache) |
| Ports | 80, 443, 9080, 9090 | — |

## Quick Start (Docker Compose)

The fastest way to get PingWAF running:

```bash
# Clone the repository
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF

# Set secrets (recommended)
export JWT_SECRET=$(openssl rand -hex 32)
export ADMIN_PASSWORD=$(openssl rand -hex 16)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)

# Start all services
docker compose up -d

# Verify (the health endpoint answers on HTTP and HTTPS alike)
curl http://localhost:9080/healthz
```

Dashboard: `https://localhost:9080` — served over TLS with a self-signed
certificate generated on first boot, so the browser warns until it is trusted
or replaced (**Settings → Control plane HTTPS**). Set `TLS_SANS` to the hostname
you use if it is not `localhost`.  
Default credentials: `admin@pingwaf.local` / value of `$ADMIN_PASSWORD`

### Environment Variables (docker-compose)

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_PASSWORD` | `pingwaf` | PostgreSQL password |
| `JWT_SECRET` | `change-me-in-production-use-32-chars` | JWT signing secret (≥16 chars) |
| `ADMIN_EMAIL` | `admin@pingwaf.local` | Initial admin email |
| `ADMIN_PASSWORD` | `pingwaf123` | Initial admin password |
| `ALLOW_REGISTRATION` | `false` | Allow new user signups |
| `HEARTBEAT_INTERVAL` | `15` | Agent heartbeat interval (seconds) |
| `RUST_LOG` | `info,sqlx=warn` | Log level filter |

## Manual Installation (Binary + systemd)

### 1. Install the Binary

```bash
# Automatic (downloads latest release)
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | bash

# Or specify version and mode
./install.sh --version 0.20.0 --mode all-in-one
```

> Prebuilt release assets are published for **Linux** (amd64/arm64) only; on
> macOS, [build from source](./quick-start.md#path-2-build-from-source).
>
> The binaries are linked against the glibc of the runner that builds them
> (Ubuntu 24.04, **glibc 2.39**), so they run on Debian 12+/Ubuntu 24.04+ and
> equivalent. On older distributions (CentOS/RHEL 8, Debian 11, Ubuntu 22.04,
> Alpine, ...) `install.sh` stops with the loader's error — build from source
> there, or run the container image.

### 2. Set Up PostgreSQL

```bash
# Install PostgreSQL
sudo apt install postgresql-16

# Create user and database
sudo -u postgres createuser pingwaf
sudo -u postgres createdb -O pingwaf pingwaf
sudo -u postgres psql -c "ALTER USER pingwaf PASSWORD 'your-secure-password';"
```

### 3. Configure

Settings come from three places, each overriding the one before it: a TOML
file, `PINGWAF_*` environment variables, and command-line flags.

1. **A TOML file** — `--config /etc/pingwaf/pingwaf.toml` (or
   `PINGWAF_CONFIG`). `install.sh` writes one and points the unit at it; its
   `[server]` and `[agent]` tables hold the settings listed in the
   [Configuration Reference](#configuration-reference).
2. **Environment variables** — set as `Environment=` lines in the systemd unit
   (a drop-in override with `sudo systemctl edit pingwaf` survives package
   upgrades).
3. **Command-line flags** — in the unit's `ExecStart`, e.g.
   `pingwaf all-in-one --tls-enabled false`.

```ini
[Service]
Environment=PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml
# Environment variables remain useful for the settings the file cannot
# express, and for secrets you would rather not put in a file:
Environment=PINGWAF_ALLOW_REGISTRATION=false
Environment=PINGWAF_DB_MAX_CONNECTIONS=40
Environment=RUST_LOG=info,sqlx=warn
```

The settings with no file key — `allow_registration`, `db_max_connections`,
`metric_retention_days`, `cors_origins`, the passkey settings and the
`PINGWAF_ES_*` Elasticsearch block — are listed under
[Environment-only settings](#server-configuration-server).

There is no reload signal: edit the file or the drop-in and
`sudo systemctl restart pingwaf`.

### 4. Start the Service

```bash
sudo systemctl enable --now pingwaf
sudo systemctl status pingwaf

# View logs
sudo journalctl -u pingwaf -f
```

## Configuration Reference

The `[server]` and `[agent]` tables of the configuration file
(`--config` / `PINGWAF_CONFIG`) take the long-flag names with dashes written as
underscores (`--admin-addr` → `admin_addr`); list values are TOML arrays. The
`all-in-one` mode reads both tables, `server` and `agent` only their own. A key
that is not recognised is reported and ignored, and a setting given both in the
file and in the environment is taken from the environment.

### Server Configuration (`[server]`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `db_url` | string | `postgres://pingwaf:pingwaf@localhost:5432/pingwaf` | PostgreSQL DSN |
| `admin_addr` | string | `0.0.0.0:9080` | REST API + dashboard address |
| `grpc_addr` | string | `0.0.0.0:9090` | gRPC control plane address |
| `jwt_secret` | string | `change-me-in-production` | JWT signing secret (≥16 chars, required) |
| `admin_email` | string | `admin@pingwaf.local` | Seeded admin email |
| `admin_password` | string | `pingwaf123` | Seeded admin password |
| `serve_frontend` | bool | `true` | Serve the embedded dashboard SPA for non-API routes |
| `tls_enabled` | bool | `true` | Serve the REST API + dashboard over HTTPS; cleartext requests get a `308` redirect, health probes are exempt. Turn off behind a TLS-terminating proxy |
| `tls_sans` | string[] | hostname, `localhost`, `127.0.0.1` | Subject alternative names of the generated self-signed certificate |

The rest of the server settings are **environment-only** — they have no flag
and therefore no file key:

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `PINGWAF_JWT_EXPIRATION_HOURS` | `12` | Access token lifetime |
| `PINGWAF_ALLOW_REGISTRATION` | `true` (code); `docker-compose.yml` and `install.sh` set `false` | Allow new user signups |
| `PINGWAF_HEARTBEAT_INTERVAL` | `15` | Heartbeat interval handed to agents at registration |
| `PINGWAF_DB_MAX_CONNECTIONS` | `20` | Connection pool maximum |
| `PINGWAF_METRIC_RETENTION_DAYS` | `7` | Days of edge-metric samples kept in `agent_metrics` |
| `PINGWAF_CORS_ORIGINS` | `[]` (all) | Allowed CORS origins, comma-separated |
| `PINGWAF_PASSKEY_ENABLED` | `true` | Offer passkey (WebAuthn) registration and login |
| `PINGWAF_PASSKEY_RP_NAME` | `PingWAF` | Relying party name shown by the authenticator |
| `PINGWAF_PASSKEY_RP_ID` | derived from the request | Relying party ID, i.e. the effective domain |
| `PINGWAF_PASSKEY_ORIGIN` | derived from the request | Origin the dashboard is served from |
| `PINGWAF_PASSKEY_TRUST_FORWARDED_PROTO` | `false` | Believe `X-Forwarded-Proto` when deriving the origin |

The refresh-token lifetime (30 days), the minimum pool size (`1`) and the
server-side log batch size (`500`) are compiled-in constants with no override.

### Agent Configuration (`[agent]`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server_url` | string | `http://localhost:9090` | Control plane gRPC URL |
| `api_key` | string | `""` | Agent authentication key (empty = auto-register over loopback in all-in-one) |
| `cache_dir` | string | `./data/cache` | Local rule cache directory |
| `fail_open` | bool | `true` | Allow traffic when disconnected |
| `heartbeat_interval_secs` | int | `30` | Fallback heartbeat frequency, used only when the control plane hands no interval down at registration |
| `log_batch_size` | int | `100` | Log entries before flush |
| `log_flush_interval_secs` | int | `5` | Max time between flushes |
| `max_body_log_size` | int | `8192` | Max request body bytes to log |
| `metrics_ship_interval_secs` | int | `30` | Edge-metrics ship interval; `0` disables shipping |

Environment variables: `PINGWAF_SERVER_URL`, `PINGWAF_API_KEY`,
`PINGWAF_CACHE_DIR`, `PINGWAF_FAIL_OPEN`, `PINGWAF_HEARTBEAT_INTERVAL`,
`PINGWAF_METRICS_SHIP_INTERVAL`. The three log settings and the reconnect
backoff constants (`1 s` doubling to `60 s`) have no environment variable.

### Environment Variables

Every setting can be given as an environment variable. The ones with a file key
are listed against it below; the dash in a table entry means the setting has no
`--flag` and is environment-only (or compiled in).

| Variable | File key |
|----------|-----------|
| `PINGWAF_CONFIG` | — (names the configuration file itself) |
| `PINGWAF_DB_URL` | `server.db_url` |
| `PINGWAF_ADMIN_ADDR` | `server.admin_addr` |
| `PINGWAF_HTTP_ADDR` | `server.admin_addr` (alias) |
| `DATABASE_URL` | `server.db_url` (used only when `PINGWAF_DB_URL` is unset) |
| `PINGWAF_GRPC_ADDR` | `server.grpc_addr` |
| `PINGWAF_JWT_SECRET` | `server.jwt_secret` |
| `PINGWAF_ADMIN_EMAIL` | `server.admin_email` |
| `PINGWAF_ADMIN_PASSWORD` | `server.admin_password` |
| `PINGWAF_SERVE_FRONTEND` | `server.serve_frontend` |
| `PINGWAF_JWT_EXPIRATION_HOURS` | — |
| `PINGWAF_ALLOW_REGISTRATION` | — |
| `PINGWAF_HEARTBEAT_INTERVAL` | `server.heartbeat_interval_seconds` (agents follow the value the control plane hands them; `agent.heartbeat_interval_secs` is only a fallback) |
| `PINGWAF_DB_MAX_CONNECTIONS` | — |
| `PINGWAF_METRIC_RETENTION_DAYS` | — |
| `PINGWAF_TLS_ENABLED` | `server.tls_enabled` |
| `PINGWAF_TLS_SANS` | `server.tls_sans` (comma-separated) |
| `PINGWAF_CORS_ORIGINS` | — (comma-separated) |
| `PINGWAF_PASSKEY_ENABLED` | — |
| `PINGWAF_PASSKEY_RP_NAME` | — |
| `PINGWAF_PASSKEY_RP_ID` | — |
| `PINGWAF_PASSKEY_ORIGIN` | — |
| `PINGWAF_PASSKEY_TRUST_FORWARDED_PROTO` | — |
| `PINGWAF_MODE` | CLI mode (`all-in-one`, `server`, `agent`) |
| `PINGWAF_SERVER_URL` | `agent.server_url` |
| `PINGWAF_API_KEY` | `agent.api_key` |
| `PINGWAF_CACHE_DIR` | `agent.cache_dir` |
| `PINGWAF_FAIL_OPEN` | `agent.fail_open` |
| `PINGWAF_METRICS_SHIP_INTERVAL` | `agent.metrics_ship_interval_secs` |
| `PINGWAF_ES_ENABLED` | — Elasticsearch shipper toggle |
| `PINGWAF_ES_URLS` | — Elasticsearch URLs (comma-separated) |
| `PINGWAF_ES_INDEX_PREFIX` | — ES index prefix |
| `PINGWAF_ES_USERNAME` | — ES basic auth username |
| `PINGWAF_ES_PASSWORD` | — ES basic auth password |
| `PINGWAF_ES_API_KEY` | — ES API key |
| `PINGWAF_ES_MAX_BODY_SIZE` | — ES body truncation limit |
| `PINGWAF_ES_BUFFER_DIR` | — ES on-disk buffer directory |
| `RUST_LOG` | Tracing log filter (default `info,sqlx=warn`) |

## Deployment Modes

### All-in-One Mode

Runs both control plane and data plane in a single process. Best for single-server setups.

```bash
pingwaf all-in-one --db-url "postgres://..." --admin-addr 0.0.0.0:9080
```

### Distributed Mode

Separate control plane server and multiple edge agents.

**Control Plane (server):**
```bash
pingwaf server --db-url "postgres://..." --admin-addr 0.0.0.0:9080 --grpc-addr 0.0.0.0:9090
```

**Edge Agent:**
```bash
pingwaf agent --server-url "http://control-plane:9090" --api-key "your-agent-key"
```

Generate an agent API key from the dashboard: **Settings → API Keys → Create Key**.

## SSL/TLS Configuration

### Automatic (ACME / Let's Encrypt)

Configure through the dashboard:
1. Add a site with your domain
2. Go to **SSL** tab
3. Select "Let's Encrypt" and choose challenge type:
   - **HTTP-01**: Requires port 80 accessible
   - **DNS-01**: Supports Cloudflare, AliDNS, Huawei DNS, Tencent DNS

Certificates are automatically renewed before expiry.

### Manual Certificates

Upload PEM-encoded certificate and key through the dashboard or API:

```bash
curl -k -X POST https://localhost:9080/api/v1/sites/{site_id}/certificates \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-cert",
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "domains": ["example.com", "*.example.com"]
  }'
```

### Control-Plane Certificate (dashboard)

The dashboard and REST API are served over HTTPS with a certificate that is
managed from the dashboard itself — no files to edit:

1. **First boot** generates a self-signed pair (EC P-256) covering the
   configured `tls_sans` plus the machine hostname, `localhost` and `127.0.0.1`.
2. **Settings → Control plane HTTPS** shows what is being served (subject,
   SANs, fingerprint, expiry) and lets you download it, upload a real
   certificate + key, or regenerate the self-signed pair.
3. Uploads are validated first — a mismatched key or a broken chain is rejected
   with `400` and the previous certificate keeps serving — and take effect
   immediately, without a restart.

`PINGWAF_TLS_ENABLED=false` (or `tls_enabled = false`) switches the port back
to plain HTTP, which is the right setting behind a reverse proxy that
terminates TLS. Passkeys require a secure origin, so with plain HTTP they are
unavailable unless the proxy publishes an HTTPS origin and
`PINGWAF_PASSKEY_TRUST_FORWARDED_PROTO=true` is set.

The API for all of this is documented in
[`docs/api.md` → Control-plane certificate](./api.md#control-plane-certificate).

## Firewall & Port Requirements

| Port | Protocol | Purpose | Required |
|------|----------|---------|----------|
| 80 | TCP | HTTP traffic / ACME HTTP-01 | Yes (for proxied sites) |
| 443 | TCP | HTTPS traffic | Yes (for proxied sites) |
| 9080 | TCP | Admin dashboard + REST API (HTTPS) | Yes |
| 9090 | TCP | gRPC control plane (agents) | Distributed mode |
| 5432 | TCP | PostgreSQL | Internal only |

```bash
# UFW example
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 9080/tcp
sudo ufw allow 9090/tcp  # Only if agents connect remotely
```

## Backup & Recovery

### Database Backup

```bash
# Full backup
pg_dump -U pingwaf -d pingwaf -F c -f pingwaf_backup_$(date +%Y%m%d).dump

# Restore
pg_restore -U pingwaf -d pingwaf --clean pingwaf_backup_20240101.dump
```

### Configuration Backup

```bash
tar -czf pingwaf_config_backup.tar.gz /etc/pingwaf/ /var/lib/pingwaf/certs/
```

### Automated Backups (cron)

```cron
# Daily at 2:00 AM
0 2 * * * pg_dump -U pingwaf -d pingwaf -F c -f /backups/pingwaf_$(date +\%Y\%m\%d).dump
# Remove backups older than 30 days
0 3 * * * find /backups -name "pingwaf_*.dump" -mtime +30 -delete
```

## Upgrade Procedure

### Docker

```bash
docker compose pull
docker compose up -d
```

### Binary

```bash
# Download and install new version
./install.sh --version NEW_VERSION --no-systemd

# Restart service
sudo systemctl restart pingwaf
```

Database migrations run automatically on startup.

### Rolling Upgrade (Distributed)

1. Upgrade the control plane server first
2. Verify agents reconnect successfully
3. Upgrade agents one at a time

## Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u pingwaf --no-pager -n 50

# Common issues:
# - PostgreSQL not running: systemctl status postgresql
# - Port already in use: ss -tlnp | grep -E '9080|9090'
# - Invalid config: pingwaf all-in-one --db-url "..." (run interactively)
```

### Database connection failed

```bash
# Test connection
psql "postgres://pingwaf:password@localhost:5432/pingwaf" -c "SELECT 1"

# Check pg_hba.conf allows connections
# Ensure the user has CREATEDB privilege for migrations
```

### Agent not connecting

1. Verify the control plane gRPC port (9090) is accessible
2. Check the API key is valid
3. Review agent logs: `RUST_LOG=debug pingwaf agent --server-url ...`
4. Ensure clocks are synchronized (NTP)

### High memory usage

- Reduce `db_max_connections`
- Lower `log_batch_size`
- Check if cache disk quota is configured

### Health check endpoint

```bash
curl http://localhost:9080/healthz
# {"status":"ok","database":"up"}
```
