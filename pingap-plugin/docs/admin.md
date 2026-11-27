# admin

Serves the data-plane configuration REST API and the process profiling
endpoints. It is **API only**: the web console is not embedded here. The
console (`web/`) is served by the control plane — `varman server` at
`--admin-addr` / `VARMAN_ADMIN_ADDR`, default `0.0.0.0:9080` — next to its
`/api/v1` REST API.

Lives in the `pingap` binary (`src/plugin/admin.rs`) because it needs the
configuration manager, the certificate/upstream providers and the restart
machinery.

- **Step:** `request` (fixed)
- **Registered as:** `admin`

Most people never declare this plugin by hand — the `--admin` command line flag
builds an equivalent configuration. Declaring it explicitly is what you do when
the admin API should live on an existing server behind a path prefix.

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `admin`. |
| `path` | string | `""` | URL prefix the API is mounted at. A trailing `/` is stripped. |
| `authorizations` | string[] | `[]` | Base64 of `user:password`, one entry per account. **Required and non-empty** unless `allow_unauthenticated` is set. An entry that does not decode to `user:password` fails construction, naming its index. |
| `allow_unauthenticated` | bool | `false` | Explicitly serves the admin API without authentication. Logs a warning at startup. Never expose such an instance beyond localhost. |
| `max_age` | duration | `2d` | Allowed clock skew for the signed token. |
| `ip_fail_limit` | int | `10` | Failed attempts per IP before that IP is blocked for 5 minutes. |

## Via the command line

```bash
pingap -c /opt/pingap/conf --admin=pingap:123123@127.0.0.1:3018

# or, mounted under a prefix on an existing listener
pingap -c /opt/pingap/conf --admin=pingap:123123@0.0.0.0:80/pingap
```

Credentials are mandatory: an address without `user:pass` produces an empty
`authorizations` entry and fails startup. Percent-encode the characters that
are special in a URL — `@` as `%40`, `:` as `%3A`, a space as `%20` — and quote
the value in the shell:

```bash
# stores the user `u` and the password `p@ss`
pingap -c /opt/pingap/conf --admin='u:p%40ss@127.0.0.1:3018'
```

Both halves of the credential are percent-decoded before they are stored. To
serve the API without authentication on purpose, declare the plugin with
`allow_unauthenticated = true` (see below) instead of dropping the credentials.

Equivalent environment variables: `PINGAP_ADMIN_ADDR`, `PINGAP_ADMIN_USER`,
`PINGAP_ADMIN_PASSWORD`.

## As a plugin

```toml
[plugins.admin]
category = "admin"
path = "/pingap"
authorizations = ["cGluZ2FwOjEyMzEyMw=="]   # pingap:123123
max_age = "1h"
ip_fail_limit = 5

[locations.admin]
path = "/pingap"
plugins = ["admin"]
weight = 2000

[servers.main]
addr = "0.0.0.0:80"
locations = ["admin", "app"]
```

## Authentication

The API does not use HTTP Basic. Each request carries

```
Authorization: <token>:<unix-seconds>
token = hex(sha256("<user>:<password>:<unix-seconds>"))
```

`<unix-seconds>` must be within `max_age` of the proxy's clock, and the token is
compared in constant time. The API has no login flow; the client computes the
token itself.

**Every path requires authentication.** There is no public route: neither `/`,
the old login-page asset names (`/index.html`, `/favicon.ico`, `/vite.svg`,
`/assets/*`), nor a static-looking suffix such as `.js`, `.css` or `.png` is
exempt — through the bare path or the `/api` prefix. Unknown paths are
authenticated first and then return `404 Not Found`.

After `ip_fail_limit` failures an IP is refused with `403 Forbidden, too many
failures` for 5 minutes.

## API

All routes are relative to `<path>`; the `/api` prefix is optional
(`<path>/api/configs` and `<path>/configs` are equivalent).

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/configs/{category}` | Read configuration for a category |
| `POST` | `/configs/{category}/{name}` | Create or update one entry |
| `POST` | `/configs/import` | Import a whole configuration |
| `DELETE` | `/configs/{category}/{name}` | Delete one entry |
| `GET` | `/config-history/{category}/{name}` | Previous versions, when the storage backend supports history |
| `GET` | `/basic` | Process info, enabled features (includes the TLS backend name `openssl` / `rustls`), supported plugins, upstream health |
| `GET` | `/certificates` | Parsed information about the loaded certificates |
| `POST` | `/aes` | AES encrypt/decrypt helper for secrets |
| `POST` | `/restart` | Trigger a graceful restart |
| `GET` | `/pprof/profile` | CPU profile (protobuf, gzip); `?seconds=` defaults to 30, max 120 |
| `GET` | `/pprof/flamegraph` | CPU flame graph (SVG); same query parameters |
| `GET` | `/pprof/memory` | Memory snapshot (JSON) |

`{category}` is one of `basic`, `server`, `location`, `upstream`, `plugin`,
`certificate`, `storage`. Any other path — including `/` — returns
`404 Not Found` after authentication.

```bash
TS=$(date +%s)
TOKEN=$(printf 'pingap:123123:%s' "$TS" | shasum -a 256 | cut -d' ' -f1)
curl -H "Authorization: $TOKEN:$TS" http://127.0.0.1:3018/api/basic
```

## Control-panel mode

`pingap --cp --admin=user:pass@127.0.0.1:3018` runs only the admin node: it
manages configuration in the shared backend (typically etcd) without proxying
traffic itself. Its listener is also API only — the console is not part of this
mode. Data-plane instances watch the same backend and hot reload.

## Usage notes

- **Authentication is required.** An empty or malformed `authorizations` list
  fails startup; it no longer disables authentication. To run without
  authentication on purpose, set `allow_unauthenticated = true` — never expose
  such an instance beyond localhost.
- The API can change certificates, upstreams and servers and can restart the
  process. Bind it to a private interface, or put
  [`ip_restriction`](ip_restriction.md) in front of the admin location.
- Configuration written through the API goes to whatever backend `-c` points at.
  With `file://` storage, a proxy started with `--upstream` (the config-file-less
  quick start) has no editable backing store and the API cannot be used to
  change it.
- The token embeds a timestamp but not the request; it is a bearer credential.
  Serve the admin API over TLS.
- `/configs/{category}/{name}` and `/config-history/{category}/{name}` both
  require the name segment; omitting it returns an error rather than a result.
