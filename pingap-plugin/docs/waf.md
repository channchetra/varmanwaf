# waf

Web Application Firewall request inspection. Every request is scored against the
PingWAF detection engine (managed signature rules plus optional per-site custom
rules), and the resulting verdict is mapped onto the proxy pipeline.

- **Step:** `early_request` (default) or `request` — configurable
- **Registered as:** `waf`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `waf`. |
| `mode` | string | `block` | `off`, `monitor` or `block`. `off` skips inspection entirely; `monitor` logs events but never blocks; `block` enforces verdicts. Case-insensitive; unknown values fall back to `block`. |
| `paranoia_level` | int | `2` | Detection sensitivity, clamped to `1`–`4`. Higher catches more but increases false positives. |
| `anomaly_threshold` | int | `40` | Accumulated anomaly score at which a request is blocked/challenged. |
| `detections` | string[] | `[]` | Enabled detection families, e.g. `["sqli", "xss", "rce", "lfi", "ssrf"]`. |
| `ml_enabled` | bool | `false` | Enable the ML scoring pass. |
| `ml_threshold` | float | `0.5` | ML confidence threshold (`0.0`–`1.0`). |
| `inspect_body` | bool | `false` | Read and inspect the request body. Off by default — reading the body on every request is expensive and interferes with streaming uploads. |
| `max_body_size` | int | `65536` | Upper bound (bytes) of the body read when `inspect_body` is on. |
| `pow_difficulty` | int | `20` | Proof-of-work difficulty used when a `Challenge` verdict delegates to the challenge subsystem. |
| `step` | string | `early_request` | `early_request` or `request`. Any other value is a configuration error. |

## Verdicts

| Verdict | Result |
| --- | --- |
| `Pass` | `Continue` — request proceeds untouched. |
| `Monitor` | Event logged, `Continue`. |
| `Block` | `403 Forbidden` HTML block page with the event id. |
| `Challenge` | `503` JS challenge page (delegated to the [challenge](challenge.md) subsystem). |

The block page body is:

```html
<html><body><h1>403 Forbidden</h1><p>Request blocked by PingWAF.</p>
<p>Reason: {reason}</p><p>Event ID: {request_id}</p></body></html>
```

## Control plane vs standalone

Rules are resolved per request:

- When a **PingWafAgent** control-plane instance is running, the site rules for
  the request's `Host` are used. Per-domain engines are cached and rebuilt
  automatically when the agent's config hash changes. If the control plane marks
  WAF disabled for a site, inspection is skipped for that host.
- Otherwise (**standalone pingap**) the locally configured engine above is used.

When either a `Block` or `Challenge` fires and an agent is present, a
`SecurityEvent` is shipped to the control plane and the site's request counters
are updated.

## Examples

Blocking mode with a raised paranoia level and body inspection:

```toml
[plugins.waf]
category = "waf"
mode = "block"
paranoia_level = 3
anomaly_threshold = 30
detections = ["sqli", "xss", "rce", "lfi", "ssrf"]
inspect_body = true
max_body_size = 131072

[locations.api]
upstream = "backend"
path = "/api"
plugins = ["waf"]
```

Monitor (shadow) mode — log what would be blocked without enforcing:

```toml
[plugins.wafShadow]
category = "waf"
mode = "monitor"
paranoia_level = 2
```

## Usage notes

- `waf` runs at `early_request` by default, ahead of most other plugins, so
  malicious traffic is rejected before authentication, caching or upstream work.
- Pair with [`challenge`](challenge.md): a `Challenge` verdict renders the
  challenge page, and the challenge plugin's verify endpoint completes the flow.
  Keep `pow_difficulty` and `cookie_secret` consistent between the two.
- The engine runs on **every** request. Leave `inspect_body` off unless you need
  body-level detection, and keep `max_body_size` bounded.
- The engine is held behind `Arc<RwLock<..>>` and per-domain engines are cached,
  so control-plane rule updates hot-reload without restarting pingap.
