# Attack simulation and rule testing (private)

> **Internal document.** This file is not part of the public documentation
> site: `website/build.mjs` only renders the documents listed in its `NAV`
> array, and `docs/private/` is not in that list. Do not add it to `NAV`.

Use these probes only on sites you own or have written permission to test.
They are non-destructive detection checks, not exploitation tools. Prefer a
dedicated test site and a disposable origin.

## 1. Create a disposable test site

1. **Sites → Add site**.
2. Domain: a hostname you control, for example
   `waf-test-YYYYMMDD.example.com`.
3. Upstream: a simple HTTP service you control. Do **not** point it at the
   WAF listener: the API rejects loopback origins on ports 80/443/9080/9090
   because they would recurse into the proxy.
   - A staging app is ideal.
   - On a private host: `python3 -m http.server 8099`, then use
     `10.x.x.x:8099` as the upstream.
4. Leave HTTPS off while testing over HTTP, or attach a certificate for the
   test hostname.
5. Set **Protection mode → Monitor** first. Switch to **Block** for the
   enforcement pass, and **Paused** for the maintenance-page check.

The built-in rules are seeded in `monitor` mode. That is why a new site starts
as **Monitoring** in the sites list.

## 2. Send a request to one specific site

If DNS does not point the test hostname at the WAF, target the listener
directly with a `Host` header:

```bash
# HTTP listener on the WAF host
curl -sS -i -H 'Host: waf-test-YYYYMMDD.example.com' \
  'http://127.0.0.1/?id=1'

# HTTPS listener, bypassing DNS and certificate-name checks
curl -sS -i -k \
  --resolve 'waf-test-YYYYMMDD.example.com:443:127.0.0.1' \
  'https://waf-test-YYYYMMDD.example.com/?id=1'
```

From another machine, replace `127.0.0.1` with the WAF's address. If
Cloudflare or another CDN is in front, bypass it for these tests so you see
the WAF's response, not the CDN's cache or challenge.

Useful additions:

```bash
-H 'X-Test-Id: rule-check-001'      # find this run in logs
-A 'sqlmap/1.8'                     # scanner user-agent probe
-X TRACE                            # unsafe-method probe
```

## 3. What the response means

| Signal | Meaning |
| --- | --- |
| `403` + `x-varmanwaf-mitigated: block` | A rule matched and Block mode enforced it |
| `200`/`3xx` + a `security_events` row with `action=monitor` | A rule matched, Monitor mode recorded it |
| `503` + `x-varmanwaf-mitigated: challenge` | Challenge plugin, not a block |
| `503` + body contains `temporarily paused` | Site is Paused |
| `403` with `Forbidden: invalid host header` | Origin rejected the forwarded Host; not the WAF |
| No event, request reaches the origin | Rule did not match (or is disabled) |

Check **Logs → Security events** for the site and filter by host, path, rule
or action. **Access logs** show the returned status and whether an upstream
was contacted.

## 4. Built-in rule probes

The stock rules cover the common families below. Run each probe in
**Monitor** first to confirm detection, then in **Block** to confirm
enforcement.

| Family | Safe probe | Expected match |
| --- | --- | --- |
| SQL injection (anomaly) | `/?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--` | `SQL injection (anomaly)` |
| XSS (anomaly) | `/?q=%3Cscript%3Ealert(1)%3C/script%3E` | `Cross-site scripting (anomaly)` |
| Command injection | `/?cmd=;cat%20/etc/passwd` | `Command injection` |
| Log4Shell / JNDI | `-H 'User-Agent: ${jndi:ldap://127.0.0.1/a}'` | `Log4Shell (JNDI)` |
| Path traversal / LFI | `/.%2e/.%2e/etc/passwd` or `/../../etc/passwd` | `Path traversal / file inclusion` |
| SSRF / metadata | `/?url=http://169.254.169.254/latest/meta-data/` | `SSRF` |
| Scanner user-agent | `-A 'sqlmap/1.8'` | `Scanner user agent` |
| Dotfile reconnaissance | `/.env` or `/.git/config` | `Dotfile reconnaissance` |
| Backup-file reconnaissance | `/backup.sql` or `/app.zip` | `Backup file reconnaissance` |
| Unsafe method | `-X TRACE /` | `Unsafe HTTP method` |
| Excessive URI length | 4096+ byte path | `Excessive URI length` |

Example block-mode check:

```bash
HOST='waf-test-YYYYMMDD.example.com'
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Host: $HOST" \
  'http://127.0.0.1/.env'
# Block mode   -> 403
# Monitor mode -> 200/3xx, with a monitor event
```

The `/.env` probe is a good smoke test: it matches the dotfile rule without
sending a destructive payload.

## 5. Test a custom rule

1. **Site → Protection → Rules** (or the policy surface if the site follows a
   policy).
2. Add a rule with an obvious, unique condition, for example:

   ```text
   http.request.uri.path eq "/waf-test-custom"
   ```

   Action: **Block**. Give it a memorable name, e.g. `test-custom-rule`.
3. Set the site mode to **Block**.
4. Probe the path:

   ```bash
   curl -sS -o /dev/null -w '%{http_code}\n' \
     -H "Host: $HOST" \
     'http://127.0.0.1/waf-test-custom'
   ```

   Expect `403` and an event whose rule name is `test-custom-rule`.
5. Set the site mode to **Monitor**, repeat the request, and confirm it
   reaches the origin while the event is recorded as `monitor`.
6. Remove the test rule when finished.

If the rule does not fire, check in this order: rule enabled, group enabled,
site mode, path/query exactness, header name lower-case, and whether a policy
layer overrides the site. The **Protection** page shows the effective posture.

## 6. Full mode matrix

Use the same three probes for each mode:

```bash
benign='/healthz'           # a path your origin answers
attack='/.env'              # a path the built-in dotfile rule matches
```

| Mode | Benign | Attack | Event action | Origin contacted |
| --- | --- | --- | --- | --- |
| Monitor | 200 | passes (200/3xx) | `monitor` | yes |
| Block | 200 | `403` | `block` | no |
| Paused | `503` | `503` | none | no |

For Paused, also check the body contains `temporarily paused` and the access
log has no `upstream_addr`. Resume into Block and confirm the attack is `403`
again.

Mode changes are pushed to the edge and can take a few seconds. Re-probe
after the data-plane reload rather than immediately after the toast.

## 7. Automation with the API

```bash
BASE='https://127.0.0.1:9080/api/v1'
TOKEN=$(curl -sk -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"…"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# Monitor
curl -sk -X PUT "$BASE/sites/$SITE_ID/waf/settings" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"waf_enabled":true,"mode":"monitor"}'

# Block
curl -sk -X PUT "$BASE/sites/$SITE_ID/waf/settings" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"waf_enabled":true,"mode":"block"}'

# Paused / resume
curl -sk -X PUT "$BASE/sites/$SITE_ID" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"status":"paused"}'
curl -sk -X PUT "$BASE/sites/$SITE_ID" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"status":"active"}'
```

The list endpoint reports the effective value:

```bash
curl -sk "$BASE/sites?search=$HOST" -H "Authorization: Bearer $TOKEN" \
  | python3 -c 'import sys,json; i=json.load(sys.stdin)["items"][0]; print(i["protection_mode"])'
```

## 8. Cleanup

- Delete the test site, or leave it **Paused**.
- Delete test custom rules and test IP blocks.
- Remove test security events/access rows if they pollute the dashboard.
- Return production sites to the mode they had before testing.

## 9. Common false alarms

- **`403` from the origin, not the WAF**: a body like
  `Forbidden: invalid host header` means the upstream app rejected the Host.
  Fix the origin's allowed-host list or point the site at the right vhost.
- **`503` challenge page**: the challenge plugin, not Paused or Block. It
  normally clears in a real browser.
- **`503` from the origin**: check the access log's `upstream_addr` and
  latency; the WAF forwarded the request.
- **No event in Monitor**: the rule did not match. Try the exact probe from
  the catalogue, then narrow the expression.
- **Dashboard writes fail with “change your password before making
  changes”**: the account has `must_change_password=true`; change the
  password or use an admin account without the flag.
