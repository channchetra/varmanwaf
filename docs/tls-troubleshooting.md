# TLS troubleshooting: 525, missing certificates, and “Unknown issuer”

This page is for the case where a site is configured for HTTPS in VarmanWAF
but browsers — or Cloudflare — cannot complete TLS with the edge. It covers
what each error means, how to find the real cause in five commands, and how to
recover without restarting the control plane blindly.

The short version: a **525 is an origin certificate problem**. The WAF is either
not presenting a certificate for that hostname, or the certificate it presents
is not trusted by the CDN. WAF rules, DNS and the origin application are not
involved yet.

## Is there a CDN in front?

The guidance splits by topology, because the certificate is validated by a
different party in each one:

| Topology | Who validates the WAF certificate | Error you see on failure |
| --- | --- | --- |
| **Direct DNS** — A/AAAA record points at the WAF | The browser | Browser TLS error (`ERR_SSL_PROTOCOL_ERROR`, `ERR_CERT_*`, `SSL_ERROR_*`); **no 525/526** |
| **Cloudflare proxied** — orange cloud, DNS points at Cloudflare | Cloudflare | **525 / 526** / 521 / 522 / 524 |

- **No CDN (direct DNS):** there is no Cloudflare leg, so 525, 526 and the
  Full / Full (strict) / Flexible modes do not exist for that hostname. The
  browser talks straight to the WAF; the WAF must simply present a valid
  certificate whose SAN covers the hostname. ACME HTTP-01 still works — Let's
  Encrypt reaches the WAF on port 80 directly, so DNS must point at the WAF and
  port 80 must be reachable. Make sure any **AAAA** record also points at the
  WAF (or is removed), or IPv6 clients will fail even when IPv4 works.
- **Cloudflare proxied:** use sections 1–6 below. Section 6 (Full/strict) only
  applies to this topology.
- **Both topologies:** sections 3–5 (certificate loaded, agent scope, ACME
  status), section 7 (“Unknown issuer”) and section 10 (WAF → private app TLS)
  are identical. The origin TLS leg is independent of the CDN.

A direct-domain check from any client:

```bash
# The WAF itself is the endpoint; this is what the browser sees.
openssl s_client -connect varman.example.com:443 \
  -servername varman.example.com </dev/null 2>&1 \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

curl -sI https://varman.example.com/
```

`varman.unitywork.space` in the production deployment is a direct-DNS site:
it resolves to the WAF and responds with `server: varmanwaf`, with no
Cloudflare headers. `mail-bridge.unity-workspace.com` is the proxied case and
responds with `server: cloudflare`. Both are supported.

## 1. Read the CDN error code first

> This section only applies when Cloudflare (or another TLS-terminating CDN) is
> in front of the WAF. For direct DNS, skip to section 2 — the browser reports
> the TLS failure itself.

| Code | Meaning | Usual cause |
| --- | --- | --- |
| **525** | TLS handshake between Cloudflare and the origin failed | No certificate loaded for that SNI, or the handshake was rejected |
| **526** | Origin certificate is invalid or untrusted | Self-signed, expired, wrong hostname, or an incomplete chain |
| **521** | Origin refused the connection | The WAF is down, or 443 is not listening |
| **522** | Connection timed out | Firewall, routing, or the host is unreachable |
| **523** | Origin unreachable | DNS/route to the origin is wrong |
| **524** | Origin accepted but did not answer in time | Slow application, not a certificate problem |

Outside Cloudflare the same failure appears as `ERR_SSL_PROTOCOL_ERROR`,
`SSL_ERROR_NO_CYPHER_OVERLAP`, or “no peer certificate available”.

## 2. Test the origin directly, with SNI

Run this **on the WAF host**. Testing `127.0.0.1` removes Cloudflare, DNS and
the network from the equation:

```bash
openssl s_client -connect 127.0.0.1:443 \
  -servername mail-bridge.example.com </dev/null 2>&1 \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

What the result means:

| Output | Meaning | Go to |
| --- | --- | --- |
| `no peer certificate available`, `alert handshake failure`, alert 40 | Nothing is serving a certificate for that SNI | Step 3 |
| A certificate, but `issuer` is the same as `subject` | Self-signed; **Full (strict)** will return 526 | Step 6 |
| A certificate with the wrong CN/SAN | The wrong certificate is selected for the site | Step 4 |
| A valid certificate, correct SAN, future dates | The origin is fine; the problem is trust or the CDN mode | Step 6 |

Also check the chain — a leaf without intermediates can pass some clients and
fail strict ones:

```bash
openssl s_client -connect 127.0.0.1:443 \
  -servername mail-bridge.example.com -showcerts </dev/null 2>&1 \
  | grep -c "BEGIN CERTIFICATE"
```

A publicly trusted certificate should normally return the leaf plus at least
one intermediate.

## 3. Is the certificate loaded by the data plane?

The edge logs the certificate entries it actually loaded at startup:

```bash
docker logs varman 2>&1 | grep "certificates loaded"
```

Expected shape:

```text
data plane: certificates loaded
  certs="7f12f3e2-..._cert,c97f6dfc-..._cert"
```

Each name is `<site-id>_cert`. Match the site id to the hostname:

```bash
docker exec varman-postgres psql -U varman -d varman -c \
  "select id, domain from sites order by domain;"
```

If the site's `<site-id>_cert` is missing, the configuration never reached the
edge. Continue with the next two steps rather than re-issuing the certificate;
a new order cannot help while the site is outside the agent's scope.

## 4. Is the site in the embedded agent's scope?

This is the failure that produced the 525 incident fixed in **v1.2.4**.

In all-in-one mode the data plane is an embedded agent registered with the
bootstrap API key. Before 1.2.4 an unbound agent received **only the sites
owned by that key's user**. A site created by a different administrator was
never pushed to the edge: it had no proxy configuration, no certificate entry,
and its ACME order could never run. The certificate row stayed `pending`, the
stale-order sweeper marked it `failed` after 30 minutes, and Cloudflare
reported 525.

Check who owns the site and who owns the agent key:

```bash
docker exec varman-postgres psql -U varman -d varman -c "
select s.domain, u.email as site_owner
from sites s join users u on u.id = s.user_id
order by s.domain;"

docker exec varman-postgres psql -U varman -d varman -c "
select a.hostname, k.name as key_name, u.email as key_owner
from agents a
join api_keys k on k.id = a.api_key_id
join users u on u.id = k.user_id;"
```

- **v1.2.4 and later:** an unbound agent holding the
  `_all-in-one-bootstrap` key serves every site, regardless of owner. The log
  should show `Updated rule cache from full site config sites=N` and every
  `_cert` entry.
- **v1.2.3 and earlier:** if the site owner differs from the key owner, the
  edge will not receive the site. Upgrade to 1.2.4. As a temporary workaround
  only, transfer the site to the key owner and restart the container; remember
  to restore ownership after the upgrade.
- **Bound agents:** an agent with a `site_id` binding intentionally serves only
  that site. Do not use a binding for the embedded data plane.

## 5. Is the certificate actually issued?

```bash
docker exec varman-postgres psql -U varman -d varman -c "
select domain, status, issuer, not_before, expires_at,
       acme_challenge_type, auto_renew, failure_reason
from site_certificates order by created_at;"
```

| Status | Meaning | Action |
| --- | --- | --- |
| `active` | The edge reported a usable certificate | Verify with `openssl`; see Step 2 |
| `pending` | An order is queued or in flight | Wait for the next ACME window (about 10 minutes), then read the events |
| `failed` | The order gave up | Read `certificate_events`, fix the cause, renew |
| `expired` | The served certificate has passed `not_after` | Renew immediately; check auto-renew |

The raw ACME transcript is in `certificate_events`:

```bash
docker exec varman-postgres psql -U varman -d varman -c "
select created_at, event_type, message
from certificate_events order by created_at desc limit 20;"
```

Trigger a renewal from the console (**SSL/TLS → Renew now**) or the API:

```bash
curl -sk -X POST \
  https://127.0.0.1:9080/api/v1/certificates/<cert-id>/renew \
  -H "Authorization: Bearer <token>"
```

Renewal marks the row `pending`, clears the previous failure and pushes the
site configuration to the agent. Issuance itself runs on the edge.

### HTTP-01 through Cloudflare

HTTP-01 works through a proxied Cloudflare hostname. Let's Encrypt connects to
the hostname on port 80, Cloudflare forwards to the WAF, and the WAF answers
from the stored token.

Before blaming ACME, prove the challenge path reaches the WAF:

```bash
curl -sSI --max-time 10 \
  http://mail-bridge.example.com/.well-known/acme-challenge/probe-test
```

- A **404** from VarmanWAF is expected for an unknown token. The log shows
  `let's encrypt http-01 token not found`, which proves the path is wired.
- A redirect to HTTPS before the handler runs will break validation. Disable
  “Always Use HTTPS” for the challenge or use DNS-01.
- A timeout means port 80 is blocked between the CDN and the origin.

If HTTP-01 is not possible, use **DNS-01** with a provider token
(Cloudflare, Route 53, Huawei, and the other supported providers). DNS-01 also
avoids exposing port 80 and works for wildcard certificates.

## 6. Trust at the CDN: Full, Full (strict), and Origin CA

> Only relevant when a CDN is proxying the hostname. With direct DNS, the
> browser validates the WAF certificate and this section does not apply.

| Mode | What Cloudflare accepts | Use it? |
| --- | --- | --- |
| **Full (strict)** | A publicly trusted certificate with a matching hostname and complete chain | **Yes, for production** |
| **Full** | Any certificate, including self-signed | Temporary diagnosis only |
| **Flexible** | No TLS to the origin at all | **No** — it disables encryption between Cloudflare and the WAF |

A Let's Encrypt certificate issued by VarmanWAF is trusted by Full (strict).
You do **not** need an Origin CA certificate when ACME is working.

If you prefer Cloudflare Origin CA:

1. Cloudflare dashboard → **SSL/TLS → Origin Server → Create Certificate**.
2. Include the hostname (or `*.example.com` for a wildcard).
3. In VarmanWAF open the **global SSL/TLS → Certificates** page and upload the
   certificate and key.
4. On the site → **SSL/TLS** → **Use a certificate** → select it → **Save**.
5. Keep Cloudflare on **Full (strict)**.

Do not use the per-site self-signed toggle for a proxied production site under
Full (strict); it will produce a 526 even though the handshake succeeds.

## 7. “Unknown issuer” — what it does and does not mean

The certificate list can show **Unknown issuer** for an ACME certificate that
is active and perfectly valid. This is a metadata display gap, not a
certificate problem.

Why it happens:

- Uploaded certificates store their PEM in the database, so the control plane
  can parse the issuer and `not_before`.
- ACME-issued PEMs live in the **edge's** ACME state, not in the database.
  The edge reports only `ssl_status` and `ssl_expires_at` over the control
  protocol, so the row can be `active` with a future expiry while `issuer` and
  `not_before` remain empty. The console falls back to “Unknown issuer”.

How to tell the difference:

```bash
openssl s_client -connect 127.0.0.1:443 \
  -servername mail-bridge.example.com </dev/null 2>&1 \
  | openssl x509 -noout -issuer -dates
```

If this prints `issuer=C = US, O = Let's Encrypt, ...`, the edge is serving a
trusted certificate. The console label is cosmetic. If it prints
`issuer=CN = mail-bridge.example.com` (subject equals issuer), the certificate
really is self-signed and Step 6 applies.

## 8. Recovery checklist

1. Read the CDN code: 525 vs 526 vs 521/522.
2. Test the origin with SNI from the WAF host.
3. Check `data plane: certificates loaded` for `<site-id>_cert`.
4. Check site ownership against the agent key owner; upgrade to 1.2.4 if the
   site is outside the embedded agent's scope.
5. Check `site_certificates.status` and `certificate_events`.
6. Renew; wait for the next ACME window (about 10 minutes; a stalled order is
   failed after 30 minutes).
7. Verify the origin certificate, then verify through the CDN.
8. Leave Cloudflare on **Full (strict)**; never use Flexible.

## 9. Copy-paste verification

```bash
# 1. Origin certificate for the hostname
openssl s_client -connect 127.0.0.1:443 \
  -servername mail-bridge.example.com </dev/null 2>&1 \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# 2. What the edge loaded
docker logs varman 2>&1 | grep "certificates loaded"

# 3. Certificate rows
docker exec varman-postgres psql -U varman -d varman -c \
  "select domain, status, expires_at from site_certificates;"

# 4. Through the CDN (should end at the application, not 5xx)
curl -sIL https://mail-bridge.example.com/

# 5. Public trust result
curl -sL -o /dev/null -w "%{http_code} %{ssl_verify_result}\n" \
  https://mail-bridge.example.com/
```

A `200 0` on the last line means the CDN trusts the origin certificate.

## 10. Origin TLS: HTTP backends and self-signed HTTPS backends

The proxy has **two independent TLS legs**, and they are configured in
different places:

```text
browser ──TLS 1──▶ Cloudflare ──TLS 1──▶ WAF edge ──TLS 2 (optional)──▶ private app
              site certificate                     origin pool SNI / verify
```

- **TLS 1 (client-facing)** uses the site certificate under **SSL/TLS** and is
  what Cloudflare validates in Full (strict). A 525/526 belongs to this leg.
- **TLS 2 (origin-facing)** is per upstream pool under **Origins**. It is
  completely separate: the origin's certificate is never the certificate the
  browser sees. A failure here is a `502`/`504` from the WAF, not a 525.

### HTTP origin — no TLS to the private app

This is the normal choice when the app listens on plain HTTP:

- **Origins → pool → HTTPS to origin = off** (leave the SNI field empty).
- Node address stays `private_ip:port`; the WAF connects with `http://`.
- Enable the pool health check against a path that the app serves over HTTP.
- Make sure the app does not redirect `http://` to `https://` on its own; that
  would create a redirect loop with the client-facing HTTPS.

Nothing else is required. In the database this is a pool with an empty `sni`
and peers whose addresses are `private_ip:port`.

### HTTPS origin — private app with a self-signed certificate

This is also supported. Configure the pool like this:

1. **Origins → pool → HTTPS to origin = on.**
2. **SNI hostname** = a name that appears in the app's certificate. It must be
   a bare hostname: no `https://`, no port, and `$host` is rejected for static
   pools. The node address remains `private_ip:port`; SNI is only the name sent
   in the handshake.
3. **Verify origin certificate = off** for a self-signed certificate.

That last point matters. Verification is on by default in the console. A
self-signed origin with verification on fails the handshake and the WAF returns
**502**, with an `InvalidCert`/certificate-verify error in the data-plane log —
not a 525.

```text
# the WAF log tells the two apart
502 + InvalidCert / certificate verify failed  -> origin TLS (leg 2)
525 from Cloudflare                            -> WAF site certificate (leg 1)
```

Security trade-off: turning verification off keeps the traffic encrypted but
stops authenticating the origin. Anyone who can intercept traffic inside the
private network could impersonate the app. Prefer, in order:

1. A certificate from an internal CA whose trust anchor the WAF can use.
2. A publicly trusted certificate for a real internal DNS name (DNS-01 works
   without exposing the app).
3. Verification off, only on a network segment you already trust.

The underlying proxy engine supports a per-upstream **CA bundle** so a private
or self-signed backend can keep verification on, but the console/API does not
expose that field yet. Today the supported control-plane setting for a
self-signed app certificate is **Verify origin certificate = off**. If you need
private-CA pinning, that is a small API/UI addition; the data-plane option
already exists (`upstream.ca`).

Other details that matter for private apps:

- **Certificate names, not addresses.** Issue the app certificate for a DNS
  name (for example `mail.internal`) and use that name as the SNI. Certificates
  that only carry an IP SAN are fragile across TLS stacks.
- **Host header.** The WAF forwards the client's `Host` header. A private app
  that serves multiple virtual hosts may need a request-header rewrite, or it
  must accept the public hostname.
- **Health checks** use the same pool TLS mode. With verification on and a
  self-signed cert, every probe fails and the node is marked unhealthy; fix the
  certificate or turn verification off for that pool.
- **Redirects.** If the app redirects to its own internal hostname, browsers
  will leave the public domain. Prefer relative redirects, or rewrite the
  `Location` header.

### Which leg is failing?

| Symptom | Leg | First check |
| --- | --- | --- |
| Cloudflare **525** | Client → WAF | Site certificate loaded for the SNI |
| Cloudflare **526** | Client → WAF | Site certificate trusted by Full (strict) |
| WAF **502** + `InvalidCert` | WAF → origin | Origin SNI and `verify_cert` vs app certificate |
| WAF **502** + connection refused | WAF → origin | `private_ip:port`, app listening, firewall |
| WAF **504** | WAF → origin | App response time, pool timeout |

A self-signed certificate on the **private app** is therefore not a problem for
Cloudflare and does not require Full (Flexible). It only affects leg 2, and it
is handled entirely under **Origins**.

## The management listener is separate

The dashboard on `:9080` has its own certificate (`management_certificate`),
not a site certificate. It also uses ACME over HTTP-01 on the control-plane
identity (IP or hostname) and renews automatically. Let's Encrypt currently
issues **short-lived** certificates for it (six days in our production run),
so renewal is frequent by design. If the console shows a certificate warning:

```bash
openssl s_client -connect 127.0.0.1:9080 \
  -servername 203.0.113.10 </dev/null 2>&1 \
  | openssl x509 -noout -issuer -dates
```

Check **Settings → Control plane HTTPS** and the application log; do not mix
this certificate up with the per-site certificates.

## Related

- [ACME certificate flow](./acme_chart.md)
- [System administrator runbook](./roles/system-administrator.md)
- [v1.2.4 release note](./releases/v1.2.4.md) — the embedded-agent scope fix
