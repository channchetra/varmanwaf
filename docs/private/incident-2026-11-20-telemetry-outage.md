# Incident report — seven-day telemetry outage (2026-11-20 → 2026-11-27)

> **Internal document.** Not part of the public website. Evidence collected
> from production `proxy-1` (`103.189.187.19`) on 2026-11-27.

## Symptom

The dashboard showed no new access logs or security events. The newest rows
were:

```text
security_events.latest_event  = 2026-11-20 04:59:34 UTC
access_logs.latest_access     = 2026-11-20 04:59:33 UTC
```

The proxy itself kept serving traffic. The container had restarted at
`2026-11-20 05:09:20 UTC`, ten minutes after the last stored row.

## Evidence

The agent was retrying its control-plane connection every 45–60 seconds:

```text
WARN varman_agent::client: Connection to control plane failed error=transport error
ERROR varman_core::services::listening: ...
  0: invalid peer certificate: certificate expired:
     verification time 1795612273 (UNIX), but certificate is not valid after
     1794610768 (1001505 seconds ago)
```

The certificate on both `:9080` and `:9090`:

```text
notBefore = Nov  7 06:59:29 2026 GMT
notAfter  = Nov 13 22:59:28 2026 GMT
```

`control_plane_certificates` showed the matching row, `source = acme`,
`is_active = true`, and `management_certificate.status = active`. No alert had
been raised.

`certificate_events` had no ACME activity after **2026-11-08 14:59 UTC**. The
ACME request existed and was enabled; it was simply never scanned again.

## Root cause

A chain of three independent failures:

1. **ACME renewal stopped.** The last certificate was issued on 11-07 and
   expired on 11-13. No order was attempted afterwards. The manual
   `POST /system/tls/acme/retry` re-armed the request and issued a new
   certificate in **20 seconds**, so the ACME path itself was healthy; the
   edge had stopped seeing the `__management` entry in its configuration.
2. **The gRPC listener could not pick up a renewal.** `configure_grpc_tls`
   built a static `tonic::ServerTlsConfig` from the active row at startup.
   Even after the retry installed a new certificate on `:9080`, `:9090`
   continued to present the expired one until the process restarted.
3. **A NUL byte poisoned log shipping.** On the first reconnect the control
   plane rejected a 17-entry batch:

   ```text
   Failed to ship logs count=17
   Query Error: invalid byte sequence for encoding "UTF8": 0x00
   ```

   The agent retried the same batch forever, its buffer filled, and every
   subsequent entry was dropped.

The seven days of buffered entries were in memory and are unrecoverable.

## Immediate recovery (2026-11-27)

1. `POST /api/v1/system/tls/acme/retry` → new certificate valid to
   **2026-12-03 19:53 UTC**, fingerprint `99565ec5…`.
2. `:9080` updated immediately; `:9090` still served the expired pair.
3. Container restart → `:9090` loaded the new row; agent connected.
4. A second restart cleared the NUL-poisoned in-memory batch; logs resumed.

Within ten minutes: 350 access rows, 181 security events, no buffer warnings.

## Fix (v1.4.3)

- gRPC TLS uses a per-connection acceptor sharing the reloadable resolver, with
  ALPN `h2` (verified by a real handshake test that rotates the certificate
  between connections).
- A 48-hour renewal watchdog re-arms the ACME request (six-hour cooldown) and
  raises an alert once per fingerprint.
- `optional()`/`truncate()` replace NUL with `U+FFFD` before insert, so one
  hostile path cannot fail a batch.
- Stream inspection: dedupe per rule per connection, honour disabled WAF /
  observation mode / unsynced bundles / engine aliases, and close on protocol
  violations.

## Production verification

To be filled in after the 1.4.3 deploy:

- [ ] `:9090` rotates after `POST /system/tls/acme/retry` **without** a restart
      (same container `StartedAt`).
- [ ] Agent reconnects after the rotation.
- [ ] Access logs and security events continue through the rotation.
- [ ] No `invalid byte sequence` errors.
- [ ] `sem.cmd.command_context` rows per request drop to 1.

## Lessons

- A certificate that the process serves but never re-reads is an outage with a
  timer on it. The rotation path must be exercised, not assumed.
- "The database is up" is not "ingest works": a single byte in a log field can
  stop the pipeline without touching the database's health check.
- Expiry alerts must cover the control plane's own certificate, not only the
  sites' certificates.
