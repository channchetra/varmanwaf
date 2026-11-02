# Incident report — office WebSocket 403s (2026-11-02)

> **Internal document.** Not part of the public website. Production evidence
> collected at 2026-11-02 08:37 UTC.

## Symptom

`office.unity-workspace.com` and `uoffice.unity-workspace.com` returned
`403` on their WebSocket routes:

```text
GET /ws        -> 403
GET /cool/ws   -> 403
```

The operator had disabled the policy assignments and set the sites to
**Monitor** with the **legacy** engine, but the blocks continued. The operator
described it as “one client” and “based on the route.”

## What was actually running

```text
site: office.unity-workspace.com
waf_enabled: true
mode: monitor
engine_mode: legacy
advanced_mode: false
paranoia: 1

site: uoffice.unity-workspace.com
waf_enabled: true
mode: monitor
engine_mode: legacy
advanced_mode: false
paranoia: 1

site_waf_policies: 0 rows
site_waf_policy_overrides: 0 rows
```

No policy was assigned to either site. The policy rows still exist and are
enabled globally, but `site_waf_policies` is empty, so the effective config is
site-only.

The blocks were:

```text
rule_id:   sem.cmd.command_context
rule_name: stream-inspection
action:    block
score:     40
host:      office.unity-workspace.com / uoffice...
path:      /ws, /cool/ws, /ws/publish
```

The source is `varman-waf/src/pipeline/semantic/command.rs`. That rule is:

```rust
rule:     "sem.cmd.command_context"
severity: Low
action:   Action::Log
score:    5
detail:   "command word near a shell metacharacter"
```

It is a **low-confidence log-only** finding, not a policy rule and not a
blocking rule.

The actual WebSocket path is **route-based, not client-based**. The access log
shows many different Cloudflare edge addresses hitting `/ws`; each browser
reconnect appears under a different edge IP. The operator sees one browser,
but every client using that WebSocket route is affected.

## Root cause

`pingap-plugin/src/waf_stream.rs` passed only `rule_id` and `detail` out of the
pipeline verdict. It discarded the finding's `action` and `score`.

`record_stream_abort` then hardcoded:

```rust
action: "block"
score: 40
response: 403
```

and always set `aborted = true`. It also never consulted the site's
`waf_settings.mode` or `engine_mode`. So a `Log` finding on a **Monitor +
legacy** site was turned into a hard 403 on the WebSocket tunnel.

The repeated config pushes and `rule change detected` reloads at 08:29–08:32
did not help, confirming this was not a stale policy/cache issue; the stream
inspector was enforcing a log-only rule directly.

## Fix (v1.4.2)

- `StreamFinding::Payload` now carries the pipeline `action` and `score`.
- Only `Action::Block` / `Action::Challenge` findings can close a stream.
- Stream enforcement is enabled only when:
  - the site mode is **Block**, and
  - the engine is **Varman** (`engine_mode=varman`, or `inherit` with the
    process-wide engine set to `varman`).
- `monitor`/`off` sites and `legacy`/`shadow` engines record a **monitor**
  security event and continue.
- Tail-body inspection follows the same rule.
- Regression tests:
  - `id;` → `sem.cmd.command_context`, `Action::Log`, score 5.
  - `$(id)` → action above `Log`.
  - `stream_enforcement` false for Monitor+Varman and Block+legacy, true for
    Block+Varman.
- `pingap-plugin`: 207 tests passed.

## Expected production behaviour after deploy

- `/ws` and `/cool/ws` no longer return 403 for the low-confidence rule.
- The same payloads are visible in Security events as `action=monitor`,
  `rule_id=sem.cmd.command_context`, score 5.
- If the site is later switched to **Block + Varman**, only high-confidence
  stream findings (`Block`/`Challenge`) close the tunnel; log-only findings
  remain monitor events.

## Notes

- This incident is unrelated to the 1.4.0 per-site WAF context keying fix, but
  both were needed: the context fix makes mode/engine changes reach the right
  site; the 1.4.2 fix makes the stream inspector obey them.
- The `office`/`uoffice` sites remain Monitor + legacy. No production setting
  needs changing to stop the false 403 after 1.4.2.
