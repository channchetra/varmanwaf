# Virtual patches (CVE response)

A **virtual patch** is a small SecLang rule set that closes a specific
vulnerability at the edge while the origin is still unpatched. It is the
"emergency brake" layer: narrow rules that match the input shapes an exploit
needs, not the application's normal traffic.

- **Where it lives** — a site's *Web Protection → Custom layers → SecLang
  virtual patches* field, or a policy's `virtual_patches` layer
  (`{ "source": "<seclang>" }`). Policies let one source cover many sites.
- **How it runs** — the native SecLang engine (`SecRuleSet`) evaluates the
  source after the built-in pipeline; `block` / `deny` / `drop` rules block,
  everything else records. The control plane validates the source on save.
- **Body-reading rules capture the body automatically** — a patch that
  targets `REQUEST_BODY`, `ARGS`, `ARGS_POST*`, `FILES*`,
  `MULTIPART_PART_HEADERS`, `REQUEST_BODY_LENGTH` or `XML` makes the edge
  capture request bodies for that site (up to the plugin's inspection cap)
  even when advanced mode is off. Without that, such a rule would silently
  never match.
- **Built-in templates** — `GET /api/v1/virtual-patch-templates` lists the
  sources shipped with the engine; the console inserts one with a click.

## PHP2Shell — CVE-2026-109618 / CVE-2026-109619

Two critical (CVSS 9.2) PHP core bugs: out-of-memory handling can leave
request state corrupted (`CVE-2026-109618`), and stale worker-global state
can be consumed by a later request (`CVE-2026-109619`). Both end in
unauthenticated remote code execution or worker-memory disclosure, in PHP
itself — no application bug is required. Affected: PHP 8.2 < 8.2.35,
8.3 < 8.3.36, 8.4 < 8.4.27, 8.5 < 8.5.12 (older branches are EOL and
vulnerable without a vendor backport).

**Updating PHP is the only complete fix.** The templates below cut the
input-side links the exploit chains need; they are defence in depth.

| Template id | Use on | What it blocks |
| --- | --- | --- |
| `varman-php2shell` | Sites that accept multipart uploads | Session upload-progress abuse (`PHP_SESSION_UPLOAD_PROGRESS`), multipart part-header floods (>100 part headers), file-control floods (>20 file controls), multipart without a declared `Content-Length`, form field-name floods (>200 names) |
| `varman-php2shell-no-uploads` | Sites that never take multipart (content sites, JSON APIs) | Every `multipart/form-data` request — the PHP advisory's own recommendation for such apps |

Rule ids are `2026109617`–`2026109622` (the CVE number, so they are easy to
find in events). Each rule carries `tag:'php2shell'` and the CVE tag.

### Applying it

1. **Patch PHP** (or have the hoster do it) and restart every PHP worker.
2. Open the site → *Web Protection* → *Custom layers* → pick the template
   under **Built-in virtual patch** → **Save**.
   (Or `PUT /api/v1/sites/{site_id}/waf/settings` with
   `{"virtual_patches": "<source>"}`.)
3. Set the WAF mode to **block** when you are ready to enforce; in
   `monitor` mode the matches are recorded but not blocked.
4. Watch *Logs → Security events* for `php2shell` hits — a blocked request
   is answered with the standard block page and the rule id.

### Also do (origin-side, from the PHP advisories)

- `session.upload_progress.enabled=0` and, on PHP 8.5,
  `fatal_error_backtraces=0` — administrative ini/pool settings, then
  restart workers.
- Keep `post_max_size` small (`8M` without uploads, `32M` with) and
  `upload_max_filesize` below it; bound input variables, multipart parts,
  part headers and uploads.
- Avoid `memory_limit=-1` unless the advisory's trade-off is understood;
  never use `RLIMIT_AS` / `RLIMIT_DATA` (they turn into the vulnerable
  allocation-failure path).
- Front the app with the WAF in **block** mode and keep it enabled after
  patching.

## Honest limits

- **The edge sees requests, not the exploit's success.** Cloudflare's
  php2shell rules pair request signals with the origin's response (their
  "full transaction detection", which catches the leaked `PHPSESSID`
  memory-disclosure cookie). VarmanWAF evaluates requests only, so a
  variant that stays under every threshold is not caught here.
- **Body inspection is bounded** (64 KiB by default, with a staged tail
  scan). A flood that only becomes fatal past the cap is not fully parsed.
- **A virtual patch is not a fix.** It reduces the attack surface; the
  vulnerable runtime stays vulnerable. Treat it as the bridge until the
  origin is updated.
- Thresholds are chosen for typical traffic (see the table). A site with
  unusually large forms or upload counts should raise them — edit the
  inserted source, which is plain SecLang.
