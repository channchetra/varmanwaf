# For administrators

> **Who this is for:** the security or platform administrator who owns the
> VarmanWAF instance, its users, its shared defenses, and its evidence. You
> have the `admin` role and can see every site.

Administrators decide **who can get in**, **what the fleet enforces by default**,
and **what evidence is kept**. Day to day you work in the global surfaces:
policies, CRS, IP intelligence, alerts, reports, history, and settings. Site
owners keep their own sites; you provide the guardrails and the audit trail.

## What you can do

- Create and disable users; reset passwords; issue scoped API keys.
- Build reusable WAF policies and assign them to sites.
- Import CRS rulesets and apply virtual patches for new CVEs.
- Maintain global IP groups and the blocked-IP list.
- Route alerts to webhooks and keep the event history.
- Configure Elasticsearch, log retention, AI providers, API protection, and
  control-plane TLS.
- Read the global audit/config history and export reports.
- Use the assistant and MCP tools with write scope.

## The administrator loop

### Step 1 — Secure the instance before inviting anyone

Open **Settings** and work top to bottom: change the seeded admin password,
set the control-plane certificate, confirm the management listener, configure
log retention, and decide whether registration and the AI provider are on.
TLS for the control plane is separate from the certificates your sites serve.

![Settings with identity, TLS, logging and provider sections](images/console/settings.webp)

### Step 2 — Create the right accounts

**Settings → Users** creates an account with a role of **administrator** or
**viewer**. Use a viewer account for site owners and read-only auditors; keep
administrator accounts few. A disabled account is rejected at login even if its
password is correct.

**Settings → API keys** issues keys with explicit permissions. A `read` key is
safe for dashboards and MCP read tools; a `write` key can change site status
and observation mode, so its owner must be an administrator.

- Prefer one key per integration, named after the service.
- Rotate keys after a person leaves or a CI secret leaks.
- Never put a key in a browser bookmark or a shared alert payload.

### Step 3 — Make policies the default, not the exception

A **policy** is a reusable bundle: engine mode, paranoia, custom rules,
managed-rule behavior, exclusions, and rate/access posture. Build it once,
preview and test it, then assign it to sites. A policy-managed site shows
*Managed by policy* in place of the local protection control.

![WAF policies with scope, version and assignment state](images/console/policies.webp)

![Policy detail with layers, preview, test and versions](images/console/policy-detail.webp)

The safe workflow is **preview → test → assign**. Roll back by version rather
than editing a live policy in place; the version history is the audit trail.

### Step 4 — Keep the rule corpus current

**CRS** shows imported rulesets, their source, version, and validation state.
Import a new archive only after checking that it parses and that the rule IDs do
not collide with local custom rules.

**Virtual patches** are the fast lane for a new CVE: bind a narrow rule to the
affected sites, observe it in monitor first, then enforce. Remove the patch when
the upstream ruleset or the vendor fix lands.

![CRS rulesets with import and validation state](images/console/crs.webp)

### Step 5 — Operate the IP layer

**IP groups** are named, reusable lists (manual, country, ASN, or a remote
subscription). **Blocked IPs** is the live enforcement list. Keep the two
separate: a group is configuration; a blocked entry is an active decision.

![Global IP groups with manual and subscribed lists](images/console/ip-groups.webp)

![Blocked IPs with source, reason and expiry](images/console/blocked-ips.webp)

### Step 6 — Make alerts actionable

**Alerts & notifications** holds the event feed, silences, and delivery
channels. Configure a webhook once, then attach it to the alert rules that
matter. A channel test proves connectivity; a silence is scoped and expiring,
so a noisy rule cannot hide a real incident forever.

![Alerts, silences and notification channels](images/console/alerts.webp)

### Step 7 — Keep evidence you can hand to someone else

**Reports** builds the interception summary for a window. **Config history**
records configuration versions and lets you compare or roll back. **Logs**
carries the request-level evidence, including the decision chain that names the
rule that acted.

![Configuration history with versions and rollback](images/console/config-history.webp)

![Decision chain for a blocked request](images/console/decision-chain.webp)

When you hand an incident to a site owner, include the request ID, the rule ID,
the action, and the exact window. Those four fields make the event
reproducible.

### Step 8 — Review the fleet, not just one site

**Agents** shows every edge node, its version, last heartbeat, served sites, and
whether it is bound to one site or serving all sites owned by its key. A stale
heartbeat is an operational incident, not a cosmetic warning.

![Agents with heartbeat, version and served-site scope](images/console/agents.webp)

The fleet topology draws **control plane → agent → site** only. There is no
control-plane → site edge: configuration always flows through an agent.

![Fleet topology with control plane, agent and site nodes](images/console/fleet-topology.webp)

## Administrator checklist

| Cadence | Check |
|---|---|
| On install | Change seeded password, install TLS, create named admin accounts, disable open registration |
| Weekly | Failed logins, disabled accounts, stale agents, expiring certificates |
| On every WAF release | CRS import, virtual patches, policy preview/test, config-history version |
| Monthly | API key inventory, alert channel test, report export, restore drill |
| On incident | Request ID → decision chain → policy/rule → version → site owner handoff |

## Boundaries

- Site behavior belongs to the [site owner](./site-user.md); do not silently
  change a site's protection mode without telling them.
- Host, database, and network changes belong to the
  [system administrator](./system-administrator.md).
- The assistant and MCP write tools act with your authority. Review the tool
  call before you accept a change.

## Related

- [Feature inventory](../features.md) — every global surface and its limits.
- [Console walkthrough](../user-guide.md) — step-by-step UI detail.
- [For system administrators](./system-administrator.md) — deployment, HA,
  backup and upgrade.
- [REST API](../api.md) — the same operations for automation.
