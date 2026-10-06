# VarmanWAF Changelog

VarmanWAF is built on the PingWAF platform (Apache-2.0). The full inherited
upstream history is preserved in
[CHANGELOG-upstream-pingwaf.md](./CHANGELOG-upstream-pingwaf.md); it is not
rewritten, because it is the factual record of the code lineage.

Changes made **in this repository** are recorded below.

## Unreleased

### Added

- Phase 0 documentation set: `docs/upstream-pingwaf-map.md`,
  `docs/architecture.md`, `docs/references.md`, `docs/roadmap.md`.

### Changed

- Imported PingWAF v0.20.0 (`c87ef671`) as the VarmanWAF foundation.
- Renamed the WAF platform crates: `pingwaf-server` → `varman-control`,
  `pingwaf-agent` → `varman-agent`, `pingwaf-waf` → `varman-waf`,
  `pingwaf-proto` → `varman-protocol`, `pingwaf-challenge` → `varman-challenge`,
  `pingwaf-pprof` → `varman-pprof`. The `pingap-*` proxy-foundation crates keep
  their names for now (see `docs/upstream-pingwaf-map.md` §10).
- Renamed the platform binary `pingwaf` → `varman` (the `pingap` proxy binary
  remains available).
- Rebranded runtime identity: environment variables `PINGWAF_*` → `VARMAN_*`,
  default dashboard credentials `admin@varman.local` / `varman123`, default
  paths `/etc/varman`, `/var/lib/varman`, database defaults
  (`varman:varman@…/varman`), Docker image/container/volume names.
- Rebranded user-facing documentation, install scripts, systemd unit
  (`varman.service`), default configuration (`varman.toml`) and the embedded
  dashboard strings.
