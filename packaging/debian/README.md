# Debian maintainer scripts

cargo-deb generates the `postinst`/`prerm`/`postrm` for the systemd unit into
this directory at package time, driven by `[package.metadata.deb.systemd-units]`
in the root `Cargo.toml`. It only does so when `maintainer-scripts` points
somewhere, which is the only reason this directory exists: without it the unit
is installed but `systemctl daemon-reload` never runs and `purge` leaves the
unit registered.

The hand-written `preinst` creates the `varman` system account and its
directories before unpacking, so the `User=varman` in `varman.service` exists on
first start. It is idempotent, so upgrades and reinstalls keep the existing
account and data.

`varman.service` here is the package unit (binary under `/usr/sbin`, unit under
`/lib/systemd/system`). The repository-root `varman.service` is the manual
install unit and targets `/usr/local/bin`; `unit-scripts` points at this
directory so the package installs the matching one.

Add a hand-written `postinst` etc. here if one is ever needed; cargo-deb merges
its generated fragments into an existing script rather than replacing it.
