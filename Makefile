# The single version every crate inherits, read straight out of the manifest.
# Scoped to the `[workspace.package]` section because the root `[package]` says
# `version.workspace = true` and `[workspace.dependencies]` repeats a version
# per member, so an unscoped match would find the wrong line.
#
# Not `cargo pkgid`: that reads Cargo.lock, which still holds the old number in
# the one moment this is for - just after the manifest was bumped, before any
# cargo command has refreshed the lock.
VERSION := $(shell awk '/^\[workspace\.package\]/{f=1;next} \
	f&&/^version = /{gsub(/"/,"",$$3);print $$3;exit}' Cargo.toml)

lint:
	typos
	cargo clippy --features=full --all-targets --all -- --deny=warnings

# Same gate for the rustls TLS backend
lint-rustls:
	cargo clippy --no-default-features --features=tls-rustls,full --all-targets --all -- --deny=warnings
	# `geo` is not part of `full`, so it needs its own pass or it silently rots.
	cargo clippy -p pingap-plugin --features=geo --all-targets -- --deny=warnings

fmt:
	cargo fmt --all

# ── Build hygiene ────────────────────────────────────────────────────────────
# Cargo never garbage-collects target/: every feature set, test binary and
# profile keeps its own artifacts forever — one checkout of this repo reached
# 108 GB that way. The heavy targets below run `check-target` first. Once
# target/ exceeds TARGET_MAX_GB it drops the incremental caches (the fastest
# growing and cheapest part to lose), and only if that is not enough clears the
# whole directory with `cargo clean`. Override per invocation
# (`make test TARGET_MAX_GB=50`). `dev` is exempt on purpose: bacon owns that
# loop and the incremental cache keeps it fast.
TARGET_MAX_GB ?= 20

HEAVY := lint lint-rustls test test-rustls cov bench bench-all bloat \
	release release-full release-rustls-full release-all release-perf \
	release-pyro

$(HEAVY): check-target

check-target:
	@used=$$(du -sm target 2>/dev/null | cut -f1); \
	limit=$$(( $(TARGET_MAX_GB) * 1024 )); \
	if [ -n "$$used" ] && [ "$$used" -gt "$$limit" ]; then \
		echo "target/ uses $${used} MB, over TARGET_MAX_GB=$(TARGET_MAX_GB): dropping incremental caches"; \
		rm -rf target/*/incremental; \
		used=$$(du -sm target 2>/dev/null | cut -f1); \
		if [ -n "$$used" ] && [ "$$used" -gt "$$limit" ]; then \
			echo "still $${used} MB: cargo clean"; \
			cargo clean; \
		fi; \
	fi

# Removes the build cache and the copied root `dist/`; `web/dist` is kept
# because pingwaf-server embeds it at compile time.
clean:
	cargo clean
	rm -rf dist

build-web:
	rm -rf dist \
	&& cd web \
	&& npm install && npm run  build \
	&& cp -rf dist ../


bench-all:
	cargo bench -p pingap-core
	cargo bench -p pingap-logger
	cargo bench -p pingap-location

bench:
	cargo bench

dev:
	bacon run --  --features=full -- -c="~/tmp/pingap?separation=true&enable_history=true" --admin=pingap:123123@127.0.0.1:3018 --autoreload

devfile:
	bacon run --  --features=full -- -c="~/tmp/pingap.toml" --admin=pingap:123123@127.0.0.1:3018 --autoreload

devetcd:
	bacon run -- -- -c="etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s&enable_history=true" --admin=127.0.0.1:3018 --autoreload

mermaid:
	cargo run --bin generate-mermaid

udeps:
	cargo +nightly udeps

msrv:
	cargo msrv list


bloat:
	cargo bloat --release --crates --bin pingap

outdated:
	cargo outdated

unused-features:
	unused-features analyze

test:
	cargo test --workspace --features=full

# Same suite on the rustls TLS backend
test-rustls:
	cargo test --workspace --no-default-features --features=tls-rustls,full

cov:
	cargo llvm-cov --workspace --html --open

release:
	cargo build --release
	ls -lh target/release

release-full:
	cargo build --release --features=full
	ls -lh target/release

# The full feature set on the rustls TLS backend (no OpenSSL in the binary)
release-rustls-full:
	cargo build --release --no-default-features --features=tls-rustls,full
	ls -lh target/release


release-all:
	cargo build --release --features=full
	mv target/release/pingap target/release/pingap-full
	cargo build --release
	ls -lh target/release

release-perf:
	cargo build --profile=release-perf --features=perf
	ls -lh target/release-perf
release-pyro:
	cargo build --profile=release-perf --features=pyro
	ls -lh target/release-perf

publish:
	make build-web
	cargo publish --registry crates-io --no-verify

hooks:
	cp hooks/* .git/hooks/

version:
	git cliff --unreleased --tag v$(VERSION) --prepend CHANGELOG.md

# Bump both places the version lives: [workspace.package] and the per-member
# requirements in [workspace.dependencies]. `make bump V=1.2.3` sets it outright.
bump-major:
	./scripts/bump-version.sh major

bump-minor:
	./scripts/bump-version.sh minor

bump-patch:
	./scripts/bump-version.sh patch

bump:
	@test -n "$(V)" || { echo "usage: make bump V=1.2.3"; exit 1; }
	./scripts/bump-version.sh $(V)

# Fails when the two places disagree, which builds from a path checkout hide.
check-version:
	./scripts/bump-version.sh --check
