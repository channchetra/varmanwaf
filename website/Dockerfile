# VarmanWAF website - build the image with the smallest practical footprint.
#
# The site is generated from the repository docs on the host (Node), so the
# build context is just this directory and the image only carries the static
# files plus a dependency-free static server compiled to a static musl binary.
#
#   cd website && npm install && npm run build
#   docker build -f website/Dockerfile -t varmanwaf-website website/
#
# The final image is `scratch`: no shell, no libc, no package manager - just
# the server binary and the site. Expected size: a few megabytes.

# ---------- stage 1: compile the static server (no crates, no cargo) --------
FROM rust:1-alpine AS server-build
WORKDIR /build
COPY server/server.rs ./server.rs
# rust:alpine's host target is x86_64-unknown-linux-musl, so this produces a
# statically linked binary that runs on scratch.
RUN rustc -O --edition 2021 -C strip=symbols -C panic=abort server.rs -o /server

# ---------- stage 2: the image --------------------------------------------
FROM scratch
COPY --from=server-build /server /server
COPY dist/ /srv/
ENV PORT=8080 \
    ROOT=/srv
EXPOSE 8080
# No HEALTHCHECK: scratch has no shell or curl. Probe http://<host>:8080/ .
ENTRYPOINT ["/server"]
