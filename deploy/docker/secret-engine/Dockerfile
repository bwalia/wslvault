# syntax=docker/dockerfile:1.7
#
# secret-engine image.
#
# Optimised for rebuild speed. The three things that made the previous version
# slow, in order of cost:
#
#   1. Every build recompiled the entire dependency graph from scratch. The
#      cargo registry and target/ are now BuildKit cache mounts, so deps are
#      downloaded and compiled ONCE and reused by later builds. Only crates
#      that actually changed are rebuilt.
#   2. The build context was ~754 MB (ui/ alone ~696 MB) and was re-sent on
#      every build, with any ui/ change busting the cache for a Rust service
#      that cannot see it. See Dockerfile.dockerignore next to this file.
#   3. Copying rust-toolchain.toml made rustup re-sync the channel and download
#      9 components on every build. The base image is already the pinned
#      1.94 stable, so that round-trip is pure overhead here.
#
# Manifests are copied before sources so a source-only change does not
# invalidate the dependency layer.
#
# Cache mounts hold target/ outside the image, so the binary MUST be copied out
# within the same RUN that builds it.

FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      musl-tools protobuf-compiler lld ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Match the musl target to the build platform. The image is built for
# linux/amd64 (pinned in CI), so this resolves to x86_64-unknown-linux-musl.
RUN case "$(uname -m)" in \
      aarch64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
      *) RUST_TARGET=x86_64-unknown-linux-musl ;; \
    esac && rustup target add $RUST_TARGET && echo $RUST_TARGET > /tmp/rust-target

WORKDIR /app

# utoipa-swagger-ui downloads its assets at build time; keep the existing
# workaround for proxied networks.
RUN echo "insecure" > /root/.curlrc

# --- manifests first (cheap, rarely change) --------------------------------
# rust-toolchain.toml is deliberately NOT copied: it would trigger a rustup
# channel re-sync on every build for a toolchain this image already has.
COPY Cargo.toml Cargo.lock ./
COPY .cargo/ .cargo/

# --- sources ---------------------------------------------------------------
# Only what the workspace needs to resolve and what secret-engine compiles.
# services/ is ~1.5 MB in total, so copying it whole costs nothing; ui/ and the
# non-Rust SDKs are excluded via Dockerfile.dockerignore.
COPY crates/ crates/
COPY services/ services/
COPY sdks/ sdks/
COPY wslvault-cli/ wslvault-cli/
COPY proto/ proto/

# --- build -----------------------------------------------------------------
# The two cache mounts are the main win: the registry avoids re-downloading
# crates, and target/ avoids recompiling unchanged ones. Because target/ lives
# in the cache mount (not the layer), the binary is copied out here.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo build --release --target $RUST_TARGET -p secret-engine && \
    cp /app/target/$RUST_TARGET/release/secret-engine /app/secret-engine

# --- runtime ---------------------------------------------------------------
# Unchanged: a statically linked musl binary on alpine. The published image is
# just ca-certificates + one binary, so pushes stay small.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/secret-engine /usr/local/bin/secret-engine
EXPOSE 8081 50052
USER 65534:65534
ENTRYPOINT ["secret-engine"]
