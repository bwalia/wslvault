# Multi-stage build for the k8s-operator binary.
#
# Stage 1 (builder): compiles the Rust workspace with musl for a fully static
# binary that runs in scratch/distroless images without glibc.
#
# Stage 2 (runtime): copies the binary into a minimal Alpine image that
# includes only CA certificates (required for TLS connections to the
# Kubernetes API server and wslvault secret-engine).
#
# Port 8090 is exposed for the built-in health/readiness HTTP server.
FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y musl-tools lld
RUN case "$(uname -m)" in \
      aarch64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
      *) RUST_TARGET=x86_64-unknown-linux-musl ;; \
    esac && rustup target add $RUST_TARGET && echo $RUST_TARGET > /tmp/rust-target

WORKDIR /app

# Copy workspace manifest and lock file first to maximise layer cache hits.
# The full source tree is needed because k8s-operator has workspace
# dependencies on crates/ and because the CRD YAML is embedded via
# include_str! at compile time.
COPY Cargo.toml Cargo.lock ./
# Copy optional cargo config (registry mirrors, build flags, etc.)
COPY .cargo/ .cargo/

# Copy all workspace members.
COPY crates/ crates/
COPY services/ services/
COPY sdks/ sdks/
COPY wslvault-cli/ wslvault-cli/
# Copy just the CRD YAML the operator embeds via include_str! at compile time
# (the rest of deploy/ is excluded by .dockerignore).
COPY deploy/kubernetes/crds/ deploy/kubernetes/crds/

RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo build --release --target $RUST_TARGET -p k8s-operator && \
    cp /app/target/$RUST_TARGET/release/k8s-operator /app/k8s-operator

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

# CA certificates are required to validate TLS connections to the Kubernetes
# API server (in-cluster) and to any HTTPS wslvault endpoint.
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/k8s-operator /usr/local/bin/k8s-operator

# Port 8090: liveness and readiness health server.
EXPOSE 8090

# Run as nobody (UID 65534) to satisfy PodSecurityStandards restricted policy.
USER 65534:65534

ENTRYPOINT ["k8s-operator"]
