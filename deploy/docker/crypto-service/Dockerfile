# Multi-stage build for crypto-service
# Stage 1: Build static musl binary
FROM rust:1.94-bookworm AS builder
RUN apt-get update && apt-get install -y musl-tools protobuf-compiler lld
RUN case "$(uname -m)" in \
      aarch64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
      *) RUST_TARGET=x86_64-unknown-linux-musl ;; \
    esac && rustup target add $RUST_TARGET && echo $RUST_TARGET > /tmp/rust-target
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo/ .cargo/
COPY crates/ crates/
COPY services/ services/
COPY sdks/ sdks/
COPY wslvault-cli/ wslvault-cli/
COPY proto/ proto/
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo build --release --target $RUST_TARGET -p crypto-service && \
    cp /app/target/$RUST_TARGET/release/crypto-service /app/crypto-service

# Stage 2: Minimal runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/crypto-service /usr/local/bin/crypto-service
EXPOSE 8080 50051
USER 65534:65534
ENTRYPOINT ["crypto-service"]
