# Multi-stage build for crypto-service
# Stage 1: Build static musl binary
FROM rust:1.94-bookworm AS builder
RUN apt-get update && apt-get install -y musl-tools protobuf-compiler lld && \
    rustup target add x86_64-unknown-linux-musl
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo/ .cargo/
COPY crates/ crates/
COPY services/ services/
COPY sdks/ sdks/
COPY wslvault-cli/ wslvault-cli/
COPY proto/ proto/
RUN cargo build --release --target x86_64-unknown-linux-musl -p crypto-service

# Stage 2: Minimal runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/crypto-service /usr/local/bin/crypto-service
EXPOSE 8080 50051
USER 65534:65534
ENTRYPOINT ["crypto-service"]
