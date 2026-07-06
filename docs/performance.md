# WSLVault Performance

## Methodology

Benchmarks are implemented with [Criterion.rs](https://github.com/bheisler/criterion.rs) v0.5
and live in `crates/wslvault-core/benches/crypto_bench.rs`.  Criterion uses statistical
sampling (100 samples, warm-up phase, outlier detection) and reports mean time ±
standard deviation, plus throughput in MiB/s for variable-size workloads.

**What is measured:** the crypto kernel only — `encrypt_with_dek` / `decrypt_with_dek`
(AES-256-GCM envelope encryption), `derive_key` (HKDF-SHA256), and
`generate_aes_gcm_nonce` (CSPRNG).  These are pure in-process operations with no I/O,
no network, and no database involvement.

**What is NOT measured:** end-to-end HTTP request latency through the secret-engine
service. That path additionally includes JSON (de)serialisation, middleware
authentication checks, PostgreSQL round-trips, and OS network stack overhead.
No end-to-end HTTP numbers are available yet — see the Unmeasured section below.

---

## Test Hardware

| Field | Value |
|---|---|
| CPU | Apple M4 Pro |
| RAM | 24 GB (25 769 803 776 bytes) |
| OS | macOS Darwin 25.5.0 |
| Rust toolchain | stable (aarch64-apple-darwin) |
| Build profile | `release` (optimised, `opt-level = 3`) |

---

## Measured Results — Crypto Layer

All times are wall-clock. Throughput is the inverse of time × payload size.

### AES-256-GCM Encrypt (`encrypt_with_dek`)

| Payload | Mean time | Throughput |
|---|---|---|
| 1 KB  (1 024 B)   | 6.70 µs  | ~146 MiB/s |
| 16 KB (16 384 B)  | 79.1 µs  | ~198 MiB/s |
| 256 KB (262 144 B) | 1.24 ms  | ~201 MiB/s |

### AES-256-GCM Decrypt (`decrypt_with_dek`)

| Payload | Mean time | Throughput |
|---|---|---|
| 1 KB  (1 024 B)   | 6.28 µs  | ~155 MiB/s |
| 16 KB (16 384 B)  | 86.5 µs  | ~181 MiB/s |
| 256 KB (262 144 B) | 1.37 ms  | ~183 MiB/s |

> Decrypt is slightly slower than encrypt at larger sizes because of the base64
> decode step required to reconstruct the nonce + ciphertext blob from the
> stored wire format.

### HKDF-SHA256 Key Derivation (`derive_key`)

| Operation | Mean time |
|---|---|
| HKDF-SHA256 → 32 B output key | 964 ns |

### CSPRNG Nonce Generation (`generate_aes_gcm_nonce`)

| Operation | Mean time |
|---|---|
| 12-byte AES-GCM nonce (ring SystemRandom) | 874 ns |

---

## Derived Per-Operation Crypto Overhead

For a typical secret-read (small value, ~64 B payload) the crypto contribution is
dominated by nonce generation + HKDF + AES-GCM encrypt/decrypt, which totals
roughly **8–10 µs** at the crypto layer alone.  For the sub-1 KB case the
per-operation time scales with base64 overhead and nonce generation, not with
ciphertext length — hence the 6–7 µs floor.

**Important scoping note:** the "`<5 ms`" performance figure referenced in earlier
project documentation was not supported by any measurements at the time of this audit.
The crypto layer comfortably operates well under 1 ms for payloads up to 16 KB on
this hardware.  Whether the *end-to-end HTTP path* achieves sub-5 ms latency under
load remains unmeasured.

---

## Running the Criterion Benchmarks

```bash
# Full benchmark run (builds release binary, then samples each benchmark)
cargo bench -p wslvault-core

# Compile only — verify bench code compiles without running
cargo bench -p wslvault-core --no-run

# Run a specific benchmark group
cargo bench -p wslvault-core -- aes256gcm/encrypt

# Baseline comparison (save a baseline named "before-change")
cargo bench -p wslvault-core -- --save-baseline before-change
# ... make your change ...
cargo bench -p wslvault-core -- --baseline before-change
```

HTML reports are written to `target/criterion/` and can be opened in any browser.

---

## End-to-End HTTP Load Test

The load-test script targets the secret-engine read path:
`GET /v1/secret/data/:path`

```bash
# Requires the secret-engine service to be running first:
# docker compose up secret-engine  (or: cargo run -p secret-engine)

# Run load test (delegates to k6 if installed, otherwise uses curl sampler)
bash scripts/load-test.sh

# Environment variable overrides:
VAULT_ADDR=http://localhost:8081 \
VAULT_TOKEN=root-token \
VAULT_TENANT_ID=acme \
VAULT_SECRET_PATH=prod/db/password \
SAMPLES=500 \
bash scripts/load-test.sh
```

### k6 (preferred)

Install k6:

```bash
# macOS
brew install k6

# Linux
sudo gpg -k && sudo gpg --no-default-keyring \
  --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 \
  --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] \
  https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6
```

When k6 is present, `load-test.sh` delegates to `scripts/load-test.js` which runs
20 VUs (configurable via `VUS=`) for 30 s and enforces thresholds:
`p(50)<50 ms`, `p(95)<200 ms`, `p(99)<500 ms`.

### curl sampler (no k6)

When k6 is absent, `load-test.sh` sends sequential curl requests and reports
p50/p95/p99 in pure bash.  This mode is useful for quick smoke tests but does
not exercise concurrent connections.

---

## What Remains Unmeasured

| Area | Status | Notes |
|---|---|---|
| End-to-end HTTP latency (secret-engine) | **Not measured** | Requires running service + seeded data |
| PostgreSQL round-trip time | **Not measured** | Dominated by DB tier, not crypto |
| KEK wrap/unwrap (crypto-service gRPC) | **Not measured** | Separate service, no local bench |
| ChaCha20-Poly1305 cipher path | **Not implemented** | `KeyAlgorithm::ChaCha20Poly1305` exists in the type system but has no `encrypt_with_chacha20` function yet; add when the cipher is wired in |
| Transit engine bulk throughput | **Not measured** | Separate service |
| Multi-tenant concurrent load | **Not measured** | Requires integration harness |

Contributions welcome — add HTTP benchmarks once the service integration test
environment is stable.
