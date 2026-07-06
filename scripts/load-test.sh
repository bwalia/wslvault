#!/usr/bin/env bash
# =============================================================================
# WSLVault HTTP Latency Sampler
# =============================================================================
# Measures end-to-end HTTP latency for the secret-engine read path
# (GET /v1/secret/data/:path) using pure bash + curl.
#
# If k6 is installed this script delegates to scripts/load-test.js for
# a full VU-based load test with p50/p95/p99 thresholds. Otherwise it runs
# a sequential curl sampler and reports percentiles in pure bash.
#
# Usage:
#   bash scripts/load-test.sh
#
# Environment variables:
#   VAULT_ADDR        - Base URL (default: http://localhost:8081)
#   VAULT_TOKEN       - Auth token (default: dev-root-token)
#   VAULT_TENANT_ID   - Tenant header value (default: test-tenant)
#   VAULT_SECRET_PATH - Secret path to read (default: bench/test-secret)
#   SAMPLES           - Number of sequential requests (default: 200)
#   CONCURRENCY       - Parallel curl workers for bash mode (default: 5)
#   VUS               - Virtual users for k6 mode (default: 20)
#   DURATION          - Test duration for k6 mode (default: 30s)
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8081}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
VAULT_TENANT_ID="${VAULT_TENANT_ID:-test-tenant}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-bench/test-secret}"
SAMPLES="${SAMPLES:-200}"
CONCURRENCY="${CONCURRENCY:-5}"
VUS="${VUS:-20}"
DURATION="${DURATION:-30s}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_URL="${VAULT_ADDR}/v1/secret/data/${VAULT_SECRET_PATH}"

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

log()   { printf "%b%s%b\n" "${CYAN}"   "$*" "${NC}"; }
ok()    { printf "%b%s%b\n" "${GREEN}"  "$*" "${NC}"; }
warn()  { printf "%b%s%b\n" "${YELLOW}" "$*" "${NC}"; }
err()   { printf "%b%s%b\n" "${RED}"    "$*" "${NC}" >&2; }

# ── Delegate to k6 if available ───────────────────────────────────────────────
if command -v k6 &>/dev/null; then
    ok "k6 found — running full load test via scripts/load-test.js"
    log "Target  : ${TARGET_URL}"
    log "VUs     : ${VUS}  Duration: ${DURATION}"
    exec k6 run \
        --env VAULT_ADDR="${VAULT_ADDR}" \
        --env VAULT_TOKEN="${VAULT_TOKEN}" \
        --env VAULT_TENANT_ID="${VAULT_TENANT_ID}" \
        --env VAULT_SECRET_PATH="${VAULT_SECRET_PATH}" \
        --env VUS="${VUS}" \
        --env DURATION="${DURATION}" \
        "${SCRIPT_DIR}/load-test.js"
fi

# ── Bash/curl fallback ────────────────────────────────────────────────────────
warn "k6 not found — using curl-based sequential sampler (install k6 for VU-mode)"
log ""
log "Target  : ${TARGET_URL}"
log "Samples : ${SAMPLES}  Concurrency: ${CONCURRENCY}"
log ""

# Check curl is present.
if ! command -v curl &>/dev/null; then
    err "curl is required but not found. Install curl and retry."
    exit 1
fi

# Pre-flight: verify the service is reachable. Warn but do not abort — the
# script is designed to be mergeable before services are up.
if ! curl -sf --max-time 2 "${VAULT_ADDR}/healthz" &>/dev/null; then
    warn "Service at ${VAULT_ADDR} is not reachable — running in dry-run mode"
    warn "(timings will be near-zero; start the service to get real numbers)"
fi

# Temporary directory for per-request timing data.
TMPDIR_LOCAL="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_LOCAL}"' EXIT

# ── Sample loop ───────────────────────────────────────────────────────────────
sample_request() {
    local idx="$1"
    # curl --write-out outputs the total time in seconds (fractional).
    local timing
    timing=$(curl -s -o /dev/null \
        --max-time 5 \
        --write-out "%{time_total}" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "X-Tenant-ID: ${VAULT_TENANT_ID}" \
        -H "Accept: application/json" \
        "${TARGET_URL}" 2>/dev/null || echo "0")
    # Convert seconds to milliseconds with two decimal places.
    printf "%.2f\n" "$(echo "${timing} * 1000" | bc -l 2>/dev/null || echo "0")" \
        > "${TMPDIR_LOCAL}/t_${idx}"
}

log "Sending ${SAMPLES} requests (concurrency ${CONCURRENCY})…"
REQUEST_IDX=0
RUNNING=0

for i in $(seq 1 "${SAMPLES}"); do
    sample_request "${i}" &
    RUNNING=$((RUNNING + 1))
    if [[ "${RUNNING}" -ge "${CONCURRENCY}" ]]; then
        wait -n 2>/dev/null || wait  # bash 4.3+; fall back to wait-all
        RUNNING=0
    fi
done
wait  # drain remaining background jobs

# ── Percentile calculation ────────────────────────────────────────────────────
# Collect all timing values, sort numerically, compute p50/p95/p99.
ALL_TIMINGS=()
while IFS= read -r -d '' file; do
    val="$(cat "${file}")"
    ALL_TIMINGS+=("${val}")
done < <(find "${TMPDIR_LOCAL}" -name "t_*" -print0 | sort -zV)

TOTAL="${#ALL_TIMINGS[@]}"
if [[ "${TOTAL}" -eq 0 ]]; then
    err "No timing data collected — service may be unreachable."
    exit 1
fi

# Sort numerically (bc-based approach; requires sort).
SORTED=($(printf '%s\n' "${ALL_TIMINGS[@]}" | sort -n))

p_at() {
    local pct="$1"
    local idx
    # Ceiling index for percentile.
    idx=$(echo "scale=0; (${TOTAL} * ${pct} + 99) / 100" | bc -l 2>/dev/null)
    idx=$((idx - 1))
    [[ "${idx}" -lt 0 ]] && idx=0
    [[ "${idx}" -ge "${TOTAL}" ]] && idx=$((TOTAL - 1))
    echo "${SORTED[${idx}]}"
}

P50=$(p_at 50)
P95=$(p_at 95)
P99=$(p_at 99)
MIN="${SORTED[0]}"
MAX="${SORTED[$((TOTAL - 1))]}"

# Sum for mean.
SUM="0"
for v in "${ALL_TIMINGS[@]}"; do
    SUM=$(echo "${SUM} + ${v}" | bc -l 2>/dev/null || echo "${SUM}")
done
MEAN=$(echo "scale=2; ${SUM} / ${TOTAL}" | bc -l 2>/dev/null || echo "N/A")

log ""
ok "=== WSLVault secret-read latency report ==="
printf "  Samples  : %d\n"        "${TOTAL}"
printf "  Min      : %s ms\n"     "${MIN}"
printf "  Mean     : %s ms\n"     "${MEAN}"
printf "  p50      : %s ms\n"     "${P50}"
printf "  p95      : %s ms\n"     "${P95}"
printf "  p99      : %s ms\n"     "${P99}"
printf "  Max      : %s ms\n"     "${MAX}"
log ""
log "To run a full VU-based load test: install k6 and re-run this script."
log "  macOS : brew install k6"
log "  Linux : https://k6.io/docs/getting-started/installation/"
