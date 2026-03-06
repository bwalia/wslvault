#!/usr/bin/env bash
# =============================================================================
# WSLVault End-to-End Test Suite
# =============================================================================
# Comprehensive feature tests for the WSLVault platform using wslvault-cli.
# Each test outputs [PASS] or [FAIL] for JUnit report generation.
#
# Usage: bash scripts/e2e-tests.sh
#
# Environment variables:
#   WSLVAULT_ADDR          - Secret engine endpoint (default: http://localhost:8081)
#   WSLVAULT_MCP_ADDR      - MCP server endpoint (default: http://localhost:8087)
#   WSLVAULT_TRANSIT_ADDR  - Transit engine endpoint (default: http://localhost:8086)
#   WSLVAULT_TENANT_ID     - Tenant ID for tests (default: test-tenant)
# =============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
VAULT_ADDR="${WSLVAULT_ADDR:-http://localhost:8081}"
MCP_ADDR="${WSLVAULT_MCP_ADDR:-http://localhost:8087}"
TRANSIT_ADDR="${WSLVAULT_TRANSIT_ADDR:-http://localhost:8086}"
TENANT_ID="${WSLVAULT_TENANT_ID:-test-tenant}"
CLI="./target/release/wslvault"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# ── Test helpers ─────────────────────────────────────────────────────────────

pass() {
    echo "[PASS] $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo "[FAIL] $1: $2"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

skip() {
    echo "[SKIP] $1: $2"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# Run a command and check exit code. Usage: run_test "test name" command args...
run_test() {
    local name="$1"
    shift
    if "$@" > /tmp/test_output.txt 2>&1; then
        pass "$name"
        return 0
    else
        fail "$name" "exit code $?, output: $(cat /tmp/test_output.txt | head -5)"
        return 1
    fi
}

# Check that a command's output contains expected text
assert_contains() {
    local name="$1"
    local expected="$2"
    shift 2
    local output
    if output=$("$@" 2>&1); then
        if echo "$output" | grep -q "$expected"; then
            pass "$name"
            return 0
        else
            fail "$name" "output did not contain '$expected': $output"
            return 1
        fi
    else
        fail "$name" "command failed with exit code $?"
        return 1
    fi
}

# Check HTTP endpoint returns 200
assert_http_ok() {
    local name="$1"
    local url="$2"
    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    if [ "$status" = "200" ]; then
        pass "$name"
    else
        fail "$name" "HTTP $status from $url"
    fi
}

echo "============================================================"
echo "  WSLVault End-to-End Test Suite"
echo "============================================================"
echo "  Server:  $VAULT_ADDR"
echo "  MCP:     $MCP_ADDR"
echo "  Transit: $TRANSIT_ADDR"
echo "  Tenant:  $TENANT_ID"
echo "  CLI:     $CLI"
echo "============================================================"
echo ""

# ── Test Suite 1: Service Health ─────────────────────────────────────────────
echo "--- Service Health Checks ---"

assert_http_ok "health: secret-engine" "$VAULT_ADDR/health"
assert_http_ok "health: mcp-server" "$MCP_ADDR/health"
assert_http_ok "health: transit-engine" "$TRANSIT_ADDR/health"
assert_http_ok "health: crypto-service" "http://localhost:8080/health"
assert_http_ok "health: identity-service" "http://localhost:8082/health"
assert_http_ok "health: policy-engine" "http://localhost:8083/health"
assert_http_ok "health: lease-manager" "http://localhost:8084/health"
assert_http_ok "health: audit-service" "http://localhost:8085/health"

echo ""

# ── Test Suite 2: CLI Basic Operations ───────────────────────────────────────
echo "--- CLI Basic Operations ---"

assert_contains "cli: --version" "wslvault" $CLI --version
assert_contains "cli: --help" "WSLVault CLI" $CLI --help || true
run_test "cli: completion bash" $CLI completion bash
run_test "cli: completion zsh" $CLI completion zsh

echo ""

# ── Test Suite 3: KV Secrets ─────────────────────────────────────────────────
echo "--- KV Secret Operations ---"

# Write a secret via REST API directly (CLI depends on running server)
SECRET_PATH="e2e-test/database/creds"

# Write via curl (the CLI calls the same endpoint)
run_test "secret: write via REST" \
    curl -sf -X POST "$VAULT_ADDR/v1/secret/data/$SECRET_PATH" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-Id: $TENANT_ID" \
    -d '{"data":{"username":"admin","password":"s3cret-p@ss!"}}'

# Read it back
run_test "secret: read via REST" \
    curl -sf "$VAULT_ADDR/v1/secret/data/$SECRET_PATH" \
    -H "X-Tenant-Id: $TENANT_ID"

# List secrets
run_test "secret: list via REST" \
    curl -sf "$VAULT_ADDR/v1/secret/list?prefix=e2e-test" \
    -H "X-Tenant-Id: $TENANT_ID"

# Write another version
run_test "secret: write version 2" \
    curl -sf -X POST "$VAULT_ADDR/v1/secret/data/$SECRET_PATH" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-Id: $TENANT_ID" \
    -d '{"data":{"username":"admin","password":"new-p@ss-v2"}}'

# Get metadata
run_test "secret: get metadata" \
    curl -sf "$VAULT_ADDR/v1/secret/metadata/$SECRET_PATH" \
    -H "X-Tenant-Id: $TENANT_ID"

# Delete (soft)
run_test "secret: soft delete" \
    curl -sf -X POST "$VAULT_ADDR/v1/secret/delete/$SECRET_PATH" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-Id: $TENANT_ID" \
    -d '{"versions":[1]}'

echo ""

# ── Test Suite 4: Transit Encryption ─────────────────────────────────────────
echo "--- Transit Encryption Operations ---"

# Create a transit key
run_test "transit: create key" \
    curl -sf -X POST "$TRANSIT_ADDR/v1/transit/keys/e2e-test-key" \
    -H "Content-Type: application/json"

# Encrypt data
ENCRYPT_RESULT=$(curl -sf -X POST "$TRANSIT_ADDR/v1/transit/encrypt/e2e-test-key" \
    -H "Content-Type: application/json" \
    -d '{"plaintext":"c2Vuc2l0aXZlIGRhdGE="}' 2>/dev/null || echo "")

if [ -n "$ENCRYPT_RESULT" ]; then
    pass "transit: encrypt data"
    CIPHERTEXT=$(echo "$ENCRYPT_RESULT" | grep -o '"ciphertext":"[^"]*"' | cut -d'"' -f4 || echo "")

    # Decrypt the ciphertext
    if [ -n "$CIPHERTEXT" ]; then
        run_test "transit: decrypt data" \
            curl -sf -X POST "$TRANSIT_ADDR/v1/transit/decrypt/e2e-test-key" \
            -H "Content-Type: application/json" \
            -d "{\"ciphertext\":\"$CIPHERTEXT\"}"
    else
        skip "transit: decrypt data" "no ciphertext to decrypt"
    fi
else
    fail "transit: encrypt data" "no response from transit engine"
    skip "transit: decrypt data" "encrypt failed"
fi

# Sign data
run_test "transit: sign data" \
    curl -sf -X POST "$TRANSIT_ADDR/v1/transit/sign/e2e-test-key" \
    -H "Content-Type: application/json" \
    -d '{"data":"ZGF0YSB0byBzaWdu"}'

# Rotate key
run_test "transit: rotate key" \
    curl -sf -X POST "$TRANSIT_ADDR/v1/transit/keys/e2e-test-key/rotate"

echo ""

# ── Test Suite 5: MCP Server ────────────────────────────────────────────────
echo "--- MCP Server Operations ---"

# Server info
assert_http_ok "mcp: server info" "$MCP_ADDR/v1/mcp/info"

# List available tools
run_test "mcp: list tools" \
    curl -sf "$MCP_ADDR/v1/mcp/tools"

# Verify tool list contains expected tools
assert_contains "mcp: has read_secret tool" "read_secret" \
    curl -sf "$MCP_ADDR/v1/mcp/tools"

assert_contains "mcp: has encrypt_data tool" "encrypt_data" \
    curl -sf "$MCP_ADDR/v1/mcp/tools"

assert_contains "mcp: has list_secrets tool" "list_secrets" \
    curl -sf "$MCP_ADDR/v1/mcp/tools"

# Call MCP tool: list secrets
run_test "mcp: call list_secrets tool" \
    curl -sf -X POST "$MCP_ADDR/v1/mcp/tools/call" \
    -H "Content-Type: application/json" \
    -d '{"name":"list_secrets","arguments":{"prefix":"e2e-test","tenant_id":"test-tenant"}}'

echo ""

# ── Test Suite 6: Identity Service ──────────────────────────────────────────
echo "--- Identity Service Operations ---"

assert_http_ok "identity: health" "http://localhost:8082/healthz"

echo ""

# ── Test Suite 7: Policy Engine ─────────────────────────────────────────────
echo "--- Policy Engine Operations ---"

assert_http_ok "policy: health" "http://localhost:8083/health"

echo ""

# ── Test Suite 8: Lease Manager ─────────────────────────────────────────────
echo "--- Lease Manager Operations ---"

assert_http_ok "lease: health" "http://localhost:8084/health"

echo ""

# ── Test Suite 9: Audit Service ─────────────────────────────────────────────
echo "--- Audit Service Operations ---"

assert_http_ok "audit: health" "http://localhost:8085/health"

echo ""

# ── Test Suite 10: Cross-Service Integration ────────────────────────────────
echo "--- Cross-Service Integration ---"

# Write a secret and verify it persists across a re-read
INTEGRATION_PATH="e2e-test/integration/round-trip"
WRITE_RESULT=$(curl -sf -X POST "$VAULT_ADDR/v1/secret/data/$INTEGRATION_PATH" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-Id: $TENANT_ID" \
    -d '{"data":{"key":"integration-test-value-42"}}' 2>/dev/null || echo "")

if [ -n "$WRITE_RESULT" ]; then
    READ_RESULT=$(curl -sf "$VAULT_ADDR/v1/secret/data/$INTEGRATION_PATH" \
        -H "X-Tenant-Id: $TENANT_ID" 2>/dev/null || echo "")
    if echo "$READ_RESULT" | grep -q "integration-test-value-42"; then
        pass "integration: write-then-read round trip"
    else
        fail "integration: write-then-read round trip" "read did not return written value"
    fi
else
    fail "integration: write-then-read round trip" "write failed"
fi

echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "============================================================"
echo "  Test Results"
echo "============================================================"
echo "  Passed:  $PASS_COUNT"
echo "  Failed:  $FAIL_COUNT"
echo "  Skipped: $SKIP_COUNT"
echo "  Total:   $((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))"
echo "============================================================"

if [ $FAIL_COUNT -gt 0 ]; then
    echo ""
    echo "RESULT: FAILED ($FAIL_COUNT test(s) failed)"
    exit 1
else
    echo ""
    echo "RESULT: ALL TESTS PASSED"
    exit 0
fi
