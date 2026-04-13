#!/usr/bin/env bash
# WSLVault Secret Lifecycle Example — bash + curl
#
# Shows the full flow:
#   1. Exchange an API key for a short-lived JWT
#   2. Write a secret (base64-encode the payload)
#   3. Read the secret back and decode it
#   4. List secrets
#   5. Read a specific version
#   6. Soft-delete a version
#
# Usage:
#   export VAULT_ADDR=http://localhost:8081
#   export VAULT_IDENTITY_ADDR=http://localhost:18082
#   export VAULT_TENANT_ID=019d813d-74bc-7660-89a7-f02fd9f2736d
#   export VAULT_API_KEY=<your-api-key>   # OR set direct headers below
#   ./wslvault_example.sh
#
# Prerequisites: curl, jq

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8081}"
VAULT_IDENTITY_ADDR="${VAULT_IDENTITY_ADDR:-http://localhost:18082}"
VAULT_TENANT_ID="${VAULT_TENANT_ID:-019d813d-74bc-7660-89a7-f02fd9f2736d}"
# Direct-access headers (used when skipping JWT auth, e.g. dev / service-to-service)
VAULT_PRINCIPAL_ID="${VAULT_PRINCIPAL_ID:-bash-example}"
VAULT_POLICIES="${VAULT_POLICIES:-admin}"

SECRET_PATH="demo/bash/db-password"

# ── Helper: add WSLVault auth headers to curl ─────────────────────────────────
#
# In production the gateway injects X-Principal-Id and X-Policies from the JWT.
# When calling the secret-engine directly (dev or service mesh), pass them manually.
vault_headers=(
  -H "X-Tenant-Id: ${VAULT_TENANT_ID}"
  -H "X-Principal-Id: ${VAULT_PRINCIPAL_ID}"
  -H "X-Policies: ${VAULT_POLICIES}"
)

# ── Optional: exchange an API key for a JWT ───────────────────────────────────
#
# Uncomment to use JWT-based auth instead of direct headers:
#
# if [[ -n "${VAULT_API_KEY:-}" ]]; then
#   echo "==> 0. Exchanging API key for JWT..."
#   JWT=$(curl -s -f -X POST "${VAULT_IDENTITY_ADDR}/v1/auth/api-key" \
#     -H "Content-Type: application/json" \
#     -d "{\"api_key\": \"${VAULT_API_KEY}\", \"tenant_id\": \"${VAULT_TENANT_ID}\"}" \
#     | jq -r '.token')
#   vault_headers=(-H "Authorization: Bearer ${JWT}")
# fi

# ── 1. Write a secret (base64-encode the payload) ────────────────────────────
echo "==> 1. Writing secret to '${SECRET_PATH}'..."
PAYLOAD=$(echo -n '{"username":"db_admin","password":"hunter2","host":"postgres:5432"}' | base64)

WRITE_RESP=$(curl -s -f -X POST "${VAULT_ADDR}/v1/secret/data/${SECRET_PATH}" \
  -H "Content-Type: application/json" \
  "${vault_headers[@]}" \
  -d "{\"data\": \"${PAYLOAD}\"}")

echo "${WRITE_RESP}" | jq .
SECRET_ID=$(echo "${WRITE_RESP}" | jq -r '.secret_id')
VERSION=$(echo "${WRITE_RESP}" | jq -r '.version')
echo "    secret_id=${SECRET_ID}  version=${VERSION}"

# ── 2. Read the secret back ───────────────────────────────────────────────────
echo ""
echo "==> 2. Reading secret from '${SECRET_PATH}'..."
READ_RESP=$(curl -s -f "${VAULT_ADDR}/v1/secret/data/${SECRET_PATH}" \
  "${vault_headers[@]}")

echo "${READ_RESP}" | jq .
DECODED=$(echo "${READ_RESP}" | jq -r '.data' | base64 -d)
echo "    Decoded payload: ${DECODED}"

# ── 3. List secrets ───────────────────────────────────────────────────────────
echo ""
echo "==> 3. Listing secrets..."
curl -s -f "${VAULT_ADDR}/v1/secret/list" \
  "${vault_headers[@]}" | jq .

# ── 4. Read a specific version ────────────────────────────────────────────────
echo ""
echo "==> 4. Reading version ${VERSION} explicitly..."
curl -s -f "${VAULT_ADDR}/v1/secret/data/${SECRET_PATH}?version=${VERSION}" \
  "${vault_headers[@]}" | jq '{version, created_at, data_decoded: (.data | @base64d)}'

# ── 5. Soft-delete the secret version ────────────────────────────────────────
echo ""
echo "==> 5. Soft-deleting version ${VERSION}..."
curl -s -f -X POST "${VAULT_ADDR}/v1/secret/delete/${SECRET_PATH}" \
  -H "Content-Type: application/json" \
  "${vault_headers[@]}" \
  -d "{\"versions\": [${VERSION}]}"
echo ""
echo "    Deleted (soft — data retained for undelete)."

echo ""
echo "Done! All WSLVault operations completed successfully."
