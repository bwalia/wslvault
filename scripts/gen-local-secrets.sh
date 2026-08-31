#!/usr/bin/env bash
# Generate the secrets a local WSLVault needs.
#
# Writes .env.local, which .gitignore already covers (.env.*). Refuses to
# overwrite: regenerating the root key would orphan every tenant KEK already
# encrypted under the old one, and regenerating the JWT secret would invalidate
# every legacy token in flight. Delete the file deliberately if you mean it.
#
# These are LOCAL DEVELOPMENT values. For anything real, generate them into a
# secret manager and reference them via `secrets.existingSecret` in the Helm
# chart — the chart refuses to render without them precisely so a placeholder
# cannot reach production.
set -euo pipefail

OUT="${1:-.env.local}"

if [[ -e "$OUT" ]]; then
  echo "refusing to overwrite $OUT" >&2
  echo "  the root key there already protects data in your local database." >&2
  echo "  delete it deliberately if you want a fresh vault." >&2
  exit 1
fi

# openssl rand -base64 32 → exactly 32 bytes, which is what the 256-bit
# AES/HKDF keys require. The services validate the decoded length and refuse to
# start on anything else.
k32() { openssl rand -base64 32; }
k64() { openssl rand -base64 64 | tr -d '\n'; }

umask 077   # the file must not be world-readable, even for a moment

cat > "$OUT" <<EOF
# WSLVault local development secrets — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
#
# Ignored by git (.gitignore covers .env.*). Do not commit, do not paste into
# an issue, and do not reuse any of it outside this machine.

# ── Key custody ──────────────────────────────────────────────────────────────
# Root KEK. Wraps every tenant KEK, and therefore everything below them:
# transit key material, PKI CA keys, per-tenant token signing keys, TOTP
# secrets. Lose it and the vault is unreadable; leak it and it is all readable.
#
# In production this is replaced by the seal (POST /v1/sys/init) so the root key
# is Shamir-split rather than sitting in an environment variable.
VAULT_ROOT_KEY=$(k32)

# Signs PKI CA private keys at rest. Separate from the root key today; folding
# the two together is tracked work.
PKI_ROOT_KEY=$(k32)

# ── Tokens ───────────────────────────────────────────────────────────────────
# Legacy shared HS256 secret. Only used for tokens issued before per-tenant
# Ed25519 signing keys existed; new tokens do not use it. Still required at
# startup, and must be >= 32 bytes.
VAULT_JWT_SECRET=$(k64)

# Break-glass platform credential. Creates the first tenant and the first API
# key, before any other credential exists. Bypasses MFA and answers to no
# tenant — once you have a superuser key with an authenticator, prefer that.
VAULT_ADMIN_TOKEN=$(k32)

# Required to seal the vault (POST /v1/sys/seal). Without it, anyone who can
# reach crypto-service can take the vault offline.
VAULT_OPERATOR_TOKEN=$(k32)

# ── Integrity ────────────────────────────────────────────────────────────────
# Master for the audit hash chain. Per-tenant keys are derived from it with
# HKDF. The service refuses to start without it: a log signed with a
# well-known key is not signed.
AUDIT_SIGNING_KEY=$(k64)

# ── Peers and perimeter ──────────────────────────────────────────────────────
# Shared across every region in a replication mesh. Must be byte-identical on
# all of them, or peers cannot authenticate to each other.
REPLICATION_PEER_TOKEN=$(k32)

# Proves a request came through the gateway. Backends fail OPEN when this is
# unset, so set it whenever a gateway is actually in front of them.
VAULT_GATEWAY_SECRET=$(k32)

# ── Local infrastructure ─────────────────────────────────────────────────────
POSTGRES_PASSWORD=$(openssl rand -hex 16)
EOF

chmod 600 "$OUT"

echo "wrote $OUT (mode 600)"
echo
echo "  Every value is freshly random. VAULT_ROOT_KEY now protects your local"
echo "  database — keep the file, or the data in it becomes unreadable."
echo
echo "  Load it with:  set -a; . ./$OUT; set +a"
