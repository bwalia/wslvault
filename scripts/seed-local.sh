#!/usr/bin/env bash
# Seed a local WSLVault: one tenant, one human key with an authenticator, one
# machine key, a policy, and a few secrets.
#
# Prints a working login at the end. Requires .env.local (see
# scripts/gen-local-secrets.sh) and a running stack (docs/operations/local-testing.md).
set -euo pipefail

IDENTITY="${IDENTITY:-http://localhost:18082}"
SECRETS="${SECRETS:-http://localhost:3012/api/secret}"
POLICY="${POLICY:-http://localhost:3012/api/policy}"

[[ -f .env.local ]] || { echo "no .env.local — run scripts/gen-local-secrets.sh first" >&2; exit 1; }
set -a; . ./.env.local; set +a

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
api() { curl -sS "$@"; }

say "1. Tenant"
TENANT=$(api -X POST "$IDENTITY/v1/tenants" \
  -H "X-Admin-Token: $VAULT_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"slug":"acme","display_name":"Acme Corp","tier":"shared","root_key_id":"acme-kek"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
echo "   acme → $TENANT"

say "2. Keys"
# A person: requires an authenticator.
USER_KEY=$(api -X POST "$IDENTITY/v1/api-keys" \
  -H "X-Admin-Token: $VAULT_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"name\":\"local-user\",\"tenant_id\":\"$TENANT\",\"policies\":[\"admin\"],\"mfa_required\":true}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["key"])')
echo "   local-user  (MFA required)"

# A machine: one-step exchange, as ESO and CI need.
MACHINE_KEY=$(api -X POST "$IDENTITY/v1/api-keys" \
  -H "X-Admin-Token: $VAULT_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"name\":\"local-machine\",\"tenant_id\":\"$TENANT\",\"policies\":[\"admin\"]}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["key"])')
echo "   local-machine  (no MFA)"

say "3. Authenticator"
TOTP_SECRET=$(api -X POST "$IDENTITY/v1/auth/mfa/totp/enroll" \
  -H 'Content-Type: application/json' -d "{\"api_key\":\"$USER_KEY\"}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["secret"])')

code() { python3 - "$TOTP_SECRET" <<'PY'
import base64, hashlib, hmac, struct, sys, time
s = sys.argv[1].upper()
key = base64.b32decode(s + "=" * (-len(s) % 8))
d = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
o = d[-1] & 0x0F
print("%06d" % ((struct.unpack(">I", d[o:o+4])[0] & 0x7FFFFFFF) % 1000000))
PY
}

api -X POST "$IDENTITY/v1/auth/mfa/totp/confirm" -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$USER_KEY\",\"code\":\"$(code)\"}" >/dev/null
echo "   enrolled and confirmed"

say "4. Policy"
# The machine key needs no second factor, so it is the simplest way to obtain a
# token for the setup calls below.
TOKEN=$(api -X POST "$IDENTITY/v1/auth/api-key" -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$MACHINE_KEY\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')

api -X PUT "$POLICY/v1/policies/admin" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"admin","rules":[{"paths":["secret/**"],"capabilities":["read","write","list","delete"]}]}' \
  >/dev/null
echo "   'admin' grants read/write/list/delete on secret/**"

say "5. Secrets"
put() {
  local b64; b64=$(printf '%s' "$2" | base64 | tr -d '\n')
  api -X POST "$SECRETS/v1/secret/data/$1" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d "{\"data\":\"$b64\"}" >/dev/null
  echo "   $1"
}
put "prod/postgres/primary" "{\"host\":\"db.prod.internal\",\"port\":\"5432\",\"username\":\"app\",\"password\":\"$(openssl rand -base64 24)\"}"
put "prod/redis/cache"      "{\"host\":\"redis.prod.internal\",\"port\":\"6379\",\"password\":\"$(openssl rand -base64 24)\"}"
put "prod/stripe/api"       "{\"publishable_key\":\"pk_test_$(openssl rand -hex 12)\",\"secret_key\":\"sk_test_$(openssl rand -hex 16)\"}"
put "staging/postgres/main" "{\"host\":\"db.staging.internal\",\"port\":\"5432\",\"username\":\"app\",\"password\":\"$(openssl rand -base64 24)\"}"
put "shared/smtp/relay"     "{\"host\":\"smtp.internal\",\"port\":\"587\",\"username\":\"noreply@acme.test\",\"password\":\"$(openssl rand -base64 18)\"}"

cat > .local-login <<EOF
# Sign in to the UI with these. Generated $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Ignored by git; delete freely and re-run scripts/seed-local.sh.

UI            http://localhost:3012
API_KEY       $USER_KEY
TOTP_SECRET   $TOTP_SECRET

# Machine key — exchanges for a token in one step, no code needed.
MACHINE_KEY   $MACHINE_KEY

# Current 6-digit code:
#   python3 -c "import base64,hashlib,hmac,struct,time,sys;s='$TOTP_SECRET';k=base64.b32decode(s+'='*(-len(s)%8));d=hmac.new(k,struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest();o=d[-1]&15;print('%06d'%((struct.unpack('>I',d[o:o+4])[0]&0x7fffffff)%1000000))"
EOF
chmod 600 .local-login

say "Done"
echo "   UI:      http://localhost:3012"
echo "   API key: $USER_KEY"
echo "   Code:    $(code)   (valid ~30s)"
echo
echo "   Saved to .local-login (mode 600, git-ignored)."
