#!/usr/bin/env bash
# Seed a local WSLVault: one tenant, one human key with an authenticator, one
# machine key, a policy, and a few secrets. Prints a working login at the end.
#
# Safe to re-run. The tenant is found-or-created; keys with a name that already
# exists are ROTATED rather than duplicated, which is also what makes re-running
# work at all — the raw key is only ever shown once, so recovering an existing
# one is impossible by design. Rotation issues a fresh key under a new id, and
# the new id carries no authenticator, so enrolment starts clean.
#
# Requires .env.local (scripts/gen-local-secrets.sh) and a running stack
# (docs/operations/local-testing.md).
set -euo pipefail

IDENTITY="${IDENTITY:-http://localhost:18082}"
SECRETS="${SECRETS:-http://localhost:3012/api/secret}"
POLICY="${POLICY:-http://localhost:3012/api/policy}"

[[ -f .env.local ]] || { echo "no .env.local — run scripts/gen-local-secrets.sh first" >&2; exit 1; }
set -a; . ./.env.local; set +a

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
die()  { printf '\n\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Pull a field out of a JSON response, or fail with the API's own error text.
#
# The previous version piped straight into json.load(...)["id"], so any error
# response surfaced as `KeyError: 'id'` — a Python traceback that says nothing
# about what the server actually refused.
field() {
  local body="$1" key="$2" what="$3"
  printf '%s' "$body" | python3 -c '
import json, sys
key, what = sys.argv[1], sys.argv[2]
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception:
    sys.exit(f"{what}: server did not return JSON: {raw[:200]}")
if isinstance(d, dict) and key in d:
    print(d[key]); sys.exit(0)
msg = d.get("message") or d.get("errors") or raw[:200] if isinstance(d, dict) else raw[:200]
sys.exit(f"{what}: {msg}")
' "$key" "$what"
}

admin() { curl -sS -H "X-Admin-Token: $VAULT_ADMIN_TOKEN" -H 'Content-Type: application/json' "$@"; }

say "1. Tenant"
CREATE=$(admin -X POST "$IDENTITY/v1/tenants" \
  -d '{"slug":"acme","display_name":"Acme Corp","tier":"shared","root_key_id":"acme-kek"}')

if TENANT=$(field "$CREATE" id "create tenant" 2>/dev/null); then
  echo "   created acme → $TENANT"
else
  # Already exists. Find it rather than failing: re-running this script should
  # top up a local vault, not demand a database reset.
  TENANT=$(admin "$IDENTITY/v1/tenants" | python3 -c '
import json, sys
for t in json.load(sys.stdin):
    if t.get("slug") == "acme":
        print(t["id"]); break
else:
    sys.exit("tenant acme neither created nor found")
')
  echo "   reusing acme → $TENANT"
fi

# Create a key, or rotate the existing one of that name to get a fresh secret.
mint_key() {
  local name="$1" extra="$2"
  local body
  body=$(admin -X POST "$IDENTITY/v1/api-keys" \
    -d "{\"name\":\"$name\",\"tenant_id\":\"$TENANT\",\"policies\":[\"admin\"]$extra}")

  if printf '%s' "$body" | grep -q '"key"'; then
    field "$body" key "create key $name"
    return
  fi

  # Duplicate name. The raw key was shown once and cannot be read back, so
  # rotation is the only way to obtain a usable one — and it also gives the key
  # a new id, so any stale authenticator enrolment is left behind.
  local id
  id=$(admin -H "X-Tenant-Id: $TENANT" "$IDENTITY/v1/api-keys" | python3 -c '
import json, sys
name = sys.argv[1]
for k in json.load(sys.stdin):
    if k.get("name") == name:
        print(k["id"]); break
else:
    sys.exit(f"key {name} neither created nor found")
' "$name") || die "could not create or locate key $name"

  admin -X POST "$IDENTITY/v1/api-keys/$id/rotate" -H "X-Tenant-Id: $TENANT" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("key") or sys.exit(d.get("message","rotate failed")))'
}

say "2. Keys"
USER_KEY=$(mint_key "local-user" ',"mfa_required":true')   || die "user key"
echo "   local-user     (MFA required)"
MACHINE_KEY=$(mint_key "local-machine" '')                 || die "machine key"
echo "   local-machine  (no MFA)"

say "3. Authenticator"
ENROLL=$(curl -sS -X POST "$IDENTITY/v1/auth/mfa/totp/enroll" \
  -H 'Content-Type: application/json' -d "{\"api_key\":\"$USER_KEY\"}")
TOTP_SECRET=$(field "$ENROLL" secret "enrol authenticator") || die "enrolment"

# Recovery codes are returned once and stored only as hashes, so if they are not
# captured here they are gone. Without them, a lost phone means a lost account.
RECOVERY=$(printf '%s' "$ENROLL" | python3 -c '
import json, sys
print("\n".join(json.load(sys.stdin).get("recovery_codes", [])))
')

code() { python3 - "$TOTP_SECRET" <<'PY'
import base64, hashlib, hmac, struct, sys, time
s = sys.argv[1].upper()
key = base64.b32decode(s + "=" * (-len(s) % 8))
d = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
o = d[-1] & 0x0F
print("%06d" % ((struct.unpack(">I", d[o:o+4])[0] & 0x7FFFFFFF) % 1000000))
PY
}

CONFIRM=$(curl -sS -X POST "$IDENTITY/v1/auth/mfa/totp/confirm" -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$USER_KEY\",\"code\":\"$(code)\"}")
printf '%s' "$CONFIRM" | grep -q '"confirmed"' || die "confirm failed: $CONFIRM"
echo "   enrolled and confirmed"

say "4. Policy"
# The machine key needs no second factor, so it is the simplest way to get a
# token for the setup calls below.
TOKEN=$(field "$(curl -sS -X POST "$IDENTITY/v1/auth/api-key" -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$MACHINE_KEY\"}")" token "exchange machine key") || die "machine login"

curl -sS -X PUT "$POLICY/v1/policies/admin" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"admin","rules":[{"paths":["secret/**"],"capabilities":["read","write","list","delete"]}]}' \
  >/dev/null
echo "   'admin' grants read/write/list/delete on secret/**"

say "5. Secrets"
put() {
  local b64; b64=$(printf '%s' "$2" | base64 | tr -d '\n')
  curl -sS -X POST "$SECRETS/v1/secret/data/$1" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d "{\"data\":\"$b64\"}" >/dev/null
  echo "   $1"
}
put "prod/postgres/primary" "{\"host\":\"db.prod.internal\",\"port\":\"5432\",\"username\":\"app\",\"password\":\"$(openssl rand -base64 24)\"}"
put "prod/redis/cache"      "{\"host\":\"redis.prod.internal\",\"port\":\"6379\",\"password\":\"$(openssl rand -base64 24)\"}"
put "prod/stripe/api"       "{\"publishable_key\":\"pk_test_$(openssl rand -hex 12)\",\"secret_key\":\"sk_test_$(openssl rand -hex 16)\"}"
put "staging/postgres/main" "{\"host\":\"db.staging.internal\",\"port\":\"5432\",\"username\":\"app\",\"password\":\"$(openssl rand -base64 24)\"}"
put "shared/smtp/relay"     "{\"host\":\"smtp.internal\",\"port\":\"587\",\"username\":\"noreply@acme.test\",\"password\":\"$(openssl rand -base64 18)\"}"

umask 077
cat > .local-login <<EOF
# Sign in to the UI with these. Git-ignored; delete freely and re-run
# scripts/seed-local.sh to mint a new set.

UI            http://localhost:3012
API_KEY       $USER_KEY
TOTP_SECRET   $TOTP_SECRET

# Machine key — exchanges for a token in one step, no code needed.
MACHINE_KEY   $MACHINE_KEY

# RECOVERY CODES — use one INSTEAD of the 6-digit code if you lose your phone.
# Each works exactly once. Only their hashes are stored, so this is the only
# copy: print it or move it to a password manager, and not onto the same phone.
$(printf '%s' "$RECOVERY" | sed 's/^/#   /')

# Current 6-digit code:
#   python3 -c "import base64,hashlib,hmac,struct,time;s='$TOTP_SECRET';k=base64.b32decode(s+'='*(-len(s)%8));d=hmac.new(k,struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest();o=d[-1]&15;print('%06d'%((struct.unpack('>I',d[o:o+4])[0]&0x7fffffff)%1000000))"
EOF
chmod 600 .local-login

say "Done"
echo "   UI:      http://localhost:3012"
echo "   API key: $USER_KEY"
echo "   Code:    $(code)   (valid ~30s)"
echo
echo "   Saved to .local-login (mode 600, git-ignored)."
