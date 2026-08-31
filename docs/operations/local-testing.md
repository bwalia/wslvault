# Running WSLVault locally

Everything below runs in Docker; no local Rust toolchain is needed. It stands up
the two services the authentication flow needs — crypto-service (key custody)
and identity-service (tokens, MFA) — plus PostgreSQL.

Ports are deliberately non-default (`55432`, `18080`, `18082`) so this does not
collide with anything else already running.

## 0. Secrets

Every service needs key material, and none of it has a default — the Helm chart
refuses to render without it, precisely so a placeholder cannot reach
production. Generate a local set:

```bash
./scripts/gen-local-secrets.sh          # writes .env.local, mode 600
set -a; . ./.env.local; set +a          # load it into your shell
```

`.env.local` is covered by `.gitignore` (`.env.*`) and the script refuses to
overwrite an existing file: regenerating `VAULT_ROOT_KEY` would orphan every
tenant KEK already encrypted under the old one, which makes the data in your
local database permanently unreadable.

| Variable | Protects |
|---|---|
| `VAULT_ROOT_KEY` | Every tenant KEK, and so transit keys, PKI CA keys, token signing keys and TOTP secrets |
| `PKI_ROOT_KEY` | CA private keys at rest |
| `VAULT_JWT_SECRET` | Legacy HS256 tokens (new ones use per-tenant Ed25519) |
| `VAULT_ADMIN_TOKEN` | Break-glass: creates the first tenant and key |
| `VAULT_OPERATOR_TOKEN` | Sealing the vault |
| `AUDIT_SIGNING_KEY` | The audit hash chain; per-tenant keys derive from it |
| `REPLICATION_PEER_TOKEN` | The peer replication API |
| `VAULT_GATEWAY_SECRET` | Proves a request came through the gateway |

### These are not login credentials

Nothing in `.env.local` signs you in. They are *deployment* secrets — what the
services need to start. You sign in with an **API key**, which is issued by
`POST /v1/api-keys` and always starts `wslv_`.

`VAULT_ADMIN_TOKEN` is the easiest to confuse: it is a bootstrap credential sent
as the `X-Admin-Token` **header** to create the first tenant and key. Pasting it
into the login form gives:

```
api key format is invalid; expected 'wslv_<base64url>'
```

## 1. Database

```bash
docker network create wv-demo
docker run -d --name wv-pg --network wv-demo \
  -e POSTGRES_PASSWORD=devpassword -e POSTGRES_USER=wslvault -e POSTGRES_DB=wslvault \
  -p 55432:5432 postgres:16-alpine

until docker exec wv-pg psql -U wslvault -d wslvault -c 'SELECT 1' >/dev/null 2>&1; do sleep 2; done
for f in storage/postgres/init/*.sql; do
  docker exec -i wv-pg psql -U wslvault -d wslvault -v ON_ERROR_STOP=1 -q < "$f"
done
```

## 2. Build and run the services

```bash
docker run --rm -v "$PWD":/w -w /w \
  -v wslvault-cargo-registry:/usr/local/cargo/registry -v wslvault-target:/w/target \
  rust:1-bookworm bash -c '
    apt-get update -qq && apt-get install -y -qq protobuf-compiler
    cargo build -p crypto-service -p identity-service'

export ROOT_KEY=$(openssl rand -base64 32)

docker run -d --name wv-crypto --network wv-demo \
  -v "$PWD":/w -w /w -v wslvault-target:/w/target \
  -e DATABASE_URL="postgres://wslvault:devpassword@wv-pg:5432/wslvault" \
  -e VAULT_ROOT_KEY="$ROOT_KEY" -e RUST_LOG=info \
  -p 18080:8080 rust:1-bookworm ./target/debug/crypto-service

docker run -d --name wv-identity --network wv-demo \
  -v "$PWD":/w -w /w -v wslvault-target:/w/target \
  -e DATABASE_URL="postgres://wslvault:devpassword@wv-pg:5432/wslvault" \
  -e CRYPTO_SERVICE_ENDPOINT="http://wv-crypto:50051" \
  -e VAULT_JWT_SECRET="dev-jwt-secret-at-least-32-bytes-long!!" \
  -e VAULT_ADMIN_TOKEN="dev-admin-token" \
  -e VAULT_HTTP_ADDR="0.0.0.0:8082" -e RUST_LOG=info \
  -p 18082:8082 rust:1-bookworm ./target/debug/identity-service
```

`docker logs wv-identity | grep signing` should say
`per-tenant token signing keys enabled`. If it says they are disabled, one of
`DATABASE_URL` or `CRYPTO_SERVICE_ENDPOINT` is missing and tokens will fall back
to the shared HS256 secret.

## 3. A tenant and a key

```bash
TENANT=$(docker exec wv-pg psql -U wslvault -d wslvault -qtA -c \
 "INSERT INTO system.tenants (id,slug,display_name,tier,root_key_id)
  VALUES (gen_random_uuid(),'acme','Acme Corp','shared','k1') RETURNING id;")

# mfa_required:true → this key must present an authenticator code.
# Omit it (the default) for machine keys: ESO, CI, the SDKs.
curl -sX POST localhost:18082/v1/api-keys \
  -H "X-Admin-Token: dev-admin-token" -H 'Content-Type: application/json' \
  -d "{\"name\":\"alice\",\"tenant_id\":\"$TENANT\",\"policies\":[\"admin\"],\"mfa_required\":true}"
```

The `key` in the response is shown once. Save it as `$KEY`.

## 4. Enrol an authenticator

```bash
curl -sX POST localhost:18082/v1/auth/mfa/totp/enroll \
  -H 'Content-Type: application/json' -d "{\"api_key\":\"$KEY\"}"
```

Returns:

| Field | What to do with it |
|---|---|
| `secret` | Base32. Type it into your app if you cannot scan. |
| `otpauth_uri` | Render as a QR code and scan it. |
| `recovery_codes` | Eight single-use fallbacks. **Shown once**; only hashes are stored. |

Turn the URI into a scannable QR without sending it anywhere:

```bash
# macOS: brew install qrencode
qrencode -t ANSIUTF8 "otpauth://totp/WSLVault:...&secret=...&issuer=WSLVault"
```

Do not paste the URI into an online QR generator — it contains the secret.

Then confirm, which is what activates the enrolment:

```bash
curl -sX POST localhost:18082/v1/auth/mfa/totp/confirm \
  -H 'Content-Type: application/json' -d "{\"api_key\":\"$KEY\",\"code\":\"123456\"}"
```

## 5. Log in

```bash
# Step 1 — the key gets you a challenge, not a token.
curl -sX POST localhost:18082/v1/auth/api-key \
     -H 'Content-Type: application/json' -d "{\"api_key\":\"$KEY\"}"
# → {"mfa_required":true,"challenge":"…","expires_in_seconds":120}

# Step 2 — the code turns it into a session.
curl -sX POST localhost:18082/v1/auth/mfa/totp \
     -H 'Content-Type: application/json' \
     -d "{\"challenge\":\"$CHALLENGE\",\"code\":\"$(cat-from-your-phone)\"}"
```

## Seeding

Once the stack is up, this creates a tenant, a human key with an authenticator
enrolled, a machine key, a policy and a few secrets — then prints a working
login:

```bash
./scripts/seed-local.sh
```

It writes `.local-login` (mode 600, git-ignored) with the API key, the TOTP
secret, and a one-liner that prints the current 6-digit code.

## The UI

The dashboard needs more than identity-service. Build and start the rest, then
point the UI at them.

```bash
docker run --rm -v "$PWD":/w -w /w \
  -v wslvault-cargo-registry:/usr/local/cargo/registry -v wslvault-target:/w/target \
  rust:1-bookworm bash -c '
    apt-get update -qq && apt-get install -y -qq protobuf-compiler
    cargo build -p secret-engine -p policy-engine -p audit-service -p lease-manager'

DB="postgres://wslvault:devpassword@wv-pg:5432/wslvault"
JWKS="http://wv-identity:8082/v1/identity/.well-known/jwks.json"
RUN="docker run -d --network wv-demo -v $PWD:/w -w /w -v wslvault-target:/w/target"

$RUN --name wv-policy -e DATABASE_URL=$DB -e VAULT_JWKS_URL=$JWKS \
     -e VAULT_HEALTH_ADDR=0.0.0.0:8083 rust:1-bookworm ./target/debug/policy-engine

$RUN --name wv-audit -e DATABASE_URL=$DB \
     -e AUDIT_SIGNING_KEY="dev-audit-signing-key-at-least-32b!!" \
     rust:1-bookworm ./target/debug/audit-service

$RUN --name wv-lease -e DATABASE_URL=$DB rust:1-bookworm ./target/debug/lease-manager

$RUN --name wv-secret -e DATABASE_URL=$DB -e VAULT_JWKS_URL=$JWKS \
     -e CRYPTO_SERVICE_ENDPOINT=http://wv-crypto:50051 \
     -e POLICY_ENGINE_ENDPOINT=http://wv-policy:50053 \
     -e AUDIT_SERVICE_ENDPOINT=http://wv-audit:50056 \
     -e LEASE_MANAGER_ENDPOINT=http://wv-lease:50055 \
     -e VAULT_HTTP_ADDR=0.0.0.0:8081 rust:1-bookworm ./target/debug/secret-engine
```

`VAULT_JWKS_URL` is what lets a service verify per-tenant tokens. Without it
they fall back to the shared HS256 secret and reject every EdDSA token.

Then the UI. It runs on 3011 inside the container; publish it wherever is free:

```bash
cd ui/apps/vault-ui
docker run -d --name wv-ui --network wv-demo -v "$PWD":/app -w /app \
  -e IDENTITY_URL=http://wv-identity:8082 \
  -e SECRET_URL=http://wv-secret:8081 \
  -e POLICY_URL=http://wv-policy:8083 \
  -e AUDIT_URL=http://wv-audit:8085 \
  -p 3012:3011 node:22-alpine npx next dev --turbopack -p 3011 -H 0.0.0.0
```

Open **http://localhost:3012**, sign in with the API key, and enter a code from
your authenticator.

### A tenant needs a policy before it can read anything

A fresh tenant's key carries a policy *name*; nothing grants it yet, so the
Secrets tile shows `permission denied on secret/list`. That is the policy engine
working, not a fault. Create the document:

```bash
curl -sX PUT localhost:3012/api/policy/v1/policies/admin \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"admin","rules":[{"paths":["secret/**","secret/*"],
       "capabilities":["read","write","list","delete"]}]}'
```

Policies are scoped to the caller's tenant, so an `admin` policy in one tenant
grants nothing in another.

### Known gaps in a partial stack

| Tile | Needs |
|---|---|
| Secrets | secret-engine **and** a policy granting `list` |
| Transit | transit-engine (not started above) |
| Regions, Cluster | region-health |
| Audit log | The UI calls an HTTP path audit-service does not serve — a pre-existing mismatch, see `docs/UI-API-AUDIT.md` |

## Generating codes without a phone

Useful in CI and for reproducing a failure. This is plain stdlib and shares no
code with the implementation, which is what makes it a real interoperability
check rather than a self-consistency one:

```python
import base64, hashlib, hmac, struct, time

def totp(secret_b32):
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", digest[off:off+4])[0] & 0x7FFFFFFF) % 1000000)
```

## Inspecting what happened

```bash
# The token is EdDSA and names the tenant key that signed it.
python3 -c "import base64,json,sys; h=sys.argv[1].split('.')[0]; \
  print(json.loads(base64.urlsafe_b64decode(h+'='*(-len(h)%4))))" "$TOKEN"

# Public keys only — this endpoint is safe to expose to verifiers.
curl -s localhost:18082/v1/identity/.well-known/jwks.json

# One signing key per tenant; NULL is the system key for superuser tokens.
docker exec wv-pg psql -U wslvault -d wslvault -c \
  "SELECT kid, tenant_id, state FROM system.tenant_signing_keys;"

# Private halves are wrapped, never plaintext.
docker exec wv-pg psql -U wslvault -d wslvault -c \
  "SELECT kid, left(wrapped_private_key, 40) FROM system.tenant_signing_keys;"
```

## Tear down

```bash
docker rm -f wv-pg wv-crypto wv-identity && docker network rm wv-demo
```

## Things worth trying

| Try | Expect |
|---|---|
| Reuse a code within its 30s window | `invalid or already-used code` |
| Reuse a spent challenge | `challenge is unknown or expired` |
| A superuser key with `mfa_required:false` | Schema forces it true |
| Log in with a superuser key before enrolling | Refused; no token minted |
| Create a key in a second tenant | A second, distinct `kid` appears in JWKS |
| `POST /v1/sys/init` on `:18080` | Shamir shares, shown once |
