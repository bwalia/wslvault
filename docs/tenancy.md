# How a secret belongs to a tenant

There are four places where the boundary between tenants is enforced. Three of
them work. This document says what each one actually guarantees, because the
gap between "declared" and "enforced" is where the interesting bugs have been.

## 1. The schema: a column and a unique key

`001_schema.sql`:

```sql
CREATE TABLE shared.secrets (
    id         UUID PRIMARY KEY,
    tenant_id  UUID NOT NULL REFERENCES system.tenants(id),
    path       TEXT NOT NULL,
    ...
    UNIQUE (tenant_id, path)
);
```

A secret belongs to exactly one tenant, and the uniqueness is on the *pair*, so
`prod/db-password` in Acme and `prod/db-password` in Globex are different rows
that never collide.

`shared.secret_versions` — where the ciphertext actually lives — has no
`tenant_id` of its own. It inherits the tenant through `secret_id → secrets`.
Anything reasoning about tenancy has to make that hop; a check that only looks
for a `tenant_id` column will miss the table holding the secret material.

## 2. Query scoping: `WHERE tenant_id = $1`

Every function in `crates/wslvault-storage/src/secret_store.rs` takes a
`TenantId` and filters on it. Today this is the layer doing the actual work.

Its weakness is that it is a convention. It holds only as long as every query
anyone writes remembers it, and it did not hold everywhere — see
`confirm_rotation` under "What was broken" below.

## 3. Cryptography: the tenant is in the AAD

`services/secret-engine/src/http.rs`:

```rust
let aad = format!("{}:{}", tenant_id, normalized_path).into_bytes();
```

Each version is envelope-encrypted, and the additional authenticated data binds
the ciphertext to `tenant_id:path`. Decrypting Acme's bytes while claiming to be
Globex fails the AEAD tag — not "returns the wrong thing", *fails*.

This is the strongest layer, and the only one that survives someone reading raw
rows out of the database. It is also why a cross-region secret cannot be
decrypted by a region that has not replicated the matching key.

## 4. Identity: the tenant comes from a signed token

`crates/wslvault-core/src/auth.rs::resolve_identity` is the only sanctioned
source of a tenant id. It reads the `tenant_id` claim out of a verified JWT —
EdDSA against the tenant's own key from JWKS, or legacy HS256 — and fails closed
on anything it cannot verify.

`X-Tenant-Id` is honoured **only** when `VAULT_TRUST_GATEWAY_HEADERS=true`,
which is off by default, because a client-supplied tenant header is a client
choosing its own tenant. The UI does not send one at all
(`ui/apps/vault-ui/src/lib/fetcher.ts`).

A superuser — `is_superuser` on the API key, `025_superuser.sql` — may name a
tenant to act on via `X-Vault-Act-Tenant`. That is the one sanctioned crossing,
it is ignored for everyone else, and it is audited as a crossing rather than
passing as an ordinary request.

## 5. The database: row-level security

This is the layer that did not work.

`004_multitenancy.sql` enabled RLS on seven tables with correct-looking
policies. `018_rls_correctness.sql` then documented, accurately, that it was
enforced on none of them, and pointed at a `019_rls_enforce.sql` that was never
written — the migrations go 018 → 020.

Two independent reasons it was inert:

- **Nothing set the session variable.** The policies resolve
  `current_setting('app.current_tenant_id')`. A grep across the Rust tree for
  that name returned only comments.
- **Services connect as the table owner.** PostgreSQL exempts a table's owner
  from its own policies unless `FORCE ROW LEVEL SECURITY` is set, and it was
  not.

### A correction worth carrying forward

018 and the shelved 019 both say the app role is "a superuser with
rolbypassrls", which would make `FORCE` a harmless no-op. That is true of the
local docker-compose database, where the postgres image makes `POSTGRES_USER` a
superuser. It is **not** true of the live regions, which run the Bitnami chart:

```
SELECT rolname, rolsuper, rolbypassrls FROM pg_roles;
 postgres | t | t
 wslvault | f | f      <-- neither
```

`wslvault` is exempt there purely as the owner. So in production `FORCE` was
never a formality — it was the live switch. Applying it "to see if anything
changes" would have made every fail-closed policy match zero rows and taken both
regions down. The step that looked inert was the dangerous one.

## What was broken, concretely

`shared.vault_confirm_rotation` resolves a rotation by id and nothing else
(`010_secret_lifecycle.sql`):

```sql
FROM shared.secret_rotations sr
WHERE sr.id = p_rotation_id
```

and the handler authorised the caller against their own tenant, then passed the
bare rotation id through. A caller with rotation permission in their own tenant
could confirm **another tenant's** rotation. Layer 2 missed it, and layer 5 was
not there to catch it.

Fixed in two places: an explicit ownership check in
`secret_store::confirm_rotation`, which works today, and an RLS policy on
`shared.secret_rotations`, which becomes a second barrier once enforcement is
on. The error reports "not found" rather than "forbidden", because telling a
caller that a UUID exists under another tenant is itself a disclosure.

## How enforcement gets turned on

Enforcement does **not** require `FORCE`. PostgreSQL applies RLS to any role
that is neither the table owner nor a superuser, so the switch is which role the
services connect as.

### Step 1 — scope every transaction (partly done)

`crates/wslvault-storage/src/tenant_scope.rs`:

```rust
let mut scope = pool.begin_tenant(&tenant_id).await?;
let meta = secret_store::get_secret_metadata(scope.conn(), &tenant_id, path).await?;
scope.commit().await?;
```

and for the jobs that genuinely span tenants:

```rust
let mut scope = pool.begin_cross_tenant("replication applier: peer events span all tenants").await?;
```

It is a transaction because `SET LOCAL` reverts when the transaction ends.
A plain `SET` would persist on a pooled connection and the next request to
borrow it would inherit some previous tenant's scope — the exact cross-tenant
read this exists to prevent, arriving through the mechanism meant to stop it.

**Wired:** secret-engine (all KV paths), replication-agent (whole applier,
cross-tenant), lease-manager (rotation sweep and version cleanup, cross-tenant).

**Not yet wired:** identity-service (`shared.api_keys`, `shared.scim_users`,
`system.revoked_tokens`), crypto-service (`system.key_descriptors` — warm-loads
every tenant's keys at boot, so it needs a cross-tenant scope), transit-engine
(`system.key_descriptors`), policy-engine (`shared.policies`), sync-scheduler
(`system.sync_jobs`), and the audit writer in `wslvault-storage`.

### Step 2 — create the least-privilege role

Once per region, as a superuser, because the migration Job's role has neither
SUPERUSER nor CREATEROLE:

```sh
psql -U postgres -d wslvault \
     -v app_password="$(openssl rand -base64 32)" \
     -f deploy/helm/wslvault/files/bootstrap/rls_app_role.sql
```

Store that password in the DB credentials secret under `app-password`. Object
grants are applied by migration 029, which re-runs harmlessly.

### Step 3 — point the services at it

```yaml
postgresql:
  appRole:
    username: wslvault_app
```

The migration Job deliberately keeps owner rights; only the services move.

**This step is the whole switch, and it must not happen until step 1 is
complete for every service in the list above.** The policies fail closed, so a
service that has not been wired does not error — it sees an empty database. An
unwired crypto-service warm-loads zero keys and nothing decrypts.

### Step 4 — optional, later: `FORCE`

Constrains `wslvault` itself, so an operator at a psql prompt is covered too.
Defence in depth, not the mechanism. See the commented block at the bottom of
`storage/postgres/init/019_rls_enforce.sql.disabled`. Any migration after that
which touches tenant rows must set `app.bypass_rls`.

## Checking where you are

```sql
SELECT * FROM shared.rls_status();
```

Reports, per tenant-scoped table: whether RLS is enabled, whether it is forced,
how many policies exist, whether the owner is still exempt, and whether it is
actually enforced. `enforced = false` everywhere is the expected state after
migration 029 and before step 3.

The property itself is asserted in CI — "Tenant isolation is enforced, not just
declared" in `.github/workflows/gitops-validate.yml` — against a real database,
as the non-owning role. Running such a check as the owner passes while proving
nothing, which is how this stayed broken.
