# Plan: finish leases

**Status:** the `lease-manager` pod is healthy on K3S1. The feature is not.
This document is the delivery plan to make leases real, then ship them.

**Checked live (2026-09-01):**

| Check | Result |
|---|---|
| `GET /api/lease/health` via vault-ui | 200 `{"status":"ok","service":"lease-manager"}` |
| `GET /api/lease/v1/leases` | 404, empty body |
| `GET https://vault.workstation.co.uk/v1/leases/` | 404 (path not on ingress) |

---

## 1. What we are building (plain language)

A **lease** is a timer on a credential.

1. Login issues a token **and** a lease (TTL + hard max TTL).
2. The lease is stored in Postgres so every replica sees it.
3. The Leases page / CLI / SDK / MCP can list, renew, and revoke it.
4. When the timer hits zero, or someone revokes it, **the token stops working**.

That is the product. If a stolen token still works after revoke/expire, this
is not done.

Leases are **not** a log of “someone read a KV secret.” Static KV values stay
in the vault until a human deletes them. HashiCorp Vault does not lease KV
reads either. We will stop pretending that a KV read creates a lease.

---

## 2. Product rules

1. **Tokens are leased.** Every issued JWT gets a real row in `shared.leases`
   with `target_type = token`. The JWT `exp` and the lease TTL must match.
2. **Revoke/expire must kill the token.** Marking a DB row `revoked` /
   `expired` is not enough. The token hash goes on the durable revocation
   list identity-service already has.
3. **Tenant isolation.** List/get/renew/revoke are scoped to the caller’s
   tenant from a **verified** JWT (`wslvault_core::auth::resolve_identity`).
   Never trust a client-supplied `tenant_id` on HTTP.
4. **Renew cannot pass max TTL.** Clamp to `issued_at + max_ttl_seconds`.
5. **Idempotent revoke.** Revoking an already-revoked lease is success.
   Revoking a missing lease is 404.
6. **Degraded login.** If lease-manager is down, login still returns a JWT
   (JWT `exp` still bounds it) with `lease_id` omitted, and a warning is
   logged. Token-lease expire/revoke only applies to tokens that got a row.
7. **No KV read leases.** Remove the stub `create_lease_for_read` call from
   the success path, or keep it as an explicit no-op with a comment. Do not
   fill `shared.leases` with rows that cannot revoke anything.

---

## 3. Out of scope (later work, not this plan)

Dynamic secret engines (database, AWS, GCP, Azure, SSH, …) are how Vault
leases earn most of their keep. They do not exist in this repo.

This plan **does not** build them. It leaves the data model ready
(`LeaseTarget::DynamicSecret` / `ServiceCredential` already exist) so a
future engine can call `CreateLease` the same way identity will.

Also out of scope:

- Periodic / orphan / batch tokens, `num_uses`
- Policy path `sys/leases/*` (any authenticated tenant member may manage
  their own tenant’s leases; superuser may cross tenants via existing
  `act_as_tenant`)
- Changing the rotation-webhook job that already lives in lease-manager
  (keep it; do not mix it into the lease API)

---

## 4. Why it is broken today

The skeleton exists. The loop is not closed.

| Gap | Where | Effect |
|---|---|---|
| No `CreateLease` RPC | `proto/wslvault/lease/v1/service.proto` | Nothing can be issued |
| Secret-engine stubs creation | `services/secret-engine/src/lease_client.rs` | Every KV read logs “not yet wired”, returns no lease |
| Identity mints a fake UUID | `services/identity-service/src/grpc.rs` | `lease_id` is never stored |
| HTTP is `/health` only | `services/lease-manager/src/main.rs` | UI, CLI, SDKs, gateway all 404 |
| `ListLeases` is `vec![]` on Postgres | `services/lease-manager/src/pg_store.rs` | Even after HTTP, the page would be empty |
| Ingress omits `/v1/leases` | `deploy/helm/wslvault/values.yaml` `edgeIngress.routes` | Public API 404 |
| MCP calls secret-engine | `services/mcp-server/src/tools.rs` | Wrong service, no such route |
| Expire only flips `state` | `expiration.rs` + `lease_store.rs` | Tokens keep working |
| `revoke_lease` ignores `rows_affected` | `crates/wslvault-storage/src/lease_store.rs` | Fake success for missing IDs |
| Helm env never read | `CRYPTO_SERVICE_ADDR`, `SECRET_ENGINE_ADDR` on lease-manager | Comments claim callbacks that do not exist |
| UI JSON shape ≠ SDK/gRPC | `ui/.../leases/page.tsx` vs `sdks/*/types` | Even a working API would render wrong |

gRPC handlers for get / renew / revoke / list (in-memory only) **are** real.
Reuse them; do not rewrite the state machine.

---

## 5. Target shape

```
Clients (UI, CLI, SDK, MCP)
        │  HTTP + Bearer JWT
        ▼
lease-manager :8084
  GET  /health
  GET  /v1/leases
  GET  /v1/leases/:id
  POST /v1/leases/:id/renew
  POST /v1/leases/:id/revoke
        │
        │  same process, existing gRPC :50055
        │  + new CreateLease
        ▼
Postgres  shared.leases
        │
        │  on revoke / expire of a token lease
        ▼
identity-service  durable revocation list (token hash)
```

Internal callers (identity-service today; a future dynamic engine later)
use gRPC `CreateLease` on :50055, which NetworkPolicy already allows from
in-cluster peers. HTTP is the operator/client surface.

---

## 6. HTTP contract (one shape everywhere)

Match the SDK types (`sdks/go/types.go`, `sdks/typescript/src/types.ts`).
The UI and CLI must be updated to this. Do not invent a third schema.

### `GET /v1/leases`

Auth required. Tenant from the JWT.

```json
{
  "leases": [
    {
      "id": "…",
      "tenant_id": "…",
      "target_type": "token",
      "target_label": "principal:…",
      "state": "active",
      "ttl_seconds": 3600,
      "max_ttl_seconds": 86400,
      "renewable": true,
      "issued_at": "2026-09-01T12:00:00Z",
      "expires_at": "2026-09-01T13:00:00Z",
      "revoked_at": null,
      "remaining_seconds": 2400
    }
  ]
}
```

`target_label` is a display string derived from `LeaseTarget` (principal id
for tokens; `path`/`role` for a future dynamic secret). Query:
`?state=active|expired|revoked` optional.

### `GET /v1/leases/:id`

Same object as one list item. 404 if missing or other tenant (do not leak
existence across tenants).

### `POST /v1/leases/:id/renew`

```json
{ "increment_seconds": 3600 }
```

`increment_seconds` optional, default `3600`. Response:

```json
{ "id": "…", "ttl_seconds": 3600, "expires_at": "…" }
```

400 if not active / not renewable. 404 if missing or other tenant.

### `POST /v1/leases/:id/revoke`

Empty body. 204 on success (including already-revoked). 404 if missing or
other tenant.

CLI today uses `X-Vault-Tenant-ID`; HTTP auth must use the JWT. After this
work the tenant header is unnecessary. Keep accepting it only if
`resolve_identity` already does.

---

## 7. Phases

Ship in order. Each phase has a stop-the-line check. Do not start the next
phase until the previous one is green locally.

### Phase 0 — lock the contract (this doc)

No code. Agree:

- Tokens are leased; KV reads are not.
- REST paths and JSON above.
- Expire/revoke must hit identity revocation.

### Phase 1 — storage + CreateLease + list (backend core)

**Files:**

- `proto/wslvault/lease/v1/service.proto` — add:

  ```
  rpc CreateLease(CreateLeaseRequest) returns (CreateLeaseResponse);

  message CreateLeaseRequest {
    string tenant_id = 1;
    string target_type = 2;   // token | dynamic_secret | service_credential
    string target_data = 3;   // JSON matching LeaseTarget
    int64 ttl_seconds = 4;
    int64 max_ttl_seconds = 5;
    bool renewable = 6;
  }
  ```

  Cap TTL: if `ttl > max`, use `max`. Reject `ttl <= 0`.
- `crates/wslvault-storage/src/lease_store.rs`
  - `list_leases(tenant_id, state_filter) -> Vec<Lease>`
  - `revoke_lease`: check `rows_affected`; return `LeaseNotFound` when 0
- `services/lease-manager/src/pg_store.rs` — implement `list_leases` with
  that query (delete the hardcoded `Vec::new()`)
- `services/lease-manager/src/grpc.rs` — implement `CreateLease` via
  existing `insert_lease`
- `services/secret-engine/src/lease_client.rs` — implement create against
  the new RPC (used by identity in phase 3; secret-engine KV path stays
  a no-op per rule 7)

**Tests:** storage list/revoke-missing; gRPC create → get → list → renew →
revoke against in-memory **and** Postgres (testcontainer or existing DB
test harness).

**Stop-the-line:** `grpcurl` or an integration test can create a lease and
list it back from Postgres.

### Phase 2 — HTTP + auth + clients

**Files:**

- `services/lease-manager/src/http.rs` (new) — axum routes in §6
- `services/lease-manager/src/main.rs` — mount HTTP next to `/health`
- Helm `lease-manager/deployment.yaml`
  - `VAULT_JWKS_URL` (same as secret-engine)
  - `VAULT_JWT_SECRET` (legacy HS256, same secret)
  - drop unused `CRYPTO_SERVICE_ADDR` / `SECRET_ENGINE_ADDR`
  - add `IDENTITY_SERVICE_GRPC` (used in phase 3)
- `deploy/helm/wslvault/values.yaml` `edgeIngress.routes` — add
  `{ path: /v1/leases, component: lease-manager, port: 8084 }`
- `deploy/k8s/wslvault-ingress.yaml` — same, keep in sync
- `gateway/conf.d/main.conf` — already proxies `/v1/leases/`; leave it
- UI `leases/page.tsx` — consume the JSON in §6; renew sends
  `{ increment_seconds }`; show `target_label` instead of `secret_path`
- `wslvault-cli/src/commands/lease.rs` — Bearer JWT; stop requiring a
  working body on empty 204 revoke
- `services/mcp-server` — `VAULT_LEASE_MANAGER_ADDR`, point
  `list_leases` / `revoke_lease` at lease-manager HTTP, not secret-engine
- Helm mcp-server env — add that URL
- SDKs already match §6; add `target_label` / `remaining_seconds` if
  missing. Confirm Go list unwraps `{ "leases": [...] }` (today it
  unmarshals a bare array — fix that)

**Auth:** every `/v1/leases*` handler calls `resolve_identity`. Filter
every query/update with `tenant_id = identity.tenant_id` unless
`act_as_tenant` for superuser.

**Stop-the-line (local compose):**

```
curl -sS -H "Authorization: Bearer $JWT" $LEASE/v1/leases
# []
# 401 without a token
```

UI Leases page loads without a 404 (empty table is OK until phase 3).

### Phase 3 — identity wiring + real revocation

This is the security close.

**Issue path** (`identity-service` authenticate + create_service_account):

1. Mint JWT as today.
2. Hash the token with the existing `revocation_store::token_hash`.
3. gRPC `CreateLease` with `LeaseTarget::Token { token_id: <hash> }`
   (the field is a stable id, **not** the raw JWT).
4. Put the returned `lease_id` on the auth response. If create fails,
   still return the JWT, omit `lease_id`, log warn (rule 6).

**Revoke/expire path** (lease-manager):

1. On `revoke_lease` and on each id returned by `expire_stale_leases`,
   if `target_type == token`, call identity gRPC
   `RevokeTokenByHash { token_hash, tenant_id, principal_id, expires_at }`.
2. Add that RPC on identity-service; it inserts into the same table
   `revocation_store::revoke` already writes. **Do not store the JWT.**
3. Fail closed on the callback: if identity is unreachable, log error and
   retry next sweep (do not silently leave a live token). For explicit
   HTTP revoke, return 503 so the operator can retry.

**Renew path:** optional for v1 — extending the lease TTL does **not**
extend JWT `exp` unless we also reissue. Pick one and document it:

- **v1 (recommended):** lease renew is bookkeeping + remaining-time UI
  only. The JWT still dies at original `exp`. To stay signed in, the
  client re-authenticates. Honest, small.
- **v2 later:** renew returns a new JWT with the new `exp` (Vault-like
  `auth/token/renew`). Do not mix this into v1.

**Helm:** lease-manager gets identity gRPC address; identity-service
already has `LEASE_MANAGER_ENDPOINT` or add it.

**Stop-the-line:**

1. Login → `lease_id` in the response.
2. `GET /v1/leases` shows that row.
3. Revoke it → subsequent API calls with that JWT are 401.
4. Wait past TTL without renew → sweep expires it → JWT 401.

### Phase 4 — stop the KV lie

- `secret-engine` HTTP/gRPC read: do **not** call `create_lease_for_read`.
- Drop `lease_id` / `lease_duration` from KV read JSON, or always omit
  them (`skip_serializing_if`).
- Comment in `lease_client.rs`: reserved for a future dynamic engine.

**Stop-the-line:** reading a KV secret does not insert a `shared.leases`
row.

### Phase 5 — deploy and prove on K3S1

Images that must rebuild: `lease-manager`, `identity-service`,
`secret-engine` (if phase 4), `vault-ui`, `mcp-server`. Chart change
for ingress + env.

After sync on region-a (`wslvault`) then region-b (`wslvault-b`):

1. `curl -sk https://vault-ui.workstation.co.uk/api/lease/health` → 200
2. Login in the UI
3. Open **Leases** — the session lease is listed (not 404, not empty
   after login)
4. Revoke it in the UI → next navigation 401s, must log in again
5. `curl -sk https://vault.workstation.co.uk/v1/leases/` with a Bearer
   token → 200 JSON, not Traefik 404
6. Repeat on `vault-b.workstation.co.uk`

Kubelet logs/exec from this Mac to cloud001 currently 502 through the
API proxy. Prefer public HTTPS checks above. If DB inspection is
needed, run the query from a Job scheduled on cloud001, not
`kubectl exec` from the laptop.

---

## 8. Implementation notes (do not skip)

**`CreateLease` is internal.** Do not expose POST `/v1/leases` for
arbitrary create. Only identity (and later engines) create via gRPC.
HTTP is list/get/renew/revoke.

**Do not put the JWT in `target_data`.** Hash only. A DB dump must not
yield live tokens.

**Leader-only expire stays.** `expiration.rs` already skips non-leaders.
After phase 3 the leader is also the only replica that calls identity
on expire — that is what we want.

**RLS.** `shared.leases` already has a tenant policy. Storage still does
not set `app.current_tenant_id` (STATUS.md remainder). Until that ships,
every SQL query **must** include `tenant_id = $1` from the verified
identity. List-without-tenant is forbidden.

**gRPC CreateLease auth.** Today lease-manager gRPC is unauthenticated
and reachable only in-cluster. Leave it that way for v1; NetworkPolicy
already limits peers. Do not open gRPC on the ingress.

**UI rewrite is baked at image build.** `deploy/docker/vault-ui/Dockerfile`
freezes `LEASE_URL`. Runtime env on the Deployment does not change
rewrites. Rebuild the UI image; do not expect a values-only bump to
retarget leases.

**Default TTLs.** Match current token TTL (identity hardcodes 3600s in
several flows). `max_ttl_seconds` = 24h unless the auth method asked
for less. Document the numbers in identity when wiring phase 3.

---

## 9. Suggested file touch list

| Area | Files |
|---|---|
| Proto | `proto/wslvault/lease/v1/service.proto`, identity proto for `RevokeTokenByHash` |
| Storage | `crates/wslvault-storage/src/lease_store.rs` |
| Lease service | `services/lease-manager/src/{main,grpc,pg_store,http,expiration}.rs` |
| Identity | `services/identity-service/src/grpc.rs` (+ small client like secret-engine’s `lease_client.rs`) |
| Secret-engine | `services/secret-engine/src/{http,grpc,lease_client}.rs` (remove KV lease attempt) |
| MCP | `services/mcp-server/src/{main,tools}.rs` |
| UI | `ui/apps/vault-ui/src/app/(dashboard)/leases/page.tsx` |
| CLI | `wslvault-cli/src/commands/lease.rs` |
| SDKs | Go list envelope; TS/Rust if fields missing |
| Chart | `deploy/helm/wslvault/templates/lease-manager/deployment.yaml`, `values.yaml` `edgeIngress.routes`, mcp-server env, `deploy/k8s/wslvault-ingress.yaml` |
| Docs | this file; one-line pointer in `docs/architecture.md` after ship |

No new tables. `shared.leases` is already correct.

---

## 10. Definition of done

All of these, on K3S1, not only on a laptop:

- [ ] Login returns a `lease_id` that exists in `shared.leases`
- [ ] Leases page lists it; remaining TTL counts down
- [ ] Renew extends `expires_at` and does not exceed max TTL
- [ ] Revoke from UI/CLI immediately 401s that JWT
- [ ] Letting TTL lapse 401s that JWT without anyone clicking revoke
- [ ] Other tenants cannot see or revoke the lease
- [ ] Unauthenticated `GET /v1/leases` is 401, not 404
- [ ] `GET /v1/leases` on `vault.workstation.co.uk` is served by
      lease-manager, not Traefik 404
- [ ] KV secret read does not create a lease
- [ ] MCP `list_leases` / `revoke_lease` talk to lease-manager and work
- [ ] Postgres `ListLeases` is a real query; in-memory leftover is not
      the production path

Until the token actually dies, the feature is still unfinished.

---

## 11. Effort sketch

Order of magnitude, one engineer who already knows this repo:

| Phase | Work |
|---|---|
| 1 Storage + CreateLease + list | ~1 day |
| 2 HTTP + auth + UI/CLI/MCP/ingress | ~1–2 days |
| 3 Identity + revocation callback | ~1–2 days |
| 4 KV cleanup | hours |
| 5 Images, chart, K3S1 proof | ~1 day |

Dynamic secrets remain a separate project after this.
