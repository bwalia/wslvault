# WSLVault UI — API Call Audit

**Audit date:** 2026-07-16 · **Scope:** `ui/apps/vault-ui` (Next.js 15.5 / React 19 / SWR)
**Method:** Static route matching. Every UI call site was traced through the `next.config.ts`
rewrite to the exact `.route(...)` declaration in the backend axum router. Nothing was guessed.

> **Note on empirical testing:** I did not run the stack. This machine has no `cargo`, no `target/`,
> and no `node_modules` (cold build ≈ 30–60 min for 13 Rust services), and ports **8088** (gateway)
> and **3011** (UI dev) are currently held by your `tax_return_gatus` and `opsapi-grafana`
> containers. I did not stop other projects' containers to free them. The findings below are
> nonetheless conclusive: a route that does not exist in the router cannot answer. Say the word and
> I'll build and run it end to end.

---

## Bottom line

**6 of 12 pages work. 5 are completely broken. 1 is partial.**

The breakage is not evenly distributed and not all the same kind of problem. Three distinct root
causes, in descending order of effort to fix:

1. **Two backends have no HTTP API at all.** `audit-service` and `lease-manager` expose exactly one
   HTTP route each — `/health`. Everything else about them is gRPC. The Audit and Leases pages call
   REST endpoints that were never written. **This is missing backend work, not a UI typo.**
2. **The Transit page has a path-prefix bug.** Every call omits the `/transit` segment. Six calls,
   all 404. Roughly a one-line fix each — but the key-list endpoint it needs doesn't exist at all.
3. **The gateway has no routes for cluster/regions/SCIM.** The Cluster, Regions, and SCIM pages
   miss twice over: the gateway has no matching `location` block, *and* the UI paths don't match the
   backend paths either. `next.config.ts` already admits this in a comment.

There is also a **security finding** (§5) that I'd rate higher than any of the above: the UI's edge
middleware decodes the JWT **without verifying its signature** and injects `X-Policies` from it.

---

## 1. Rewrite map — all 7 prefixes resolve correctly

`next.config.ts` rewrites `/api/<x>/:path*` → `<SERVICE_URL>/:path*`. Every default port matches
`docker-compose.yml`. **The plumbing is right; the paths travelling through it are not.**

| UI prefix | Default target | Compose mapping | Port OK? |
|---|---|---|---|
| `/api/identity` | `localhost:18082` | `18082:8082` | ✅ |
| `/api/secret` | `localhost:8081` | `8081:8081` | ✅ |
| `/api/transit` | `localhost:18086` | `18086:8086` | ✅ |
| `/api/policy` | `localhost:8083` | `8083:8083` | ✅ |
| `/api/audit` | `localhost:18085` | `18085:8085` | ✅ |
| `/api/lease` | `localhost:18084` | `18084:8084` | ✅ |
| `/api/gateway` | `localhost:8088` | gateway `8088:8080` | ✅ |

Note the rewrite **strips the prefix**: `/api/transit/v1/encrypt/k` → `localhost:18086/v1/encrypt/k`.
That stripping is the source of the Transit bug — the UI never adds `/transit` back.

---

## 2. Page-by-page verdict

| Page | Status | Detail |
|---|---|---|
| **Login** | ✅ **Works** | `POST /api/identity/v1/auth/api-key` → [api_keys.rs:927](../services/identity-service/src/api_keys.rs#L927) `/v1/auth/api-key` |
| **Secrets** | ✅ **Works** | All 4 calls match. The base64/`metadata.version` adapter at [secrets/page.tsx:123](../ui/apps/vault-ui/src/app/(dashboard)/secrets/page.tsx#L123) correctly reshapes the response. Nicely done. |
| **Policies** | ✅ **Works** | `GET/POST /v1/policies` + `GET/PUT/DELETE /v1/policies/:name` → [http.rs:356-360](../services/policy-engine/src/http.rs#L356) |
| **Tenants** | ⚠️ **Works in dev only** | Routes match ([tenant_handlers.rs:543](../services/identity-service/src/tenant_handlers.rs#L543)), but **every call returns HTTP 500 when `DATABASE_URL` is set** (STATUS.md P1-8). Compose omits `DATABASE_URL` for identity, so dev works and prod breaks. |
| **Identity (API keys)** | ✅ **Works** | `GET/POST /v1/api-keys`, `DELETE /:id`, `POST /:id/rotate` all match |
| **Settings** | ✅ **Works** | Reuses `/v1/tenants` + `/v1/api-keys` |
| **Dashboard** | ⚠️ **3 of 4 widgets** | tenants ✅, api-keys ✅, secrets ✅ — **audit widget 404s** |
| **Transit** | ❌ **Fully broken** | All 6 calls 404. See §3. |
| **Audit** | ❌ **Fully broken** | Backend has no HTTP API. See §4. |
| **Leases** | ❌ **Fully broken** | Backend has no HTTP API. See §4. |
| **SCIM** | ❌ **Fully broken** | Path wrong + no gateway route. See §4. |
| **Cluster** | ❌ **Fully broken** | Path wrong + no gateway route. See §4. |
| **Regions** | ❌ **Fully broken** | Path wrong + no gateway route. See §4. |

---

## 3. Transit page — every call 404s (path-prefix bug)

The UI drops the `/transit` path segment on all five operations.

| UI call ([transit/page.tsx](../ui/apps/vault-ui/src/app/(dashboard)/transit/page.tsx)) | Resolves to | Backend actually has | |
|---|---|---|---|
| `/api/transit/v1/encrypt/:n` | `:18086/v1/encrypt/:n` | `/v1/transit/encrypt/:key_name` | ❌ |
| `/api/transit/v1/decrypt/:n` | `:18086/v1/decrypt/:n` | `/v1/transit/decrypt/:key_name` | ❌ |
| `/api/transit/v1/sign/:n` | `:18086/v1/sign/:n` | `/v1/transit/sign/:key_name` | ❌ |
| `/api/transit/v1/verify/:n` | `:18086/v1/verify/:n` | `/v1/transit/verify/:key_name` | ❌ |
| `POST /api/transit/v1/keys` | `:18086/v1/keys` | `/v1/transit/keys/:key_name` | ❌ |
| `GET /api/transit/v1/keys` (list) | `:18086/v1/keys` | **no list route exists at all** | ❌❌ |

Backend routes: [transit-engine/src/main.rs:140-150](../services/transit-engine/src/main.rs#L140-L150).

Two of these are more than typos:

- **Key list has no backend.** [transit/page.tsx:89](../ui/apps/vault-ui/src/app/(dashboard)/transit/page.tsx#L89) does
  `useSWR<TransitKeyResponse>(TRANSIT_KEY, fetcher)`, but transit-engine exposes **no `GET` route
  whatsoever** — only `POST` create and `POST` rotate. Fixing the prefix won't help; the endpoint
  must be written. (Consistent with STATUS.md: transit has no list/read/delete key operations.)
- **Create-key shape mismatch.** The UI `POST`s to a collection with the name in the body; the
  backend wants the name **in the path** (`/v1/transit/keys/:key_name`). Fixing the prefix alone
  still 404s.

**Also worth knowing:** even once wired, the Transit page's Sign/Verify tabs are labelled
misleadingly — those endpoints are HMAC-SHA256, not digital signatures (STATUS.md P1-11).

---

## 4. The four pages calling endpoints that don't exist

### 4a. Audit — the service has no HTTP API

- **UI calls:** `GET /api/audit/v1/audit/events?...` — from [audit/page.tsx:39](../ui/apps/vault-ui/src/app/(dashboard)/audit/page.tsx#L39) and the dashboard widget.
- **audit-service's entire HTTP router** ([main.rs:69-71](../services/audit-service/src/main.rs#L69-L71)):
  ```rust
  let health_router = Router::new()
      .route("/health", get(health::health_handler))
      .layer(middleware::from_fn(metrics_middleware));
  ```
  That's it. Querying audit events is **gRPC-only** (`QueryEvents`).
- **Verdict:** ❌ 404. Needs a REST handler wrapping the existing gRPC `QueryEvents`.
- **Bonus:** `analytics.rs::compute_analytics` already computes rich dashboard data and is wired to
  **no endpoint at all** — dead code that is close to what the page wants.

### 4b. Leases — the service has no HTTP API

- **UI calls:** `GET /api/lease/v1/leases`, `POST /v1/leases/:id/renew`, `POST /v1/leases/:id/revoke`.
- **lease-manager's entire HTTP router** ([main.rs:119](../services/lease-manager/src/main.rs#L119)):
  ```rust
  let health_router = Router::new().route("/health", get(health::health_handler));
  ```
- **Verdict:** ❌ 404 on all three. gRPC-only (`GetLease`/`RenewLease`/`RevokeLease`/`ListLeases`).
- **Bonus:** even after you add REST, **`ListLeases` returns a hardcoded empty vec on the Postgres
  backend** ([pg_store.rs:223-235](../services/lease-manager/src/pg_store.rs#L223-L235)), so the
  page would render empty in any real deployment.

> **This also breaks production, not just the UI.** The gateway proxies `/v1/leases/` →
> `lease_manager` and `/v1/audit/` → `audit_service` ([main.conf:226,234](../gateway/conf.d/main.conf#L226)).
> Those upstreams don't serve HTTP, so those gateway routes 404 for every client — SDK, CLI, or
> browser. The MCP server's `list_leases` / `revoke_lease` tools proxy to
> `{secret_engine}/v1/leases`, which doesn't exist either. **Three consumers all point at an API
> nobody wrote.**

### 4c / 4d / 4e. SCIM, Cluster, Regions — wrong path *and* no gateway route

These fail twice. `next.config.ts` even carries a comment admitting it.

| Page | UI path | Gateway `location` match? | Backend actually has |
|---|---|---|---|
| SCIM | `/api/gateway/v1/scim/Users` | ❌ gateway has `location /scim/` — `/v1/scim/…` doesn't match | `/scim/v2/Users` ([scim/mod.rs:315](../services/identity-service/src/scim/mod.rs#L315)) |
| Cluster | `/api/gateway/v1/cluster/status` | ❌ **no cluster location block at all** | `/v1/sys/cluster/status` ([region-health/main.rs:97](../services/region-health/src/main.rs#L97)) |
| Regions | `/api/gateway/v1/regions` | ❌ **no regions location block at all** | `/v1/sys/regions` ([region-health/main.rs:94](../services/region-health/src/main.rs#L94)) |

The gateway's full route list is `/v1/auth/`, `/v1/secret/`, `/v1/transit/`, `/v1/tenants`,
`/v1/api-keys`, `/scim/`, `/v1/identity/`, `/v1/policies/`, `/v1/leases/`, `/v1/audit/`,
`/v1/quotas/`, `/v1/pki/`, `/v1/mcp/` — **region-health is not proxied at all.** So Cluster and
Regions need a new gateway upstream + location block, plus the `/sys` segment in the UI paths.

---

## 5. Security finding — the middleware forges policies for you

Rated above everything else here.

[`src/middleware.ts`](../ui/apps/vault-ui/src/middleware.ts) decodes the JWT and injects
`x-principal-id` and `x-policies` into the proxied request. Its own docstring is candid:

> *"The JWT payload is decoded (not re-verified) because: 1. The token was issued and signed by our
> identity-service. 2. The backend services trust these headers from an internal caller."*

Assumption 1 is not checked — that is what "not re-verified" means. Anyone can hand-craft
`{"sub":"x","policies":["root"],"tenant_id":"y"}`, base64url it into an unsigned three-part
token, and the middleware will faithfully inject `x-policies: root`.

The backends then trust it, because:
- `GatewayAuth::from_env()` **disables itself when `VAULT_GATEWAY_SECRET` is unset**
  ([middleware.rs:67-81](../crates/wslvault-core/src/middleware.rs#L67-L81)) — it logs a warning
  and allows everything. **No compose service sets that variable.**
- And per STATUS.md P0-3, the policy engine's HTTP `authorize` ignores the principal anyway.

**Chained:** forged JWT → injected `x-policies` → gateway auth disabled → authorize ignores
principal. Authorization is decorative on this path. It's contained today because the proxy is
dev-only, but `next.config.ts` sets `output: 'standalone'` — this UI is built to be deployed. If it
ships as-is with services behind it, the login screen is ornamental.

**Fix:** verify the signature in the middleware (needs the JWT secret in the edge runtime), or
better, drop the header-injection shortcut and put the real gateway in front in every environment.
Set `VAULT_GATEWAY_SECRET` everywhere regardless.

---

## 6. Suggested fix order

**Quick wins (~1 hour, unblocks 1.5 pages):**
1. Add `/transit` to the five Transit paths in [transit/page.tsx](../ui/apps/vault-ui/src/app/(dashboard)/transit/page.tsx). Fixes encrypt/decrypt/sign/verify immediately.
2. Change create-key to `POST /api/transit/v1/transit/keys/${name}` (name in path, not body).

**Small backend additions (~half a day each, unblocks 2.5 pages):**
3. `GET /v1/transit/keys` list route on transit-engine — completes the Transit page.
4. REST wrapper over gRPC `QueryEvents` on audit-service — unblocks the Audit page **and** the
   dashboard widget **and** the dead-but-ready `analytics.rs`.
5. REST wrapper over gRPC lease ops on lease-manager — unblocks Leases. Fix the hardcoded empty
   `list_leases` on the Postgres backend at the same time or the page stays blank.

**Gateway + path alignment (~half a day, unblocks 3 pages):**
6. Add a `region_health` upstream + `location /v1/sys/` block to the gateway; change UI paths to
   `/api/gateway/v1/sys/cluster/status` and `/api/gateway/v1/sys/regions`.
7. Change SCIM paths to `/api/gateway/scim/v2/Users|Groups` (matches both the gateway's existing
   `/scim/` block and the backend).

**Security (do before any deploy):**
8. Verify the JWT signature in the middleware, or route through the real gateway.
9. Set `VAULT_GATEWAY_SECRET` on every service in compose and Helm.

**Prevents recurrence:**
10. There is no test anywhere that asserts a UI path matches a backend route. Every bug in this
    document is one contract test away from being caught. A tiny table-driven test that walks the
    rewrite map and asserts a non-404 against a running stack would have caught all six.

---

## 7. Credit where due

The Secrets page is genuinely well built. It correctly handles the awkward parts: per-segment path
encoding (because axum's `*path` wildcard won't match `%2F`), the base64-string-not-object `data`
field, and reshaping `{data, version}` into `{data, metadata:{version}}` in the SWR adapter. The
comments explain *why*, not *what*. Whoever wrote that page read the backend carefully — the Transit
page reads like it was written from memory instead.
