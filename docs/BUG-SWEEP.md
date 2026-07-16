# WSLVault — Silent-Failure Bug Sweep

**Date:** 2026-07-16 · **Trigger:** the "delete doesn't work" bug
**Method:** four parallel audits (SQL/empty-collection, backend divergence, swallowed errors, UI error handling), every finding re-verified against source before landing here.

---

## The bug class

The reported delete bug had a shape worth naming, because the codebase is full of it:

> **An operation reports success while doing nothing.**

The delete instance had three independent causes stacked:

1. **Empty collection → SQL matches nothing.** The UI sent `{"versions": []}` meaning "delete this secret". Postgres `version = ANY('{}')` is false for every row → 0 rows updated → `Ok(0)` → **HTTP 200 `{"count":0}`**.
2. **The two backends disagreed.** In-memory resolved `[]` to "current version" ([kv_store.rs:397](../services/secret-engine/src/kv_store.rs#L397)); Postgres passed it straight through. Dev used one, prod the other, and only the dev one had tests.
3. **The UI hid it.** `catch { // ignore }` plus never inspecting the response body.

**The sweep found 25 more instances of the same class.** The root cause is nearly always one of two things: a trait method whose signature *cannot express failure* (`-> Option<T>`, `-> Vec<T>`, `-> ()`), or an empty/missing value that means "nothing" to SQL but "everything" to the caller.

---

## Part 1 — FIXED in this pass

### 1.1 The delete bug was only half-fixed by the obvious fix ⚠️

Resolving `versions: []` made the delete *mark* `deleted_at`. **The secret was still readable afterwards.**

`shared.secrets.current_version` is a **write pointer** — `vault_upsert_secret` advances it, `vault_soft_delete_versions` never moves it back ([003_functions.sql:70-79](../storage/postgres/init/003_functions.sql#L70)). Postgres `get(None)` trusted that pointer, and `get_secret_version` only checked `destroyed`, never `deleted_at`. So:

```
DELETE /v1/secret/data/foo   →  200, deleted_at set on v3
GET    /v1/secret/data/foo   →  200, returns v3's plaintext   ← the "delete didn't work" symptom
```

In-memory got this right (`current_version_number()` skips deleted). **Postgres — i.e. your actual deployment — did not.**

**Fixed:** added [`latest_live_version()`](../crates/wslvault-storage/src/secret_store.rs) (`MAX(version) WHERE deleted_at IS NULL AND destroyed = false`); `pg_store::get(None)` now resolves through it. `get(Some(n))` still returns soft-deleted versions (matching in-memory, and leaving room for undelete).

> **Note:** a soft-deleted path still appears in `list` — that is correct KV v2 behaviour (metadata survives; that's what makes undelete possible). Vault behaves the same.

### 1.2 Empty-versions resolution (the original fix)

[pg_store.rs](../services/secret-engine/src/pg_store.rs) — `resolve_soft_delete_targets` / `resolve_destroy_targets`, extracted as pure functions so the cross-backend contract is unit-testable without a database. **9 regression tests**; 19/19 secret-engine tests pass.

### 1.3 `get_metadata` reported `current_version: 0` for every secret

Postgres returned `versions: Vec::new()`, but `current_version_number()` derives the version *by scanning that vec*. Both call sites ([http.rs:987](../services/secret-engine/src/http.rs#L987), grpc.rs:764) used it. **Fixed:** populate version *stubs* (numbers + lifecycle flags, no ciphertext — a metadata endpoint must not carry secret material).

### 1.4 UI — the whole error-handling layer

New: [`lib/safe.ts`](../ui/apps/vault-ui/src/lib/safe.ts) (total `JSON.parse`/`atob`/`btoa`/`localStorage`), [`hooks/useAsyncAction.ts`](../ui/apps/vault-ui/src/hooks/useAsyncAction.ts) (try/catch + pending + re-entrancy guard + 401→logout, in one primitive), [`components/ErrorBanner.tsx`](../ui/apps/vault-ui/src/components/ErrorBanner.tsx), `app/global-error.tsx`, typed `ApiError` carrying HTTP status.

Fixed across the app:

| Issue | Where |
|---|---|
| **8 empty `catch {}`** — logged *nothing*, modals stuck open forever | identity ×2, policies, tenants, leases ×2, scim ×2 |
| **The tenants comment was a lie** — "the confirm modal will close" — `setDeleteTarget(null)` was inside the `try`, so it did not | tenants |
| **API-key rotate discarded the new key** — `res.key` on a possibly-null cast, TypeError into an empty catch. Old key already dead server-side = **unrecoverable lockout** | identity |
| **9 `useSWR` sites ignored `error`** — a dead backend rendered "No secrets yet" / "No API keys yet". A confident empty vault is the worst possible way to be wrong | dashboard ×4, identity, policies, tenants, leases, scim ×2 |
| **`AuthContext` boot-loop** — unguarded `JSON.parse(localStorage)` above every error boundary; corrupt value = permanent white screen until manual storage clear | AuthContext |
| **`ThemeContext` white-screened Safari private mode** — raw `setItem` above every boundary, over a theme preference | ThemeContext |
| **Login NaN-expiry redirect loop** — malformed `expires_at` → `isAuthenticated` false → bounce forever, no error | AuthContext |
| **Context value rebuilt every render** — every `useAuth` consumer re-rendered; `logout` identity unstable | Auth + Theme |
| **Unguarded clipboard** — one-time key "copied" when it wasn't (rejects on plain HTTP) | CodeChip, identity |
| **Unguarded `row.policies.length` / `policy.rules.map`** — crashed the page over a cosmetic column | identity, policies |
| **No unhandled-rejection handler** | providers.tsx |
| **`btoa` spread** — `RangeError` on large secrets; now chunked | safe.ts |
| **Blank-editor-then-overwrite** — a corrupt blob rendered an *empty* editor; hitting Save overwrote the real secret with `{}`. Now blocks editing | secrets |

**And two bugs in my own first-pass fix**, caught by the audit:

- The "deleted 0 versions" error rendered **behind the modal backdrop** — the user saw the exact original symptom. `ConfirmModal` now takes an `error` prop.
- `if (res && res.count === 0)` let a **null body pass as success**. Now checks the shape, not just the value.

**Verified:** `tsc` exit 0 · `next build` 18/18 routes · `cargo test -p secret-engine` 19/19.

---

## Part 2 — OUTSTANDING (not fixed; ranked)

I did not fix these — several need a decision from you, not a patch.

### P0 — security: reports success, grants access anyway

| # | Finding | Location |
|---|---|---|
| 1 | **SCIM group→policy sync is a no-op that logs a lie.** `add_policy_to_principal`/`remove_policy_from_principal` only `info!("...would be added (pending store API)")`. Returns **200/204**. A user removed from `admins` **keeps the admins policy forever**. IdP offboarding silently does nothing. Root cause: `update_policies` is `#[cfg(test)]`-only — there is *no* production path to change a principal's policies. | [scim/groups.rs:96-136](../services/identity-service/src/scim/groups.rs#L96) |
| 2 | **Poisoned revocation lock fails OPEN — permanently.** The comment says "the worst outcome is accepting a revoked token once". That premise is **false**: a `RwLock` stays poisoned for the process lifetime, so *every revoked token is valid again* after one panic. `revoke_token` fails *closed* — the two halves disagree. | [identity/grpc.rs:103-110](../services/identity-service/src/grpc.rs#L103) |
| 3 | **Policy delete is never replicated.** The trigger is `AFTER INSERT OR UPDATE` — no `OR DELETE` — and `policy_store` issues a hard `DELETE`. Revoke a policy; region B still grants it. (`tenant_store` soft-deletes and *does* replicate — the asymmetry is the bug.) | [015_replication_event_triggers.sql:70](../storage/postgres/init/015_replication_event_triggers.sql#L70) |
| 4 | **Secret delete/destroy is never replicated.** `emit_replication_event` hardcodes `'secret_upsert'` and is only called from `write()`. The applier's `secret_delete`/`secret_destroy` arms are **dead code**. A credential you *destroyed* stays readable in every other region. | [pg_store.rs:97](../services/secret-engine/src/pg_store.rs#L97) |

### P1 — silent data loss / wrong results

| # | Finding | Location |
|---|---|---|
| 5 | **`put_policy` reports 200 on a failed write.** DB error is logged, `None` returned, `grpc.rs:221` discards it. Worse: the handler *eagerly updates the compiled snapshot*, so the policy works until restart, then vanishes. `docker-compose.yml:91-93` documents disabling PG in dev *because of the FK error this swallows*. | [policy/pg_store.rs:159](../services/policy-engine/src/pg_store.rs#L159) |
| 6 | **HTTP `DELETE /v1/policies/:name` 404s on every success** — the PG backend always returns `None`, which the handler maps to 404. This **breaks the k8s-operator**: it treats the 404 as failure, never removes the finalizer, and `VaultPolicy` CRs hang in `Terminating` forever. | [policy/http.rs:274](../services/policy-engine/src/http.rs#L274) |
| 7 | **A transient DB blip denies everything, tenant-wide, and logs "refreshed".** `get_all()` returns an empty vec on error; the compile task installs it unconditionally; the evaluator is deny-by-default. Fail-closed, so safe — but a silent total outage. | [policy/main.rs:141-153](../services/policy-engine/src/main.rs#L141) |
| 8 | **`transit rotate_key` rotates the WRONG key.** `get_active_key` filters on `tenant + purpose` — the SQL **has no key-name column**. With two transit keys, rotating A marks B's descriptor `RotatingOut`. | [transit/pg_store.rs:241](../services/transit-engine/src/pg_store.rs#L241) |
| 9 | **`transit create_key`'s duplicate guard is cache-only.** After a restart the cache is empty, so creating an existing key **succeeds**, writes a second descriptor, and generates fresh material — orphaning all ciphertext under the old key. | [transit/pg_store.rs:136](../services/transit-engine/src/pg_store.rs#L136) |
| 10 | **`revoke_lease` never checks `rows_affected`** → success for a lease that doesn't exist. `renew_lease` 10 lines above *does* check. In-memory returns `Err`. | [lease_store.rs:134](../crates/wslvault-storage/src/lease_store.rs#L134) |
| 11 | **`secret put` silently drops `custom_metadata`** on Postgres — the param is `_custom_metadata`, never bound, though the SQL function accepts it. | [pg_store.rs:172](../services/secret-engine/src/pg_store.rs#L172) |
| 12 | **`audit query_events`: `limit=0` means "all" in memory, "none" in Postgres.** An omitted proto field is 0 → `LIMIT 0` → empty page with a non-zero `total`. Ordering also differs (insertion vs `DESC`). | [audit/pg_store.rs:102](../services/audit-service/src/pg_store.rs#L102) |
| 13 | **`list_leases` on PG is a hardcoded `[]`.** Its comment claims the PG backend isn't active in dev — `docker-compose.yml:135` sets `DATABASE_URL`. Operators auditing live credentials see none. | [lease/pg_store.rs:227](../services/lease-manager/src/pg_store.rs#L227) |
| 14 | **Forced failover to a nonexistent region returns `{"status":"ok"}`** and writes an audit row with `outcome` hardcoded `'success'` — a compliance log recording a promotion that never happened. | [failover.rs:36](../services/region-health/src/failover.rs#L36) |
| 15 | **`secret list` prefix is an unescaped LIKE pattern** — a `%` or `_` in a caller-supplied prefix acts as a wildcard. In-memory uses `starts_with`. | [secret_store.rs:177](../crates/wslvault-storage/src/secret_store.rs#L177) |

### P2 — structural

| # | Finding |
|---|---|
| 16 | **`PolicyStoreBackend` cannot express failure.** Returns `Option<T>`/`Vec<T>`, no `Result` anywhere — chosen to match an infallible in-memory impl. The PG impl has nowhere to put an error, so it logs and swallows. **Findings 5, 6, 7 all collapse into this one signature.** `secret-engine`'s local `KvStore::list -> Vec<String>` has the same flaw (core's own `KvStore::list` correctly returns `Result`). |
| 17 | **A landmine for whoever implements finding 4.** If the delete event forwards the HTTP body's `versions` verbatim, the UI's `{"versions": []}` hits `if !versions.is_empty()`, skips, logs "replicated secret_delete", and **acks the event as applied** — reproducing the exact bug one layer down. The payload must carry *resolved* versions. |
| 18 | **Zero tests on 10 of 12 PG backends.** No `tests/` dir under `services/` at all. Every divergence above lives in an untested implementation. |

---

## Part 3 — Is it production ready?

**No.** Not because of these bugs — they're fixable — but for the reasons in [STATUS.md](STATUS.md), which stand unchanged:

1. **There is no seal/unseal.** No Shamir, no init ceremony, no auto-unseal by default. The root key is a plaintext env var. This is the defining feature of a vault and it is 0% built.
2. **The UI middleware forges policies.** It decodes the JWT **without verifying the signature** and injects `X-Policies`; `GatewayAuth` disables itself when `VAULT_GATEWAY_SECRET` is unset (no compose service sets it); the policy engine's HTTP authorize ignores the principal anyway. Chained, authorization is decorative.
3. **Two backends per service, one tested.** This sweep found 19 divergences. That ratio won't improve without integration tests.
4. **CI ships images when tests fail** (`needs: []`), with lint and `cargo audit` both `continue-on-error` (the latter admitting 14 known CVEs).

**What this sweep changes about the assessment:** the gap is wider than STATUS.md implied. It isn't just "features missing" — the Postgres paths that *only run in production* are systematically less correct than the in-memory paths that only run in dev. Every one of P0-1 through P0-4 reports success while failing, and four of them fail **in the direction of granting access**.

### Recommended order

1. **P0-1, P0-2** — both are live privilege-retention holes with a small diff each.
2. **Change `PolicyStoreBackend` to return `Result`** — collapses P1-5, P1-6, P1-7 at once.
3. **P0-3, P0-4** — replication of deletes. Read finding 17 first.
4. **P1-8, P1-9** — transit key handling; both silently destroy access to ciphertext.
5. **Integration tests over a real Postgres**, asserting the two backends agree. The pure-resolver pattern in [pg_store.rs](../services/secret-engine/src/pg_store.rs) is the seam that generalises: extract the semantics above the SQL, test them without a DB.

A single generalised regression test — *"a delete/revoke against a failing pool must not return success"* — would have caught the original bug plus findings 5, 6, and 10.
