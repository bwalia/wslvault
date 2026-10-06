# Prompt: Secret & tenant tags + SDLC environments (INT / TEST / ACC / PROD)

Use this prompt with an implementation agent. It is the product brief and technical
constraints for extending WSLVault so operators can categorize secrets with tags
and attach SDLC environments, while keeping **PROD in a separate tenancy** from
lower environments.

---

## Goal

Extend **secrets** (and optionally **tenants**) with:

1. **Tags** — free-form labels for categories (e.g. `database`, `api-key`, `ci`, `payment`, `observability`) so secrets are easy to filter, group, and browse.
2. **Environment** — a first-class SDLC dimension on each secret: `INT` | `TEST` | `ACC` | `PROD`.

**Tenancy model (product rule):**

| Tenancy pattern | Environments in that tenant | Example |
|-----------------|-----------------------------|---------|
| Shared lower-env project tenant | `INT`, `TEST`, `ACC` only | `project-dta` |
| Production tenant | `PROD` only | `project-dta-prod` |

- One tenant like **Project-DTA** (`project-dta`) may hold secrets for **all lower environments** (INT / TEST / ACC), distinguished by the secret’s `environment` field (and optionally path prefix).
- **PROD must not share that tenant.** Recommend / enforce a **separate production tenancy** (e.g. `project-dta-prod`) so a lower-env compromise, shared operator key, or overly broad policy cannot reach production secrets.
- Do **not** conflate SDLC environment with **geo region** (Manchester / London replication). Regions stay as they are today.

---

## User stories

1. As an operator creating a secret in `project-dta`, I pick environment `INT` / `TEST` / `ACC` and add tags like `postgres`, `app=billing` so I can later filter “all TEST database secrets”.
2. As an operator, when I try to set environment `PROD` on a secret in a lower-env project tenant, the UI warns and the API rejects (or strongly discourages) unless the tenant is marked as a production tenant.
3. As an operator creating a new project, the tenant form lets me declare the tenant’s **allowed environments** (default for a project tenant: INT+TEST+ACC; for a prod tenant: PROD only).
4. As an operator browsing secrets, I can filter by environment and by tag, and the tree/list groups or badges make category + env obvious at a glance.

---

## Current state (read before coding)

- Tenants: `system.tenants` — `id`, `slug`, `display_name`, `tier`, `root_key_id`, timestamps. **No tags / metadata / allowed-envs.**
- Secrets: `shared.secrets` + `shared.secret_versions` — already have `custom_metadata JSONB`, but **Postgres put path does not persist it** (see `docs/BUG-SWEEP.md` #11). List API returns paths only; metadata GET omits custom metadata. UI has no tags/env fields.
- Path convention today is informal (`prod/db/...`); that is **not** typed, queryable, or policy-aware as an environment enum.
- Envelope AAD binds `"{tenant_id}:{normalized_path}"`. Changing path requires re-encrypt; **environment/tags as metadata must not require path renames** for v1.
- Dual schema: shared + `tenant_{uuid}` for dedicated/sovereign — migrations must cover both.
- Key paths: `docs/tenancy.md`, `docs/security-model.md`, `storage/postgres/init/*`, `crates/wslvault-core/src/types/{tenant,secret}.rs`, `services/secret-engine/src/{http.rs,pg_store.rs}`, `services/identity-service/src/tenant_handlers.rs`, `ui/apps/vault-ui/src/app/(dashboard)/{secrets,tenants}/page.tsx`, `ui/apps/vault-ui/src/lib/api.ts`, `proto/wslvault/secret/v1/service.proto`.

---

## Proposed design

### A. Secret: environment + tags (required)

**Preferred shape (first-class columns + keep custom_metadata):**

On `shared.secrets` (and dedicated tenant schemas):

- `environment TEXT NULL` — check constraint / enum: `INT` | `TEST` | `ACC` | `PROD`
- `tags TEXT[] NOT NULL DEFAULT '{}'` — normalized lowercase kebab or allow `key` / `key:value`; document one convention and stick to it
- Indexes: btree on `(tenant_id, environment)`, GIN on `tags` for `&&` / `@>` filters

Also **fix `custom_metadata` persistence** end-to-end so arbitrary key/value categories still work for advanced users; mirror `environment` / `tags` into reserved metadata keys on write if useful for Vault-compat clients (`environment`, `tags` as comma-joined).

**API:**

- `PUT` / create secret: accept `environment` (required on create; default may be tenant’s default env) and `tags` (optional array).
- `GET` secret + `GET …/metadata`: return `environment` and `tags`.
- `PATCH` metadata (preferred) or put-with-CAS: allow updating tags/environment **without** a new ciphertext version when only labels change.
- `LIST` secrets: query params `?environment=TEST&tag=postgres` (AND semantics); response includes path + environment + tags (not ciphertext).
- Proto: extend put/get/metadata/list messages accordingly.

**UI (vault-ui secrets):**

- Create/edit: environment select (only envs allowed for this tenant); tag input (chips).
- List/tree: badge for env; filter bar for env + tags; optional group-by environment.
- Do not put env only in the path for v1 (path may still use `{env}/…` as a **suggested** template in the UI hint).

### B. Tenant: allowed environments + optional tags (required for the tenancy rule)

On `system.tenants` (or adjacent table):

- `allowed_environments TEXT[] NOT NULL` — subset of `{INT,TEST,ACC,PROD}`
- `default_environment TEXT` — must be ∈ allowed_environments
- Optional: `tags TEXT[]` for tenant-level categories (e.g. `project:dta`, `team:platform`)
- Optional convenience: `tenant_kind` / flag `is_production` — if true, `allowed_environments = {PROD}` only; if false (project), default `{INT,TEST,ACC}` and **reject PROD**

**Create-tenant UX / API defaults:**

- New “project” tenant → allowed = INT, TEST, ACC; default = INT; slug example `project-dta`.
- New “production” tenant → allowed = PROD; default = PROD; slug example `project-dta-prod`; copy in UI: *“Keep production secrets in a separate tenant from lower environments.”*

**Enforcement:**

- Secret write with `environment` ∉ tenant.`allowed_environments` → `400` with clear error.
- Document that cross-env promotion (ACC → PROD) is **copy/migrate into the prod tenant**, not flipping a label in the lower-env tenant.

### C. Policy & security (must address)

- Authorization remains path-based today (`secret/data/{path}`). Document whether env/tags are **advisory** for v1 (filter/UX only) or whether policy can constrain env (e.g. deny PROD writes for certain keys). If policy is deferred, say so explicitly in the PR.
- Never store secret values in tags/metadata.
- Superuser / act-as-tenant behavior unchanged; filters always scoped by JWT tenant.
- RLS / query scoping: every new list filter must keep `tenant_id` predicates.

### D. Docs

Update `docs/tenancy.md` (or add `docs/operations/secret-tags-and-environments.md`) with:

- Project-DTA pattern vs separate PROD tenancy
- Environment enum meaning (INT / TEST / ACC / PROD)
- Tag conventions
- Migration / promotion path for ACC → PROD
- Explicit note: environment ≠ region

---

## Implementation order

1. Fix `custom_metadata` persistence in secret-engine PG store (BUG-SWEEP #11) — prerequisite.
2. Schema migration: secret `environment` + `tags`; tenant `allowed_environments` + `default_environment` (+ optional tenant tags); backfill existing secrets to a chosen default (e.g. `INT` or leave nullable only during migration then tighten).
3. Core types + storage + HTTP/proto.
4. Tenant create/update validation + UI.
5. Secrets create/edit/list filters + UI badges.
6. Docs + a small integration/API test for: project tenant rejects PROD; prod tenant accepts PROD; list filter by env/tag.

---

## Acceptance criteria

- [ ] Creating a secret requires a valid `environment` allowed for that tenant.
- [ ] Tags can be set/updated and used to filter the secret list.
- [ ] A project-style tenant (allowed INT/TEST/ACC) **cannot** store `PROD` secrets.
- [ ] A production-style tenant can store `PROD` and is the documented home for production secrets for that project.
- [ ] UI makes env + tags obvious on create and browse.
- [ ] Metadata/list APIs expose the new fields; existing envelope encryption / AAD / tenant isolation unchanged.
- [ ] Dedicated-tenant schemas receive the same migration.
- [ ] Docs describe the Project-DTA (lower envs) vs `project-dta-prod` (PROD) pattern.

---

## Out of scope (unless trivial)

- Automatic secret promotion workflow ACC → PROD (manual copy is fine for v1).
- Changing AAD to include environment (keep path-based AAD).
- Replacing path ACLs with tag-based ACLs.
- Treating geo regions as environments.

---

## Non-goals / anti-patterns

- Do not put INT/TEST/ACC/PROD secrets for the same project in one tenant **including PROD**.
- Do not rely on path prefixes alone as the source of truth for environment.
- Do not invent a purple/glow redesign in the UI — follow existing vault-ui steel/brass patterns.

---

## Deliverable

Implement behind a normal feature PR: schema + API + vault-ui + docs + tests. Title suggestion:

`feat(secrets): tags and INT/TEST/ACC/PROD environments with project vs prod tenancy`
