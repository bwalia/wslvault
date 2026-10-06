# Secret tags and SDLC environments

WSLVault labels every KV secret with:

- **environment** — `INT` | `TEST` | `ACC` | `PROD` (SDLC stage; **not** a geo region)
- **tags** — free-form categories (lowercase kebab recommended: `database`, `api-key`, `app:billing`)

## Tenancy pattern (Project-DTA)

| Tenant kind | Allowed environments | Example slug |
|-------------|----------------------|--------------|
| **project** | INT, TEST, ACC | `project-dta` |
| **production** | PROD only | `project-dta-prod` |

Keep **production secrets in a separate tenant**. A project tenant can hold all
lower environments in one place; writing `environment=PROD` there is rejected by
the API with a clear error. This limits blast radius if a lower-env credential
or policy is compromised.

Promote ACC → PROD by **copying** the secret into the production tenant (do not
flip the label in the lower-env tenant). Automatic promotion workflows are out
of scope for v1.

Environment is **not** the same as HA region (Manchester / London replication).

## Tag conventions

- Prefer lowercase kebab-case: `postgres`, `api-key`, `observability`
- Key/value style is allowed: `app:billing`, `team:platform`
- Never put secret values in tags or custom metadata

## Policy note (v1)

Authorization remains path-based (`secret/data/{path}`). Environment and tags
are advisory for filtering and UX in v1 — they are enforced on write against the
tenant’s `allowed_environments`, but policy documents do not yet constrain by
environment.

## API sketch

- `POST /v1/tenants` — optional `tenant_kind`, `allowed_environments`,
  `default_environment`, `tags`. Defaults: project → INT/TEST/ACC + INT;
  production → PROD only.
- `POST /v1/secret/data/{path}` — optional `environment`, `tags` (mirrored into
  reserved `metadata` keys `environment` and comma-joined `tags`)
- `GET /v1/secret/metadata/{path}` — returns `environment`, `tags`, `metadata`
- `GET /v1/secret/list?environment=TEST&tag=database` — AND filters; response
  keeps `paths` for compatibility and adds `secrets[]` with labels

## Schema

Migration `035_secret_tags_environments.sql` adds columns on `system.tenants`
and `shared.secrets` (plus dedicated tenant schemas).

See also `docs/prompts/secret-tags-and-environments.md`.
