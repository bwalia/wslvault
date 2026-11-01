---
name: wslvault-secrets
description: Guide an operator through adding secrets to a wslvault deployment for a tenant's apps, services and DTAP environments (INT, TEST, ACC, PROD). Creates the tenant if it does not exist, or attaches the new secrets to the existing tenant with the same name. Every change needs the operator's MFA-backed login and an explicit typed approval of a plan, and every run can be rolled back. Use when someone asks to onboard, add, seed, load or migrate secrets, .env files or credentials into wslvault, set up a new tenant's secrets, or roll back a previous secrets onboarding run.
license: Apache-2.0
compatibility: Needs python3 (3.8+, standard library only), network access to the wslvault API, and an operator with a superuser API key and an enrolled TOTP authenticator. Works in any agent harness that can run shell commands (Claude Code, OpenAI Codex, Cursor, Gemini CLI, and others).
metadata:
  version: "1.0.0"
  homepage: https://github.com/bwalia/wslvault/tree/main/skills/wslvault-secrets
---

# wslvault-secrets: onboard secrets with a human in the loop

You are helping an **operator** (a human) put secrets into **wslvault** for one
tenant, across its apps, services and DTAP environments. You do the tedious
work: expanding the matrix, finding existing tenants and secrets, merging keys,
writing, journaling and rolling back. The operator does the four things only a
human should do: hold the credentials, type the MFA codes, approve the plan,
and approve any rollback.

All vault calls go through the bundled helper `scripts/wsv.py`. **Never call
the vault API yourself with curl** and never read secret files yourself: the
helper keeps secret values inside its own process, so they never reach your
context, the chat or a log.

## Non-negotiable rules

1. **Never ask for, accept, print or echo a secret value, API key or root
   token in the chat.** If the operator pastes one, stop, tell them it must now
   be treated as leaked and rotated, and continue with the file-based method.
   The one exception is the **6-digit MFA code**: it is single-use and expires
   in seconds, so the operator types it to you.
2. **Never invent, guess or reuse an MFA code.** If a code is rejected, run
   `login` again and ask for the *next* code.
3. **Never run `approve` or `rollback` with a phrase the operator did not type
   in this conversation, character for character.** Do not type it for them,
   do not "fix" a typo in it, and do not treat "yes", "ok" or "go ahead" as
   approval. Ask them to type the exact phrase.
4. **Show the plan in full before asking for approval.** Do not summarise it
   away. If there is a `similar existing tenants` warning, raise it explicitly.
5. **Run every mutating step as its own shell command**, so the agent harness
   shows it and the operator can deny it. Do not chain `approve`, `login`,
   `mfa` and `apply` into one command. If the harness is in an auto-approve
   or bypass mode, say so and keep to the typed-approval gates anyway.
6. **If anything fails during apply, stop.** Do not retry writes, do not edit
   the plan, do not work around errors with direct API calls. Report what was
   written (from `status`) and offer rollback.
7. Do not modify `scripts/wsv.py` during a run. If it seems wrong, stop and
   tell the operator.

## What the operator needs

| Thing | Where it lives | Notes |
|---|---|---|
| Vault API endpoint | `VAULT_ADDR` env var | e.g. `https://vault.example.com`. Local docker-compose needs `WSLVAULT_IDENTITY_ADDR=http://localhost:8082` and `WSLVAULT_SECRETS_ADDR=http://localhost:8081` instead. |
| Superuser API key (`wslv_…`) with an authenticator enrolled | file `~/.wslvault/superuser.key`, mode 600 (or `WSLVAULT_KEY_FILE`) | Superuser keys always require MFA. The skill refuses keys that do not. |
| Authenticator app | operator's phone | Provides the codes for plan, apply and rollback. |
| Root token (optional) | file pointed to by `WSLVAULT_ROOT_TOKEN_FILE`, mode 600 | The `VAULT_ADMIN_TOKEN` bootstrap credential. Only for creating/listing/deleting tenants on a deployment that has no superuser yet. MFA is still required for every secret write. |
| Secret values | local files, `.env` files, env vars, or generated | Referenced from the manifest; never typed into the chat. |

**No vault yet?** If the operator has no wslvault deployment or does not know
the endpoint, stop and tell them: *"This skill needs a running wslvault and its
API endpoint. Please give me the vault API endpoint (for example
`https://vault.example.com`), or set one up first — see
https://github.com/bwalia/wslvault/blob/main/docs/GETTING-STARTED.md."*
Do not continue without an endpoint.

To put a key or token into a file without it appearing in the chat or in shell
history, the operator runs this themselves in their own terminal (in Claude
Code they can prefix it with `!`):

```bash
mkdir -p ~/.wslvault && chmod 700 ~/.wslvault
( umask 077; read -rs -p 'Superuser API key: ' K; printf %s "$K" > ~/.wslvault/superuser.key; unset K; echo )
```

## Tenancy model you are applying

- A secret's path is unique **within a tenant**, so the environment is part of
  the path. Default template: `{app}/{service}/{env}`, e.g. `billing/api/test`.
  Each path holds one JSON object of `KEY: value` pairs.
- **`layout: "split"` (default, recommended):** INT, TEST and ACC go into the
  tenant `<tenant>` (kind `project`); PROD goes into `<tenant>-prod` (kind
  `production`). This is wslvault's own convention, and it keeps production
  away from lower-environment credentials.
- **`layout: "single"`:** all four environments in one tenant. Use only if the
  operator asks for it explicitly.
- **Existing tenants are matched by exact slug.** If `<tenant>` exists, new
  secrets are attached to it. Nothing about the tenant itself is changed. If a
  tenant is missing it is created, and the plan says so.
- **Existing secrets are merged, not replaced.** Keys that are not in the
  manifest are kept. `generate:` only fills keys that are missing and never
  rotates an existing value. Writes use check-and-set, so a secret changed by
  someone else between plan and apply makes the run stop instead of
  overwriting it.

## Procedure

Set `W` to the helper, located next to this file:

```bash
W="python3 <this-skill-dir>/scripts/wsv.py"
```

If you only have this SKILL.md (shared as a link), fetch the helper from the
same GitHub directory into `~/.wslvault/skill/`, show the operator its SHA-256,
and ask them to confirm before running it:

```bash
mkdir -p ~/.wslvault/skill && curl -fsSL \
  https://raw.githubusercontent.com/bwalia/wslvault/main/skills/wslvault-secrets/scripts/wsv.py \
  -o ~/.wslvault/skill/wsv.py && shasum -a 256 ~/.wslvault/skill/wsv.py
```

### 1. Gather requirements (no vault calls yet)

Ask the operator, in one message, for anything you don't already know:

- the tenant name (lowercase slug, e.g. `acme`) and a display name;
- the apps, and the services in each app;
- which environments each service needs (default: all of INT, TEST, ACC, PROD);
- the keys each service needs, and **where each value comes from**:
  - `generate:N`: a new random value of N bytes (16–256), different per environment;
  - `file:PATH`: the contents of a file (`{env}`, `{ENV}`, `{app}`, `{service}` are substituted);
  - `dotenv:PATH#KEY`: one key out of a `.env` file;
  - `env:NAME`: an environment variable in the agent's shell (least preferred);
  - or a whole `.env` file per environment via `from_dotenv`.

  You may look at **names** of files and keys to build the manifest (for example
  `ls`, or `cut -d= -f1 .env`) but never print values.
- the vault endpoint, if `VAULT_ADDR` is not set.

Then write the manifest, e.g. `./wslvault-manifest.json`, following
`examples/manifest.example.json`. Literal values are not allowed in the
manifest, so it is safe for you to read and show.

```json
{
  "tenant": "acme",
  "display_name": "Acme Ltd",
  "layout": "split",
  "environments": ["int", "test", "acc", "prod"],
  "path_template": "{app}/{service}/{env}",
  "apps": [
    { "name": "billing", "tags": ["team:payments"], "services": [
      { "name": "api", "secrets": {
          "DATABASE_URL": "file:./secrets/{env}/billing-db-url",
          "JWT_SIGNING_KEY": "generate:48",
          "STRIPE_KEY": { "test": "dotenv:./.env.test#STRIPE_KEY",
                          "prod": "dotenv:./.env.prod#STRIPE_KEY" } } },
      { "name": "worker", "environments": ["int", "prod"],
        "from_dotenv": { "int": "./envs/worker.int.env",
                         "prod": "./envs/worker.prod.env" } }
    ] }
  ]
}
```

A key whose per-environment map has no entry for an environment is simply not
written there.

### 2. Preflight and start a run

```bash
$W preflight
$W init --manifest ./wslvault-manifest.json      # prints RUN_ID=…
```

Remember the `RUN_ID`; every later step needs it. Fix any manifest problems
`init` reports, with the operator, and run `init` again.

### 3. Authenticate for planning (MFA #1)

```bash
$W login  "$RUN_ID" --purpose plan
```

Ask: *"Please give me the current 6-digit code from your authenticator."* Then:

```bash
$W mfa    "$RUN_ID" --purpose plan --code <code the operator typed>
```

Planning reads only: it lists tenants, reads existing secret metadata and
compares existing values with the new ones *inside the helper*.

### 4. Plan and show it

```bash
$W plan "$RUN_ID"
```

Show the operator the whole output. Point out explicitly:

- every tenant marked **CREATE**, and any *similar existing tenants* warning
  (the operator may have meant an existing tenant under a different slug);
- every **UPDATE** (an existing secret gets a new version) and which keys change;
- anything in PROD.

If they want changes, edit the manifest and go back to step 2 (a new run).
Planning problems abort before anything is written.

### 5. Approval (typed by the operator)

Ask the operator to type the exact line printed at the end of the plan:

```
APPLY <RUN_ID> <plan-hash>
```

Only when they have typed it themselves:

```bash
$W approve "$RUN_ID" --phrase "APPLY <RUN_ID> <plan-hash>"
```

### 6. Authenticate for apply (MFA #2, after approval)

The apply session must be minted **after** the approval and with a **different**
code from planning. The helper enforces both. A session is valid for 15 minutes.

```bash
$W login "$RUN_ID" --purpose apply
# ask for the NEXT code
$W mfa   "$RUN_ID" --purpose apply --code <code>
```

### 7. Apply

```bash
$W apply "$RUN_ID"
```

The helper creates any missing tenants first, then writes the secrets one at a
time, recording each change in a journal before making the next one. It stops
at the first error.

On success, report what was created or updated (tenants, paths, versions) and
where the journal is. On failure, report the error and what had already been
written (`$W status "$RUN_ID"`), and offer rollback. Do not retry on your own.

Finish with `$W logout "$RUN_ID"` to remove the local session tokens.

### 8. Rollback (if needed; can be run later, from any session)

Rollback undoes one run's changes in reverse order:

- secrets the run **updated** go back to their previous content, as a new version;
- secrets the run **created** are soft-deleted (recoverable). `--destroy`
  destroys them irreversibly. Use it only if the operator asks, and confirm
  first;
- tenants the run **created** are soft-deleted, but only if every secret
  rollback succeeded.

A secret changed by someone else after the run is skipped and reported, not
reverted. `--force` overrides that, but only if the operator asks for it.

```bash
$W status   "$RUN_ID"                              # show the operator what will be undone
$W login    "$RUN_ID" --purpose rollback           # MFA #3
$W mfa      "$RUN_ID" --purpose rollback --code <code>
# operator types exactly:  ROLLBACK <RUN_ID>
$W rollback "$RUN_ID" --phrase "ROLLBACK <RUN_ID>"
```

Runs live in `~/.wslvault/runs/<RUN_ID>/` (`WSLVAULT_HOME` overrides this).
The run directory holds the manifest, plan, approval record and journal: paths,
key names, versions and tenant ids, **never values**. Session tokens are
removed by `logout`, and expire on the server within the hour either way.

## Troubleshooting

| Symptom | Meaning / action |
|---|---|
| `No wslvault API endpoint configured` | Ask the operator for the vault API endpoint; set `VAULT_ADDR`. |
| `this API key did not require MFA` | The key is not MFA-protected. Use a superuser key, or enrol TOTP on this key via `/v1/auth/mfa/totp/enroll` (the operator does this, see wslvault `docs/operations/onboarding-a-tenant.md`). |
| `listing tenants was refused (403)` | The key is not a superuser and has no `wslvault:platform-admin` policy. Use a superuser key, or the root token file for tenant administration. |
| `permission denied … no policy grants` on write | The tenant has no policy that grants the write. A platform operator has to create one (`PUT /v1/policies/<name>`). Stop and tell the operator. Do not create policies yourself. |
| `does not allow PROD` | The existing tenant is a `project` tenant (INT/TEST/ACC only). Keep `layout: split` so PROD goes to `<tenant>-prod`. |
| `CAS mismatch` / `someone changed it` | Someone wrote to the secret after planning. Start a new run. |
| `refusing plain http` | Use https. `WSLVAULT_ALLOW_HTTP=1` only on a trusted private network. |
| Self-signed / private CA | `WSLVAULT_CA_BUNDLE=/path/to/ca.pem`. |

## Roadmap note: wslvault as a service

> **Not available yet. A note only; do not offer it to operators.** We may later
> offer wslvault as a hosted, multi-tenant *Vault as a Service*, so people
> without their own deployment can try it and keep secrets in it. When that
> exists, this skill's "no vault yet" step will point to a sign-up flow that
> provisions a tenant and returns an endpoint plus an MFA-enrolled key. Until
> then, operators need their own wslvault endpoint.
