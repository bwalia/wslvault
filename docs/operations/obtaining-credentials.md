# Obtaining credentials

How to get a working credential for the web console, the API, and admin
operations — and what to do when the one you have stops working.

---

## TL;DR — a key for the web console

```bash
export KUBECONFIG=~/.kube/k3s1.yaml

# 1. An admin JWT already exists for External Secrets Operator.
ADMIN=$(kubectl -n int get secret wslvault-token -o jsonpath='{.data.token}' | base64 -d)

# 2. Its tenant.
TENANT=$(curl -s https://vault.workstation.co.uk/v1/auth/token/lookup-self \
           -H "X-Vault-Token: $ADMIN" | jq -r .data.meta.tenant_id)

# 3. Mint an API key.
curl -s -X POST https://vault.workstation.co.uk/v1/api-keys \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"name\":\"vault-ui-login\",\"tenant_id\":\"$TENANT\",\"policies\":[\"root\",\"admin\",\"default\"]}" \
  | jq -r .key
```

That prints a `wslv_…` key. Paste it into <https://vault-ui.workstation.co.uk/login>.

**The raw key is shown exactly once.** Only its SHA-256 hash is stored, so a
lost key cannot be recovered — mint a new one and revoke the old.

---

## The three credential types

| | Looks like | Lifetime | Used for |
|---|---|---|---|
| **API key** | `wslv_<43 chars>` | until revoked | logging into the console; long-lived automation |
| **Session token** | JWT (`eyJ…`) | **1 hour** | every API call after login |
| **Bootstrap token** | operator-chosen | until rotated | creating the first key of a fresh deployment |

The console takes an **API key**, exchanges it once for a **session token**,
and uses that token for everything after. You never paste a JWT into the UI.

---

## Why your key stopped working

`{"code":"key_not_found","message":"api key not found"}` on a key you know is
correct almost always means **identity-service restarted**.

API keys were held in an in-process `HashMap` until the persistence work landed
(`shared.api_keys`, migration `005` + `016`). Any deployment still running an
image from before that keeps keys in memory, so every restart — a `helm
upgrade`, a node drain, an OOM kill — silently invalidates every key ever
minted.

Check what is actually running:

```bash
kubectl -n wslvault get deploy wslvault-identity-service \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

If that tag predates the persistence merge, expect to re-mint after restarts.
There is nothing to recover: mint a new key.

> **Keys are per-region.** They do not replicate. A key minted against
> region A returns `key_not_found` on region B, and vice versa. Mint against
> the region you intend to use, or mint one in each. See
> `docs/ha-two-region.md`.

---

## Bootstrapping a deployment with no admin key

The step above needs an admin credential you do not yet have. For a fresh
deployment, `VAULT_ADMIN_TOKEN` is the way in:

```yaml
identityService:
  extraEnv:
    - name: VAULT_ADMIN_TOKEN
      valueFrom:
        secretKeyRef: {name: wslvault-bootstrap, key: token}
```

```bash
curl -s -X POST https://<host>/v1/api-keys \
  -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"bootstrap","tenant_id":"<tenant>","policies":["root","admin"]}'
```

Then **remove `VAULT_ADMIN_TOKEN` and redeploy.** It is a static shared secret
with full administrative rights and no expiry; it exists to create the first
key, not to stay in the environment.

`VAULT_ADMIN_POLICY` (default `admin`) selects which policy a JWT caller must
hold to use the admin endpoints.

---

## Rotating and revoking

```bash
# List (never returns raw keys — only id, prefix, name, policies)
curl -s https://vault.workstation.co.uk/v1/api-keys \
  -H "Authorization: Bearer $ADMIN" | jq '.[] | {id, key_prefix, name}'

# Rotate: issues a new raw key, keeps the id and grants
curl -s -X POST https://vault.workstation.co.uk/v1/api-keys/<id>/rotate \
  -H "Authorization: Bearer $ADMIN" | jq -r .key

# Revoke
curl -s -X DELETE https://vault.workstation.co.uk/v1/api-keys/<id> \
  -H "Authorization: Bearer $ADMIN"
```

Revoked keys stay in the table as an audit trail. Migration `016` scopes name
uniqueness to *active* keys, so a replacement may reuse the revoked key's name
— before it, rotation-by-name failed on a unique-constraint violation.

---

## Identifying a key you already hold

The 8 characters after `wslv_` are the `key_prefix`, stored in clear
specifically so a key can be identified in logs and lists without exposing it:

```
wslv_kAQ3fR9c...
     ^^^^^^^^ key_prefix — safe to quote in a ticket
```

Match it against `GET /v1/api-keys`. If nothing matches, that key is not
registered in this region.

---

## Handling

- Never commit a `wslv_` key. GitGuardian scans every PR in this repo.
- Prefer piping straight into `kubectl create secret` over a file on disk.
- If you must stash one locally, `chmod 600` it and treat `/tmp` as ephemeral.
- Rotate anything that has been pasted into a chat, a ticket, or a shell that
  writes history.
- One key per consumer, so revoking one does not take down the rest.
