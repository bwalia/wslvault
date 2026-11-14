# Vault KV v2 compatibility (using wslvault with External Secrets Operator)

wslvault exposes a **HashiCorp Vault KV v2-compatible** surface so tooling written
for Vault works against it unchanged. The immediate driver is the
[External Secrets Operator](https://external-secrets.io) (ESO), whose `vault`
provider is the standard way to sync secrets into Kubernetes, but the same
surface serves the `vault` CLI and the Terraform provider.

Implementation: [`services/secret-engine/src/kv2.rs`](../../services/secret-engine/src/kv2.rs).

## Why a separate mount

| | Path | Shape |
|---|---|---|
| Native wslvault | `/v1/secret/data/*` | `{"data": "<base64 blob>", "version": N, …}` |
| Vault-compatible | `/v1/kv/data/*` | `{"data": {"data": {…}, "metadata": {…}}}` |

The native shape is consumed by the UI, the SDKs and the CLI, so changing it
would break them. The compatible surface therefore lives at its own mount,
`kv`. Both mounts read and write the *same* underlying secrets, with the same
envelope encryption, versioning and policy checks.

## The data-model difference (important)

Vault KV v2 stores a **map of key → value** at a path. wslvault natively stores
**one opaque blob**. The compat layer bridges this by serialising the map to
JSON and storing that as the blob:

```
write {"data":{"POSTGRES_HOST":"db","POSTGRES_PORT":"5432"}}
  -> stored blob: {"POSTGRES_HOST":"db","POSTGRES_PORT":"5432"}
read  -> {"data":{"data":{"POSTGRES_HOST":"db","POSTGRES_PORT":"5432"}, "metadata":{…}}}
```

A blob that is **not** a JSON object — e.g. one written through the native API —
is surfaced under a single `value` key (UTF-8 if valid text, base64 otherwise)
so pre-existing secrets remain readable through this mount rather than erroring.

This matters when planning a migration: to use `dataFrom.extract` in ESO (which
pulls *all* keys at a path into one Kubernetes Secret), write the secret through
the `kv` mount so it is stored as a JSON object.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/kv/data/<path>` | Read current version (`?version=N` for a specific one) |
| `POST` | `/v1/kv/data/<path>` | Write a new version (`options.cas` for check-and-set) |
| `GET` | `/v1/auth/token/lookup-self` | Token self-lookup; Vault clients probe this |
| `POST` | `/v1/auth/token/revoke-self` | Revoke the calling token (`204`); ESO calls it after each reconcile when it logged in via an auth method |
| `POST` | `/v1/auth/kubernetes/login` | Kubernetes service-account login (identity-service); returns Vault's `auth.client_token` shape |
| `GET` | `/v1/sys/health` | Vault-shaped health |

Errors use Vault's `{"errors": ["…"]}` body, not wslvault's native
`{"code","message"}`, because Vault clients parse that shape.

## Authentication

Identity is resolved in this order:

1. `X-Tenant-Id` (+ `X-Principal-Id`, `X-Policies`) — the internal contract the
   native handlers use.
2. `X-Vault-Tenant-ID` (+ `X-Vault-Principal-ID`, `X-Vault-Policies`) — what
   `gateway/lua/auth/token_auth.lua` injects on a token-cache hit.
3. `X-Vault-Token` or `Authorization: Bearer …` — a wslvault JWT, **verified**
   with HS256 against the shared `VAULT_JWT_SECRET`.

> **`VAULT_JWT_SECRET` must be set on secret-engine**, matching the value
> identity-service signs with. Tier 3 **fails closed**: without it, tokens are
> rejected rather than trusted. Accepting unverified claims would let any caller
> that can reach the service assert an arbitrary tenant.

The gateway (`token_auth.lua`) accepts `X-Vault-Token` as well as
`Authorization: Bearer`, so Vault clients are not rejected at the edge.

Requests still pass the existing `X-Gateway-Auth` origin check, so the compat
mount inherits exactly the same protection as the native API.

## Wiring up ESO

1. Store the token ESO should use:

```bash
kubectl -n <ns> create secret generic wslvault-token --from-literal=token='<jwt>'
```

2. Create the store (`ClusterSecretStore` for cluster-wide use):

```yaml
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: wslvault-backend
spec:
  provider:
    vault:
      server: "https://vault.workstation.co.uk"
      path: "kv"          # the compat mount
      version: "v2"
      auth:
        tokenSecretRef:
          name: wslvault-token
          namespace: <ns>
          key: token
```

3. Consume it exactly as with HashiCorp Vault:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: myapp-secrets
spec:
  secretStoreRef:
    name: wslvault-backend
    kind: ClusterSecretStore
  target:
    name: myapp-secrets
  dataFrom:
    - extract:
        key: myapp/config      # -> GET /v1/kv/data/myapp/config
```

Because the request/response shapes match Vault's, an existing ExternalSecret
needs no changes beyond repointing `secretStoreRef` at this store.

## Kubernetes auth for ESO (per-tenant stores)

A static token in `tokenSecretRef` belongs to exactly one tenant, and secret
reads are tenant-scoped: a store whose token is in tenant A gets
`Secret does not exist` for a path that exists in tenant B. Production secrets
live in their own tenant by design (project tenants refuse PROD writes), so a
production store needs a credential in the production tenant.

Kubernetes auth gives each store one without a long-lived token: ESO mints a
short-lived token for a service account, identity-service checks it with the
TokenReview API and maps the role to a tenant and policies.

1. Enable it in the chart (`identityService.kubernetesAuth`, see values.yaml)
   with a role per store, e.g.

   ```yaml
   identityService:
     kubernetesAuth:
       enabled: true
       apiServer:
         cidrs: [10.43.0.1/32, <api-server endpoint IPs>/32]
       roles:
         closeknitty-prod:
           bound_service_account_namespaces: [external-secrets]
           bound_service_account_names: [closeknitty-prod-eso]
           tenant_id: <production tenant id>
           policies: [closeknitty-prod-read]
           audience: wslvault
   ```

2. In that tenant, create the policy the role names (read on the store's paths).

3. Point the store at it:

   ```yaml
   auth:
     kubernetes:
       mountPath: kubernetes
       role: closeknitty-prod
       serviceAccountRef:
         name: closeknitty-prod-eso
         namespace: external-secrets
         audiences: [wslvault]   # must equal the role's audience
   ```

Each reconcile logs in (one TokenReview), reads, and revokes its token via
`revoke-self`. Tokens are not renewable; ESO simply logs in again.

## Verifying by hand

```bash
TOKEN=<jwt>

# write a map
curl -sS -X POST https://vault.workstation.co.uk/v1/kv/data/myapp/config \
  -H "X-Vault-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"data":{"POSTGRES_HOST":"db","POSTGRES_PORT":"5432"}}'

# read it back — expect {"data":{"data":{...},"metadata":{...}}}
curl -sS https://vault.workstation.co.uk/v1/kv/data/myapp/config \
  -H "X-Vault-Token: $TOKEN"

# token self-lookup
curl -sS https://vault.workstation.co.uk/v1/auth/token/lookup-self \
  -H "X-Vault-Token: $TOKEN"
```

## Cluster prerequisites (learned the hard way)

Two things block ESO even when the mount itself is correct:

**1. NetworkPolicy.** The `wslvault` namespace is default-deny, so ESO cannot
reach the secret-engine and the store fails with `dial tcp …: connect:
connection refused`. Allow exactly that path:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: wslvault-allow-external-secrets, namespace: wslvault }
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/instance: wslvault
      app.kubernetes.io/name: secret-engine
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: external-secrets }
      ports: [{ protocol: TCP, port: 8081 }]
```

**2. Ingress routes.** `/v1/kv`, `/v1/auth/token` and `/v1/sys` must route to the
secret-engine, or requests 404 at the edge. `/v1/auth/token` has to be a *longer*
prefix than `/v1/auth` (identity-service) so Traefik's more-specific match wins.
Both the chart (`edgeIngress.routes`) and `deploy/k8s/wslvault-ingress.yaml`
carry these.

Pointing ESO at the in-cluster service (`http://wslvault-secret-engine.wslvault.svc.cluster.local:8081`)
avoids the public edge entirely and is the recommended configuration.

## What store validation actually requires

ESO does **not** just read the secret — it validates the store by calling
`/v1/auth/token/lookup-self` and asserting on the response. Two fields are
mandatory and their absence produces misleading "invalid vault credentials"
errors even when the credentials are perfect:

| Missing field | ESO error |
|---|---|
| `data.type` | `could not assert token type` |
| `data.expire_time` / non-zero `ttl` | `no expiration time found in response` |

Both are now returned, derived from the JWT's `exp`.

## Known gaps

Deliberately not implemented yet — add them if a client needs them:

- `DELETE /v1/kv/data/<path>` (soft delete) and `/v1/kv/destroy`, `/v1/kv/undelete`.
- `GET /v1/kv/metadata/<path>` and `LIST` (`?list=true`).
- `/v1/sys/internal/ui/mounts/<mount>` — some Vault clients probe it to detect
  the KV version. ESO does not need it when `version: "v2"` is set explicitly.
- Vault's own auth backends (`approle`, `kubernetes`, `jwt` logins under
  `/v1/auth/*/login`). Only pre-issued wslvault JWTs are accepted today, so ESO
  must use `tokenSecretRef` rather than `appRole`/`kubernetes` auth.
