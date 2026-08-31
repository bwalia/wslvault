# WSLVault

A self-hosted, multi-tenant secrets platform: envelope-encrypted secret storage,
transit encryption-as-a-service, PKI, dynamic identity, policy-based
authorization, and cross-region replication — with a HashiCorp Vault-compatible
KV v2 API so existing tooling works unchanged.

## What it is

Thirteen Rust services behind an OpenResty gateway, backed by PostgreSQL.

| Service | Does |
|---|---|
| `crypto-service` | Root KEK custody and the seal, tenant KEKs, DEKs, envelope encryption |
| `secret-engine` | KV v2 secret storage, versioning, rotation; native and Vault-compatible mounts |
| `identity-service` | Authentication (OIDC, Kubernetes, AWS IAM, Azure, LDAP, mTLS, device flow, SCIM, API keys) and tokens |
| `policy-engine` | Tenant-scoped ACL evaluation |
| `transit-engine` | Encryption as a service — encrypt/decrypt/rewrap without storing the plaintext |
| `pki-engine` | Certificate authority: issue, sign, revoke, CRL |
| `audit-service` | Hash-chained, per-tenant-signed audit log |
| `lease-manager` | Lease lifecycle, renewal, expiry |
| `replication-agent` | Cross-region replication with vector-clock conflict resolution |
| `region-health`, `sync-scheduler` | Region status; scheduled sync to external secret stores |
| `k8s-operator` | `VaultSecret` / `VaultPolicy` CRDs reconciled into native Kubernetes Secrets |
| `mcp-server` | Model Context Protocol server, so AI agents can use the vault as a tool |

Plus a Next.js UI, a CLI, and SDKs for Go, Python, TypeScript and Rust.

## Quick start

```bash
docker compose up -d          # Postgres + every service
./scripts/e2e-tests.sh        # smoke test the running stack
```

The UI is on `:3011`, the gateway on `:8080`.

## Initialising a vault

A fresh vault starts **sealed**: the root key is split into Shamir shares and no
single holder can open it.

```bash
# Once, ever. The shares are shown once and cannot be recovered.
curl -sX POST localhost:8080/v1/sys/init \
     -d '{"secret_shares":5,"secret_threshold":3}'

# After every restart: three different share holders each POST theirs.
curl -sX POST localhost:8080/v1/sys/unseal -d '{"key":"<share>"}'

curl -s localhost:8080/v1/sys/seal-status
```

Until unsealed, every operation that touches key material returns `503 sealed`.

`VAULT_ROOT_KEY` still works and boots unsealed, for deployments that predate
the seal. It warns on every start, because it means the root key lives in a
process environment — which is what the seal exists to replace.

## Using it

```bash
# Native API
curl -H "Authorization: Bearer $TOKEN" \
     localhost:8080/v1/secret/data/prod/db

# HashiCorp Vault-compatible mount — the vault CLI, Terraform provider and
# External Secrets Operator all speak this unchanged
VAULT_ADDR=http://localhost:8080 VAULT_TOKEN=$TOKEN vault kv get kv/prod/db
```

Identity always comes from the signed token. No API accepts a tenant or a
policy set as a request header unless an operator has explicitly opted in to the
gateway contract via `VAULT_TRUST_GATEWAY_HEADERS`, which is off by default.

## Deploying

```bash
helm install wslvault deploy/helm/wslvault \
  --set secrets.rootKey="$(openssl rand -base64 32)" \
  --set secrets.jwtSecret="$(openssl rand -base64 64)"
```

The chart refuses to render without real keys rather than emitting placeholders.
For production, supply them from an external secret manager via
`secrets.existingSecret`.

Kustomize overlays are in `deploy/kubernetes/`, Terraform in `deploy/terraform/`,
and a two-region GitOps setup in `deploy/gitops/`.

## Development

There is no local toolchain requirement beyond Docker:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Database migrations are `storage/postgres/init/*.sql`, applied in order. The
copies under `deploy/helm/wslvault/files/migrations/` must stay in sync.

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | How the services fit together |
| [Security model](docs/security-model.md) | Trust boundaries, NetworkPolicy, the gateway |
| [Status](docs/STATUS.md) | Honest assessment of what is built and what is not |
| [Deployment](docs/operations/deployment.md) | Running it for real |
| [Vault KV v2 compatibility](docs/operations/vault-kv2-compatibility.md) | What the compatible mount supports |
| [Tenant authentication](docs/tenant-authentication.md) | How tenants authenticate |
| [Two-region HA](docs/ha-two-region.md) | Active/active replication |

## Licence

Apache-2.0.
