# WSLVault Security Model

## Threat Model

WSLVault is designed to protect against the following threats:

### Database Compromise
- All secret values are encrypted with AES-256-GCM before storage
- DEKs are encrypted under tenant KEKs; tenant KEKs under root KEK
- Root KEK lives in AWS KMS / HSM — never in the database
- Database access alone cannot decrypt any secret

### Service Compromise
- Each service runs with minimum necessary permissions
- crypto-service is the only service that handles raw key material
- Key material uses `ZeroizeOnDrop` — wiped from memory when no longer needed
- Plaintext secrets exist in memory only for the duration of a single request

### Network Eavesdropping
- All external traffic via TLS 1.2+ through the gateway
- Inter-service communication uses gRPC with optional mTLS
- Secrets never appear in logs (custom Debug impls redact sensitive fields)

### Unauthorized Access
- Every API request requires a valid JWT token
- Policy engine evaluates RBAC policies for each operation
- Tenant isolation enforced at every layer (gateway, service, database)
- Audit trail for every operation (immutable, HMAC-signed)

## Cryptographic Primitives

| Algorithm | Usage |
|-----------|-------|
| AES-256-GCM | Secret encryption (envelope encryption) |
| HKDF-SHA256 | Key derivation from master material |
| HMAC-SHA256 | Audit log integrity, JWT signing |
| Ed25519 | Digital signatures (future: transit engine) |

## Key Material Lifecycle

1. **Root KEK**: Loaded at startup via a pluggable `RootKeyProvider` (see below); never stored in plaintext on disk or in the database.
2. **Tenant KEK**: Generated on tenant creation; encrypted under Root KEK; stored (wrapped) in DB
3. **DEK**: Generated per-secret-write; encrypted under Tenant KEK; stored alongside ciphertext
4. **Rotation**: New key version created; old versions decrypt existing data; re-encryption on access

## Root Key Provider Model

The root KEK source is selected via the `VAULT_ROOT_KEY_PROVIDER` environment variable:

| Value | Description |
|-------|-------------|
| `env` (default) | Reads `VAULT_ROOT_KEY` (standard base64, 32 bytes). Backward-compatible. |
| `aws-kms` | Decrypts an encrypted root key blob via AWS KMS `Decrypt`. Requires the `aws-kms` Cargo feature and `VAULT_KMS_KEY_ID` + `VAULT_ROOT_KEY_CIPHERTEXT` env vars. |

**AWS KMS bootstrap (one-time):** Set `VAULT_KMS_GENERATE=true` (with no `VAULT_ROOT_KEY_CIPHERTEXT`) to call `GenerateDataKey(AES_256)`, log the `CiphertextBlob` in base64, and use the plaintext for the current session. The operator must persist the logged blob as `VAULT_ROOT_KEY_CIPHERTEXT` before the next restart.

All plaintext key bytes returned by the provider are held in `Zeroizing<[u8; 32]>` wrappers and wiped on drop.

## Memory Safety

- All key material types implement `ZeroizeOnDrop`
- `PlaintextSecret` implements `ZeroizeOnDrop` — plaintext wiped after request completes
- `KeyMaterial` custom `Debug` implementation prints `[REDACTED]` instead of key bytes
- No secret values in error messages, log output, or stack traces

## Multi-Tenant Isolation

- Gateway extracts tenant_id from JWT and enforces it on every request
- Database: schema-per-tenant for dedicated/sovereign tiers
- Policy evaluation is tenant-scoped — policies from one tenant cannot affect another
- Audit logs are partitioned by tenant_id

## Network Isolation (Kubernetes)

The Helm chart deploys a zero-trust NetworkPolicy model
(`deploy/helm/wslvault/templates/networkpolicies.yaml`, gated by
`networkPolicies.enabled`):

- **Default deny**: `{release}-default-deny` blocks all ingress *and* egress
  for every pod in the namespace. Every legitimate flow below is an explicit,
  additive allow policy — anything not listed is rejected by the kernel
  (k3s network-policy controller, `KUBE-POD-FW-*` REJECT chains).
- **Ingress path**: only the Traefik ingress controller (kube-system) may
  reach service pods; external clients terminate TLS at the edge PoP
  (wslproxy) which re-encrypts to Traefik's `websecure` entrypoint. All
  Ingress objects pin `router.entrypoints: websecure`, so plain-HTTP routes
  do not exist inside the cluster.
- **East-west**: per-service policies mirror the call graph (see the traffic
  topology comment at the top of `networkpolicies.yaml`); only PostgreSQL,
  audit ingest, and declared service-to-service ports are open.
- **DNS**: a single policy permits egress to kube-dns on port 53.

### wslproxy host ingress to vault-ui (`ui.wslproxyIngress`)

`{release}-vault-ui-allow-wslproxy-hosts` (in `templates/vault-ui.yaml`) is
an optional, additive policy rendered only when `ui.wslproxyIngress.cidrs`
is non-empty. It exists because the edge chain has a variant where a
wslproxy instance running **on a cluster node's host network** proxies
straight to the vault-ui ClusterIP, bypassing Traefik. Host-originated
traffic reaches pods with the node's flannel address as its source
(`flannel.1` = `x.y.z.0` cross-node, `cni0` = `x.y.z.1` same-node) — a
source class no other policy covers, so default-deny rejects it.

- List one `/31` per wslproxy node, derived from the node's `podCIDR`
  (e.g. `podCIDR 10.42.16.0/24` → `10.42.16.0/31`). Never widen this to the
  pod CIDR (`10.42.0.0/16`): that would let every pod in the cluster reach
  the UI port directly.
- Leave `cidrs` empty (the default) when the edge enters via Traefik's 443 —
  the deny-all model then stays fully intact. Prefer that path: it keeps the
  hop encrypted (the pod-overlay VXLAN is not) and keeps Traefik as the
  single audited entry point.

### wslproxy host ingress to the API services (`networkPolicies.wslproxyHostIngress`)

`{release}-allow-wslproxy-hosts` (in `templates/networkpolicies.yaml`) is the
API-side counterpart of the vault-ui policy above: when the whole release is
pinned to the edge PoP node (`global.scheduling`), the node-local wslproxy /
traefik-edge origin hop reaches the API pods with the node's flannel host
address as source, which default-deny would otherwise reject. The policy
allows only the `/31` host addresses in `cidrs` (anchored to
`global.edgeHostCidrs`) to the declared public API HTTP ports — the same
route set as `edgeIngress.routes`. gRPC and PostgreSQL ports stay closed to
host traffic.

### Single-node placement (`global.scheduling`)

The entire release — every service, vault-ui, and PostgreSQL — is
co-scheduled onto one node via `global.scheduling` in `values.yaml`
(currently `cloud001`, the public edge PoP origin). This is a deliberate
constraint: pods on cloud001 cannot reach pods on other nodes (flannel VXLAN
to the LAN nodes is unroutable), so splitting the stack across nodes silently
partitions it. Placement, tolerations, and the edge-host CIDRs are wired from
a single block via YAML anchors — re-pinning the stack is a one-block edit.

### Hardening checklist for the edge path

- wslproxy origin must target Traefik `websecure` (443) with SNI/Host
  preserved; a plain-HTTP origin can never match the websecure-pinned
  routers.
- The origin TLS certificate (`wslvault-gateway-tls`) is self-signed; to
  enable origin verification at the PoP, add the UI hostname to the SANs,
  reference the secret from the vault-ui Ingress `tls` block, and set
  `proxy_ssl_verify on` with the pinned certificate in wslproxy.
- Do not expose the UI via NodePort: node ports bind on every node,
  including public cloud nodes, bypassing the PoP entirely.

## Audit Trail

- Every operation produces an `AuditEvent` with:
  - Timestamp, principal, tenant, action, resource, outcome, client IP
- Events are HMAC-SHA256 signed before storage (tamper-evident)
- Audit logs are append-only; no UPDATE or DELETE operations permitted
- Monthly partitioning for efficient archival and retention management
