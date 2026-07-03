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

## Audit Trail

- Every operation produces an `AuditEvent` with:
  - Timestamp, principal, tenant, action, resource, outcome, client IP
- Events are HMAC-SHA256 signed before storage (tamper-evident)
- Audit logs are append-only; no UPDATE or DELETE operations permitted
- Monthly partitioning for efficient archival and retention management
