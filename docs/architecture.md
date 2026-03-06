# WSLVault Architecture

## Overview

WSLVault is a next-generation secrets management platform designed for enterprise production environments and multi-tenant SaaS deployments.

## Three-Layer Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Clients                            │
│  (SDKs, CLI, Web UI, AI Agents via MCP)             │
└──────────────────────┬──────────────────────────────┘
                       │ HTTPS
┌──────────────────────┴──────────────────────────────┐
│              Layer 1: Edge Gateway                    │
│           (OpenResty / NGINX + LuaJIT)               │
│  • TLS termination    • Token validation             │
│  • Rate limiting      • Request routing              │
│  • Secret caching     • Tenant isolation             │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP / gRPC
┌──────────────────────┴──────────────────────────────┐
│           Layer 2: Rust Core Services                │
│                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐    │
│  │ secret-  │ │ crypto-  │ │ identity-        │    │
│  │ engine   │ │ service  │ │ service          │    │
│  └──────────┘ └──────────┘ └──────────────────┘    │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐    │
│  │ policy-  │ │ transit- │ │ lease-           │    │
│  │ engine   │ │ engine   │ │ manager          │    │
│  └──────────┘ └──────────┘ └──────────────────┘    │
│  ┌──────────┐ ┌──────────┐                          │
│  │ audit-   │ │ mcp-     │                          │
│  │ service  │ │ server   │                          │
│  └──────────┘ └──────────┘                          │
└──────────────────────┬──────────────────────────────┘
                       │ SQL (TLS)
┌──────────────────────┴──────────────────────────────┐
│         Layer 3: Encrypted Storage                   │
│              PostgreSQL 16                            │
│  • All secrets encrypted at rest (AES-256-GCM)      │
│  • Schema-per-tenant isolation                       │
│  • Partitioned audit logs                            │
└─────────────────────────────────────────────────────┘
```

## Service Responsibilities

| Service | Port (HTTP) | Port (gRPC) | Responsibility |
|---------|-------------|-------------|----------------|
| crypto-service | 8080 | 50051 | Key management, envelope encryption, DEK generation |
| secret-engine | 8081 | 50052 | KV secrets CRUD, versioning, CAS writes |
| identity-service | 8082 | 50054 | Authentication, JWT tokens, SCIM, OIDC |
| policy-engine | 8083 | 50053 | RBAC policy evaluation, path-based access control |
| lease-manager | 8084 | 50055 | Lease lifecycle, automatic expiration, renewal |
| audit-service | 8085 | 50056 | Immutable audit logging, HMAC integrity |
| transit-engine | 8086 | — | Encryption-as-a-service (encrypt/decrypt/sign/verify) |
| mcp-server | 8087 | — | AI agent integration via Model Context Protocol |
| gateway | 443/8080 | — | Edge routing, TLS, rate limiting, caching |

## Envelope Encryption Hierarchy

```
Root KEK (AWS KMS / HSM)
  └─► Tenant KEK (per-tenant, encrypted under Root KEK)
       └─► DEK (per-secret, encrypted under Tenant KEK)
            └─► Secret Value (AES-256-GCM encrypted under DEK)
```

- Root KEK never leaves KMS/HSM
- Tenant KEKs are stored encrypted in PostgreSQL
- DEKs are generated per-secret and stored alongside the ciphertext
- Database compromise does not expose plaintext secrets

## Data Flow: Secret Read

```
1. Client → Gateway:     GET /v1/secret/data/prod/db/password
2. Gateway → token_auth: Validate JWT, extract tenant_id
3. Gateway → secret-engine: Forward with X-Vault-Tenant-ID header
4. secret-engine → crypto-service: Decrypt(tenant_id, ciphertext, aad)
5. crypto-service:       Unwrap DEK → Decrypt secret → Return plaintext
6. secret-engine → Gateway → Client: JSON response with secret data
7. audit-service:        Async audit event emitted
```

## Technology Stack

- **Core Engine**: Rust + Tokio async runtime
- **Inter-service**: gRPC (tonic) + Protobuf (prost)
- **HTTP API**: axum web framework
- **Database**: PostgreSQL 16 with encrypted storage
- **Edge Gateway**: OpenResty (NGINX + LuaJIT)
- **Cryptography**: AES-256-GCM, HKDF-SHA256, Ed25519
- **Observability**: OpenTelemetry, Prometheus, structured JSON logging
- **Deployment**: Docker, Kubernetes (Kustomize), Terraform (AWS)
