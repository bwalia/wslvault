# WSLVault — Project Status

**Audit date:** 2026-07-10 · **Commit:** `c8b63fd` · **Branch:** `main`
**Scale:** ~47,000 lines of Rust · 4 library crates · 13 services · 1 OpenResty gateway · 275 unit tests (4 ignored)

This document is a ground-truth assessment of what is built, what is faked, and what is missing —
benchmarked against HashiCorp Vault (OSS and Enterprise). Every claim below is anchored to a
file and line number that was read directly.

---

## 1. Where you actually are

You have built a lot. The auth surface is broader than most Vault clones ever get (LDAP,
Kubernetes, AWS IAM, Azure workload identity, OIDC, mTLS, OAuth device flow, SCIM), the
multi-region replication engine has real conflict resolution, the MCP server is spec-compliant,
and the four SDKs plus CLI plus UI are genuine working code rather than scaffolding. The
envelope-encryption hierarchy (Root KEK → Tenant KEK → DEK) is correctly implemented and tested.

The honest summary is this: **WSLVault today is a well-architected multi-tenant secrets API. It is
not yet a vault.** The thing that makes Vault a *vault* — the seal/unseal ceremony, where the root
key is split, never persisted in the clear, and reconstructed at boot — does not exist anywhere in
this codebase. The root key is read from a plaintext environment variable at startup and the
process boots directly into an unsealed state.

Beyond that, there are five defects that will lose data or grant unauthorized access the moment
this runs in a real cluster. They are listed in §3 and they are all fixable — none require
re-architecting anything.

**Rough completeness toward "self-hostable Vault replacement": ~55–60%**, with the caveat that the
remaining 40% contains the single hardest and most security-critical component (seal/unseal, key
custody, and durable revocation).

---

## 2. Subsystem scorecard

| Subsystem | State | Notes |
|---|---|---|
| `wslvault-core` (crypto, types, middleware) | **Solid — 85%** | AES-256-GCM envelope, HKDF, CSPRNG nonces, all tested. ChaCha20 declared but unwired. |
| `wslvault-storage` (Postgres) | **Solid — 80%** | Real typed SQL layer over 23 tables + stored procedures. **Zero tests.** |
| `wslvault-connectors` | **Good — 75%** | AWS/Azure/GCP/HashiCorp/K8s/Postgres all real. Batch `sync()` is a no-op. **Zero tests.** |
| `wslvault-cluster` | **Good — 80%** | Correct Postgres advisory-lock leader election. **Zero tests.** |
| `crypto-service` | **Partial — 55%** | 3-tier envelope KMS works. No seal/unseal. Rotation destroys old DEKs. |
| `secret-engine` | **Partial — 65%** | KV v2 only; no undelete, no patch, no metadata config, no dynamic secrets. |
| `transit-engine` | **Weak — 35%** | AES-256-GCM only. Postgres backend does not persist key material. |
| `pki-engine` | **Partial — 50%** | Single-level ECDSA CA, issue/sign/revoke/CRL. No intermediate CA, no OCSP/ACME. RSA advertised but broken. |
| `identity-service` | **Mixed — auth 75% / tokens 20%** | Excellent auth-method coverage; token model is a bare JWT with no leases, renewal, or durable revocation. |
| `policy-engine` | **Partial — 45%** | Deny-wins ACL works. **HTTP authorize endpoint has an authz bypass.** No sudo, no templating. |
| `audit-service` | **Weak — 35%** | Per-record HMAC only. No hash chain, signatures never verified, write failures swallowed. |
| `lease-manager` | **Partial — 50%** | Renew/revoke/expire real. No lease creation RPC. `ListLeases` returns `[]` on Postgres. |
| `mcp-server` | **Strong — 85%** | Spec-compliant JSON-RPC 2.0, 10 tools, stdio + HTTP. No resources/prompts. |
| `k8s-operator` | **Good — 60%** | Two real CRDs with working reconcilers. No injector, no CSI, no SA auth. |
| `replication-agent` | **Good — 60%** | Real LWW + vector-clock conflict resolution. Key material intentionally does not replicate. Metrics are dead. |
| `region-health` / `sync-scheduler` | **Partial — 45%** | Both work; Azure and GCP sync are stubs. **Zero tests each.** |
| SDKs (Go/Python/TS/Rust) | **Strong — 85%** | Real clients with retries. Go is the reference. No READMEs; Python build would fail. |
| CLI | **Good — 70%** | 16 commands, all implemented. Missing Vault's `operator`, `token`, `auth`, `secrets`, `pki`. |
| UI | **Good — 75%** | 12 wired Next.js pages, real login. Three pages 404 in dev (missing proxy rewrite). |
| Deploy / infra | **Partial — 55%** | Terraform + Helm + Kustomize all exist and diverge from each other. **Helm gateway enforces nothing.** |
| Docs | **Thin — 30%** | 4 files, no root README. `performance.md` is admirably honest about what's unmeasured. |

---

## 3. Blockers — fix these before you host this anywhere

These are ordered by blast radius. Each is a confirmed defect, not a missing feature.

### P0-1 · There is no seal/unseal. The root key is a plaintext env var.

`grep -rniE '\bshamir\b|\bunseal\b|seal_status|\brekey\b'` across the entire repo returns exactly
one hit — a *comment* in [applier.rs:235](services/replication-agent/src/applier.rs#L235) explaining
what Shamir sharing would be for.

The root KEK is loaded at startup from `VAULT_ROOT_KEY` (base64) via `RootKeyProvider`
([root_key.rs](services/crypto-service/src/root_key.rs)). There is no `init`, no seal state machine,
no unseal ceremony, no key shares, no recovery keys, no `/sys/seal-status`, no root token, and no
`step-down`/`rekey`/`generate-root`.

The one alternative provider is AWS KMS — and it is feature-gated **off by default**
([crypto-service/Cargo.toml:13](services/crypto-service/Cargo.toml#L13) → `default = []`). No
PKCS#11/HSM, no Azure Key Vault, no GCP KMS, no Transit auto-unseal.

Consequence: whoever can read your Kubernetes Secret, your Helm values, or a process environment
owns every secret in the vault, in perpetuity. There is no documented recovery path if the key is
lost. **This is the defining feature of Vault and it is 0% built.**

### P0-2 · Transit keys are never persisted. A pod restart permanently destroys all transit ciphertext.

[pg_store.rs:178](services/transit-engine/src/pg_store.rs#L178) and
[:262](services/transit-engine/src/pg_store.rs#L262) literally write the ASCII string
`"TODO:wrap_key_material"` into the database's `wrapped_key` column instead of wrapped key material.
[:112](services/transit-engine/src/pg_store.rs#L112) never warm-loads keys on boot, and `get_key`
reads only the in-process cache.

The module doc admits it ([:16-28](services/transit-engine/src/pg_store.rs#L16-L28)): key material
"still lives exclusively in memory."

Consequence: in a cluster, pods restart. When one does, every ciphertext ever produced by that
transit key becomes permanently undecryptable. With more than one replica, encrypt and decrypt
routed to different pods will not even agree in the first place. **This is unrecoverable data loss
and it triggers on the most routine event in Kubernetes.**

### P0-3 · Policy authorization over HTTP ignores the principal entirely.

[http.rs:242-245](services/policy-engine/src/http.rs#L242-L245):

```rust
// Collect policy names for this principal by loading all tenant policies
let docs = state.store.get_all_for_tenant(&tid).await;
let policy_names: Vec<String> = docs.iter().map(|d| d.name.clone()).collect();
```

`principal_id` is accepted in the request body and then never used. The endpoint evaluates the
caller against the **union of every policy in the tenant**. If any policy in the tenant grants
`write` on `secret/*`, every principal in the tenant has it.

The gRPC path does this correctly ([grpc.rs:167-168](services/policy-engine/src/grpc.rs#L167-L168) —
it evaluates only the caller-supplied `req.policies`). The two entry points disagree, and the
gateway routes `/v1/policies/` to the HTTP one.

Compounding this: the compiled policy snapshot is a flat `HashMap<policy_name, rules>` that is
**not tenant-scoped** ([evaluator.rs:22-25](services/policy-engine/src/evaluator.rs#L22-L25),
rebuilt across all tenants at [main.rs:141-146](services/policy-engine/src/main.rs#L141-L146)). Two
tenants with a policy of the same name collide; last writer wins. That is a cross-tenant leak.

There are **zero tests** in `policy-engine/src/http.rs`, which is why this survives.

### P0-4 · Token revocation is an in-memory `HashSet`. It does not survive a restart and does not propagate between replicas.

[grpc.rs:67](services/identity-service/src/grpc.rs#L67):
`revoked_tokens: Arc<RwLock<HashSet<String>>>`.

Revoking a token adds the raw string to a per-process set. Restart the pod and the token works
again until its natural expiry. Run two replicas — which the Helm chart does — and revoking on pod A
has no effect on pod B. There is no revocation by accessor, by prefix, or by principal.

A poisoned lock fails **open**, treating the token as not-revoked
([grpc.rs:106-109](services/identity-service/src/grpc.rs#L106-L109)).

Related: the entire principal store is an in-memory `HashMap`
([store.rs:38-40](services/identity-service/src/store.rs#L38-L40)) with no database backing.
Principals vanish on restart.

### P0-5 · The Helm gateway runs stock OpenResty. None of your auth, rate-limiting, or quota Lua is mounted.

[deploy/helm/wslvault/templates/gateway/deployment.yaml](deploy/helm/wslvault/templates/gateway/deployment.yaml)
mounts exactly three volumes: `tls`, `tmp`, `openresty-cache`. It never mounts `nginx.conf` and never
mounts `gateway/lua/`. Its own comment concedes configuration "should be mounted from a ConfigMap
(not generated here)" — and no such ConfigMap template exists in the chart.

The raw-kustomize gateway *references* `gateway-config` and `gateway-lua` ConfigMaps, but those are
never defined either (`grep -rl "gateway-config" deploy/` finds only the consumer, never a producer).

Consequence: deploy via Helm and your security perimeter — token validation, per-tenant rate
limiting, quota enforcement, the `X-Gateway-Auth` shared secret that stops clients forging
`X-Tenant-Id` — silently evaporates. The gateway becomes a bare reverse proxy. Backends trust the
`X-Tenant-Id` header. **Any client can then assert any tenant.**

---

## 4. High-severity defects (P1)

| # | Issue | Location |
|---|---|---|
| P1-1 | **DEK rotation discards the old DEK.** Ciphertext under the previous version becomes undecryptable. No re-encryption window. | [kek_store.rs:576-577](services/crypto-service/src/kek_store.rs#L576-L577) |
| P1-2 | **Audit signatures are never verified.** `verify_signature` is `#[cfg(test)]`-gated; `query_events` returns records unchecked, and the proto doesn't even carry the signature field. | [integrity.rs:31-32](services/audit-service/src/integrity.rs#L31-L32) |
| P1-3 | **No audit hash chain.** Each record is signed independently — no `prev_hash`, no sequence linkage. Deleting, truncating, or reordering rows is undetectable. | [integrity.rs:47-62](services/audit-service/src/integrity.rs#L47-L62) |
| P1-4 | **Hardcoded fallback audit HMAC key**, and it is one global key for all tenants despite the doc comment claiming per-tenant keys. | [grpc.rs:30,44-46](services/audit-service/src/grpc.rs#L30) |
| P1-5 | **Audit write failures are swallowed and logged.** A failed audit insert does not fail the audited operation. Vault guarantees the opposite. | [pg_store.rs:75-84](services/audit-service/src/pg_store.rs#L75-L84) |
| P1-6 | **SCIM group→policy mapping is a no-op.** `add_policy_to_principal` / `remove_policy_from_principal` log `"(pending store API)"` and mutate nothing. Your IdP thinks it is granting and revoking access; nothing happens. | [scim/groups.rs:99-142](services/identity-service/src/scim/groups.rs#L99-L142) |
| P1-7 | Root cause of P1-6: `PrincipalStore::update_policies` is `#[cfg(test)]`-only. **There is no production code path to change a principal's policies after creation.** | [store.rs:119-120](services/identity-service/src/store.rs#L119-L120) |
| P1-8 | **Tenant CRUD returns HTTP 500 whenever `DATABASE_URL` is set.** The `Database` variant is a placeholder returning `Internal("requires async context")`. | [tenant_handlers.rs:87-93](services/identity-service/src/tenant_handlers.rs#L87-L93) |
| P1-9 | **Kubernetes connector disables TLS verification** (`danger_accept_invalid_certs(true)`) with a comment claiming the CA is "handled separately." It is not. | [kubernetes.rs:42](crates/wslvault-connectors/src/kubernetes.rs#L42) |
| P1-10 | `ListLeases` **hardcodes an empty vec** on the Postgres backend. Works only in-memory. | [pg_store.rs:223-235](services/lease-manager/src/pg_store.rs#L223-L235) |
| P1-11 | Transit `/sign` and `/verify` are **HMAC-SHA256, not digital signatures.** The endpoint names are misleading; there is no asymmetric signing anywhere. | [operations.rs:62-78](services/transit-engine/src/operations.rs#L62-L78) |
| P1-12 | `GetKeyDescriptor` returns **hardcoded** `algorithm`/`purpose`/`state` regardless of the real key. | [grpc.rs:285-291](services/crypto-service/src/grpc.rs#L285-L291) |
| P1-13 | Rust SDK retry loop calls `f().await` an **extra time and discards the result** on network-error retries — every retried request executes twice. | [client.rs:747-763](sdks/rust/src/client.rs#L747-L763) |
| P1-14 | CLI sends `X-Vault-Tenant-ID`; SDKs, UI, and examples send `X-Tenant-Id`. 18 vs 17 occurrences across the tree. One of them is wrong. | `wslvault-cli/src/mcp/mod.rs:77` |
| P1-15 | Replication metrics (`vault_replication_lag_ms`, etc.) are **registered but never incremented.** `/metrics` always reports zero. Replication lag is never computed. | `services/replication-agent/src/metrics.rs` |
| P1-16 | `wslvault-core/src/ha/` is a **single-process in-memory simulation.** `health_score: 1.0` and `replication_lag_ms: 0` are hardcoded; no peer transport exists despite the doc claiming "bully algorithm over gRPC." It duplicates and contradicts the real `wslvault-cluster` crate. | [ha/cluster.rs:84,184](crates/wslvault-core/src/ha/cluster.rs#L84) |

---

## 5. Feature parity vs HashiCorp Vault (OSS)

### Secret engines

| Feature | Status |
|---|---|
| KV v2 (versioning, CAS, soft delete, destroy, metadata read) | ✅ Built |
| KV v1 | ❌ Absent — engine string hardcoded `"kv-v2"` ([http.rs:990](services/secret-engine/src/http.rs#L990)) |
| KV undelete | ❌ [kv_store.rs:377](services/secret-engine/src/kv_store.rs#L377) "reserved for future use" |
| KV patch / subkeys / `delete_version_after` | ❌ Absent |
| Metadata write (`max_versions`, `cas_required`, custom metadata) | ❌ Read-only. `max_versions` silently defaults to 10 and cannot be set via API |
| Mount management (`secrets enable/disable/tune/move`) | ❌ Absent — one engine, fixed at `/v1/secret` |
| Two-phase rotation (initiate → confirm) | ⚠️ Postgres backend only; in-memory returns `UnsupportedOperation` |
| **Dynamic secrets (database, AWS, GCP, Azure, SSH, RabbitMQ, Consul…)** | ❌ **Entirely absent.** This is a huge chunk of Vault's value |

### Transit

| Feature | Status |
|---|---|
| encrypt / decrypt / rewrap / key rotate | ✅ Built |
| Key types beyond `aes256-gcm` | ❌ Enum has exactly one variant ([key_store.rs:58-61](services/transit-engine/src/key_store.rs#L58-L61)). No ed25519, ecdsa, rsa, chacha20 |
| True sign / verify (asymmetric) | ❌ The endpoints are HMAC |
| `hmac`, `hash`, `random`, `datakey` endpoints | ❌ Absent |
| Batch operations (`batch_input`) | ❌ Absent |
| Convergent encryption / derived keys | ❌ Absent |
| `min_decryption_version` / key config | ❌ No config endpoint; all old versions usable forever |
| BYOK import, key export, backup/restore, trim | ❌ Absent |
| List / read / delete keys | ❌ Absent |

### PKI

| Feature | Status |
|---|---|
| Root CA generate, import, get | ✅ Built |
| Issue, sign-CSR, revoke, CRL | ✅ Built |
| **Intermediate CA** (`/intermediate/generate`, `/set-signed`) | ❌ Absent. Single-level self-signed roots only |
| OCSP | ❌ Absent |
| ACME | ❌ Absent |
| RSA key types | ⚠️ Advertised in the enum but **non-functional** under the `ring` backend; the test is `#[ignore]`d ([ca.rs:663-667](services/pki-engine/src/ca.rs#L663-L667)) |
| Ed25519 | ❌ Absent |
| `/tidy`, `/config/urls`, `/cert/:serial`, list certs | ❌ Absent (`list_active_certs` exists but is wired to no route) |
| Rich role constraints (`allowed_uri_sans`, `enforce_hostnames`, `require_cn`, EKU flags…) | ⚠️ Partial — 8 of ~25 |

### Auth methods

| Method | Status |
|---|---|
| OIDC / JWT (consumer) | ✅ Real — discovery, JWKS cache, RS256 |
| Kubernetes | ✅ Real — TokenReview + offline JWKS |
| AWS IAM | ✅ Real — STS `GetCallerIdentity` replay |
| Azure workload identity | ✅ Real |
| LDAP / AD | ✅ Real — direct + search bind, group mapping |
| OAuth 2.0 device flow (RFC 8628) | ✅ Real |
| API keys (`wslv_` prefix) | ✅ Real |
| mTLS / cert | ⚠️ Weak — single-level chain check, **no CRL/OCSP**, no SAN/`allowed_names` constraints, no roles |
| **userpass** | ❌ Absent |
| **AppRole** | ❌ Absent |
| GitHub, Okta, RADIUS, GCP IAM | ❌ Absent |

### Tokens, identity, policy, audit

| Feature | Status |
|---|---|
| Token types (service vs batch) | ❌ One flavour — a bare HS256 JWT |
| Token renewal / leases on tokens | ❌ A `lease_id` UUID is generated and **never stored** ([grpc.rs:375](services/identity-service/src/grpc.rs#L375)) |
| Token accessors, orphan tokens, periodic tokens, `num_uses` | ❌ Absent |
| Durable revocation | ❌ See P0-4 |
| TTL configuration | ⚠️ Hardcoded 3600s in every auth flow |
| **Identity entities / aliases / groups, entity merging** | ❌ Absent. Each auth method mints its own prefixed principal (`oidc:…`, `aws:…`); the same human is N unrelated principals |
| Namespaces | ⚠️ Flat `tenant_id`, not hierarchical |
| Policy language | ⚠️ Custom JSON — not HCL. `*`/`**` globs, **no `+`** — Vault ACL paths will not port |
| Capabilities | ⚠️ 7 of 10 — **no `sudo`**, no `patch`, no `subscribe` |
| Templated policies (`{{identity.entity.id}}`) | ❌ Absent |
| Parameter constraints (`allowed_parameters`, `required_parameters`) | ❌ Absent |
| Path priority / longest-prefix specificity | ❌ Flat scan with deny short-circuit |
| Response wrapping (cubbyhole) | ❌ Absent |
| Audit devices (file / syslog / socket) | ❌ None — one gRPC sink to Postgres |
| Audit HMAC of sensitive *fields* | ❌ Values stored in cleartext; whole record signed once |
| MFA (TOTP / Duo / PingID / Okta) | ❌ Absent — `grep -i 'totp\|mfa\|duo'` returns nothing |
| `sys/health`, `sys/metrics`, `sys/capabilities` | ⚠️ Partial |

---

## 6. Feature parity vs HashiCorp Vault **Enterprise** (the paid features)

This is the part you said you were targeting. Scorecard:

| Enterprise feature | Status |
|---|---|
| **Namespaces** | ⚠️ **Partial** — flat tenants with RLS + optional dedicated per-tenant schemas ([013_dedicated_tenant_schemas.sql](storage/postgres/init/013_dedicated_tenant_schemas.sql)). Not hierarchical. Genuinely good work. |
| **Secrets Sync** (to AWS/GCP/Azure/GitHub…) | ⚠️ **Partial** — connectors are real, but batch `sync()` **discards pulled data and no-ops on push** across all 6 connectors. Azure and GCP sync-scheduler dispatch are outright stubs ([runner.rs:59,71](services/sync-scheduler/src/runner.rs#L59)). |
| **Performance / DR Replication** | ⚠️ **Partial** — real symmetric peer replication with LWW + vector-clock conflict resolution and DB-trigger event emission. But **no DR-secondary vs performance-secondary distinction**, no read-only forwarding, no path filters. **Key material does not replicate by design** ([applier.rs:220-241](services/replication-agent/src/applier.rs#L220-L241)) — each region rotates independently. |
| **HSM support / seal wrap / PKCS#11** | ❌ Absent |
| **Auto-unseal** | ❌ AWS KMS only, feature-gated **off**. No Azure/GCP/OCI/Transit. And there is no seal to un-seal. |
| **Sentinel policies (EGP/RGP)** | ❌ Absent |
| **Control groups / dual authorization** | ❌ Absent |
| **Transform engine (FPE, tokenization, masking)** | ❌ Absent |
| **KMIP secrets engine** | ❌ Absent |
| **Key Management secrets engine** | ❌ Absent |
| **Entropy augmentation** | ❌ Absent |
| **Audit log filtering** | ❌ Absent |
| **Lease count quotas / rate limit quotas** | ⚠️ **Partial** — per-tenant quota tables + gateway token-bucket exist ([012_tenant_quotas.sql](storage/postgres/init/012_tenant_quotas.sql), `gateway/lua/middleware/quota_check.lua`). But the gateway relies on an external "quota-sync job" that **does not exist**, so it falls back to hardcoded defaults. |
| **Automated integrated-storage snapshots** | ❌ Absent |
| **Vault Agent / injector / CSI driver** | ❌ Absent (`k8s-operator` syncs to native Secrets instead — a reasonable alternative) |
| **MCP server for AI agents** | ✅ **Built, and this is ahead of HashiCorp.** Spec-compliant JSON-RPC 2.0, 10 tools, stdio + HTTP. |

**Read:** you have made real progress on Namespaces, Secrets Sync, Replication, and Quotas — four
genuinely Enterprise-tier features. The three that gate a paid-tier story and are at zero are
**HSM/seal-wrap, Sentinel, and Transform/tokenization**. And Secrets Sync's actual sync loop is
hollow.

---

## 7. Test coverage

275 unit tests, 4 `#[ignore]`d. **No integration test directory exists for any Rust crate or
service** — `wslvault-cli/tests`, `sdks/python/tests`, `sdks/typescript/tests` are the only `tests/`
dirs in the repo. Nothing exercises a real database, a real gRPC call, or a real HTTP handler.

| Crate / service | Tests | Gap |
|---|---|---|
| identity-service | 110 | **0 in `grpc.rs` and `oidc.rs`** — the gRPC handlers and OIDC validation are untested |
| wslvault-core | 35 | Good on crypto + middleware; 0 on `ha/`, config, metrics |
| crypto-service | 21 | Good. KMS test `#[ignore]`d |
| policy-engine | 19 | **0 in `http.rs`** — which is why P0-3 survives |
| mcp-server | 18 | All in `jsonrpc.rs`; `tools.rs` untested |
| pki-engine | 16 | Strong on `ca.rs`; 0 on store/http. RSA test ignored |
| replication-agent | 14 | All in `conflict.rs`; applier/consumer/producer untested |
| k8s-operator | 13 | All in `policy_controller.rs` |
| secret-engine | 10 | Store only; **no rotation, HTTP, or gRPC tests** |
| lease-manager | 6 | SQL "tests" are `contains()` string checks, not real queries |
| wslvault-cli | 6 | — |
| transit-engine | 4 | **0 on `pg_store.rs`** — which is why P0-2 survives |
| audit-service | 3 | Integrity only |
| **`wslvault-storage`** | **0** | The entire Postgres layer |
| **`wslvault-connectors`** | **0** | All six connectors |
| **`wslvault-cluster`** | **0** | Leader election |
| **`sdks/rust`** | **0** | Where the retry bug lives |
| **region-health, sync-scheduler** | **0** | — |

CI (`.github/workflows/ci.yml`) runs `cargo test --workspace` against a Postgres 16 service
container, but **lint and `cargo audit` are both `continue-on-error: true`** (lines 18, 103 — the
latter admits "14 known dependency CVEs"). Image builds run with `needs: []`, so **images ship even
when tests fail**.

---

## 8. Deployment readiness

Three deployment paths exist and they **disagree with each other**:

| | Terraform + Helm | Raw Kustomize | docker-compose |
|---|---|---|---|
| Services covered | 13 (no `k8s-operator`) | 12 (no `pki-engine`, no `k8s-operator`) | 15 (no `k8s-operator`) |
| Gateway config mounted | ❌ **No** (P0-5) | References ConfigMaps that don't exist | ✅ Yes |
| RBAC | ❌ `rbac.create` renders nothing — no `rbac.yaml` template | ✅ Only for `k8s-operator` | n/a |
| Ingress | ❌ `ingress.enabled` renders nothing — no `ingress.yaml` template | n/a | n/a |

Additional gaps:

- **TLS certificates are referenced by Secret name but never issued.** No cert-manager, no Issuer,
  no ACME. The dev gateway is plain HTTP on `:8080` — the `8443:443` compose mapping is dead.
- **No backup or restore.** RDS automated backups only (14-day, prod). No `pg_dump`, no WAL
  archiving, no PITR, no snapshot automation, no DR runbook.
- **Postgres HA failover is manual.** The multi-region overlay declares primary + 2 standbys and its
  own comments suggest CloudNativePG/Patroni — none of which are included. The single-region base is
  a 1-replica StatefulSet (SPOF).
- **Prometheus scrapes only 8 of 14 services.** `pki-engine`, `replication-agent`, `region-health`,
  `sync-scheduler`, `k8s-operator`, and the gateway are unmonitored. **No Alertmanager** — the 8
  alert rules fire into the void.
- **Terraform IRSA is not wired.** The crypto-service IAM role trusts `ec2.amazonaws.com` rather
  than the EKS OIDC provider, so pods cannot assume it as written.
- HPAs cover 8 of 14 services and default to `enabled: false`.
- Helm `secrets.yaml` renders literal `REPLACE_ME_WITH_A_REAL_KEY` placeholders.
- `identity-service` and `policy-engine` run **in-memory in docker-compose** (DATABASE_URL
  deliberately omitted), so nothing you do in local dev persists.

---

## 9. Suggested order of work

**Stop-the-bleeding (do before any cluster deploy):**

1. Fix P0-3 (policy HTTP authz bypass) — smallest diff, largest security win. Make `http.rs` read
   the principal's policies, and tenant-scope the compiled snapshot. Add tests to `http.rs`.
2. Fix P0-2 (transit key persistence). Wrap key material under the root KEK before
   `insert_key_descriptor`, and warm-load on boot. Until then, transit is unusable in a cluster.
3. Fix P0-5 (Helm gateway config). Add a `gateway-configmap.yaml` template mounting `main.conf` +
   `lua/`, and set `VAULT_GATEWAY_SECRET`.
4. Fix P0-4 (durable revocation). Move `revoked_tokens` to Postgres with a TTL index; persist
   `PrincipalStore`. Make the poison-lock path fail **closed**.
5. Fix P1-1 (DEK rotation data loss). Retain old DEK versions; add `min_decryption_version`.

**Then — make it a vault:**

6. Build seal/unseal. Shamir split of the root key, `sys/init`, `sys/seal-status`, `sys/unseal`,
   `sys/seal`. Then auto-unseal providers behind the same trait (`root_key.rs` is already the right
   seam). Un-gate AWS KMS; add Azure/GCP/Transit.
7. Harden audit: hash chain (`prev_hash` + sequence), read-time verification, per-tenant keys, and
   make audit-write failure fail the request.
8. Wire SCIM group → policy (P1-6/P1-7). Promote `update_policies` out of `#[cfg(test)]`.

**Then — close the parity gap that users will notice:**

9. Transit: asymmetric keys (ed25519, ecdsa-p256, rsa), real `sign`/`verify`, `datakey`, `hmac`,
   `hash`, `random`, batch input.
10. Dynamic secrets engines (start with `database/postgres` — you already have
    `postgres_rotation.rs` doing the hard part).
11. PKI intermediate CA + OCSP. Fix or remove the broken RSA key types.
12. Lease model on tokens: accessors, renewal, TTL config.
13. `userpass` + `AppRole` auth.

**Then — the Enterprise story:**

14. Make Secrets Sync actually sync (the `sync()` no-op across all 6 connectors).
15. Transform engine (FPE/tokenization) — this is the highest-value paid feature you don't have.
16. Sentinel-equivalent policy hooks, control groups.
17. PKCS#11 / HSM + seal wrap.

**Continuously:**

- Add integration tests. There are none, and they are precisely what would have caught P0-2, P0-3,
  and P1-8.
- Re-block `cargo clippy` and `cargo audit` in CI; gate image builds on tests.
- Write a root `README.md`.
- Resolve the `X-Tenant-Id` vs `X-Vault-Tenant-ID` header split (P1-14).
- Delete `wslvault-core/src/ha/` or make it real — right now it is a misleading simulation that
  duplicates `wslvault-cluster` (P1-16).

---

## 10. What genuinely impressed

Worth saying, because the list above is unrelenting:

- The envelope-encryption hierarchy in `crypto-service/kek_store.rs` is correct, AAD-bound,
  race-tested, and cross-tenant-isolation-tested.
- The advisory-lock leader election in `wslvault-cluster/leader.rs` correctly reasons about
  session-scoped locks on a dedicated connection — a bug most people ship.
- `replication-agent/conflict.rs` implements real vector-clock dominance with a deterministic
  concurrent tiebreak, plus loop prevention via `SET LOCAL app.replication_agent`.
- The MCP server is spec-compliant and ahead of HashiCorp.
- `docs/performance.md` explicitly retracts an unsupported `<5ms` claim from earlier
  documentation and marks five metrics "Not measured." That intellectual honesty is rarer than
  working code.
