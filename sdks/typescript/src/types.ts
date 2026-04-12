/**
 * TypeScript interfaces for all WSLVault API request and response types.
 *
 * These types are plain interfaces (no runtime validation). If you need
 * runtime validation, parse responses with a schema library such as Zod.
 */

// ---------------------------------------------------------------------------
// Secret types
// ---------------------------------------------------------------------------

/** Response from reading a secret. */
export interface SecretData {
  data: Record<string, unknown>;
  version: number;
  created_at?: string;
  metadata?: Record<string, string>;
}

/** Response from writing a secret. */
export interface WriteResponse {
  secret_id: string;
  version: number;
}

/** Response from listing secret paths. */
export interface ListResponse {
  paths: string[];
}

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

/** A single rule within a policy document. */
export interface PolicyRule {
  /** Glob-style path patterns. */
  paths: string[];
  /** Capabilities granted for matching paths, e.g. "read", "write". */
  capabilities: string[];
}

/** Request body for creating or replacing a policy. */
export interface PolicyCreateRequest {
  name: string;
  rules: PolicyRule[];
}

/** Response body for a single policy. */
export interface PolicyResponse {
  name: string;
  rules: PolicyRule[];
  created_at?: string;
  updated_at?: string;
}

/** Response body for listing all policies. */
export interface PolicyListResponse {
  policies: PolicyResponse[];
}

// ---------------------------------------------------------------------------
// Audit types
// ---------------------------------------------------------------------------

/** Optional filters for an audit event query. */
export interface AuditQueryFilters {
  start_time?: string;
  end_time?: string;
  action_filter?: string;
  principal_filter?: string;
  limit?: number;
  offset?: number;
}

/** A single immutable audit event record. */
export interface AuditEvent {
  id: string;
  tenant_id: string;
  principal_id: string;
  action: string;
  resource: string;
  outcome: string;
  outcome_detail?: string;
  client_ip?: string;
  timestamp: string;
}

/** Paginated response from an audit event query. */
export interface AuditQueryResponse {
  events: AuditEvent[];
  total: number;
}

// ---------------------------------------------------------------------------
// Lease types
// ---------------------------------------------------------------------------

/** A full lease record returned by the service. */
export interface LeaseRecord {
  id: string;
  tenant_id: string;
  target_type: string;
  state: "active" | "expired" | "revoked";
  ttl_seconds: number;
  max_ttl_seconds: number;
  renewable: boolean;
  issued_at: string;
  expires_at: string;
  revoked_at?: string;
}

/** Response from a lease renewal operation. */
export interface LeaseRenewResponse {
  id: string;
  expires_at: string;
  ttl_seconds: number;
}

// ---------------------------------------------------------------------------
// Transit types
// ---------------------------------------------------------------------------

export interface TransitEncryptResponse {
  ciphertext: string;
}

export interface TransitDecryptResponse {
  /** Base64-encoded plaintext. */
  plaintext: string;
}

export interface TransitSignResponse {
  signature: string;
}

export interface TransitVerifyResponse {
  valid: boolean;
}

export interface TransitHashResponse {
  hash: string;
}

export interface TransitHmacResponse {
  hmac: string;
}

export interface TransitKeyResponse {
  key_name: string;
  algorithm: string;
}

export interface TransitKeyRotateResponse {
  key_name: string;
  new_version: number;
}

// ---------------------------------------------------------------------------
// Tenant types
// ---------------------------------------------------------------------------

/** Request body for creating a new tenant. */
export interface TenantCreateRequest {
  slug: string;
  display_name: string;
  tier?: "shared" | "dedicated" | "sovereign";
  root_key_id: string;
}

/** Response body for a single tenant. */
export interface TenantResponse {
  id: string;
  slug: string;
  display_name: string;
  tier: string;
  root_key_id: string;
  created_at: string;
  updated_at: string;
  deleted_at?: string;
}

// ---------------------------------------------------------------------------
// API key types
// ---------------------------------------------------------------------------

/** Request body for creating a new API key. */
export interface ApiKeyCreateRequest {
  name: string;
  tenant_id: string;
  policies?: string[];
  path_prefixes?: string[];
  /** Seconds until the key expires; omit for a non-expiring key. */
  expires_in_seconds?: number;
  rate_limit_per_minute?: number;
}

/**
 * Response from creating an API key.
 *
 * The {@link key} field contains the raw API key and is **only returned once**.
 * Store it securely immediately.
 */
export interface ApiKeyCreateResponse {
  id: string;
  /** Raw API key string. Shown at creation only — never returned again. */
  key: string;
  key_prefix: string;
  name: string;
  tenant_id: string;
  policies: string[];
  path_prefixes: string[];
  expires_at?: string;
  created_at: string;
}

/** API key metadata returned by list/rotate (no raw key exposed). */
export interface ApiKeyMetadata {
  id: string;
  name: string;
  tenant_id: string;
  key_prefix: string;
  policies: string[];
  path_prefixes: string[];
  created_by: string;
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  rate_limit_per_minute: number;
}

/** Response from exchanging a raw API key for a short-lived JWT. */
export interface ApiKeyAuthResponse {
  token: string;
  expires_at: string;
  tenant_id: string;
  policies: string[];
}

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

/** Options accepted by {@link WslVaultClient}. */
export interface WslVaultClientOptions {
  /** Base URL of the WSLVault gateway, e.g. "https://vault.example.com". */
  endpoint: string;
  /** Bearer token (JWT) used for authentication. */
  token?: string;
  /** Tenant UUID sent as X-Tenant-Id on every request. */
  tenantId?: string;
  /** Per-request timeout in milliseconds (default 30 000). */
  timeoutMs?: number;
  /** Maximum number of retry attempts for transient errors (default 3). */
  maxRetries?: number;
}
