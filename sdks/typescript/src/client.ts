/**
 * WSLVault TypeScript SDK — main client.
 *
 * Uses the native `fetch` API (available in Node.js 18+ and all modern browsers).
 *
 * @example
 * ```ts
 * import { WslVaultClient } from "wslvault";
 *
 * const client = new WslVaultClient({
 *   endpoint: "https://vault.example.com",
 *   token: "s.my-jwt-token",
 *   tenantId: "my-tenant-uuid",
 * });
 *
 * // Read a secret
 * const secret = await client.secrets.get("prod/db/password");
 * console.log(secret.data.password);
 *
 * // Transit encrypt
 * const enc = await client.transit.encrypt("my-key", "dGVzdA==");
 * console.log(enc.ciphertext);
 *
 * // Create a tenant
 * const tenant = await client.tenants.create({
 *   slug: "acme",
 *   display_name: "Acme Corp",
 *   root_key_id: "kek-001",
 * });
 * ```
 *
 * ### Retry behaviour
 * All requests are automatically retried up to `maxRetries` times on transient
 * HTTP errors (408, 429, 500, 502, 503, 504) and network failures, using
 * exponential backoff starting at 100 ms and capped at 10 s.
 */

import {
  VaultApiError,
  VaultAuthError,
  VaultConnectionError,
  VaultNotFoundError,
  VaultPermissionError,
} from "./errors";
import type {
  ApiKeyAuthResponse,
  ApiKeyCreateRequest,
  ApiKeyCreateResponse,
  ApiKeyMetadata,
  AuditQueryFilters,
  AuditQueryResponse,
  LeaseRecord,
  LeaseRenewResponse,
  ListResponse,
  PolicyCreateRequest,
  PolicyListResponse,
  PolicyResponse,
  SecretData,
  TenantCreateRequest,
  TenantResponse,
  TransitDecryptResponse,
  TransitEncryptResponse,
  TransitHashResponse,
  TransitHmacResponse,
  TransitKeyResponse,
  TransitKeyRotateResponse,
  TransitSignResponse,
  TransitVerifyResponse,
  WslVaultClientOptions,
  WriteResponse,
} from "./types";

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/** HTTP status codes that represent transient server-side failures. */
const RETRYABLE_STATUSES = new Set([408, 429, 500, 502, 503, 504]);

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 100;
const MAX_BACKOFF_MS = 10_000;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Section base class
// ---------------------------------------------------------------------------

class BaseSection {
  constructor(protected readonly client: WslVaultClient) {}

  protected async get<T>(path: string, params?: Record<string, string>): Promise<T> {
    return this.client._request<T>("GET", path, { params });
  }

  protected async post<T>(path: string, body?: unknown): Promise<T> {
    return this.client._request<T>("POST", path, { body });
  }

  protected async delete(path: string): Promise<void> {
    await this.client._request<void>("DELETE", path, { expectBody: false });
  }
}

// ---------------------------------------------------------------------------
// Service sections
// ---------------------------------------------------------------------------

/** Methods for the KV secrets engine. */
class SecretsSection extends BaseSection {
  /** Read a secret at *path*. */
  async get(path: string): Promise<SecretData> {
    return this.get<SecretData>(`/v1/secret/data/${path}`);
  }

  /** Write *data* to a secret at *path*. */
  async put(path: string, data: Record<string, unknown>): Promise<WriteResponse> {
    return this.post<WriteResponse>(`/v1/secret/data/${path}`, { data });
  }

  /** Soft-delete specific *versions* of a secret (or pass an empty array for all). */
  async delete(path: string, versions: number[] = []): Promise<void> {
    await this.client._request<void>("POST", `/v1/secret/delete/${path}`, {
      body: { versions },
      expectBody: false,
    });
  }

  /** List secret paths under *prefix*. */
  async list(prefix: string): Promise<ListResponse> {
    return this.get<ListResponse>("/v1/secret/list", { prefix });
  }
}

/** Methods for the transit encryption engine. */
class TransitSection extends BaseSection {
  /** Encrypt base64-encoded *plaintext* using the named transit key. */
  async encrypt(keyName: string, plaintext: string): Promise<TransitEncryptResponse> {
    return this.post<TransitEncryptResponse>(`/v1/transit/encrypt/${keyName}`, { plaintext });
  }

  /** Decrypt a versioned *ciphertext* using the named transit key. */
  async decrypt(keyName: string, ciphertext: string): Promise<TransitDecryptResponse> {
    return this.post<TransitDecryptResponse>(`/v1/transit/decrypt/${keyName}`, { ciphertext });
  }

  /** Sign base64-encoded *data* with the named transit key. */
  async sign(keyName: string, data: string): Promise<TransitSignResponse> {
    return this.post<TransitSignResponse>(`/v1/transit/sign/${keyName}`, { data });
  }

  /** Verify a *signature* over base64-encoded *data* using the named transit key. */
  async verify(
    keyName: string,
    data: string,
    signature: string,
  ): Promise<TransitVerifyResponse> {
    return this.post<TransitVerifyResponse>(`/v1/transit/verify/${keyName}`, {
      data,
      signature,
    });
  }

  /** Compute a hash of *inputData* using the named key context. */
  async hash(keyName: string, inputData: string): Promise<TransitHashResponse> {
    return this.post<TransitHashResponse>(`/v1/transit/hash/${keyName}`, {
      input: inputData,
    });
  }

  /** Compute an HMAC over *inputData* using the named transit key. */
  async hmac(keyName: string, inputData: string): Promise<TransitHmacResponse> {
    return this.post<TransitHmacResponse>(`/v1/transit/hmac/${keyName}`, {
      input: inputData,
    });
  }

  /** Create a new named transit key. */
  async createKey(keyName: string): Promise<TransitKeyResponse> {
    return this.post<TransitKeyResponse>(`/v1/transit/keys/${keyName}`, {});
  }

  /** Rotate the named transit key, adding a new key version. */
  async rotateKey(keyName: string): Promise<TransitKeyRotateResponse> {
    return this.post<TransitKeyRotateResponse>(`/v1/transit/keys/${keyName}/rotate`, {});
  }
}

/** Methods for tenant management. */
class TenantsSection extends BaseSection {
  /** Create a new tenant. */
  async create(req: TenantCreateRequest): Promise<TenantResponse> {
    return this.post<TenantResponse>("/v1/tenants", req);
  }

  /** Get a single tenant by its UUID. */
  async get(tenantId: string): Promise<TenantResponse> {
    return super.get<TenantResponse>(`/v1/tenants/${tenantId}`);
  }

  /** List all active tenants. */
  async list(): Promise<TenantResponse[]> {
    return super.get<TenantResponse[]>("/v1/tenants");
  }

  /** Soft-delete a tenant by its UUID. */
  async delete(tenantId: string): Promise<void> {
    await super.delete(`/v1/tenants/${tenantId}`);
  }
}

/** Methods for API key lifecycle management. */
class ApiKeysSection extends BaseSection {
  /**
   * Create a new API key.
   *
   * The {@link ApiKeyCreateResponse.key} field is shown **only once**.
   * Store it securely immediately.
   */
  async create(req: ApiKeyCreateRequest): Promise<ApiKeyCreateResponse> {
    return this.post<ApiKeyCreateResponse>("/v1/api-keys", req);
  }

  /** List active API keys for the configured tenant. */
  async list(): Promise<ApiKeyMetadata[]> {
    return this.get<ApiKeyMetadata[]>("/v1/api-keys");
  }

  /** Revoke an API key by its UUID. */
  async revoke(keyId: string): Promise<void> {
    await this.delete(`/v1/api-keys/${keyId}`);
  }

  /**
   * Rotate an API key: revoke the existing key and return a replacement
   * with the same configuration.
   */
  async rotate(keyId: string): Promise<ApiKeyCreateResponse> {
    return this.post<ApiKeyCreateResponse>(`/v1/api-keys/${keyId}/rotate`, {});
  }

  /**
   * Exchange a raw API key (`wslv_...`) for a short-lived JWT.
   *
   * Pass the returned token to the client constructor as `token` or call
   * {@link WslVaultClient.loginWithApiKey} to update the token in-place.
   */
  async authenticate(apiKey: string): Promise<ApiKeyAuthResponse> {
    return this.post<ApiKeyAuthResponse>("/v1/auth/api-key", { api_key: apiKey });
  }
}

/** Methods for policy management. */
class PoliciesSection extends BaseSection {
  /** Create or replace a policy. */
  async create(req: PolicyCreateRequest): Promise<PolicyResponse> {
    return this.post<PolicyResponse>("/v1/policies", req);
  }

  /** Get a policy by name. */
  async get(name: string): Promise<PolicyResponse> {
    return super.get<PolicyResponse>(`/v1/policies/${name}`);
  }

  /** Delete a policy by name. */
  async delete(name: string): Promise<void> {
    await super.delete(`/v1/policies/${name}`);
  }

  /** List all policies for the configured tenant. */
  async list(): Promise<PolicyListResponse> {
    return super.get<PolicyListResponse>("/v1/policies");
  }
}

/** Methods for querying audit events. */
class AuditSection extends BaseSection {
  /** Query audit events with optional *filters*. */
  async query(filters?: AuditQueryFilters): Promise<AuditQueryResponse> {
    const params: Record<string, string> = {};
    if (filters) {
      if (filters.start_time !== undefined) params["start_time"] = filters.start_time;
      if (filters.end_time !== undefined) params["end_time"] = filters.end_time;
      if (filters.action_filter !== undefined) params["action"] = filters.action_filter;
      if (filters.principal_filter !== undefined)
        params["principal"] = filters.principal_filter;
      if (filters.limit !== undefined) params["limit"] = String(filters.limit);
      if (filters.offset !== undefined) params["offset"] = String(filters.offset);
    }
    return this.get<AuditQueryResponse>(
      "/v1/audit/events",
      Object.keys(params).length > 0 ? params : undefined,
    );
  }
}

/** Methods for lease lifecycle management. */
class LeasesSection extends BaseSection {
  /** Retrieve a lease by its UUID. */
  async get(leaseId: string): Promise<LeaseRecord> {
    return super.get<LeaseRecord>(`/v1/leases/${leaseId}`);
  }

  /** Revoke a lease immediately. */
  async revoke(leaseId: string): Promise<void> {
    await this.client._request<void>("POST", `/v1/leases/${leaseId}/revoke`, {
      body: {},
      expectBody: false,
    });
  }

  /** Renew a lease by extending its TTL by *incrementSeconds*. */
  async renew(leaseId: string, incrementSeconds: number): Promise<LeaseRenewResponse> {
    return this.post<LeaseRenewResponse>(`/v1/leases/${leaseId}/renew`, {
      increment_seconds: incrementSeconds,
    });
  }
}

// ---------------------------------------------------------------------------
// Internal request options
// ---------------------------------------------------------------------------

interface RequestOptions {
  params?: Record<string, string>;
  body?: unknown;
  expectBody?: boolean;
}

// ---------------------------------------------------------------------------
// Main client
// ---------------------------------------------------------------------------

/**
 * Async client for the WSLVault secrets platform.
 *
 * All service operations are available as namespaced sections on this class:
 * - {@link secrets} — KV secret read/write/delete/list
 * - {@link transit} — encrypt/decrypt/sign/verify/hash/hmac/key management
 * - {@link tenants} — tenant CRUD
 * - {@link apiKeys} — API key lifecycle
 * - {@link policies} — policy CRUD
 * - {@link audit} — audit event queries
 * - {@link leases} — lease lifecycle
 */
export class WslVaultClient {
  private readonly endpoint: string;
  private token: string | undefined;
  private readonly tenantId: string | undefined;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;

  /** Methods for the KV secrets engine. */
  readonly secrets: SecretsSection;
  /** Methods for the transit encryption engine. */
  readonly transit: TransitSection;
  /** Methods for tenant management. */
  readonly tenants: TenantsSection;
  /** Methods for API key lifecycle management. */
  readonly apiKeys: ApiKeysSection;
  /** Methods for policy management. */
  readonly policies: PoliciesSection;
  /** Methods for querying audit events. */
  readonly audit: AuditSection;
  /** Methods for lease lifecycle management. */
  readonly leases: LeasesSection;

  constructor(options: WslVaultClientOptions) {
    if (!options.endpoint) {
      throw new Error("WslVaultClient: endpoint must not be empty");
    }

    this.endpoint = options.endpoint.replace(/\/+$/, "");
    this.token = options.token;
    this.tenantId = options.tenantId;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;

    this.secrets = new SecretsSection(this);
    this.transit = new TransitSection(this);
    this.tenants = new TenantsSection(this);
    this.apiKeys = new ApiKeysSection(this);
    this.policies = new PoliciesSection(this);
    this.audit = new AuditSection(this);
    this.leases = new LeasesSection(this);
  }

  // -------------------------------------------------------------------------
  // Convenience auth helpers
  // -------------------------------------------------------------------------

  /**
   * Update the bearer token used for subsequent requests.
   *
   * Useful after {@link loginWithApiKey} to refresh an expired JWT without
   * constructing a new client instance.
   */
  setToken(token: string): void {
    this.token = token;
  }

  /**
   * Exchange a raw API key (`wslv_...`) for a short-lived JWT and install
   * the returned token on the client automatically.
   */
  async loginWithApiKey(apiKey: string): Promise<ApiKeyAuthResponse> {
    const resp = await this.apiKeys.authenticate(apiKey);
    this.setToken(resp.token);
    return resp;
  }

  // -------------------------------------------------------------------------
  // Internal HTTP request with retry/backoff
  // -------------------------------------------------------------------------

  /** @internal Exposed for section classes; not intended as a public API. */
  async _request<T>(
    method: string,
    path: string,
    options: RequestOptions = {},
  ): Promise<T> {
    const { params, body, expectBody = true } = options;

    let url = `${this.endpoint}${path}`;
    if (params && Object.keys(params).length > 0) {
      const qs = new URLSearchParams(params).toString();
      url = `${url}?${qs}`;
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    if (this.tenantId) {
      headers["X-Tenant-Id"] = this.tenantId;
    }

    let delayMs = INITIAL_BACKOFF_MS;
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        await sleep(delayMs);
        delayMs = Math.min(delayMs * 2, MAX_BACKOFF_MS);
      }

      let response: Response;
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
          response = await fetch(url, {
            method,
            headers,
            body: body !== undefined ? JSON.stringify(body) : undefined,
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timeoutId);
        }
      } catch (fetchErr: unknown) {
        // Network-level failures (DNS, connection refused, abort/timeout).
        const message =
          fetchErr instanceof Error ? fetchErr.message : String(fetchErr);
        const connErr = new VaultConnectionError(
          `request failed: ${message}`,
          fetchErr,
        );
        lastError = connErr;
        if (attempt < this.maxRetries) {
          continue;
        }
        throw connErr;
      }

      // --- Map HTTP status to typed errors ---
      if (!response.ok) {
        const body = await response.text().catch(() => "");
        const status = response.status;
        let err: Error;

        if (status === 401) {
          err = new VaultAuthError();
        } else if (status === 403) {
          err = new VaultPermissionError(body);
        } else if (status === 404) {
          err = new VaultNotFoundError(body);
        } else {
          err = new VaultApiError(status, body);
        }

        if (RETRYABLE_STATUSES.has(status) && attempt < this.maxRetries) {
          lastError = err;
          continue;
        }

        throw err;
      }

      // --- Success ---
      if (!expectBody || response.status === 204) {
        return undefined as unknown as T;
      }

      try {
        return (await response.json()) as T;
      } catch (parseErr: unknown) {
        throw new VaultApiError(
          response.status,
          `failed to parse JSON response: ${parseErr instanceof Error ? parseErr.message : String(parseErr)}`,
        );
      }
    }

    // All retries exhausted.
    if (lastError instanceof Error) {
      throw lastError;
    }
    throw new VaultConnectionError("request failed after all retry attempts");
  }
}
