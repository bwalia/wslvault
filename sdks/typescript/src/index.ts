/**
 * WSLVault TypeScript SDK — public API surface.
 *
 * @example
 * ```ts
 * import {
 *   WslVaultClient,
 *   VaultError,
 *   VaultNotFoundError,
 * } from "wslvault";
 *
 * const client = new WslVaultClient({
 *   endpoint: "https://vault.example.com",
 *   token: "s.my-jwt-token",
 *   tenantId: "my-tenant-uuid",
 * });
 *
 * try {
 *   const secret = await client.secrets.get("prod/db/password");
 *   console.log(secret.data.password);
 * } catch (err) {
 *   if (err instanceof VaultNotFoundError) {
 *     console.error("secret not found");
 *   } else if (err instanceof VaultError) {
 *     console.error("vault error:", err.message);
 *   }
 * }
 * ```
 */

// Main client
export { WslVaultClient } from "./client";

// Error classes
export {
  VaultApiError,
  VaultAuthError,
  VaultConflictError,
  VaultConnectionError,
  VaultError,
  VaultNotFoundError,
  VaultPermissionError,
} from "./errors";

// All request/response types and options
export type {
  ApiKeyAuthResponse,
  ApiKeyCreateRequest,
  ApiKeyCreateResponse,
  ApiKeyMetadata,
  AuditEvent,
  AuditQueryFilters,
  AuditQueryResponse,
  LeaseRecord,
  LeaseRenewResponse,
  ListResponse,
  PolicyCreateRequest,
  PolicyListResponse,
  PolicyResponse,
  PolicyRule,
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
