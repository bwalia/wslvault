/**
 * Single source of truth for backend endpoints and SWR cache keys.
 *
 * Every path the UI calls is declared here, once. Pages import these builders
 * instead of hand-writing URL strings, because a hand-written key that drifts
 * from the one used at write time produces a revalidation that silently no-ops
 * — the mutation succeeds, the list never refreshes, and it looks like the
 * backend lost the write.
 *
 * The `/api/<service>/` prefixes are rewritten to the real service by
 * `next.config.ts`; the rewrite strips the prefix, so the rest of the path must
 * match the backend router exactly. Cross-check `services/<name>/src/**` before
 * changing anything here.
 */

/**
 * Encode a secret path for use in a URL path segment.
 *
 * The secret-engine mounts KV under `/v1/secret/data/*path` (an axum wildcard).
 * A wildcard will not match a percent-encoded `%2F`, so slashes must survive as
 * real separators — encode each segment individually rather than the whole path.
 */
export const encodeSecretPath = (path: string): string =>
  path
    .split('/')
    .filter(Boolean)
    .map(encodeURIComponent)
    .join('/')

export const api = {
  secret: {
    /** GET — list paths under a prefix. Also the SWR key for the tree. */
    list: (prefix = '') => `/api/secret/v1/secret/list?prefix=${encodeURIComponent(prefix)}`,
    /** GET (read) / POST (write) a secret's data. */
    data: (path: string) => `/api/secret/v1/secret/data/${encodeSecretPath(path)}`,
    /** POST — soft-delete versions. Empty `versions` = current version. */
    delete: (path: string) => `/api/secret/v1/secret/delete/${encodeSecretPath(path)}`,
    /** POST — permanently destroy versions. Empty `versions` = all versions. */
    destroy: (path: string) => `/api/secret/v1/secret/destroy/${encodeSecretPath(path)}`,
    /** GET — version history. */
    versions: (path: string) => `/api/secret/v1/secret/versions/${encodeSecretPath(path)}`,
    /** GET — path metadata (no plaintext). */
    metadata: (path: string) => `/api/secret/v1/secret/metadata/${encodeSecretPath(path)}`,
  },
  identity: {
    tenants: () => '/api/identity/v1/tenants',
    tenant: (id: string) => `/api/identity/v1/tenants/${encodeURIComponent(id)}`,
    apiKeys: () => '/api/identity/v1/api-keys',
    apiKey: (id: string) => `/api/identity/v1/api-keys/${encodeURIComponent(id)}`,
    rotateApiKey: (id: string) => `/api/identity/v1/api-keys/${encodeURIComponent(id)}/rotate`,
    authApiKey: () => '/api/identity/v1/auth/api-key',
  },
  policy: {
    list: () => '/api/policy/v1/policies',
    byName: (name: string) => `/api/policy/v1/policies/${encodeURIComponent(name)}`,
  },
  /**
   * NOTE: the transit paths below include the `/transit` segment that the
   * backend router requires (`/v1/transit/encrypt/:key_name`). The rewrite
   * strips only the `/api/transit` prefix — it does not re-add `/transit`.
   */
  transit: {
    key: (name: string) => `/api/transit/v1/transit/keys/${encodeURIComponent(name)}`,
    rotateKey: (name: string) => `/api/transit/v1/transit/keys/${encodeURIComponent(name)}/rotate`,
    encrypt: (name: string) => `/api/transit/v1/transit/encrypt/${encodeURIComponent(name)}`,
    decrypt: (name: string) => `/api/transit/v1/transit/decrypt/${encodeURIComponent(name)}`,
    sign: (name: string) => `/api/transit/v1/transit/sign/${encodeURIComponent(name)}`,
    verify: (name: string) => `/api/transit/v1/transit/verify/${encodeURIComponent(name)}`,
    rewrap: (name: string) => `/api/transit/v1/transit/rewrap/${encodeURIComponent(name)}`,
  },
} as const
