/**
 * HTTP layer for the vault API.
 *
 * Two rules this module exists to enforce:
 *
 *  1. Errors carry their status. Callers need to distinguish 401 (re-auth) from
 *     403 (policy denied) from 404 (gone) — a bare `Error("failed")` cannot.
 *  2. Mutations return their parsed body. Several vault endpoints report work
 *     done in the body rather than the status: `POST /v1/secret/delete/*`
 *     answers `200 {"count":0}` when it deleted nothing. A caller that only
 *     checks `res.ok` treats that as success and shows the user a lie.
 */

/** An API error that preserves the HTTP status and any server-supplied detail. */
export class ApiError extends Error {
  readonly status: number
  readonly detail?: string

  constructor(message: string, status: number, detail?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }

  /** Token missing/expired — the caller should send the user back to login. */
  get isAuthError(): boolean {
    return this.status === 401
  }

  /** Authenticated but not permitted by policy. */
  get isPermissionError(): boolean {
    return this.status === 403
  }

  get isNotFound(): boolean {
    return this.status === 404
  }
}

/** Shape of the error envelope the Rust services return. */
interface ErrorBody {
  message?: string
  error?: string
  reason?: string
}

async function toApiError(res: Response): Promise<ApiError> {
  const body = (await res.json().catch(() => ({}))) as ErrorBody
  const message = body.message ?? body.error ?? body.reason ?? `Request failed (${res.status})`
  return new ApiError(message, res.status, body.reason)
}

function authHeaders(token: string | null, tenantId: string | null): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (tenantId) headers['X-Tenant-Id'] = tenantId
  return headers
}

/**
 * Build an SWR fetcher bound to the current credentials.
 *
 * Memoize this at the call site (see `useVaultSWR`) — a fresh function identity
 * on every render defeats SWR's deduplication.
 */
export function createFetcher(token: string | null, tenantId: string | null) {
  return async <T = unknown>(url: string): Promise<T> => {
    const res = await fetch(url, {
      headers: authHeaders(token, tenantId),
      // Secret material must never land in the browser HTTP cache.
      cache: 'no-store',
    })
    if (!res.ok) throw await toApiError(res)
    return (await res.json()) as T
  }
}

/**
 * Perform a mutating request and return the parsed response body.
 *
 * Returns `null` for `204 No Content`. Throws `ApiError` on a non-2xx status.
 * Callers must still inspect the body where the endpoint reports work done
 * there rather than via the status code.
 */
export async function mutate<T = unknown>(
  url: string,
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  body: unknown,
  token: string | null,
  tenantId: string | null,
): Promise<T | null> {
  const res = await fetch(url, {
    method,
    headers: authHeaders(token, tenantId),
    body: body === null || body === undefined ? undefined : JSON.stringify(body),
    cache: 'no-store',
  })
  if (!res.ok) throw await toApiError(res)
  if (res.status === 204) return null
  return (await res.json().catch(() => null)) as T | null
}

/** Narrow an unknown caught value to a human-readable message. */
export function errorMessage(err: unknown, fallback = 'Something went wrong'): string {
  if (err instanceof ApiError) return err.message
  if (err instanceof Error) return err.message
  return fallback
}
