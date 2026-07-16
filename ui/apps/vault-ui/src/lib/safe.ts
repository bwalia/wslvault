/**
 * Total wrappers around partial browser APIs.
 *
 * `JSON.parse`, `atob`, `btoa`, and `localStorage` all throw, and every one of
 * them is reachable from untrusted or environment-dependent input in this app:
 *
 *   - `atob` throws on any non-base64 secret blob (a corrupted row, a value
 *     written by a different client, a partial response).
 *   - `btoa` throws on any code point above U+00FF — a secret containing an
 *     emoji or non-Latin text kills the save.
 *   - `localStorage` throws in Safari private mode and when the quota is full.
 *
 * Uncaught, each of these unmounts the React tree and shows a blank page. These
 * return a discriminated result instead so callers must decide what to do.
 */

export type Result<T> = { ok: true; value: T } | { ok: false; error: string }

const ok = <T>(value: T): Result<T> => ({ ok: true, value })
const err = <T>(error: string): Result<T> => ({ ok: false, error })

/** `JSON.parse` that cannot throw. */
export function safeJsonParse<T = unknown>(text: string): Result<T> {
  try {
    return ok(JSON.parse(text) as T)
  } catch (e) {
    return err(e instanceof Error ? e.message : 'Invalid JSON')
  }
}

/**
 * Decode base64 → UTF-8 string. Handles non-ASCII correctly.
 *
 * `atob` yields one char per byte, so multi-byte UTF-8 arrives mojibake'd
 * unless it is routed back through TextDecoder.
 */
export function safeB64Decode(b64: string): Result<string> {
  try {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0))
    return ok(new TextDecoder().decode(bytes))
  } catch {
    return err('Value is not valid base64')
  }
}

/** Encode a UTF-8 string → base64. Safe for any code point. */
export function safeB64Encode(text: string): Result<string> {
  try {
    const bytes = new TextEncoder().encode(text)
    let binary = ''
    // Chunked to avoid blowing the argument limit on large secrets.
    const CHUNK = 0x8000
    for (let i = 0; i < bytes.length; i += CHUNK) {
      binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK))
    }
    return ok(btoa(binary))
  } catch (e) {
    return err(e instanceof Error ? e.message : 'Could not encode value')
  }
}

/** Decode a base64(JSON) secret blob into a key/value map. */
export function decodeSecretBlob(b64: string): Result<Record<string, string>> {
  const decoded = safeB64Decode(b64)
  if (!decoded.ok) return err(decoded.error)

  const parsed = safeJsonParse<unknown>(decoded.value)
  if (!parsed.ok) return err('Secret data is not valid JSON')

  const value = parsed.value
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return err('Secret data is not a key/value object')
  }

  // Coerce scalars to strings so a secret written by the CLI or an SDK with
  // numeric/boolean values still renders instead of crashing the editor.
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = typeof v === 'string' ? v : JSON.stringify(v)
  }
  return ok(out)
}

/** Encode a key/value map as the base64(JSON) blob the API expects. */
export function encodeSecretBlob(obj: Record<string, string>): Result<string> {
  return safeB64Encode(JSON.stringify(obj))
}

/**
 * localStorage that degrades instead of throwing.
 *
 * Safari private mode throws on `setItem`; a full quota throws anywhere. An
 * uncaught throw here happens during auth bootstrap, i.e. before any error
 * boundary is mounted — the user gets a white screen with no way forward.
 */
export const safeStorage = {
  get(key: string): string | null {
    try {
      return localStorage.getItem(key)
    } catch {
      return null
    }
  },
  set(key: string, value: string): boolean {
    try {
      localStorage.setItem(key, value)
      return true
    } catch {
      return false
    }
  },
  remove(key: string): void {
    try {
      localStorage.removeItem(key)
    } catch {
      // Nothing useful to do — the value is already unreachable.
    }
  },
}
