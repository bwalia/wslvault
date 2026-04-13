/**
 * Next.js Edge Middleware — JWT claim injection for backend proxying.
 *
 * The UI sends `Authorization: Bearer <jwt>` + `X-Tenant-Id` headers.
 * Backend services (secret-engine, transit-engine, etc.) expect the
 * policy-engine-facing headers `X-Principal-Id` and `X-Policies` to be set.
 *
 * The OpenResty gateway handles this translation in production. For the
 * dev-mode Next.js rewrite proxy (next.config.ts), this middleware fills
 * the same role by decoding the JWT payload and injecting the headers
 * before the rewrite forwards the request to the backend.
 *
 * The JWT payload is decoded (not re-verified) because:
 *   1. The token was issued and signed by our identity-service.
 *   2. The backend services trust these headers from an internal caller.
 *   3. Full HMAC-SHA256 verification would require the JWT secret in the
 *      Next.js edge runtime — unnecessary for an internal dev proxy.
 */

import { NextRequest, NextResponse } from 'next/server'

/** Paths that route to backend services and need the injected headers. */
const BACKEND_PREFIXES = [
  '/api/secret/',
  '/api/transit/',
  '/api/policy/',
  '/api/audit/',
  '/api/lease/',
]

/** Decode a base64url string to a UTF-8 string (Edge runtime safe). */
function decodeBase64Url(b64url: string): string {
  // Pad to multiple of 4, replace URL-safe chars with standard base64 chars.
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/')
  const pad = padded.length % 4
  const b64 = pad ? padded + '='.repeat(4 - pad) : padded
  return atob(b64)
}

interface JwtPayload {
  sub?: string
  policies?: string[]
  tenant_id?: string
}

/** Extract claims from a JWT without verifying the signature. */
function decodeJwtPayload(token: string): JwtPayload | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    return JSON.parse(decodeBase64Url(parts[1])) as JwtPayload
  } catch {
    return null
  }
}

export function middleware(request: NextRequest): NextResponse {
  const { pathname } = request.nextUrl

  const isBackendRequest = BACKEND_PREFIXES.some((prefix) =>
    pathname.startsWith(prefix),
  )

  if (!isBackendRequest) {
    return NextResponse.next()
  }

  const authHeader = request.headers.get('authorization') ?? ''
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null

  if (!token) {
    return NextResponse.next()
  }

  const claims = decodeJwtPayload(token)
  if (!claims) {
    return NextResponse.next()
  }

  const requestHeaders = new Headers(request.headers)

  if (claims.sub) {
    requestHeaders.set('x-principal-id', claims.sub)
  }

  if (Array.isArray(claims.policies) && claims.policies.length > 0) {
    requestHeaders.set('x-policies', claims.policies.join(','))
  }

  // Also ensure X-Tenant-Id is set from the token claim if not already present,
  // in case the UI forgot to include it.
  if (claims.tenant_id && !requestHeaders.get('x-tenant-id')) {
    requestHeaders.set('x-tenant-id', claims.tenant_id)
  }

  return NextResponse.next({ request: { headers: requestHeaders } })
}

export const config = {
  matcher: [
    '/api/secret/:path*',
    '/api/transit/:path*',
    '/api/policy/:path*',
    '/api/audit/:path*',
    '/api/lease/:path*',
  ],
}
