import type { NextConfig } from 'next'

/**
 * Backend proxying.
 *
 * These rewrites make the UI pod a reverse proxy to the internal services. That
 * is only safe because the services behind them now authenticate every request
 * themselves (`services/secret-engine/src/identity.rs`) — the proxy adds no
 * credential of its own and grants nothing.
 *
 * There used to be a `src/middleware.ts` alongside this file that decoded the
 * caller's JWT *without verifying its signature* and injected `x-principal-id`,
 * `x-policies` and `x-tenant-id` from the result. Anyone could mint an unsigned
 * token claiming `{"policies":["root"],"tenant_id":"<victim>"}` and have this
 * proxy stamp it as trusted identity on the internal network. It has been
 * deleted: backends read identity from the signed token directly, so the
 * translation is now both unsafe and unnecessary.
 *
 * The browser's `Authorization: Bearer <jwt>` header passes through untouched,
 * which is all the backends need.
 */
const nextConfig: NextConfig = {
  output: 'standalone',
  async rewrites() {
    return [
      {
        source: '/api/identity/:path*',
        destination: `${process.env.IDENTITY_URL ?? 'http://localhost:18082'}/:path*`,
      },
      {
        source: '/api/secret/:path*',
        destination: `${process.env.SECRET_URL ?? 'http://localhost:8081'}/:path*`,
      },
      {
        source: '/api/transit/:path*',
        destination: `${process.env.TRANSIT_URL ?? 'http://localhost:18086'}/:path*`,
      },
      {
        source: '/api/policy/:path*',
        destination: `${process.env.POLICY_URL ?? 'http://localhost:8083'}/:path*`,
      },
      {
        source: '/api/audit/:path*',
        destination: `${process.env.AUDIT_URL ?? 'http://localhost:18085'}/:path*`,
      },
      {
        source: '/api/lease/:path*',
        destination: `${process.env.LEASE_URL ?? 'http://localhost:18084'}/:path*`,
      },
      {
        // Regions and cluster pages call `/api/gateway/*`. With the gateway
        // disabled GATEWAY_URL points at region-health, which serves
        // /v1/sys/regions and /v1/sys/cluster/*. SCIM is served by
        // identity-service at /api/identity/scim/v2/*.
        source: '/api/gateway/:path*',
        destination: `${process.env.GATEWAY_URL ?? 'http://localhost:8088'}/:path*`,
      },
    ]
  },
}

export default nextConfig
