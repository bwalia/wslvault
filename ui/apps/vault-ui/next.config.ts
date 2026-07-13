import type { NextConfig } from 'next'

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
        // Regions/cluster/SCIM pages call `/api/gateway/*`. Historically this
        // hit the OpenResty gateway; with the gateway disabled, point it at the
        // edge ingress (which routes /v1/* and /scim/*) or the region-health
        // service. NOTE: some of those pages still use pre-gateway paths
        // (e.g. /v1/regions vs /v1/sys/regions, /v1/scim vs /scim/v2) and need
        // path alignment before they fully work — tracked separately.
        source: '/api/gateway/:path*',
        destination: `${process.env.GATEWAY_URL ?? 'http://localhost:8088'}/:path*`,
      },
    ]
  },
}

export default nextConfig
