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
    ]
  },
}

export default nextConfig
