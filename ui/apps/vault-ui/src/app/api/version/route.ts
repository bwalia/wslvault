import { NextResponse } from 'next/server'

// Never pre-render this at build: the env vars and start time belong to the
// running pod, not the builder.
export const dynamic = 'force-dynamic'

/**
 * Captured once, when the server process starts. A deploy changes the image
 * tag and rolls the pod, so process start IS the moment this build went live
 * in this region — no clock has to be threaded through the chart.
 */
const startedAt = new Date().toISOString()

/**
 * Build/deploy stamp for the footer. APP_VERSION and APP_GIT_SHA are set on
 * the Deployment by the chart; the Dockerfile bakes fallbacks for local runs.
 */
export function GET() {
  return NextResponse.json({
    version: process.env.APP_VERSION || 'dev',
    sha: process.env.APP_GIT_SHA || '',
    deployed_at: startedAt,
  })
}
