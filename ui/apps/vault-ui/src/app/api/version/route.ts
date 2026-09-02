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
 * Build/deploy stamp for the footer. APP_VERSION / APP_GIT_SHA are baked by
 * the image (CI build-args) and can be overridden by the Deployment.
 *
 * Bracket access on purpose: Next replaces `process.env.FOO` at compile time,
 * so a missing builder env used to freeze every image as `version: "dev"`.
 */
export function GET() {
  return NextResponse.json({
    version: process.env['APP_VERSION'] || 'dev',
    sha: process.env['APP_GIT_SHA'] || '',
    deployed_at: startedAt,
  })
}
