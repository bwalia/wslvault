'use client'
import { useEffect, useState } from 'react'
import { cn } from '@/lib/utils'

interface VersionInfo {
  version: string
  sha: string
  deployed_at: string
}

/**
 * "v0.1.0 · 9f724df · Deployed 1h ago" — reads /api/version, which the UI pod
 * answers itself. Renders nothing until the fetch succeeds, so a failure costs
 * a page nothing. Size/spacing come from the call site; both current homes
 * (login's steel panel, the sidebar) share the steel palette.
 */
export default function BuildStamp({
  collapsed,
  className,
}: {
  collapsed?: boolean
  className?: string
}) {
  const [info, setInfo] = useState<VersionInfo | null>(null)

  useEffect(() => {
    let cancelled = false
    fetch('/api/version')
      .then(res => (res.ok ? res.json() : null))
      .then(data => {
        if (!cancelled && data?.version) setInfo(data)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [])

  if (!info) return null

  // Image tags here are full git SHAs; show the customary 7 characters. A pin
  // by release tag would repeat the version — say it once.
  let sha = info.sha === info.version ? '' : info.sha
  if (/^[0-9a-f]{40}$/i.test(sha)) sha = sha.slice(0, 7)
  const deployed = formatDeployed(info.deployed_at)
  const title = [
    info.version,
    info.sha || null,
    `Deployed ${new Date(info.deployed_at).toLocaleString()}`,
  ]
    .filter(Boolean)
    .join(' · ')

  if (collapsed) {
    return (
      <p
        className={cn('font-mono text-steel-ink-dim text-center truncate', className)}
        title={title}
      >
        {info.version}
      </p>
    )
  }

  return (
    <p className={cn('font-mono text-steel-ink-dim truncate', className)} title={title}>
      {[info.version, sha, deployed ? `Deployed ${deployed}` : null]
        .filter(Boolean)
        .join(' · ')}
    </p>
  )
}

function formatDeployed(iso: string): string | null {
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return null
  const mins = Math.floor((Date.now() - t) / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`
  return new Date(t).toLocaleDateString()
}
