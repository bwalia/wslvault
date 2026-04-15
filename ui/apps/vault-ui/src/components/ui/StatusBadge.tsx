import { Badge } from './Badge'

const statusMap: Record<string, { variant: 'success' | 'danger' | 'warning' | 'default' | 'info'; label: string }> = {
  active: { variant: 'success', label: 'Active' },
  enabled: { variant: 'success', label: 'Enabled' },
  expired: { variant: 'danger', label: 'Expired' },
  revoked: { variant: 'danger', label: 'Revoked' },
  renewing: { variant: 'warning', label: 'Renewing' },
  shared: { variant: 'default', label: 'Shared' },
  dedicated: { variant: 'info', label: 'Dedicated' },
  sovereign: { variant: 'warning', label: 'Sovereign' },
  success: { variant: 'success', label: 'Success' },
  failure: { variant: 'danger', label: 'Failure' },
  error: { variant: 'danger', label: 'Error' },
  // Cluster / region statuses
  healthy: { variant: 'success', label: 'Healthy' },
  unhealthy: { variant: 'danger', label: 'Unhealthy' },
  standby: { variant: 'info', label: 'Standby' },
  degraded: { variant: 'warning', label: 'Degraded' },
  leader: { variant: 'info', label: 'Leader' },
  follower: { variant: 'default', label: 'Follower' },
  candidate: { variant: 'warning', label: 'Candidate' },
}

export function StatusBadge({ status }: { status?: string | null }) {
  if (!status) return <Badge variant="default">—</Badge>
  const cfg = statusMap[status.toLowerCase()] ?? { variant: 'default' as const, label: status }
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>
}
