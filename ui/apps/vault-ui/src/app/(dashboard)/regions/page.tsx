'use client'
import useSWR from 'swr'
import { useFetcher } from '@/hooks/useVaultSWR'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { StatCard } from '@/components/ui/StatCard'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { Globe, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/Button'

// Mirrors the RegionInfo that region-health serves from GET /v1/sys/regions
// (services/region-health/src/store.rs). The page previously declared
// `name`, `leader` and `last_sync_at`, none of which that endpoint returns —
// so every field rendered as undefined even when the request succeeded.
interface Region {
  id: string
  display_name: string
  status: 'active' | 'degraded' | 'offline' | string
  replication_lag_ms: number | null
  is_local: boolean
  last_seen: string | null
  endpoint: string | null
}

// The endpoint returns a BARE ARRAY, not an envelope. Reading `data.regions`
// off it yields undefined, which the page rendered as "No regions configured"
// — a successful 200 that looked like an empty cluster.
type RegionsResponse = Region[]

function LagCell({ lagMs }: { lagMs: number | null }) {
  if (lagMs === null) return <span className="font-mono text-[13px] text-ink-faint">—</span>
  const variant: 'success' | 'warning' | 'danger' =
    lagMs < 100 ? 'success' : lagMs < 1000 ? 'warning' : 'danger'
  return (
    <Badge variant={variant} size="sm">
      <span className="font-mono tabular">{lagMs.toLocaleString()} ms</span>
    </Badge>
  )
}

// region-health serves /v1/sys/regions (services/region-health/src/main.rs).
// The bare /v1/regions here is a pre-gateway path and 404s.
const REGIONS_KEY = '/api/gateway/v1/sys/regions'

export default function RegionsPage() {
  const fetcher = useFetcher()

  const { data, isLoading, error, mutate: revalidate } = useSWR<RegionsResponse>(
    REGIONS_KEY,
    fetcher,
    { refreshInterval: 15_000 },
  )

  const regions = data ?? []

  const activeCount = regions.filter(r => r.status === 'active').length
  const standbyCount = regions.filter(r => r.status === 'standby').length
  const degradedCount = regions.filter(r => r.status === 'degraded').length
  const maxLagMs = regions
    .filter(r => !r.is_local && r.replication_lag_ms !== null)
    .reduce((max, r) => Math.max(max, r.replication_lag_ms as number), -1)

  return (
    <div className="max-w-7xl space-y-6">
      <PageHeader
        title="Regions & Replication"
        description="Multi-region replication topology and lag metrics"
        actions={
          <Button variant="secondary" size="sm" onClick={() => revalidate()}>
            <RefreshCw className="w-4 h-4" aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      {/* Stat row — max replication lag is the headline metric */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard
          label="Active"
          value={isLoading ? '—' : activeCount}
          detail="regions online"
        />
        <StatCard
          label="Standby"
          value={isLoading ? '—' : standbyCount}
          detail="ready to promote"
        />
        <StatCard
          label="Degraded"
          value={isLoading ? '—' : degradedCount}
          detail="need attention"
        />
        <StatCard
          label="Max Replication Lag"
          value={isLoading ? '—' : maxLagMs === -1 ? '—' : `${maxLagMs.toLocaleString()} ms`}
          detail="across follower regions"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Region Status</CardTitle>
        </CardHeader>
        <CardBody className="p-0">
          {isLoading ? (
            <div className="py-12 text-center text-sm text-ink-faint">Loading regions…</div>
          ) : error ? (
            <div className="py-12 text-center text-sm text-danger-600">
              Failed to load regions:{' '}
              {error instanceof Error ? error.message : 'Unknown error'}
            </div>
          ) : regions.length === 0 ? (
            <EmptyState
              icon={Globe}
              title="No regions configured"
              description="Add a replication region to see topology and lag metrics here."
            />
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-surface-2">
                <tr>
                  <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Region
                  </th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Status
                  </th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Locality
                  </th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Replication Lag
                  </th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Last Sync
                  </th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Endpoint
                  </th>
                </tr>
              </thead>
              <tbody className="bg-surface divide-y divide-line">
                {regions.map(region => (
                  <tr
                    key={region.id}
                    className="hover:bg-surface-2 transition-colors"
                  >
                    <td className="px-4 py-2.5 text-ink">
                      <span className="font-medium">{region.display_name ?? region.id}</span>
                      {region.display_name && region.display_name !== region.id && (
                        <span className="block font-mono text-[13px] text-ink-faint mt-0.5">
                          {region.id}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusBadge status={region.status} />
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusBadge status={region.is_local ? 'local' : 'peer'} />
                    </td>
                    <td className="px-4 py-2.5">
                      {region.is_local ? (
                        <span className="font-mono text-[13px] text-ink-faint">—</span>
                      ) : (
                        <LagCell lagMs={region.replication_lag_ms} />
                      )}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[13px] text-ink-faint">
                      {region.last_seen
                        ? new Date(region.last_seen).toLocaleString('en-GB', {
                            day: '2-digit',
                            month: 'short',
                            year: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })
                        : '—'}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[13px] text-ink-faint">
                      {region.endpoint ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardBody>
      </Card>
    </div>
  )
}
