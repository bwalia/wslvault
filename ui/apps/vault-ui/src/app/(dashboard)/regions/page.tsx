'use client'
import useSWR from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardHeader, CardBody } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Globe, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/Button'

interface Region {
  id: string
  name: string
  status: 'active' | 'standby' | 'degraded' | string
  replication_lag_ms: number | null
  leader: boolean
  last_sync_at: string | null
  endpoint: string | null
}

interface RegionsResponse {
  regions: Region[]
}

function statusVariant(
  status: string,
): 'success' | 'warning' | 'danger' | 'default' {
  switch (status.toLowerCase()) {
    case 'active':
      return 'success'
    case 'standby':
      return 'info' as unknown as 'default'
    case 'degraded':
      return 'danger'
    default:
      return 'default'
  }
}

function LagCell({ lagMs }: { lagMs: number | null }) {
  if (lagMs === null) return <span className="text-slate-400 text-xs">—</span>
  const variant: 'success' | 'warning' | 'danger' =
    lagMs < 100 ? 'success' : lagMs < 1000 ? 'warning' : 'danger'
  return (
    <Badge variant={variant} size="sm">
      {lagMs.toLocaleString()} ms
    </Badge>
  )
}

const REGIONS_KEY = '/api/gateway/v1/regions'

export default function RegionsPage() {
  const { token, tenantId } = useAuth()
  const fetcher = createFetcher(token, tenantId)

  const { data, isLoading, error, mutate: revalidate } = useSWR<RegionsResponse>(
    REGIONS_KEY,
    fetcher,
    { refreshInterval: 15_000 },
  )

  const regions = data?.regions ?? []

  const activeCount = regions.filter(r => r.status === 'active').length
  const standbyCount = regions.filter(r => r.status === 'standby').length
  const degradedCount = regions.filter(r => r.status === 'degraded').length

  return (
    <div>
      <PageHeader
        title="Regions & Replication"
        description="Multi-region replication topology and lag metrics"
        icon={Globe}
        actions={
          <Button variant="secondary" size="sm" onClick={() => revalidate()}>
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
        }
      />

      {/* Summary stat row */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm px-6 py-4 flex items-center gap-4">
          <div className="w-9 h-9 rounded-lg bg-accent-50 dark:bg-accent-900/20 flex items-center justify-center">
            <Globe className="w-5 h-5 text-accent-600 dark:text-accent-400" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Active</p>
            <p className="text-xl font-semibold text-slate-900 dark:text-white">
              {isLoading ? '—' : activeCount}
            </p>
          </div>
        </div>
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm px-6 py-4 flex items-center gap-4">
          <div className="w-9 h-9 rounded-lg bg-primary-50 dark:bg-primary-900/20 flex items-center justify-center">
            <Globe className="w-5 h-5 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Standby</p>
            <p className="text-xl font-semibold text-slate-900 dark:text-white">
              {isLoading ? '—' : standbyCount}
            </p>
          </div>
        </div>
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm px-6 py-4 flex items-center gap-4">
          <div className="w-9 h-9 rounded-lg bg-danger-50 dark:bg-danger-900/20 flex items-center justify-center">
            <Globe className="w-5 h-5 text-danger-600 dark:text-danger-400" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Degraded</p>
            <p className="text-xl font-semibold text-slate-900 dark:text-white">
              {isLoading ? '—' : degradedCount}
            </p>
          </div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Region Status</h2>
        </CardHeader>
        <CardBody className="p-0">
          {isLoading ? (
            <div className="py-12 text-center text-sm text-slate-400">Loading regions…</div>
          ) : error ? (
            <div className="py-12 text-center text-sm text-danger-600 dark:text-danger-400">
              Failed to load regions: {error instanceof Error ? error.message : 'Unknown error'}
            </div>
          ) : regions.length === 0 ? (
            <div className="py-12 text-center text-sm text-slate-400">No regions configured</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-slate-50 dark:bg-slate-800/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Region
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Role
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Replication Lag
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Last Sync
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Endpoint
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-slate-900 divide-y divide-slate-100 dark:divide-slate-800/50">
                {regions.map(region => (
                  <tr
                    key={region.id}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors"
                  >
                    <td className="px-6 py-3 font-medium text-slate-900 dark:text-white">
                      {region.name ?? region.id}
                    </td>
                    <td className="px-6 py-3">
                      <Badge variant={statusVariant(region.status)}>
                        {region.status}
                      </Badge>
                    </td>
                    <td className="px-6 py-3">
                      {region.leader ? (
                        <Badge variant="info" size="sm">Leader</Badge>
                      ) : (
                        <span className="text-xs text-slate-500">Follower</span>
                      )}
                    </td>
                    <td className="px-6 py-3">
                      {region.leader ? (
                        <span className="text-xs text-slate-400">—</span>
                      ) : (
                        <LagCell lagMs={region.replication_lag_ms} />
                      )}
                    </td>
                    <td className="px-6 py-3 text-xs text-slate-500">
                      {region.last_sync_at
                        ? new Date(region.last_sync_at).toLocaleString('en-GB', {
                            day: '2-digit',
                            month: 'short',
                            year: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })
                        : '—'}
                    </td>
                    <td className="px-6 py-3 text-xs font-mono text-slate-500">
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
