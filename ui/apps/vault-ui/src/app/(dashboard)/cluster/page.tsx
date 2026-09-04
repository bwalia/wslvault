'use client'
import useSWR from 'swr'
import { useFetcher } from '@/hooks/useVaultSWR'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { StatCard } from '@/components/ui/StatCard'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { Server, RefreshCw, Crown, CheckCircle2, XCircle, HelpCircle } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/utils'

interface ClusterNode {
  id: string
  address: string
  role: 'leader' | 'follower' | 'candidate' | string
  health: 'healthy' | 'unhealthy' | 'unknown' | string
  raft_index: number | null
  commit_index: number | null
  last_contact_ms: number | null
}

interface ClusterStatus {
  leader_id: string | null
  term: number | null
  nodes: ClusterNode[]
  quorum_met: boolean | null
  raft_index: number | null
  commit_index: number | null
}

// region-health serves /v1/sys/cluster/status, not /v1/cluster/status.
const CLUSTER_KEY = '/api/gateway/v1/sys/cluster/status'

export default function ClusterPage() {
  const fetcher = useFetcher()

  const {
    data,
    isLoading,
    error,
    mutate: revalidate,
  } = useSWR<ClusterStatus>(CLUSTER_KEY, fetcher, { refreshInterval: 10_000 })

  const nodes = data?.nodes ?? []
  const healthyCount = nodes.filter(n => n.health === 'healthy').length
  const leaderNode = nodes.find(n => n.role === 'leader')

  return (
    <div className="max-w-7xl space-y-6">
      <PageHeader
        title="Cluster & HA Health"
        description="Raft cluster topology, node health, and consensus metrics"
        actions={
          <Button variant="secondary" size="sm" onClick={() => revalidate()}>
            <RefreshCw className="w-4 h-4" aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      {/* Summary stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Nodes"
          value={isLoading ? '—' : nodes.length}
          detail="in cluster"
        />
        <StatCard
          label="Healthy Nodes"
          value={isLoading ? '—' : healthyCount}
          detail={isLoading ? undefined : `of ${nodes.length}`}
        />
        <StatCard
          label="Raft Term"
          value={isLoading ? '—' : (data?.term ?? '—')}
          detail="current election term"
        />
        <StatCard
          label="Commit Index"
          value={isLoading ? '—' : (data?.commit_index ?? '—')}
          detail="log entries applied"
        />
      </div>

      {/* Quorum status banner — left rule + icon + label, no colored fill */}
      {!isLoading && data && (
        <div
          className={cn(
            'flex items-start gap-4 px-5 py-4 rounded-xl border border-line bg-surface',
            data.quorum_met === true && 'border-l-2 border-l-success-500',
            data.quorum_met === false && 'border-l-2 border-l-danger-500',
            data.quorum_met === null && 'border-l-2 border-l-ink-faint',
          )}
          role="status"
          aria-label="Quorum status"
        >
          {data.quorum_met === true && (
            <CheckCircle2 className="w-5 h-5 text-success-500 shrink-0 mt-0.5" aria-hidden="true" />
          )}
          {data.quorum_met === false && (
            <XCircle className="w-5 h-5 text-danger-500 shrink-0 mt-0.5" aria-hidden="true" />
          )}
          {data.quorum_met === null && (
            <HelpCircle className="w-5 h-5 text-ink-faint shrink-0 mt-0.5" aria-hidden="true" />
          )}
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-ink">
              {data.quorum_met === true
                ? 'Quorum met'
                : data.quorum_met === false
                ? 'Quorum not met'
                : 'Quorum unknown'}
            </p>
            <p className="text-xs text-ink-muted mt-0.5">
              {data.quorum_met === true
                ? 'Cluster is fully operational and accepting writes.'
                : data.quorum_met === false
                ? 'Cluster may be unavailable for writes until quorum is restored.'
                : 'Quorum state could not be determined. Check node connectivity.'}
            </p>
          </div>
          {leaderNode && (
            <div className="flex items-center gap-1.5 text-xs text-ink-muted shrink-0">
              <Crown className="w-3.5 h-3.5 text-warn-500" aria-hidden="true" />
              <span>Leader:</span>
              <span className="font-mono text-sm text-ink">
                {leaderNode.address ?? leaderNode.id}
              </span>
            </div>
          )}
        </div>
      )}

      {/* Node table */}
      <Card>
        <CardHeader>
          <CardTitle>Cluster Nodes</CardTitle>
        </CardHeader>
        <CardBody className="p-0">
          {isLoading ? (
            <div className="py-12 text-center text-sm text-ink-faint">Loading cluster status…</div>
          ) : error ? (
            <div className="py-12 text-center text-sm text-danger-600">
              Failed to load cluster status:{' '}
              {error instanceof Error ? error.message : 'Unknown error'}
            </div>
          ) : nodes.length === 0 ? (
            <EmptyState
              icon={Server}
              title="No cluster nodes reported"
              description="No node data is available. Verify the cluster is reachable and the gateway is configured correctly."
            />
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-surface-2">
                <tr>
                  <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Node ID
                  </th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Address
                  </th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Role
                  </th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Health
                  </th>
                  <th className="px-4 py-2.5 text-right text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Raft Index
                  </th>
                  <th className="px-4 py-2.5 text-right text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Commit Index
                  </th>
                  <th className="px-4 py-2.5 text-right text-xs font-medium uppercase tracking-wide text-ink-faint">
                    Last Contact
                  </th>
                </tr>
              </thead>
              <tbody className="bg-surface divide-y divide-line">
                {nodes.map(node => (
                  <tr
                    key={node.id}
                    className="hover:bg-surface-2 transition-colors"
                  >
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        {node.role === 'leader' && (
                          <Crown
                            className="w-3.5 h-3.5 text-warn-500 shrink-0"
                            aria-label="Leader node"
                          />
                        )}
                        <span className="font-mono text-sm text-ink truncate max-w-[140px]">
                          {node.id}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-sm text-ink-faint">
                      {node.address ?? '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusBadge status={node.role} />
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusBadge status={node.health} />
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-sm tabular text-ink-muted">
                      {node.raft_index?.toLocaleString() ?? '—'}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-sm tabular text-ink-muted">
                      {node.commit_index?.toLocaleString() ?? '—'}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-sm tabular text-ink-muted">
                      {node.last_contact_ms != null ? `${node.last_contact_ms} ms` : '—'}
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
